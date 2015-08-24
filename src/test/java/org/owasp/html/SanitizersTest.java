// Copyright (c) 2011, Mike Samuel
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
// Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
// Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
// Neither the name of the OWASP nor the names of its contributors may
// be used to endorse or promote products derived from this software
// without specific prior written permission.
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
// ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package org.owasp.html;

import org.junit.Test;

import java.util.BitSet;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;

import junit.framework.TestCase;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;

@SuppressWarnings("javadoc")
public class SanitizersTest extends TestCase {

  @Test
  public static final void testFormatting() {
    assertEquals("", Sanitizers.FORMATTING.sanitize(null));
    assertEquals("", Sanitizers.FORMATTING.sanitize(""));
    assertEquals(
        "Hello, World!",
        Sanitizers.FORMATTING.sanitize("Hello, World!"));
    assertEquals(
        "Hello, <b>World</b>!",
        Sanitizers.FORMATTING.sanitize("Hello, <b>World</b>!"));
    assertEquals(
        "Hello, <b>World</b>!",
        Sanitizers.FORMATTING.sanitize(
            "<p>Hello, <b onclick=alert(1337)>World</b>!</p>"));
  }

  @Test
  public static final void testBlockElements() {
    assertEquals("", Sanitizers.BLOCKS.sanitize(null));
    assertEquals(
        "Hello, World!",
        Sanitizers.BLOCKS.sanitize("Hello, World!"));
    assertEquals(
        "Hello, World!",
        Sanitizers.BLOCKS.sanitize("Hello, <b>World</b>!"));
    assertEquals(
        "<p>Hello, World!</p>",
        Sanitizers.BLOCKS.sanitize(
            "<p onclick=alert(1337)>Hello, <b>World</b>!</p>"));
  }

  @Test
  public static final void testBlockAndFormattingElements() {
    PolicyFactory s = Sanitizers.BLOCKS.and(Sanitizers.FORMATTING);
    PolicyFactory r1 = Sanitizers.BLOCKS.and(Sanitizers.FORMATTING)
        .and(Sanitizers.BLOCKS);
    PolicyFactory r2 = Sanitizers.BLOCKS.and(Sanitizers.FORMATTING)
        .and(Sanitizers.FORMATTING);
    for (PolicyFactory f : new PolicyFactory[] { s, r1, r2 }) {
      assertEquals("", f.sanitize(null));
      assertEquals("Hello, World!", f.sanitize("Hello, World!"));
      assertEquals("Hello, <b>World</b>!", f.sanitize("Hello, <b>World</b>!"));
      assertEquals(
          "<p>Hello, <b>World</b>!</p>",
          f.sanitize("<p onclick=alert(1337)>Hello, <b>World</b>!</p>"));
    }
  }

  @Test
  public static final void testStylesAndFormatting() {
    PolicyFactory sanitizer = Sanitizers.FORMATTING
      .and(Sanitizers.BLOCKS).and(Sanitizers.STYLES).and(Sanitizers.LINKS);
    String input = "<span style=\"font-weight:bold;"
      + "text-decoration:underline;background-color:yellow\""
      + ">aaaaaaaaaaaaaaaaaaaaaaa</span>";
    String got = sanitizer.sanitize(input);
    String want = input;
    assertEquals(want, got);
  }

  @Test
  public static final void testAndIntersects() {
    PolicyFactory restrictedLink = new HtmlPolicyBuilder()
       .allowElements("a")
       .allowUrlProtocols("https")
       .allowAttributes("href", "title").onElements("a")
       .toFactory();
    PolicyFactory inline = Sanitizers.FORMATTING.and(Sanitizers.LINKS);
    String inputHtml =
        "<a href='http://foo.com/'>Hello, <b>World</b></a>"
        + "<a title='!' href='https://foo.com/#!'>!</a>";
    PolicyFactory and1 = restrictedLink.and(inline);
    PolicyFactory and2 = inline.and(restrictedLink);
    assertEquals(
        "https-only links",
        "Hello, World<a title=\"!\" href=\"https://foo.com/#!\">!</a>",
        restrictedLink.sanitize(inputHtml));
    assertEquals(
        "inline els",
        "<a href=\"http://foo.com/\" rel=\"nofollow\">Hello, <b>World</b></a>"
        + "<a href=\"https://foo.com/#!\" rel=\"nofollow\">!</a>",
        inline.sanitize(inputHtml));
    assertEquals(
        "https-only links and inline els",
        "Hello, <b>World</b>"
        + "<a title=\"!\" href=\"https://foo.com/#!\" rel=\"nofollow\">!</a>",
        and1.sanitize(inputHtml));
    assertEquals(
        "inline els and https-only links",
        "Hello, <b>World</b>"
        + "<a title=\"!\" href=\"https://foo.com/#!\" rel=\"nofollow\">!</a>",
        and2.sanitize(inputHtml));
  }

  @Test
  public static final void testImages() {
    PolicyFactory s = Sanitizers.IMAGES;
    assertEquals(
        "foo", s.sanitize("<a href=\"javascript:alert(1337)\">foo</a>"));
    assertEquals(
        "<img src=\"foo.gif\" />", s.sanitize("<img src=\"foo.gif\">"));
    assertEquals(
        "", s.sanitize("<img src=\"javascript://alert(1337)\">"));
    assertEquals(
        "<img src=\"x.gif\" alt=\"y\""
        + " width=\"96\" height=\"64\" border=\"0\" />",
        s.sanitize(
            "<img src=\"x.gif\" alt=\"y\" width=96 height=64 border=0>"));
    assertEquals(
        "<img src=\"x.png\" alt=\"y\" height=\"64\" border=\"0\" />",
        s.sanitize(
            "<img src=\"x.png\" alt=\"y\" width=\"widgy\" height=64 border=0>")
        );
  }

  @Test
  public static final void testLinks() {
    PolicyFactory s = Sanitizers.LINKS;
    assertEquals(
        "<a href=\"foo.html\" rel=\"nofollow\">Link text</a>",
        s.sanitize("<a href=\"foo.html\">Link text</a>"));
    assertEquals(
        "<a href=\"foo.html\" rel=\"nofollow\">Link text</a>",
        s.sanitize(
            "<a href=\"foo.html\" onclick=\"alert(1337)\">Link text</a>"));
    assertEquals(
        "<a href=\"http://example.com/x.html\" rel=\"nofollow\">Link text</a>",
        s.sanitize(
            "<a href=\"http://example.com/x.html\""
            + " onclick=\"alert(1337)\">Link text</a>"));
    assertEquals(
        "<a href=\"https://example.com/x.html\" rel=\"nofollow\">Link text</a>",
        s.sanitize(
            "<a href=\"https://example.com/x.html\""
            + " onclick=\"alert(1337)\">Link text</a>"));
    assertEquals(
        "<a href=\"HTTPS://example.com/x.html\" rel=\"nofollow\">Link text</a>",
        s.sanitize(
            "<a href=\"HTTPS://example.com/x.html\""
            + " onclick=\"alert(1337)\">Link text</a>"));
    assertEquals(
        "<a href=\"//example.com/x.html\" rel=\"nofollow\">Link text</a>",
        s.sanitize(
            "<a href=\"//example.com/x.html\""
            + " onclick=\"alert(1337)\">Link text</a>"));
    assertEquals(
        "Link text",
        s.sanitize(
            "<a href=\"javascript:alert(1337).html\""
            + " onclick=\"alert(1337)\">Link text</a>"));
    // Not a link.  Instead, an attempt to intercept URL references that has
    // not been explicitly allowed.
    assertEquals(
        "Header text",
        s.sanitize("<a name=\"header\" id=\"header\">Header text</a>"));
  }

  @Test
  public static final void testExplicitlyAllowedProtocolsAreCaseInsensitive() {
    // Issue 24.
    PolicyFactory s = new HtmlPolicyBuilder()
        .allowElements("a")
        .allowAttributes("href").onElements("a")
        .allowStandardUrlProtocols()
        .allowUrlProtocols("file")  // Don't try this at home
        .toFactory();
    String input = (
        "<a href='file:///etc/passwd'>Copy and paste this into email</a>"
        + "<a href='FILE:///etc/passwd'>Or this one</a>"
        + "<a href='F\u0130LE:///etc/passwd'>not with Turkish dotted I's</a>"
        + "<a href='fail:///etc/passed'>The fail protocol needs to happen</a>");
    String want = (
        "<a href=\"file:///etc/passwd\">Copy and paste this into email</a>"
        + "<a href=\"FILE:///etc/passwd\">Or this one</a>"
        + "not with Turkish dotted I&#39;s"
        + "The fail protocol needs to happen");
    assertEquals(want, s.sanitize(input));
  }

  @Test
  public static final void testIssue9StylesInTables() {
    String input = ""
        + "<table style=\"color: rgb(0, 0, 0);"
        + " font-family: Arial, Geneva, sans-serif;\">"
        + "<tbody>"
        + "<tr>"
        + "<th>Column One</th><th>Column Two</th>"
        + "</tr>"
        + "<tr>"
        + "<td align=\"center\""
        + " style=\"background-color: rgb(255, 255, 254);\">"
        + "<font size=\"2\">Size 2</font></td>"
        + "<td align=\"center\""
        + " style=\"background-color: rgb(255, 255, 254);\">"
        + "<font size=\"7\">Size 7</font></td>"
        + "</tr>"
        + "</tbody>"
        + "</table>";
    PolicyFactory s = new HtmlPolicyBuilder()
        .allowElements("table", "tbody", "thead", "tr", "td", "th")
        .allowCommonBlockElements()
        .allowCommonInlineFormattingElements()
        .allowStyling()
        .allowAttributes("align").matching(true, "left", "center", "right")
          .onElements("table", "tr", "td", "th")
        .allowAttributes("size").onElements("font", "img")
        .toFactory();
    String sanitized = ""
        + "<table style=\"color:rgb( 0 , 0 , 0 );"
        + "font-family:&#39;arial&#39; , &#39;geneva&#39; , sans-serif\">"
        + "<tbody>"
        + "<tr>"
        + "<th>Column One</th><th>Column Two</th>"
        + "</tr>"
        + "<tr>"
        + "<td align=\"center\""
        + " style=\"background-color:rgb( 255 , 255 , 254 )\">"
        + "<font size=\"2\">Size 2</font></td>"
        + "<td align=\"center\""
        + " style=\"background-color:rgb( 255 , 255 , 254 )\">"
        + "<font size=\"7\">Size 7</font></td>"
        + "</tr>"
        + "</tbody>"
        + "</table>";
    assertEquals(sanitized, s.sanitize(input));
  }

  @Test
  public static final void testSkipIfEmptyUnionsProperly() {
    // Issue 23
    PolicyFactory extras = new HtmlPolicyBuilder()
        .allowWithoutAttributes("span", "div")
        .allowElements("span", "div", "textarea")
        // This is not the proper way to require the attribute disabled on
        // textareas.  This is a test.  This is only a test.
        .allowAttributes("disabled").onElements("textarea")
        .disallowWithoutAttributes("textarea")
        .toFactory();
    PolicyFactory policy = Sanitizers.FORMATTING
        .and(Sanitizers.BLOCKS)
        .and(Sanitizers.IMAGES)
        .and(Sanitizers.STYLES)
        .and(extras);
    String input =
        "<textarea>text</textarea><textarea disabled></textarea>"
        + "<div onclick='redirect()'><span>Styled by span</span></div>";
    String want = "text<textarea disabled=\"disabled\"></textarea>"
        + "<div><span>Styled by span</span></div>";
    assertEquals(want, policy.sanitize(input));
  }

  @Test
  public static final void testIssue30() {
    String test = "&nbsp;&gt;";

    PolicyFactory policy = Sanitizers.FORMATTING.and(Sanitizers.BLOCKS)
      .and(Sanitizers.STYLES);
    String safeHTML = policy.sanitize(test);

    assertEquals(test, "\u00a0&gt;", safeHTML);
  }

  @Test
  public static final void testScriptInTable() {
    String input = "<table>Hallo\r\n<script>SCRIPT</script>\nEnde\n\r";
    PolicyFactory pf = Sanitizers.BLOCKS.and(Sanitizers.FORMATTING)
      .and(Sanitizers.LINKS)
      .and(Sanitizers.STYLES)
      .and(Sanitizers.IMAGES)
      .and(Sanitizers.TABLES);
    assertEquals("<table></table>Hallo\r\n\nEnde\n\r", pf.sanitize(input));
  }

  @Test
  public static final void testAndOrdering() {
    String input = ""
        + "xss<a href=\"http://www.google.de\" style=\"color:red;\""
        + " onmouseover=alert(1) onmousemove=\"alert(2)\" onclick=alert(3)>"
        + "g"
        + "<img src=\"http://example.org\"/>oogle</a>";
    String want = ""
        + "xss<a href=\"http://www.google.de\" style=\"color:red\""
        + " rel=\"nofollow\">"
        + "g"
        + "<img src=\"http://example.org\" />oogle</a>";

    for (List<PolicyFactory> permutation :
         new Permutations<PolicyFactory>(
             Sanitizers.BLOCKS,
             Sanitizers.IMAGES,
             Sanitizers.STYLES,
             Sanitizers.LINKS
         )) {
      PolicyFactory policyFactory = permutation.get(0);
      for (PolicyFactory p : permutation.subList(1, permutation.size())) {
        policyFactory = policyFactory.and(p);
      }
      String got = policyFactory.sanitize(input);
      assertEquals(permutation.toString(), want, got);
    }
  }

  static int fac(int n) {
    int ifac = 1;
    for (int i = 1; i <= n; ++i) {
      int ifacp = ifac * i;
      if (ifacp < ifac) { throw new IllegalArgumentException("undeflow"); }
      ifac = ifacp;
    }
    return ifac;
  }

  /**
   * An iterable over the length k partial permutations of elements where all
   * elements are assumed distinct.
   */
  private static class Permutations<T> implements Iterable<List<T>> {
    final ImmutableList<T> elements;
    /** Permutation size. */
    final int k;

    Permutations(T... elements) {
      this(elements.length, elements);
    }

    Permutations(int k, T... elements) {
      this.k = k;
      this.elements = ImmutableList.copyOf(elements);
    }

    public Iterator<List<T>> iterator() {
      return new Iterator<List<T>>() {
        private int i;
        private final int limit;
        private final BitSet mask;
        private List<T> pending;

        {
          this.limit = fac(elements.size()) / fac(elements.size() - k);
          this.mask = new BitSet(k);
        }

        public void remove() { throw new UnsupportedOperationException(); }

        public boolean hasNext() {
          fill();
          return pending != null;
        }

        public List<T> next() {
          fill();
          List<T> result = pending;
          if (result == null) { throw new NoSuchElementException(); }
          pending = null;
          return result;
        }

        private void fill() {
          if (pending != null || i == limit) { return; }

          List<T> permutation = Lists.newArrayListWithCapacity(k);
          mask.clear();

          for (int j = 0, p = i; j < k; ++j) {
            int m = k - j;  // Number of remaining elements.
            int x = p % m;
            p /= m;

            // x is now an index into an els but without any elements indexed by
            // indices[0:j] so find the x-th unfilled spot.
            int unfilled = -1;
            while (true) {
              unfilled = mask.nextClearBit(unfilled + 1);
              if (x == 0) { break; }
              --x;
            }
            mask.set(unfilled);

            permutation.add(elements.get(unfilled));
          }
          pending = permutation;
          ++i;
        }
      };
    }
  }
}
