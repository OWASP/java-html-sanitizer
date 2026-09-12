// Copyright (c) 2011, Mike Samuel
// All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause
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

import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.annotation.Nullable;

import java.io.StringReader;
import java.util.Collections;
import java.util.regex.Pattern;

import nu.validator.htmlparser.dom.HtmlDocumentBuilder;
import org.junit.jupiter.api.Test;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.junit.jupiter.api.Assertions.fail;


class HtmlSanitizerTest {

  private static String nest(String inner, int depth) {
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < depth; ++i) { sb.append("<div>"); }
    sb.append(inner);
    for (int i = 0; i < depth; ++i) { sb.append("</div>"); }
    return sb.toString();
  }

  /**
   * Issue #205.  The nesting limit bounds how deep the output nests; it is not
   * a licence to delete content.  Markup nested past the limit used to come
   * out as a well-formed stack of empty elements with the author's text
   * removed from the middle, silently.  It should flatten instead.
   */
  @Test
  void testTextSurvivesPastTheNestingLimit() {
    PolicyFactory p = new HtmlPolicyBuilder().allowElements("div").toFactory();
    for (int depth : new int[] { 100, 255, 256, 257, 300, 1000 }) {
      assertTrue(
          p.sanitize(nest("MARKER", depth)).contains("MARKER"),
          "text should survive at depth " + depth);
    }
    // The output itself stays bounded; it is the text that is kept.
    String deep = p.sanitize(nest("MARKER", 1000));
    assertEquals(256, deep.split("<div>", -1).length - 1);
    assertEquals(256, deep.split("</div>", -1).length - 1);
  }

  /** The element at the 256th level is emitted and must also be closed. */
  @Test
  void testElementAtDefaultNestingLimitRoundTrips() throws Exception {
    PolicyFactory p = new HtmlPolicyBuilder()
        .allowElements("div", "span", "p")
        .allowWithoutAttributes("span")
        .toFactory();
    String input = nest("<span>x</span><p>y</p>", 255);
    String out = p.sanitize(input);

    assertEquals(input, out);
    assertEquals(out, p.sanitize(out));
    assertEquals(parseAsBrowser(input), parseAsBrowser(out));
  }

  /**
   * Issue #205.  Text kept past the limit is still text: it is escaped on the
   * way out and cannot reintroduce markup.
   */
  @Test
  void testTextKeptPastTheNestingLimitIsEscaped() {
    PolicyFactory p = new HtmlPolicyBuilder().allowElements("div").toFactory();
    String out = p.sanitize(nest("1<2 & <img src=x onerror=alert(1)>", 300));
    assertTrue(out.contains("1&lt;2"), out);
    assertFalse(out.contains("<img"), out);
    assertFalse(out.contains("onerror"), out);
  }

  /**
   * Keeping text past the limit must not resurface content the policy would
   * have suppressed.  The policy decides to skip a script or style body when
   * it sees the start tag; a tag the balancer drops never reaches it, so the
   * balancer has to keep that content suppressed itself.
   */
  @Test
  void testSuppressedContentDoesNotResurfacePastTheNestingLimit() {
    PolicyFactory p = new HtmlPolicyBuilder().allowElements("div").toFactory();
    for (String elementName : new String[] {
        "script", "style", "noscript", "nostyle", "noembed", "noframes",
        "iframe", "object", "title" }) {
      String out = p.sanitize(
          nest("<" + elementName + ">SECRET</" + elementName + ">", 300));
      assertFalse(
          out.contains("SECRET"),
          elementName + " content should stay suppressed: " + out);
    }
    // Unbalanced input fails closed rather than open.
    assertFalse(p.sanitize(nest("<script>SECRET", 300)).contains("SECRET"));
    assertFalse(
        p.sanitize(nest("<script><script>SECRET</script></script>", 300))
            .contains("SECRET"));
    // But ordinary text outside the suppressed element still comes through.
    assertTrue(
        p.sanitize(nest("<script>S</script>VISIBLE", 300)).contains("VISIBLE"));

    // The same holds for an element the policy, rather than the fixed list,
    // says to suppress text in: the balancer has to ask the policy.
    PolicyFactory q = new HtmlPolicyBuilder()
        .allowElements("div").disallowTextIn("template").toFactory();
    String deep = nest("<template>SECRET</template>", 300);
    assertFalse(q.sanitize(deep).contains("SECRET"));
    // Also with an HtmlChangeReporter between the balancer and the policy.
    HtmlChangeListener<Object> listener = new HtmlChangeListener<Object>() {
      public void discardedTag(@Nullable Object context, String elementName) {
        // Not under test.
      }
      public void discardedAttributes(
          @Nullable Object context, String tagName, String... attributeNames) {
        // Not under test.
      }
    };
    assertFalse(q.sanitize(deep, listener, null).contains("SECRET"));
    // And the template's text still shows where nothing disallows it.
    assertTrue(p.sanitize(deep).contains("SECRET"));
  }

  /**
   * The balancer forwards tags it does not recognize without counting them
   * toward the nesting limit, so a run of them is the one way to grow the
   * policy's open-element stack without bound.  Nothing on the per-tag or
   * per-text path may walk that stack, or a few hundred kilobytes of unknown
   * tags cost seconds of CPU.  Quadratic behaviour takes minutes here; linear
   * takes a fraction of a second.
   */
  @Test
  void testLongRunOfUnknownTagsIsLinear() {
    PolicyFactory p = new HtmlPolicyBuilder().allowElements("div").toFactory();
    int n = 200_000;
    StringBuilder html = new StringBuilder("<div>");
    StringBuilder expected = new StringBuilder("<div>");
    for (int i = 0; i < n; ++i) {
      html.append("<zz>a");
      expected.append('a');
    }
    for (int i = 0; i < n; ++i) {
      html.append("</zz>");
    }
    html.append("</div>");
    expected.append("</div>");
    String input = html.toString();
    String out = assertTimeoutPreemptively(
        Duration.ofSeconds(20), () -> p.sanitize(input));
    assertEquals(expected.toString(), out);
  }

  /**
   * Issue #205.  A tag dropped for exceeding the nesting limit is discarded
   * from the input, so a listener should hear about it.  The tag balancer runs
   * upstream of the policy, and so upstream of HtmlChangeReporter, so this
   * previously went unreported and the loss was undetectable.
   */
  @Test
  void testNestingLimitReportsDiscardedTags() {
    final List<String> discarded = new ArrayList<>();
    HtmlChangeListener<Object> listener = new HtmlChangeListener<Object>() {
      public void discardedTag(@Nullable Object context, String elementName) {
        discarded.add(elementName);
      }
      public void discardedAttributes(
          @Nullable Object context, String tagName, String... attributeNames) {
        // Not under test.
      }
    };
    PolicyFactory p = new HtmlPolicyBuilder().allowElements("div").toFactory();

    String out = p.sanitize(nest("MARKER", 300), listener, null);
    assertTrue(out.contains("MARKER"));
    // 300 requested, 256 emitted, so 44 were dropped by the limit.
    assertEquals(44, discarded.size(), discarded.toString());
    for (String name : discarded) {
      assertEquals("div", name);
    }

    // Nothing to report when the input stays within the limit.
    discarded.clear();
    p.sanitize(nest("MARKER", 10), listener, null);
    assertEquals(Arrays.asList(), discarded);
  }

  @Test
  void testEmpty() {
    assertEquals("", sanitize(""));
    assertEquals("", sanitize(null));
  }

  @Test
  void testSimpleText() {
    assertEquals("hello world", sanitize("hello world"));
  }

  @Test
  void testEntities1() {
    assertEquals("&lt;hello world&gt;", sanitize("&lt;hello world&gt;"));
  }

  @Test
  void testEntities2() {
    assertEquals("<b>hello <i>world</i></b>",
                 sanitize("<b>hello <i>world</i></b>"));
  }

  @Test
  void testC1NumericReferencesAreWindows1252() {
    // "&#x85;" is an ellipsis in a browser, not the NEL control.  The
    // ellipsis is written back as a reference since its compatibility
    // decomposition is three full stops.
    assertEquals(
        "<b>a&#x2026;b</b>",
        Sanitizers.FORMATTING.sanitize("<b>a&#x85;b</b>"));
    assertEquals(
        "<b>a\u20acb</b>",
        Sanitizers.FORMATTING.sanitize("<b>a&#128;b</b>"));
    // An undefined Windows-1252 byte stays a control and is removed.
    assertEquals(
        "<b>ab</b>",
        Sanitizers.FORMATTING.sanitize("<b>a&#x81;b</b>"));
  }

  @Test
  void testUnknownTagsRemoved() {
    assertEquals("<b>hello <i>world</i></b>",
                 sanitize("<b>hello <bogus></bogus><i>world</i></b>"));
  }

  @Test
  void testUnsafeTagsRemoved() {
    assertEquals("<b>hello <i>world</i></b>",
                 sanitize("<b>hello <i>world</i>"
                          + "<script src=foo.js></script></b>"));
  }

  @Test
  void testUnsafeAttributesRemoved() {
    assertEquals(
        "<b>hello <i>world</i></b>",
        sanitize("<b>hello <i onclick=\"takeOverWorld(this)\">world</i></b>"));
  }

  @Test
  void testCruftEscaped() {
    assertEquals("<b>hello <i>world&lt;</i></b> &amp; tomorrow the universe",
                 sanitize(
                     "<b>hello <i>world<</i></b> & tomorrow the universe"));
  }

  @Test
  void testTagCruftRemoved() {
    assertEquals("<b id=\"p-foo\">hello <i>world&lt;</i></b>",
                 sanitize("<b id=\"foo\" / -->hello <i>world<</i></b>"));
  }

  @Test
  void testIdsAndClassesPrefixed() {
    assertEquals(
        "<b id=\"p-foo\" class=\"p-boo p-bar p-baz\">"
        + "hello <i>world&lt;</i></b>",
        sanitize(
            "<b id=\"foo\" class=\"boo bar baz\">hello <i>world<</i></b>"));
  }

  @Test
  void testSpecialCharsInAttributes() {
    assertEquals(
        "<b title=\"a&lt;b &amp;&amp; c&gt;b\">bar</b>",
        sanitize("<b title=\"a<b && c>b\">bar</b>"));
  }

  @Test
  void testUnclosedTags() {
    assertEquals("<div id=\"p-foo\">Bar<br />Baz</div>",
                 sanitize("<div id=\"foo\">Bar<br>Baz"));
  }

  @Test
  void testUnopenedTags() {
    assertEquals("Foo<b>Bar</b>Baz",
                 sanitize("Foo<b></select>Bar</b></b>Baz</select>"));
  }

  @Test
  void testUnsafeEndTags() {
    assertEquals(
        "",
        sanitize(
            "</meta http-equiv=\"refesh\""
            + " content=\"1;URL=http://evilgadget.com\">"));
  }

  @Test
  void testEmptyEndTags() {
    assertEquals("<input />", sanitize("<input></input>"));
  }

  @Test
  void testOnLoadStripped() {
    assertEquals(
        "<img />",
        sanitize("<img src=http://foo.com/bar ONLOAD=alert(1)>"));
  }

  @Test
  void testClosingTagParameters() {
    assertEquals(
        "<p>Hello world</p>",
        sanitize("<p>Hello world</b style=\"width:expression(alert(1))\">"));
  }

  @Test
  void testOptionalEndTags() {
    // Should not be
    //     "<ol> <li>A</li> <li>B<li>C </li></li></ol>"
    // The difference is significant because in the first, the item contains no
    // space after 'A", but in the third, the item contains 'C' and a space.
    assertEquals(
        "<ol><li>A</li><li>B</li><li>C </li></ol>",
        sanitize("<ol> <li>A</li> <li>B<li>C </ol>"));
  }

  @Test
  void testFoldingOfHtmlAndBodyTags() {
    assertEquals(
        "<p>P 1</p>",
        sanitize("<html><head><title>Foo</title></head>"
                 + "<body><p>P 1</p></body></html>"));
    assertEquals(
        "Hello",
        sanitize("<body bgcolor=\"blue\">Hello</body>"));
    assertEquals(
        "<p>Foo</p><p>One</p><p>Two</p>Three<p>Four</p>",
        sanitize(
            "<html>"
            + "<head>"
            + "<title>Blah</title>"
            + "<p>Foo</p>"
            + "</head>"
            + "<body>"
            + "<p>One"
            + "<p>Two</p>"
            + "Three"
            + "<p>Four</p>"
            + "</body>"
            + "</html>"));
  }

  @Test
  void testEmptyAndValuelessAttributes() {
    assertEquals(
        "<input checked=\"checked\" type=\"checkbox\" id=\"\" class=\"\" />",
        sanitize("<input checked type=checkbox id=\"\" class=>"));
  }

  @Test
  void testAllowedAttributes() {
    assertEquals(
            "<div __foo=\"__foo\" __bar=\"foo\" foo-bar=\"foo-bar\"></div>",
            sanitize("<div __foo __bar=\"foo\" foo-bar></div>"));
  }

  @Test
  void testSgmlShortTags() {
    // We make no attempt to correctly handle SGML short tags since they are
    // not implemented consistently across browsers, and have been removed from
    // HTML 5.
    //
    // According to http://www.w3.org/QA/2007/10/shorttags.html
    //      Shorttags - the odd side of HTML 4.01
    //      ...
    //      It uses an ill-known feature of SGML called shorthand markup, which
    //      was authorized in HTML up to HTML 4.01. But what used to be a "cool"
    //      feature for SGML experts becomes a liability in HTML, where the
    //      construct is more likely to appear as a typo than as a conscious
    //      choice.
    //
    //      All could be fine if this form typo-that-happens-to-be-legal was
    //      properly implemented in contemporary HTML user-agents. It is not.
    // Short-tag discarded, and since the input ends inside the tag, the tag
    // goes with it, as in a browser (#410).
    assertEquals("", sanitize("<p/b/"));
    assertEquals("<p></p>", sanitize("<p<b>"));  // Discard <b attribute
    assertEquals(
        // This behavior for short tags is not ideal, but it is safe.  The
        // "</>" is nothing to a browser, and nothing here (#410).
        "<p href=\"/\">first part of the text second part</p>",
        sanitize("<p<a href=\"/\">first part of the text</> second part"));
  }

  @Test
  void testNul() {
    assertEquals(
        "<a title="
        + "\"harmless  SCRIPT&#61;javascript:alert(1) ignored&#61;ignored\">"
        + "</a>",
        sanitize(
            "<A TITLE="
            + "\"harmless\0  SCRIPT=javascript:alert(1) ignored=ignored\">"
            ));
  }

  @Test
  void testDigitsInAttrNames() {
    // See bug 614 for details.
    assertEquals(
        "<div>Hello</div>",
        sanitize(
            "<div style1=\"expression(\'alert(1)\")\">Hello</div>"
            ));
  }

  @Test
  void testSupplementaryCodepointEncoding()
      {
    // &#xd87e;&#xdc1a; is not appropriate.
    // &#x2f81a; is appropriate as is the unencoded form.
    assertEquals(
        "&#x2f81a; | &#x2f81a; | &#x2f81a;",
        sanitize("&#x2F81A; | \ud87e\udc1a | &#xd87e;&#xdc1a;"));
  }

  @Test
  void testDeeplyNestedTagsDoS() {
    String sanitized = sanitize(stringRepeatedTimes("<div>", 20000));
    int n = sanitized.length() / "<div></div>".length();
    assertTrue(50 <= n && n <= 1000, "" + n);
    int middle = n * "<div>".length();
    assertEquals(sanitized.substring(0, middle),
                 stringRepeatedTimes("<div>", n));
    assertEquals(sanitized.substring(middle),
                 stringRepeatedTimes("</div>", n));
  }

  @Test
  void testInnerHTMLIE8() {
    // Apparently, in quirks mode, IE8 does a poor job producing innerHTML
    // values.  Given
    //     <div attr="``foo=bar">
    // we encode &#96; but if JavaScript does:
    //    nodeA.innerHTML = nodeB.innerHTML;
    // and nodeB contains the DIV above, then IE8 will produce
    //     <div attr=``foo=bar>
    // as the value of nodeB.innerHTML and assign it to nodeA.
    // IE8's HTML parser treats `` as a blank attribute value and foo=bar
    // becomes a separate attribute.
    // Adding a space at the end of the attribute prevents this by forcing
    // IE8 to put double quotes around the attribute when computing
    // nodeB.innerHTML.
    assertEquals(
        "<div title=\"&#96;&#96;onmouseover&#61;alert(1337) \"></div>",
        sanitize("<div title=\"``onmouseover=alert(1337)\">"));
  }

  @Test
  void testNabobsOfNegativism() {
    // Treating <noscript> as raw-text gains us nothing security-wise
    // and we don't want to push tag content outside.
    assertEquals("<noscript></noscript>",
                 sanitize("<noscript><evil></noscript>"));
    assertEquals("<noscript>I <b>&lt;3</b> Ponies</noscript>",
                 sanitize("<noscript>I <b><3</b> Ponies</noscript>"));
    assertEquals("<noscript>I <b>&lt;3</b> Ponies</noscript>",
                 sanitize("<NOSCRIPT>I <b><3</b> Ponies</noscript><evil>"));
    assertEquals("<noframes>I <b>&lt;3</b> Ponies</noframes>",
                 sanitize("<noframes>I <b><3</b> Ponies</noframes><evil>"));
    assertEquals("<noembed>I <b>&lt;3</b> Ponies</noembed>",
                 sanitize("<noembed>I <b><3</b> Ponies</noembed><evil>"));
    assertEquals("<noxss>I <b>&lt;3</b> Ponies</noxss>",
                 sanitize("<noxss>I <b><3</b> Ponies</noxss><evil>"));
    assertEquals(
        "&lt;noscript&gt;I &lt;b&gt;&lt;3&lt;/b&gt; Ponies&lt;/noscript&gt;",
        sanitize("<xmp><noscript>I <b><3</b> Ponies</noscript></xmp>"));
  }

  @Test
  void testNULs() {
    assertEquals("<b>Hello, </b>", sanitize("<b>Hello, \u0000</b>"));
    assertEquals("<b>Hello, </b>", sanitize("<b>Hello, \u0000"));
    assertEquals("",               sanitize("\u0000"));
    assertEquals("<b>Hello, </b>", sanitize("<b>Hello, &#0;</b>"));
    assertEquals("",               sanitize("&#0;"));
  }

  @Test
  void testDegenerateComments() {
    // Issue #258: a comment opened by <!-- and closed by --!> after nothing
    // but dashes must not swallow the rest of the document.
    assertEquals("<b>after</b>", sanitize("<!----!><b>after</b>"));
    assertEquals("<b>after</b>", sanitize("<!-----!><b>after</b>"));
    // <!-> is an empty bogus comment, not a directive that runs to the
    // next '>' and eats the following tag.
    assertEquals("c<b>after</b>", sanitize("<!->c<b>after</b>"));
    // Other complete empty comments.
    assertEquals("x", sanitize("<!>x"));
    assertEquals("x", sanitize("<!-->x"));
    assertEquals("x", sanitize("<!--->x"));
    // Fewer than two dashes after <!-- leave !> as comment content, so the
    // comment runs to the end of input, as it does in a browser.
    assertEquals("", sanitize("<!--!><b>after</b>"));
    assertEquals("", sanitize("<!---!><b>after</b>"));
    // Only a contiguous --> or --!> closes a comment; a lone dash followed
    // later by -> does not, so these comments also run to end of input.
    assertEquals("", sanitize("<!-- a -x-><b>after</b>"));
    assertEquals("", sanitize("<!-- a --b-><b>after</b>"));
    assertEquals("<b>after</b>", sanitize("<!-- a -x--><b>after</b>"));
  }

  @Test
  void testQMarkMeta() {
    assertEquals(
        "Hello, <b>World</b>!",
        sanitize(
            ""
            // An XML Prologue.
            // HTML5 treats it as ignorable content via the bogus comment state.
            + "<?xml version=\"1\" ?>"
            + "Hello, "
            // An XML Processing instruction.
            // HTML5 treats it as ignorable content via the bogus comment state.
            + "<?processing instruction?>"
            + "<b>World"
            // Appears in HTML copied from outlook.
            + "<?xml:namespace prefix = o ns = "
            + "\"urn:schemas-microsoft-com:office:office\" />"
            + "</b>!"));
  }

  @Test
  void testScriptInIframe() {
    assertEquals(
        "<iframe></iframe>",
        sanitize(
            "<iframe>\n"
            + "  <script>alert(Hi)</script>\n"
            + "</iframe>"));
  }

  @Test
  void testBalancingOfEmptyTags() {
    assertEquals(
        "<span style=\"color:rgb( 72 , 72 , 72 );font-family:&#39;helveticaneue&#39;\">"
        + " "
        + "my \u00A0"
        + " list of style names or a "
        + "</span>",
        sanitize(
            "<span style=\"color:rgb(72, 72, 72); font-family:helveticaneue\">"
            + " "
            + "<span>my &nbsp;</span>"
            + " list of style names or a "
            + "</span>"));
  }

  @Test
  void testDuplicateAttributes() {
    assertEquals(
        sanitize("<br id=\"foo\">"),
        sanitize("<br id=foo id=bar>"));
  }

  @Test
  void testNbsps() {
    String input =
        "test&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;bob";

    PolicyFactory policy = new HtmlPolicyBuilder()
        .toFactory();

    String got = policy.sanitize(input);
    int[] codeUnits = new int[got.length()];
    for (int i = 0, n = got.length(); i < n; ++i) {
      codeUnits[i] = got.charAt(i);
    }

    assertArrayEquals(
        new int[] {
            116, 101, 115, 116,
            160, 160, 160, 160, 160, 160, 160, 160,
            98, 111, 98,
        },
        codeUnits,
        Arrays.toString(codeUnits));
  }


  @Test
  void testIssue254SemicolonlessNamedCharactersInUrls() {
    String input = "<a href=\"/test/?param1=valueOne&param2=valueTwo\">click me</a>";
    String want = "<a href=\"/test/?param1&#61;valueOne&amp;param2&#61;valueTwo\">click me</a>";
    assertEquals(want, sanitize(input));
  }

  @Test
  void testStylingCornerCase() {
    String input = "<a style=\\006-\\000038";
    String want = "";
    assertEquals(want, sanitize(input));
  }

  /**
   * These 5 tests cover regression scenarios for CVE-2025-66021, which relates to
   * improper sanitization of HTML content involving <style> and <noscript> tags.
   * The tests ensure that HTMLSanitizer:
   *   - properly closes any opened elements,
   *   - only allows allowed elements inside <style> blocks,
   *   - prevents injection of forbidden HTML or scripts within style or noscript,
   *   - does not allow unexpected element escape or context breaking.
   */

  /**
   * Test #1:
   * Verify that unallowed elements (<div>) injected inside <style> are removed,
   * and only allowed content (CSS and allowed elements) remain.
   */
  @Test
  void testCVE202566021_1() {
    // Arrange: Attempt to inject a <div> inside <style>. Only 'style' and 'noscript' are allowed.
    String actualPayload = "<noscript><style>/* user content */.x { font-size: 12px; }<div id=\"evil\">XSS?</div></style></noscript>";
    String expectedPayload = "<noscript><style>/* user content */.x { font-size: 12px; }</style></noscript>";

    HtmlPolicyBuilder htmlPolicyBuilder = new HtmlPolicyBuilder();
    PolicyFactory policy = htmlPolicyBuilder
        .allowElements("style", "noscript")
        .allowTextIn("style")
        .toFactory();

    // Act
    String sanitized = policy.sanitize(actualPayload);

    // Assert
    assertEquals(expectedPayload, sanitized);
  }

  /**
   * Test #2:
   * Ensure that <script> tags (attempting script injection) are stripped out
   * even when they appear inside allowed <style> tags.
   */
  @Test
  void testCVE202566021_2() {
    // Arrange: Attempt to inject a <script> inside <style>. Only 'style' and 'noscript' are allowed.
    String actualPayload = "<noscript><style>/* user content */.x { font-size: 12px; }<script>alert('XSS Attack!')</script></style></noscript>";
    String expectedPayload = "<noscript><style>/* user content */.x { font-size: 12px; }</style></noscript>";

    HtmlPolicyBuilder htmlPolicyBuilder = new HtmlPolicyBuilder();
    PolicyFactory policy = htmlPolicyBuilder
        .allowElements("style", "noscript")
        .allowTextIn("style")
        .toFactory();

    // Act
    String sanitized = policy.sanitize(actualPayload);

    // Assert
    assertEquals(expectedPayload, sanitized);
  }

  /**
   * Test #3:
   * A tag inside style text is text to a browser, never markup, so even an
   * allowed element's tag goes, content and all.  It used to be copied
   * through with its attributes unvetted, which is how an event handler
   * could follow the breakout in test #7.
   */
  @Test
  void testCVE202566021_3() {
    // Arrange: <div> is allowed as an element, which buys it nothing as style text.
    String actualPayload = "<noscript><style>/* user content */.x { font-size: 12px; }<div id=\"good\">ALLOWED?</div></style></noscript>";
    String expectedPayload = "<noscript><style>/* user content */.x { font-size: 12px; }</style></noscript>";

    HtmlPolicyBuilder htmlPolicyBuilder = new HtmlPolicyBuilder();
    PolicyFactory policy = htmlPolicyBuilder
        .allowElements("style", "noscript", "div")
        .allowTextIn("style")
        .toFactory();

    // Act
    String sanitized = policy.sanitize(actualPayload);

    // Assert
    assertEquals(expectedPayload, sanitized);
  }

  /**
   * Test #4:
   * Confirm that an attempt to prematurely close <style> with </noscript>, then inject a script,
   * does not allow the injected script.  The </noscript> goes too: a browser
   * with scripting on reads noscript as raw text up to the first </noscript>
   * and parses whatever follows as markup, so no end tag may survive in
   * style text, whatever element it names.
   */
  @Test
  void testCVE202566021_4() {
    // Arrange: Try to break out of <style> and <noscript>, then add a script. Only style/noscript/p allowed.
    String actualPayload = "<noscript><style></noscript><script>alert(1)</script>";
    String expectedPayload = "<noscript><style></style></noscript>";

    HtmlPolicyBuilder htmlPolicyBuilder = new HtmlPolicyBuilder();
    PolicyFactory policy = htmlPolicyBuilder
        .allowElements("style", "noscript", "p")
        .allowTextIn("style")
        .toFactory();

    // Act
    String sanitized = policy.sanitize(actualPayload);

    // Assert
    assertEquals(expectedPayload, sanitized);
  }

  /**
   * Test #5:
   * Like Test #4, but with <p> instead of <noscript>. Ensures sanitizer emits correctly closed tags
   * and strips the injected script tag completely.  The </p> in the style
   * text goes like every other end tag there, allowed element or not.
   */
  @Test
  void testCVE202566021_5() {
    // Arrange: Try to break out of <style> through <p>, then add a script. Only style/noscript/p allowed.
    String actualPayload = "<p><style></p><script>alert(1)</script>";
    String expectedPayload = "<p><style></style></p>";

    HtmlPolicyBuilder htmlPolicyBuilder = new HtmlPolicyBuilder();
    PolicyFactory policy = htmlPolicyBuilder
        .allowElements("style", "noscript", "p")
        .allowTextIn("style")
        .toFactory();

    // Act
    String sanitized = policy.sanitize(actualPayload);

    // Assert
    assertEquals(expectedPayload, sanitized);
  }

  /**
   * Test that <script> tags with space < script> are sanitized correctly.
   */
  @Test
  void testCVE202566021_6() {
    // Arrange: Attempt to inject a <script> inside <style>. Only 'style' and 'noscript' elements are allowed.
    String actualPayload = "<noscript><style>/* user content */.x { font-size: 12px; }< script>alert('XSS Attack!')</script></style></noscript>";
    String expectedPayload = "<noscript><style>/* user content */.x { font-size: 12px; }</style></noscript>";

    HtmlPolicyBuilder htmlPolicyBuilder = new HtmlPolicyBuilder();
    PolicyFactory policy = htmlPolicyBuilder
        .allowElements("style", "noscript")
        .allowTextIn("style")
        .toFactory();

    // Act
    String sanitized = policy.sanitize(actualPayload);

    // Assert
    assertEquals(expectedPayload, sanitized);
  }

  /**
   * Test #7:
   * An allowed element's start tag inside style text used to be copied
   * through with its attributes unvetted, and an end tag was kept when its
   * element was allowed.  Together they let an event handler follow a
   * {@code </noscript>} that a browser with scripting on honours as the end
   * of the raw-text noscript.  Neither survives.
   */
  @Test
  void testCVE202566021_7AllowedElementInStyleTextKeepsNoAttributes() {
    PolicyFactory policy = new HtmlPolicyBuilder()
        .allowElements("noscript", "style", "img", "b")
        .allowTextIn("style")
        .allowAttributes("src").onElements("img")
        .allowUrlProtocols("https")
        .toFactory();

    assertEquals(
        "<noscript><style></style></noscript>",
        policy.sanitize(
            "<noscript><style></noscript>"
            + "<img src=x onerror=alert(1)></style></noscript>"));
    assertEquals(
        "<noscript><style></style></noscript>",
        policy.sanitize(
            "<noscript><style></noscript>"
            + "<b onmouseover=alert(1)>x</b></style></noscript>"));
    // Outside any noscript the same tag is harmless, and treated the same.
    assertEquals(
        "<style></style>",
        policy.sanitize("<style><img src=x onerror=alert(1)></style>"));
  }

  /**
   * Test #8:
   * noframes and noembed are raw text to a browser whether or not scripting
   * is on, so they break out the same way, and every spelling of an end tag
   * a browser accepts has to go: any case, trailing whitespace, or a slash
   * before the {@code >}.
   */
  @Test
  void testCVE202566021_8EveryEndTagLeavesStyleText() {
    PolicyFactory policy = new HtmlPolicyBuilder()
        .allowElements("noframes", "noembed", "style", "b")
        .allowTextIn("style")
        .toFactory();

    assertEquals(
        "<noframes><style></style></noframes>",
        policy.sanitize(
            "<noframes><style></noframes>"
            + "<b onmouseover=alert(1)>x</b></style></noframes>"));
    assertEquals(
        "<noembed><style></style></noembed>",
        policy.sanitize(
            "<noembed><style></NOEMBED ><b onclick=alert(1)>x</b>"
            + "</style></noembed>"));
    assertEquals(
        "<style>a{} b{}</style>",
        policy.sanitize("<style>a{} </noembed/></div></ b>b{}</style>"));
  }

  /**
   * Test #9:
   * iframe content is literal to the renderer too, and used to escape the
   * filter, which looked only for style and script.
   */
  @Test
  void testCVE202566021_9IframeContent() {
    PolicyFactory policy = new HtmlPolicyBuilder()
        .allowElements("noscript", "iframe", "img")
        .allowTextIn("iframe")
        .allowAttributes("src").onElements("img")
        .allowUrlProtocols("https")
        .toFactory();

    assertEquals(
        "<noscript><iframe></iframe></noscript>",
        policy.sanitize(
            "<noscript><iframe></noscript>"
            + "<img src=x onerror=alert(1)></iframe></noscript>"));
  }

  /**
   * Test #10:
   * The IE-only comment element was read as raw text, but no current
   * browser reads it so: its content is markup to all of them.  It used to
   * be emitted unescaped, so a tag inside it reached the browser unvetted,
   * and a start tag with no {@code >} of its own was completed by the
   * {@code >} of the sanitizer's own end tag.  Its content is now parsed,
   * vetted and escaped like any other element's.
   */
  @Test
  void testCVE202566021_10CommentElementIsNotLiteralContent() {
    PolicyFactory policy = new HtmlPolicyBuilder()
        .allowElements("comment", "img")
        .allowTextIn("comment")
        .allowAttributes("src").onElements("img")
        .allowUrlProtocols("https")
        .toFactory();

    assertEquals(
        "<comment><img src=\"x\" /></comment>",
        policy.sanitize("<comment><img src=x onerror=alert(1)></comment>"));
    assertEquals(
        "<comment>x<img src=\"x\" /></comment>",
        policy.sanitize(
            "<comment>x<img src=x onerror=alert(1)//</comment>"));
    assertEquals(
        "<comment>a &lt;b&gt; c</comment>",
        policy.sanitize("<comment>a &lt;b&gt; c</comment>"));
  }

  /**
   * Test #11:
   * Text reaches the policy in chunks whose boundaries fall anywhere, so a
   * chunk that ends in {@code <}, or holds {@code </} with no {@code >},
   * must not combine with the next chunk into an end tag.  A preprocessor
   * that delivers one character at a time is the extreme case.
   */
  @Test
  void testCVE202566021_11ChunkBoundariesCannotAssembleAnEndTag() {
    PolicyFactory policy = new HtmlPolicyBuilder()
        .allowElements("noscript", "style", "img")
        .allowTextIn("style")
        .allowAttributes("src").onElements("img")
        .withPreprocessor(r -> new HtmlStreamEventReceiverWrapper(r) {
          @Override
          public void text(String text) {
            for (int i = 0, n = text.length(); i < n; ++i) {
              underlying.text(text.substring(i, i + 1));
            }
          }
        })
        .toFactory();

    assertEquals(
        "<noscript><style>/noscript>img src=x onerror=alert(1)>"
        + "</style></noscript>",
        policy.sanitize(
            "<noscript><style></noscript>"
            + "<img src=x onerror=alert(1)></style></noscript>"));
  }

  /**
   * Test #12:
   * A {@code <} that opens no tag used to carry everything up to the next
   * {@code >} through as text, and that {@code >} could belong to an end tag
   * inside the span, so {@code <</noscript>} and {@code < </noscript>} kept
   * the breakout that a bare {@code </noscript>} lost.  The original fix had
   * the same hole.  The scan now resumes right after such a {@code <}.
   */
  @Test
  void testCVE202566021_12EndTagBehindAStrayBracket() {
    PolicyFactory policy = noscriptStyleImg();

    assertEquals(
        "<noscript><style></style></noscript>",
        policy.sanitize(
            "<noscript><style><</noscript>"
            + "<<img src=x onerror=alert(1)></style></noscript>"));
    assertEquals(
        "<noscript><style>< </style></noscript>",
        policy.sanitize(
            "<noscript><style>< </noscript>"
            + "<img src=x onerror=alert(1)></style></noscript>"));
    assertEquals(
        "<noscript><style><3</style></noscript>",
        policy.sanitize(
            "<noscript><style><3</noscript>"
            + "<img src=x onerror=alert(1)></style></noscript>"));
    assertEquals(
        "<noscript><style><??></style></noscript>",
        policy.sanitize(
            "<noscript><style><?</noscript>"
            + "<img src=x onerror=alert(1)>?></style></noscript>"));
    assertEquals(
        "<noscript><style><!----></style></noscript>",
        policy.sanitize(
            "<noscript><style><!--</noscript>"
            + "<img src=x onerror=alert(1)>--></style></noscript>"));
    // The dropped tag takes a '<' just before it along: "<" + "/noscript>"
    // would otherwise be an end tag again.
    assertEquals(
        "<noscript><style>/noscript></style></noscript>",
        policy.sanitize(
            "<noscript><style><<b>/noscript></style></noscript>"));
  }

  /**
   * Test #13:
   * Once a breakout has put a browser in a markup state, a start tag left
   * without its {@code >} inside the literal text is completed by the
   * {@code >} of the sanitizer's own end tag.  A dangling {@code <} goes
   * unless HTML whitespace follows it, which starts no tag in any browser
   * state.
   */
  @Test
  void testCVE202566021_13DanglingBracketBeforeTheEndTag() {
    PolicyFactory policy = noscriptStyleImg();

    assertEquals(
        "<noscript><style>< img src=y onerror=alert(1)</style></noscript>",
        policy.sanitize(
            "<noscript><style>< </noscript>"
            + "<img src=y onerror=alert(1)</style></noscript>"));
    assertEquals(
        "<style>a { } b < c</style>",
        policy.sanitize("<style>a { } b < c</style>"));
  }

  /**
   * Test #14:
   * The lexer hands the content of a literal element over in more than one
   * chunk when a server-side script tag {@code <%...%>} sits in it, so the
   * pieces of an end tag or a start tag can arrive in different chunks, and
   * each chunk has to drop its own dangling {@code <}.
   */
  @Test
  void testCVE202566021_14ChunksSplitByServerCode() {
    assertEquals(
        "<noscript><style>/noscript>img src=x onerror=alert(1)>"
        + "</style></noscript>",
        noscriptStyleImg().sanitize(
            "<noscript><style><<<%%>/noscript><<<%%>"
            + "img src=x onerror=alert(1)></style></noscript>"));
  }

  /**
   * Test #15:
   * Text re-chunked by a preprocessor into fixed-size blocks, which can
   * split a tag anywhere, still leaves nothing in the literal text that a
   * browser could read as an end tag or as a start tag.
   */
  @Test
  void testCVE202566021_15FixedSizeRechunking() {
    for (final int size : new int[] { 1, 2, 3, 5, 7, 16 }) {
      PolicyFactory policy = new HtmlPolicyBuilder()
          .allowElements("noscript", "style", "img")
          .allowTextIn("style")
          .allowAttributes("src").onElements("img")
          .withPreprocessor(r -> new HtmlStreamEventReceiverWrapper(r) {
            @Override
            public void text(String text) {
              for (int i = 0, n = text.length(); i < n; i += size) {
                underlying.text(text.substring(i, Math.min(n, i + size)));
              }
            }
          })
          .toFactory();
      for (String html : new String[] {
              "<noscript><style><</noscript>"
              + "<<img src=x onerror=alert(1)></style></noscript>",
              "<noscript><style>< </noscript>"
              + "<img src=y onerror=alert(1)</style></noscript>",
           }) {
        String out = policy.sanitize(html);
        String styleText = out.substring(
            out.indexOf("<style>") + 7, out.indexOf("</style>"));
        assertFalse(styleText.contains("</"), size + ": " + out);
        assertFalse(
            Pattern.compile("<[a-zA-Z]").matcher(styleText).find(),
            size + ": " + out);
      }
    }
  }

  /**
   * Test #16:
   * The renderer itself refuses literal content holding the end tag of an
   * element that a browser reads as raw text, so a policy that never runs
   * the filter, such as one built by hand on {@code PolicyFactory.apply},
   * is covered too.
   */
  @Test
  void testCVE202566021_16RendererRefusesContainerEndTags() {
    for (String name
         : new String[] { "noscript", "NOSCRIPT", "noframes", "noembed" }) {
      StringBuilder sb = new StringBuilder();
      HtmlStreamRenderer r = HtmlStreamRenderer.create(sb, Handler.DO_NOTHING);
      r.openDocument();
      r.openTag("style", Collections.<String>emptyList());
      r.text("a{} </" + name + "><img src=x onerror=alert(1)> b{}");
      r.closeTag("style");
      r.closeDocument();
      assertEquals("<style></style>", sb.toString(), name);
    }
    // Names that only start alike are left alone.
    StringBuilder sb = new StringBuilder();
    HtmlStreamRenderer r = HtmlStreamRenderer.create(sb, Handler.DO_NOTHING);
    r.openDocument();
    r.openTag("style", Collections.<String>emptyList());
    r.text("a{} </noscripts> </no b{}");
    r.closeTag("style");
    r.closeDocument();
    assertEquals("<style>a{} </noscripts> </no b{}</style>", sb.toString());
  }

  /** Allows noscript, style with its text, and img with src. */
  private static PolicyFactory noscriptStyleImg() {
    return new HtmlPolicyBuilder()
        .allowElements("noscript", "style", "img")
        .allowTextIn("style")
        .allowAttributes("src").onElements("img")
        .allowUrlProtocols("https")
        .toFactory();
  }

  /**
   * A chunk of literal text full of start tags with no end tags is the
   * worst case for pairing tags, since every one is searched for a match.
   * Pairing is done in one pass, so this takes a fraction of a second; a
   * search restarted from each tag takes minutes.
   */
  @Test
  void testLongRunOfUnmatchedTagsInLiteralTextIsLinear() {
    PolicyFactory p = new HtmlPolicyBuilder()
        .allowElements("style").allowTextIn("style").toFactory();
    int n = 200_000;
    final String html = "<style>" + stringRepeatedTimes("<b>x", n) + "</style>";
    String expected = "<style>" + stringRepeatedTimes("x", n) + "</style>";

    String out = assertTimeoutPreemptively(
        Duration.ofSeconds(20), () -> p.sanitize(html));
    assertEquals(expected, out);
  }

  /** Invalid tag openings must not repeatedly rescan the same long suffix. */
  @Test
  void testLongRunOfStrayBracketsInLiteralTextIsLinear() {
    PolicyFactory p = new HtmlPolicyBuilder()
        .allowElements("style").allowTextIn("style").toFactory();
    int n = 1_000_000;
    String brackets = stringRepeatedTimes("<", n);
    final String html = "<style>" + brackets + "></style>";

    String out = assertTimeoutPreemptively(
        Duration.ofSeconds(20), () -> p.sanitize(html));
    assertEquals(html, out);
  }

  /** Removing a tag must not turn preceding brackets into a new start tag. */
  @Test
  void testTagRemovalTakesAllAdjacentOpeningBrackets() {
    PolicyFactory p = new HtmlPolicyBuilder()
        .allowElements("style").allowTextIn("style").toFactory();

    assertEquals(
        "<style>img src=x onerror=alert(1)></style>",
        p.sanitize("<style><<<b>img src=x onerror=alert(1)></style>"));
  }

  /**
   * The worst case for the sweep that keeps a removal from leaving a tag
   * behind: a long run of what could be the start of one, ended by a tag that
   * goes.  Every {@code <} of the run goes with it, and the run is rewritten
   * once rather than closed up around each, which would be quadratic: this
   * text takes well under a second, where closing up each takes half a minute.
   */
  @Test
  void testLongRunOfUnfinishedTagsInLiteralTextIsLinear() {
    PolicyFactory p = new HtmlPolicyBuilder()
        .allowElements("style", "svg").allowTextIn("style").toFactory();
    int n = 1_500_000;
    final String html =
        "<style>" + stringRepeatedTimes("<b", n) + "<svg></style>";

    String out = assertTimeoutPreemptively(
        Duration.ofSeconds(20), () -> p.sanitize(html));
    assertEquals("<style>" + stringRepeatedTimes("b", n) + "</style>", out);
  }

  /**
   * The other worst case for the scan: literal text where no {@code <} opens a
   * tag and the only {@code >} is at the end, so that every {@code <} is
   * looked at and none of them resolves until the last character.  The scan
   * remembers the {@code >} it found rather than looking for the same one
   * again from each {@code <}, which would be quadratic: this text takes
   * under a second, where looking again takes minutes.
   */
  @Test
  void testLiteralTextFullOfBracketsThatOpenNoTagIsLinear() {
    PolicyFactory p = new HtmlPolicyBuilder()
        .allowElements("style").allowTextIn("style").toFactory();
    final String html =
        "<style>" + stringRepeatedTimes("a<b'", 1_000_000) + ">" + "</style>";

    String out = assertTimeoutPreemptively(
        Duration.ofSeconds(20), () -> p.sanitize(html));
    // None of it is a tag, so none of it goes.
    assertEquals(html, out);
  }

  /**
   * The filter no longer discards the rest of a chunk after a start tag with
   * no matching end tag, and keeps a {@code <} that opens no tag, so script
   * and style text with a bare comparison survives.
   */
  @Test
  void testLiteralTextKeepsWhatIsNotATag() {
    PolicyFactory policy = new HtmlPolicyBuilder()
        .allowElements("script", "style")
        .allowTextIn("script", "style")
        .toFactory();

    assertEquals(
        "<script>if (a < b) x();</script>",
        policy.sanitize("<script>if (a < b) x();</script>"));
    // A '<' dangling before a letter at the end of a chunk goes: a later
    // chunk could complete it into a tag.
    assertEquals(
        "<script>if (ab) x();</script>",
        policy.sanitize("<script>if (a<b) x();</script>"));
    // "<b'; var t = 'c>" is a tag only where a browser would read "b';" as a
    // tag name, which is nowhere this text can reach one, so it stays (#470).
    assertEquals(
        "<script>var s = 'a<b'; var t = 'c>d';</script>",
        policy.sanitize("<script>var s = 'a<b'; var t = 'c>d';</script>"));
    assertEquals(
        "<style>a{}c{}</style>",
        policy.sanitize("<style>a{}<b>c{}</style>"));
    // With one, it goes with its content, as a script in a style block does.
    assertEquals(
        "<style>a{}c{}</style>",
        policy.sanitize("<style>a{}<b>x<b>y</b>z</b>c{}</style>"));
    // Not tags: a comment and an empty end tag stay; a bare bracket with no
    // '>' after it in the chunk is dangling and goes.
    assertEquals(
        "<style>a{}<!-- x --></>c3{}</style>",
        policy.sanitize("<style>a{}<!-- x --></>c<3{}</style>"));
    assertEquals(
        "<style>a{}<3>{}</style>",
        policy.sanitize("<style>a{}<3>{}</style>"));
  }

  /**
   * Issue #470.  Ordinary script and style text tripped the filter, which
   * took {@code <} plus anything up to the next {@code >} for a tag, so a
   * comparison or a loop condition lost the text between.  A tag now needs a
   * well-formed name.
   */
  @Test
  void testIssue470ComparisonOperatorsInScriptTextSurvive() {
    PolicyFactory policy = new HtmlPolicyBuilder()
        .allowElements("script", "style")
        .allowTextIn("script", "style")
        .toFactory();

    for (String js : new String[] {
            "if (a < b) { x(); } if (c > d) { y(); }",
            "for(i=0;i<n;i++){a[i]=b>c;}",
            "a = b << 2 >> 1;",
            "if (x<y) { g(); } // z>w",
            "if (a<b){c();}else{d>e;}",
         }) {
      assertEquals("<script>" + js + "</script>",
                   policy.sanitize("<script>" + js + "</script>"), js);
    }
    // CSS keeps its own comparisons, and a media query's parentheses.
    assertEquals(
        "<style>@media (max-width:10px){a{}}</style>",
        policy.sanitize("<style>@media (max-width:10px){a{}}</style>"));
    // What is left: a name followed by whitespace is a tag wherever a browser
    // reads markup, so "<b ||" goes with everything up to the next '>', as
    // the "< script>" that test #6 pins does.  The filter cannot tell them
    // apart, and an end tag hiding there would break out.
    assertEquals(
        "<script>if (ad) f();</script>",
        policy.sanitize("<script>if (a<b || c>d) f();</script>"));
  }

  /**
   * Issue #470.  Relaxing what counts as a tag gives up nothing: a browser
   * reads a weird name as a tag only in a markup context, and the text of a
   * kept literal-content element never reaches one.  Anything that could end
   * such an element for a browser has a well-formed name and still goes,
   * including a name that only becomes one once the renderer elides a
   * character it cannot emit.
   */
  @Test
  void testIssue470OnlyAWellFormedNameMakesATag() {
    PolicyFactory policy = noscriptStyleImg();

    // Names a browser could act on, in every shape an element name takes.
    for (String tag : new String[] {
            "<img src=x onerror=alert(1)>", "<my-widget onmouseover=alert(1)>",
            "<svg:a onmouseover=alert(1)>", "<b2 onmouseover=alert(1)>",
            "<b_c onmouseover=alert(1)>", "<b.c onmouseover=alert(1)>",
            "< img src=x onerror=alert(1)>", "<img/src=x onerror=alert(1)>",
         }) {
      assertEquals(
          "<style>a{}b{}</style>",
          policy.sanitize("<style>a{}" + tag + "b{}</style>"), tag);
    }
    // A name that is not one stays, and is inert: a browser reads the text of
    // a style element literally, and an end tag whose name is not an element's
    // own name does not end it.
    for (String notATag : new String[] {
            "<b) onmouseover=alert(1)>", "<n;i++){a[i]=b>", "<b'x'>",
            "</b) onmouseover=alert(1)>", "</3>",
         }) {
      assertEquals(
          "<style>a{}" + notATag + "b{}</style>",
          policy.sanitize("<style>a{}" + notATag + "b{}</style>"), notATag);
    }
    // The renderer elides a NUL, a DEL and a C1 control, which would
    // otherwise join a name to what follows it, so they end a name instead.
    for (String elided : new String[] { "\u0000", "\u007f", "\u0085" }) {
      assertEquals(
          "<noscript><style></style></noscript>",
          policy.sanitize(
              "<noscript><style></noscript" + elided + ">"
              + "<img src=x onerror=alert(1)></style></noscript>"),
          "U+" + Integer.toHexString(elided.charAt(0)));
      assertEquals(
          "<style>a{}b{}</style>",
          policy.sanitize(
              "<style>a{}<img" + elided + " src=x onerror=alert(1)>b{}"
              + "</style>"));
    }
  }

  /**
   * Issue #473.  The filter kept a record per tag, so a chunk of literal text
   * full of tags cost a multiple of its own size in heap, and text that used
   * to sanitize in 160 MB needed 256 MB.  It now keeps only its output and a
   * bounded note of the start tags it has not matched, so the cost per tag is
   * what the lexer already spends on the same text.
   */
  @Test
  void testIssue473LiteralTextFilterKeepsNoRecordPerTag() {
    java.lang.management.ThreadMXBean threads
        = java.lang.management.ManagementFactory.getThreadMXBean();
    assumeTrue(threads instanceof com.sun.management.ThreadMXBean,
               "needs a JVM that counts allocation per thread");
    com.sun.management.ThreadMXBean counter
        = (com.sun.management.ThreadMXBean) threads;

    int n = 200_000;
    String html = "<style>" + stringRepeatedTimes("<b>x", n) + "</style>";
    // The same text, filtered and not: one policy keeps the text of a style
    // element and filters it, the other drops it, so the difference in what
    // they allocate is the filter's own, without the lexer's share of it.
    PolicyFactory filtering = new HtmlPolicyBuilder()
        .allowElements("style").allowTextIn("style").toFactory();
    PolicyFactory notFiltering = new HtmlPolicyBuilder()
        .allowElements("style").toFactory();
    filtering.sanitize(html);
    notFiltering.sanitize(html);  // Load the classes both use.

    long id = Thread.currentThread().getId();
    long before = counter.getThreadAllocatedBytes(id);
    filtering.sanitize(html);
    long between = counter.getThreadAllocatedBytes(id);
    notFiltering.sanitize(html);
    long after = counter.getThreadAllocatedBytes(id);

    long perTag = ((between - before) - (after - between)) / n;
    // Around 5 bytes a tag, for the output and the string it becomes; a
    // record per tag cost more than 700.
    assertTrue(perTag < 64, perTag + " bytes allocated per tag");
  }

  /**
   * Issue #473.  Pairing a start tag with its end tag keeps a dropped
   * element's content with it, which is fidelity rather than safety, so the
   * filter bounds what it remembers.  Literal text nested deeper than that
   * loses each tag on its own, and still no tag survives.
   */
  @Test
  void testIssue473LiteralTextNestedPastThePairingBoundIsStillTagFree() {
    PolicyFactory policy = new HtmlPolicyBuilder()
        .allowElements("style").allowTextIn("style").toFactory();
    for (int depth : new int[] { 8, 64, 65, 100, 1000 }) {
      String html = "<style>" + stringRepeatedTimes("<b>x", depth)
          + stringRepeatedTimes("</b>", depth) + "</style>";
      String out = policy.sanitize(html);
      String body = out.substring(
          out.indexOf("<style>") + 7, out.lastIndexOf("</style>"));
      assertFalse(body.contains("<"), depth + ": " + out);
      assertFalse(body.contains(">"), depth + ": " + out);
    }
  }

  /**
   * Issue #475.  Removing a tag joins the text on either side of it, which
   * could make a {@code <!--} or a {@code -->} that the input did not have.
   * The renderer refuses the whole content of a literal element whose comment
   * delimiters do not balance, so the element came out empty.  A space goes in
   * where the join would make one.
   */
  @Test
  void testIssue475RemovingATagDoesNotSpliceACommentDelimiter() {
    PolicyFactory policy = new HtmlPolicyBuilder()
        .allowElements("style", "script", "b")
        .allowTextIn("style", "script")
        .toFactory();

    assertEquals(
        "<style>a{}- ->b{}</style>",
        policy.sanitize("<style>a{}-<b>->b{}</style>"));
    assertEquals(
        "<style>a{}-- >b{}</style>",
        policy.sanitize("<style>a{}--<b>>b{}</style>"));
    assertEquals(
        "<style>a<! --x</style>",
        policy.sanitize("<style>a<!<b>--x</style>"));
    assertEquals(
        "<style>a<!- -x</style>",
        policy.sanitize("<style>a<!-<b>-x</style>"));
    // The text on either side of the join can be in different chunks, which
    // the lexer splits at server-side script tags, so the last of a chunk is
    // remembered, and a join at the end of one assumes the worst.
    assertEquals(
        "<style>a{}- ->b{}</style>",
        policy.sanitize("<style>a{}-<%%><b>->b{}</style>"));
    assertEquals(
        "<style>a{}- ->b{}</style>",
        policy.sanitize("<style>a{}-<b><%%>->b{}</style>"));
    // A delimiter the input itself holds is not the filter's to fix: the
    // renderer still refuses the content, and says so.
    assertEquals(
        "<style></style>",
        policy.sanitize("<style>a{}--><b>b{}</style>"));
  }

  /**
   * Issue #475, the other way round: a start tag dropped together with its
   * content can take a {@code -->} with it and leave an earlier {@code <!--}
   * unclosed, which costs the whole content again.  Such a pair is dropped
   * tag by tag instead, so what the comment holds stays.
   */
  @Test
  void testIssue475ADroppedPairDoesNotTakeACommentDelimiter() {
    PolicyFactory policy = new HtmlPolicyBuilder()
        .allowElements("style", "script", "b")
        .allowTextIn("style", "script")
        .toFactory();

    assertEquals(
        "<script><!-- if (a > 0) {  } -->  f();</script>",
        policy.sanitize(
            "<script><!-- if (a > 0) { <b> } --> </b> f();</script>"));
    assertEquals(
        "<style><!-- a --> b </style>",
        policy.sanitize("<style><!-- a<b> --> b </b></style>"));
    // A pair whose content holds no delimiter still goes whole.
    assertEquals(
        "<style>a{}c{}</style>",
        policy.sanitize("<style>a{}<b>x - y</b>c{}</style>"));
  }

  /**
   * Removing a tag must not splice what is on either side of it into another
   * tag, nor leave the element's own end tag to finish one.  A browser reads
   * the text of a kept literal-content element literally, so none of this is
   * reachable, but the filter must not hand one a tag the text did not hold:
   * {@code <b<svg>} is a tag a browser acts on and the text after it is text,
   * while {@code <b} followed by that text is a tag with a live handler.
   */
  @Test
  void testRemovingATagDoesNotSpliceAnotherTag() {
    PolicyFactory policy = new HtmlPolicyBuilder()
        .allowElements("noscript", "style", "script", "svg", "b", "img", "p")
        .allowTextIn("style", "script")
        .allowAttributes("src").onElements("img")
        .allowUrlProtocols("https")
        .toFactory();

    // The "<b" the removed tag followed goes, so the text after it cannot
    // become its attributes.
    assertEquals(
        "<style>b onmouseover=alert(1)>x</style>",
        policy.sanitize("<style><b<svg> onmouseover=alert(1)>x</style>"));
    // Every '<' of the run goes: dropping one leaves the next before a name.
    assertEquals(
        "<style>bb onmouseover=alert(1)>x</style>",
        policy.sanitize("<style><b<b<svg> onmouseover=alert(1)>x</style>"));
    // A "</" before the removed tag would have met the name after it, which
    // is the breakout the filter exists to stop.
    assertEquals(
        "<style>/noscript></style>",
        policy.sanitize("<style></<b>noscript></style>"));
    assertEquals(
        "<noscript><style>/noscript></style></noscript>",
        policy.sanitize(
            "<noscript><style></<b>noscript>"
            + "<img src=x onerror=alert(1)></style></noscript>"));
    // At the end of the text it is the element's own end tag that would
    // finish the tag, whether or not a '>' came earlier.
    assertEquals(
        "<style>a{}b</style>",
        policy.sanitize("<style>a{}<b<svg></style>"));
    assertEquals(
        "<script>x> x<3/style</script>",
        policy.sanitize("<script>x><p> x<3</style<B></script>"));
    // A start tag the text kept has a place to come back to that the sweep
    // has already been over, so its end tag cannot cut the text short.
    assertEquals(
        "<noscript><style>--bnoscript></style></noscript>",
        policy.sanitize(
            "<noscript><style>--<b<b/></><style></ b>noscript></noscript>"));
    // What opens no tag stays: "3" is no name, and no browser state starts a
    // tag at '<' and whitespace.
    assertEquals(
        "<style>a{}<3{}</style>",
        policy.sanitize("<style>a{}<3<svg>{}</style>"));
    assertEquals(
        "<style>a{}< b{}</style>",
        policy.sanitize("<style>a{}< b<svg>{}</style>"));
    // And ordinary text is untouched.
    assertEquals(
        "<style>a{}c{}</style>",
        policy.sanitize("<style>a{}<b>c{}</style>"));
    assertEquals(
        "<script>var s = 'a<b'; var t = 'c>d';</script>",
        policy.sanitize("<script>var s = 'a<b'; var t = 'c>d';</script>"));
  }

  /**
   * Issue #474.  Inside {@code svg} or {@code math} a browser parses the
   * content of every element as markup, so the renderer escapes the text of a
   * style or script element there instead of emitting it as written.  The
   * filter used to strip the tags from that text as well, which was safe but
   * lost them for no reason.
   */
  @Test
  void testIssue474LiteralTextInForeignContentIsEscapedNotStripped() {
    PolicyFactory policy = new HtmlPolicyBuilder()
        .allowElements("svg", "math", "style", "script", "b")
        .allowTextIn("style", "script", "svg", "math")
        .toFactory();

    assertEquals(
        "<svg><style>a{}&lt;b&gt;x&lt;/b&gt;c{}</style></svg>",
        policy.sanitize("<svg><style>a{}<b>x</b>c{}</style></svg>"));
    assertEquals(
        "<math><script>a&lt;b&gt;c</script></math>",
        policy.sanitize("<math><script>a<b>c</script></math>"));
    // Escaped, so a breakout cannot ride along on it either.
    assertEquals(
        "<svg><style>&lt;/noscript&gt;&lt;img src&#61;x onerror&#61;alert(1)&gt;"
        + "</style></svg>",
        policy.sanitize(
            "<svg><style></noscript><img src=x onerror=alert(1)></style>"
            + "</svg>"));
    // Outside the svg the same element's text is emitted as written, so the
    // filter runs over it: the tags go and the end tag with them.
    assertEquals(
        "<svg></svg><style>a{}c{}</style>",
        policy.sanitize("<svg></svg><style>a{}<b>x</b>c{}</style>"));
    assertEquals(
        "<svg><b></b></svg><style>a{}c{}</style>",
        policy.sanitize("<svg><b></b></svg><style>a{}<b>x</b>c{}</style>"));
  }

  /**
   * Issue #474.  The filter judged the element by the name the library's own
   * renderer emits, which renames {@code xmp}, {@code listing} and
   * {@code plaintext} to {@code pre} and escapes their text.  A receiver
   * handed to {@link PolicyFactory#apply} does not rename, so it used to
   * receive the text of those elements with its tags intact, a
   * {@code </noscript>} among them, and the renderer-side check cannot run
   * for it either.  With any other receiver every element whose content the
   * lexer read as raw text is filtered.
   */
  @Test
  void testIssue474ACustomReceiverGetsRawTextWithoutTags() {
    PolicyFactory policy = new HtmlPolicyBuilder()
        .allowElements("noscript", "xmp", "listing", "plaintext", "style",
                       "img")
        .allowTextIn("xmp", "listing", "plaintext", "style")
        .allowAttributes("src").onElements("img")
        .toFactory();

    for (String rawText : new String[] { "xmp", "listing", "plaintext" }) {
      String html = "<noscript><" + rawText + "></noscript>"
          + "<img src=x onerror=alert(1)></" + rawText + "></noscript>";
      final List<String> text = new ArrayList<>();
      HtmlSanitizer.sanitize(html, policy.apply(collectText(text)));
      assertEquals(Arrays.asList(""), text, rawText);

      // Through the library's renderer, which renames the element and escapes
      // its text, the tags are still there to see.  A plaintext element runs
      // to the end of the input, so its own end tag is part of its text.
      assertEquals(
          "<noscript><pre>&lt;/noscript&gt;&lt;img src&#61;x"
          + " onerror&#61;alert(1)&gt;"
          + ("plaintext".equals(rawText)
             ? "&lt;/plaintext&gt;&lt;/noscript&gt;" : "")
          + "</pre></noscript>",
          policy.sanitize(html), rawText);
    }
    // A receiver the library cannot see through gets no tags in the text of a
    // style element inside an svg either, where the renderer would escape
    // them, since it may write what it is given as it stands.
    PolicyFactory svgPolicy = new HtmlPolicyBuilder()
        .allowElements("svg", "style", "b").allowTextIn("style", "svg")
        .toFactory();
    final List<String> text = new ArrayList<>();
    HtmlSanitizer.sanitize(
        "<svg><style>a{}<b>x</b>c{}</style></svg>",
        svgPolicy.apply(collectText(text)));
    assertEquals(Arrays.asList("a{}c{}"), text);
  }

  /** A receiver that records the text events it is given. */
  private static HtmlStreamEventReceiver collectText(final List<String> text) {
    return new HtmlStreamEventReceiver() {
      public void openDocument() { /* Not under test. */ }

      public void closeDocument() { /* Not under test. */ }

      public void openTag(String elementName, List<String> attrs) {
        // Not under test.
      }

      public void closeTag(String elementName) { /* Not under test. */ }

      public void text(String t) { text.add(t); }
    };
  }

  /**
   * Listening for what a policy drops must not change what it keeps.  The
   * filter follows what the receiver escapes, and a reporter sits between the
   * policy and the renderer, so the renderer has to stay visible behind it.
   */
  @Test
  void testTheLiteralTextFilterDoesNotDependOnAListener() {
    PolicyFactory policy = new HtmlPolicyBuilder()
        .allowElements("svg", "style", "xmp", "b")
        .allowTextIn("style", "xmp", "svg")
        .toFactory();
    HtmlChangeListener<Object> ignore = new HtmlChangeListener<Object>() {
      public void discardedTag(Object context, String elementName) {
        // Not under test.
      }

      public void discardedAttributes(
          Object context, String tagName, String... attributeNames) {
        // Not under test.
      }
    };

    for (String html : new String[] {
            "<svg><style>a{}<b>x</b>c{}</style></svg>",
            "<style>a{}<b>x</b>c{}</style>",
            "<xmp>a<b>x</b>c</xmp>",
         }) {
      assertEquals(
          policy.sanitize(html), policy.sanitize(html, ignore, null), html);
    }
  }

  /**
   * Two tokenizer differences left over from #189 (#410).  A tag that the
   * input ends inside is dropped whole, as a browser drops it, rather than
   * opened with whatever attributes had been read; and {@code </} followed
   * by anything but a letter is a bogus comment running to the next
   * {@code >}, or text at the end of input, rather than text up to the next
   * tag.
   */
  @Test
  void testIssue410EofInTagAndBogusEndTags() {
    PolicyFactory p = new HtmlPolicyBuilder()
        .allowElements("p", "b")
        .allowAttributes("class", "x").onElements("p")
        .toFactory();

    // End of input inside a tag: the tag goes, the text before it stays.
    assertEquals("x", p.sanitize("x<p "));
    assertEquals("", p.sanitize("<p class=\">y</p>"));
    assertEquals(
        "<p>foo</p> ",
        p.sanitize("<p>foo</p> <p class=\"test\" \"=\">bar</p> <p>baz</p>"));
    // An end tag the input ends inside goes too; the balancer closes the
    // element at the end as it would have anyway.
    assertEquals("<b>x</b>", p.sanitize("<b>x</b"));
    assertEquals("<b>x</b>", p.sanitize("<b>x</b class"));

    // "</" and a non-letter.
    assertEquals("<p>z</p>", p.sanitize("<p></>z"));
    assertEquals("<p x=\"x\">y</p>", p.sanitize("<p x></\"<p>y</p>"));
    assertEquals("<b>xy</b>", p.sanitize("<b>x</ b>y"));
    assertEquals("a&lt;/", p.sanitize("a</"));
  }

  /**
   * A link inside a table cell inside a link stays where it is: a browser
   * clears its active formatting elements to a marker on entering the cell,
   * so the inner {@code a} does not end the outer one.  The balancer used to
   * close back to the outer {@code a}, taking the inner table's cell, row
   * and table with it, so that table's second row landed in the outer table
   * (#333).  The parser check reads both the input and the output the way a
   * browser does and compares the trees.
   */
  @Test
  void testLinkInsideCellInsideLinkKeepsTheTableTogether() throws Exception {
    PolicyFactory p = new HtmlPolicyBuilder()
        .allowElements("a", "table", "tbody", "tr", "td", "th", "caption")
        .allowAttributes("href").onElements("a")
        .allowUrlProtocols("http")
        .toFactory();
    String input = "<table><tr><td><a href=\"http://b.example\">"
        + "<table><tbody>"
        + "<tr><td><a href=\"http://b.example\">11111</a></td></tr>"
        + "<tr><td><a href=\"http://b.example\">22222</a></td></tr>"
        + "</tbody></table></a></td></tr></table>";
    String out = p.sanitize(input);

    assertEquals(
        "<table><tbody><tr><td><a href=\"http://b.example\">"
        + "<table><tbody>"
        + "<tr><td><a href=\"http://b.example\">11111</a></td></tr>"
        + "<tr><td><a href=\"http://b.example\">22222</a></td></tr>"
        + "</tbody></table></a></td></tr></tbody></table>",
        out);
    assertEquals(parseAsBrowser(input), parseAsBrowser(out));

    // caption and th are markers too; a link straight inside a link is not,
    // and the second still ends the first, as in a browser.
    for (String html : new String[] {
            "<a href=\"http://u\"><table><caption><a href=\"http://v\">c"
            + "</a></caption></table></a>",
            "<a href=\"http://u\"><table><tr><th><a href=\"http://v\">h"
            + "</a></th></tr></table></a>",
            "<a href=\"http://u\">x<a href=\"http://v\">y</a>z</a>",
         }) {
      assertEquals(
          parseAsBrowser(html), parseAsBrowser(p.sanitize(html)), html);
    }
  }

  /** A formatting marker matters only when the policy keeps it in output. */
  @Test
  void testDroppedFormattingMarkersDoNotProtectNestedLinks()
      throws Exception {
    String expected = "<a href=\"u\" rel=\"nofollow\"></a>"
        + "<a href=\"v\" rel=\"nofollow\">x</a>y";
    for (String marker : new String[] {
            "applet", "caption", "marquee", "object", "td", "template", "th",
         }) {
      String input = "<a href=u><" + marker + "><a href=v>x</a></"
          + marker + ">y</a>";
      String out = Sanitizers.LINKS.sanitize(input);

      assertEquals(expected, out, marker);
      assertEquals(out, Sanitizers.LINKS.sanitize(out), marker);
      assertEquals(parseAsBrowser(expected), parseAsBrowser(out), marker);
    }
  }

  /** A marker that survives policy still permits the browser's nested links. */
  @Test
  void testKeptFormattingMarkerStillProtectsNestedLinks() throws Exception {
    PolicyFactory p = new HtmlPolicyBuilder()
        .allowElements("a", "marquee")
        .allowAttributes("href").onElements("a")
        .toFactory();
    String input = "<a href=u><marquee><a href=v>x</a></marquee>y</a>";
    String out = p.sanitize(input);

    assertEquals(
        "<a href=\"u\"><marquee><a href=\"v\">x</a></marquee>y</a>",
        out);
    assertEquals(parseAsBrowser(input), parseAsBrowser(out));
    assertEquals(out, p.sanitize(out));
  }

  /** Marker scope follows an element policy's output name, not its input. */
  @Test
  void testRenamedElementsDetermineFormattingMarkerScope() {
    PolicyFactory awayFromMarker = new HtmlPolicyBuilder()
        .allowElements("a", "div")
        .allowElements((name, attrs) -> "div", "marquee")
        .allowAttributes("href").onElements("a")
        .toFactory();
    String renamedAway = awayFromMarker.sanitize(
        "<a href=u><marquee><a href=v>x</a></marquee>y</a>");
    assertEquals(
        "<a href=\"u\"><div></div></a><a href=\"v\">x</a>y",
        renamedAway);
    assertEquals(renamedAway, awayFromMarker.sanitize(renamedAway));

    PolicyFactory intoMarker = new HtmlPolicyBuilder()
        .allowElements("a", "marquee")
        .allowElements((name, attrs) -> "marquee", "div")
        .allowAttributes("href").onElements("a")
        .toFactory();
    String renamedInto = intoMarker.sanitize(
        "<a href=u><div><a href=v>x</a></div>y</a>");
    assertEquals(
        "<a href=\"u\"><marquee><a href=\"v\">x</a></marquee>y</a>",
        renamedInto);
    assertEquals(renamedInto, intoMarker.sanitize(renamedInto));
  }

  /**
   * A browser puts content that cannot go inside a table in front of the
   * table and keeps the table open, so that the next row pops the content
   * and carries on in the same table (#342).  The output cannot put anything
   * in front of a tag already written, so the table is closed there, the
   * content written after it, and the table written again for its rows.
   * The content used to stay open until the end of the document, taking the
   * rows and everything after the table with it.  A browser now reads the
   * output as it reads the input, but for the empty table in front.
   */
  @Test
  void testContentPushedOutOfATableIsClosedWhenTheTableResumes()
      throws Exception {
    PolicyFactory p = tablePolicy();
    String input = "<table><div>x<tr><td>y</td></tr></div></table>tail";
    String out = p.sanitize(input);

    assertEquals(
        "<table></table><div>x</div>"
        + "<table><tbody><tr><td>y</td></tr></tbody></table>tail",
        out);
    assertEquals(out, p.sanitize(out));
    assertEquals(parseAsBrowser("<table></table>" + input), parseAsBrowser(out));
  }

  /**
   * The shape reported in #342: the table had rows before the content and
   * attributes of its own.  The rows before stay in the first table, and the
   * table written again for the rows after has no attributes, as a formatting
   * element written again after being closed has none.
   */
  @Test
  void testRowsAfterPushedOutContentContinueInANewTable() throws Exception {
    PolicyFactory p = tablePolicy();
    String input = "<table class=t><tbody><tr><td>a</td></tr>"
        + "<div class=d>x<tr><td>y</td></tr></div></table>tail";
    String out = p.sanitize(input);

    assertEquals(
        "<table class=\"t\"><tbody><tr><td>a</td></tr></tbody></table>"
        + "<div class=\"d\">x</div>"
        + "<table><tbody><tr><td>y</td></tr></tbody></table>tail",
        out);
    assertEquals(out, p.sanitize(out));
  }

  /**
   * Content pushed out of a table nests as usual until a part of the table
   * arrives, which closes all of it.  End tags for that content arriving
   * later find nothing to close, as in a browser, and the text after them
   * is pushed out as well.  A browser puts that text in front of the table;
   * the output, written in order, can only put it after.
   */
  @Test
  void testPushedOutContentNestsUntilATablePartArrives() {
    PolicyFactory p = tablePolicy();
    String input = "<table><div><p>x<span>s<tr><td>y</td></tr></span>t</div>u"
        + "</table>v";
    String out = p.sanitize(input);

    assertEquals(
        "<table></table><div><p>x<span>s</span></p></div>"
        + "<table><tbody><tr><td>y</td></tr></tbody></table>tuv",
        out);
    assertEquals(out, p.sanitize(out));
  }

  /**
   * A browser keeps the table open below the content it pushed out, so an
   * end tag for an element enclosing the table is ignored meanwhile, and the
   * text after it lands in the pushed-out content.  The balancer used to
   * close the table and let the end tag through.
   */
  @Test
  void testEndTagBelowAPushedOutTableIsIgnoredWhileItIsOpen()
      throws Exception {
    PolicyFactory p = tablePolicy();
    String input = "<div><table><span>x</div>y</table>z";
    String out = p.sanitize(input);

    assertEquals("<div><table></table><span>xy</span>z</div>", out);
    assertEquals(out, p.sanitize(out));
    assertEquals(
        parseAsBrowser("<div><table></table><span>xy</span>z</div>"),
        parseAsBrowser(out));
  }

  /**
   * The table's own end tag ends the content pushed out of it.  A browser
   * has the content in front of the table and the text after both; the
   * output has the same nodes with the table first.
   */
  @Test
  void testTableEndTagEndsPushedOutContent() {
    PolicyFactory p = tablePolicy();
    String out = p.sanitize("<table><div>x</table>tail");

    assertEquals("<table></table><div>x</div>tail", out);
    assertEquals(out, p.sanitize(out));
  }

  /**
   * A table arriving inside pushed-out content pops the open table in a
   * browser and takes its place, rather than nesting in the content; and
   * with tables pushed out at two levels, a row returns to the nearest.
   */
  @Test
  void testTableInsidePushedOutContentReplacesTheOpenTable()
      throws Exception {
    PolicyFactory p = tablePolicy();
    String input = "<table><div>x<table><tr><td>y</td></tr></table>tail";
    String out = p.sanitize(input);
    assertEquals(
        "<table></table><div>x</div>"
        + "<table><tbody><tr><td>y</td></tr></tbody></table>tail",
        out);
    assertEquals(out, p.sanitize(out));

    String nested = "<table><div>x<table><span>y<tr><td>z</td></tr></table>"
        + "</div>w</table>v";
    out = p.sanitize(nested);
    assertEquals(
        "<table></table><div>x</div><table></table><span>y</span>"
        + "<table><tbody><tr><td>z</td></tr></tbody></table>wv",
        out);
    assertEquals(out, p.sanitize(out));
    assertEquals(parseAsBrowser("<table></table>" + nested), parseAsBrowser(out));
  }

  /** Every part of a table brings the pushed-out table back. */
  @Test
  void testEveryTablePartReturnsToThePushedOutTable() throws Exception {
    PolicyFactory p = tablePolicy();
    String[][] cases = {
        { "<caption>c</caption>", "<caption>c</caption>" },
        { "<thead><tr><th>h</th></tr></thead>", "<thead><tr><th>h</th></tr></thead>" },
        { "<tbody><tr><td>y</td></tr></tbody>", "<tbody><tr><td>y</td></tr></tbody>" },
        { "<tr><td>y</td></tr>", "<tbody><tr><td>y</td></tr></tbody>" },
        { "<td>y</td>", "<tbody><tr><td>y</td></tr></tbody>" },
        { "<th>h</th>", "<tbody><tr><th>h</th></tr></tbody>" },
    };
    for (String[] c : cases) {
      String input = "<table><div>x" + c[0] + "</table>";
      String out = p.sanitize(input);
      assertEquals(
          "<table></table><div>x</div><table>" + c[1] + "</table>", out, c[0]);
      assertEquals(out, p.sanitize(out), c[0]);
      assertEquals(
          parseAsBrowser("<table></table>" + input), parseAsBrowser(out), c[0]);
    }
  }

  /**
   * Table-part names in SVG and MathML stay in foreign content.  Treating
   * them as HTML used to close the foreign ancestors and move the elements
   * into the pushed-out table.  At an HTML integration point the same names
   * do use HTML rules and still return to the table.
   */
  @Test
  void testForeignTablePartsDoNotReturnToAPushedOutTable() throws Exception {
    PolicyFactory p = new HtmlPolicyBuilder()
        .allowElements(
            "b", "caption", "colgroup", "table", "thead", "tbody",
            "tr", "td", "div", "svg", "g", "textArea", "foreignObject",
            "math", "mrow", "mtext")
        .toFactory();
    String input = "<table><svg><g><tr><td>s</td></tr>"
        + "<textArea><tr><td>t</td></tr></textArea></g></svg>"
        + "<math><mrow><tr><td>m</td></tr></mrow></math>"
        + "<tr><td>h</td></tr></table>tail";
    String out = p.sanitize(input);

    assertEquals(
        "<table></table><svg><g><tr><td>s</td></tr>"
        + "<textArea><tr><td>t</td></tr></textArea></g></svg>"
        + "<math><mrow><tr><td>m</td></tr></mrow></math>"
        + "<table><tbody><tr><td>h</td></tr></tbody></table>tail",
        out);
    assertEquals(out, p.sanitize(out));
    assertEquals(parseAsBrowser("<table></table>" + input), parseAsBrowser(out));

    for (String[] integrationPoint : new String[][] {
            { "<svg><foreignObject>", "</foreignObject></svg>" },
            { "<math><mtext>", "</mtext></math>" },
         }) {
      input = "<table><div>" + integrationPoint[0]
          + "<tr><td>i</td></tr>" + integrationPoint[1]
          + "<tr><td>h</td></tr></table>tail";
      out = p.sanitize(input);
      assertEquals(out, p.sanitize(out), integrationPoint[0]);
      assertEquals(
          parseAsBrowser("<table></table>" + input), parseAsBrowser(out),
          integrationPoint[0]);
    }

    // An emitted HTML breakout leaves the rendered foreign root before the
    // table is written again.  Its later end tag must not close that table in
    // the policy's stack and strand the following section outside it.
    input = "<table><svg><b><thead></svg>"
        + "<tbody><tr><td>y</td></tr></table>tail";
    out = p.sanitize(input);
    assertEquals(
        "<table></table><svg><b></b></svg>"
        + "<table><thead></thead><tbody><tr><td><b>y</b></td></tr>"
        + "</tbody></table><b>tail</b>",
        out);
    assertEquals(out, p.sanitize(out));

    // A stray table end tag cannot lose foreign context and send a later
    // table part back into the pushed-out table.
    String foreign = "<table><svg><colgroup></thead>"
        + "<caption>c</caption></colgroup></svg>"
        + "<tr><td>y</td></tr></table>tail";
    out = p.sanitize(foreign);
    assertEquals(out, p.sanitize(out));
    assertEquals(
        parseAsBrowser("<table></table>" + foreign), parseAsBrowser(out));
  }

  /** Raw-text and RCDATA elements stay bounded by a pushed-out run. */
  @Test
  void testLiteralContentInPushedOutTableContent() {
    PolicyFactory p = new HtmlPolicyBuilder()
        .allowElements(
            "table", "tbody", "tr", "td", "div", "span", "style",
            "script", "textarea", "noscript")
        .allowTextIn("style", "script", "noscript")
        .toFactory();
    String input = "<table><textarea>&lt;tr&gt;</textarea><div>"
        + "<style>x{}</style><script>x()</script>"
        + "<noscript><span>n</span></noscript></div>"
        + "<tr><td>y</td></tr></table>tail";
    String out = p.sanitize(input);

    assertEquals(
        "<table></table><textarea>&lt;tr&gt;</textarea><div>"
        + "<style>x{}</style><script>x()</script>"
        + "<noscript>n</noscript></div>"
        + "<table><tbody><tr><td>y</td></tr></tbody></table>tail",
        out);
    assertEquals(out, p.sanitize(out));
  }

  /**
   * A policy may drop or rename the attribute-free table written when table
   * content resumes.  A renamed synthetic table and its row structure cannot
   * safely be emitted, but allowed cell text still survives.  This includes
   * replacements with table, void, select, raw-text and foreign parsing rules.
   */
  @Test
  void testTableStructureIsSuppressedUnderRenamedReopenedTable() {
    String input = "<table class=t><div>x<tr><td>"
        + "a&lt;/script&gt;&lt;svg onload=x&gt;b"
        + "</td></tr></table>tail";
    String[] replacements = {
        "", "div", "tbody", "tr", "td", "caption", "colgroup", "col",
        "br", "select", "option", "script", "style", "textarea",
        "noscript", "xmp", "plaintext", "iframe", "svg", "math",
    };
    HtmlChangeListener<Object> ignore = new HtmlChangeListener<Object>() {
      public void discardedTag(Object context, String elementName) {
        // Output is under test, notifications are not.
      }

      public void discardedAttributes(
          Object context, String tagName, String... attributeNames) {
        // Output is under test, notifications are not.
      }
    };
    for (String c : replacements) {
      final String replacement = c.isEmpty() ? null : c;
      PolicyFactory p = new HtmlPolicyBuilder()
          .allowElements(
              (elementName, attrs) -> attrs.isEmpty()
                  ? replacement : elementName,
              "table")
          .allowElements("tbody", "tr", "td", "div")
          .allowAttributes("class").onElements("table")
          .allowTextIn("table")
          .toFactory();
      String out = p.sanitize(input);

      assertEquals(
          "<table class=\"t\"></table><div>x</div>"
              + "a&lt;/script&gt;&lt;svg onload&#61;x&gt;btail",
          out, c);
      assertEquals(out, p.sanitize(out), c);
      assertEquals(out, p.sanitize(input, ignore, null), c);
    }
  }

  /**
   * A link pushed out of a table is closed when the table resumes, and is
   * not written again around another link or inside one: nested links do
   * not survive a browser's parse.  Text is pushed out likewise, and needs
   * nothing closed.
   */
  @Test
  void testPushedOutLinkIsNotResumedAroundAnotherLink() throws Exception {
    PolicyFactory p = new HtmlPolicyBuilder()
        .allowElements("table", "tbody", "tr", "td", "a")
        .allowAttributes("href").onElements("a")
        .allowWithoutAttributes("a")
        .toFactory();
    String out = p.sanitize(
        "<table><a href=u>x<tr><td><a href=v>y</a>z</td></tr></table>w");

    assertEquals(
        "<table></table><a href=\"u\">x</a>"
        + "<table><tbody><tr><td><a href=\"v\">y</a><a>z</a></td></tr></tbody>"
        + "</table><a>w</a>",
        out);
    assertEquals(out, p.sanitize(out));
    assertEquals(
        "<table></table>x<table><tbody><tr><td>y</td></tr></tbody></table>",
        p.sanitize("<table>x<tr><td>y</td></tr></table>"));
  }

  /**
   * A browser looks for the table to return to within table scope only, so
   * a table or row inside a {@code template} in the pushed-out content
   * stays in the template, and the pushed-out table waits for a part
   * arriving outside it.
   */
  @Test
  void testReturnToAPushedOutTableStopsAtATableScopeBoundary() {
    PolicyFactory p = new HtmlPolicyBuilder()
        .allowElements("table", "tbody", "tr", "td", "div", "template")
        .toFactory();
    String out = p.sanitize(
        "<table><div><template><table><tr><td>y</td></tr></table></template>"
        + "z</div>w<tr><td>v</td></tr></table>u");

    assertEquals(
        "<table></table><div><template>"
        + "<table><tbody><tr><td>y</td></tr></tbody></table></template>z</div>w"
        + "<table><tbody><tr><td>v</td></tr></tbody></table>u",
        out);
    assertEquals(out, p.sanitize(out));
  }

  /**
   * Content is judged by what holds the table it was pushed out of, since
   * that is where a browser puts it.  An element that cannot hold the
   * content closes instead of nesting it: a heading inside a heading does
   * not survive a browser's parse, so the output would read back as a
   * different tree.
   */
  @Test
  void testPushedOutContentIsJudgedByWhatHoldsTheTable() {
    PolicyFactory p = new HtmlPolicyBuilder()
        .allowElements("table", "tbody", "tr", "td", "h1", "button")
        .toFactory();
    String heading = p.sanitize(
        "<h1><table><tr><td>a</td></tr><h1>b</h1></table>");
    assertEquals(
        "<h1><table><tbody><tr><td>a</td></tr></tbody></table></h1>"
        + "<h1>b</h1>",
        heading);
    assertEquals(heading, p.sanitize(heading));

    String button = p.sanitize(
        "<button><table><tr><td>a</td></tr><button>b</button></table>");
    assertEquals(
        "<button><table><tbody><tr><td>a</td></tr></tbody></table></button>"
        + "<button>b</button>",
        button);
    assertEquals(button, p.sanitize(button));
  }

  /**
   * And it gets the elements a browser would imply around it there: an
   * option needs its select whether or not a table was pushed out of the
   * way, which the tables never leave to chance, since the sanitizer does
   * not know what the output will be embedded in.
   */
  @Test
  void testContentBesideAPushedOutTableStillGetsItsImpliedWrapper() {
    PolicyFactory p = new HtmlPolicyBuilder()
        .allowElements("table", "tbody", "tr", "td", "select", "option")
        .toFactory();
    String out = p.sanitize("<table>x<option>o</option></table>z");

    assertEquals("<table></table>x<select><option>o</option></select>z", out);
    assertEquals(out, p.sanitize(out));
  }

  /**
   * Text that follows a pushed-out table reaches the output even where the
   * element holding the table cannot hold text: that element closes, as it
   * would for text arriving anywhere else, rather than the text going into
   * it and being dropped.  The row after a column closes the colgroup and
   * continues in the existing table (#483), and {@code tail} survives.
   */
  @Test
  void testTextAfterAPushedOutTableSurvivesAContainerThatCannotHoldIt() {
    PolicyFactory p = new HtmlPolicyBuilder()
        .allowElements("table", "colgroup", "col", "tbody", "tr", "td")
        .toFactory();
    String out = p.sanitize("<table><col><tr><td>a</td></tr>tail</table>");

    assertEquals(
        "<table><colgroup><col /></colgroup>"
        + "<tbody><tr><td>a</td></tr></tbody></table>tail",
        out);
    assertEquals(out, p.sanitize(out));
  }

  /**
   * A cell returning to a pushed-out table lands in the table, not in a
   * fresh one: the row group it arrives in cannot hold a cell without a row
   * between, and the path to that row runs through a table, so the row group
   * goes and the table takes the cell.
   */
  @Test
  void testACellReturningToAPushedOutSectionDoesNotOpenANewTable() {
    PolicyFactory p = new HtmlPolicyBuilder()
        .allowElements("table", "thead", "tfoot", "tbody", "tr", "td", "th")
        .toFactory();
    String head = p.sanitize("<table><thead>x<td>y</td></table>tail");
    assertEquals(
        "<table><thead></thead></table>x"
        + "<table><tbody><tr><td>y</td></tr></tbody></table>tail",
        head);
    assertEquals(head, p.sanitize(head));

    String foot = p.sanitize("<table><tfoot>x<th>h</th></table>tail");
    assertEquals(
        "<table><tfoot></tfoot></table>x"
        + "<table><tbody><tr><th>h</th></tr></tbody></table>tail",
        foot);
    assertEquals(foot, p.sanitize(foot));
  }

  /**
   * The rule that a link is not written again around or inside another link
   * is not about tables: an end tag that closes the element a link was
   * misnested in queues the link for resumption, and resuming it around the
   * next link used to produce nested links, which a browser's parse
   * unnests, so the output read back as a different tree.
   */
  @Test
  void testLinkIsNotResumedAroundAnotherLinkWithoutATable() {
    PolicyFactory p = new HtmlPolicyBuilder()
        .allowElements("div", "p", "a")
        .allowAttributes("href").onElements("a")
        .allowUrlProtocols("http")
        .allowWithoutAttributes("a")
        .toFactory();
    String out = p.sanitize(
        "<div><a href=http://u>x</div><a href=http://v>y");
    assertEquals(
        "<div><a href=\"http://u\">x</a></div><a href=\"http://v\">y</a>",
        out);
    assertEquals(out, p.sanitize(out));

    String nested = p.sanitize(
        "<div><a href=http://u>x<p><a href=http://v>y</a></p></a>");
    assertEquals(
        "<div><a href=\"http://u\">x<p></p></a>"
        + "<a href=\"http://v\">y</a></div>",
        nested);
    assertEquals(nested, p.sanitize(nested));
  }

  /** Pushed-out content is bounded by the nesting limit like any other. */
  @Test
  void testPushedOutContentRespectsTheNestingLimit() {
    PolicyFactory p = tablePolicy();
    StringBuilder sb = new StringBuilder("<table>");
    for (int i = 0; i < 300; ++i) { sb.append("<div>"); }
    sb.append("<tr><td>y</td></tr></table>z");
    String out = p.sanitize(sb.toString());
    assertTrue(
        out.endsWith("</div><table><tbody><tr><td>y</td></tr></tbody></table>z"),
        out.substring(out.length() - 80));
    assertEquals(out, p.sanitize(out));
  }

  /**
   * A table arriving beside a pushed-out table replaces it, so a long run
   * of them leaves nothing behind: the stack stays flat however many there
   * are, where the content used to nest one run inside the next.
   */
  @Test
  void testRepeatedPushOutAndReturnDoesNotAccumulate() {
    PolicyFactory p = tablePolicy();
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < 300; ++i) { sb.append("<table><div>"); }
    sb.append("<tr><td>y</td></tr></table>z");
    String out = p.sanitize(sb.toString());

    StringBuilder expected = new StringBuilder();
    for (int i = 0; i < 300; ++i) { expected.append("<table></table><div></div>"); }
    expected.setLength(expected.length() - "<table></table><div></div>".length());
    expected.append("<table></table><div></div>")
        .append("<table><tbody><tr><td>y</td></tr></tbody></table>z");
    assertEquals(expected.toString(), out);
    assertEquals(out, p.sanitize(out));
  }

  private static PolicyFactory tablePolicy() {
    return new HtmlPolicyBuilder()
        .allowElements(
            "table", "caption", "thead", "tbody", "tfoot", "tr", "td", "th",
            "div", "p", "span")
        .allowAttributes("class").onElements("table", "div")
        .allowWithoutAttributes("span")
        .toFactory();
  }

  /** Issue #483: table parts clear back to the table before implying tags. */
  @Test
  void testTablePartsInsideCellContentReturnToTheOpenTable() throws Exception {
    PolicyFactory p = new HtmlPolicyBuilder()
        .allowElements("table", "caption", "colgroup", "col", "thead", "tbody",
            "tfoot", "tr", "td", "th", "div", "b")
        .toFactory();
    String prefix = "<table><tr><td><div><b>x";
    String closedCell = "<table><tbody><tr><td><div><b>x</b></div></td>";
    String[][] cases = {
        { "<tr><td>y</td></tr></table>",
          closedCell + "</tr><tr><td>y</td></tr></tbody></table>" },
        { "<td>y</td></tr></table>",
          closedCell + "<td>y</td></tr></tbody></table>" },
        { "<th>y</th></tr></table>",
          closedCell + "<th>y</th></tr></tbody></table>" },
        { "<caption>y</caption></table>",
          closedCell + "</tr></tbody><caption>y</caption></table>" },
        { "<col></table>",
          closedCell + "</tr></tbody><colgroup><col /></colgroup></table>" },
        { "<colgroup><col></colgroup></table>",
          closedCell + "</tr></tbody><colgroup><col /></colgroup></table>" },
        { "<thead><tr><td>y</td></tr></thead></table>",
          closedCell + "</tr></tbody><thead><tr><td>y</td></tr></thead></table>" },
        { "<tbody><tr><td>y</td></tr></tbody></table>",
          closedCell + "</tr></tbody><tbody><tr><td>y</td></tr></tbody></table>" },
        { "<tfoot><tr><td>y</td></tr></tfoot></table>",
          closedCell + "</tr></tbody><tfoot><tr><td>y</td></tr></tfoot></table>" },
    };
    for (String[] c : cases) {
      String input = prefix + c[0];
      String out = p.sanitize(input);
      assertEquals(c[1], out, input);
      assertEquals(out, p.sanitize(out), input);
      assertEquals(parseAsBrowser(input), parseAsBrowser(out), input);
    }
  }

  @Test
  void testRowAfterColumnUsesTheExistingTable() throws Exception {
    PolicyFactory p = new HtmlPolicyBuilder()
        .allowElements("table", "colgroup", "col", "tbody", "tr", "td")
        .toFactory();
    String input = "<table><col><tr><td>y</td></tr></table>";
    String out = p.sanitize(input);
    assertEquals(
        "<table><colgroup><col /></colgroup>"
        + "<tbody><tr><td>y</td></tr></tbody></table>", out);
    assertEquals(out, p.sanitize(out));
    assertEquals(parseAsBrowser(input), parseAsBrowser(out));
  }

  /** An explicit table in a cell stays nested, and owns its later rows. */
  @Test
  void testTablePartReturnsToTheNearestNestedTable() throws Exception {
    PolicyFactory p = tablePolicy();
    String input = "<table><tr><td><table><tr><td><div>x"
        + "<tr><td>y</td></tr></table>z</td></tr></table>";
    String out = p.sanitize(input);
    assertEquals(
        "<table><tbody><tr><td><table><tbody><tr><td><div>x</div></td></tr>"
        + "<tr><td>y</td></tr></tbody></table>z</td></tr></tbody></table>", out);
    assertEquals(out, p.sanitize(out));
    assertEquals(parseAsBrowser(input), parseAsBrowser(out));
  }

  /** The existing orphan-part wrapper must obey the containment of p. */
  @Test
  void testImpliedTableClosesParagraphBeforeItsPartsOpen() throws Exception {
    PolicyFactory p = tablePolicy();
    String out = p.sanitize("<div><p>x<tr><td>y</td></tr>");
    String expected = "<div><p>x</p><table><tbody><tr><td>y</td></tr>"
        + "</tbody></table></div>";
    assertEquals(expected, out);
    assertEquals(out, p.sanitize(out));
    assertEquals(parseAsBrowser(expected), parseAsBrowser(out));

    // The balancer still supplies the wrapper needed when an orphan part is
    // embedded in an unknown context; the explicit table is the equivalent
    // browser input, since a body parser drops the bare tr and td tags.
    assertEquals(out, p.sanitize("<div><p>x<table><tr><td>y</td></tr>"));
  }

  /** Balancing never exempts table parts or their implied tags from policy. */
  @Test
  void testMisnestedTablePartsStillApplyElementAndAttributePolicies() {
    PolicyFactory p = tablePolicy();
    String out = p.sanitize(
        "<table onclick=blocked><tr><td><div data-denied=blocked>x"
        + "<tr onclick=blocked><td>y<script>blocked</script></table>");
    assertEquals(
        "<table><tbody><tr><td><div>x</div></td></tr>"
        + "<tr><td>y</td></tr></tbody></table>", out);
    assertEquals(out, p.sanitize(out));

    PolicyFactory textOnly = new HtmlPolicyBuilder().allowElements("p")
        .toFactory();
    String text = textOnly.sanitize("<p>x<tr onclick=blocked><td>y</td></tr>");
    assertEquals("<p>x</p>y", text);
    assertEquals(text, textOnly.sanitize(text));
  }

  /** A logical table omitted by policy does not establish output context. */
  @Test
  void testTableContextReturnStopsAtDroppedTable() {
    PolicyFactory p = new HtmlPolicyBuilder()
        .allowElements("tbody", "tr", "td", "div")
        .toFactory();
    String input = "<table><tr><td><table><tr><td><div>x"
        + "<tr><td>y</table>z</table>";
    String out = p.sanitize(input);

    assertEquals(
        "<tbody><tr><td><tbody><tr><td><div>x"
        + "<tbody><tr><td>y</td></tr></tbody>z</div></td></tr></tbody>"
        + "</td></tr></tbody>",
        out);
    assertEquals(out, p.sanitize(out));
  }

  /** A template bounds table scope and its end tag closes all its content. */
  @Test
  void testTemplateEndsThroughItsTableStructure() {
    PolicyFactory p = new HtmlPolicyBuilder()
        .allowElements("template", "table", "tbody", "tr", "td", "div", "b")
        .toFactory();
    String[][] cases = {
        { "<template><tr><td>y</td></tr></template>z",
          "<template><table><tbody><tr><td>y</td></tr></tbody></table>"
          + "</template>z" },
        { "<template><table><tr><td><b>y</template>z",
          "<template><table><tbody><tr><td><b>y</b></td></tr></tbody>"
          + "</table></template>z" },
        { "<template><div><b>x</div></template>y",
          "<template><div><b>x</b></div></template>y" },
        { "<template><template><tr><td>x</template>y</template>z",
          "<template><template><table><tbody><tr><td>x</td></tr></tbody>"
          + "</table></template>y</template>z" },
        { "<table><tr><td><template><tr><td>x</template>y<tr><td>z</table>w",
          "<table><tbody><tr><td><template><table><tbody><tr><td>x</td></tr>"
          + "</tbody></table></template>y</td></tr><tr><td>z</td></tr>"
          + "</tbody></table>w" },
        { "<table><div><template><tr><td>x</template>y<tr><td>z</table>w",
          "<table></table><div><template><table><tbody><tr><td>x</td></tr>"
          + "</tbody></table></template>y</div><table><tbody><tr><td>z</td>"
          + "</tr></tbody></table>w" },
        { "<table><tr><td>x</template>y</td></tr></table>z",
          "<table><tbody><tr><td>xy</td></tr></tbody></table>z" },
        { "<template><noscript>x</template>y</noscript>z",
          "<template>z</template>" },
        { "<template><noembed>x</template>y</noembed>z",
          "<template>z</template>" },
        { "<template><noframes>x</template>y</noframes>z",
          "<template>z</template>" },
    };
    for (String[] c : cases) {
      String out = p.sanitize(c[0]);
      assertEquals(c[1], out, c[0]);
      assertEquals(out, p.sanitize(out), c[0]);
    }
  }

  /** Foreign table names remain foreign; integration points use HTML rules. */
  @Test
  void testTablePartsInForeignCellContentKeepTheirContext() throws Exception {
    PolicyFactory p = new HtmlPolicyBuilder()
        .allowElements("table", "tbody", "tr", "td", "svg", "math",
            "foreignObject", "mtext")
        .toFactory();
    for (String[] names : new String[][] {
        { "svg", "foreignObject" }, { "math", "mtext" },
    }) {
      String foreign = "<" + names[0] + "><tr><td>x</td></tr></" + names[0] + ">";
      String input = "<table><tr><td>" + foreign + "<tr><td>y</table>";
      String out = p.sanitize(input);
      assertEquals("<table><tbody><tr><td>" + foreign
          + "</td></tr><tr><td>y</td></tr></tbody></table>", out);
      assertEquals(out, p.sanitize(out));
      assertEquals(parseAsBrowser(input), parseAsBrowser(out));

      input = "<table><tr><td><" + names[0] + "><" + names[1]
          + "><tr><td>x</table>";
      out = p.sanitize(input);
      assertEquals("<table><tbody><tr><td><" + names[0] + "><" + names[1]
          + "></" + names[1] + "></" + names[0]
          + "></td></tr><tr><td>x</td></tr></tbody></table>", out);
      assertEquals(out, p.sanitize(out));
      assertEquals(parseAsBrowser(input), parseAsBrowser(out));
    }
  }

  /** The tree a browser builds from html, one node per line. */
  private static String parseAsBrowser(String html) throws Exception {
    Node fragment = new HtmlDocumentBuilder().parseFragment(
        new InputSource(new StringReader(html)), "body");
    StringBuilder sb = new StringBuilder();
    appendTree(fragment, "", sb);
    return sb.toString();
  }

  private static void appendTree(Node node, String indent, StringBuilder sb) {
    switch (node.getNodeType()) {
      case Node.ELEMENT_NODE:
        sb.append(indent).append('<').append(node.getNodeName());
        NamedNodeMap attrs = node.getAttributes();
        for (int i = 0, n = attrs.getLength(); i < n; ++i) {
          Node attr = attrs.item(i);
          sb.append(' ').append(attr.getNodeName())
              .append('=').append(attr.getNodeValue());
        }
        sb.append(">\n");
        indent += "  ";
        break;
      case Node.TEXT_NODE:
        sb.append(indent).append('"').append(node.getNodeValue())
            .append("\"\n");
        break;
      default:
        break;
    }
    for (Node child = node.getFirstChild(); child != null;
         child = child.getNextSibling()) {
      appendTree(child, indent, sb);
    }
  }

  @Test
  void testIssue189StrayQuoteInTag() {
    // A quote that does not directly follow an attribute name and '=' is part
    // of an attribute name in the WHATWG tokenizer, so it must not pair with
    // a later quote and swallow the rest of the document.
    assertEquals(
        "<p>foo</p> <p class=\"p-test\">bar</p> <p>baz</p>",
        sanitize("<p>foo</p> <p class=\"test\" \"=\"\">bar</p> <p>baz</p>"));
    assertEquals(
        "<p class=\"p-test\">bar</p> <p>baz</p>",
        sanitize("<p class=\"test\" \">bar</p> <p>baz</p>"));
    assertEquals("<p>b&#34;&gt;c</p>", sanitize("<p \"a>b\">c</p>"));
    assertEquals("<p class=\"p-x\">y</p>", sanitize("<p class=\"x\"=\">y</p>"));
    assertEquals("<p>y</p>", sanitize("<p =\"x\">y</p>"));
    assertEquals("<p>y</p>", sanitize("<p / \"x\">y</p>"));
    assertEquals("<p class=\"p-x\">y</p>", sanitize("<p class=\"x\"/=\">y</p>"));
    assertEquals("<p>y</p>", sanitize("<p title/=\">y</p>"));
    // Here the second quote does follow '=', so it begins a value that never
    // closes; browsers hit EOF inside the tag and drop everything from it on,
    // and so does the sanitizer (#410).
    assertEquals(
        "<p>foo</p> ",
        sanitize("<p>foo</p> <p class=\"test\" \"=\">bar</p> <p>baz</p>"));
  }

  /**
   * Issue #122.  Browsers honor the self-closing flag on {@code <svg/>} and
   * {@code <math/>}, and on most start tags inside them, where
   * {@code <path/>} is a complete, empty element.  The sanitizer discarded
   * the flag, so each self-closing path nested inside the one before it and
   * the end of the SVG closed them all at once.
   */
  @Test
  void testSelfClosingTagsInForeignContent() {
    PolicyFactory p = foreignContentPolicy();
    // The markup from the issue.
    assertEquals(
        "<svg width=\"24\" height=\"24\" viewBox=\"0 0 24 24\">\n"
        + "    <path id=\"bounds\" opacity=\"0\" d=\"M0 0h24v24H0z\"></path>\n"
        + "    <path d=\"M2 2\"></path>\n"
        + "    <path d=\"M3 3\"></path>\n"
        + "</svg>",
        p.sanitize(
            "<svg width=\"24\" height=\"24\" viewBox=\"0 0 24 24\">\n"
            + "    <path id=\"bounds\" opacity=\"0\" d=\"M0 0h24v24H0z\"/>\n"
            + "    <path d=\"M2 2\"/>\n"
            + "    <path d=\"M3 3\"/>\n"
            + "</svg>"));
    // What follows a self-closing tag is a sibling, not content.
    assertEquals(
        "<svg><path d=\"M0 0\"></path>text<path d=\"M1 1\"></path></svg>",
        p.sanitize("<svg><path d=\"M0 0\"/>text<path d=\"M1 1\"/></svg>"));
    assertEquals(
        "<svg><g><path d=\"M0 0\"></path><rect></rect></g>"
        + "<path d=\"M1 1\"></path></svg>",
        p.sanitize(
            "<svg><g><path d=\"M0 0\"/><rect/></g><path d=\"M1 1\"/></svg>"));
    // Names that keep their case are foreign content too, and SVG's
    // textArea is not HTML's textarea.
    assertEquals(
        "<svg><clipPath></clipPath><g></g>x</svg>",
        p.sanitize("<svg><clipPath/><g/>x</svg>"));
    assertEquals(
        "<svg><textArea></textArea>x</svg>",
        p.sanitize("<svg><textArea/>x</svg>"));
    assertEquals(
        "<math><mi></mi>x<mrow></mrow>y</math>",
        p.sanitize("<math><mi/>x<mrow/>y</math>"));
    // The flag is honored on <svg/> and <math/> themselves, anywhere.
    assertEquals("<svg></svg>x", p.sanitize("<svg/>x"));
    assertEquals("<svg></svg>x", p.sanitize("<SVG/>x"));
    assertEquals("<math></math>x", p.sanitize("<math/>x"));
    assertEquals(
        "<svg><svg></svg><path d=\"M0 0\"></path></svg>",
        p.sanitize("<svg><svg/><path d=\"M0 0\"/></svg>"));
    // Only a solidus right before the '>' sets the flag.
    assertEquals(
        "<svg><path d=\"M0\"></path>x</svg>",
        p.sanitize("<svg><path d=M0 />x</svg>"));
    assertEquals(
        "<svg><path d=\"M0/&gt;\"></path>x</svg>",
        p.sanitize("<svg><path d=\"M0/>\"/>x</svg>"));
    // In an unquoted value the solidus is part of the value.
    assertEquals(
        "<svg><path d=\"M0/\">x</path></svg>",
        p.sanitize("<svg><path d=M0/>x</svg>"));
    assertEquals(
        "<svg><path d=\"/\">x</path></svg>",
        p.sanitize("<svg><path d=/>x</svg>"));
    assertEquals(
        "<svg><path>x</path></svg>", p.sanitize("<svg><path / >x</svg>"));
  }

  /**
   * Issue #122.  In HTML content the self-closing flag means nothing on a
   * non-void element, so outside {@code <svg>} and {@code <math>} nothing
   * changes: {@code <path/>} still opens an element that only an end tag
   * closes.
   */
  @Test
  void testSelfClosingTagsOutsideForeignContent() {
    PolicyFactory p = foreignContentPolicy();
    assertEquals(
        "<path d=\"M0 0\">x</path>", p.sanitize("<path d=\"M0 0\"/>x"));
    assertEquals("<p>x</p>", p.sanitize("<p/>x"));
    // Foreign content ends with the element that started it.
    assertEquals(
        "<svg></svg><path d=\"M0 0\">x</path>",
        p.sanitize("<svg></svg><path d=\"M0 0\"/>x"));
    assertEquals(
        "<svg><path></path></svg><path d=\"M0 0\">x</path>",
        p.sanitize("<svg><path/></svg><path d=\"M0 0\"/>x"));
  }

  /**
   * Issue #122.  Browsers process the start tags that break out of foreign
   * content as HTML, where the flag is ignored again; a void element is
   * empty with or without it.
   */
  @Test
  void testSelfClosingTagsThatBreakOutOfForeignContent() {
    PolicyFactory p = foreignContentPolicy();
    assertEquals("<svg><div>x</div></svg>", p.sanitize("<svg><div/>x</svg>"));
    assertEquals("<svg><p>x</p></svg>", p.sanitize("<svg><p/>x</svg>"));
    // <font> breaks out only with a color, face or size attribute.
    assertEquals(
        "<svg><font color=\"red\">x</font></svg>",
        p.sanitize("<svg><font color=\"red\"/>x</svg>"));
    assertEquals(
        "<svg><font></font>x</svg>", p.sanitize("<svg><font/>x</svg>"));
    assertEquals("<svg><br />x</svg>", p.sanitize("<svg><br/>x</svg>"));
  }

  /** Issue #457.  Start tags at integration points use the HTML rules. */
  @Test
  void testSelfClosingTagsAtHtmlIntegrationPoints() {
    PolicyFactory p = foreignContentPolicy();
    assertEquals(
        "<svg><foreignObject><path>x</path></foreignObject></svg>",
        p.sanitize("<svg><foreignObject><path/>x</foreignObject></svg>"));
    assertEquals(
        "<svg><desc><path>x</path></desc></svg>",
        p.sanitize("<svg><desc><path/>x</desc></svg>"));
    assertEquals(
        "<math><mi><path>x</path></mi></math>",
        p.sanitize("<math><mi><path/>x</mi></math>"));
    assertEquals(
        "<math><annotation-xml encoding=\"text/html\"><path>x</path>"
        + "</annotation-xml></math>",
        p.sanitize(
            "<math><annotation-xml encoding=text/html><path/>x"
            + "</annotation-xml></math>"));
    assertEquals(
        "<math><mi><mglyph></mglyph>x</mi></math>",
        p.sanitize("<math><mi><mglyph/>x</mi></math>"));
    // A dropped object remains open under HTML rules, so its fallback text
    // stays suppressed.
    assertEquals(
        "<svg><foreignObject></foreignObject></svg>",
        p.sanitize(
            "<svg><foreignObject><object/>hidden</foreignObject></svg>"));
  }

  /** Issue #457.  A breakout token ends the surrounding foreign context. */
  @Test
  void testForeignContentBreakoutUpdatesFollowingContext() {
    PolicyFactory p = foreignContentPolicy();
    assertEquals(
        "<svg><p><path>x</path></p></svg>",
        p.sanitize("<svg><p/><path/>x</svg>"));
    assertEquals(
        "<svg><p>x</p></svg>",
        p.sanitize("<svg><p/>x<object/>hidden</svg>"));
    assertEquals(
        "<svg><font color=\"red\"><path>x</path></font></svg>",
        p.sanitize("<svg><font color=red /><path/>x</svg>"));
    assertEquals(
        "<svg><path>x</path></svg>",
        p.sanitize("<svg></p><path/>x</svg>"));
  }

  /** Issue #457.  Foreign end tags match against the open-element stack. */
  @Test
  void testForeignContentEndTagsUpdateTheMatchingContext() {
    PolicyFactory p = foreignContentPolicy();
    assertEquals(
        "<math><mi></mi>x</math>",
        p.sanitize("<math></svg><mi/>x</math>"));
    assertEquals(
        "<svg><math></math></svg><path>x</path>",
        p.sanitize("<svg><math></svg><path/>x"));
    assertEquals(
        "<math><svg></svg></math><path>x</path>",
        p.sanitize("<math><svg></math><path/>x"));
    assertEquals(
        "<svg><math></math><path></path>x</svg>",
        p.sanitize("<svg><math></math><path/>x</svg>"));
    assertEquals(
        "<svg><math></math></svg>",
        p.sanitize("<svg><math></svg><object/>hidden"));
    // The end tag of an HTML element that is open below a foreign element
    // closes both, and puts the parser back under the HTML rules.
    assertEquals(
        "<math><mi><div><svg></svg></div><path>x</path></mi></math>",
        p.sanitize(
            "<math><mi><div><svg></div><path/>x</svg></div></mi></math>"));
  }

  /**
   * Issue #457.  An end tag that names none of the open foreign elements
   * may close an HTML ancestor of the foreign root, which is not tracked.
   * The context is then unknown and the sanitizer falls back to the HTML
   * rules, unless the browser would ignore the tag.
   */
  @Test
  void testEndTagsOfHtmlAncestorsEndForeignContent() {
    PolicyFactory p = foreignContentPolicy();
    assertEquals(
        "<div><svg></svg></div>",
        p.sanitize("<div><svg></div><object/>hidden"));
    assertEquals(
        "<div><svg><path></path></svg></div>",
        p.sanitize("<div><svg><path></div><object/>hidden"));
    assertEquals(
        "<p><svg></svg></p>",
        p.sanitize("<p><svg></p><object/>hidden"));
    assertEquals(
        "<div><svg><path></path></svg></div><path>x</path>",
        p.sanitize("<div><svg><path></div><path/>x"));
    // An integration point is in the special category and stops the search
    // for the named element, so the tag is ignored and the content of the
    // integration point stays under the HTML rules.
    assertEquals(
        "<div><svg><foreignObject></foreignObject></svg></div>",
        p.sanitize("<div><svg><foreignObject></div><object/>hidden"));
    assertEquals(
        "<div><math><mi></mi></math></div>",
        p.sanitize("<div><math><mi></div><object/>hidden"));
    // The path is still empty and closes at once.  Where the tag balancer
    // then puts it is its own concern.
    assertEquals(
        "<div><svg><foreignObject><div><svg></svg></div></foreignObject>"
        + "<path></path>x</svg></div>",
        p.sanitize(
            "<div><svg><foreignObject><div><svg></foreignObject>"
            + "<path/>x"));
    // No HTML element is named svg or math, so a stray foreign end tag is
    // ignored rather than taken as closing an ancestor.
    assertEquals(
        "<div><math><mi></mi>x</math></div>",
        p.sanitize("<div><math></svg><mi/>x</math></div>"));
    // A stray end tag that names nothing open is ignored by browsers, and
    // the self-closing flag is still honored after it.  The sanitizer does
    // not know that nothing below the svg matched, so it errs toward the
    // HTML rules, where the flag is ignored and the path holds the text.
    assertEquals(
        "<svg><path>x</path></svg>",
        p.sanitize("<svg></foo><path/>x</svg>"));
  }

  /**
   * Issue #457.  HTML raw-text and RCDATA modes do not apply to self-closing
   * foreign elements that happen to have the same names.
   */
  @Test
  void testSelfClosingForeignLiteralContentNames() {
    PolicyFactory p = foreignContentPolicy();
    assertEquals(
        "<svg><title></title>x</svg><p>after</p>",
        p.sanitize("<svg><title/>x</svg><p>after</p>"));
    assertEquals(
        "<svg><style></style>x</svg><p>after</p>",
        p.sanitize("<svg><style/>x</svg><p>after</p>"));
    assertEquals(
        "<svg><textarea></textarea>x</svg>",
        p.sanitize("<svg><textarea/>x</textarea></svg>"));
    assertEquals(
        "<math><textarea></textarea>x</math><p>after</p>",
        p.sanitize("<math><textarea/>x</math><p>after</p>"));
    // The dropped script closes before ordinary text, so that text survives.
    assertEquals(
        "<svg>visible</svg><p>after</p>",
        p.sanitize("<svg><script/>visible</svg><p>after</p>"));
    assertEquals(
        "<svg>visible</svg><p>after</p>",
        p.sanitize("<svg><plaintext/>visible</svg><p>after</p>"));
    // At an HTML integration point, the same name really is RCDATA and a
    // solidus does not close it.
    assertEquals(
        "<svg><foreignObject><title>x</title></foreignObject></svg>",
        p.sanitize(
            "<svg><foreignObject><title/>x</title></foreignObject></svg>"));
  }

  /**
   * Issue #122.  A self-closing tag is still subject to the policy, and what
   * follows one is still text or markup that the policy sees, so the flag
   * cannot smuggle anything past either.
   */
  @Test
  void testSelfClosingTagsInForeignContentAreStillSanitized() {
    PolicyFactory p = foreignContentPolicy();
    assertEquals(
        "<svg><path></path>x</svg>",
        p.sanitize("<svg><path onload=\"alert(1)\"/>x</svg>"));
    // The solidus does not end this tag, so what follows it is an attribute.
    assertEquals(
        "<svg><path>x</path></svg>",
        p.sanitize("<svg><path/onload=alert(1)>x</svg>"));
    assertEquals(
        "<svg>x</svg>",
        p.sanitize("<svg><a href=\"javascript:alert(1)\"/>x</svg>"));
    assertEquals(
        "<svg><a href=\"http://example.com/\"></a>x</svg>",
        p.sanitize("<svg><a href=\"http://example.com/\"/>x</svg>"));
    assertEquals(
        "<svg><g></g></svg>",
        p.sanitize("<svg><g/><img src=x onerror=alert(1)></svg>"));
    assertEquals(
        "<svg><foreignObject></foreignObject><div>x</div></svg>",
        p.sanitize("<svg><foreignObject/><div>x</div></svg>"));
    // A self-closing foreign RCDATA element closes before the next tag.
    assertEquals(
        "<svg><title></title></svg>",
        p.sanitize("<svg><title/><img src=x onerror=alert(1)></title></svg>"));
    assertEquals(
        "<svg><style></style></svg>",
        p.sanitize("<svg><style/><script>alert(1)</script></style></svg>"));
    // Text after a dropped element that closed itself is shown, as in a
    // browser, where that element is empty.
    assertEquals("<svg>x</svg>", p.sanitize("<svg><noscript/>x</svg>"));
    // Self-closing elements are siblings, so they never reach the nesting
    // limit.
    StringBuilder sb = new StringBuilder("<svg>");
    for (int i = 0; i < 300; ++i) { sb.append("<g/>"); }
    sb.append("x</svg>");
    String out = p.sanitize(sb.toString());
    assertEquals(300, out.split("<g></g>", -1).length - 1);
    assertTrue(out.endsWith("x</svg>"));
  }

  /** Issue #122.  The events a policy sees for a self-closing tag. */
  @Test
  void testSelfClosingTagEvents() {
    final List<String> events = new ArrayList<>();
    HtmlSanitizer.Policy recorder = new HtmlSanitizer.Policy() {
      public void openDocument() { events.add("openDocument"); }
      public void closeDocument() { events.add("closeDocument"); }
      public void openTag(String elementName, List<String> attrs) {
        events.add("openTag " + elementName + " " + attrs);
      }
      public void closeTag(String elementName) {
        events.add("closeTag " + elementName);
      }
      public void text(String text) { events.add("text " + text); }
    };
    HtmlSanitizer.sanitize(
        "<svg><path d=\"M0 0\"/>x</svg><path/>y", recorder);
    assertEquals(
        Arrays.asList(
            "openDocument",
            "openTag svg []",
            "openTag path [d, M0 0]",
            "closeTag path",
            "text x",
            "closeTag svg",
            "openTag path []",
            "text y",
            "closeDocument"),
        events);
  }

  /**
   * Issue #461.  Browsers process the end tags of table structure with
   * table scope, which no integration point bounds, so they can close the
   * foreign content around a cell along with the cell.
   */
  @Test
  void testTableScopeEndTagsEndForeignContent() {
    PolicyFactory p = foreignContentPolicy();
    for (String endTag
         : new String[] { "</table>", "</tbody>", "</tr>", "</td>" }) {
      assertEquals(
          "<svg><foreignObject><svg></svg></foreignObject></svg>",
          p.sanitize(
              "<table><tbody><tr><td><svg><foreignObject><svg>" + endTag
              + "<object/>hidden"),
          endTag);
    }
    assertEquals(
        "<svg><foreignObject><svg></svg></foreignObject></svg>",
        p.sanitize(
            "<table><caption><svg><foreignObject><svg></caption>"
            + "<object/>hidden"));
    assertEquals(
        "<svg><desc><svg></svg></desc></svg>",
        p.sanitize("<table><tr><td><svg><desc><svg></table><object/>hidden"));
    assertEquals(
        "<math><mi><svg></svg></mi></math>",
        p.sanitize("<table><tr><td><math><mi><svg></table><object/>hidden"));
    assertEquals(
        "<math><annotation-xml encoding=\"text/html\"><svg></svg>"
        + "</annotation-xml></math>",
        p.sanitize(
            "<table><tr><td><math><annotation-xml encoding=text/html><svg>"
            + "</table><object/>hidden"));
    // This table began below the tracked foreign root, so the context stays
    // unknown after the end tag.
    assertEquals(
        "<svg><foreignObject><svg></svg></foreignObject></svg>"
        + "<svg><path>x</path></svg>",
        p.sanitize(
            "<table><tr><td><svg><foreignObject><svg></table><svg><path/>x"));
    // Table structure inside an integration point follows the inherited
    // table insertion mode, including implied elements and cell closing.
    assertEquals(
        "<svg><foreignObject><svg></svg></foreignObject></svg>",
        p.sanitize(
            "<svg><foreignObject><table><tr><td><svg></tbody>"
            + "<object/>hidden"));
    assertEquals(
        "<svg><foreignObject><svg>hidden</svg></foreignObject></svg>",
        p.sanitize("<svg><foreignObject><select><svg><object/>hidden"));
    // An end tag searched in the default or list-item scope stops at the
    // integration point, so a browser ignores it and the dropped element
    // still closes itself in foreign content.
    assertEquals(
        "<svg><foreignObject><svg></svg></foreignObject></svg>shown",
        p.sanitize(
            "<ul><li><svg><foreignObject><svg></li><object/>shown"));
  }

  /** Issue #461.  HTML start-tag rules can remove tracked stack entries. */
  @Test
  void testHtmlStartTagsUpdateForeignContentContext() {
    PolicyFactory p = foreignContentPolicy();
    String[] inputs = {
        // image is rewritten to the void img element.
        "<svg><foreignObject><image><math></svg><object/>hidden",
        // command and isindex are ordinary elements in the current parser,
        // despite legacy serialization tables classifying them as void.
        "<svg><foreignObject><command><math></math></foreignObject>"
        + "<object/>hidden",
        "<svg><foreignObject><isindex><math></math></foreignObject>"
        + "<object/>hidden",
        // A block start closes p in button scope.
        "<svg><foreignObject><p><div></div><math></svg><object/>hidden",
        "<svg><foreignObject><p><hr><math></svg><object/>hidden",
        // A heading start pops a heading current node.
        "<svg><foreignObject><h2><h1></h1><math></svg><object/>hidden",
        // A second button pops the first button and everything above it.
        "<svg><foreignObject><button><div><button></button></div>"
        + "<math></svg><object/>hidden",
        // Duplicate formatting elements invoke the adoption agency rules.
        "<svg><foreignObject><a><div><a></a></div><math></svg>"
        + "<object/>hidden",
        "<svg><foreignObject><nobr><div><nobr></nobr></div><math></svg>"
        + "<object/>hidden",
        // A non-formatting end tag can strand b in the active formatting
        // list, from which a later start tag reconstructs it.
        "<svg><foreignObject><div><b></div><math></math>"
        + "</foreignObject><object/>hidden",
        // An adoption-agency end tag removes only its own formatting entry;
        // other formatting elements it pops can still be reconstructed.
        "<svg><foreignObject><b><i></b><math></math></foreignObject>"
        + "<object/>hidden",
        // A duplicate form is ignored while the form pointer is non-null.
        "<svg><foreignObject><form><div><form></form></div><math></svg>"
        + "<object/>hidden",
        // A form start closes p before inserting the form.
        "<svg><foreignObject><p><form></form><math></svg><object/>hidden",
        // A form end generates implied end tags before removing the form.
        "<svg><foreignObject><form><option></form><image><math></svg>"
        + "<object/>hidden",
        // New list and description items close an earlier item.
        "<svg><foreignObject><li><div><li></li></div><math></svg>"
        + "<object/>hidden",
        "<svg><foreignObject><dd><div><dt></dt></div><math></svg>"
        + "<object/>hidden",
        // A second option closes the current option even without a select.
        "<svg><foreignObject><option><option></option><math></svg>"
        + "<object/>hidden",
        // input pops a select that is in scope under the current rules.
        "<svg><foreignObject><select><input><math></svg><object/>hidden",
        // In table mode a form is inserted and immediately popped.
        "<table><svg><foreignObject><form><math></svg><object/>hidden",
    };
    for (String input : inputs) {
      String output = p.sanitize(input);
      assertFalse(output.contains("hidden"), input + " -> " + output);
    }
    // bgsound is still inserted and immediately popped by the tree builder,
    // even though it is absent from the sanitizer's legacy void table.
    assertEquals(
        "<svg><foreignObject><math></math></foreignObject>hidden</svg>",
        p.sanitize(
            "<svg><foreignObject><bgsound><math></math></foreignObject>"
            + "<object/>hidden"));
  }

  /** Issue #461.  {@code </form>} has a different effect in a template. */
  @Test
  void testFormEndTagInTemplatePopsThroughForm() {
    assertEquals(
        "<form><svg></svg></form>",
        foreignContentPolicy().sanitize(
            "<body><template><form><svg></form><object/>hidden"));
  }

  /** Well-formed HTML islands do not poison later foreign-content tracking. */
  @Test
  void testForeignContentContextRecoversAfterHtmlIsland() {
    PolicyFactory p = foreignContentPolicy();
    assertEquals(
        "<svg><path></path><rect></rect></svg>"
        + "<svg><path></path></svg>",
        p.sanitize(
            "<table><tr><td><svg><path/><rect/></svg></td></tr></table>"
            + "<svg><path/></svg>"));
    assertEquals(
        "<svg><foreignObject></foreignObject></svg>"
        + "<svg><path></path><rect></rect></svg>",
        p.sanitize(
            "<svg><foreignObject><table></table></foreignObject></svg>"
            + "<svg><path/><rect/></svg>"));
    assertEquals(
        "<svg><foreignObject></foreignObject></svg>"
        + "<svg><title></title><path></path></svg><p>after</p>",
        p.sanitize(
            "<svg><foreignObject><select></select></foreignObject></svg>"
            + "<svg><title/><path/></svg><p>after</p>"));
  }

  /**
   * Issue #461.  Under the HTML rules an end tag search stops at an element
   * in the special category, so the elements above it stay open, and the
   * end tag of the integration point holding them is ignored while they do.
   */
  @Test
  void testSpecialElementsBlockHtmlEndTagsInForeignContent() {
    PolicyFactory p = foreignContentPolicy();
    assertEquals(
        "<svg><foreignObject><cite><div></div></cite></foreignObject></svg>",
        p.sanitize(
            "<svg><foreignObject><cite><div></cite></foreignObject>"
            + "<object/>hidden"));
    assertEquals(
        "<math><mi><cite><div></div></cite></mi></math>",
        p.sanitize("<math><mi><cite><div></cite></mi><object/>hidden"));
    // A td start tag is ignored in body, but the div it seems to hold is
    // still special.
    assertEquals(
        "<svg><foreignObject><div></div></foreignObject></svg>",
        p.sanitize(
            "<svg><foreignObject><td><div></td></foreignObject>"
            + "<object/>hidden"));
    // Without a special element in the way the end tags match, the
    // integration point closes, and the flag is honored again.
    assertEquals(
        "<svg><foreignObject><cite><kbd></kbd></cite></foreignObject>"
        + "<path></path>x</svg>",
        p.sanitize(
            "<svg><foreignObject><cite><kbd></cite></foreignObject>"
            + "<path/>x"));
    // Any h1 through h6 end tag closes an open heading.
    assertEquals(
        "<svg><foreignObject><h2><svg></svg></h2></foreignObject></svg>",
        p.sanitize("<svg><foreignObject><h2><svg></h1><object/>hidden"));
    // </form> removes the form without closing what it holds.
    assertEquals(
        "<svg><foreignObject><form><cite></cite></form></foreignObject></svg>",
        p.sanitize(
            "<svg><foreignObject><form><cite></form></foreignObject>"
            + "<object/>hidden"));
    assertEquals(
        "<svg><foreignObject><form><svg></svg></form>shown</foreignObject>"
        + "</svg>",
        p.sanitize(
            "<svg><foreignObject><form><svg></form><object/>shown"));
    // The adoption agency algorithm rebuilds the stack around a special
    // element and drops the foreign nodes above it.
    assertEquals(
        "<svg><foreignObject><b><div><svg></svg></div></b></foreignObject>"
        + "</svg>",
        p.sanitize(
            "<svg><foreignObject><b><div><svg></b></foreignObject>"
            + "<object/>hidden"));
    // When a special element blocks the end tag, the foreign element above
    // it is still the current node, where the flag is honored.
    assertEquals(
        "<svg><foreignObject><cite><div><svg></svg></div></cite>shown"
        + "</foreignObject></svg>",
        p.sanitize(
            "<svg><foreignObject><cite><div><svg></cite><object/>shown"));
  }

  /**
   * Issue #461.  After a stray end tag the tracker cannot tell whether the
   * browser left the foreign content, and the next svg start tag inside
   * MathML is a MathML element whose foreignObject is not an integration
   * point, so the tracker stays unknown rather than starting over.
   */
  @Test
  void testStrayEndTagLeavesForeignContentContextUnknown() {
    PolicyFactory p = foreignContentPolicy();
    assertEquals(
        "<math><mrow><svg><foreignObject><div></div></foreignObject></svg>"
        + "</mrow></math>",
        p.sanitize(
            "<math><mrow></foo><svg><foreignObject><div></div>"
            + "</foreignObject><object/>hidden"));
    assertEquals(
        "<svg><g></g></svg><svg><path>x</path></svg>",
        p.sanitize("<svg><g></foo></g></svg><svg><path/>x</svg>"));
    // A self-closing root is still empty in every context.
    assertEquals(
        "<svg><g></g></svg><svg></svg>x",
        p.sanitize("<svg><g></foo></g></svg><svg/>x"));
  }

  /**
   * Issue #461.  More start-tag rules that change the tracked stack, and
   * those whose outcome the sanitizer cannot know.
   */
  @Test
  void testMoreHtmlStartTagRulesInForeignContentContext() {
    PolicyFactory p = foreignContentPolicy();
    // xmp closes a p in button scope, as pre and listing do.
    assertEquals(
        "<svg><foreignObject><p></p><math></math></foreignObject></svg>",
        p.sanitize(
            "<svg><foreignObject><p><xmp></xmp><math></svg><object/>hidden"));
    assertEquals(
        "<svg><foreignObject><p></p></foreignObject></svg>"
        + "<svg><path></path></svg>",
        p.sanitize(
            "<svg><foreignObject><p><xmp></xmp></foreignObject></svg>"
            + "<svg><path/></p></foreignObject><object/>hidden"));
    // Whether a table start closes an open p depends on the quirks mode of
    // the document that embeds the output, so the context fails closed.
    assertEquals(
        "<svg><foreignObject><p></p></foreignObject></svg>",
        p.sanitize(
            "<svg><foreignObject><p><table></table></foreignObject>"
            + "<object/>hidden"));
    // The tokenizer keeps only the first of duplicate attributes, so this
    // input is not hidden: in table mode it still pops the open select.
    assertEquals(
        "<svg><foreignObject></foreignObject></svg>",
        p.sanitize(
            "<table><svg><foreignObject><select><input type=text type=hidden>"
            + "</foreignObject></svg></select></foreignObject>"
            + "<object/>hidden"));
    // A table inside a cell's foreign content is tracked exactly and hands
    // the cell's in-body rules back when it closes.
    assertEquals(
        "<svg><foreignObject></foreignObject></svg>",
        p.sanitize(
            "<table><tr><td><svg><foreignObject><table></table>"
            + "<object/>hidden"));
    // A self-closing root closes itself even where the tracker gives up.
    assertEquals(
        "<svg><foreignObject><svg></svg>x</foreignObject></svg>",
        p.sanitize("<svg><foreignObject><table><svg/>x"));
  }

  /**
   * Issue #461.  The specification puts search in the special category but
   * Chrome does not, so an end-tag or list-item walk that reaches one has
   * no single right answer, and the context fails closed.
   */
  @Test
  void testSearchElementCategoryIsNotReliedOn() {
    PolicyFactory p = foreignContentPolicy();
    assertEquals(
        "<svg><foreignObject><cite></cite></foreignObject></svg>",
        p.sanitize(
            "<svg><foreignObject><cite><search><span></cite></foreignObject>"
            + "</svg></span></search></cite></foreignObject><object/>hidden"));
    assertEquals(
        "<svg><foreignObject></foreignObject></svg>",
        p.sanitize(
            "<svg><foreignObject><li><search><li></li></foreignObject></svg>"
            + "</search></li></foreignObject><object/>hidden"));
  }

  /**
   * Issue #461.  Like {@code search}, {@code dialog} is in the special
   * category of the WHATWG parsing algorithm but not in Chrome's special-node
   * set, so a walk that reaches an open {@code dialog} has no single right
   * answer across browsers and the context must fail closed.  Without this a
   * following {@code <object/>} was honored as self-closing, exposing text
   * that a spec-compliant parser keeps inside the HTML {@code object}.
   */
  @Test
  void testDialogElementCategoryIsNotReliedOn() {
    PolicyFactory p = foreignContentPolicy();
    // "Any other end tag" (</cite>) walks past the open dialog.
    assertEquals(
        "<svg><foreignObject><cite></cite></foreignObject></svg>",
        p.sanitize(
            "<svg><foreignObject><cite><dialog></cite></foreignObject>"
            + "<object/>hidden"));
    // A list-item start (<li>) walks past the open dialog.
    assertEquals(
        "<svg><foreignObject></foreignObject></svg>",
        p.sanitize(
            "<svg><foreignObject><li><dialog><li></li></foreignObject>"
            + "<object/>hidden"));
    // The adoption agency's furthest-block search (</b>) reaches the dialog.
    assertEquals(
        "<svg><foreignObject><b><svg></svg></b></foreignObject></svg>",
        p.sanitize(
            "<svg><foreignObject><b><dialog><svg></b></foreignObject>"
            + "<object/>hidden"));
  }

  /**
   * Issue #461.  The insertion mode inherited from an untracked table
   * depends on which cell, caption or section is open, and browsers ignore
   * the end tags that name something else.
   */
  @Test
  void testUntrackedTableEndTagsMustNameTheOpenPart() {
    PolicyFactory p = foreignContentPolicy();
    String svgForm
        = "<svg><foreignObject><form></foreignObject><object/>hidden";
    // Inside a cell or caption the in-body rules insert the form, which
    // stays open and keeps the object's fallback text hidden.
    String hidden = "<svg><foreignObject><form></form></foreignObject></svg>";
    for (String context : new String[] {
             "<table><tr><th></td>", "<table><tr><td></th>",
             "<table><thead><tr><td></tbody>", "<table><tr><td></tfoot>",
             "<table><tr><td></caption>", "<table><caption></tr>",
             "<table><caption></tbody>", "<table><caption></td>",
             "<table><caption>", "<table><tr><td><table></table>",
             "<table><tr><td><table><tr><td></table>",
             "<table><tr><td><table><tr><td></td></tr></table>" }) {
      assertEquals(hidden, p.sanitize(context + svgForm), context);
    }
    // Back in the table modes the form is inserted and popped at once, so
    // the foreignObject closes and the object is foreign.
    String shown
        = "<svg><foreignObject><form></form></foreignObject>hidden</svg>";
    for (String context : new String[] {
             "<table><tr><td></td>", "<table><tr><td></tr>",
             "<table><thead><tr><td></thead>", "<table><caption></caption>",
             "<table><tr><td><table></table></td>",
             "<table><tr><td><table><tr><td></td></tr></table></td>" }) {
      assertEquals(shown, p.sanitize(context + svgForm), context);
    }
    // Table structure inside a caption closes the caption and everything
    // above it, which the tracker does not follow.
    assertEquals(
        "<svg><foreignObject></foreignObject></svg>",
        p.sanitize(
            "<table><caption><svg><foreignObject><td></foreignObject>"
            + "<object/>hidden"));
  }

  /** Well-formed nested tables and captions do not poison later SVG. */
  @Test
  void testForeignContentContextRecoversAfterNestedTables() {
    PolicyFactory p = foreignContentPolicy();
    assertEquals(
        "x<svg><path></path><rect></rect></svg>",
        p.sanitize(
            "<table><tr><td><table><tr><td>x</td></tr></table></td></tr>"
            + "</table><svg><path/><rect/></svg>"));
    assertEquals(
        "x<svg><path></path><rect></rect></svg>",
        p.sanitize(
            "<table><caption>x</caption></table><svg><path/><rect/></svg>"));
    assertEquals(
        "<svg><path></path><rect></rect></svg>",
        p.sanitize(
            "<table><caption><table></table></caption></table>"
            + "<svg><path/><rect/></svg>"));
  }

  /**
   * Issue #461.  The modeled transitions are followed exactly rather than
   * by failing closed: a self-closing tag is still honored in later SVG.
   */
  @Test
  void testModeledTransitionsKeepHonoringSelfClosingTags() {
    PolicyFactory p = foreignContentPolicy();
    String[] inputs = {
        "<svg><foreignObject><p><div></div><math></svg><svg><path/>x",
        "<svg><foreignObject><h2><h1></h1><math></svg><svg><path/>x",
        "<svg><foreignObject><button><div><button></button></div><math>"
        + "</svg><svg><path/>x",
        "<svg><foreignObject><form><div><form></form></div><math></svg>"
        + "<svg><path/>x",
        "<svg><foreignObject><li><div><li></li></div><math></svg>"
        + "<svg><path/>x",
        "<svg><foreignObject><dd><div><dt></dt></div><math></svg>"
        + "<svg><path/>x",
        "<svg><foreignObject><option><option></option><math></svg>"
        + "<svg><path/>x",
        "<svg><foreignObject><select><input><math></svg><svg><path/>x",
        "<svg><foreignObject><p><hr><math></svg><svg><path/>x",
        "<svg><foreignObject><p><xmp></xmp><math></svg><svg><path/>x",
        "<svg><foreignObject><image><math></svg><svg><path/>x",
        "<svg><foreignObject><form><option></form><image><math></svg>"
        + "<svg><path/>x",
        "<svg><foreignObject><h2><svg></h1><svg><path/>x",
        "<svg><foreignObject><form><cite></form></foreignObject>"
        + "<svg><path/>x",
        "<svg><foreignObject><cite><div></cite></foreignObject>"
        + "<svg><path/>x",
        "<table><svg><foreignObject><form><math></svg><svg><path/>x",
        "<table><tr><th></td><svg><foreignObject><form></foreignObject>"
        + "</svg><svg><path/>x",
        "<table><tr><td><table><tr><td>x</td></tr></table></td></tr></table>"
        + "<svg><foreignObject><form></foreignObject></svg><svg><path/>x",
    };
    for (String input : inputs) {
      String output = p.sanitize(input);
      assertTrue(output.contains("<path></path>x"), input + " -> " + output);
    }
  }

  /** The bounded context tracker falls back to suppressing dropped content. */
  @Test
  void testDeepForeignContentContextFailsClosed() {
    PolicyFactory p = foreignContentPolicy();
    StringBuilder html = new StringBuilder("<svg>");
    for (int i = 0; i < 300; ++i) { html.append("<g>"); }
    html.append("<object/>hidden");
    String out = p.sanitize(html.toString());
    assertFalse(out.contains("hidden"), out);
  }

  private static PolicyFactory foreignContentPolicy() {
    return new HtmlPolicyBuilder()
        .allowElements(
            "svg", "math", "path", "g", "rect", "clipPath", "foreignObject",
            "desc", "annotation-xml", "textArea", "textarea", "mi", "mrow",
            "mglyph", "a", "div", "p", "font", "br", "style", "title",
            "cite", "kbd", "b", "h2", "form")
        .allowAttributes("width", "height", "viewBox").onElements("svg")
        .allowAttributes("id", "opacity", "d").onElements("path")
        .allowAttributes("href").onElements("a")
        .allowAttributes("color").onElements("font")
        .allowAttributes("encoding").onElements("annotation-xml")
        .allowWithoutAttributes("font")
        .allowStandardUrlProtocols()
        .toFactory();
  }

  private static String sanitize(@Nullable String html) {
    StringBuilder sb = new StringBuilder();
    HtmlStreamRenderer renderer = HtmlStreamRenderer.create(
        sb, errorMessage -> fail(errorMessage));

    HtmlSanitizer.Policy policy = new HtmlPolicyBuilder()
        // Allow these tags.
       .allowElements(
           "a", "b", "br", "div", "i", "iframe", "img", "input", "li",
           "ol", "p", "span", "ul", "noscript", "noframes", "noembed", "noxss")
       // And these attributes.
       .allowAttributes(
           "dir", "checked", "class", "href", "id", "target", "title", "type",
               "__foo", "__bar", "foo-bar")
       .globally()
       // Cleanup IDs and CLASSes and prefix them with p- to move to a separate
       // name-space.
       .allowAttributes("id", "class")
       .matching(
           (elementName, attributeName, value) ->
               value.replaceAll("(?:^|\\s)([a-zA-Z])", " p-$1")
                   .replaceAll("\\s+", " ")
                   .trim())
       .globally()
       .allowStyling()
       // Don't throw out useless <img> and <input> elements to ease debugging.
       .allowWithoutAttributes("img", "input")
       .build(renderer);

    HtmlSanitizer.sanitize(html, policy);

    return sb.toString();
  }

  private static String stringRepeatedTimes(String s, int n) {
    StringBuilder sb = new StringBuilder(s.length() * n);
    for (int nToAppend = n; --nToAppend >= 0;) {
      sb.append(s);
    }
    return sb.toString();
  }
}
