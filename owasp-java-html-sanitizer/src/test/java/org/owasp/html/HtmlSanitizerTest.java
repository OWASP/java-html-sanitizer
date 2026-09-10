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

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;
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
    assertEquals("<p></p>", sanitize("<p/b/"));  // Short-tag discarded.
    assertEquals("<p></p>", sanitize("<p<b>"));  // Discard <b attribute
    assertEquals(
        // This behavior for short tags is not ideal, but it is safe.
        "<p href=\"/\">first part of the text&lt;/&gt; second part</p>",
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
   * Ensure that, if <div> is allowed, then <div> injected inside <style>
   * is retained by the sanitizer (since it is now in the policy).
   */
  @Test
  void testCVE202566021_3() {
    // Arrange: <div> is now allowed, so it should survive sanitization inside <style>.
    String actualPayload = "<noscript><style>/* user content */.x { font-size: 12px; }<div id=\"good\">ALLOWED?</div></style></noscript>";
    String expectedPayload = "<noscript><style>/* user content */.x { font-size: 12px; }<div id=\"good\">ALLOWED?</div></style></noscript>";

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
   * does not allow the injected script. Sanitizer closes elements properly and only emits allowed tags.
   */
  @Test
  void testCVE202566021_4() {
    // Arrange: Try to break out of <style> and <noscript>, then add a script. Only style/noscript/p allowed.
    String actualPayload = "<noscript><style></noscript><script>alert(1)</script>";
    String expectedPayload = "<noscript><style></noscript></style></noscript>";

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
   * and strips the injected script tag completely.
   */
  @Test
  void testCVE202566021_5() {
    // Arrange: Try to break out of <style> through <p>, then add a script. Only style/noscript/p allowed.
    String actualPayload = "<p><style></p><script>alert(1)</script>";
    String expectedPayload = "<p><style></p></style></p>";

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
    // closes; browsers hit EOF inside the tag and drop everything from it on.
    assertEquals(
        "<p>foo</p> <p class=\"p-test\"></p>",
        sanitize("<p>foo</p> <p class=\"test\" \"=\">bar</p> <p>baz</p>"));
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
