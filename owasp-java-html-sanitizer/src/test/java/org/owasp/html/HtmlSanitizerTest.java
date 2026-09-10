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
