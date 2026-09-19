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

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.owasp.html.TagBalancingHtmlStreamEventReceiver
    .isInterElementWhitespace;
import static org.owasp.shim.Java8Shim.j8;

class TagBalancingHtmlStreamRendererTest {

  StringBuilder htmlOutputBuffer;
  TagBalancingHtmlStreamEventReceiver balancer;
  int emittedOpenElements;
  int emittedCloseElements;

  @BeforeEach
  void createBalancer() {
    htmlOutputBuffer = new StringBuilder();
    HtmlStreamEventReceiver renderer = HtmlStreamRenderer.create(
        htmlOutputBuffer,
        x -> fail("Unexpected renderer error: " + x));
    balancer = new TagBalancingHtmlStreamEventReceiver(
        new HtmlStreamEventReceiverWrapper(renderer) {
          @Override
          public void openTag(String elementName, List<String> attrs) {
            super.openTag(elementName, attrs);
            if (!HtmlTextEscapingMode.isVoidElement(
                HtmlLexer.canonicalElementName(elementName))) {
              ++emittedOpenElements;
            }
          }

          @Override
          public void closeTag(String elementName) {
            super.closeTag(elementName);
            ++emittedCloseElements;
          }
        });
  }

  @Test
  void testTagBalancing() {
    balancer.openDocument();
    balancer.openTag("html", j8().listOf());
    balancer.openTag("head", j8().listOf());
    balancer.openTag("title", j8().listOf());
    balancer.text("Hello, <<World>>!");
    // TITLE closed with case-sensitively different name.
    balancer.closeTag("TITLE");
    balancer.closeTag("head");
    balancer.openTag("body", j8().listOf());
    balancer.openTag("p", j8().listOf("id", "p'0"));
    balancer.text("Hello,");
    balancer.openTag("Br", j8().listOf());
    balancer.text("<<World>>!");
    // HTML, P, and BODY unclosed, but BR not.
    balancer.closeDocument();

    assertEquals(
        "<html><head><title>Hello, &lt;&lt;World&gt;&gt;!</title></head>"
        + "<body><p id=\"p&#39;0\">Hello,"
        + "<br />&lt;&lt;World&gt;&gt;!</p></body></html>",
        htmlOutputBuffer.toString());
  }

  @Test
  void testTagSoupIronedOut() {
    balancer.openDocument();
    balancer.openTag("i", j8().listOf());
    balancer.text("x");
    balancer.openTag("b", j8().listOf());
    balancer.text("y");
    balancer.closeTag("i");
    balancer.text("z");
    balancer.closeDocument();

    assertEquals(
        "<i>x<b>y</b></i><b>z</b>",
        htmlOutputBuffer.toString());
  }

  @Test
  void testListInListDirectly() {
    balancer.openDocument();
    balancer.openTag("ul", j8().listOf());
    balancer.openTag("li", j8().listOf());
    balancer.text("foo");
    balancer.closeTag("li");
    balancer.openTag("ul", j8().listOf());
    balancer.openTag("li", j8().listOf());
    balancer.text("bar");
    balancer.closeTag("li");
    balancer.closeTag("ul");
    balancer.closeTag("ul");
    balancer.closeDocument();

    assertEquals(
        "<ul><li>foo</li><li><ul><li>bar</li></ul></li></ul>",
        htmlOutputBuffer.toString());
  }

  @Test
  void testTextContent() {
    balancer.openDocument();
    balancer.openTag("title", j8().listOf());
    balancer.text("Hello, World!");
    balancer.closeTag("title");
    balancer.text("Hello, ");
    balancer.openTag("b", j8().listOf());
    balancer.text("World!");
    balancer.closeTag("b");
    balancer.openTag("p", j8().listOf());
    balancer.text("Hello, ");
    balancer.openTag("textarea", j8().listOf());
    balancer.text("World!");
    balancer.closeTag("textarea");
    balancer.closeTag("p");
    balancer.openTag("h1", j8().listOf());
    balancer.text("Hello");
    balancer.openTag("style", j8().listOf("type", "text/css"));
    balancer.text("\n.World {\n  color: blue\n}\n");
    balancer.closeTag("style");
    balancer.closeTag("h1");
    balancer.openTag("ul", j8().listOf());
    balancer.text("\n  ");
    balancer.openTag("li", j8().listOf());
    balancer.text("Hello,");
    balancer.closeTag("li");
    balancer.text("\n  ");
    balancer.text("World!");
    balancer.closeDocument();

    assertEquals(
        // Text and only text allowed in title
        "<title>Hello, World!</title>"
        // Text allowed at top level and in phrasing content
        + "Hello, <b>World!</b>"
        // Text allowed in block elements and in text areas.
        + "<p>Hello, <textarea>World!</textarea></p>"
        + "<h1>Hello"
        // Text allowed in special style tag.
        + "<style type=\"text/css\">\n"
        + ".World {\n  color: blue\n}\n"
        + "</style></h1>"
        // Whitespace allowed inside <ul> but non-whitespace text nodes are
        // moved inside <li>.
        + "<ul><li>Hello,</li><li>World!</li></ul>",
        htmlOutputBuffer.toString());
  }

  @Test
  void testMismatchedHeaders() {
    balancer.openDocument();
    balancer.openTag("H1", j8().listOf());
    balancer.text("header");
    balancer.closeTag("h1");
    balancer.text("body");
    balancer.openTag("H2", j8().listOf());
    balancer.text("sub-header");
    balancer.closeTag("h3");
    balancer.text("sub-body");
    balancer.openTag("h3", j8().listOf());
    balancer.text("sub-sub-");
    balancer.closeTag("hr"); // hr is not a header tag so does not close an h3.
    balancer.text("header");
    // <h3> is not allowed in h3.
    balancer.openTag("h3", j8().listOf());
    balancer.closeTag("h3");
    balancer.text("sub-sub-body");
    balancer.closeTag("H4");
    balancer.closeTag("h2");
    balancer.closeDocument();

    assertEquals(

        "<h1>header</h1>body"
        + "<h2>sub-header</h2>sub-body"
        + "<h3>sub-sub-header</h3><h3></h3>sub-sub-body",
        htmlOutputBuffer.toString());
  }

  @Test
  void testListNesting() {
    balancer.openDocument();
    balancer.openTag("ul", j8().listOf());
    balancer.openTag("li", j8().listOf());
    balancer.openTag("ul", j8().listOf());
    balancer.openTag("li", j8().listOf());
    balancer.text("foo");
    balancer.closeTag("li");
    // Does not closes the second <ul> since only </ol> and </ul> can close a
    // <ul> based on the "has an element in list scope test" used by the HTML5
    // tree building algo.
    balancer.closeTag("li");
    // This would append inside a list, not an item.  We insert an <li>.
    balancer.openTag("ul", j8().listOf());
    balancer.openTag("li", j8().listOf());
    balancer.text("bar");
    balancer.closeDocument();

    assertEquals(
        "<ul><li><ul><li>foo</li><li><ul><li>bar</li></ul></li></ul></li></ul>",
        htmlOutputBuffer.toString());
  }

  @Test
  void testTableNesting() {
    balancer.openDocument();
    balancer.openTag("table", j8().listOf());
    balancer.openTag("tbody", j8().listOf());
    balancer.openTag("tr", j8().listOf());
    balancer.openTag("td", j8().listOf());
    balancer.text("foo");
    balancer.closeTag("td");
    // Chrome does not insert a td to contain this mis-nested table.
    // Instead, it ends one table and starts another.
    balancer.openTag("table", j8().listOf());
    balancer.openTag("tbody", j8().listOf());
    balancer.openTag("tr", j8().listOf());
    balancer.openTag("th", j8().listOf());
    balancer.text("bar");
    balancer.closeTag("table");
    balancer.closeTag("table");
    balancer.closeDocument();

    assertEquals(
        "<table><tbody><tr><td>foo</td></tr></tbody></table>"
        + "<table><tbody><tr><th>bar</th></tr></tbody></table>",

        htmlOutputBuffer.toString());
  }

  /**
   * A browser puts content that cannot go inside a table in front of the
   * table and keeps the table open, so that the next row pops the content
   * and carries on in the same table (#342).  The output cannot put anything
   * in front of a tag already written, so the table is closed there and
   * written again for the row; the content is closed when the row comes,
   * where it used to stay open and swallow the row and everything after.
   */
  @Test
  void testContentPushedOutOfATableIsClosedWhenTheTableResumes() {
    balancer.openDocument();
    balancer.openTag("table", j8().listOf());
    balancer.openTag("div", j8().listOf());
    balancer.text("x");
    balancer.openTag("tr", j8().listOf());
    balancer.openTag("td", j8().listOf());
    balancer.text("y");
    balancer.closeTag("td");
    balancer.closeTag("tr");
    balancer.closeTag("div");  // Ignored: no div in table scope.
    balancer.closeTag("table");
    balancer.text("tail");
    balancer.closeDocument();

    assertEquals(
        "<table></table><div>x</div>"
        + "<table><tbody><tr><td>y</td></tr></tbody></table>tail",
        htmlOutputBuffer.toString());
  }

  /** The row group and row the content was pushed out of return as well. */
  @Test
  void testPushedOutRowAndRowGroupReturnWithTheTable() {
    balancer.openDocument();
    balancer.openTag("table", j8().listOf());
    balancer.openTag("tbody", j8().listOf());
    balancer.openTag("tr", j8().listOf());
    balancer.openTag("td", j8().listOf());
    balancer.text("a");
    balancer.closeTag("td");
    balancer.openTag("div", j8().listOf());
    balancer.text("x");
    balancer.openTag("td", j8().listOf());
    balancer.text("b");
    balancer.closeTag("td");
    balancer.closeTag("tr");
    balancer.closeTag("table");
    balancer.closeDocument();

    assertEquals(
        "<table><tbody><tr><td>a</td></tr></tbody></table><div>x</div>"
        + "<table><tbody><tr><td>b</td></tr></tbody></table>",
        htmlOutputBuffer.toString());
  }

  /** The table's own end tag ends the content pushed out of it. */
  @Test
  void testPushedOutTableEndsWithItsEndTag() {
    balancer.openDocument();
    balancer.openTag("table", j8().listOf());
    balancer.openTag("div", j8().listOf());
    balancer.text("x");
    balancer.closeTag("table");
    balancer.text("tail");
    balancer.closeDocument();

    assertEquals(
        "<table></table><div>x</div>tail", htmlOutputBuffer.toString());
  }

  /**
   * A pushed-out table is closed in the output but still counts toward the
   * nesting limit, which is a conservative reading of the limit.
   */
  @Test
  void testPushedOutTableCountsTowardTheNestingLimit() {
    balancer.setNestingLimit(3);
    balancer.openDocument();
    balancer.openTag("table", j8().listOf());
    balancer.openTag("div", j8().listOf());
    balancer.openTag("p", j8().listOf());
    balancer.openTag("span", j8().listOf());  // Past the limit.
    balancer.text("x");
    balancer.closeDocument();

    assertEquals(
        "<table></table><div><p>x</p></div>", htmlOutputBuffer.toString());
  }

  /** Implied table structure never opens past a small nesting limit. */
  @Test
  void testPushedOutTableImpliedElementsRespectSmallNestingLimits() {
    String[] expected = {
        "xytail",
        "<table></table>x<table></table>ytail",
        "<table></table><div>x</div>"
            + "<table><tbody></tbody></table>ytail",
        "<table></table><div>x</div>"
            + "<table><tbody><tr></tr></tbody></table>ytail",
    };
    for (int limit = 0; limit < expected.length; ++limit) {
      StringBuilder out = new StringBuilder();
      TagBalancingHtmlStreamEventReceiver limited =
          new TagBalancingHtmlStreamEventReceiver(
              HtmlStreamRenderer.create(
                  out, x -> fail("Unexpected renderer error: " + x)));
      limited.setNestingLimit(limit);
      limited.openDocument();
      limited.openTag("table", j8().listOf());
      limited.openTag("div", j8().listOf());
      limited.text("x");
      limited.openTag("tr", j8().listOf());
      limited.openTag("td", j8().listOf());
      limited.text("y");
      limited.closeTag("td");
      limited.closeTag("tr");
      limited.closeTag("table");
      limited.text("tail");
      limited.closeDocument();

      assertEquals(expected[limit], out.toString(), "limit " + limit);
    }
  }

  /** An empty table-mode form does not consume nesting depth. */
  @Test
  void testTableFormRespectsSmallNestingLimits() {
    String[] expected = {
        "xy",
        "<table></table>x<table></table>y",
        "<table><form></form></table>x<table><tbody></tbody></table>y",
        "<table><form></form></table>x"
            + "<table><tbody><tr></tr></tbody></table>y",
        "<table><form></form></table>x"
            + "<table><tbody><tr><td>y</td></tr></tbody></table>",
    };
    for (int limit = 0; limit < expected.length; ++limit) {
      StringBuilder out = new StringBuilder();
      TagBalancingHtmlStreamEventReceiver limited =
          new TagBalancingHtmlStreamEventReceiver(
              HtmlStreamRenderer.create(
                  out, x -> fail("Unexpected renderer error: " + x)));
      limited.setNestingLimit(limit);
      limited.openDocument();
      limited.openTag("table", j8().listOf());
      limited.openTag("form", j8().listOf());
      limited.text("x");
      limited.openTag("tr", j8().listOf());
      limited.openTag("td", j8().listOf());
      limited.text("y");
      limited.closeDocument();

      assertEquals(expected[limit], out.toString(), "limit " + limit);
    }
  }

  /** The form-pointer reset pair also stays within the nesting limit. */
  @Test
  void testFormPointerResetPairRespectsTheNestingLimit() {
    assertEquals(
        "<form><table><tbody></tbody></table></form>",
        renderBalancedEvents(3, "form", "table", "tbody", "/form"));

    PolicyFactory factory = new HtmlPolicyBuilder()
        .allowElements("form", "table", "tbody")
        .allowTextIn("form", "table", "tbody")
        .allowWithoutAttributes("form", "table", "tbody")
        .toFactory();
    StringBuilder output = new StringBuilder();
    List<String> open = new ArrayList<>();
    int[] eventCounts = new int[3];
    TagBalancingHtmlStreamEventReceiver limited =
        new TagBalancingHtmlStreamEventReceiver(
            factory.apply(strictRenderer(output, open, eventCounts)));
    limited.setNestingLimit(3);
    limited.openDocument();
    limited.openTag("form", j8().listOf());
    limited.openTag("table", j8().listOf());
    limited.openTag("tbody", j8().listOf());
    limited.closeTag("form");
    limited.closeDocument();

    assertEquals(
        "<form><table><tbody></tbody></table></form>", output.toString());
    assertEquals(eventCounts[0], eventCounts[1]);
    assertEquals(3, eventCounts[2]);
  }

  /** Retiring a stale form closes every emitted descendant at a small limit. */
  @Test
  void testDeferredFormRetirementKeepsRawEventsBalanced() {
    balancer.setNestingLimit(3);
    balancer.openDocument();
    balancer.openTag("form", j8().listOf());
    balancer.openTag("table", j8().listOf());
    balancer.openTag("form", j8().listOf());
    balancer.text("x");
    balancer.closeTag("form");
    balancer.openTag("tr", j8().listOf());
    balancer.openTag("td", j8().listOf());
    balancer.text("y");
    balancer.closeTag("td");
    balancer.closeTag("tr");
    balancer.closeTag("table");
    balancer.openTag("div", j8().listOf());
    balancer.openTag("form", j8().listOf());
    balancer.text("z");
    balancer.closeTag("form");
    balancer.closeTag("div");
    balancer.closeTag("form");
    balancer.closeDocument();

    assertEquals(
        "<form><table></table>x<table><tbody></tbody></table>y"
        + "<div></div></form><form>z</form>",
        htmlOutputBuffer.toString());
    assertEquals(emittedOpenElements, emittedCloseElements);
  }

  @Test
  void testNestingLimits() {
    // Some browsers can be DoSed by deeply nested structures.
    // See Issue 3, "Deeply nested elements crash FF 8, Chrome 11"
    // @ https://github.com/OWASP/java-html-sanitizer/issues/3

    balancer.setNestingLimit(10);
    balancer.openDocument();
    List<String> attrs = j8().listOf();
    for (int i = 20000; --i >= 0;) {
      balancer.openTag("div", attrs);
    }
    balancer.openTag("hr", attrs);
    balancer.closeDocument();
    assertEquals(
          "<div><div><div><div><div><div><div><div><div><div>"
        + "</div></div></div></div></div></div></div></div></div></div>",
        htmlOutputBuffer.toString());
    assertEquals(emittedOpenElements, emittedCloseElements);
  }

  /** An explicit end tag closes an element written at the nesting limit. */
  @Test
  void testExplicitCloseAtNestingLimit() {
    balancer.setNestingLimit(3);
    balancer.openDocument();
    balancer.openTag("div", j8().listOf());
    balancer.openTag("div", j8().listOf());
    balancer.openTag("span", j8().listOf());
    balancer.text("x");
    balancer.closeTag("span");
    balancer.openTag("p", j8().listOf());
    balancer.text("y");
    balancer.closeDocument();

    assertEquals(
        "<div><div><span>x</span><p>y</p></div></div>",
        htmlOutputBuffer.toString());
    assertEquals(emittedOpenElements, emittedCloseElements);
  }

  /** A sibling implicitly closes an incompatible element at the limit. */
  @Test
  void testImplicitCloseAtNestingLimit() {
    balancer.setNestingLimit(3);
    balancer.openDocument();
    balancer.openTag("div", j8().listOf());
    balancer.openTag("div", j8().listOf());
    balancer.openTag("textarea", j8().listOf());
    balancer.text("x");
    balancer.openTag("p", j8().listOf());
    balancer.text("y");
    balancer.closeDocument();

    assertEquals(
        "<div><div><textarea>x</textarea><p>y</p></div></div>",
        htmlOutputBuffer.toString());
    assertEquals(emittedOpenElements, emittedCloseElements);
  }

  /** Closing an ancestor also closes descendants written at the limit. */
  @Test
  void testAncestorCloseAtNestingLimit() {
    balancer.setNestingLimit(3);
    balancer.openDocument();
    balancer.openTag("div", j8().listOf());
    balancer.openTag("div", j8().listOf());
    balancer.openTag("span", j8().listOf());
    balancer.text("x");
    balancer.closeTag("div");
    balancer.closeDocument();

    assertEquals(
        "<div><div><span>x</span></div></div>",
        htmlOutputBuffer.toString());
    assertEquals(emittedOpenElements, emittedCloseElements);
  }

  /** Raising the limit must not close a resumed element that was not written. */
  @Test
  void testRaisedLimitDoesNotCloseUnemittedResumedElement() {
    balancer.setNestingLimit(3);
    balancer.openDocument();
    balancer.openTag("table", j8().listOf());
    balancer.openTag("caption", j8().listOf());
    balancer.openTag("strong", j8().listOf());
    balancer.closeTag("caption");
    balancer.text("x");
    balancer.openTag("strong", j8().listOf());
    balancer.openTag("caption", j8().listOf());
    balancer.closeTag("caption");
    balancer.openTag("strong", j8().listOf());
    balancer.openTag("span", j8().listOf());
    balancer.setNestingLimit(4);
    balancer.closeTag("table");
    balancer.closeDocument();

    assertEquals(
        "<table><caption><strong></strong></caption></table>"
            + "x<strong></strong><table><caption></caption></table>"
            + "<strong><strong></strong></strong>",
        htmlOutputBuffer.toString());
    assertEquals(emittedOpenElements, emittedCloseElements);
  }

  @Test
  void testTablesGuarded() {
    // Derived from issue 12.
    balancer.openDocument();
    balancer.openTag("html", j8().listOf());
    balancer.openTag("head", j8().listOf());
    balancer.openTag("meta", j8().listOf());
    balancer.closeTag("head");
    balancer.openTag("body", j8().listOf());
    balancer.openTag("p", j8().listOf());
    balancer.text("Hi");
    balancer.closeTag("p");
    balancer.openTag("p", j8().listOf());
    balancer.text("How are you");
    balancer.closeTag("p");
    balancer.text("\n");
    balancer.openTag("ul", j8().listOf());
    balancer.openTag("li", j8().listOf());
    balancer.openTag("table", j8().listOf());
    balancer.openTag("tbody", j8().listOf());
    balancer.openTag("tr", j8().listOf());
    for (int i = 2; --i >= 0;) {
      balancer.openTag("td", j8().listOf());
      balancer.openTag("b", j8().listOf());
      balancer.openTag("font", j8().listOf());
      balancer.openTag("font", j8().listOf());
      balancer.openTag("p", j8().listOf());
      balancer.text("Cell");
      balancer.closeTag("p");
      balancer.closeTag("font");
      balancer.closeTag("font");
      balancer.closeTag("li");
      balancer.text("\n");
      balancer.closeTag("td");
    }
    balancer.closeTag("tr");
    balancer.closeTag("tbody");
    balancer.closeTag("table");
    balancer.closeTag("ul");
    balancer.text("\n");
    balancer.openTag("p", j8().listOf());
    balancer.text("x");
    balancer.closeTag("p");
    balancer.closeTag("body");
    balancer.closeTag("html");
    balancer.closeDocument();

    assertEquals(
        "<html><head><meta /></head><body><p>Hi</p><p>How are you</p>\n"
        + "<ul><li><table><tbody><tr>"
        + "<td><b><font><font><p>Cell</p></font></font>\n"
        + "</b></td>"
        // The close </li> tag does not close the whole table.
        + "<td><b><b><font><font><p>Cell</p></font></font>\n"
        + "</b></b></td>"
        + "</tr></tbody></table></li></ul>\n"
        + "<b><b><p>x</p></b></b></body></html>",
        htmlOutputBuffer.toString());
  }

  @Test
  void testIsInterElementWhitespace() {
    assertFalse(isInterElementWhitespace("foo"));
    assertTrue(isInterElementWhitespace(""));
    assertTrue(isInterElementWhitespace(" "));
    assertTrue(isInterElementWhitespace("\t"));
    assertTrue(isInterElementWhitespace("\n"));
    assertTrue(isInterElementWhitespace(" \n"));
    assertTrue(isInterElementWhitespace("\r\n"));
    assertTrue(isInterElementWhitespace("\r"));
    assertTrue(isInterElementWhitespace(" "));
    assertTrue(isInterElementWhitespace(" \t "));
    assertFalse(isInterElementWhitespace(" foo "));
    assertFalse(isInterElementWhitespace("\u00A0"));
    assertFalse(isInterElementWhitespace("\u0000"));
  }

  @Test
  void testAnchorTransparentToBlock() {
    List<String> hrefOnly = j8().listOf("href", "");
    balancer.openDocument();
    balancer.openTag("div", j8().listOf());
    balancer.openTag("a", hrefOnly);
    balancer.openTag("div", j8().listOf());
    balancer.text("...");
    balancer.closeTag("div");
    balancer.closeTag("a");
    balancer.closeTag("div");
    balancer.closeDocument();

    assertEquals(
        "<div><a href=\"\"><div>...</div></a></div>",
        htmlOutputBuffer.toString());
  }


  @Test
  void testAnchorTransparentToSpans() {
    List<String> hrefOnly = j8().listOf("href", "");
    balancer.openDocument();
    balancer.openTag("span", j8().listOf());
    balancer.openTag("a", hrefOnly);
    balancer.openTag("span", j8().listOf());
    balancer.text("...");
    balancer.closeTag("span");
    balancer.closeTag("a");
    balancer.closeTag("span");
    balancer.closeDocument();

    assertEquals(
        "<span><a href=\"\"><span>...</span></a></span>",
        htmlOutputBuffer.toString());
  }


  @Test
  void testAnchorWithInlineInBlock() {
    List<String> hrefOnly = j8().listOf("href", "");
    balancer.openDocument();
    balancer.openTag("div", j8().listOf());
    balancer.openTag("a", hrefOnly);
    balancer.openTag("span", j8().listOf());
    balancer.text("...");
    balancer.closeTag("span");
    balancer.closeTag("a");
    balancer.closeTag("div");
    balancer.closeDocument();

    assertEquals(
        "<div><a href=\"\"><span>...</span></a></div>",
        htmlOutputBuffer.toString());
  }

  @Test
  void testDirectlyNestedAnchor() {
    List<String> hrefOnly = j8().listOf("href", "");
    balancer.openDocument();
    balancer.openTag("span", j8().listOf());
    balancer.openTag("a", hrefOnly);
    balancer.openTag("a", hrefOnly);
    balancer.text("...");
    balancer.closeTag("a");
    balancer.closeTag("a");
    balancer.closeTag("span");
    balancer.closeDocument();

    assertEquals(
        "<span><a href=\"\"></a><a href=\"\">...</a></span>",
        htmlOutputBuffer.toString());
  }


  @Test
  void testAnchorClosedWhenBlockInInline() {
    List<String> hrefOnly = j8().listOf("href", "");
    balancer.openDocument();
    balancer.openTag("span", j8().listOf());
    balancer.openTag("a", hrefOnly);
    balancer.openTag("div", j8().listOf());
    balancer.text("...");
    balancer.closeTag("div");
    balancer.closeTag("a");
    balancer.closeTag("span");
    balancer.closeDocument();

    assertEquals(
        // According to the spec, div is not nestable within span, but
        // browsers allow it.
        "<span><a href=\"\"><div>...</div></a></span>",
        htmlOutputBuffer.toString());
  }


  @Test
  void testAnchorInAnchorIndirectly() {
    List<String> hrefOnly = j8().listOf("href", "");
    balancer.openDocument();
    balancer.openTag("div", j8().listOf());
    balancer.openTag("a", hrefOnly);
    balancer.openTag("div", j8().listOf());
    balancer.openTag("a", hrefOnly);
    balancer.text("...");
    balancer.closeTag("a");
    balancer.closeTag("div");
    balancer.closeTag("a");
    balancer.closeTag("div");
    balancer.closeDocument();

    assertEquals(
        "<div><a href=\"\"><div></div></a><a href=\"\">...</a></div>",
        htmlOutputBuffer.toString());
  }

  @Test
  void testInteractiveInAnchorIndirectly() {
    List<String> hrefOnly = j8().listOf("href", "");
    balancer.openDocument();
    balancer.openTag("div", j8().listOf());
    balancer.openTag("a", hrefOnly);
    balancer.openTag("div", j8().listOf());
    balancer.openTag("video", j8().listOf());
    balancer.closeTag("video");
    balancer.closeTag("div");
    balancer.closeTag("a");
    balancer.closeTag("div");
    balancer.closeDocument();
    assertEquals(
        "<div><a href=\"\"><div><video></video></div></a></div>",
        htmlOutputBuffer.toString());
  }

  @Test
  void testAnchorWithBlockAtTopLevel() {
    List<String> hrefOnly = j8().listOf("href", "");
    balancer.openDocument();
    balancer.openTag("a", hrefOnly);
    balancer.openTag("div", j8().listOf());
    balancer.text("...");
    balancer.closeTag("div");
    balancer.closeTag("a");
    balancer.closeDocument();
    assertEquals(
        "<a href=\"\"><div>...</div></a>",
        htmlOutputBuffer.toString());
  }

  @Test
  void testResumedElementsAllowedWhereResumed() {
    balancer.openDocument();
    balancer.openTag("a", j8().listOf());
    balancer.openTag("b", j8().listOf());
    balancer.text("foo");
    balancer.openTag("i", j8().listOf());
    balancer.openTag("a", j8().listOf());
    balancer.text("bar");
    balancer.closeTag("a");
    balancer.closeTag("i");
    balancer.closeTag("b");
    balancer.closeTag("a");
    balancer.closeDocument();
    assertEquals(
        "<a><b>foo<i></i></b></a><b><i><a>bar</a></i></b>",
        htmlOutputBuffer.toString());
  }

  /**
   * {@code <template>} used to be tabled as unable to contain anything, so
   * its children were hoisted out to be its siblings (#113).
   */
  @Test
  void testTemplateKeepsItsChildren() {
    balancer.openDocument();
    balancer.openTag("template", j8().listOf("id", "t"));
    balancer.openTag("b", j8().listOf());
    balancer.openTag("a", j8().listOf("href", "https://example.com/"));
    balancer.text("link");
    balancer.closeTag("a");
    balancer.closeTag("b");
    balancer.closeTag("template");
    balancer.closeDocument();
    assertEquals(
        "<template id=\"t\"><b><a href=\"https://example.com/\">link</a></b>"
        + "</template>",
        htmlOutputBuffer.toString());
  }

  @Test
  void testTemplateHoldsTextAndNestedTemplates() {
    balancer.openDocument();
    balancer.openTag("template", j8().listOf());
    balancer.text("outer ");
    balancer.openTag("template", j8().listOf());
    balancer.text("inner");
    balancer.closeTag("template");
    balancer.closeTag("template");
    balancer.closeDocument();
    assertEquals(
        "<template>outer <template>inner</template></template>",
        htmlOutputBuffer.toString());
  }

  @Test
  void testUnclosedTemplateClosesAtEndOfDocument() {
    balancer.openDocument();
    balancer.openTag("template", j8().listOf());
    balancer.openTag("b", j8().listOf());
    balancer.text("x");
    balancer.closeDocument();
    assertEquals("<template><b>x</b></template>", htmlOutputBuffer.toString());
  }

  /**
   * A browser leaves table parts bare in {@code template.content}.  Here they
   * stay inside the template, but get the implied {@code <table><tbody>} they
   * get anywhere else: the balancer never emits a row or cell without a table
   * on the stack, since it cannot know what the output is embedded in.
   */
  @Test
  void testTablePartsInsideTemplateStayInsideIt() {
    balancer.openDocument();
    balancer.openTag("div", j8().listOf());
    balancer.openTag("template", j8().listOf());
    balancer.openTag("tr", j8().listOf());
    balancer.openTag("td", j8().listOf());
    balancer.text("x");
    balancer.closeTag("td");
    balancer.closeTag("tr");
    balancer.closeTag("template");
    balancer.closeTag("div");
    balancer.closeDocument();
    assertEquals(
        "<div><template><table><tbody><tr><td>x</td></tr></tbody></table>"
        + "</template></div>",
        htmlOutputBuffer.toString());
  }

  @Test
  void testMenuItemNesting() {
    // issue 96
    balancer.openDocument();
    balancer.openTag("div", j8().listOf());
    balancer.openTag("menu", j8().listOf());
    balancer.openTag("menuitem", j8().listOf());
    balancer.closeTag("menuitem");
    balancer.openTag("menuitem", j8().listOf());
    balancer.closeTag("menuitem");
    balancer.closeTag("menu");
    balancer.closeTag("div");
    assertEquals(
        "<div><menu><menuitem></menuitem><menuitem></menuitem></menu></div>",
        htmlOutputBuffer.toString());
  }

  /**
   * A browser clears its list of active formatting elements to a marker on
   * entering a table cell, so an {@code a} opened inside the cell does not
   * end an {@code a} open outside the table (#333).  The balancer used to
   * close back to any open {@code a}, taking the cell, row and table with
   * it.
   */
  @Test
  void testLinkInsideCellInsideLinkStaysNested() {
    balancer.openDocument();
    balancer.openTag("a", j8().listOf("href", "u"));
    balancer.openTag("table", j8().listOf());
    balancer.openTag("tr", j8().listOf());
    balancer.openTag("td", j8().listOf());
    balancer.openTag("a", j8().listOf("href", "v"));
    balancer.text("1");
    balancer.closeTag("a");
    balancer.closeTag("td");
    balancer.closeTag("tr");
    balancer.closeTag("table");
    balancer.closeTag("a");
    balancer.closeDocument();

    assertEquals(
        "<a href=\"u\"><table><tbody><tr><td><a href=\"v\">1</a></td></tr>"
        + "</tbody></table></a>",
        htmlOutputBuffer.toString());
  }

  /** The other elements a browser puts a marker on entering do the same. */
  @Test
  void testLinkInsideFormattingMarkerInsideLinkStaysNested() {
    for (String marker
         : new String[] { "applet", "marquee", "object", "template" }) {
      createBalancer();
      balancer.openDocument();
      balancer.openTag("a", j8().listOf("href", "u"));
      balancer.openTag(marker, j8().listOf());
      balancer.openTag("a", j8().listOf("href", "v"));
      balancer.text("x");
      balancer.closeTag("a");
      balancer.closeTag(marker);
      balancer.closeTag("a");
      balancer.closeDocument();

      assertEquals(
          "<a href=\"u\"><" + marker + "><a href=\"v\">x</a></" + marker
          + "></a>",
          htmlOutputBuffer.toString(), marker);
    }
  }

  /** With no marker between them, a second {@code a} still ends the first. */
  @Test
  void testLinkInsideLinkStillEndsIt() {
    balancer.openDocument();
    balancer.openTag("a", j8().listOf("href", "u"));
    balancer.text("x");
    balancer.openTag("a", j8().listOf("href", "v"));
    balancer.text("y");
    balancer.closeTag("a");
    balancer.text("z");
    balancer.closeTag("a");
    balancer.closeDocument();

    assertEquals(
        "<a href=\"u\">x</a><a href=\"v\">y</a>z",
        htmlOutputBuffer.toString());
  }

  /** Table-context returns emit a properly nested stream of receiver events. */
  @Test
  void testTableContextChangesHaveBalancedReceiverEvents() {
    assertEquals(
        "<table><tbody><tr><td><div>x</div></td></tr>"
        + "<tr><td>y</td></tr></tbody></table>z",
        renderBalancedEvents(20, "table", "tr", "td", "div", "#x",
            "tr", "td", "#y", "/table", "#z"));
    assertEquals(
        "<div><p>x</p><table><tbody><tr><td>y</td></tr></tbody></table></div>",
        renderBalancedEvents(20, "div", "p", "#x", "tr", "td", "#y"));
    assertEquals(
        "<table><colgroup><col /></colgroup><tbody><tr><td>y</td></tr>"
        + "</tbody></table>",
        renderBalancedEvents(20, "table", "col", "tr", "td", "#y"));
    assertEquals(
        "<template><table><tbody><tr><td><b>y</b></td></tr></tbody></table>"
        + "</template>z",
        renderBalancedEvents(20, "template", "tr", "td", "b", "#y",
            "/template", "#z"));
  }

  /** The return walk closes every emitted element, including at the limit. */
  @Test
  void testTableContextReturnsRespectSmallNestingLimits() {
    String[] expected = {
        "xy",
        "<table></table>x<table></table>y",
        "<table><tbody></tbody></table>x<table><tbody></tbody></table>y",
        "<table><tbody><tr></tr></tbody></table>x"
        + "<table><tbody><tr></tr></tbody></table>y",
        "<table><tbody><tr><td>x</td></tr><tr><td>y</td></tr></tbody></table>",
        "<table><tbody><tr><td><div>x</div></td></tr>"
        + "<tr><td>y</td></tr></tbody></table>",
    };
    for (int limit = 0; limit < expected.length; ++limit) {
      assertEquals(expected[limit], renderBalancedEvents(limit,
          "table", "tr", "td", "div", "#x", "tr", "td", "#y"),
          "limit " + limit);
    }
  }

  /** A suppressed option run at the limit uses bounded policy state. */
  @Test
  void testMappedForeignSelectOptionsAtNestingLimitAreBoundedAndReported() {
    final int optionCount = 10_000;
    for (int limit : new int[] { 2, 5 }) {
      final int[] optionPolicyCalls = new int[1];
      final int[] discarded = new int[2];
      PolicyFactory factory = new HtmlPolicyBuilder()
          .allowElements(
              "svg", "table", "tbody", "tr", "td", "option", "span")
          .allowElements((name, attrs) -> "select", "table")
          .allowElements((name, attrs) -> {
            ++optionPolicyCalls[0];
            return "option";
          }, "option")
          .allowTextIn(
              "svg", "table", "tbody", "tr", "td", "option", "span")
          .allowWithoutAttributes(
              "svg", "table", "tbody", "tr", "td", "option", "span")
          .toFactory();

      StringBuilder output = new StringBuilder();
      List<String> open = new ArrayList<>();
      int[] eventCounts = new int[3];
      HtmlStreamEventReceiver checked = strictRenderer(
          output, open, eventCounts);
      HtmlChangeListener<Object> listener = new HtmlChangeListener<Object>() {
        public void discardedTag(Object context, String elementName) {
          if ("option".equals(elementName)) {
            ++discarded[0];
          } else {
            ++discarded[1];
          }
        }

        public void discardedAttributes(
            Object context, String tagName, String... attributeNames) {
          fail("Unexpected discarded attributes on " + tagName);
        }
      };
      TagBalancingHtmlStreamEventReceiver limited =
          new TagBalancingHtmlStreamEventReceiver(
              factory.apply(checked, listener, null));
      limited.setNestingLimit(limit);
      limited.openDocument();
      limited.openTag("svg", j8().listOf());
      limited.openTag("table", j8().listOf());
      limited.openTag("tr", j8().listOf());
      limited.openTag("td", j8().listOf());
      for (int i = 0; i < optionCount; ++i) {
        limited.openTag("option", j8().listOf());
      }

      // Re-applying the limit proves the untracked run did not grow the
      // balancer's effective stack depth.
      limited.setNestingLimit(limit);
      for (int i = 0; i < optionCount; ++i) {
        limited.closeTag("option");
      }
      limited.closeTag("td");
      limited.closeTag("tr");
      limited.closeTag("table");
      limited.closeTag("svg");
      limited.closeDocument();

      assertEquals(
          "<svg><select></select></svg>",
          output.toString(), "limit " + limit);
      assertEquals(limit == 2 ? 0 : 1, optionPolicyCalls[0], "limit " + limit);
      assertEquals(optionCount, discarded[0], "limit " + limit);
      assertEquals(2, discarded[1], "limit " + limit);
      assertEquals(eventCounts[0], eventCounts[1], "limit " + limit);
      assertTrue(eventCounts[2] <= limit, "limit " + limit);
    }
  }

  /** Suppressed unrecognized starts still count toward the nesting limit. */
  @Test
  void testMappedForeignSelectUnknownChildrenAreBoundedAndReported() {
    final int childCount = 10_000;
    for (int limit : new int[] { 2, 3 }) {
      final int[] policyCalls = new int[1];
      final int[] discarded = new int[1];
      PolicyFactory factory = new HtmlPolicyBuilder()
          .allowElements("svg")
          .allowElements((name, attrs) -> "select", "table")
          .allowElements((name, attrs) -> {
            ++policyCalls[0];
            return "foo";
          }, "foo")
          .allowTextIn("svg", "table", "foo")
          .allowWithoutAttributes("svg", "table", "foo")
          .toFactory();
      HtmlChangeListener<Object> listener = new HtmlChangeListener<Object>() {
        public void discardedTag(Object context, String elementName) {
          assertEquals("foo", elementName);
          ++discarded[0];
        }

        public void discardedAttributes(
            Object context, String tagName, String... attributeNames) {
          fail("Unexpected discarded attributes on " + tagName);
        }
      };
      StringBuilder output = new StringBuilder();
      List<String> open = new ArrayList<>();
      int[] eventCounts = new int[3];
      TagBalancingHtmlStreamEventReceiver limited =
          new TagBalancingHtmlStreamEventReceiver(
              factory.apply(
                  strictRenderer(output, open, eventCounts), listener, null));
      limited.setNestingLimit(limit);
      limited.openDocument();
      limited.openTag("svg", j8().listOf());
      limited.openTag("table", j8().listOf());
      for (int i = 0; i < childCount; ++i) {
        limited.openTag("foo", j8().listOf());
      }
      limited.setNestingLimit(limit);
      limited.closeDocument();

      assertEquals("<svg><select></select></svg>", output.toString());
      assertEquals(limit == 2 ? 0 : 1, policyCalls[0], "limit " + limit);
      assertEquals(childCount, discarded[0], "limit " + limit);
      assertEquals(eventCounts[0], eventCounts[1], "limit " + limit);
      assertTrue(eventCounts[2] <= limit, "limit " + limit);
    }
  }

  /** A cap-dropped nested table end cannot close the suppression owner. */
  @Test
  void testMappedForeignSelectShadowsNestedTablesAtTheLimit() {
    assertEquals(
        "<svg><select></select></svg>",
        renderMappedSelectPolicyEvents(
            "@2", "svg", "table", "table", "/table",
            "b", "#must-drop", "/b", "/table", "/svg"));
    assertEquals(
        "<svg><select></select></svg>",
        renderMappedSelectPolicyEvents(
            "@3", "svg", "table", "b", "table", "/table",
            "i", "#must-drop", "/i", "/b", "/table", "/svg"));
    assertEquals(
        "<template><svg><select></select></svg></template>",
        renderMappedSelectPolicyEvents(
            "@3", "template", "svg", "table", "b", "#must-drop", "/b",
            "/table", "/svg", "/template"));
  }

  /** Closing a suppressed option discards policy-only descendants. */
  @Test
  void testSuppressedOptionAllowsNestingLimitToBeLoweredAfterClose() {
    PolicyFactory factory = new HtmlPolicyBuilder()
        .allowElements(
            "svg", "table", "tbody", "tr", "td", "option", "span")
        .allowElements((name, attrs) -> "select", "table")
        .allowTextIn(
            "svg", "table", "tbody", "tr", "td", "option", "span")
        .allowWithoutAttributes(
            "svg", "table", "tbody", "tr", "td", "option", "span")
        .toFactory();
    StringBuilder output = new StringBuilder();
    List<String> open = new ArrayList<>();
    int[] eventCounts = new int[3];
    TagBalancingHtmlStreamEventReceiver limited =
        new TagBalancingHtmlStreamEventReceiver(
            factory.apply(strictRenderer(output, open, eventCounts)));

    limited.setNestingLimit(5);
    limited.openDocument();
    limited.openTag("svg", j8().listOf());
    limited.openTag("table", j8().listOf());
    limited.openTag("tr", j8().listOf());
    limited.openTag("td", j8().listOf());
    limited.openTag("option", j8().listOf());
    limited.setNestingLimit(100);
    for (int i = 0; i < 90; ++i) {
      limited.openTag("span", j8().listOf());
    }
    limited.closeTag("option");

    // This throws if the descendants removed with the suppressed option
    // remain on either stack.
    limited.setNestingLimit(5);
    limited.closeDocument();

    assertEquals(
        "<svg><select></select></svg>",
        output.toString());
    assertEquals(eventCounts[0], eventCounts[1]);
    assertEquals(2, eventCounts[2]);
  }

  /** Formatting queued inside a suppressed option cannot resume after it. */
  @Test
  void testSuppressedOptionDiscardsItsFormattingResumeEntries() {
    assertEquals(
        "<svg><select></select></svg>",
        renderMappedSelectPolicyEvents(
            "@5", "svg", "table", "tr", "td", "option", "@30",
            "form", "a", "/form", "/option", "div", "#after", "/div"));

    // The policy may end the suppressed option implicitly.  The next start
    // observes that and must discard the same queued formatting suffix.
    assertEquals(
        "<svg><select></select></svg>",
        renderMappedSelectPolicyEvents(
            "@5", "svg", "table", "tr", "td", "option", "@30",
            "i", "em", "/tbody", "div", "#after", "/div"));

    // A formatting entry queued before the virtual option still resumes.
    assertEquals(
        "<svg><select></select></svg>",
        renderMappedSelectPolicyEvents(
            "@5", "svg", "table", "tr", "td", "@30", "form", "a",
            "/form", "@5", "option", "/option", "@30", "div", "#after",
            "/div"));

    // If an ancestor end makes the policy end suppression first, the next
    // event also retires every logical descendant of the virtual option.
    assertEquals(
        "<svg><select></select></svg>",
        renderMappedSelectPolicyEvents(
            "@5", "svg", "table", "tr", "td", "option", "@30", "a",
            "em", "/svg", "@5"));

    // A template bounds the table-to-select lookup, so the inner option is
    // tracked normally and its end must not consume the outer option counter.
    assertEquals(
        "<svg><select></select></svg>",
        renderMappedSelectPolicyEvents(
            "@2", "svg", "table", "option", "@10", "template", "option",
            "/option", "/template", "/option", "div", "#after", "/div"));
  }

  private static String renderMappedSelectPolicyEvents(String... events) {
    PolicyFactory factory = new HtmlPolicyBuilder()
        .allowElements(
            "svg", "table", "tbody", "tr", "td", "option", "form", "a",
            "div", "i", "em", "template")
        .allowElements((name, attrs) -> "select", "table")
        .allowTextIn(
            "svg", "table", "tbody", "tr", "td", "option", "form", "a",
            "div", "i", "em", "template")
        .allowWithoutAttributes(
            "svg", "table", "tbody", "tr", "td", "option", "form", "a",
            "div", "i", "em", "template")
        .toFactory();
    StringBuilder output = new StringBuilder();
    List<String> open = new ArrayList<>();
    int[] eventCounts = new int[3];
    TagBalancingHtmlStreamEventReceiver receiver =
        new TagBalancingHtmlStreamEventReceiver(
            factory.apply(strictRenderer(output, open, eventCounts)));
    receiver.openDocument();
    for (String event : events) {
      if (event.startsWith("@")) {
        receiver.setNestingLimit(Integer.parseInt(event.substring(1)));
      } else if (event.startsWith("#")) {
        receiver.text(event.substring(1));
      } else if (event.startsWith("/")) {
        receiver.closeTag(event.substring(1));
      } else {
        receiver.openTag(event, j8().listOf());
      }
    }
    receiver.closeDocument();
    assertEquals(eventCounts[0], eventCounts[1]);
    return output.toString();
  }

  private static HtmlStreamEventReceiver strictRenderer(
      StringBuilder output, final List<String> open, final int[] counts) {
    return new HtmlStreamEventReceiverWrapper(
        HtmlStreamRenderer.create(output, x -> fail(x))) {
      @Override
      public void openTag(String name, List<String> attrs) {
        String canonName = HtmlLexer.canonicalElementName(name);
        if (!HtmlTextEscapingMode.isVoidElement(canonName)) {
          open.add(canonName);
          ++counts[0];
          counts[2] = Math.max(counts[2], open.size());
        }
        super.openTag(name, attrs);
      }

      @Override
      public void closeTag(String name) {
        String canonName = HtmlLexer.canonicalElementName(name);
        assertFalse(open.isEmpty(), "unmatched close " + canonName);
        assertEquals(open.remove(open.size() - 1), canonName, "close order");
        ++counts[1];
        super.closeTag(name);
      }

      @Override
      public void closeDocument() {
        assertTrue(open.isEmpty(), "unclosed elements " + open);
        super.closeDocument();
      }
    };
  }

  /** A foreign end tag closes the entries it pops before it is forwarded. */
  @Test
  void testForeignEndTagClosesPoppedEntriesForPlainReceiver() {
    assertEquals(
        "<svg><noscript></noscript></svg>x",
        renderBalancedEvents(256, "svg", "noscript", "/svg", "#x"));
    assertEquals(
        "<svg><noscript><noscript></noscript></noscript></svg>",
        renderBalancedEvents(256, "svg", "noscript", "noscript", "/svg"));
    // The inner end tag closes only the inner element.
    assertEquals(
        "<svg><noscript><noscript></noscript><path></path></noscript></svg>",
        renderBalancedEvents(
            256, "svg", "noscript", "noscript", "/noscript", "path",
            "/path", "/svg"));
  }

  /**
   * Elements outside the containment metadata are forwarded as written, so
   * their end tags are balanced against what was forwarded: everything opened
   * inside one closes first, a stray end tag closes nothing, and whatever is
   * still open ends with the document.
   */
  @Test
  void testUnrecognizedElementsAreBalancedForPlainReceiver() {
    assertEquals(
        "<foo><b>x</b></foo><b>y</b>",
        renderBalancedEvents(256, "foo", "b", "#x", "/foo", "#y"));
    assertEquals(
        "<b>x</b>",
        renderBalancedEvents(256, "/foo", "b", "#x"));
    assertEquals(
        "<foo><bar>x</bar></foo>",
        renderBalancedEvents(256, "foo", "bar", "#x"));
    assertEquals(
        "<foo><foo><foo>x</foo></foo></foo>",
        renderBalancedEvents(
            256, "foo", "foo", "foo", "#x", "/foo", "/foo", "/foo"));
    // A table part clears a browser's stack back to the table context.  The
    // balancer does not foster-parent the unrecognized element out of the
    // table, so it is written inside the table rather than in front of it.
    assertEquals(
        "<table><foo></foo><tbody><tr><td>x</td></tr></tbody></table>",
        renderBalancedEvents(256, "table", "foo", "tr", "td", "#x"));
    // Formatting closed with an integration point is not resumed while
    // content is inserted under SVG rules.
    assertEquals(
        "<svg><desc><b>x</b></desc>y</svg><b>w</b>",
        renderBalancedEvents(
            256, "svg", "desc", "b", "#x", "/desc", "#y", "/svg", "#w"));
    // A void breakout element adds no empty formatting element in front of
    // it; the text after it, now in HTML content, resumes the formatting.
    assertEquals(
        "<svg><desc><b>x</b></desc><hr /><b>y</b></svg>",
        renderBalancedEvents(
            256, "svg", "desc", "b", "#x", "/desc", "hr", "#y", "/svg"));
  }

  /**
   * With no policy to report what it emitted, every element forwarded without
   * a stack entry reaches the receiver below and nests there, so it counts
   * toward the nesting limit like any other open element.  Otherwise the
   * limit is not a bound at all for unrecognized names.  Behind a policy the
   * policy's own output depth covers the ones it emitted, and the ones it
   * dropped nest nothing.
   */
  @Test
  void testForwardedElementsCountTowardTheNestingLimit() {
    assertEquals(
        "<foo><foo>xy</foo></foo>",
        renderBalancedEvents(2, "foo", "foo", "foo", "#x", "b", "#y"));
    assertEquals(
        "<svg>x</svg>",
        renderBalancedEvents(1, "svg", "path", "#x", "/path", "/svg"));
    // Closing a forwarded element frees its depth again.
    assertEquals(
        "<foo></foo><bar></bar>",
        renderBalancedEvents(1, "foo", "bar", "/foo", "bar"));
  }

  /** A root dropped at the limit owns nothing below for its end tag to close. */
  @Test
  void testDroppedForeignRootEndTagIsNotForwardedAfterLimitIncreases() {
    StringBuilder output = new StringBuilder();
    List<String> open = new ArrayList<>();
    int[] eventCounts = new int[3];
    TagBalancingHtmlStreamEventReceiver limited =
        new TagBalancingHtmlStreamEventReceiver(
            strictRenderer(output, open, eventCounts));
    limited.setNestingLimit(0);
    limited.openDocument();
    limited.openTag("svg", j8().listOf());
    limited.setNestingLimit(2);
    limited.openTag("noscript", j8().listOf());
    limited.closeTag("svg");
    limited.openTag("path", j8().listOf());
    limited.closeTag("path");
    limited.closeDocument();

    assertEquals("<noscript></noscript><path></path>", output.toString());
    assertEquals(eventCounts[0], eventCounts[1]);

    PolicyFactory factory = new HtmlPolicyBuilder()
        .allowElements("svg", "path", "select")
        .allowElements((name, attrs) -> "select", "noscript")
        .allowWithoutAttributes("svg", "path", "select", "noscript")
        .toFactory();
    assertEquals(
        "<select></select><path></path>",
        renderPolicyEvents(
            factory, "@0", "svg", "@2", "noscript", "/svg", "path", "/path"));
  }

  /** A node dropped at the limit cannot alias an older node with its name. */
  @Test
  void testDroppedForeignElementDoesNotAliasOlderElementAtNestingLimit() {
    PolicyFactory renamed = new HtmlPolicyBuilder()
        .allowElements("svg", "g", "path", "select")
        .allowElements((name, attrs) -> "select", "noscript")
        .allowWithoutAttributes("svg", "g", "path", "select", "noscript")
        .toFactory();
    assertEquals(
        "<svg><select><g></g></select><path></path></svg>",
        renderPolicyEvents(
            renamed, "@3", "svg", "noscript", "g", "noscript", "/g",
            "/noscript", "path", "/path", "/svg"));

    // Without a rename, the limit drops the inner noscript.  Its end tag
    // must leave the outer one open for the path once the limit allows it.
    PolicyFactory keep = new HtmlPolicyBuilder()
        .allowElements("svg", "noscript", "path")
        .allowWithoutAttributes("svg", "noscript", "path")
        .toFactory();
    assertEquals(
        "<svg><noscript><path></path></noscript></svg>",
        renderPolicyEvents(
            keep, "@2", "svg", "noscript", "noscript", "/noscript", "@3",
            "path", "/path", "/svg"));
    assertEquals(
        "<svg><noscript><noscript></noscript><path></path></noscript></svg>",
        renderPolicyEvents(
            keep, "@3", "svg", "noscript", "noscript", "/noscript", "path",
            "/path", "/svg"));
  }

  /**
   * The limit cannot be set below what is open.  With no policy below to
   * count its own output, the elements outside the containment metadata
   * that were forwarded count too, since each nests the output.
   */
  @Test
  void testNestingLimitCannotBeSetBelowTheOpenDepth() {
    balancer.openDocument();
    balancer.openTag("foo", j8().listOf());
    balancer.openTag("div", j8().listOf());
    IllegalStateException ex = assertThrows(
        IllegalStateException.class, () -> balancer.setNestingLimit(1));
    assertEquals(
        "Cannot set the nesting limit to 1: elements are already open 2 deep",
        ex.getMessage());
    balancer.setNestingLimit(2);
    balancer.openTag("p", j8().listOf());
    balancer.text("x");
    balancer.closeDocument();

    assertEquals("<foo><div>x</div></foo>", htmlOutputBuffer.toString());
    assertEquals(emittedOpenElements, emittedCloseElements);
  }

  /**
   * A pre-processor can hand the balancer a name in a case the lexer would
   * not.  Every start tag is forwarded under its canonical name, so a tag
   * the policy drops is reported to the listener under that name.  The tags
   * the balancer drops itself, a form ignored while the form element pointer
   * is set and a tag past the nesting limit, are reported the same way,
   * whether or not the element is in the containment metadata.
   */
  @Test
  void testDroppedTagsAreReportedUnderTheCanonicalName() {
    final List<String> discarded = new ArrayList<>();
    HtmlChangeListener<Object> listener = new HtmlChangeListener<Object>() {
      public void discardedTag(Object context, String elementName) {
        discarded.add(elementName);
      }

      public void discardedAttributes(
          Object context, String tagName, String... attributeNames) {
        fail("Unexpected discarded attributes on " + tagName);
      }
    };
    PolicyFactory factory = new HtmlPolicyBuilder()
        .allowElements("form", "div", "foo")
        .withPreprocessor(r -> new HtmlStreamEventReceiverWrapper(r) {
          @Override
          public void openTag(String elementName, List<String> attrs) {
            underlying.openTag(elementName.toUpperCase(Locale.ROOT), attrs);
          }

          @Override
          public void closeTag(String elementName) {
            underlying.closeTag(elementName.toUpperCase(Locale.ROOT));
          }
        })
        .toFactory();

    // The second form start is ignored under the form element pointer rule
    // before it reaches the policy; the b is dropped by the policy.
    assertEquals(
        "<form></form>",
        factory.sanitize(
            "<form><form></form></form><b></b>", listener, null));
    assertEquals(j8().listOf("form", "b"), discarded);

    // One start past the limit HtmlSanitizer sets, for an element in the
    // containment metadata and for one outside it.
    final int limit = 256;
    for (String name : new String[] { "div", "foo" }) {
      discarded.clear();
      StringBuilder input = new StringBuilder();
      StringBuilder expected = new StringBuilder();
      for (int i = 0; i <= limit; ++i) {
        input.append('<').append(name).append('>');
        if (i < limit) { expected.append('<').append(name).append('>'); }
      }
      input.append('x');
      expected.append('x');
      for (int i = 0; i <= limit; ++i) {
        input.append("</").append(name).append('>');
        if (i < limit) { expected.append("</").append(name).append('>'); }
      }
      assertEquals(
          expected.toString(),
          factory.sanitize(input.toString(), listener, null), name);
      assertEquals(j8().listOf(name), discarded, name);
    }
  }

  /**
   * A balancer can be reused for another document.  The first leaves a
   * dropped element whose text is suppressed, the form element pointer set,
   * and a foreign root open; the next document starts with none of that.
   * {@link #testOpenDocumentResetsWhatAThrowingReceiverLeftOpen} covers the
   * same reset when the first document ends in a throw instead.
   */
  @Test
  void testBalancerStartsEachDocumentClean() {
    balancer.setNestingLimit(2);
    balancer.openDocument();
    balancer.openTag("form", j8().listOf());
    balancer.openTag("svg", j8().listOf());
    balancer.openTag("script", j8().listOf());
    balancer.text("alert(1)");
    balancer.closeDocument();
    assertEquals("<form><svg></svg></form>", htmlOutputBuffer.toString());
    assertEquals(emittedOpenElements, emittedCloseElements);

    htmlOutputBuffer.setLength(0);
    balancer.openDocument();
    balancer.text("x");
    balancer.openTag("form", j8().listOf());
    balancer.openTag("p", j8().listOf());
    balancer.text("y");
    balancer.closeDocument();
    assertEquals("x<form><p>y</p></form>", htmlOutputBuffer.toString());
    assertEquals(emittedOpenElements, emittedCloseElements);
  }

  /**
   * Item 4 of #492.  A receiver that throws leaves the document without its
   * closeDocument.  openDocument used to start the next document with the
   * previous document's open elements, so that document's output began with
   * the previous document's close tags.  Both lifecycle calls now reset the
   * document state: here the first document leaves an HTML form with the
   * pointer set, a forwarded custom element, table structure, and a
   * formatting element queued to resume; the next document starts with
   * none of it.  {@link #testBalancerStartsEachDocumentClean} is the same
   * reset through closeDocument.  The receiver records events itself, since
   * the renderer refuses a second document while one is open.
   */
  @Test
  void testOpenDocumentResetsWhatAThrowingReceiverLeftOpen() {
    final StringBuilder events = new StringBuilder();
    final TagBalancingHtmlStreamEventReceiver b =
        new TagBalancingHtmlStreamEventReceiver(new HtmlStreamEventReceiver() {
          public void openDocument() {
            events.append("[open]");
          }

          public void closeDocument() {
            events.append("[close]");
          }

          public void openTag(String elementName, List<String> attrs) {
            events.append('<').append(elementName).append('>');
          }

          public void closeTag(String elementName) {
            if ("tr".equals(elementName)) {
              throw new IllegalStateException("receiver failed");
            }
            events.append("</").append(elementName).append('>');
          }

          public void text(String text) {
            events.append(text);
          }
        });
    b.openDocument();
    b.openTag("form", j8().listOf());
    b.openTag("foo", j8().listOf());
    b.openTag("table", j8().listOf());
    b.openTag("tr", j8().listOf());
    b.openTag("td", j8().listOf());
    b.openTag("b", j8().listOf());
    b.text("x");
    // Closing the cell pops the b, which is queued to resume; the row's
    // close is where the receiver fails.
    b.closeTag("td");
    IllegalStateException ex = assertThrows(
        IllegalStateException.class, () -> b.closeTag("tr"));
    assertEquals("receiver failed", ex.getMessage());
    assertEquals(
        "[open]<form><foo><table><tbody><tr><td><b>x</b></td>",
        events.toString());
    events.setLength(0);

    // The next document starts clean: the text is not wrapped in the queued
    // b, the form is not ignored for a pointer the last document set, no
    // close tag comes for the custom element or the table, and the nesting
    // limit, set once the new document is open, applies from depth zero.
    b.openDocument();
    b.setNestingLimit(3);
    b.text("y");
    b.openTag("form", j8().listOf());
    b.openTag("p", j8().listOf());
    b.openTag("span", j8().listOf());
    b.openTag("span", j8().listOf());
    b.text("z");
    b.closeDocument();
    assertEquals(
        "[open]y<form><p><span>z</span></p></form>[close]",
        events.toString());
  }

  /**
   * An option suppressed at the limit inside a table mapped to a foreign
   * select owns a policy entry.  That entry is opened under the canonical
   * name, like every other start tag, so the end tag the balancer sends under
   * that name closes it, and the listener hears the same name a
   * pre-processor's recasing cannot change.
   */
  @Test
  void testSuppressedOptionAtLimitIsForwardedUnderTheCanonicalName() {
    final List<String> discarded = new ArrayList<>();
    HtmlChangeListener<Object> listener = new HtmlChangeListener<Object>() {
      public void discardedTag(Object context, String elementName) {
        discarded.add(elementName);
      }

      public void discardedAttributes(
          Object context, String tagName, String... attributeNames) {
        fail("Unexpected discarded attributes on " + tagName);
      }
    };
    PolicyFactory factory = new HtmlPolicyBuilder()
        .allowElements("svg", "table", "option")
        .allowElements((name, attrs) -> "select", "table")
        .allowTextIn("svg", "table", "option")
        .allowWithoutAttributes("svg", "table", "option")
        .toFactory();
    StringBuilder output = new StringBuilder();
    List<String> open = new ArrayList<>();
    int[] eventCounts = new int[3];
    TagBalancingHtmlStreamEventReceiver limited =
        new TagBalancingHtmlStreamEventReceiver(
            factory.apply(
                strictRenderer(output, open, eventCounts), listener, null));
    limited.setNestingLimit(2);
    limited.openDocument();
    limited.openTag("svg", j8().listOf());
    limited.openTag("table", j8().listOf());
    limited.openTag("OPTION", j8().listOf());
    limited.text("dropped");
    limited.closeTag("OPTION");
    limited.closeTag("table");
    limited.closeTag("svg");
    limited.closeDocument();

    assertEquals("<svg><select></select></svg>", output.toString());
    assertEquals(j8().listOf("option"), discarded);
    assertEquals(eventCounts[0], eventCounts[1]);
  }

  /**
   * Runs events through a balancer over the policy, both directly and through
   * the change reporter, checking that the emitted events stay balanced.
   */
  private static String renderPolicyEvents(
      PolicyFactory factory, String... events) {
    String direct = null;
    for (boolean reported : new boolean[] { false, true }) {
      StringBuilder output = new StringBuilder();
      List<String> open = new ArrayList<>();
      int[] eventCounts = new int[3];
      HtmlStreamEventReceiver checked = strictRenderer(
          output, open, eventCounts);
      HtmlChangeListener<Object> ignore = new HtmlChangeListener<Object>() {
        public void discardedTag(Object context, String elementName) {
          // Output through the reporter decorator is under test.
        }

        public void discardedAttributes(
            Object context, String tagName, String... attributeNames) {
          // Output through the reporter decorator is under test.
        }
      };
      TagBalancingHtmlStreamEventReceiver receiver =
          new TagBalancingHtmlStreamEventReceiver(
              reported
              ? factory.apply(checked, ignore, null)
              : factory.apply(checked));
      receiver.openDocument();
      for (String event : events) {
        if (event.startsWith("@")) {
          receiver.setNestingLimit(Integer.parseInt(event.substring(1)));
        } else if (event.startsWith("#")) {
          receiver.text(event.substring(1));
        } else if (event.startsWith("/")) {
          receiver.closeTag(event.substring(1));
        } else {
          receiver.openTag(event, j8().listOf());
        }
      }
      receiver.closeDocument();
      assertEquals(eventCounts[0], eventCounts[1]);
      if (reported) {
        assertEquals(direct, output.toString(), "reporter parity");
      } else {
        direct = output.toString();
      }
    }
    return direct;
  }

  /** Checks events themselves, since the renderer can hide missing closes. */
  private static String renderBalancedEvents(int limit, String... events) {
    StringBuilder output = new StringBuilder();
    List<String> open = new ArrayList<>();
    HtmlStreamEventReceiver checked = new HtmlStreamEventReceiverWrapper(
        HtmlStreamRenderer.create(output, x -> fail(x))) {
      @Override
      public void openTag(String name, List<String> attrs) {
        if (!HtmlTextEscapingMode.isVoidElement(name)) { open.add(name); }
        assertTrue(open.size() <= limit, "nesting limit");
        super.openTag(name, attrs);
      }

      @Override
      public void closeTag(String name) {
        assertFalse(open.isEmpty(), "unmatched close " + name);
        assertEquals(open.remove(open.size() - 1), name, "close order");
        super.closeTag(name);
      }

      @Override
      public void closeDocument() {
        assertTrue(open.isEmpty(), "unclosed elements " + open);
        super.closeDocument();
      }
    };
    TagBalancingHtmlStreamEventReceiver receiver =
        new TagBalancingHtmlStreamEventReceiver(checked);
    receiver.setNestingLimit(limit);
    receiver.openDocument();
    for (String event : events) {
      if (event.startsWith("#")) {
        receiver.text(event.substring(1));
      } else if (event.startsWith("/")) {
        receiver.closeTag(event.substring(1));
      } else {
        receiver.openTag(event, j8().listOf());
      }
    }
    receiver.closeDocument();
    return output.toString();
  }
}
