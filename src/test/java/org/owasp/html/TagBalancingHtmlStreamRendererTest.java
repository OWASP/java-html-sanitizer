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

import com.google.common.collect.ImmutableList;

import junit.framework.TestCase;

import org.junit.Test;
import org.junit.Before;
import org.junit.Ignore;

import static org.owasp.html.TagBalancingHtmlStreamEventReceiver
              .isInterElementWhitespace;


@SuppressWarnings("javadoc")
public class TagBalancingHtmlStreamRendererTest extends TestCase {

  StringBuilder htmlOutputBuffer;
  TagBalancingHtmlStreamEventReceiver balancer;

  @Before @Override protected void setUp() throws Exception {
    super.setUp();
    htmlOutputBuffer = new StringBuilder();
    balancer = new TagBalancingHtmlStreamEventReceiver(
        HtmlStreamRenderer.create(htmlOutputBuffer, new Handler<String>() {
          public void handle(String x) {
            fail("An unexpected error was raised during the testcase");
          }
        }));
  }

  @Test
  public final void testTagBalancing() {
    balancer.openDocument();
    balancer.openTag("html", ImmutableList.<String>of());
    balancer.openTag("head", ImmutableList.<String>of());
    balancer.openTag("title", ImmutableList.<String>of());
    balancer.text("Hello, <<World>>!");
    // TITLE closed with case-sensitively different name.
    balancer.closeTag("TITLE");
    balancer.closeTag("head");
    balancer.openTag("body", ImmutableList.<String>of());
    balancer.openTag("p", ImmutableList.of("id", "p'0"));
    balancer.text("Hello,");
    balancer.openTag("Br", ImmutableList.<String>of());
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
  public final void testTagSoupIronedOut() {
    balancer.openDocument();
    balancer.openTag("i", ImmutableList.<String>of());
    balancer.text("x");
    balancer.openTag("b", ImmutableList.<String>of());
    balancer.text("y");
    balancer.closeTag("i");
    balancer.text("z");
    balancer.closeDocument();

    assertEquals(
        "<i>x<b>y</b></i><b>z</b>",
        htmlOutputBuffer.toString());
  }

  @Test
  public final void testListInListDirectly() {
    balancer.openDocument();
    balancer.openTag("ul", ImmutableList.<String>of());
    balancer.openTag("li", ImmutableList.<String>of());
    balancer.text("foo");
    balancer.closeTag("li");
    balancer.openTag("ul", ImmutableList.<String>of());
    balancer.openTag("li", ImmutableList.<String>of());
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
  public final void testTextContent() {
    balancer.openDocument();
    balancer.openTag("title", ImmutableList.<String>of());
    balancer.text("Hello, World!");
    balancer.closeTag("title");
    balancer.text("Hello, ");
    balancer.openTag("b", ImmutableList.<String>of());
    balancer.text("World!");
    balancer.closeTag("b");
    balancer.openTag("p", ImmutableList.<String>of());
    balancer.text("Hello, ");
    balancer.openTag("textarea", ImmutableList.<String>of());
    balancer.text("World!");
    balancer.closeTag("textarea");
    balancer.closeTag("p");
    balancer.openTag("h1", ImmutableList.<String>of());
    balancer.text("Hello");
    balancer.openTag("style", ImmutableList.<String>of("type", "text/css"));
    balancer.text("\n.World {\n  color: blue\n}\n");
    balancer.closeTag("style");
    balancer.closeTag("h1");
    balancer.openTag("ul", ImmutableList.<String>of());
    balancer.text("\n  ");
    balancer.openTag("li", ImmutableList.<String>of());
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
        + "<style type=\"text/css\">\n.World {\n  color: blue\n}\n</style></h1>"
        // Whitespace allowed inside <ul> but non-whitespace text nodes are
        // moved inside <li>.
        + "<ul><li>Hello,</li><li>World!</li></ul>",
        htmlOutputBuffer.toString());
  }

  @Test
  public final void testMismatchedHeaders() {
    balancer.openDocument();
    balancer.openTag("H1", ImmutableList.<String>of());
    balancer.text("header");
    balancer.closeTag("h1");
    balancer.text("body");
    balancer.openTag("H2", ImmutableList.<String>of());
    balancer.text("sub-header");
    balancer.closeTag("h3");
    balancer.text("sub-body");
    balancer.openTag("h3", ImmutableList.<String>of());
    balancer.text("sub-sub-");
    balancer.closeTag("hr"); // hr is not a header tag so does not close an h3.
    balancer.text("header");
    // <h3> is not allowed in h3.
    balancer.openTag("h3", ImmutableList.<String>of());
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
  public final void testListNesting() {
    balancer.openDocument();
    balancer.openTag("ul", ImmutableList.<String>of());
    balancer.openTag("li", ImmutableList.<String>of());
    balancer.openTag("ul", ImmutableList.<String>of());
    balancer.openTag("li", ImmutableList.<String>of());
    balancer.text("foo");
    balancer.closeTag("li");
    // Does not closes the second <ul> since only </ol> and </ul> can close a
    // <ul> based on the "has an element in list scope test" used by the HTML5
    // tree building algo.
    balancer.closeTag("li");
    // This would append inside a list, not an item.  We insert an <li>.
    balancer.openTag("ul", ImmutableList.<String>of());
    balancer.openTag("li", ImmutableList.<String>of());
    balancer.text("bar");
    balancer.closeDocument();

    assertEquals(
        "<ul><li><ul><li>foo</li><li><ul><li>bar</li></ul></li></ul></li></ul>",
        htmlOutputBuffer.toString());
  }

  @Test
  public final void testTableNesting() {
    balancer.openDocument();
    balancer.openTag("table", ImmutableList.<String>of());
    balancer.openTag("tbody", ImmutableList.<String>of());
    balancer.openTag("tr", ImmutableList.<String>of());
    balancer.openTag("td", ImmutableList.<String>of());
    balancer.text("foo");
    balancer.closeTag("td");
    // Chrome does not insert a td to contain this mis-nested table.
    // Instead, it ends one table and starts another.
    balancer.openTag("table", ImmutableList.<String>of());
    balancer.openTag("tbody", ImmutableList.<String>of());
    balancer.openTag("tr", ImmutableList.<String>of());
    balancer.openTag("th", ImmutableList.<String>of());
    balancer.text("bar");
    balancer.closeTag("table");
    balancer.closeTag("table");
    balancer.closeDocument();

    assertEquals(
        "<table><tbody><tr><td>foo</td></tr></tbody></table>"
        + "<table><tbody><tr><th>bar</th></tr></tbody></table>",

        htmlOutputBuffer.toString());
  }

  @Test
  public final void testNestingLimits() {
    // Some browsers can be DoSed by deeply nested structures.
    // See Issue 3, "Deeply nested elements crash FF 8, Chrome 11"
    // @ https://github.com/OWASP/java-html-sanitizer/issues/3

    balancer.setNestingLimit(10);
    balancer.openDocument();
    ImmutableList<String> attrs = ImmutableList.<String>of();
    for (int i = 20000; --i >= 0;) {
      balancer.openTag("div", attrs);
    }
    balancer.openTag("hr", attrs);
    balancer.closeDocument();
    assertEquals(
          "<div><div><div><div><div><div><div><div><div><div>"
        + "</div></div></div></div></div></div></div></div></div></div>",
        htmlOutputBuffer.toString());
  }

  @Test
  public final void testTablesGuarded() {
    // Derived from issue 12.
    balancer.openDocument();
    balancer.openTag("html", ImmutableList.<String>of());
    balancer.openTag("head", ImmutableList.<String>of());
    balancer.openTag("meta", ImmutableList.<String>of());
    balancer.closeTag("head");
    balancer.openTag("body", ImmutableList.<String>of());
    balancer.openTag("p", ImmutableList.<String>of());
    balancer.text("Hi");
    balancer.closeTag("p");
    balancer.openTag("p", ImmutableList.<String>of());
    balancer.text("How are you");
    balancer.closeTag("p");
    balancer.text("\n");
    balancer.openTag("ul", ImmutableList.<String>of());
    balancer.openTag("li", ImmutableList.<String>of());
    balancer.openTag("table", ImmutableList.<String>of());
    balancer.openTag("tbody", ImmutableList.<String>of());
    balancer.openTag("tr", ImmutableList.<String>of());
    for (int i = 2; --i >= 0;) {
      balancer.openTag("td", ImmutableList.<String>of());
      balancer.openTag("b", ImmutableList.<String>of());
      balancer.openTag("font", ImmutableList.<String>of());
      balancer.openTag("font", ImmutableList.<String>of());
      balancer.openTag("p", ImmutableList.<String>of());
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
    balancer.openTag("p", ImmutableList.<String>of());
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
  public static final void testIsInterElementWhitespace() {
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
  public final void testAnchorTransparentToBlock() {
    ImmutableList<String> hrefOnly = ImmutableList.of("href", "");
    balancer.openDocument();
    balancer.openTag("div", ImmutableList.<String>of());
    balancer.openTag("a", hrefOnly);
    balancer.openTag("div", ImmutableList.<String>of());
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
  public final void testAnchorTransparentToSpans() {
    ImmutableList<String> hrefOnly = ImmutableList.of("href", "");
    balancer.openDocument();
    balancer.openTag("span", ImmutableList.<String>of());
    balancer.openTag("a", hrefOnly);
    balancer.openTag("span", ImmutableList.<String>of());
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
  public final void testAnchorWithInlineInBlock() {
    ImmutableList<String> hrefOnly = ImmutableList.of("href", "");
    balancer.openDocument();
    balancer.openTag("div", ImmutableList.<String>of());
    balancer.openTag("a", hrefOnly);
    balancer.openTag("span", ImmutableList.<String>of());
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
  public final void testDirectlyNestedAnchor() {
    ImmutableList<String> hrefOnly = ImmutableList.of("href", "");
    balancer.openDocument();
    balancer.openTag("span", ImmutableList.<String>of());
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
  public final void testAnchorClosedWhenBlockInInline() {
    ImmutableList<String> hrefOnly = ImmutableList.of("href", "");
    balancer.openDocument();
    balancer.openTag("span", ImmutableList.<String>of());
    balancer.openTag("a", hrefOnly);
    balancer.openTag("div", ImmutableList.<String>of());
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


  // TODO: Double check this test and handle nested anchors properly.
  @Test
  @Ignore
  public final void failingtestAnchorInAnchorIndirectly() {
    ImmutableList<String> hrefOnly = ImmutableList.of("href", "");
    balancer.openDocument();
    balancer.openTag("div", ImmutableList.<String>of());
    balancer.openTag("a", hrefOnly);
    balancer.openTag("div", ImmutableList.<String>of());
    balancer.openTag("a", hrefOnly);
    balancer.text("...");
    balancer.closeTag("a");
    balancer.closeTag("div");
    balancer.closeTag("a");
    balancer.closeTag("div");
    balancer.closeDocument();

    assertEquals(
        "<div><a href=\"\"><div></div></a><a href=\"\">...</a></a>",
        htmlOutputBuffer.toString());
  }

  @Test
  public final void testInteractiveInAnchorIndirectly() {
    ImmutableList<String> hrefOnly = ImmutableList.of("href", "");
    balancer.openDocument();
    balancer.openTag("div", ImmutableList.<String>of());
    balancer.openTag("a", hrefOnly);
    balancer.openTag("div", ImmutableList.<String>of());
    balancer.openTag("video", ImmutableList.<String>of());
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
  public final void testAnchorWithBlockAtTopLevel() {
    ImmutableList<String> hrefOnly = ImmutableList.of("href", "");
    balancer.openDocument();
    balancer.openTag("a", hrefOnly);
    balancer.openTag("div", ImmutableList.<String>of());
    balancer.text("...");
    balancer.closeTag("div");
    balancer.closeTag("a");
    balancer.closeDocument();
    assertEquals(
        "<a href=\"\"><div>...</div></a>",
        htmlOutputBuffer.toString());
  }

  @Test
  public final void testResumedElementsAllowedWhereResumed() {
    balancer.openDocument();
    balancer.openTag("a", ImmutableList.<String>of());
    balancer.openTag("b", ImmutableList.<String>of());
    balancer.text("foo");
    balancer.openTag("i", ImmutableList.<String>of());
    balancer.openTag("a", ImmutableList.<String>of());
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

  @Test
  public final void testMenuItemNesting() {
    // issue 96
    balancer.openDocument();
    balancer.openTag("div", ImmutableList.<String>of());
    balancer.openTag("menu", ImmutableList.<String>of());
    balancer.openTag("menuitem", ImmutableList.<String>of());
    balancer.closeTag("menuitem");
    balancer.openTag("menuitem", ImmutableList.<String>of());
    balancer.closeTag("menuitem");
    balancer.closeTag("menu");
    balancer.closeTag("div");
    assertEquals(
        "<div><menu><menuitem></menuitem><menuitem></menuitem></menu></div>",
        htmlOutputBuffer.toString());
  }
}
