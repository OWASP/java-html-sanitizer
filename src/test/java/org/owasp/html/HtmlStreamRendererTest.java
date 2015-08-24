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

import java.util.List;

import com.google.common.base.Joiner;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;

import junit.framework.TestCase;

@SuppressWarnings("javadoc")
public class HtmlStreamRendererTest extends TestCase {

  private final List<String> errors = Lists.newArrayList();
  private final StringBuilder rendered = new StringBuilder();
  private final HtmlStreamRenderer renderer = HtmlStreamRenderer.create(
      rendered, new Handler<String>() {
        public void handle(String errorMessage) {
          @SuppressWarnings({"hiding", "synthetic-access"})
          List<String> errors = HtmlStreamRendererTest.this.errors;
          errors.add(errorMessage);
        }
      });

  @Override
  protected void setUp() throws Exception {
    super.setUp();
    errors.clear();
    rendered.setLength(0);
  }

  @Override
  protected void tearDown() throws Exception {
    super.tearDown();
    assertTrue(errors.isEmpty());  // Catch any tests that don't check errors.
  }

  public final void testEmptyDocument() throws Exception {
    assertNormalized("", "");
  }

  public final void testElementNamesNormalized() throws Exception {
    assertNormalized("<br />", "<br>");
    assertNormalized("<br />", "<BR>");
    assertNormalized("<br />", "<Br />");
    assertNormalized("<br />", "<br\n>");
  }

  public final void testAttributeNamesNormalized() throws Exception {
    assertNormalized("<input id=\"foo\" />", "<input  id=foo>");
    assertNormalized("<input id=\"foo\" />", "<input id=\"foo\">");
    assertNormalized("<input id=\"foo\" />", "<input  ID='foo'>");
    assertNormalized("<input id=\"foo\" />", "<input\nid='foo'>");
    assertNormalized("<input id=\"foo\" />", "<input\nid=foo'>");
  }

  public final void testAttributeValuesEscaped() throws Exception {
    assertNormalized("<div title=\"a&lt;b\"></div>", "<div title=a<b></div>");
  }

  public final void testRcdataEscaped() throws Exception {
    assertNormalized(
        "<title>I &lt;3 PONIES, OMG!!!</title>",
        "<TITLE>I <3 PONIES, OMG!!!</TITLE>");
  }

  public final void testCdataNotEscaped() throws Exception {
    assertNormalized(
        "<script>I <3\n!!!PONIES, OMG</script>",
        "<script>I <3\n!!!PONIES, OMG</script>");
  }

  public final void testIllegalElementName() throws Exception {
    renderer.openDocument();
    renderer.openTag(":svg", ImmutableList.<String>of());
    renderer.openTag("svg:", ImmutableList.<String>of());
    renderer.openTag("-1", ImmutableList.<String>of());
    renderer.openTag("svg::svg", ImmutableList.<String>of());
    renderer.openTag("a@b", ImmutableList.<String>of());
    renderer.closeDocument();

    String output = rendered.toString();
    assertFalse(output, output.contains("<"));

    assertEquals(
        Joiner.on('\n').join(
            "Invalid element name : :svg",
            "Invalid element name : svg:",
            "Invalid element name : -1",
            "Invalid element name : svg::svg",
            "Invalid element name : a@b"),
        Joiner.on('\n').join(errors));
    errors.clear();
  }

  public final void testIllegalAttributeName() throws Exception {
    renderer.openDocument();
    renderer.openTag("div", ImmutableList.of(":svg", "x"));
    renderer.openTag("div", ImmutableList.of("svg:", "x"));
    renderer.openTag("div", ImmutableList.of("-1", "x"));
    renderer.openTag("div", ImmutableList.of("svg::svg", "x"));
    renderer.openTag("div", ImmutableList.of("a@b", "x"));
    renderer.closeDocument();

    String output = rendered.toString();
    assertFalse(output, output.contains("="));

    assertEquals(
        Joiner.on('\n').join(
            "Invalid attr name : :svg",
            "Invalid attr name : svg:",
            "Invalid attr name : -1",
            "Invalid attr name : svg::svg",
            "Invalid attr name : a@b"),
        Joiner.on('\n').join(errors));
    errors.clear();
  }

  public final void testCdataContainsEndTag1() throws Exception {
    renderer.openDocument();
    renderer.openTag("script", ImmutableList.of("type", "text/javascript"));
    renderer.text("document.write('<SCRIPT>alert(42)</SCRIPT>')");
    renderer.closeTag("script");
    renderer.closeDocument();

    assertEquals(
        "<script type=\"text/javascript\"></script>", rendered.toString());
    assertEquals(
        "Invalid CDATA text content : </SCRIPT>'",
        Joiner.on('\n').join(errors));
    errors.clear();
  }

  public final void testCdataContainsEndTag2() throws Exception {
    renderer.openDocument();
    renderer.openTag("style", ImmutableList.of("type", "text/css"));
    renderer.text("/* </St");
    // Split into two text chunks, and insert NULs.
    renderer.text("\0yle> */");
    renderer.closeTag("style");
    renderer.closeDocument();

    assertEquals(
        "<style type=\"text/css\"></style>", rendered.toString());
    assertEquals(
        "Invalid CDATA text content : </Style> *",
        Joiner.on('\n').join(errors));
    errors.clear();
  }

  public final void testRcdataContainsEndTag() throws Exception {
    renderer.openDocument();
    renderer.openTag("textarea", ImmutableList.<String>of());
    renderer.text("<textarea></textarea>");
    renderer.closeTag("textarea");
    renderer.closeDocument();

    assertEquals(
        "<textarea>&lt;textarea&gt;&lt;/textarea&gt;</textarea>",
        rendered.toString());
  }

  public final void testCdataContainsEndTagInEscapingSpan() throws Exception {
    assertNormalized(
        "<script><!--document.write('<SCRIPT>alert(42)</SCRIPT>')--></script>",
        "<script><!--document.write('<SCRIPT>alert(42)</SCRIPT>')--></script>");
  }

  public final void testTagInCdata() throws Exception {
    renderer.openDocument();
    renderer.openTag("script", ImmutableList.<String>of());
    renderer.text("alert('");
    renderer.openTag("b", ImmutableList.<String>of());
    renderer.text("foo");
    renderer.closeTag("b");
    renderer.text("')");
    renderer.closeTag("script");
    renderer.closeDocument();

    assertEquals(
        "<script>alert('foo')</script>", rendered.toString());
    assertEquals(
        Joiner.on('\n').join(
            "Tag content cannot appear inside CDATA element : b",
            "Tag content cannot appear inside CDATA element : b"),
        Joiner.on('\n').join(errors));
    errors.clear();
  }

  public final void testUnclosedEscapingTextSpan() throws Exception {
    renderer.openDocument();
    renderer.openTag("script", ImmutableList.<String>of());
    renderer.text("<!--alert('</script>')");
    renderer.closeTag("script");
    renderer.closeDocument();

    assertEquals("<script></script>", rendered.toString());
    assertEquals(
        "Invalid CDATA text content : <!--alert(",
        Joiner.on('\n').join(errors));
    errors.clear();
  }

  public final void testSupplementaryCodepoints() throws Exception {
    renderer.openDocument();
    renderer.text("\uD87E\uDC1A");  // Supplementary codepoint U+2F81A
    renderer.closeDocument();

    assertEquals("&#x2f81a;", rendered.toString());
  }

  // Test that policies that naively allow <xmp>, <listing>, or <plaintext>
  // on XHTML don't shoot themselves in the foot.

  public final void testPreSubstitutes1() throws Exception {
    renderer.openDocument();
    renderer.openTag("Xmp", ImmutableList.<String>of());
    renderer.text("<form>Hello, World</form>");
    renderer.closeTag("Xmp");
    renderer.closeDocument();

    assertEquals("<pre>&lt;form&gt;Hello, World&lt;/form&gt;</pre>",
                 rendered.toString());
  }

  public final void testPreSubstitutes2() throws Exception {
    renderer.openDocument();
    renderer.openTag("xmp", ImmutableList.<String>of());
    renderer.text("<form>Hello, World</form>");
    renderer.closeTag("xmp");
    renderer.closeDocument();

    assertEquals("<pre>&lt;form&gt;Hello, World&lt;/form&gt;</pre>",
                 rendered.toString());
  }

  public final void testPreSubstitutes3() throws Exception {
    renderer.openDocument();
    renderer.openTag("LISTING", ImmutableList.<String>of());
    renderer.text("<form>Hello, World</form>");
    renderer.closeTag("LISTING");
    renderer.closeDocument();

    assertEquals("<pre>&lt;form&gt;Hello, World&lt;/form&gt;</pre>",
                 rendered.toString());
  }

  public final void testPreSubstitutes4() throws Exception {
    renderer.openDocument();
    renderer.openTag("plaintext", ImmutableList.<String>of());
    renderer.text("<form>Hello, World</form>");
    renderer.closeDocument();

    assertEquals("<pre>&lt;form&gt;Hello, World&lt;/form&gt;",
                 rendered.toString());
  }

  private void assertNormalized(String golden, String htmlInput)
      throws Exception {
    assertEquals(golden, normalize(htmlInput));

    // Check that normalization is idempotent.
    if (!golden.equals(htmlInput)) {
      assertNormalized(golden, golden);
    }
  }

  private String normalize(String htmlInput) {
    @SuppressWarnings("hiding")
    final HtmlStreamRenderer renderer = this.renderer;
    // Use a permissive sanitizer to generate the events.
    HtmlSanitizer.sanitize(htmlInput, new HtmlSanitizer.Policy() {
      public void openTag(String elementName, List<String> attrs) {
        renderer.openTag(elementName, attrs);
      }

      public void closeTag(String elementName) {
        renderer.closeTag(elementName);
      }

      public void text(String textChunk) {
        renderer.text(textChunk);
      }

      public void openDocument() {
        renderer.openDocument();
      }

      public void closeDocument() {
        renderer.closeDocument();
      }
    });

    String result = rendered.toString();
    rendered.setLength(0);
    return result;
  }
}
