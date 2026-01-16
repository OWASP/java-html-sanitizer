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

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.owasp.shim.Java8Shim.j8;

class HtmlStreamRendererTest {

  private final List<String> errors = new ArrayList<>();
  private final StringBuilder rendered = new StringBuilder();
  private final HtmlStreamRenderer renderer = HtmlStreamRenderer.create(
      rendered, errorMessage -> {
        @SuppressWarnings({"synthetic-access"})
        List<String> errors = HtmlStreamRendererTest.this.errors;
        errors.add(errorMessage);
      });

  @BeforeEach
  void setUp() {
    errors.clear();
    rendered.setLength(0);
  }

  @AfterEach
  void tearDown() {
    assertTrue(errors.isEmpty(), errors.toString());  // Catch any tests that don't check errors.
  }

  @Test
  void testEmptyDocument() {
    assertNormalized("", "");
  }

  @Test
  void testElementNamesNormalized() {
    assertNormalized("<br />", "<br>");
    assertNormalized("<br />", "<BR>");
    assertNormalized("<br />", "<Br />");
    assertNormalized("<br />", "<br\n>");
  }

  @Test
  void testAttributeNamesNormalized() {
    assertNormalized("<input id=\"foo\" />", "<input  id=foo>");
    assertNormalized("<input id=\"foo\" />", "<input id=\"foo\">");
    assertNormalized("<input id=\"foo\" />", "<input  ID='foo'>");
    assertNormalized("<input id=\"foo\" />", "<input\nid='foo'>");
    assertNormalized("<input id=\"foo\" />", "<input\nid=foo'>");
  }

  @Test
  void testAttributeValuesEscaped() {
    assertNormalized("<div title=\"a&lt;b\"></div>", "<div title=a<b></div>");
  }

  @Test
  void testRcdataEscaped() {
    assertNormalized(
        "<title>I &lt;3 PONIES, OMG!!!</title>",
        "<TITLE>I <3 PONIES, OMG!!!</TITLE>");
  }

  @Test
  void testCdataNotEscaped() {
    assertNormalized(
        "<script>I <3\n!!!PONIES, OMG</script>",
        "<script>I <3\n!!!PONIES, OMG</script>");
  }

  @Test
  void testIllegalElementName() {
    renderer.openDocument();
    renderer.openTag(":svg", j8().listOf());
    renderer.openTag("svg:", j8().listOf());
    renderer.openTag("-1", j8().listOf());
    renderer.openTag("svg::svg", j8().listOf());
    renderer.openTag("a@b", j8().listOf());
    renderer.closeDocument();

    String output = rendered.toString();
    assertFalse(output.contains("<"), output);

    assertEquals(
            String.join("\n", "Invalid element name : :svg",
                    "Invalid element name : svg:",
                    "Invalid element name : -1",
                    "Invalid element name : svg::svg",
                    "Invalid element name : a@b"),
            String.join("\n", errors));
    errors.clear();
  }

  @Test
  void testIllegalAttributeName() {
    renderer.openDocument();
    renderer.openTag("div", j8().listOf(":svg", "x"));
    renderer.openTag("div", j8().listOf("svg:", "x"));
    renderer.openTag("div", j8().listOf("-1", "x"));
    renderer.openTag("div", j8().listOf("svg::svg", "x"));
    renderer.openTag("div", j8().listOf("a@b", "x"));
    renderer.closeDocument();

    String output = rendered.toString();
    assertFalse(output.contains("="), output);

    assertEquals(
            String.join("\n", "Invalid attr name : :svg",
                    "Invalid attr name : svg:",
                    "Invalid attr name : -1",
                    "Invalid attr name : svg::svg",
                    "Invalid attr name : a@b"),
            String.join("\n", errors));
    errors.clear();
  }

  @Test
  void testCdataContainsEndTag1() {
    renderer.openDocument();
    renderer.openTag("script", j8().listOf("type", "text/javascript"));
    renderer.text("document.write('<SCRIPT>alert(42)</SCRIPT>')");
    renderer.closeTag("script");
    renderer.closeDocument();

    assertEquals(
        "<script type=\"text/javascript\"></script>", rendered.toString());
    assertEquals(
        "Invalid CDATA text content : </SCRIPT>'",
            String.join("\n", errors));
    errors.clear();
  }

  @Test
  void testCdataContainsEndTag2() {
    renderer.openDocument();
    renderer.openTag("style", j8().listOf("type", "text/css"));
    renderer.text("/* </St");
    // Split into two text chunks, and insert NULs.
    renderer.text("\0yle> */");
    renderer.closeTag("style");
    renderer.closeDocument();

    assertEquals(
        "<style type=\"text/css\"></style>", rendered.toString());
    assertEquals(
        "Invalid CDATA text content : </Style> *",
            String.join("\n", errors));
    errors.clear();
  }

  @Test
  void testRcdataContainsEndTag() {
    renderer.openDocument();
    renderer.openTag("textarea", j8().listOf());
    renderer.text("<textarea></textarea>");
    renderer.closeTag("textarea");
    renderer.closeDocument();

    assertEquals(
        "<textarea>&lt;textarea&gt;&lt;/textarea&gt;</textarea>",
        rendered.toString());
  }

  @Test
  void testEndTagInsideScriptBodyInner() {
    assertNormalized(
        "<script></script>&#39;)--&gt;",
        "<script><!--document.write('<SCRIPT>alert(42)</SCRIPT>')--></script>");
    assertEquals(
        "Invalid CDATA text content : <SCRIPT>al",
            String.join("\n", errors));
    errors.clear();
  }

  // Testcases from
  // www.w3.org/TR/html51/semantics-scripting.html#restrictions-for-contents-of-script-elements
  @Test
  void testHtml51SemanticsScriptingExample5Part1() {
    String js = "  var example = 'Consider this string: <!-- <script>';\n"
        + "  console.log(example);\n";

    renderer.openDocument();
    renderer.openTag("script", j8().listOf());
    renderer.text(js);
    renderer.closeTag("script");
    renderer.closeDocument();

    assertEquals(
        "<script></script>",
        rendered.toString());
    assertEquals(
        "Invalid CDATA text content : <script>';",
            String.join("\n", errors));
    errors.clear();
  }

  @Test
  void testHtml51SemanticsScriptingExample5Part2() {
    String js = "if (x<!--y) { ... }\n";

    renderer.openDocument();
    renderer.openTag("script", j8().listOf());
    renderer.text(js);
    renderer.closeTag("script");
    renderer.closeDocument();

    assertEquals(
        "<script></script>",
        rendered.toString());
    assertEquals(
        "Invalid CDATA text content : <!--y) { .",
            String.join("\n", errors));
    errors.clear();
  }

  @Test
  void testMoreUnbalancedHtmlCommentsInScripts() {
    String js = "if (x-->y) { ... }\n";

    renderer.openDocument();
    renderer.openTag("script", j8().listOf());
    renderer.text(js);
    renderer.closeTag("script");
    renderer.closeDocument();

    // We could actually allow this since --> is not banned per 4.12.1.3
    assertEquals(
        "<script></script>",
        rendered.toString());
    assertEquals(
        "Invalid CDATA text content : -->y) { ..",
            String.join("\n", errors));
    errors.clear();
  }

  @Test
  void testShortHtmlCommentInScript() {
    String js = "// <!----> <!--->";

    renderer.openDocument();
    renderer.openTag("script", j8().listOf());
    renderer.text(js);
    renderer.closeTag("script");
    renderer.closeDocument();

    // We could actually allow this since --> is not banned per 4.12.1.3
    assertEquals(
        "<script></script>",
        rendered.toString());
    assertEquals(
        "Invalid CDATA text content : <!--->",
            String.join("\n", errors));
    errors.clear();
  }

  @Test
  void testHtml51SemanticsScriptingExample5Part3() {
    String js = "<!-- if ( player<script ) { ... } -->";

    renderer.openDocument();
    renderer.openTag("script", j8().listOf());
    renderer.text(js);
    renderer.closeTag("script");
    renderer.closeDocument();

    assertEquals(
        "<script></script>",
        rendered.toString());
    assertEquals(
        "Invalid CDATA text content : <script ) ",
            String.join("\n", errors));
    errors.clear();
  }

  @Test
  void testHtml51SemanticsScriptingExample5Part4() {
    String js = "<!--\n"
        + "if (x < !--y) { ... }\n"
        + "if (!--y > x) { ... }\n"
        + "if (!(--y) > x) { ... }\n"
        + "if (player < script) { ... }\n"
        + "if (script > player) { ... }\n"
        + "-->";

    renderer.openDocument();
    renderer.openTag("script", j8().listOf());
    renderer.text(js);
    renderer.closeTag("script");
    renderer.closeDocument();

    assertEquals(
        "<script><!--\n"
        + "if (x < !--y) { ... }\n"
        + "if (!--y > x) { ... }\n"
        + "if (!(--y) > x) { ... }\n"
        + "if (player < script) { ... }\n"
        + "if (script > player) { ... }\n"
        + "--></script>",
        rendered.toString());
  }

  @Test
  void testHtmlCommentInRcdata() {
    String str = "// <!----> <!---> <!--";

    renderer.openDocument();
    renderer.openTag("title", j8().listOf());
    renderer.text(str);
    renderer.closeTag("title");
    renderer.openTag("textarea", j8().listOf());
    renderer.text(str);
    renderer.closeTag("textarea");
    renderer.closeDocument();

    assertEquals(
        "<title>// &lt;!----&gt; &lt;!---&gt; &lt;!--</title>"
        + "<textarea>// &lt;!----&gt; &lt;!---&gt; &lt;!--</textarea>",
        rendered.toString());
  }

  @Test
  void testTagInCdata() {
    renderer.openDocument();
    renderer.openTag("script", j8().listOf());
    renderer.text("alert('");
    renderer.openTag("b", j8().listOf());
    renderer.text("foo");
    renderer.closeTag("b");
    renderer.text("')");
    renderer.closeTag("script");
    renderer.closeDocument();

    assertEquals(
        "<script>alert('foo')</script>", rendered.toString());
    assertEquals(
            String.join("\n", "Tag content cannot appear inside CDATA element : b",
                    "Tag content cannot appear inside CDATA element : b"),
            String.join("\n", errors));
    errors.clear();
  }

  @Test
  void testUnclosedEscapingTextSpan() {
    renderer.openDocument();
    renderer.openTag("script", j8().listOf());
    renderer.text("<!--alert('</script>')");
    renderer.closeTag("script");
    renderer.closeDocument();

    assertEquals("<script></script>", rendered.toString());
    assertEquals(
        "Invalid CDATA text content : </script>'",
            String.join("\n", errors));
    errors.clear();
  }

  @Test
  void testAlmostCompleteEndTag() {
    renderer.openDocument();
    renderer.openTag("script", j8().listOf());
    renderer.text("//</scrip");
    renderer.closeTag("script");
    renderer.closeDocument();

    assertEquals("<script>//</scrip</script>", rendered.toString());
  }

  @Test
  void testBalancedCommentInNoscript() {
    renderer.openDocument();
    renderer.openTag("noscript", j8().listOf());
    renderer.text("<!--<script>foo</script>-->");
    renderer.closeTag("noscript");
    renderer.closeDocument();

    assertEquals(
        "<noscript>&lt;!--&lt;script&gt;foo&lt;/script&gt;--&gt;</noscript>",
        rendered.toString());
  }

  @Test
  void testUnbalancedCommentInNoscript() {
    renderer.openDocument();
    renderer.openTag("noscript", j8().listOf());
    renderer.text("<!--<script>foo</script>--");
    renderer.closeTag("noscript");
    renderer.openTag("noscript", j8().listOf());
    renderer.text("<script>foo</script>-->");
    renderer.closeTag("noscript");
    renderer.closeDocument();

    assertEquals(
        "<noscript>&lt;!--&lt;script&gt;foo&lt;/script&gt;--</noscript>"
        + "<noscript>&lt;script&gt;foo&lt;/script&gt;--&gt;</noscript>",
        rendered.toString());
  }

  @Test
  void testSupplementaryCodepoints() {
    renderer.openDocument();
    renderer.text("\uD87E\uDC1A");  // Supplementary codepoint U+2F81A
    renderer.closeDocument();

    assertEquals("&#x2f81a;", rendered.toString());
  }

  // Test that policies that naively allow <xmp>, <listing>, or <plaintext>
  // on XHTML don't shoot themselves in the foot.

  @Test
  void testPreSubstitutes1() {
    renderer.openDocument();
    renderer.openTag("Xmp", j8().listOf());
    renderer.text("<form>Hello, World</form>");
    renderer.closeTag("Xmp");
    renderer.closeDocument();

    assertEquals("<pre>&lt;form&gt;Hello, World&lt;/form&gt;</pre>",
                 rendered.toString());
  }

  @Test
  void testPreSubstitutes2() {
    renderer.openDocument();
    renderer.openTag("xmp", j8().listOf());
    renderer.text("<form>Hello, World</form>");
    renderer.closeTag("xmp");
    renderer.closeDocument();

    assertEquals("<pre>&lt;form&gt;Hello, World&lt;/form&gt;</pre>",
                 rendered.toString());
  }

  @Test
  void testPreSubstitutes3() {
    renderer.openDocument();
    renderer.openTag("LISTING", j8().listOf());
    renderer.text("<form>Hello, World</form>");
    renderer.closeTag("LISTING");
    renderer.closeDocument();

    assertEquals("<pre>&lt;form&gt;Hello, World&lt;/form&gt;</pre>",
                 rendered.toString());
  }

  @Test
  void testPreSubstitutes4() {
    renderer.openDocument();
    renderer.openTag("plaintext", j8().listOf());
    renderer.text("<form>Hello, World</form>");
    renderer.closeDocument();

    assertEquals("<pre>&lt;form&gt;Hello, World&lt;/form&gt;",
                 rendered.toString());
  }

  private void assertNormalized(String golden, String htmlInput) {
    assertEquals(golden, normalize(htmlInput));

    // Check that normalization is idempotent.
    if (!golden.equals(htmlInput)) {
      assertNormalized(golden, golden);
    }
  }

  private String normalize(String htmlInput) {
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
