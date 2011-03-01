package org.owasp.html;

import com.google.common.collect.ImmutableSet;

import java.util.List;
import java.util.ListIterator;

import junit.framework.TestCase;


public class HtmlSanitizerTest extends TestCase {

  public final void testDecodeHtml() {
    String html =
      "The quick&nbsp;brown fox&#xa;jumps over&#xd;&#10;the lazy dog&#x000a;";
    //          1         2         3         4         5         6
    // 123456789012345678901234567890123456789012345678901234567890123456789
    String golden =
      "The quick\u00a0brown fox\njumps over\r\nthe lazy dog\n";
    assertEquals(golden, HtmlSanitizer.decodeHtml(html));

    // Don't allocate a new string when no entities.
    assertSame(golden, HtmlSanitizer.decodeHtml(golden));

    // test interrupted escapes and escapes at end of file handled gracefully
    assertEquals(
        HtmlSanitizer.decodeHtml("\\\\u000a"),
        "\\\\u000a");
    assertEquals(
        HtmlSanitizer.decodeHtml("&#x000a;"),
        "\n");
    assertEquals(
        HtmlSanitizer.decodeHtml("&#x00a;"),
        "\n");
    assertEquals(
        HtmlSanitizer.decodeHtml("&#x0a;"),
        "\n");
    assertEquals(
        HtmlSanitizer.decodeHtml("&#xa;"),
        "\n");
    assertEquals(
        HtmlSanitizer.decodeHtml("&#x10000;"),
        String.valueOf(Character.toChars(0x10000)));
    assertEquals(
        HtmlSanitizer.decodeHtml("&#xa"),
        "&#xa");
    assertEquals(
        HtmlSanitizer.decodeHtml("&#x00ziggy"),
        "&#x00ziggy");
    assertEquals(
        HtmlSanitizer.decodeHtml("&#xa00z;"),
        "&#xa00z;");
    assertEquals(
        HtmlSanitizer.decodeHtml("&#&#x000a;"),
        "&#\n");
    assertEquals(
        HtmlSanitizer.decodeHtml("&#x&#x000a;"),
        "&#x\n");
    assertEquals(
        HtmlSanitizer.decodeHtml("&#xa&#x000a;"),
        "&#xa\n");
    assertEquals(
        HtmlSanitizer.decodeHtml("&#&#xa;"),
        "&#\n");
    assertEquals(
        HtmlSanitizer.decodeHtml("&#x"),
        "&#x");
    assertEquals(
        HtmlSanitizer.decodeHtml("&#x0"),
        "&#x0");
    assertEquals(
        HtmlSanitizer.decodeHtml("&#"),
        "&#");

    assertEquals(
        HtmlSanitizer.decodeHtml("\\"),
        "\\");
    assertEquals(
        HtmlSanitizer.decodeHtml("&"),
        "&");

    assertEquals(
        HtmlSanitizer.decodeHtml("&#000a;"),
        "&#000a;");
    assertEquals(
        HtmlSanitizer.decodeHtml("&#10;"),
        "\n");
    assertEquals(
        HtmlSanitizer.decodeHtml("&#010;"),
        "\n");
    assertEquals(
        HtmlSanitizer.decodeHtml("&#0010;"),
        "\n");
    assertEquals(
        HtmlSanitizer.decodeHtml("&#9;"),
        "\t");
    assertEquals(
        HtmlSanitizer.decodeHtml("&#10"),
        "&#10");
    assertEquals(
        HtmlSanitizer.decodeHtml("&#00ziggy"),
        "&#00ziggy");
    assertEquals(
        HtmlSanitizer.decodeHtml("&#&#010;"),
        "&#\n");
    assertEquals(
        HtmlSanitizer.decodeHtml("&#0&#010;"),
        "&#0\n");
    assertEquals(
        HtmlSanitizer.decodeHtml("&#01&#10;"),
        "&#01\n");
    assertEquals(
        HtmlSanitizer.decodeHtml("&#&#10;"),
        "&#\n");
    assertEquals(
        HtmlSanitizer.decodeHtml("&#1"),
        "&#1");
    assertEquals(
        HtmlSanitizer.decodeHtml("&#10"),
        "&#10");

    // test the named escapes
    assertEquals(
        HtmlSanitizer.decodeHtml("&lt;"),
        "<");
    assertEquals(
        HtmlSanitizer.decodeHtml("&gt;"),
        ">");
    assertEquals(
        HtmlSanitizer.decodeHtml("&quot;"),
        "\"");
    assertEquals(
        HtmlSanitizer.decodeHtml("&apos;"),
        "'");
    assertEquals(
        HtmlSanitizer.decodeHtml("&#39;"),
        "'");
    assertEquals(
        HtmlSanitizer.decodeHtml("&#x27;"),
        "'");
    assertEquals(
        HtmlSanitizer.decodeHtml("&amp;"),
        "&");
    assertEquals(
        HtmlSanitizer.decodeHtml("&amp;lt;"),
        "&lt;");
    assertEquals(
        HtmlSanitizer.decodeHtml("&AMP;"),
        "&");
    assertEquals(
        HtmlSanitizer.decodeHtml("&AMP"),
        "&AMP");
    assertEquals(
        HtmlSanitizer.decodeHtml("&AmP;"),
        "&");
    assertEquals(
        HtmlSanitizer.decodeHtml("&Alpha;"),
        "\u0391");
    assertEquals(
        HtmlSanitizer.decodeHtml("&alpha;"),
        "\u03b1");


    assertEquals(
        HtmlSanitizer.decodeHtml("&;"),
        "&;");
    assertEquals(
        HtmlSanitizer.decodeHtml("&bogus;"),
        "&bogus;");
  }


  public final void testEmpty() throws Exception {
    assertEquals("", sanitize(""));
  }

  public final void testSimpleText() throws Exception {
    assertEquals("hello world", sanitize("hello world"));
  }

  public final void testEntities1() throws Exception {
    assertEquals("&lt;hello world&gt;", sanitize("&lt;hello world&gt;"));
  }

  public final void testEntities2() throws Exception {
    assertEquals("<b>hello <i>world</i></b>",
		 sanitize("<b>hello <i>world</i></b>"));
  }

  public final void testUnknownTagsRemoved() throws Exception {
    assertEquals("<b>hello <i>world</i></b>",
		 sanitize("<b>hello <bogus></bogus><i>world</i></b>"));
  }

  public final void testUnsafeTagsRemoved() throws Exception {
    assertEquals("<b>hello <i>world</i></b>",
		 sanitize("<b>hello <i>world</i>"
			  + "<script src=foo.js></script></b>"));
  }

  public final void testUnsafeAttributesRemoved() throws Exception {
    assertEquals("<b>hello <i>world</i></b>",
		 sanitize(
                     "<b>hello <i onclick=\"takeOverWorld(this)\">world</i></b>"));
  }

  public final void testCruftEscaped() throws Exception {
    assertEquals("<b>hello <i>world&lt;</i></b> &amp; tomorrow the universe",
		 sanitize(
                     "<b>hello <i>world<</i></b> & tomorrow the universe"));
  }

  public final void testTagCruftRemoved() throws Exception {
    assertEquals("<b id=\"p-foo\">hello <i>world&lt;</i></b>",
		 sanitize("<b id=\"foo\" / -->hello <i>world<</i></b>"));
  }

  public final void testIdsAndClassesPrefixed() throws Exception {
    assertEquals(
        "<b id=\"p-foo\" class=\"p-boo p-bar p-baz\">hello <i>world&lt;</i></b>",
        sanitize(
            "<b id=\"foo\" class=\"boo bar baz\">hello <i>world<</i></b>"));
  }

  public final void testSpecialCharsInAttributes() throws Exception {
    assertEquals(
        "<b title=\"a&lt;b &amp;&amp; c&gt;b\">bar</b>",
        sanitize("<b title=\"a<b && c>b\">bar</b>"));
  }

  public final void testUnclosedTags() throws Exception {
    assertEquals("<div id=\"p-foo\">Bar<br>Baz</div>",
		 sanitize("<div id=\"foo\">Bar<br>Baz"));
  }

  public final void testUnopenedTags() throws Exception {
    assertEquals("Foo<b>Bar</b>Baz",
		 sanitize("Foo<b></select>Bar</b></b>Baz</select>"));
  }

  public final void testUnsafeEndTags() throws Exception {
    assertEquals(
        "",
        sanitize(
            "</meta http-equiv=\"refesh\" content=\"1;URL=http://evilgadget.com\">"));
  }

  public final void testEmptyEndTags() throws Exception {
    assertEquals("<input>", sanitize("<input></input>"));
  }

  public final void testOnLoadStripped() throws Exception {
    assertEquals(
        "<img>",
        sanitize("<img src=http://foo.com/bar ONLOAD=alert(1)>"));
  }

  public final void testClosingTagParameters() throws Exception {
    assertEquals(
        "<p>Hello world</p>",
        sanitize("<p>Hello world</b style=\"width:expression(alert(1))\">"));
  }

  public final void testOptionalEndTags() throws Exception {
    // Should not be
    //     "<ol> <li>A</li> <li>B<li>C </li></li></ol>"
    // The difference is significant because in the first, the item contains no
    // space after 'A", but in the third, the item contains 'C' and a space.
    assertEquals(
        "<ol> <li>A</li> <li>B</li><li>C </li></ol>",
        sanitize("<ol> <li>A</li> <li>B<li>C </ol>"));
  }

  public final void testFoldingOfHtmlAndBodyTags() throws Exception {
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
            + "<p>One</p>"
            + "<p>Two</p>"
            + "Three"
            + "<p>Four</p>"
            + "</body>"
            + "</html>"));
  }

  public final void testEmptyAndValuelessAttributes() throws Exception {
    assertEquals(
        "<input checked=\"checked\" type=\"checkbox\" id=\"\" class=\"\">",
        sanitize("<input checked type=checkbox id=\"\" class=>"));
  }

  public final void testSgmlShortTags() throws Exception {
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

  public final void testNul() throws Exception {
    // See bug 614 for details.
    assertEquals(
        "<a title=\"harmless  SCRIPT&#61;javascript:alert(1) ignored&#61;ignored\">"
        + "</a>",
        sanitize(
            "<A TITLE=\"harmless\0  SCRIPT=javascript:alert(1) ignored=ignored\">"
            ));
  }

  public final void testDigitsInAttrNames() throws Exception {
    // See bug 614 for details.
    assertEquals(
        "<div>Hello</div>",
        sanitize(
            "<div style1=\"expression(\'alert(1)\")\">Hello</div>"
            ));
  }

  private static String sanitize(String html) throws Exception {
    StringBuilder sb = new StringBuilder();
    final HtmlStreamRenderer renderer = HtmlStreamRenderer.create(
        sb,
        new Handler<String>() {
          @Override
          public void handle(String errorMessage) {
            fail(errorMessage);
          }
        });

    // A VERY SIMPLE WHITELISTING POLICY
    final ImmutableSet<String> okTags = ImmutableSet.of(
        "a", "b", "br", "div", "i", "img", "input", "li",
        "ol", "p", "span", "ul");
    final ImmutableSet<String> okAttrs = ImmutableSet.of(
        "div", "checked", "class", "href", "id", "target", "title", "type");

    HtmlSanitizer.Policy policy = new HtmlSanitizer.Policy() {

      int ignoreDepth = 0;

      @Override
      public void openDocument() {
        renderer.openDocument();
      }

      @Override
      public void closeDocument() {
        renderer.closeDocument();
      }

      @Override
      public void text(String textChunk) {
        if (ignoreDepth == 0) { renderer.text(textChunk); }
      }

      @Override
      public void openTag(String elementName, List<String> attrs) {
        if (okTags.contains(elementName)) {
          for (ListIterator<String> it = attrs.listIterator();
               it.hasNext();) {
            String attrName = it.next();
            if (okAttrs.contains(attrName)) {
              String value = it.next();
              if ("id".equals(attrName) || "class".equals(attrName)) {
                it.set(value.replaceAll("(?:^|\\s)([a-zA-Z])", " p-$1")
                       .replaceAll("\\s+", " ")
                       .trim());
              }
            } else {
              it.remove();
              it.next();
              it.remove();
            }
          }
          renderer.openTag(elementName, attrs);
        } else if (ignoreContents(elementName)) {
          ++ignoreDepth;
        }
      }

      @Override
      public void closeTag(String elementName) {
        if (okTags.contains(elementName)) {
          renderer.closeTag(elementName);
        } else if (ignoreContents(elementName)) {
          --ignoreDepth;
        }
      }

      private boolean ignoreContents(String unsafeElementName) {
        return !("body".equals(unsafeElementName)
                 || "html".equals(unsafeElementName)
                 || "head".equals(unsafeElementName));
      }
    };

    new HtmlSanitizer().sanitize(html, policy);

    return sb.toString();
  }

}
