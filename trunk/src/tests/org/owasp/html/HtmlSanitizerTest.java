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

import junit.framework.TestCase;

import javax.annotation.Nullable;


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
        "\\\\u000a",
        HtmlSanitizer.decodeHtml("\\\\u000a"));
    assertEquals(
        "\n",
        HtmlSanitizer.decodeHtml("&#x000a;"));
    assertEquals(
        "\n",
        HtmlSanitizer.decodeHtml("&#x00a;"));
    assertEquals(
        "\n",
        HtmlSanitizer.decodeHtml("&#x0a;"));
    assertEquals(
        "\n",
        HtmlSanitizer.decodeHtml("&#xa;"));
    assertEquals(
        HtmlSanitizer.decodeHtml("&#x10000;"),
        String.valueOf(Character.toChars(0x10000)));
    assertEquals(
        "\n",
        HtmlSanitizer.decodeHtml("&#xa"));
    assertEquals(
        "&#x00ziggy",
        HtmlSanitizer.decodeHtml("&#x00ziggy"));
    assertEquals(
        "&#xa00z;",
        HtmlSanitizer.decodeHtml("&#xa00z;"));
    assertEquals(
        "&#\n",
        HtmlSanitizer.decodeHtml("&#&#x000a;"));
    assertEquals(
        "&#x\n",
        HtmlSanitizer.decodeHtml("&#x&#x000a;"));
    assertEquals(
        "\n\n",
        HtmlSanitizer.decodeHtml("&#xa&#x000a;"));
    assertEquals(
        "&#\n",
        HtmlSanitizer.decodeHtml("&#&#xa;"));
    assertEquals(
        "&#x",
        HtmlSanitizer.decodeHtml("&#x"));
    assertEquals(
        "\u0000",
        HtmlSanitizer.decodeHtml("&#x0"));
    assertEquals(
        "&#",
        HtmlSanitizer.decodeHtml("&#"));

    assertEquals(
        "\\",
        HtmlSanitizer.decodeHtml("\\"));
    assertEquals(
        "&",
        HtmlSanitizer.decodeHtml("&"));

    assertEquals(
        "&#000a;",
        HtmlSanitizer.decodeHtml("&#000a;"));
    assertEquals(
        "\n",
        HtmlSanitizer.decodeHtml("&#10;"));
    assertEquals(
        "\n",
        HtmlSanitizer.decodeHtml("&#010;"));
    assertEquals(
        "\n",
        HtmlSanitizer.decodeHtml("&#0010;"));
    assertEquals(
        "\t",
        HtmlSanitizer.decodeHtml("&#9;"));
    assertEquals(
        "\n",
        HtmlSanitizer.decodeHtml("&#10"));
    assertEquals(
        "&#00ziggy",
        HtmlSanitizer.decodeHtml("&#00ziggy"));
    assertEquals(
        "&#\n",
        HtmlSanitizer.decodeHtml("&#&#010;"));
    assertEquals(
        "\u0000\n",
        HtmlSanitizer.decodeHtml("&#0&#010;"));
    assertEquals(
        "\u0001\n",
        HtmlSanitizer.decodeHtml("&#01&#10;"));
    assertEquals(
        "&#\n",
        HtmlSanitizer.decodeHtml("&#&#10;"));
    assertEquals(
        "\u0001",
        HtmlSanitizer.decodeHtml("&#1"));
    assertEquals(
        "\n",
        HtmlSanitizer.decodeHtml("&#10"));

    // test the named escapes
    assertEquals(
        "<",
        HtmlSanitizer.decodeHtml("&lt;"));
    assertEquals(
        ">",
        HtmlSanitizer.decodeHtml("&gt;"));
    assertEquals(
        "\"",
        HtmlSanitizer.decodeHtml("&quot;"));
    assertEquals(
        "'",
        HtmlSanitizer.decodeHtml("&apos;"));
    assertEquals(
        "'",
        HtmlSanitizer.decodeHtml("&#39;"));
    assertEquals(
        "'",
        HtmlSanitizer.decodeHtml("&#x27;"));
    assertEquals(
        "&",
        HtmlSanitizer.decodeHtml("&amp;"));
    assertEquals(
        "&lt;",
        HtmlSanitizer.decodeHtml("&amp;lt;"));
    assertEquals(
        "&",
        HtmlSanitizer.decodeHtml("&AMP;"));
    assertEquals(
        "&",
        HtmlSanitizer.decodeHtml("&AMP"));
    assertEquals(
        "&",
        HtmlSanitizer.decodeHtml("&AmP;"));
    assertEquals(
        "\u0391",
        HtmlSanitizer.decodeHtml("&Alpha;"));
    assertEquals(
        "\u03b1",
        HtmlSanitizer.decodeHtml("&alpha;"));


    assertEquals(
        "&;",
        HtmlSanitizer.decodeHtml("&;"));
    assertEquals(
        "&bogus;",
        HtmlSanitizer.decodeHtml("&bogus;"));
  }


  public final void testEmpty() throws Exception {
    assertEquals("", sanitize(""));
    assertEquals("", sanitize(null));
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
    assertEquals(
        "<b>hello <i>world</i></b>",
        sanitize("<b>hello <i onclick=\"takeOverWorld(this)\">world</i></b>"));
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
        "<b id=\"p-foo\" class=\"p-boo p-bar p-baz\">"
        + "hello <i>world&lt;</i></b>",
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
            "</meta http-equiv=\"refesh\""
            + " content=\"1;URL=http://evilgadget.com\">"));
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
            + "<p>One"
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
    assertEquals(
        "<a title="
        + "\"harmless  SCRIPT&#61;javascript:alert(1) ignored&#61;ignored\">"
        + "</a>",
        sanitize(
            "<A TITLE="
            + "\"harmless\0  SCRIPT=javascript:alert(1) ignored=ignored\">"
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

  public final void testSupplementaryCodepointEncoding() throws Exception {
    // &#xd87e;&#xdc1a; is not appropriate.
    // &#x2f81a; is appropriate as is the unencoded form.
    assertEquals(
        "&#x2f81a; | &#x2f81a; | &#x2f81a;",
        sanitize("&#x2F81A; | \ud87e\udc1a | &#xd87e;&#xdc1a;"));
  }

  public final void testDeeplyNestedTagsDoS() throws Exception {
    String sanitized = sanitize(stringRepeatedTimes("<div>", 20000));
    int n = sanitized.length() / "<div></div>".length();
    assertTrue("" + n, 50 <= n && n <= 1000);
    int middle = n * "<div>".length();
    assertEquals(sanitized.substring(0, middle),
                 stringRepeatedTimes("<div>", n));
    assertEquals(sanitized.substring(middle),
                 stringRepeatedTimes("</div>", n));
  }

  public final void testInnerHTMLIE8() throws Exception {
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

  public final void testNabobsOfNegativism() throws Exception {
    // Treating <noscript> as raw-text gains us nothing security-wise.
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

  public final void testNULs() throws Exception {
    assertEquals("<b>Hello, </b>", sanitize("<b>Hello, \u0000</b>"));
    assertEquals("<b>Hello, </b>", sanitize("<b>Hello, \u0000"));
    assertEquals("",               sanitize("\u0000"));
    assertEquals("<b>Hello, </b>", sanitize("<b>Hello, &#0;</b>"));
    assertEquals("",               sanitize("&#0;"));
  }

  public final void testQMarkMeta() throws Exception {
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

  private static String sanitize(@Nullable String html) throws Exception {
    StringBuilder sb = new StringBuilder();
    HtmlStreamRenderer renderer = HtmlStreamRenderer.create(
        sb,
        new Handler<String>() {
          public void handle(String errorMessage) {
            fail(errorMessage);
          }
        });

    HtmlSanitizer.Policy policy = new HtmlPolicyBuilder()
        // Allow these tags.
       .allowElements(
           "a", "b", "br", "div", "i", "img", "input", "li",
           "ol", "p", "span", "ul", "noscript", "noframes", "noembed", "noxss")
       // And these attributes.
       .allowAttributes(
           "dir", "checked", "class", "href", "id", "target", "title", "type")
       .globally()
       // Cleanup IDs and CLASSes and prefix them with p- to move to a separate
       // name-space.
       .allowAttributes("id", "class")
       .matching(
           new AttributePolicy() {
            public String apply(
                String elementName, String attributeName, String value) {
              return value.replaceAll("(?:^|\\s)([a-zA-Z])", " p-$1")
                  .replaceAll("\\s+", " ")
                  .trim();
            }
           })
       .globally()
       // Don't throw out useless <img> and <input> elements to ease debugging.
       .allowWithoutAttributes("img", "input")
       .build(renderer);

    HtmlSanitizer.sanitize(html, policy);

    return sb.toString();
  }

  private static final String stringRepeatedTimes(String s, int n) {
    StringBuilder sb = new StringBuilder(s.length() * n);
    while (--n >= 0) {
      sb.append(s);
    }
    return sb.toString();
  }
}
