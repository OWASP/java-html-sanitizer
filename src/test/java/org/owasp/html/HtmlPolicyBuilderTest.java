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
import java.util.Locale;

import org.junit.Test;

import com.google.common.base.Joiner;

import junit.framework.TestCase;

@SuppressWarnings("javadoc")
public class HtmlPolicyBuilderTest extends TestCase {

  static final String EXAMPLE = Joiner.on('\n').join(
      "<h1 id='foo'>Header</h1>",
      "<p onclick='alert(42)'>Paragraph 1<script>evil()</script></p>",
      ("<p><a href='java\0script:bad()'>Click</a> <a href='foo.html'>me</a>"
       + " <a href='http://outside.org/'>out</a></p>"),
      ("<p><img src=canary.png alt=local-canary>" +
       "<img src='http://canaries.org/canary.png'></p>"),
      "<p><b style=font-size:bigger>Fancy</b> with <i><b>soupy</i> tags</b>.",
      "<p style='color: expression(foo()); text-align: center;",
      "          /* direction: ltr */; font-weight: bold'>Stylish Para 1</p>",
      "<p style='color: red; font-weight; expression(foo());",
      "          direction: rtl; font-weight: bold'>Stylish Para 2</p>",
      "");

  @Test
  public static final void testTextFilter() {
    assertEquals(
        Joiner.on('\n').join(
            "Header",
            "Paragraph 1",
            "Click me out",
            "",
            "Fancy with soupy tags.",
            "Stylish Para 1",
            "Stylish Para 2",
            ""),
        apply(new HtmlPolicyBuilder()));
  }

  @Test
  public static final void testCannedFormattingTagFilter() {
    assertEquals(
        Joiner.on('\n').join(
            "Header",
            "Paragraph 1",
            "Click me out",
            "",
            "<b>Fancy</b> with <i><b>soupy</b></i><b> tags</b>.",
            "Stylish Para 1",
            "Stylish Para 2",
            ""),
        apply(new HtmlPolicyBuilder()
              .allowCommonInlineFormattingElements()));
  }

  @Test
  public static final void testCannedFormattingTagFilterNoItalics() {
    assertEquals(
        Joiner.on('\n').join(
            "Header",
            "Paragraph 1",
            "Click me out",
            "",
            "<b>Fancy</b> with <b>soupy</b><b> tags</b>.",
            "Stylish Para 1",
            "Stylish Para 2",
            ""),
        apply(new HtmlPolicyBuilder()
              .allowCommonInlineFormattingElements()
              .disallowElements("I")));
  }

  @Test
  public static final void testSimpleTagFilter() {
    assertEquals(
        Joiner.on('\n').join(
            "<h1>Header</h1>",
            "Paragraph 1",
            "Click me out",
            "",
            "Fancy with <i>soupy</i> tags.",
            "Stylish Para 1",
            "Stylish Para 2",
            ""),
        apply(new HtmlPolicyBuilder()
              .allowElements("h1", "i")));
  }

  @Test
  public static final void testLinksAllowed() {
    assertEquals(
        Joiner.on('\n').join(
            "Header",
            "Paragraph 1",
            // We haven't allowed any protocols so only relative URLs are OK.
            "Click <a href=\"foo.html\">me</a> out",
            "",
            "Fancy with soupy tags.",
            "Stylish Para 1",
            "Stylish Para 2",
            ""),
        apply(new HtmlPolicyBuilder()
              .allowElements("a")
              .allowAttributes("href").onElements("a")));
  }

  @Test
  public static final void testExternalLinksAllowed() {
    assertEquals(
        Joiner.on('\n').join(
            "Header",
            "Paragraph 1",
            "Click <a href=\"foo.html\">me</a>"
            + " <a href=\"http://outside.org/\">out</a>",
            "",
            "Fancy with soupy tags.",
            "Stylish Para 1",
            "Stylish Para 2",
            ""),
        apply(new HtmlPolicyBuilder()
              .allowElements("a")
              // Allows http.
              .allowStandardUrlProtocols()
              .allowAttributes("href").onElements("a")));
  }

  @Test
  public static final void testLinksWithNofollow() {
    assertEquals(
        Joiner.on('\n').join(
            "Header",
            "Paragraph 1",
            "Click <a href=\"foo.html\" rel=\"nofollow\">me</a> out",
            "",
            "Fancy with soupy tags.",
            "Stylish Para 1",
            "Stylish Para 2",
            ""),
        apply(new HtmlPolicyBuilder()
              .allowElements("a")
              // Allows http.
              .allowAttributes("href").onElements("a")
              .requireRelNofollowOnLinks()));
  }

  @Test
  public static final void testImagesAllowed() {
    assertEquals(
        Joiner.on('\n').join(
            "Header",
            "Paragraph 1",
            "Click me out",
            "<img src=\"canary.png\" alt=\"local-canary\" />",
            // HTTP img not output because only HTTPS allowed.
            "Fancy with soupy tags.",
            "Stylish Para 1",
            "Stylish Para 2",
            ""),
        apply(new HtmlPolicyBuilder()
              .allowElements("img")
              .allowAttributes("src", "alt").onElements("img")
              .allowUrlProtocols("https")));
  }

  @Test
  public static final void testStyleFiltering() {
    assertEquals(
        Joiner.on('\n').join(
            "<h1>Header</h1>",
            "<p>Paragraph 1</p>",
            "<p>Click me out</p>",
            "<p></p>",
            "<p><b>Fancy</b> with <i><b>soupy</b></i><b> tags</b>.",
            ("</p><p style=\"text-align:center;font-weight:bold\">"
             + "Stylish Para 1</p>"),
            ("<p style=\"color:red;direction:rtl;font-weight:bold\">"
             + "Stylish Para 2</p>"),
            ""),
        apply(new HtmlPolicyBuilder()
              .allowCommonInlineFormattingElements()
              .allowCommonBlockElements()
              .allowStyling()
              .allowStandardUrlProtocols()));
  }

  @Test
  public static final void testElementTransforming() {
    assertEquals(
        Joiner.on('\n').join(
            "<div class=\"header-h1\">Header</div>",
            "<p>Paragraph 1</p>",
            "<p>Click me out</p>",
            "<p></p>",
            "<p>Fancy with soupy tags.",
            "</p><p>Stylish Para 1</p>",
            "<p>Stylish Para 2</p>",
            ""),
        apply(new HtmlPolicyBuilder()
              .allowElements("h1", "p", "div")
              .allowElements(
                  new ElementPolicy() {
                    public String apply(
                        String elementName, List<String> attrs) {
                      attrs.add("class");
                      attrs.add("header-" + elementName);
                      return "div";
                    }
                  }, "h1")));
  }

  @Test
  public static final void testAllowUrlProtocols() {
    assertEquals(
        Joiner.on('\n').join(
            "Header",
            "Paragraph 1",
            "Click me out",
            "<img src=\"canary.png\" alt=\"local-canary\" />"
            + "<img src=\"http://canaries.org/canary.png\" />",
            "Fancy with soupy tags.",
            "Stylish Para 1",
            "Stylish Para 2",
            ""),
            apply(new HtmlPolicyBuilder()
            .allowElements("img")
            .allowAttributes("src", "alt").onElements("img")
            .allowUrlProtocols("http")));
  }

  @Test
  public static final void testPossibleFalloutFromIssue5() {
    assertEquals(
        "Bad",
        apply(
            new HtmlPolicyBuilder()
            .allowElements("a")
            .allowAttributes("href").onElements("a")
            .allowUrlProtocols("http"),

            "<a href='javascript:alert(1337)//:http'>Bad</a>"));
  }

  @Test
  public static final void testTextInOption() {
    assertEquals(
        "<select><option>1</option><option>2</option></select>",
        apply(
            new HtmlPolicyBuilder()
            .allowElements("select", "option"),

            "<select>\n  <option>1</option>\n  <option>2</option>\n</select>"));
  }

  @Test
  public static final void testEntities() {
    assertEquals(
        "(Foo)\u00a0(Bar)\u2666\u2666\u2666\u2666(Baz)"
        + "&#x14834;&#x14834;&#x14834;(Boo)",
        apply(
            new HtmlPolicyBuilder(),
            "(Foo)&nbsp;(Bar)&diams;&#9830;&#x2666;&#X2666;(Baz)"
            + "\ud812\udc34&#x14834;&#x014834;(Boo)"));
  }

  @Test
  public static final void testImageTag() {
    assertEquals(
        ""
        + "<img src=\"http://example.com/foo.png\" />"
        + "<img src=\"http://example.com/bar.png\" />"
        + "<img />",  // OK if this isn't here too.

        apply(
            new HtmlPolicyBuilder()
            .allowElements("img")
            .allowElements(
                new ElementPolicy() {

                  public String apply(String elementName, List<String> attrs) {
                    return "img";
                  }

                }, "image")
            .allowAttributes("src").onElements("img", "image")
            .allowStandardUrlProtocols(),
            ""
            + "<image src=\"http://example.com/foo.png\" />"
            + "<Image src=\"http://example.com/bar.png\">"
            + "<IMAGE>"));
  }

  @Test
  public static final void testDuplicateAttributesDoNotReachElementPolicy() {
    final int[] idCount = new int[1];
    assertEquals(
        // The id that is emitted is the first that passes the attribute
        // starts-with-b filter.
        // The attribute policy sees 3 id elements, hence id-count=3.
        // The element policy sees 2 attributes, one "id" and one "href",
        // hence attr-count=2.
        "<a href=\"foo\" id=\"bar\" attr-count=\"2\" id-count=\"3\">link</a>",

        apply(
            new HtmlPolicyBuilder()
            .allowElements(
                new ElementPolicy() {
                  public String apply(String elementName, List<String> attrs) {
                    int nAttrs = attrs.size() / 2;
                    attrs.add("attr-count");
                    attrs.add("" + nAttrs);
                    attrs.add("id-count");
                    attrs.add("" + idCount[0]);
                    return elementName;
                  }
                },
                "a"
            )
            .allowAttributes("id").matching(new AttributePolicy() {
              public String apply(
                  String elementName, String attributeName, String value) {
                ++idCount[0];
                return value.startsWith("b") ? value : null;
              }
            }).onElements("a")
            .allowAttributes("href").onElements("a"),
            "<a href=\"foo\" id='far' id=\"bar\" href=baz id=boo>link</a>")
        );
  }

  @Test
  public static final void testPreprocessors() {
    String input =
        "<h1 title='foo'>one</h1> <h2>Two!</h2> <h3>three</h3>"
        + " <h4>Four</h4> <h5>5</h5> <h6>seis</h6>";
    // We upper-case all text nodes and increment all header elements.
    // Since h7 is not white-listed, the incremented version of <h6> is dropped.
    // The title attribute value is not upper-cased.
    String expected =
        "<h2 title=\"foo\">ONE</h2> <h3>TWO!</h3> <h4>THREE</h4>"
        + " <h5>FOUR</h5> <h6>5</h6> SEIS";
    assertEquals(
        expected,

        apply(
            new HtmlPolicyBuilder()
            .allowElements("h1", "h2", "h3", "h4", "h5", "h6")
            .allowAttributes("title").globally()
            .withPreprocessor(new HtmlStreamEventProcessor() {
              public HtmlStreamEventReceiver wrap(HtmlStreamEventReceiver r) {
                return new HtmlStreamEventReceiverWrapper(r) {
                  @Override
                  public void text(String s) {
                    underlying.text(s.toUpperCase(Locale.ROOT));
                  }
                  @Override
                  public String toString() {
                    return "shouty-text";
                  }
                };
              }
            })
            .withPreprocessor(new HtmlStreamEventProcessor() {
              public HtmlStreamEventReceiver wrap(HtmlStreamEventReceiver r) {
                return new HtmlStreamEventReceiverWrapper(r) {
                  @Override
                  public void openTag(String elementName, List<String> attrs) {
                    underlying.openTag(incr(elementName), attrs);
                  }

                  @Override
                  public void closeTag(String elementName) {
                    underlying.closeTag(incr(elementName));
                  }

                  String incr(String en) {
                    if (en.length() == 2) {
                      char c0 = en.charAt(0);
                      char c1 = en.charAt(1);
                      if ((c0 == 'h' || c0 == 'H')
                          && '0' <= c1 && c1 <= '6') {
                        // h1 -> h2, h2 -> h3, etc.
                        return "h" + (c1 - '0' + 1);
                      }
                    }
                    return en;
                  }

                  @Override
                  public String toString() {
                    return "incr-headers";
                  }
                };
              }
            }),

            input));
  }


  @Test
  public static final void testPostprocessors() {
    String input =
        "<h1 title='foo'>one</h1> <h2>TWO!</h2> <h3>three</h3>"
        + " <h4>Four</h4> <h5>5</h5> <h6>seis</h6>";
    // We upper-case the first letter of each text nodes and increment all
    // header elements.
    // Since post-processors run after the policy, they can insert elements like
    // <h7> which are not white-listed.
    String expected =
        "<h2 title=\"foo\">One</h2> <h3>TWO!</h3> <h4>Three</h4>"
        + " <h5>Four</h5> <h6>5</h6> <h7>Seis</h7>";
    assertEquals(
        expected,

        apply(
            new HtmlPolicyBuilder()
            .allowElements("h1", "h2", "h3", "h4", "h5", "h6")
            .allowAttributes("title").globally()
            .withPostprocessor(new HtmlStreamEventProcessor() {
              public HtmlStreamEventReceiver wrap(HtmlStreamEventReceiver r) {
                return new HtmlStreamEventReceiverWrapper(r) {
                  @Override
                  public void text(String s) {
                    if (!s.isEmpty()) {
                      int cp0 = s.codePointAt(0);
                      underlying.text(
                          new StringBuilder(s.length())
                          .appendCodePoint(Character.toUpperCase(cp0))
                          .append(s, Character.charCount(cp0), s.length())
                          .toString());
                    }
                  }
                  @Override
                  public String toString() {
                    return "shouty-text";
                  }
                };
              }
            })
            .withPostprocessor(new HtmlStreamEventProcessor() {
              public HtmlStreamEventReceiver wrap(HtmlStreamEventReceiver r) {
                return new HtmlStreamEventReceiverWrapper(r) {
                  @Override
                  public void openTag(String elementName, List<String> attrs) {
                    underlying.openTag(incr(elementName), attrs);
                  }

                  @Override
                  public void closeTag(String elementName) {
                    underlying.closeTag(incr(elementName));
                  }

                  String incr(String en) {
                    if (en.length() == 2) {
                      char c0 = en.charAt(0);
                      char c1 = en.charAt(1);
                      if ((c0 == 'h' || c0 == 'H')
                          && '0' <= c1 && c1 <= '6') {
                        // h1 -> h2, h2 -> h3, etc.
                        return "h" + (c1 - '0' + 1);
                      }
                    }
                    return en;
                  }

                  @Override
                  public String toString() {
                    return "incr-headers";
                  }
                };
              }
            }),

            input));

  }

  @Test
  public static final void testBackgroundImageWithUrl() {
    PolicyFactory policy = new HtmlPolicyBuilder()
        .allowStandardUrlProtocols()
        .allowStyling()
        .allowUrlsInStyles(AttributePolicy.IDENTITY_ATTRIBUTE_POLICY)
        .allowElements("div")
        .toFactory();
    String unsafeHtml = policy.sanitize(
        "<html><head><title>test</title></head><body>" +
        "<div style='"
        + "color: red; background-image: "
        + "url(http://example.com/foo.png)" +
        "'>div content" +
        "</div></body></html>");
    String safeHtml = policy.sanitize(unsafeHtml);
    String expected =
        "<div style=\""
        + "color:red;background-image:"
        + "url(&#39;http://example.com/foo.png&#39;)"
        + "\">div content</div>";
    assertEquals(expected, safeHtml);
  }

  @Test
  public static final void testBackgroundImageWithImageFunction() {
    PolicyFactory policy = new HtmlPolicyBuilder()
        .allowStandardUrlProtocols()
        .allowStyling()
        .allowUrlsInStyles(AttributePolicy.IDENTITY_ATTRIBUTE_POLICY)
        .allowElements("div")
        .toFactory();
    String unsafeHtml = policy.sanitize(
        "<html><head><title>test</title></head><body>" +
        "<div style='" +
        "color: red; background-image: " +
        "image(\"blue sky.png\", blue)'>" +
        "div content" +
        "</div></body></html>");
    String safeHtml = policy.sanitize(unsafeHtml);
    String expected =
        "<div style=\""
        + "color:red;background-image:"
        + "image( url(&#39;blue%20sky.png&#39;) , blue )"
        + "\">div content</div>";
    assertEquals(expected, safeHtml);
  }

  @Test
  public static final void testBackgroundWithUrls() {
    HtmlPolicyBuilder builder = new HtmlPolicyBuilder()
        .allowStandardUrlProtocols()
        .allowStyling()
        .allowElements("div");

    PolicyFactory noUrlsPolicy = builder.toFactory();
    PolicyFactory urlsPolicy = builder
        .allowUrlsInStyles(AttributePolicy.IDENTITY_ATTRIBUTE_POLICY)
        .toFactory();

    String unsafeHtml =
        "<div style=\"background:&quot;//evil.org/foo.png&quot;\"></div>";

    String safeWithUrls =
        "<div style=\"background:url(&#39;//evil.org/foo.png&#39;)\"></div>";
    String safeWithoutUrls = "<div></div>";

    assertEquals(safeWithoutUrls, noUrlsPolicy.sanitize(unsafeHtml));
    assertEquals(safeWithUrls, urlsPolicy.sanitize(unsafeHtml));
  }

  @Test
  public static final void testBackgroundsThatViolateGlobalUrlPolicy() {
    PolicyFactory policy = new HtmlPolicyBuilder()
        .allowStandardUrlProtocols()
        .allowStyling()
        .allowElements("div")
        .allowUrlsInStyles(AttributePolicy.IDENTITY_ATTRIBUTE_POLICY)
        .toFactory();

    String unsafeHtml =
        "<div style=\"background:'javascript:alert(1337)'\"></div>";
    String safeHtml = "<div></div>";

    assertEquals(safeHtml, policy.sanitize(unsafeHtml));

  }

  @Test
  public static final void testSpanTagFilter() {
    PolicyFactory policy = new HtmlPolicyBuilder()
        .allowElements("span")
        .allowWithoutAttributes("span")
        .toFactory();
    String unsafeHtml = policy.sanitize(
        "<span>test1</span>");
    String safeHtml = policy.sanitize(unsafeHtml);
    String expected =
        "<span>test1</span>";
    assertEquals(expected, safeHtml);
  }

  @Test
  public static final void testLinkRels() {
    HtmlPolicyBuilder b = new HtmlPolicyBuilder()
        .allowElements("a")
        .allowAttributes("href").onElements("a")
        .allowAttributes("rel").onElements("a")
        .allowAttributes("target").onElements("a")
        .allowStandardUrlProtocols();

    PolicyFactory defaultLinkPolicy = b.toFactory();
    PolicyFactory externalLinkPolicy = b
        .requireRelsOnLinks("external")
        .toFactory();
    PolicyFactory noNoFollowPolicy = new HtmlPolicyBuilder()
        .allowElements("a")
        .allowAttributes("href").onElements("a")
        //.allowAttributes("rel").onElements("a")
        .allowStandardUrlProtocols()
        .allowAttributes("target").onElements("a")
        .skipRelsOnLinks("noreferrer")
        .toFactory();

    PolicyFactory and0 = externalLinkPolicy.and(noNoFollowPolicy);
    PolicyFactory and1 = noNoFollowPolicy.and(externalLinkPolicy);

    String link = "<a target=T href=http://example.com/>eg</a>";

    assertEquals(
        "<a target=\"T\" href=\"http://example.com/\""
        + " rel=\"noopener noreferrer\">eg</a>",
        defaultLinkPolicy.sanitize(link));
    assertEquals(
        "<a target=\"T\" href=\"http://example.com/\""
        + " rel=\"external noopener noreferrer\">eg</a>",
        externalLinkPolicy.sanitize(link));
    assertEquals(
        "<a target=\"T\" href=\"http://example.com/\""
        + " rel=\"noopener\">eg</a>",
        noNoFollowPolicy.sanitize(link));
    assertEquals(
        "<a target=\"T\" href=\"http://example.com/\""
        + " rel=\"external noopener\">eg</a>",
        and0.sanitize(link));
    assertEquals(
        "<a target=\"T\" href=\"http://example.com/\""
        + " rel=\"external noopener\">eg</a>",
        and1.sanitize(link));
  }

  @Test
  public static final void testLinkRelsWhenRelPresent() {
    PolicyFactory pf = new HtmlPolicyBuilder()
        .allowElements("a")
        .allowAttributes("href").onElements("a")
        .allowAttributes("rel").onElements("a")
        .allowAttributes("target").onElements("a")
        .allowStandardUrlProtocols()
        .requireRelNofollowOnLinks()
        .toFactory();

    assertEquals(
        ""
        + "<a rel=\"external nofollow noopener noreferrer\""
        + " target=\"_blank\" href=\"http://example.com/\">eg</a>",

        pf.sanitize(
            "<a rel=external target=_blank href=http://example.com/>eg</a>"));

    assertEquals(
        ""
        + "<a rel=\"external nofollow noopener noreferrer\""
        + " target=\"windowname\" href=\"//example.com/\">eg</a>",

        pf.sanitize(
            "<A REL=external TARGET=windowname HREF=//example.com/ >eg</A>"
            ));
  }

  @Test
  public static final void testFailFastOnSpaceSeparatedStrings() {
    boolean failed;
    try {
      // Should be ("nofollow", "noreferrer")
      new HtmlPolicyBuilder().requireRelsOnLinks("nofollow noreferrer");
      failed = false;
    } catch (@SuppressWarnings("unused") IllegalArgumentException ex) {
      failed = true;
    }
    assertTrue(failed);
    try {
      new HtmlPolicyBuilder().skipRelsOnLinks("nofollow noreferrer");
      failed = false;
    } catch (@SuppressWarnings("unused") IllegalArgumentException ex) {
      failed = true;
    }
    assertTrue(failed);
  }

  @Test
  public static final void testScopingExitInNoContent() {
    PolicyFactory pf = new HtmlPolicyBuilder()
        .allowElements("table", "tr", "td", "noscript")
        .toFactory();

    assertEquals(
        "<table><tr><td>foo<noscript></noscript></td><td>bar</td></tr></table>",
        pf.sanitize("<table><tr><td>foo<noscript></table></noscript><td>bar"));

  }

  @Test
  public static final void testIssue80() {
    PolicyFactory pf = new HtmlPolicyBuilder()
        .allowElements("table", "tr", "td", "tbody")
        .toFactory();

    assertEquals(
        "<table><tbody>"
        + "<tr><td>td1</td><td>td2</td></tr>"
        + "<tr><td>new line</td></tr>"
        + "</tbody></table>",
        pf.sanitize(
            "<table><tbody>"
            + "<tr><td>td1</td><td>td2</tr>"
            + "<td>new line</tbody></table>"));
  }

  private static String apply(HtmlPolicyBuilder b) {
    return apply(b, EXAMPLE);
  }

  private static String apply(HtmlPolicyBuilder b, String src) {
    return b.toFactory().sanitize(
        src, null,
        new Handler<String>() {
          public void handle(String x) { fail(x); }
        });
  }
}
