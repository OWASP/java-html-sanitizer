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

import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Predicate;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;
import static org.owasp.shim.Java8Shim.j8;

@SuppressWarnings({"HttpUrlsUsage", "RedundantSuppression", "UnnecessaryUnicodeEscape"})
class HtmlPolicyBuilderTest {

  static final String EXAMPLE = String.join(
      "\n",
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

  /**
   * allowAttributes("style").globally() installs a default schema so that
   * styling is sanitized at all, but it must not overrule a schema the caller
   * named -- in either order.  Unioning silently handed back CssSchema.DEFAULT
   * to a caller who asked for something narrower.
   */
  @Test
  void testGloballyDoesNotWidenAnExplicitStylingSchema() {
    CssSchema colorOnly = CssSchema.withProperties(Arrays.asList("color"));
    String css = "color:red;font-weight:bold;width:10px";

    PolicyFactory globallyFirst = new HtmlPolicyBuilder()
        .allowElements("div")
        .allowAttributes("style").globally()
        .allowStyling(colorOnly)
        .toFactory();
    assertEquals(
        "<div style=\"color:red\">x</div>",
        globallyFirst.sanitize("<div style=\"" + css + "\">x</div>"));

    PolicyFactory stylingFirst = new HtmlPolicyBuilder()
        .allowElements("div")
        .allowStyling(colorOnly)
        .allowAttributes("style").globally()
        .toFactory();
    assertEquals(
        "<div style=\"color:red\">x</div>",
        stylingFirst.sanitize("<div style=\"" + css + "\">x</div>"));
  }

  /** With no explicit schema, allowing style globally still sanitizes it. */
  @Test
  void testGloballyStillInstallsADefaultStylingSchema() {
    PolicyFactory p = new HtmlPolicyBuilder()
        .allowElements("div")
        .allowAttributes("style").globally()
        .toFactory();
    assertEquals(
        "<div style=\"color:red\">x</div>",
        p.sanitize("<div style=\"color:red;position:fixed\">x</div>"));
  }

  /** Two explicit schemas still combine, which is the documented behaviour. */
  @Test
  void testTwoExplicitStylingSchemasStillUnion() {
    PolicyFactory p = new HtmlPolicyBuilder()
        .allowElements("div")
        .allowAttributes("style").onElements("div")
        .allowStyling(CssSchema.withProperties(Arrays.asList("color")))
        .allowStyling(CssSchema.withProperties(Arrays.asList("font-weight")))
        .toFactory();
    assertEquals(
        "<div style=\"color:red;font-weight:bold\">x</div>",
        p.sanitize("<div style=\"color:red;font-weight:bold;width:10px\">x</div>"));
  }

  @Test
  void testTextFilter() {
    assertEquals(
        String.join(
            "\n",

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
  void testCannedFormattingTagFilter() {
    assertEquals(
        String.join(
            "\n",
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
  void testCannedFormattingTagFilterNoItalics() {
    assertEquals(
        String.join(
            "\n",
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
  void testSimpleTagFilter() {
    assertEquals(
        String.join(
            "\n",
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
  void testLinksAllowed() {
    assertEquals(
        String.join(
            "\n",
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
  void testExternalLinksAllowed() {
    assertEquals(
        String.join(
            "\n",
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
  void testLinksWithNofollow() {
    assertEquals(
        String.join(
            "\n",
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
  void testLinksWithNofollowAlreadyPresent() {
    assertEquals(
        "html <a href=\"/\" rel=\"nofollow\">link</a>",
        apply(
            new HtmlPolicyBuilder()
              .allowElements("a")
              .allowAttributes("href").onElements("a")
              .requireRelNofollowOnLinks(),
            "html <a href='/' rel='nofollow'>link</a>"));
  }

  @Test
  void testImagesAllowed() {
    assertEquals(
        String.join(
            "\n",
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
  void testStyleFiltering() {
    assertEquals(
        String.join(
            "\n",
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
  void testSpecificStyleFilterung() {
    assertEquals(
        String.join(
            "\n",
            "<h1>Header</h1>",
            "<p>Paragraph 1</p>",
            "<p>Click me out</p>",
            "<p></p>",
            "<p><b>Fancy</b> with <i><b>soupy</b></i><b> tags</b>.",
            "</p><p style=\"text-align:center\">Stylish Para 1</p>",
            "<p style=\"color:red\">Stylish Para 2</p>",
            ""),
        apply(new HtmlPolicyBuilder()
              .allowCommonInlineFormattingElements()
              .allowCommonBlockElements()
              .allowStyling(CssSchema.withProperties(
                  j8().listOf("color", "text-align", "font-size")))
              .allowStandardUrlProtocols()));
  }

  @Test
  void testCustomPropertyStyleFiltering() {
    assertEquals(
        String.join(
            "\n",
            "<h1>Header</h1>",
            "<p>Paragraph 1</p>",
            "<p>Click me out</p>",
            "<p></p>",
            "<p><b>Fancy</b> with <i><b>soupy</b></i><b> tags</b>.",
            "</p><p style=\"text-align:center\">Stylish Para 1</p>",
            "<p>Stylish Para 2</p>",
            ""),
        apply(new HtmlPolicyBuilder()
              .allowCommonInlineFormattingElements()
              .allowCommonBlockElements()
              .allowStyling(
                  CssSchema.withProperties(
                      j8().mapOfEntries(
                          j8().mapEntry("text-align",
                              new CssSchema.Property(0,
                                  j8().setOf("center"),
                                  j8().mapOfEntries())))))
              .allowStandardUrlProtocols()));
  }

  @Test
  void testUnionStyleFiltering() {
    assertEquals(
        String.join(
            "\n",
            "<h1>Header</h1>",
            "<p>Paragraph 1</p>",
            "<p>Click me out</p>",
            "<p></p>",
            "<p><b>Fancy</b> with <i><b>soupy</b></i><b> tags</b>.",
            "</p><p style=\"text-align:center\">Stylish Para 1</p>",
            "<p style=\"color:red\">Stylish Para 2</p>",
            ""),
        apply(new HtmlPolicyBuilder()
              .allowCommonInlineFormattingElements()
              .allowCommonBlockElements()
              .allowStyling(CssSchema.withProperties(
                  j8().listOf("color", "text-align")))
              .allowStyling( // union allowed style properties
                   CssSchema.withProperties(j8().listOf("font-size")))
              .allowStandardUrlProtocols()));
  }

  @Test
  void testCustomPropertyStyleFilteringDisallowed() {
    assertEquals(
        String.join(
            "\n",
            "<h1>Header</h1>",
            "<p>Paragraph 1</p>",
            "<p>Click me out</p>",
            "<p></p>",
            "<p><b>Fancy</b> with <i><b>soupy</b></i><b> tags</b>.",
            "</p><p>Stylish Para 1</p>",
            "<p>Stylish Para 2</p>",
            ""),
        apply(new HtmlPolicyBuilder()
              .allowCommonInlineFormattingElements()
              .allowCommonBlockElements()
              .allowStyling(
                      CssSchema.withProperties(
                          j8().mapOfEntries(
                              j8().mapEntry("text-align",
                                  new CssSchema.Property(0,
                                      j8().setOf("left", "right"),
                                      j8().mapOfEntries())))))
              .allowStandardUrlProtocols()));
  }

  @Test
  void testElementTransforming() {
    assertEquals(
        String.join(
            "\n",
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
                  (elementName, attrs) -> {
                    attrs.add("class");
                    attrs.add("header-" + elementName);
                    return "div";
                  },
                  "h1")));
  }

  @Test
  void testBodyTransforming() {
    assertEquals(
        "<div>foo</div>",
        apply(
            new HtmlPolicyBuilder()
            .allowElements(
                (elementName, attrs) -> "div",
                "body")
            .allowElements("div"),
            "<body>foo</body>"));
  }
  @Test
  void testAllowUrlProtocols() {
    assertEquals(
        String.join(
            "\n",
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
  void testDisallowUrlProtocols() {
    assertEquals(
        String.join(
            "\n",
            "Header",
            "Paragraph 1",
            "Click me out",
            "<img src=\"canary.png\" alt=\"local-canary\" />",
            "Fancy with soupy tags.",
            "Stylish Para 1",
            "Stylish Para 2",
            ""),
        apply(new HtmlPolicyBuilder()
            .allowElements("img")
            .allowAttributes("src", "alt").onElements("img")
            .allowUrlProtocols("http", "https")
            .disallowUrlProtocols("http")));
  }

  @Test
  void testPossibleFalloutFromIssue5() {
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
  void testTextInOption() {
    assertEquals(
        "<select><option>1</option><option>2</option></select>",
        apply(
            new HtmlPolicyBuilder()
            .allowElements("select", "option"),

            "<select>\n  <option>1</option>\n  <option>2</option>\n</select>"));
  }

  @Test
  void testEntities() {
    assertEquals(
        "(Foo)\u00a0(Bar)\u2666\u2666\u2666\u2666(Baz)"
        + "&#x14834;&#x14834;&#x14834;(Boo)",
        apply(
            new HtmlPolicyBuilder(),
            "(Foo)&nbsp;(Bar)&diams;&#9830;&#x2666;&#X2666;(Baz)"
            + "\ud812\udc34&#x14834;&#x014834;(Boo)"));
  }

  @Test
  void testImageTag() {
    assertEquals(
        ""
        + "<img src=\"http://example.com/foo.png\" />"
        + "<img src=\"http://example.com/bar.png\" />"
        + "<img />",  // OK if this isn't here too.

        apply(
            new HtmlPolicyBuilder()
            .allowElements("img")
            .allowElements((elementName, attrs) -> "img", "image")
            .allowAttributes("src").onElements("img", "image")
            .allowStandardUrlProtocols(),
            ""
            + "<image src=\"http://example.com/foo.png\" />"
            + "<Image src=\"http://example.com/bar.png\">"
            + "<IMAGE>"));
  }

  @Test
  void testImgSrcsetSyntax() {
    assertEquals(
        ""
        + "<img srcset=\"http://example.com/foo.png\" />\n"
        + "<img srcset=\"http://example.com/foo.png 640w\" />\n"
        + "<img srcset=\"http://example.com/foo.png 48x\" />\n"
        + "<img srcset=\"http://example.com/foo.png .123x\" />\n"
        + "<img srcset=\"http://example.com/foo.png .123e2x\" />\n"
        + "<img srcset=\"http://example.com/foo.png 123.456E-1x\" />\n"
        + "<img srcset=\"http://example.com/foo.png -123x\" />\n"
        + "no float: \n"
        + "no fraction: \n"
        + "no exponent: \n"
        + "<img srcset=\"/big.png 64w , /little.png\" />\n"
        + "<img srcset=\"/big.png 64w , /little.png\" />\n"
        + "<img srcset=\"/big.png 64w , /little.png\" />\n"
        + "<img srcset=\"foo%2cbar.png\" />\n"
        + "empty: \n"
        + "only space: \n"
        + "only comma: \n"
        + "comma at end: <img srcset=\"foo.png\" />\n"
        + "comma stuck to url: \n"
        + "commas inside: <img srcset=\"foo.png%2c%2cbar.png\" />\n"
        + "double commas 1: \n"
        + "double commas 2: \n"
        + "bad url: <img srcset=\"foo.png 1w\" />\n",

        apply(
            new HtmlPolicyBuilder()
            .allowElements("img")
            .allowAttributes("srcset").onElements("img")
            .allowStandardUrlProtocols(),
            ""
            + "<img srcset=\"http://example.com/foo.png\" />\n"
            + "<img srcset=\"http://example.com/foo.png 640w\" />\n"
            + "<img srcset=\"http://example.com/foo.png 48x\" />\n"
            + "<img srcset=\"http://example.com/foo.png .123x\" />\n"
            + "<img srcset=\"http://example.com/foo.png .123e2x\" />\n"
            + "<img srcset=\"http://example.com/foo.png 123.456E-1x\" />\n"
            + "<img srcset=\"http://example.com/foo.png -123x\" />\n"
            + "no float: <img srcset=\"http://example.com/foo.png -x\" />\n"
            + "no fraction: <img srcset=\"http://example.com/foo.png -.e1\" />\n"
            + "no exponent: <img srcset=\"http://example.com/foo.png -1e+x\" />\n"
            + "<img srcset=\"/big.png 64w, /little.png\" />\n"
            + "<img srcset=\" /big.png 64w , /little.png\" />\n"
            + "<img srcset=\"\t\t/big.png 64w\r\n,/little.png\t\t\" />\n"
            + "<img srcset=\"foo,bar.png\" />\n"
            + "empty: <img srcset=\"\" />\n"
            + "only space: <img srcset=\"  \" />\n"
            + "only comma: <img srcset=\",\" />\n"
            + "comma at end: <img srcset=\"foo.png ,\" />\n"  // ok
            + "comma stuck to url: <img srcset=\"bar.png,\" />\n"  // not ok
            + "commas inside: <img srcset=\"foo.png,,bar.png\" />\n"  // escaped
            + "double commas 1: <img srcset=\"a ,, b\" />\n"  // not ok
            + "double commas 2: <img srcset=\"a , , b\" />\n"  // not ok
            + "bad url: <img srcset=\"foo.png 1w, javascript:evil()\" />\n"
            ));
  }

  @Test
  void testUrlChecksLayer() {
    assertEquals(
        ""
        + "<img src=\"http://example.com/OK.png\" />\n"
        + "\n"
        + "<img srcset=\"http://example.com/bar.png#OK 1w\" />",

        apply(
            new HtmlPolicyBuilder()
            .allowElements("img")
            .allowAttributes("src", "srcset")
                .matching(Pattern.compile(".*OK.*"))
                .onElements("img")
            .allowStandardUrlProtocols(),
            ""
            + "<img src=\"http://example.com/OK.png\" />\n"
            + "<img src=\"http://example.com/\" />\n"
            + "<img srcset=\"http://example.com/bar.png#OK 1w, javascript:alert%28%27OK%27%29\">"
            )
        );
  }

  /**
   * disallowAttributes rejects every value, and joining a policy onto one that
   * already rejects everything cannot widen it, so a matching call after
   * disallowAttributes does nothing.  Pinned because it reads as though it
   * should reject only the matching values.
   */
  @Test
  void testMatchingAfterDisallowAttributesHasNoEffect() {
    String withMatching = apply(
        new HtmlPolicyBuilder()
        .allowUrlProtocols("http", "https")
        .allowElements("img")
        .allowAttributes("src").onElements("img")
        .disallowAttributes("src")
            .matching(Pattern.compile(".*example.*")).onElements("img"),
        "<img src=\"http://other.example/a.png\">");

    assertEquals("", withMatching, "the non-matching src is dropped too");
  }

  /**
   * The URL protocol guard runs after the policies an author attaches with
   * matching, so it vets what they produce: a rewrite cannot hand the output
   * a protocol the builder did not allow, while a rewrite to an allowed one
   * survives.
   */
  @Test
  void testUrlProtocolGuardVetsWhatAMatchingPolicyProduces() {
    assertEquals(
        "x",
        apply(
            new HtmlPolicyBuilder()
            .allowElements("a")
            .allowAttributes("href")
                .matching((elementName, attributeName, value) ->
                    "javascript:" + value)
                .onElements("a")
            .allowUrlProtocols("http"),
            "<a href='/x'>x</a>"));
    assertEquals(
        "<a href=\"http://example.com/x\">x</a>",
        apply(
            new HtmlPolicyBuilder()
            .allowElements("a")
            .allowAttributes("href")
                .matching((elementName, attributeName, value) ->
                    "http://example.com" + value)
                .onElements("a")
            .allowUrlProtocols("http"),
            "<a href='/x'>x</a>"));
  }

  /**
   * Issue #454.  A matching policy on a URL attribute runs before the
   * protocol guard, so it sees the value as written, after entity decoding
   * but before the guard trims whitespace and percent-encodes parentheses,
   * and before the guard has rejected anything.  A pattern that expects the
   * normalized form rejects the raw one, which fails closed.
   */
  @Test
  void testMatchingPoliciesSeeTheUrlAsWrittenBeforeTheProtocolGuard() {
    List<String> seen = new ArrayList<>();
    AttributePolicy record = (elementName, attributeName, value) -> {
      seen.add(value);
      return value;
    };
    String links =
        "<a href=\" http://example.com/a&#40;b) \">x</a>"
        + "<a href=\"javascript:alert(1)\">y</a>";

    assertEquals(
        "<a href=\"http://example.com/a%28b%29\">x</a>y",
        apply(
            new HtmlPolicyBuilder()
            .allowElements("a")
            .allowAttributes("href").matching(record).onElements("a")
            .allowUrlProtocols("http"),
            links));
    assertEquals(
        Arrays.asList(" http://example.com/a(b) ", "javascript:alert(1)"),
        seen);

    Pattern normalized = Pattern.compile("http://example\\.com/a%28b%29");
    Pattern asWritten = Pattern.compile(" http://example\\.com/a\\(b\\) ");
    assertEquals(
        "xy",
        apply(
            new HtmlPolicyBuilder()
            .allowElements("a")
            .allowAttributes("href").matching(normalized).onElements("a")
            .allowUrlProtocols("http"),
            links));
    assertEquals(
        "<a href=\"http://example.com/a%28b%29\">x</a>y",
        apply(
            new HtmlPolicyBuilder()
            .allowElements("a")
            .allowAttributes("href").matching(asWritten).onElements("a")
            .allowUrlProtocols("http"),
            links));
  }

  /**
   * Issue #454.  A policy that rewrites one URL into another is handed the
   * unvetted value, so a redirector that wraps it produces an allowed URL
   * that carries a protocol the builder never allowed.  The guard passes
   * that, as it should, so the rewriter has to vet the protocol itself,
   * which putting a FilterUrlByProtocolAttributePolicy ahead of it does.
   */
  @Test
  void testARewritingPolicyMustVetTheProtocolItself() {
    AttributePolicy redirector = (elementName, attributeName, url) ->
        "https://example.com/go?u=" + url;
    String links =
        "<a href=\"javascript:alert(1)\">x</a>"
        + "<a href=\"https://other.example/p\">y</a>";

    assertEquals(
        "<a href=\"https://example.com/go?u&#61;javascript:alert%281%29\">x</a>"
        + "<a href=\"https://example.com/go?u&#61;https://other.example/p\">"
        + "y</a>",
        apply(
            new HtmlPolicyBuilder()
            .allowElements("a")
            .allowAttributes("href").matching(redirector).onElements("a")
            .allowUrlProtocols("https"),
            links));

    assertEquals(
        "x"
        + "<a href=\"https://example.com/go?u&#61;https://other.example/p\">"
        + "y</a>",
        apply(
            new HtmlPolicyBuilder()
            .allowElements("a")
            .allowAttributes("href")
                .matching(new FilterUrlByProtocolAttributePolicy(
                    Arrays.asList("https")))
                .matching(redirector)
                .onElements("a")
            .allowUrlProtocols("https"),
            links));
  }

  /**
   * Issue #454.  The policy given to allowUrlsInStyles runs before the
   * protocol guard too, so it is consulted even when no protocol was
   * allowed, sees a javascript: URL the guard goes on to drop, and on its
   * own admits only relative URLs.
   */
  @Test
  void testStyleUrlPolicyRunsBeforeTheProtocolGuard() {
    List<String> seen = new ArrayList<>();
    AttributePolicy record = (elementName, attributeName, value) -> {
      seen.add(value);
      return value;
    };
    CssSchema images =
        CssSchema.withProperties(Arrays.asList("background-image"));

    assertEquals(
        "<div>x</div>"
        + "<div style=\"background-image:url(&#39;/i.png&#39;)\">y</div>",
        apply(
            new HtmlPolicyBuilder()
            .allowElements("div")
            .allowAttributes("style").onElements("div")
            .allowStyling(images)
            .allowUrlsInStyles(record),
            "<div style=\"background-image: url(javascript:alert%281%29)\">"
            + "x</div>"
            + "<div style=\"background-image: url(/i.png)\">y</div>"));
    assertEquals(
        Arrays.asList("javascript:alert%281%29", "/i.png"), seen);
  }

  /** Rejecting only some values means allowing the rest. */
  @Test
  void testAnInvertedAllowRejectsOnlyTheMatchingValues() {
    HtmlPolicyBuilder b = new HtmlPolicyBuilder()
        .allowUrlProtocols("http", "https")
        .allowElements("img")
        .allowAttributes("src")
            .matching((elementName, attributeName, value) ->
                value.contains("example") ? null : value)
            .onElements("img");

    assertEquals(
        "<img src=\"http://other.test/a.png\" />",
        apply(b, "<img src=\"http://other.test/a.png\">"));
    assertEquals(
        "", apply(b, "<img src=\"http://other.example/a.png\">"));
  }

  /**
   * The {@link Predicate} overload of {@code matching} keeps the values the
   * predicate accepts and drops the rest, just as the {@link Pattern} one
   * does.
   */
  @Test
  void testMatchingPredicateKeepsOnlyAcceptedValues() {
    Predicate<String> isNote = value -> value.startsWith("note-");
    HtmlPolicyBuilder b = new HtmlPolicyBuilder()
        .allowElements("p")
        .allowAttributes("class")
            .matching(isNote)
            .onElements("p");

    assertEquals(
        "<p class=\"note-aside\">Hi</p>",
        apply(b, "<p class=\"note-aside\">Hi</p>"));
    assertEquals(
        "<p>Hi</p>", apply(b, "<p class=\"warning\">Hi</p>"),
        "the attribute goes, the element stays");
  }

  /**
   * That overload takes a {@code Predicate<? super String>}, so a predicate
   * written against a supertype fits as well.  Only the wildcard makes this
   * compile.
   */
  @Test
  void testMatchingAcceptsAPredicateOverASupertypeOfString() {
    Predicate<CharSequence> isNotEmpty = value -> value.length() != 0;
    HtmlPolicyBuilder b = new HtmlPolicyBuilder()
        .allowElements("p")
        .allowAttributes("title")
            .matching(isNotEmpty)
            .onElements("p");

    assertEquals("<p title=\"t\">Hi</p>", apply(b, "<p title=\"t\">Hi</p>"));
    assertEquals("<p>Hi</p>", apply(b, "<p title=\"\">Hi</p>"));
  }

  /**
   * The {@code ignoreCase} flag of the value-set overloads picks whether the
   * value is lower-cased before it is looked up.  Every caller in the suite
   * passed {@code true}, so the case-sensitive arm -- the one that compares
   * the value as written -- went unexercised.
   */
  @Test
  void testMatchingComparesValuesAsWrittenUnlessIgnoringCase() {
    HtmlPolicyBuilder caseSensitive = new HtmlPolicyBuilder()
        .allowElements("p")
        .allowAttributes("class")
            .matching(false, "Note")
            .onElements("p");

    assertEquals(
        "<p class=\"Note\">Hi</p>",
        apply(caseSensitive, "<p class=\"Note\">Hi</p>"));
    assertEquals(
        "<p>Hi</p>", apply(caseSensitive, "<p class=\"note\">Hi</p>"),
        "a value that differs in case is not one of the allowed values");

    HtmlPolicyBuilder ignoringCase = new HtmlPolicyBuilder()
        .allowElements("p")
        .allowAttributes("class")
            .matching(true, "note")
            .onElements("p");

    assertEquals(
        "<p class=\"note\">Hi</p>",
        apply(ignoringCase, "<p class=\"Note\">Hi</p>"),
        "ignoring case keeps the lower-cased value, not the one written");
  }

  /**
   * {@code ignoreCase} lower-cases the value it looks up but not the values it
   * looks them up in, so an allowed value that is not already lower-case can
   * never be matched and the policy rejects everything.  It fails closed, but
   * silently: pinned so the asymmetry is visible to anyone changing it.
   */
  @Test
  void testMatchingIgnoringCaseNeverMatchesAnUpperCaseAllowedValue() {
    HtmlPolicyBuilder b = new HtmlPolicyBuilder()
        .allowElements("p")
        .allowAttributes("class")
            .matching(true, "Note")
            .onElements("p");

    for (String written : new String[] { "Note", "note", "NOTE" }) {
      assertEquals(
          "<p>Hi</p>", apply(b, "<p class=\"" + written + "\">Hi</p>"),
          "nothing matches the allowed value `Note`");
    }
  }

  /**
   * The duplicate-attribute scan walks a flat list of alternating names and
   * values, so it has to compare names against names.  It used to compare
   * against values too, which dropped an attribute whose name matched an
   * earlier attribute's value.
   * <p>
   * Reaching that comparison takes three attributes, not two: the scan only
   * runs once the attribute's first letter has already been seen on the tag,
   * so {@code sizes} is here to put {@code s} in play and send {@code src}
   * down the scan path, where it used to collide with {@code alt}'s value.
   * Without an attribute in that role the test passes either way.
   */
  @Test
  void testAttributeNameMatchingAnEarlierValueIsNotADuplicate() {
    assertEquals(
        "<img sizes=\"100vw\" alt=\"src\""
        + " src=\"http://example.com/a.png\" />",

        apply(
            new HtmlPolicyBuilder()
            .allowElements("img")
            .allowAttributes("sizes", "alt", "src").onElements("img")
            .allowUrlProtocols("http", "https"),
            "<img sizes=\"100vw\" alt=\"src\""
            + " src=\"http://example.com/a.png\">")
        );
  }

  /** Genuine repeats are still dropped, keeping the first. */
  @Test
  void testRepeatedAttributeNamesStillCollapseToTheFirst() {
    assertEquals(
        "<img alt=\"first\" />",

        apply(
            new HtmlPolicyBuilder()
            .allowElements("img")
            .allowAttributes("alt").onElements("img"),
            "<img alt=\"first\" ALT=\"second\" alt=\"third\">")
        );
  }

  @Test
  void testDuplicateAttributesDoNotReachElementPolicy() {
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
                (elementName, attrs) -> {
                  int nAttrs = attrs.size() / 2;
                  attrs.add("attr-count");
                  attrs.add("" + nAttrs);
                  attrs.add("id-count");
                  attrs.add("" + idCount[0]);
                  return elementName;
                },
                "a")
            .allowAttributes("id").matching(
                (elementName, attributeName, value) -> {
                  ++idCount[0];
                  return value.startsWith("b") ? value : null;
                })
            .onElements("a")
            .allowAttributes("href").onElements("a"),
            "<a href=\"foo\" id='far' id=\"bar\" href=baz id=boo>link</a>")
        );
  }

  @Test
  void testPreprocessors() {
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
            .withPreprocessor(r -> new HtmlStreamEventReceiverWrapper(r) {
              @Override
              public void text(String s) {
                underlying.text(s.toUpperCase(Locale.ROOT));
              }
              @Override
              public String toString() {
                return "shouty-text";
              }
            })
            .withPreprocessor(r -> new HtmlStreamEventReceiverWrapper(r) {
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
            }),

            input));
  }


  @Test
  void testPostprocessors() {
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
            .withPostprocessor(r -> new HtmlStreamEventReceiverWrapper(r) {
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
            })
            .withPostprocessor(r -> new HtmlStreamEventReceiverWrapper(r) {
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
            }),

            input));

  }

  @Test
  void testBackgroundImageWithUrl() {
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
  void testCalcInStyleAttribute() {
    PolicyFactory policy = new HtmlPolicyBuilder()
        .allowStyling()
        .allowElements("div")
        .toFactory();
    assertEquals(
        "<div style=\"width:calc( 100% - 20px );"
        + "max-height:calc( ( 50% - 2em ) / 2 )\">x</div>",
        policy.sanitize(
            "<div style=\"width: calc(100% - 20px);"
            + " max-height: calc((50% - 2em) / 2)\">x</div>"));
    // Nothing executable or URL-bearing survives inside calc().
    assertEquals(
        "<div style=\"width:calc( )\">x</div>",
        policy.sanitize(
            "<div style=\"width: calc(expression(alert(1)))\">x</div>"));
    assertEquals(
        "<div style=\"width:calc( 100% - )\">x</div>",
        policy.sanitize(
            "<div style=\"width: calc(100% - url(//evil.org/x))\">x</div>"));
  }

  @Test
  void testBackgroundImageWithImageFunction() {
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
  void testBackgroundWithUrls() {
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
  void testBackgroundsThatViolateGlobalUrlPolicy() {
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
  void testSpanTagFilter() {
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
  void testLinkRels() {
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
  void testLinkRelsWhenRelPresent() {
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
  void testRelLinksWhenRelIsPartOfData() {
    PolicyFactory pf = new HtmlPolicyBuilder()
        .allowElements("a")
        .allowAttributes("href").onElements("a")
        .allowAttributes("rel").onElements("a")
        .allowAttributes("target").onElements("a")
        .allowStandardUrlProtocols()
        .toFactory();
    String toSanitize = "<a target=\"_blank\" rel=\"noopener noreferrer\" href=\"https://google.com\">test</a>";
    assertEquals(toSanitize, pf.sanitize(toSanitize));
  }

  @Test
  void testRelLinksWithDuplicateRels() {
    PolicyFactory pf = new HtmlPolicyBuilder()
        .allowElements("a")
        .allowAttributes("href").onElements("a")
        .allowAttributes("rel").onElements("a")
        .allowAttributes("target").onElements("a")
        .allowStandardUrlProtocols()
        .toFactory();
    assertEquals("<a target=\"_blank\" rel=\"noopener noreferrer\" href=\"https://google.com\">test</a>", pf.sanitize("<a target=\"_blank\" rel=\"noopener noreferrer noreferrer\" href=\"https://google.com\">test</a>"));
  }

  @Test
  void testRelLinksWithDuplicateRelsRequired() {
    PolicyFactory pf = new HtmlPolicyBuilder()
        .allowElements("a")
        .allowAttributes("href").onElements("a")
        .allowAttributes("rel").onElements("a")
        .allowAttributes("target").onElements("a")
        .allowStandardUrlProtocols()
        .requireRelsOnLinks("noreferrer")
        .toFactory();
    assertEquals("<a target=\"_blank\" rel=\"noopener noreferrer\" href=\"https://google.com\">test</a>", pf.sanitize("<a target=\"_blank\" rel=\"noopener noreferrer noreferrer\" href=\"https://google.com\">test</a>"));
  }

  @Test
  void testFailFastOnSpaceSeparatedStrings() {
    // Should be ("nofollow", "noreferrer")
    assertThrows(
        IllegalArgumentException.class,
        () -> new HtmlPolicyBuilder().requireRelsOnLinks("nofollow noreferrer"));
    assertThrows(
        IllegalArgumentException.class,
        () -> new HtmlPolicyBuilder().skipRelsOnLinks("nofollow noreferrer"));
  }

  @Test
  void testEmptyDefaultLinkRelsSet() {
    PolicyFactory pf = new HtmlPolicyBuilder()
        .allowElements("a")
        .allowAttributes("href", "target").onElements("a")
        .allowStandardUrlProtocols()
        .skipRelsOnLinks("noopener", "noreferrer")
        .toFactory();

    assertEquals(
        "<a href=\"http://example.com\" target=\"_blank\">eg</a>",
        pf.sanitize("<a href=\"http://example.com\" target=\"_blank\">eg</a>"));
  }

  @Test
  void testRequireAndSkipRels() {
    PolicyFactory pf = new HtmlPolicyBuilder()
        .allowElements("a")
        .allowAttributes("href", "target").onElements("a")
        .allowStandardUrlProtocols()
        .requireRelsOnLinks("noreferrer")
        .skipRelsOnLinks("noopener", "noreferrer")
        .toFactory();

    assertEquals(
            "<a href=\"http://example.com\" target=\"_blank\">eg</a>",
            pf.sanitize("<a href=\"http://example.com\" target=\"_blank\">eg</a>"));

    assertEquals(
            "<a href=\"http://example.com\" target=\"_blank\">eg</a>",
            pf.sanitize("<a href=\"http://example.com\" rel=noreferrer target=\"_blank\">eg</a>"));

    assertEquals(
            "<a href=\"http://example.com\" target=\"_blank\">eg</a>",
            pf.sanitize("<a href=\"http://example.com\" rel=noopener target=\"_blank\">eg</a>"));
  }

  @Test
  void testSkipAndRequireRels() {
    PolicyFactory pf = new HtmlPolicyBuilder()
        .allowElements("a")
        .allowAttributes("href", "target").onElements("a")
        .allowStandardUrlProtocols()
        .skipRelsOnLinks("noopener", "noreferrer")
        .requireRelsOnLinks("noreferrer")
        .toFactory();

    assertEquals(
            "<a href=\"http://example.com\" target=\"_blank\" rel=\"noreferrer\">eg</a>",
            pf.sanitize("<a href=\"http://example.com\" target=\"_blank\">eg</a>"));

    assertEquals(
            "<a href=\"http://example.com\" target=\"_blank\" rel=\"noreferrer\">eg</a>",
            pf.sanitize("<a href=\"http://example.com\" rel=noreferrer target=\"_blank\">eg</a>"));

    assertEquals(
            "<a href=\"http://example.com\" target=\"_blank\" rel=\"noreferrer\">eg</a>",
            pf.sanitize("<a href=\"http://example.com\" rel=noopener target=\"_blank\">eg</a>"));
  }

  @Test
  void testOverflowWrap() {
    PolicyFactory pf = new HtmlPolicyBuilder()
        .allowElements("span")
        .allowStyling(CssSchema.union(CssSchema.DEFAULT, CssSchema.withProperties(j8().listOf("overflow-wrap"))))
        .toFactory();

    assertEquals(
        "<span style=\"overflow-wrap:anywhere\">Something</span>",
        pf.sanitize("<span style=\"overflow-wrap: anywhere\">Something</span>"));

    assertEquals(
        "<span style=\"overflow-wrap:inherit\">Something</span>",
        pf.sanitize("<span style=\"overflow-wrap: inherit\">Something</span>"));

    assertEquals(
        "Something",
        pf.sanitize("<span style=\"overflow-wrap: something\">Something</span>"));
  }

  @Test
  void testOverflowWrapNotAllowed() {
    PolicyFactory pf = new HtmlPolicyBuilder()
        .allowElements("span")
        .allowStyling()
        .toFactory();

    assertEquals(
        "Something",
        pf.sanitize("<span style=\"overflow-wrap: anywhere\">Something</span>"));
  }

  @Test
  void testExplicitRelsSkip() {
    PolicyFactory pf = new HtmlPolicyBuilder()
        .allowElements("a")
        .allowAttributes("href", "target", "rel").onElements("a")
        .allowStandardUrlProtocols()
        .skipRelsOnLinks("noopener", "noreferrer")
        .toFactory();

    assertEquals(
        "<a href=\"http://example.com\" target=\"_blank\">text</a>",
        pf.sanitize(
            "<a href=\"http://example.com\" target=\"_blank\""
            + " rel=\"noopener\">text</a>"));
    assertEquals(
        "<a href=\"http://example.com\" target=\"_blank\">text</a>",
        pf.sanitize(
            "<a href=\"http://example.com\" target=\"_blank\""
            + " rel=\"noreferrer noopener\">text</a>"));
    assertEquals(
        "<a href=\"http://example.com\" target=\"_blank\" rel=\"nofoo nobar nobaz\">text</a>",
        pf.sanitize(
            "<a href=\"http://example.com\" target=\"_blank\""
            + " rel=\"nofoo noopener nobar  NOREFERRER nobaz \">text</a>"));
  }

  @Test
  void testScopingExitInNoContent() {
    PolicyFactory pf = new HtmlPolicyBuilder()
        .allowElements("table", "tr", "td", "noscript")
        .toFactory();

    assertEquals(
        "<table><tr><td>foo<noscript></noscript></td><td>bar</td></tr></table>",
        pf.sanitize("<table><tr><td>foo<noscript></table></noscript><td>bar"));

  }

  @Test
  void testIssue80() {
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

  @Test
  void testDirLi() {
    assertEquals(
        "<dir compact=\"compact\"><li>something</li></dir>",
        apply(
            new HtmlPolicyBuilder()
            .allowElements("dir", "li", "ul")
            .allowAttributes("compact").onElements("dir"),
            "<dir compact=\"compact\"><li>something</li></dir>"));
  }

  @Test
  void testDisallowTextIn() {
    HtmlPolicyBuilder sharedPolicyBuilder = new HtmlPolicyBuilder()
        .allowElements("div")
        .allowAttributes("style").onElements("div");

    PolicyFactory allowPolicy = sharedPolicyBuilder.toFactory();
    assertEquals("<div style=\"display:node\">Some Text</div>",
        allowPolicy.sanitize("<div style=\"display:node\">Some Text</div>"));

    PolicyFactory disallowTextPolicy =
        sharedPolicyBuilder.disallowTextIn("div").toFactory();
    assertEquals("<div style=\"display:node\"></div>",
        disallowTextPolicy.sanitize(
            "<div style=\"display:node\">Some Text</div>"));
  }

  @Test
  void testDisallowAttribute() {
    HtmlPolicyBuilder sharedPolicyBuilder = new HtmlPolicyBuilder()
        .allowElements("div", "p")
        .allowAttributes("style").onElements("div", "p");

    PolicyFactory allowPolicy = sharedPolicyBuilder.toFactory();
    assertEquals(
        "<p style=\"display:node\">Some</p><div style=\"display:node\">Text</div>",
            allowPolicy.sanitize(
                "<p style=\"display:node\">Some</p><div style=\"display:node\">Text</div>"));

    PolicyFactory disallowTextPolicy =
        sharedPolicyBuilder.disallowAttributes("style").onElements("p").toFactory();
    assertEquals("<p>Some</p><div style=\"display:node\">Text</div>",
        disallowTextPolicy.sanitize(
            "<p style=\"display:node\">Some</p><div style=\"display:node\">Text</div>"));
  }

  @Test
  void testCreativeCSSStyling() {
    PolicyFactory policy = new HtmlPolicyBuilder()
        .allowElements("p")
        .allowAttributes("style").onElements("p").allowStyling().toFactory();

    assertEquals("<p>Some</p>",
            policy.sanitize("<p style=\"{display:none\">Some</p>"));

    assertEquals("<p style=\"color:red\">Some</p>",
            policy.sanitize("<p style=\"{display:none;};color:red\">Some</p>"));

    assertEquals("<p style=\"color:red\">Some</p>",
            policy.sanitize("<p style=\"{display:none;}color:red\">Some</p>"));

    assertEquals("<p style=\"color:red\">Some</p>",
            policy.sanitize("<p style=\"display:none }; color:red\">Some</p>"));

    assertEquals("<p style=\"color:red\">Some</p>",
            policy.sanitize("<p style=\"{display:none;}}color:red\">Some</p>"));
  }

  @Test
  void testScriptTagWithCommentBlockContainingHtmlCommentEnd() {
    PolicyFactory scriptSanitizer = new HtmlPolicyBuilder()
        // allow scripts of type application/json
        .allowElements(
            (elementName, attrs) -> {
              int typeIndex = attrs.indexOf("type");
              if (typeIndex < 0 || attrs.size() < typeIndex + 1
                  || !attrs.get(typeIndex + 1).equals("application/json")) {
                return null;
              }
              return elementName;
            },
            "script")
        // allow contents in this script tag
        .allowTextIn("script")
        // keep type attribute in application/json script tag
        .allowAttributes("type").matching(true, j8().setOf("application/json")).onElements("script")
        .toFactory();

    String mismatchedHtmlComments = "<script type=\"application/json\">\n" +
            "<!--\n" +
            "{\"field\":\"-->\"}\n" +
            "// -->\n" +
            "</script>";
    assertEquals(
        "<script type=\"application/json\"></script>",
        scriptSanitizer.sanitize(mismatchedHtmlComments));

    String htmlMetaCharsEscaped = "<script type=\"application/json\">\n" +
        "<!--\n" +
        "{\"field\":\"--\\u003c\"}\n" +
        "// -->\n" +
        "</script>";
    assertEquals(
        htmlMetaCharsEscaped,
        scriptSanitizer.sanitize(htmlMetaCharsEscaped));
  }

  @Test
  void testNoscriptInAttribute() {
    PolicyFactory pf = new HtmlPolicyBuilder()
        .allowElements("img", "p", "noscript")
        .allowAttributes("title").globally()
        .allowAttributes("img").onElements("img")
        .toFactory();

    assertEquals(
        "<noscript>"
        + "<p title=\"&lt;/noscript&gt;&lt;img src&#61;x onerror&#61;alert(1)&gt;\">"
        + "</p>"
        + "</noscript>",
        pf.sanitize(
            "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">"));
  }

  @Test
  void testTableStructure() {
    String input =
        "<TABLE>"
        + "<TR><TD>Foo<TD>Bar"
        + "<TR><TH>Baz<TH>Boo<TH>Far<TH>Faz"
        + "<TR><TD>Oink<TD>Doink<TD>Poink<TD>Toink";
    String sanitized = Sanitizers.TABLES.sanitize(input);
    assertEquals(
            ("<table><tbody>"
             + "<tr><td>Foo</td><td>Bar</td></tr>"
             + "<tr><th>Baz</th><th>Boo</th><th>Far</th><th>Faz</th></tr>"
             + "<tr><td>Oink</td><td>Doink</td><td>Poink</td><td>Toink</td></tr>"
             + "</tbody></table>"),
        sanitized);
  }

  @Test
  void testSvgNames() {
    PolicyFactory policyFactory = new HtmlPolicyBuilder()
            .allowElements("svg", "animateColor")
            .allowAttributes("viewBox").onElements("svg")
            .toFactory();
    String svg = "<svg viewBox=\"0 0 0 0\"><animateColor></animateColor></svg>";
    assertEquals(svg, policyFactory.sanitize(svg));
  }

  @Test
  void testRawTextElementsInsideForeignContent() {
    PolicyFactory policyFactory = new HtmlPolicyBuilder()
            .allowElements("svg", "math", "style")
            .allowTextIn("style")
            .toFactory();
    // Outside svg/math, style content is raw text and is emitted verbatim.
    assertEquals(
        "<style>a &amp; b</style>",
        policyFactory.sanitize("<style>a &amp; b</style>"));
    // Inside svg/math, browsers decode character references in style content,
    // so it is escaped once, not twice.
    assertEquals(
        "<svg><style>a &amp; b &lt;c&gt;</style></svg>",
        policyFactory.sanitize("<svg><style>a &amp; b &lt;c&gt;</style></svg>"));
    assertEquals(
        "<math><style>a &amp; b</style></math>",
        policyFactory.sanitize("<math><style>a &amp; b</style></math>"));
    assertEquals(
        "<svg><style>a &amp; b</style></svg><style>c &amp; d</style>",
        policyFactory.sanitize(
            "<svg><style>a &amp; b</style></svg><style>c &amp; d</style>"));
  }

  @Test
  void testTextareaIsNotTextArea() {
    String input = "<textarea>x</textarea><textArea>y</textArea>";
    PolicyFactory textareaPolicy = new HtmlPolicyBuilder().allowElements("textarea").toFactory();
    PolicyFactory textAreaPolicy = new HtmlPolicyBuilder().allowElements("textArea").toFactory();
    assertEquals("<textarea>x</textarea>y", textareaPolicy.sanitize(input));
    assertEquals("x<textArea>y</textArea>", textAreaPolicy.sanitize(input));
  }

  @Test
  void testHtmlPolicyBuilderDefinitionWithNoAttributesDefinedGlobally() {
    // Does not crash with a runtime exception
    new HtmlPolicyBuilder().allowElements().allowAttributes().globally().toFactory();
  }

  @Test
  void testCSSTextAlign() {
    HtmlPolicyBuilder builder = new HtmlPolicyBuilder();
    PolicyFactory factory = builder.allowElements("span")
        .allowAttributes("style").onElements("span").allowStyling()
        .toFactory();

    // Every value text-align accepts: the keywords from the CSS Text spec
    // followed by the CSS-wide keywords, which are valid on any property.
    for (String value
         : new String[] {
             "center", "end", "inherit", "justify", "justify-all",
             "match-parent", "start", "left", "right", "initial", "revert",
             "revert-layer", "unset" }) {
      String toSanitize = "<span style=\"text-align:" + value + "\">x</span>";
      assertEquals(toSanitize, factory.sanitize(toSanitize), value);
    }

    String toSanitizeTextAlignFoo = "<span style=\"text-align:foo\">foo</span>";
    assertEquals("foo", factory.sanitize(toSanitizeTextAlignFoo));
  }

  @Test
  void testCSSWideKeywords() {
    HtmlPolicyBuilder builder = new HtmlPolicyBuilder();
    PolicyFactory factory = builder.allowElements("span")
        .allowAttributes("style").onElements("span").allowStyling()
        .toFactory();

    // Not just text-align: the CSS-wide keywords reset any property.
    for (String property
         : new String[] { "color", "font-size", "text-decoration" }) {
      for (String keyword
           : new String[] {
               "inherit", "initial", "revert", "revert-layer", "unset" }) {
        String toSanitize =
            "<span style=\"" + property + ":" + keyword + "\">x</span>";
        assertEquals(
            toSanitize, factory.sanitize(toSanitize), property + ":" + keyword);
      }
    }

    // They are whole values, not arguments to a function, so inside rgb(...)
    // "initial" is dropped like any other word the function does not take.
    assertEquals(
        factory.sanitize("<span style=\"color:rgb(foo,0,0)\">x</span>"),
        factory.sanitize("<span style=\"color:rgb(initial,0,0)\">x</span>"));
  }

  @Test
  void testCSSFontSize() {
    HtmlPolicyBuilder builder = new HtmlPolicyBuilder();
    PolicyFactory factory = builder.allowElements("span")
        .allowAttributes("style").onElements("span").allowStyling()
        .toFactory();
    String toSanitizeXXXLarge = "the <span style=\"font-size:xxx-large\">large</span> formatting issue with chrome";
    assertEquals(toSanitizeXXXLarge, factory.sanitize(toSanitizeXXXLarge));

    String toSanitizeMedium = "the <span style=\"font-size:medium\">medium</span> formatting issue with chrome";
    assertEquals(toSanitizeMedium, factory.sanitize(toSanitizeMedium));
  }

  @Test
  void testCSSChildCombinator() {
    HtmlPolicyBuilder builder = new HtmlPolicyBuilder();

    PolicyFactory factory = builder.allowElements("span","style","h1").allowTextIn("style","h1")
        .allowAttributes("type").onElements("style").allowStyling()
        .toFactory();

    String toSanitize = "<style type=\"text/css\">\n"
        + "<!--\n"
        + ".hdg-1 {\n"
        + "width:100%;\n"
        + "}\n"
        + "\n"
        + ".hdg-1>._inner {\n"
        + "background-color: #999;\n"
        + "}\n"
        + "-->\n"
        + "</style>\n"
        + "<h1>Test</h1>\n"
        + "\n"
        + "<style>\n"
        + "<!--\n"
        + ".hdg-1 {\n"
        + "width:100%;\n"
        + "}\n"
        + "\n"
        + ".hdg-1>._inner {\n"
        + "background-color: #666;\n"
        + "}\n"
        + "-->\n"
        + "</style>";
    assertEquals(toSanitize, factory.sanitize(toSanitize));
  }

  /** The input from #113: children of a template came out as its siblings. */
  @Test
  void testTemplateKeepsItsChildren() {
    HtmlPolicyBuilder b = new HtmlPolicyBuilder()
        .allowElements("template", "b", "a")
        .allowAttributes("id").onElements("template")
        .allowAttributes("href").onElements("a")
        .allowStandardUrlProtocols();
    assertEquals(
        "<template id=\"something\"><b>"
        + "<a href=\"https://www.google.com\"> google </a></b></template>",
        apply(
            b,
            "<template id=\"something\"><b>"
            + "<a href=https://www.google.com> google </a></b></template>"));
  }

  /**
   * The javadoc of {@link HtmlPolicyBuilder#disallowTextIn} names
   * {@code <template>} as the element it exists for.  While the tables said a
   * template could hold no text, the balancer moved the text out before the
   * policy could suppress it.
   */
  @Test
  void testDisallowTextInTemplate() {
    HtmlPolicyBuilder b = new HtmlPolicyBuilder()
        .allowElements("template", "h1")
        .disallowTextIn("template");
    assertEquals(
        "<h1>allowed text</h1><template></template>",
        apply(b, "<h1>allowed text</h1><template>excluded-text</template>"));
  }

  /**
   * The text gate was set from the last tag alone, so a dropped tag inside an
   * element whose content is never shown reset it and let the content
   * through.  Text now belongs to the nearest enclosing element the policy
   * kept, and a dropped element in between suppresses it only if its content
   * is never shown.  Regression test for #444.
   */
  @Test
  void testDroppedTagInsideSuppressedContentDoesNotResetTheTextGate() {
    HtmlPolicyBuilder b = new HtmlPolicyBuilder().allowElements("h1", "div");
    assertEquals("", apply(b, "<noscript>text</noscript>"));
    assertEquals("", apply(b, "<noscript><b>text</b></noscript>"));
    assertEquals("", apply(b, "<noscript><b>a</b>b</noscript>"));
    // A dropped void element never goes on the stack, so it must not reset
    // the gate either.
    assertEquals("", apply(b, "<noscript><img>text</noscript>"));
    assertEquals(
        "<div>z</div>",
        apply(b, "<div><object><b>x</b>y</object>z</div>"));
    // A kept element inside is a text container in its own right.
    assertEquals(
        "<div>shown</div>",
        apply(b, "<noscript><div>shown</div></noscript>"));
  }

  /**
   * The same slip seen through {@code disallowTextIn}: a dropped {@code <p>}
   * between the text and the kept template reset the gate.  Part of #444.
   */
  @Test
  void testDisallowTextInReachesPastADroppedChild() {
    HtmlPolicyBuilder b = new HtmlPolicyBuilder()
        .allowElements("template", "h1")
        .disallowTextIn("template");
    assertEquals(
        "<template></template>",
        apply(b, "<template><p>excluded-text</p></template>"));
    assertEquals(
        "<template><h1>shown</h1></template>",
        apply(b, "<template><h1>shown</h1></template>"));
  }

  /**
   * {@code disallowTextIn(x)} applies when the policy drops {@code x} too.
   * The builder used to discard the disallowed names when it compiled, so a
   * policy that disallowed both the template element and text in it still
   * emitted the template's text as bare text.  The policy and input are the
   * ones reported in #194.
   */
  @Test
  void testDisallowTextInAppliesToADroppedElement() {
    HtmlPolicyBuilder b = new HtmlPolicyBuilder()
        .disallowElements("template")
        .disallowTextIn("template")
        .allowElements("h1");
    assertEquals(
        "<h1>allowed text</h1>",
        apply(
            b,
            "<html><h1>allowed text</h1><template><p>excluded-text</p>"
            + "</template><script>script-text</script><html>"));
    // Text after the dropped element resumes.
    assertEquals("after", apply(b, "<template>hidden</template>after"));
    // Text inside an allowed element nested in the dropped one belongs to
    // that element, and is not affected.
    assertEquals(
        "<h1>shown</h1>",
        apply(b, "<template><h1>shown</h1></template>"));

    // An allowed element that is dropped for having no attributes is dropped
    // all the same, so the text in it goes too.
    HtmlPolicyBuilder noBareSpans = new HtmlPolicyBuilder()
        .allowElements("span")
        .allowAttributes("title").onElements("span")
        .disallowTextIn("span");
    assertEquals(
        "<span title=\"t\"></span>",
        apply(noBareSpans, "<span title=t>x</span>"));
    assertEquals("", apply(noBareSpans, "<span>x</span>"));
  }

  /**
   * {@code and} carries a {@code disallowTextIn} over from either factory,
   * unless the other allows text in that element: grants union under
   * {@code and}, as they do for elements and attributes.
   */
  @Test
  void testAndCombinesDisallowedTextContainers() {
    PolicyFactory headings = new HtmlPolicyBuilder()
        .allowElements("h1").toFactory();
    PolicyFactory noTemplateText = new HtmlPolicyBuilder()
        .disallowTextIn("template").toFactory();
    String html = "<h1>a</h1><template>hidden</template>";
    assertEquals("<h1>a</h1>hidden", headings.sanitize(html));
    assertEquals("<h1>a</h1>", headings.and(noTemplateText).sanitize(html));
    assertEquals("<h1>a</h1>", noTemplateText.and(headings).sanitize(html));

    PolicyFactory templates = new HtmlPolicyBuilder()
        .allowElements("template").toFactory();
    assertEquals(
        "<h1>a</h1><template>hidden</template>",
        headings.and(noTemplateText).and(templates).sanitize(html));

    // Disallowing the element in one factory grants nothing, so it does not
    // cancel the other factory's disallowTextIn.
    PolicyFactory noDivs = new HtmlPolicyBuilder()
        .disallowElements("div").toFactory();
    PolicyFactory noDivText = new HtmlPolicyBuilder()
        .disallowTextIn("div").toFactory();
    assertEquals("", noDivText.and(noDivs).sanitize("<div>hidden</div>"));
    assertEquals("", noDivs.and(noDivText).sanitize("<div>hidden</div>"));
  }

  /**
   * A kept element is judged by the name it was kept under, so a policy that
   * renames {@code span} to {@code div} would otherwise honour
   * {@code disallowTextIn("span")} only when the span happened to be dropped.
   * The rule follows the name the author wrote.
   */
  @Test
  void testDisallowTextInFollowsARenamedElement() {
    HtmlPolicyBuilder b = new HtmlPolicyBuilder()
        .allowElements((name, attrs) -> "div", "span")
        .allowElements("div")
        .allowAttributes("title").onElements("span")
        .disallowTextIn("span");
    assertEquals(
        "<div title=\"t\"></div>", apply(b, "<span title=t>hi</span>"));
    assertEquals("", apply(b, "<span>hi</span>"));
    assertEquals("<div>hi</div>", apply(b, "<div>hi</div>"));
  }

  /**
   * Once a kept child closes, the text that follows it is still inside the
   * dropped element, and stays suppressed.  The old gate reset to the nearest
   * kept ancestor at every close tag, so that text leaked.
   */
  @Test
  void testSuppressionResumesAfterAKeptChildCloses() {
    HtmlPolicyBuilder b = new HtmlPolicyBuilder().allowElements("p");
    assertEquals("<p>b</p>", apply(b, "<noscript>a<p>b</p>c</noscript>"));
    // Text after the dropped element itself is unaffected.
    assertEquals("<p>b</p>d", apply(b, "<noscript>a<p>b</p>c</noscript>d"));
    assertEquals(
        "<p>b</p>",
        apply(
            b.disallowTextIn("template"), "<template>a<p>b</p>c</template>"));
  }

  /**
   * The other side of the gate following the nearest kept element: text inside
   * a dropped child of a kept element that cannot hold text itself is dropped
   * too, where it used to be written straight into that element.  A browser
   * would not keep text directly inside a {@code <tr>} either.  Policies that
   * allow the cells are unaffected.
   */
  @Test
  void testTextInADroppedCellOfAKeptRowIsDropped() {
    String table = "<table><tr><td>cell</td></tr></table>";
    assertEquals(
        "<table><tbody><tr></tr></tbody></table>",
        apply(new HtmlPolicyBuilder().allowElements("table", "tbody", "tr"),
              table));
    assertEquals(
        "<table><tbody><tr><td>cell</td></tr></tbody></table>",
        apply(
            new HtmlPolicyBuilder().allowElements("table", "tbody", "tr", "td"),
            table));
  }

  /**
   * Whether an element may hold text is said of the name the author wrote,
   * which is the name {@code allowElements(ElementPolicy, String...)} takes,
   * so a rename to a name the policy does not allow in its own right keeps
   * the text (#445).  The gate used to follow the emitted name, so the span
   * survived as an empty div.
   */
  @Test
  void testTextSurvivesARenameToAnUnallowedName() {
    assertEquals(
        "<div>hi</div>",
        apply(
            new HtmlPolicyBuilder()
                .allowElements((name, attrs) -> "div", "span")
                .allowWithoutAttributes("span"),
            "<span>hi</span>"));
    assertEquals(
        "<div>hi</div> <div>x<i>y</i>z</div>",
        apply(
            new HtmlPolicyBuilder()
                .allowElements((name, attrs) -> "div", "b")
                .allowElements("i"),
            "<b>hi</b> <b>x<i>y</i>z</b>"));
  }

  /**
   * {@code allowTextIn} takes the name the author wrote too, so it reaches a
   * renamed element, and without it the text of a raw-text element written
   * under that name stays out, whatever the policy renames it to.
   */
  @Test
  void testAllowTextInFollowsTheInputNameOfARenamedElement() {
    HtmlPolicyBuilder styleToDiv = new HtmlPolicyBuilder()
        .allowElements((name, attrs) -> "div", "style");
    assertEquals(
        "<div></div>", apply(styleToDiv, "<style>a<b</style>"));
    assertEquals(
        "<div>a&lt;b</div>",
        apply(styleToDiv.allowTextIn("style"), "<style>a<b</style>"));
  }

  /**
   * A rename into an element whose content a browser reads literally is held
   * to the bar the builder sets for that name: text in a {@code style} needs
   * {@code allowTextIn("style")} whether the author wrote {@code <style>} or
   * a {@code <div>} the policy turned into one.  Otherwise a rename would be
   * a way to write raw stylesheet or script text without saying so.
   */
  @Test
  void testRenameIntoALiteralContentElementStillNeedsAllowTextInOnTheTarget() {
    HtmlPolicyBuilder divToStyle = new HtmlPolicyBuilder()
        .allowElements((name, attrs) -> "style", "div");
    assertEquals(
        "<style></style>", apply(divToStyle, "<div>a{b:c}</div>"));
    assertEquals(
        "<style>a{b:c}</style>",
        apply(divToStyle.allowTextIn("style"), "<div>a{b:c}</div>"));
  }

  /**
   * A void element renamed to one that is not void is closed at once (#450).
   * The lexer never produces a close tag for {@code br}, and the balancer,
   * which also goes by the input name, never synthesizes one, so the renamed
   * element used to stay open until its parent closed and swallowed every
   * sibling after it.  Same result whether or not the target may hold text:
   * the text after the void element belongs to the paragraph.
   */
  @Test
  void testVoidElementRenamedToANonVoidOneIsClosedAtOnce() {
    String html = "<p>a<br>b<i>c</i>d</p><p>e</p>";
    assertEquals(
        "<p>a<span></span>bcd</p><p>e</p>",
        apply(
            new HtmlPolicyBuilder()
                .allowElements((name, attrs) -> "span", "br")
                .allowElements("p", "span"),
            html));
    assertEquals(
        "<p>a<span></span>bcd</p><p>e</p>",
        apply(
            new HtmlPolicyBuilder()
                .allowElements((name, attrs) -> "span", "br")
                .allowElements("p"),
            html));
  }

  /**
   * The balancer caps how deep the output nests, but it never counts a void
   * input element, so the phantom entries of #450 nested past the cap: three
   * hundred {@code <br>} renamed to {@code span} came out as three hundred
   * spans inside one another.
   */
  @Test
  void testVoidElementRenamedToANonVoidOneDoesNotNest() {
    StringBuilder html = new StringBuilder();
    StringBuilder expected = new StringBuilder();
    for (int i = 0; i < 300; ++i) {
      html.append("<br>");
      expected.append("<span></span>");
    }
    assertEquals(
        expected.toString(),
        apply(
            new HtmlPolicyBuilder()
                .allowElements((name, attrs) -> "span", "br")
                .allowElements("span"),
            html.toString()));
  }

  /**
   * The reverse rename, to a void element, has nothing to close in the
   * output, and the text after the void element belongs to the enclosing
   * container, as it does after a dropped element.  Text was disallowed in
   * the element by the name the author wrote, so that still holds.
   */
  @Test
  void testNonVoidElementRenamedToAVoidOne() {
    HtmlPolicyBuilder spanToBr = new HtmlPolicyBuilder()
        .allowElements((name, attrs) -> "br", "span")
        .allowWithoutAttributes("span")
        .allowElements("p");
    assertEquals(
        "<p>x<br />yz</p>", apply(spanToBr, "<p>x<span>y</span>z</p>"));
    assertEquals(
        "<p>x<br />z</p>",
        apply(spanToBr.disallowTextIn("span"), "<p>x<span>y</span>z</p>"));
  }

  /**
   * The close tag of an element renamed to a void one pops that element and
   * nothing else.  Before #450 the policy pushed nothing for it, so the close
   * tag found the nearest open element of the same input name instead and
   * ended the outer span early, leaving {@code c} outside it.
   */
  @Test
  void testCloseTagOfAnElementRenamedToAVoidOnePopsOnlyThatElement() {
    HtmlPolicyBuilder classedSpanToBr = new HtmlPolicyBuilder()
        .allowElements(
            (name, attrs) -> attrs.isEmpty() ? "span" : "br", "span")
        .allowWithoutAttributes("span")
        .allowAttributes("class").onElements("span");
    assertEquals(
        "<span>a<br class=\"x\" />bc</span>",
        apply(classedSpanToBr, "<span>a<span class=x>b</span>c</span>"));
  }

  /**
   * A factory is typically parked in a static final for the life of the JVM,
   * so nothing it holds may point back at the throwaway builder.  The value
   * policies behind {@code matching(...)} used to be anonymous classes, and
   * each one captured the {@code AttributeBuilder}, and through it the whole
   * {@code HtmlPolicyBuilder} and its intermediate maps.
   */
  @Test
  void testFactoryDoesNotRetainBuilder() {
    PolicyFactory factory = new HtmlPolicyBuilder()
        .allowElements("a", "p", "span", "img")
        .allowAttributes("href").onElements("a")
        .allowAttributes("lang").matching(Pattern.compile("[a-z]{2}"))
            .globally()
        .allowAttributes("title").matching(v -> !v.isEmpty()).globally()
        .allowAttributes("align").matching(true, "left", "right")
            .onElements("p")
        .allowAttributes("dir").matching(false, j8().setOf("ltr", "rtl"))
            .globally()
        .allowAttributes("style").globally()
        .allowUrlProtocols("https")
        .allowTextIn("span")
        .requireRelNofollowOnLinks()
        .withPreprocessor(r -> r)
        .toFactory()
        .and(new HtmlPolicyBuilder()
            .allowAttributes("id").matching(Pattern.compile("[a-z]+"))
                .onElements("p")
            .toFactory());

    assertEquals(Collections.emptyList(), buildersReachableFrom(factory));
    assertEquals(
        Collections.emptyList(),
        buildersReachableFrom(
            Sanitizers.FORMATTING.and(Sanitizers.BLOCKS).and(Sanitizers.STYLES)
                .and(Sanitizers.LINKS).and(Sanitizers.TABLES)
                .and(Sanitizers.IMAGES)));
  }

  /**
   * Walks the object graph under root and returns a field path for every
   * builder found, so a regression names the field that leaked it.
   * Descends through arrays, collections, maps, and the fields of this
   * project's classes; JDK types such as strings and patterns are leaves.
   */
  private static List<String> buildersReachableFrom(Object root) {
    List<String> found = new ArrayList<>();
    Map<Object, Boolean> seen = new IdentityHashMap<>();
    walk(root, root.getClass().getSimpleName(), seen, found);
    return found;
  }

  private static void walk(
      Object o, String path, Map<Object, Boolean> seen, List<String> found) {
    if (o == null || seen.put(o, Boolean.TRUE) != null) { return; }
    if (o instanceof HtmlPolicyBuilder
        || o instanceof HtmlPolicyBuilder.AttributeBuilder) {
      found.add(path);
      return;
    }
    Class<?> c = o.getClass();
    if (c.isArray()) {
      if (!c.getComponentType().isPrimitive()) {
        for (int i = 0, n = Array.getLength(o); i < n; ++i) {
          walk(Array.get(o, i), path + "[" + i + "]", seen, found);
        }
      }
    } else if (o instanceof Map) {
      for (Map.Entry<?, ?> e : ((Map<?, ?>) o).entrySet()) {
        walk(e.getKey(), path + ".key", seen, found);
        walk(e.getValue(), path + "[" + e.getKey() + "]", seen, found);
      }
    } else if (o instanceof Iterable) {
      int i = 0;
      for (Object el : (Iterable<?>) o) {
        walk(el, path + "[" + i++ + "]", seen, found);
      }
    } else if (c.getName().startsWith("org.owasp.")) {
      for (Class<?> k = c; k != null && k.getName().startsWith("org.owasp.");
           k = k.getSuperclass()) {
        for (Field f : k.getDeclaredFields()) {
          if (Modifier.isStatic(f.getModifiers())
              || f.getType().isPrimitive()) {
            continue;
          }
          f.setAccessible(true);
          Object v;
          try {
            v = f.get(o);
          } catch (IllegalAccessException ex) {
            throw new AssertionError(path + "." + f.getName(), ex);
          }
          walk(v, path + "." + f.getName(), seen, found);
        }
      }
    }
  }

  private static String apply(HtmlPolicyBuilder b) {
    return apply(b, EXAMPLE);
  }

  /** Sanitizes src with b's policy; any renderer error fails the test. */
  private static String apply(HtmlPolicyBuilder b, String src) {
    PolicyFactory factory = b.toFactory();
    StringBuilder sb = new StringBuilder();
    HtmlStreamRenderer renderer = HtmlStreamRenderer.create(
        sb, errorMessage -> fail(errorMessage));
    HtmlSanitizer.sanitize(
        src, factory.apply(renderer), factory.preprocessor());
    return sb.toString();
  }
}
