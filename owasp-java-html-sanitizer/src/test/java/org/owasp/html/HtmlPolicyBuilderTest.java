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

import java.util.Arrays;
import java.util.List;
import java.util.Locale;
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
