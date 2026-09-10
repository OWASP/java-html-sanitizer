// Copyright (c) 2019, Mike Samuel
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

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

final class PolicyFactoryTest {

  /**
   * Issue #423.  and() is documented to intersect policies where they overlap.
   * For the style attribute it used to union the CSS schemas, so combining two
   * factories allowed properties that neither one allowed on its own.
   */
  @Test
  void testAndIntersectsCssSchemas() {
    String css = "color: red; width: 10px";
    String html = "<div style=\"" + css + "\">x</div>";

    PolicyFactory colorOnly = new HtmlPolicyBuilder()
        .allowElements("div")
        .allowAttributes("style").onElements("div")
        .allowStyling(CssSchema.withProperties(Arrays.asList("color")))
        .toFactory();
    PolicyFactory widthOnly = new HtmlPolicyBuilder()
        .allowElements("div")
        .allowAttributes("style").onElements("div")
        .allowStyling(CssSchema.withProperties(Arrays.asList("width")))
        .toFactory();
    PolicyFactory both = new HtmlPolicyBuilder()
        .allowElements("div")
        .allowAttributes("style").onElements("div")
        .allowStyling(CssSchema.withProperties(Arrays.asList("color", "width")))
        .toFactory();

    assertEquals("<div style=\"color:red\">x</div>", colorOnly.sanitize(html));
    assertEquals("<div style=\"width:10px\">x</div>", widthOnly.sanitize(html));

    // Neither allows the other's property, so together they allow neither.
    assertEquals("<div>x</div>", colorOnly.and(widthOnly).sanitize(html));
    assertEquals("<div>x</div>", widthOnly.and(colorOnly).sanitize(html));

    // Where they overlap, the shared property survives, and the order of the
    // operands does not matter.
    assertEquals(
        "<div style=\"color:red\">x</div>", both.and(colorOnly).sanitize(html));
    assertEquals(
        "<div style=\"color:red\">x</div>", colorOnly.and(both).sanitize(html));
  }

  /**
   * Two allowStyling calls on one builder still accumulate: the builder unions
   * them into a single schema before any joining happens, so making the join
   * narrow does not change this.
   */
  @Test
  void testTwoAllowStylingCallsStillAccumulate() {
    PolicyFactory p = new HtmlPolicyBuilder()
        .allowElements("div")
        .allowAttributes("style").onElements("div")
        .allowStyling(CssSchema.withProperties(Arrays.asList("color")))
        .allowStyling(CssSchema.withProperties(Arrays.asList("width")))
        .toFactory();
    assertEquals(
        "<div style=\"color:red;width:10px\">x</div>",
        p.sanitize("<div style=\"color: red; width: 10px\">x</div>"));
  }

  /**
   * Issue #204.  A builder that never allowed a URL protocol guards its URL
   * attributes with a default that rejects every absolute URL.  Joined with
   * a factory that did allow some, that default used to be intersected as
   * though it were a policy, so the combination rejected the protocols the
   * other factory allowed, in either order.  The default now yields to an
   * allowlist.
   */
  @Test
  void testAndDefaultUrlProtocolGuardYieldsToAnAllowlist() {
    String links = String.join(
        "\n",
        "<a href='http://example.com/'>http</a>",
        "<a href='HTTP://example.com/'>HTTP</a>",
        "<a href='https://example.com/'>https</a>",
        "<a href='//example.com/'>scheme-relative</a>",
        "<a href='/local'>relative</a>",
        "<a href='javascript:alert(1)'>js</a>",
        "<a href='jAvAsCrIpT:alert(1)'>JS</a>",
        "<a href='\tjavascript:alert(1)'>tab js</a>",
        "<a href='java&#9;script:alert(1)'>split js</a>",
        "<a href='data:text/html,x'>data</a>",
        "<a href='vbscript:x'>vbs</a>");
    String relativeOnly = String.join(
        "\n",
        "http",
        "HTTP",
        "https",
        "scheme-relative",
        "<a href=\"/local\">relative</a>",
        "js",
        "JS",
        "tab js",
        "split js",
        "data",
        "vbs");
    String httpOnly = String.join(
        "\n",
        "<a href=\"http://example.com/\">http</a>",
        "<a href=\"HTTP://example.com/\">HTTP</a>",
        "https",
        "scheme-relative",
        "<a href=\"/local\">relative</a>",
        "js",
        "JS",
        "tab js",
        "split js",
        "data",
        "vbs");

    PolicyFactory noProtocols = links();
    PolicyFactory http = links("http");

    assertEquals(relativeOnly, noProtocols.sanitize(links));
    assertEquals(httpOnly, http.sanitize(links));
    assertEquals(httpOnly, noProtocols.and(http).sanitize(links));
    assertEquals(httpOnly, http.and(noProtocols).sanitize(links));
  }

  /** Two factories that allowed no protocol still allow none together. */
  @Test
  void testAndOfTwoDefaultUrlProtocolGuardsAllowsNoProtocol() {
    PolicyFactory noProtocols = links();
    PolicyFactory noProtocolsWithTitle = new HtmlPolicyBuilder()
        .allowElements("a")
        .allowAttributes("href", "title").onElements("a")
        .toFactory();
    String links = String.join(
        "\n",
        "<a href='http://example.com/' title='t'>http</a>",
        "<a href='/local' title='t'>relative</a>");
    String expected = String.join(
        "\n",
        "<a title=\"t\">http</a>",
        "<a href=\"/local\" title=\"t\">relative</a>");

    assertEquals(
        expected, noProtocols.and(noProtocolsWithTitle).sanitize(links));
    assertEquals(
        expected, noProtocolsWithTitle.and(noProtocols).sanitize(links));
  }

  /**
   * Two allowlists intersect, as and() documents.  An empty intersection is
   * an allowlist too, not the default, so it does not yield to a third
   * factory: the same factories allow the same URLs however they are
   * grouped.
   */
  @Test
  void testAndIntersectsUrlProtocolAllowlists() {
    PolicyFactory http = links("http");
    PolicyFactory https = links("https");
    PolicyFactory both = links("http", "https");

    String links = String.join(
        "\n",
        "<a href='http://example.com/'>http</a>",
        "<a href='https://example.com/'>https</a>",
        "<a href='//example.com/'>scheme-relative</a>",
        "<a href='/local'>relative</a>",
        "<a href='javascript:alert(1)'>js</a>");
    String bothKept = String.join(
        "\n",
        "<a href=\"http://example.com/\">http</a>",
        "<a href=\"https://example.com/\">https</a>",
        "<a href=\"//example.com/\">scheme-relative</a>",
        "<a href=\"/local\">relative</a>",
        "js");
    String httpKept = String.join(
        "\n",
        "<a href=\"http://example.com/\">http</a>",
        "https",
        "scheme-relative",
        "<a href=\"/local\">relative</a>",
        "js");
    String noneKept = String.join(
        "\n",
        "http",
        "https",
        "scheme-relative",
        "<a href=\"/local\">relative</a>",
        "js");

    assertEquals(bothKept, both.sanitize(links));
    assertEquals(httpKept, both.and(http).sanitize(links));
    assertEquals(httpKept, http.and(both).sanitize(links));
    assertEquals(noneKept, http.and(https).sanitize(links));
    assertEquals(noneKept, https.and(http).sanitize(links));

    assertEquals(noneKept, http.and(https).and(both).sanitize(links));
    assertEquals(noneKept, both.and(http.and(https)).sanitize(links));
    assertEquals(noneKept, http.and(both.and(https)).sanitize(links));
    assertEquals(noneKept, http.and(https).and(links()).sanitize(links));
  }

  /**
   * The case that bites in practice: Sanitizers.LINKS combined with a
   * factory that only meant to restrict href to a pattern, and so never
   * mentioned protocols, used to lose every absolute link.
   */
  @Test
  void testAndLinksWithAFactoryThatRestrictsHrefButAllowedNoProtocol() {
    PolicyFactory exampleOnly = new HtmlPolicyBuilder()
        .allowElements("a")
        .allowAttributes("href")
            .matching(Pattern.compile("(?:https?://example\\.com)?/.*"))
            .onElements("a")
        .toFactory();
    String links = String.join(
        "\n",
        "<a href='http://example.com/a'>example</a>",
        "<a href='https://example.com/b'>secure example</a>",
        "<a href='http://evil.example/c'>elsewhere</a>",
        "<a href='/d'>local</a>",
        "<a href='javascript:alert(1)'>js</a>",
        "<a href='mailto:x@example.com'>mail</a>");
    String expected = String.join(
        "\n",
        "<a href=\"http://example.com/a\" rel=\"nofollow\">example</a>",
        "<a href=\"https://example.com/b\" rel=\"nofollow\">secure example</a>",
        "elsewhere",
        "<a href=\"/d\" rel=\"nofollow\">local</a>",
        "js",
        "mail");

    assertEquals(
        String.join(
            "\n",
            "example",
            "secure example",
            "elsewhere",
            "<a href=\"/d\">local</a>",
            "js",
            "mail"),
        exampleOnly.sanitize(links));
    assertEquals(expected, Sanitizers.LINKS.and(exampleOnly).sanitize(links));
    assertEquals(expected, exampleOnly.and(Sanitizers.LINKS).sanitize(links));
  }

  /** A global href grant that allowed no protocol does not veto either. */
  @Test
  void testAndLinksWithAGlobalHrefGrantThatAllowedNoProtocol() {
    PolicyFactory hrefAnywhere = new HtmlPolicyBuilder()
        .allowAttributes("href").globally()
        .toFactory();
    String links = String.join(
        "\n",
        "<a href='http://example.com/'>http</a>",
        "<a href='javascript:alert(1)'>js</a>");
    String expected = String.join(
        "\n",
        "<a href=\"http://example.com/\" rel=\"nofollow\">http</a>",
        "js");

    assertEquals(expected, Sanitizers.LINKS.and(hrefAnywhere).sanitize(links));
    assertEquals(expected, hrefAnywhere.and(Sanitizers.LINKS).sanitize(links));
  }

  /**
   * The default yields only to another builder's allowlist, never to a
   * policy the author attached with matching, so a builder that allowed no
   * protocol still rejects every absolute URL on its own, as the javadoc of
   * allowUrlProtocols promises, even when that policy is the library's own
   * protocol filter.  And an allowlist from another factory intersects with
   * such a policy, as with any other.
   */
  @Test
  void testDefaultUrlProtocolGuardDoesNotYieldToAMatchingPolicy() {
    PolicyFactory httpsByMatching = new HtmlPolicyBuilder()
        .allowElements("a")
        .allowAttributes("href")
            .matching(new FilterUrlByProtocolAttributePolicy(
                Arrays.asList("https")))
            .onElements("a")
        .toFactory();
    String links = String.join(
        "\n",
        "<a href='https://example.com/'>https</a>",
        "<a href='/local'>relative</a>");
    String relativeOnly = String.join(
        "\n",
        "https",
        "<a href=\"/local\">relative</a>");

    assertEquals(relativeOnly, httpsByMatching.sanitize(links));
    assertEquals(relativeOnly, httpsByMatching.and(links()).sanitize(links));
    assertEquals(relativeOnly, links().and(httpsByMatching).sanitize(links));
    assertEquals(
        relativeOnly, httpsByMatching.and(links("http")).sanitize(links));
    assertEquals(
        String.join(
            "\n",
            "<a href=\"https://example.com/\">https</a>",
            "<a href=\"/local\">relative</a>"),
        httpsByMatching.and(links("https")).sanitize(links));
  }

  /** The same for srcset, whose guard wraps the protocol guard. */
  @Test
  void testAndDefaultUrlProtocolGuardYieldsInSrcset() {
    PolicyFactory noProtocols = images();
    PolicyFactory http = images("http");
    String img = "<img src='http://example.com/a.png'"
        + " srcset='http://example.com/a.png 1x, javascript:alert(1) 2x,"
        + " /b.png 3x'>";
    String httpKept = "<img src=\"http://example.com/a.png\""
        + " srcset=\"http://example.com/a.png 1x , /b.png 3x\" />";

    assertEquals("<img srcset=\"/b.png 3x\" />", noProtocols.sanitize(img));
    assertEquals(httpKept, http.sanitize(img));
    assertEquals(httpKept, noProtocols.and(http).sanitize(img));
    assertEquals(httpKept, http.and(noProtocols).sanitize(img));
  }

  /**
   * And for url() in style, whose rewriter wraps the protocol guard, between
   * factories that both allowed URLs in styles.  A rewriter from
   * CssSchema.toAttributePolicy is a policy of the author's, and takes part
   * however the factories are grouped, as does the policy given to
   * allowUrlsInStyles, which the default does not yield to.
   */
  @Test
  void testAndDefaultUrlProtocolGuardYieldsInStyles() {
    CssSchema images =
        CssSchema.withProperties(Arrays.asList("background-image"));
    PolicyFactory noProtocols = styled(images);
    PolicyFactory https = styled(images, "https");
    String divs =
        "<div style=\"background-image: url(https://example.com/i.png)\">"
        + "x</div>"
        + "<div style=\"background-image: url(javascript:alert%281%29)\">"
        + "y</div>";
    String httpsKept =
        "<div style=\"background-image:url("
        + "&#39;https://example.com/i.png&#39;)\">"
        + "x</div><div>y</div>";

    assertEquals("<div>x</div><div>y</div>", noProtocols.sanitize(divs));
    assertEquals(httpsKept, https.sanitize(divs));
    assertEquals(httpsKept, noProtocols.and(https).sanitize(divs));
    assertEquals(httpsKept, https.and(noProtocols).sanitize(divs));

    PolicyFactory vetted = new HtmlPolicyBuilder()
        .allowElements("div")
        .allowAttributes("style")
            .matching(images.toAttributePolicy(url -> url + "?vetted"))
            .onElements("div")
        .toFactory();
    String vettedKept =
        "<div style=\"background-image:url("
        + "&#39;https://example.com/i.png?vetted&#39;)\">"
        + "x</div><div>y</div>";
    assertEquals(
        "<div>x</div><div>y</div>", noProtocols.and(vetted).sanitize(divs));
    assertEquals(vettedKept, noProtocols.and(vetted).and(https).sanitize(divs));
    assertEquals(vettedKept, noProtocols.and(vetted.and(https)).sanitize(divs));
    assertEquals(vettedKept, vetted.and(https).and(noProtocols).sanitize(divs));
    assertEquals(vettedKept, https.and(noProtocols.and(vetted)).sanitize(divs));

    PolicyFactory httpsInStylesOnly = new HtmlPolicyBuilder()
        .allowElements("div")
        .allowAttributes("style").onElements("div")
        .allowStyling(images)
        .allowUrlsInStyles(new FilterUrlByProtocolAttributePolicy(
            Arrays.asList("https")))
        .toFactory();
    assertEquals("<div>x</div><div>y</div>", httpsInStylesOnly.sanitize(divs));
    assertEquals(
        "<div>x</div><div>y</div>",
        httpsInStylesOnly.and(noProtocols).sanitize(divs));
    assertEquals(httpsKept, httpsInStylesOnly.and(https).sanitize(divs));
  }

  /** Links, with the given protocols allowed. */
  private static PolicyFactory links(String... protocols) {
    return new HtmlPolicyBuilder()
        .allowElements("a")
        .allowAttributes("href").onElements("a")
        .allowUrlProtocols(protocols)
        .toFactory();
  }

  /** Images with src and srcset, with the given protocols allowed. */
  private static PolicyFactory images(String... protocols) {
    return new HtmlPolicyBuilder()
        .allowElements("img")
        .allowAttributes("src", "srcset").onElements("img")
        .allowUrlProtocols(protocols)
        .toFactory();
  }

  /**
   * Styled divs that allow URLs in styles, with the given protocols allowed.
   */
  private static PolicyFactory styled(CssSchema schema, String... protocols) {
    return new HtmlPolicyBuilder()
        .allowElements("div")
        .allowAttributes("style").onElements("div")
        .allowStyling(schema)
        .allowUrlsInStyles(AttributePolicy.IDENTITY_ATTRIBUTE_POLICY)
        .allowUrlProtocols(protocols)
        .toFactory();
  }

  @Test
  void testAnd() {
    // Filters srcset to only contain URLs with the substring "foo"
    PolicyFactory f = new HtmlPolicyBuilder()
        .allowElements("img")
        .allowAttributes("srcset")
        .matching(new SubstringFilter("foo"))
        .globally()
        .allowStandardUrlProtocols()
        .toFactory();
    // Filters srcset to only contain URLs with the substring "bar"
    PolicyFactory g = new HtmlPolicyBuilder()
        .allowElements("img")
        .allowAttributes("srcset")
        .matching(new SubstringFilter("bar"))
        .globally()
        .allowStandardUrlProtocols()
        .toFactory();

    // The javascript URL will be allowed if the extra policies are not
    // preserved.
    String html = "<img"
        + " srcset=\"/foo.png , /bar.png , javascript:alert('foobar') , /foobar.png\""
        // title is not whitelisted.
        + " title=Hi>!";

    PolicyFactory[] factories = {
        f,
        g,
        // Test that .and() intersects regardless of order.
        f.and(g),
        g.and(f),
    };
    String[] expectedOutputs = {
        // f
        "<img srcset=\"/foo.png , /foobar.png\" />",

        // g
        "<img srcset=\"/bar.png , /foobar.png\" />",

        // f and g
        "<img srcset=\"/foobar.png\" />",

        // g and f
        "<img srcset=\"/foobar.png\" />",
    };
    String[] expectedLogs = {
        // f
        ""
        + "discardedAttributes img, [title]\n"
        + "Handled IOException BANG\n",

        // g
        ""
        + "discardedAttributes img, [title]\n"
        + "Handled IOException BANG\n",

        // f and g
        ""
        + "discardedAttributes img, [title]\n"
        + "Handled IOException BANG\n",

        // g and f
        ""
        + "discardedAttributes img, [title]\n"
        + "Handled IOException BANG\n",
    };

    for (int i = 0; i < factories.length; ++i) {
      PolicyFactory factory = factories[i];
      String expectedOutput = expectedOutputs[i];
      String expectedLog = expectedLogs[i];

      // A dummy value that lets us check that context is properly threaded
      // through joined policies.
      final Object context = new Object();
      // Collect events from callbacks.
      final StringBuilder log = new StringBuilder();
      // Collects output HTML.
      final StringBuilder out = new StringBuilder();

      // A noisy listener that logs.
      HtmlChangeListener<Object> listener = new HtmlChangeListener<Object>() {

        public void discardedTag(Object ctx, String elementName) {
          assertEquals(context, ctx);
          log.append("discardedTag " + elementName + "\n");
        }

        public void discardedAttributes(
            Object ctx, String tagName, String... attributeNames) {
          assertEquals(context, ctx);
          log.append(
              "discardedAttributes " + tagName
              + ", " + Arrays.asList(attributeNames)
              + "\n");
        }

      };

      Handler<IOException> ioHandler =
          x -> log.append("Handled IOException " + x.getMessage() + "\n");

      // Should not be called.
      Handler<String> badHtmlHandler = x -> { throw new AssertionError(x); };

      // Wraps out to throw when a '!' is written to test the ioHandler.
      // There is a '!' at the end of the output.
      Appendable throwingOut = new Appendable() {

        public Appendable append(CharSequence csq) throws IOException {
          return append(csq, 0, csq.length());
        }

        public Appendable append(CharSequence csq, int start, int end) throws IOException {
          for (int j = start; j < end; ++j) {
            if (csq.charAt(j) == '!') {
              throw new IOException("BANG");
            }
          }
          out.append(csq, start, end);
          return this;
        }

        public Appendable append(char c) throws IOException {
          if (c == '!') {
            throw new IOException("BANG");
          }
          out.append(c);
          return this;
        }

      };

      HtmlStreamEventReceiver receiver = HtmlStreamRenderer.create(
          throwingOut, ioHandler, badHtmlHandler);
      HtmlSanitizer.Policy policy = factory.apply(
          receiver, listener, context);
      HtmlSanitizer.sanitize(html, policy);

      assertEquals(
          "Out:\n" + expectedOutput + "\n\nLog:\n" + expectedLog,

          "Out:\n" + out + "\n\nLog:\n" + log,
          "i:" + i);
    }
  }

  // Default Skip Tag
  // beforePolicy : X
  // afterPolicy : X
  @Test
  void testHtmlTagSkipPolicy1() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("span")
            .toFactory();

    String spanTagString = "<span>Hi</span>";
    String resultString = beforePolicy.sanitize(spanTagString);
    assertEquals("Hi", resultString);

    PolicyFactory afterPolicy = beforePolicy.and(new HtmlPolicyBuilder()
            .allowElements("span")
            .toFactory());

    resultString = afterPolicy.sanitize(spanTagString);
    assertEquals("Hi", resultString);
  }

  // Default Skip Tag
  // beforePolicy : X
  // afterPolicy : allow
  @Test
  void testHtmlTagSkipPolicy2() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("span")
            .toFactory();

    String spanTagString = "<span>Hi</span>";
    String resultString = beforePolicy.sanitize(spanTagString);
    assertEquals("Hi", resultString);

    PolicyFactory afterPolicy = beforePolicy.and(new HtmlPolicyBuilder()
            .allowElements("span")
            .allowWithoutAttributes("span")
            .toFactory());

    resultString = afterPolicy.sanitize(spanTagString);
    assertEquals("<span>Hi</span>", resultString);
  }

  // Default Skip Tag
  // beforePolicy : X
  // afterPolicy : disallow
  @Test
  void testHtmlTagSkipPolicy3() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("span")
            .toFactory();

    String spanTagString = "<span>Hi</span>";
    String resultString = beforePolicy.sanitize(spanTagString);
    assertEquals("Hi", resultString);

    PolicyFactory afterPolicy = beforePolicy.and(new HtmlPolicyBuilder()
            .allowElements("span")
            .disallowWithoutAttributes("span")
            .toFactory());

    resultString = afterPolicy.sanitize(spanTagString);
    assertEquals("Hi", resultString);
  }

  // Default Skip Tag
  // beforePolicy : allow
  // afterPolicy : X
  @Test
  void testHtmlTagSkipPolicy4() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("span")
            .allowWithoutAttributes("span")
            .toFactory();

    String spanTagString = "<span>Hi</span>";
    String resultString = beforePolicy.sanitize(spanTagString);
    assertEquals("<span>Hi</span>", resultString);

    PolicyFactory afterPolicy = beforePolicy.and(new HtmlPolicyBuilder()
            .allowElements("span")
            .toFactory());

    resultString = afterPolicy.sanitize(spanTagString);
    assertEquals("<span>Hi</span>", resultString);
  }

  // Default Skip Tag
  // beforePolicy : allow
  // afterPolicy : allow
  @Test
  void testHtmlTagSkipPolicy5() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("span")
            .allowWithoutAttributes("span")
            .toFactory();

    String spanTagString = "<span>Hi</span>";
    String resultString = beforePolicy.sanitize(spanTagString);
    assertEquals("<span>Hi</span>", resultString);

    PolicyFactory afterPolicy = beforePolicy.and(new HtmlPolicyBuilder()
            .allowElements("span")
            .allowWithoutAttributes("span")
            .toFactory());

    resultString = afterPolicy.sanitize(spanTagString);
    assertEquals("<span>Hi</span>", resultString);
  }

  // Default Skip Tag
  // beforePolicy : allow
  // afterPolicy : disallow
  @Test
  void testHtmlTagSkipPolicy6() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("span")
            .allowWithoutAttributes("span")
            .toFactory();

    String spanTagString = "<span>Hi</span>";
    String resultString = beforePolicy.sanitize(spanTagString);
    assertEquals("<span>Hi</span>", resultString);

    PolicyFactory afterPolicy = beforePolicy.and(new HtmlPolicyBuilder()
            .allowElements("span")
            .disallowWithoutAttributes("span")
            .toFactory());

    resultString = afterPolicy.sanitize(spanTagString);
    assertEquals("Hi", resultString);
  }

  // Default Skip Tag
  // beforePolicy : disallow
  // afterPolicy : X
  @Test
  void testHtmlTagSkipPolicy7() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("span")
            .disallowWithoutAttributes("span")
            .toFactory();

    String spanTagString = "<span>Hi</span>";
    String resultString = beforePolicy.sanitize(spanTagString);
    assertEquals("Hi", resultString);

    PolicyFactory afterPolicy = beforePolicy.and(new HtmlPolicyBuilder()
            .allowElements("span")
            .toFactory());

    resultString = afterPolicy.sanitize(spanTagString);
    assertEquals("Hi", resultString);
  }

  // Default Skip Tag
  // beforePolicy : disallow
  // afterPolicy : allow
  @Test
  void testHtmlTagSkipPolicy8() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("span")
            .disallowWithoutAttributes("span")
            .toFactory();

    String spanTagString = "<span>Hi</span>";
    String resultString = beforePolicy.sanitize(spanTagString);
    assertEquals("Hi", resultString);

    PolicyFactory afterPolicy = beforePolicy.and(new HtmlPolicyBuilder()
            .allowElements("span")
            .allowWithoutAttributes("span")
            .toFactory());

    resultString = afterPolicy.sanitize(spanTagString);
    assertEquals("<span>Hi</span>", resultString);
  }

  // Default Skip Tag
  // beforePolicy : disallow
  // afterPolicy : disallow
  @Test
  void testHtmlTagSkipPolicy9() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("span")
            .disallowWithoutAttributes("span")
            .toFactory();

    String spanTagString = "<span>Hi</span>";
    String resultString = beforePolicy.sanitize(spanTagString);
    assertEquals("Hi", resultString);

    PolicyFactory afterPolicy = beforePolicy.and(new HtmlPolicyBuilder()
            .allowElements("span")
            .disallowWithoutAttributes("span")
            .toFactory());

    resultString = afterPolicy.sanitize(spanTagString);
    assertEquals("Hi", resultString);
  }

  // Not Default Skip Tag
  // beforePolicy : X
  // afterPolicy : X
  @Test
  void testHtmlTagSkipPolicy10() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("p")
            .toFactory();

    String pTagString = "<p>Hi</p>";
    String resultString = beforePolicy.sanitize(pTagString);
    assertEquals("<p>Hi</p>", resultString);

    PolicyFactory afterPolicy = beforePolicy.and(new HtmlPolicyBuilder()
            .allowElements("p")
            .toFactory());

    resultString = afterPolicy.sanitize(pTagString);
    assertEquals("<p>Hi</p>", resultString);
  }

  // Not Default Skip Tag
  // beforePolicy : X
  // afterPolicy : allow
  @Test
  void testHtmlTagSkipPolicy11() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("p")
            .toFactory();

    String pTagString = "<p>Hi</p>";
    String resultString = beforePolicy.sanitize(pTagString);
    assertEquals("<p>Hi</p>", resultString);

    PolicyFactory afterPolicy = beforePolicy.and(new HtmlPolicyBuilder()
            .allowElements("p")
            .allowWithoutAttributes("p")
            .toFactory());

    resultString = afterPolicy.sanitize(pTagString);
    assertEquals("<p>Hi</p>", resultString);
  }

  // Not Default Skip Tag
  // beforePolicy : X
  // afterPolicy : disallow
  @Test
  void testHtmlTagSkipPolicy12() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("p")
            .toFactory();

    String pTagString = "<p>Hi</p>";
    String resultString = beforePolicy.sanitize(pTagString);
    assertEquals("<p>Hi</p>", resultString);

    PolicyFactory afterPolicy = beforePolicy.and(new HtmlPolicyBuilder()
            .allowElements("p")
            .disallowWithoutAttributes("p")
            .toFactory());

    resultString = afterPolicy.sanitize(pTagString);
    assertEquals("Hi", resultString);
  }

  // Not Default Skip Tag
  // beforePolicy : allow
  // afterPolicy : X
  @Test
  void testHtmlTagSkipPolicy13() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("p")
            .allowWithoutAttributes("p")
            .toFactory();

    String pTagString = "<p>Hi</p>";
    String resultString = beforePolicy.sanitize(pTagString);
    assertEquals("<p>Hi</p>", resultString);

    PolicyFactory afterPolicy = beforePolicy.and(new HtmlPolicyBuilder()
            .allowElements("p")
            .toFactory());

    resultString = afterPolicy.sanitize(pTagString);
    assertEquals("<p>Hi</p>", resultString);
  }

  // Not Default Skip Tag
  // beforePolicy : allow
  // afterPolicy : allow
  @Test
  void testHtmlTagSkipPolicy14() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("p")
            .allowWithoutAttributes("p")
            .toFactory();

    String pTagString = "<p>Hi</p>";
    String resultString = beforePolicy.sanitize(pTagString);
    assertEquals("<p>Hi</p>", resultString);

    PolicyFactory afterPolicy = beforePolicy.and(new HtmlPolicyBuilder()
            .allowElements("p")
            .allowWithoutAttributes("p")
            .toFactory());

    resultString = afterPolicy.sanitize(pTagString);
    assertEquals("<p>Hi</p>", resultString);
  }

  // Not Default Skip Tag
  // beforePolicy : allow
  // afterPolicy : disallow
  @Test
  void testHtmlTagSkipPolicy15() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("p")
            .allowWithoutAttributes("p")
            .toFactory();

    String pTagString = "<p>Hi</p>";
    String resultString = beforePolicy.sanitize(pTagString);
    assertEquals("<p>Hi</p>", resultString);

    PolicyFactory afterPolicy = beforePolicy.and(new HtmlPolicyBuilder()
            .allowElements("p")
            .disallowWithoutAttributes("p")
            .toFactory());

    resultString = afterPolicy.sanitize(pTagString);
    assertEquals("Hi", resultString);
  }

  // Not Default Skip Tag
  // beforePolicy : disallow
  // afterPolicy : X
  @Test
  void testHtmlTagSkipPolicy16() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("p")
            .disallowWithoutAttributes("p")
            .toFactory();

    String pTagString = "<p>Hi</p>";
    String resultString = beforePolicy.sanitize(pTagString);
    assertEquals("Hi", resultString);

    PolicyFactory afterPolicy = beforePolicy.and(new HtmlPolicyBuilder()
            .allowElements("p")
            .toFactory());

    resultString = afterPolicy.sanitize(pTagString);
    assertEquals("Hi", resultString);
  }

  // Not Default Skip Tag
  // beforePolicy : disallow
  // afterPolicy : allow
  @Test
  void testHtmlTagSkipPolicy17() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("p")
            .disallowWithoutAttributes("p")
            .toFactory();

    String pTagString = "<p>Hi</p>";
    String resultString = beforePolicy.sanitize(pTagString);
    assertEquals("Hi", resultString);

    PolicyFactory afterPolicy = beforePolicy.and(new HtmlPolicyBuilder()
            .allowElements("p")
            .allowWithoutAttributes("p")
            .toFactory());

    resultString = afterPolicy.sanitize(pTagString);
    assertEquals("<p>Hi</p>", resultString);
  }

  // Not Default Skip Tag
  // beforePolicy : disallow
  // afterPolicy : disallow
  @Test
  void testHtmlTagSkipPolicy18() {
    PolicyFactory beforePolicy = new HtmlPolicyBuilder()
            .allowElements("p")
            .disallowWithoutAttributes("p")
            .toFactory();

    String pTagString = "<p>Hi</p>";
    String resultString = beforePolicy.sanitize(pTagString);
    assertEquals("Hi", resultString);

    PolicyFactory afterPolicy = beforePolicy.and(new HtmlPolicyBuilder()
            .allowElements("p")
            .disallowWithoutAttributes("p")
            .toFactory());

    resultString = afterPolicy.sanitize(pTagString);
    assertEquals("Hi", resultString);
  }

  static final class SubstringFilter implements AttributePolicy {
    final String substr;

    SubstringFilter(String substr) {
      this.substr = substr;
    }

    public String apply(
        String elementName, String attributeName, String value) {
      List<String> outParts = new ArrayList<>();
      for (String part : value.split(",")) {
        part = part.trim();
        if (part.contains(substr)) {
          outParts.add(part);
        }
      }
      return String.join(" , ", outParts);
    }
  }
}