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