// Copyright (c) 2019, Mike Samuel
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

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

import com.google.common.base.Joiner;

import junit.framework.TestCase;

@SuppressWarnings({ "javadoc" })
public final class PolicyFactoryTest extends TestCase {

  @Test
  public static void testAnd() {
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

      Handler<IOException> ioHandler = new Handler<IOException>() {

        public void handle(IOException x) {
          log.append("Handled IOException " + x.getMessage() + "\n");
        }

      };

      // Should not be called.
      Handler<String> badHtmlHandler = new Handler<String>() {

        public void handle(String x) {
          throw new AssertionError(x);
        }

      };

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

      HtmlStreamEventReceiver receiver = new HtmlStreamRenderer(
          throwingOut, ioHandler, badHtmlHandler);
      HtmlSanitizer.Policy policy = factory.apply(
          receiver, listener, context);
      HtmlSanitizer.sanitize(html, policy);

      assertEquals(
          "i:" + i,

          "Out:\n" + expectedOutput + "\n\nLog:\n" + expectedLog,
          "Out:\n" + out + "\n\nLog:\n" + log);
    }
  }

  static final class SubstringFilter implements AttributePolicy {
    final String substr;

    SubstringFilter(String substr) {
      this.substr = substr;
    }

    public String apply(
        String elementName, String attributeName, String value) {
      List<String> outParts = new ArrayList<String>();
      for (String part : value.split(",")) {
        part = part.trim();
        if (part.contains(substr)) {
          outParts.add(part);
        }
      }
      return Joiner.on(" , ").join(outParts);
    }
  }
}