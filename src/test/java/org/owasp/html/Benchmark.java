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

import java.io.File;
import java.io.StringReader;
import java.util.List;
import java.util.ListIterator;

import org.w3c.dom.Node;
import org.xml.sax.InputSource;

import com.google.common.base.Charsets;
import com.google.common.io.Files;

import nu.validator.htmlparser.dom.HtmlDocumentBuilder;

/**
 * An executable that benchmarks the sanitizer against an alternative.
 */
public class Benchmark {

  /**
   * By default times all alternatives.
   * If there is an input of the form {@code /[hsp]+/} then each letter
   * specifies a benchmark to run and unspecified ones are not run.
   */
  public static void main(String[] args) throws Exception {
    String html = Files.toString(new File(args[0]), Charsets.UTF_8);

    boolean timeLibhtmlparser = true;
    boolean timeSanitize = true;
    boolean timePolicyBuilder = true;

    if (args.length > 1) {
      String s = args[1];
      timeLibhtmlparser = s.contains("h");
      timeSanitize = s.contains("s");
      timePolicyBuilder = s.contains("p");
    }

    int n = 0;  // Defeat optimizations.

    if (timeLibhtmlparser) {
      for (int i = 100; --i >= 0;) {
        n += parseUsingLibhtmlparser(html);
      }
    }

    if (timeSanitize) {
      for (int i = 100; --i >= 0;) {
        n += sanitize(html).length();
      }
    }

    if (timePolicyBuilder) {
      for (int i = 100; --i >= 0;) {
        n += sanitizeUsingPolicyBuilder(html).length();
      }
    }

    long t0 = 0, t1 = -1;
    if (timeLibhtmlparser) {
      t0 = System.nanoTime();
      for (int i = 100; --i >= 0;) {
        n += parseUsingLibhtmlparser(html);
      }
      t1 = System.nanoTime();
    }

    long t2 = 0, t3 = -1;
    if (timeSanitize) {
      t2 = System.nanoTime();
      for (int i = 100; --i >= 0;) {
        n += sanitize(html).length();
      }
      t3 = System.nanoTime();
    }

    long t4 = 0, t5 = -1;
    if (timePolicyBuilder) {
      t4 = System.nanoTime();
      for (int i = 100; --i >= 0;) {
        n += sanitizeUsingPolicyBuilder(html).length();
      }
      t5 = System.nanoTime();
    }

    // Defeat optimization by using n.
    if (n < 0) {
      throw new AssertionError("Oh noes underflow");
    }

    if (timeLibhtmlparser) {
      System.err.println(String.format(
          "Tree parse           : %12d", (t1 - t0)));
    }
    if (timeSanitize) {
      System.err.println(String.format(
          "Full sanitize custom : %12d", (t3 - t2)));
    }
    if (timePolicyBuilder) {
      System.err.println(String.format(
          "Full sanitize w/ PB  : %12d", (t5 - t4)));
    }
  }

  private static int parseUsingLibhtmlparser(String html) throws Exception {
    HtmlDocumentBuilder parser = new HtmlDocumentBuilder();
    Node node = parser.parse(new InputSource(new StringReader(html)));
    return System.identityHashCode(node) >> 24;
  }

  private static String sanitize(String html) {
    StringBuilder sb = new StringBuilder(html.length());

    final HtmlStreamRenderer renderer = HtmlStreamRenderer.create(
        sb, new Handler<String>() {

          public void handle(String x) {
            throw new AssertionError(x);
          }
        });

    HtmlSanitizer.sanitize(html, new HtmlSanitizer.Policy() {

      public void openDocument() {
        renderer.openDocument();
      }

      public void closeDocument() {
        renderer.closeDocument();
      }

      public void text(String textChunk) {
        renderer.text(textChunk);
      }

      public void openTag(String elementName, List<String> attrs) {
        if ("a".equals(elementName)) {
          for (ListIterator<String> it = attrs.listIterator(); it.hasNext();) {
            String name = it.next();
            if ("href".equals(name)) {
              it.next();
            } else {
              it.remove();
              it.next();
              it.remove();
            }
          }
          renderer.openTag(elementName, attrs);
        }
      }

      public void closeTag(String elementName) {
        if ("a".equals(elementName)) {
          renderer.closeTag(elementName);
        }
      }
    });
    return sb.toString();
  }

  private static HtmlPolicyBuilder policyBuilder;

  private static String sanitizeUsingPolicyBuilder(String html) {
    if (policyBuilder == null) {
      policyBuilder = new HtmlPolicyBuilder()
          .allowStandardUrlProtocols()
          .allowElements("a")
          .allowAttributes("href").onElements("a");
    }

    StringBuilder sb = new StringBuilder(html.length());

    HtmlStreamRenderer renderer = HtmlStreamRenderer.create(
        sb, new Handler<String>() {
          public void handle(String x) {
            throw new AssertionError(x);
          }
        });

    HtmlSanitizer.sanitize(html, policyBuilder.build(renderer));
    return sb.toString();
  }

}
