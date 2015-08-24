// Copyright (c) 2013, Mike Samuel
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

package org.owasp.html.examples;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.owasp.html.Handler;
import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.HtmlSanitizer;
import org.owasp.html.HtmlStreamEventReceiver;
import org.owasp.html.HtmlStreamRenderer;
import org.owasp.html.HtmlTextEscapingMode;
import org.owasp.html.PolicyFactory;
import org.owasp.html.TagBalancingHtmlStreamEventReceiver;

/**
 * Uses a custom event receiver to emit the domain of a link or inline image
 * after the link or image.
 */
public class UrlTextExample {

  /** An event receiver that emits the domain of a link or image after it. */
  static class AppendDomainAfterText implements HtmlStreamEventReceiver {
    final HtmlStreamEventReceiver underlying;
    private final List<String> pendingText = new ArrayList<String>();

    AppendDomainAfterText(HtmlStreamEventReceiver underlying) {
      this.underlying = underlying;
    }

    public void openDocument() {
      underlying.openDocument();
    }
    public void closeDocument() {
      underlying.closeDocument();
    }
    public void openTag(String elementName, List<String> attribs) {
      underlying.openTag(elementName, attribs);

      String trailingText = null;

      if (!attribs.isEmpty()) {
        // Figure out which attribute we should look for.
        String urlAttrName = null;
        if ("a".equals(elementName)) {
          urlAttrName = "href";
        } else if ("img".equals(elementName)) {
          urlAttrName = "src";
        }
        if (urlAttrName != null) {
          // Look for the attribute, and after it for its value.
          for (int i = 0, n = attribs.size(); i < n; i += 2) {
            if (urlAttrName.equals(attribs.get(i))) {
              String url = attribs.get(i+1).trim();
              String domain = domainOf(url);
              if (domain != null) {
                trailingText = " - " + domain;
              }
              break;
            }
          }
        }
      }
      if (HtmlTextEscapingMode.isVoidElement(elementName)) {
        // A void element like <img> will not have a corresponding closeTag
        // call.
        if (trailingText != null) {
          text(trailingText);
        }
      } else {
        // Push the trailing text onto a stack so when we see the corresponding
        // close tag, we can emit the text.
        pendingText.add(trailingText);
      }
    }
    public void closeTag(String elementName) {
      underlying.closeTag(elementName);
      // Pull the trailing text for the recently closed element off the stack.
      int pendingTextSize = pendingText.size();
      if (pendingTextSize != 0) {
        String trailingText = pendingText.remove(pendingTextSize - 1);
        if (trailingText != null) {
          text(trailingText);
        }
      }
    }
    public void text(String text) {
      underlying.text(text);
    }
  }

  /**
   * Sanitizes inputs to out.
   */
  public static void run(Appendable out, String... inputs) throws IOException {
    PolicyFactory policyBuilder = new HtmlPolicyBuilder()
      .allowAttributes("src").onElements("img")
      .allowAttributes("href").onElements("a")
      // Allow some URLs through.
      .allowStandardUrlProtocols()
      .allowElements(
          "a", "label", "h1", "h2", "h3", "h4", "h5", "h6",
          "p", "i", "b", "u", "strong", "em", "small", "big", "pre", "code",
          "cite", "samp", "sub", "sup", "strike", "center", "blockquote",
          "hr", "br", "col", "font", "span", "div", "img",
          "ul", "ol", "li", "dd", "dt", "dl", "tbody", "thead", "tfoot",
          "table", "td", "th", "tr", "colgroup", "fieldset", "legend"
      ).toFactory();

    StringBuilder htmlOut = new StringBuilder();
    HtmlSanitizer.Policy policy = policyBuilder.apply(
        // The tag balancer passes events to AppendDomainAfterText which
        // assumes that openTag and closeTag events line up with one-another.
        new TagBalancingHtmlStreamEventReceiver(
            // The domain appender forwards events to the HTML renderer,
            new AppendDomainAfterText(
                // which puts tags and text onto the output buffer.
                HtmlStreamRenderer.create(htmlOut, Handler.DO_NOTHING)
            )
        )
    );

    for (String input : inputs) {
      HtmlSanitizer.sanitize(input, policy);
    }

    out.append(htmlOut);
  }

  /**
   * Sanitizes each of its inputs (argv) and writes them to stdout with a
   * line-break after each one.
   */
  public static void main(String... argv) throws IOException {
    run(System.out, argv);
    System.out.println();
  }


  /**
   * The domain (actually authority component) of an HTML5 URL.
   * If the input is not hierarchical, then the return value is undefined.
   */
  static String domainOf(String url) {
    int start = -1;
    if (url.startsWith("//")) {
      start = 2;
    } else {
      start = url.indexOf("://");
      if (start >= 0) { start += 3; }
    }
    if (start < 0) { return null; }
    for (int i = 0; i < start - 3; ++i) {
      switch (url.charAt(i)) {
      case '/': case '?': case '#': return null;
      default: break;
      }
    }
    int end = url.length();
    for (int i = start; i < end; ++i) {
      switch (url.charAt(i)) {
      case '/': case '?': case '#': end = i; break;
      default: break;
      }
    }
    if (start < end) {
      return url.substring(start, end);
    } else {
      return null;
    }
  }
}
