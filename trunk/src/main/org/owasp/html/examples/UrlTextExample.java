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

package org.owasp.html.examples;

import java.util.ArrayList;
import java.util.List;

import org.owasp.html.Handler;
import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.HtmlSanitizer;
import org.owasp.html.HtmlStreamEventReceiver;
import org.owasp.html.HtmlStreamRenderer;
import org.owasp.html.PolicyFactory;
import org.owasp.html.TagBalancingHtmlStreamEventReceiver;

/**
 * Uses a custom event receiver to emit the domain of a link or inline image
 * after the link or image.
 */
public class UrlTextExample {

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
        String urlAttrName = null;
        if ("a".equals(elementName)) {
          urlAttrName = "href";
        } else if ("img".equals(elementName)) {
          urlAttrName = "src";
        }
        if (urlAttrName != null) {
          for (int i = 0, n = attribs.size(); i < n; i += 2) {
            if (urlAttrName.equals(attribs.get(i))) {
              String url = attribs.get(i+1);
              trailingText = domainOf(url);
              break;
            }
          }
        }
      }
      pendingText.add(trailingText);
    }
    public void closeTag(String elementName) {
      underlying.closeTag(elementName);
      int pendingTextSize = pendingText.size();
      if (pendingTextSize != 0) {
        String trailingText = pendingText.remove(pendingTextSize - 1);
        if (trailingText != null) {
          text(" - " + trailingText);
        }
      }
    }
    public void text(String text) {
      underlying.text(text);
    }
  }


  public static void main(String... argv) {
    PolicyFactory policyBuilder = new HtmlPolicyBuilder()
      .allowAttributes("src").onElements("img")
      .allowAttributes("href").onElements("a")
      .allowStandardUrlProtocols()
      .allowElements(
          "a", "label", "h1", "h2", "h3", "h4", "h5", "h6",
          "p", "i", "b", "u", "strong", "em", "small", "big", "pre", "code",
          "cite", "samp", "sub", "sup", "strike", "center", "blockquote",
          "hr", "br", "col", "font", "span", "div", "img",
          "ul", "ol", "li", "dd", "dt", "dl", "tbody", "thead", "tfoot",
          "table", "td", "th", "tr", "colgroup", "fieldset", "legend"
      ).toFactory();


    final StringBuilder htmlOut = new StringBuilder();
    HtmlSanitizer.Policy policy = policyBuilder.apply(
        new TagBalancingHtmlStreamEventReceiver(
            new AppendDomainAfterText(
                HtmlStreamRenderer.create(htmlOut, Handler.DO_NOTHING)
            )
        )
    );

    for (String input : argv) {
      HtmlSanitizer.sanitize(input, policy);
    }

    System.out.println(htmlOut);
  }

  /**
   * The domain (actually authority component) of an HTML5 URL.
   * If the input is not hierarchical, then this has undefined behavior.
   */
  private static String domainOf(String url) {
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
      }
    }
    int end = url.length();
    for (int i = start; i < end; ++i) {
      switch (url.charAt(i)) {
      case '/': case '?': case '#': end = i; break;
      }
    }
    if (start < end) {
      return url.substring(start, end);
    } else {
      return null;
    }
  }
}
