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

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Lists;

/**
 * Wraps an HTML stream event receiver to fill in missing close tags.
 * If the balancer is given the HTML {@code <p>1<p>2}, the wrapped receiver will
 * see events equivalent to {@code <p>1</p><p>2</p>}.
 *
 * @author Mike Samuel <mikesamuel@gmail.com>
 */
@TCB
public class TagBalancingHtmlStreamEventReceiver
    implements HtmlStreamEventReceiver {
  private final HtmlStreamEventReceiver underlying;
  private final List<String> openElements = Lists.newArrayList();

  public TagBalancingHtmlStreamEventReceiver(
      HtmlStreamEventReceiver underlying) {
    this.underlying = underlying;
  }

  public void openDocument() {
    underlying.openDocument();
  }

  public void closeDocument() {
    while (!openElements.isEmpty()) {
      closeTag(openElements.get(openElements.size() - 1));
    }
    underlying.closeDocument();
  }

  public void openTag(String elementName, List<String> attrs) {
    String canonElementName = HtmlLexer.canonicalName(elementName);
    String optionalEndTagPartition = END_TAG_PARTITIONS.get(canonElementName);
    if (optionalEndTagPartition != null) {
      int n = openElements.size();
      while (--n >= 0) {
        if (!optionalEndTagPartition.equals(
                END_TAG_PARTITIONS.get(openElements.get(n)))) {
          break;
        }
        underlying.closeTag(openElements.remove(n));
      }
    }
    if (HtmlTextEscapingMode.VOID != HtmlTextEscapingMode.getModeForTag(
            canonElementName)) {
      openElements.add(canonElementName);
    }
    underlying.openTag(elementName, attrs);
  }

  public void closeTag(String elementName) {
    String canonElementName = HtmlLexer.canonicalName(elementName);
    int index = openElements.lastIndexOf(canonElementName);
    if (index < 0) { return; }  // Don't close unopened tags.
    int last = openElements.size();
    while (--last > index) {
      String unclosedElementName = openElements.remove(last);
      underlying.closeTag(unclosedElementName);
    }
    openElements.remove(index);
    underlying.closeTag(elementName);
  }

  public void text(String text) {
    underlying.text(text);
  }


  private static final ImmutableMap<String, String> END_TAG_PARTITIONS
      = ImmutableMap.<String, String>builder()
      .put("body", "body")
      .put("colgroup", "colgroup")
      .put("dd", "dd")
      .put("dt", "dd")
      .put("head", "body")
      .put("li", "li")
      .put("option", "option")
      .put("p", "p")
      .put("tbody", "tbody")
      .put("td", "td")
      .put("tfoot", "tbody")
      .put("th", "td")
      .put("thead", "tbody")
      .put("tr", "tr")
      .build();
}
