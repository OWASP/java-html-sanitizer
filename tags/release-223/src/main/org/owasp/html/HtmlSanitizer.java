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

import java.util.LinkedList;
import java.util.List;
import javax.annotation.Nullable;

import com.google.common.collect.Lists;

/**
 * Consumes an HTML stream, and dispatches events to a policy object which
 * decides which elements and attributes to allow.
 */
public final class HtmlSanitizer {

  /**
   * Receives events based on the HTML stream, and applies a policy to decide
   * what HTML constructs to allow.
   * Typically, implementations use an {@link HtmlStreamRenderer} to produce
   * the sanitized output.
   *
   * <p>
   * <b>Implementations of this class are in the TCB.</b></p>
   */
  @TCB
  public interface Policy extends HtmlStreamEventReceiver {
    /**
     * Called when an HTML tag like {@code <foo bar=baz>} is seen in the input.
     *
     * @param elementName a normalized (lower-case for non-namespaced names)
     *     element name.
     * @param attrs a list of alternating attribute name and value pairs.
     *     For efficiency, this list may be mutated by this during this method
     *     call, but ownership reverts to the caller on method exit.
     *     The values are raw -- HTML entities have been decoded.
     *     Specifically, implementations are allowed to use a list iterator
     *     and remove all disallowed attributes, add necessary attributes, and
     *     then pass the list to an {@link HtmlStreamRenderer}.
     */
    void openTag(String elementName, List<String> attrs);

    /**
     * Called when an HTML tag like {@code </foo>} is seen in the input.
     *
     * @param elementName a normalized (lower-case for non-namespaced names)
     *     element name.
     */
    void closeTag(String elementName);

    /**
     * Called when textual content is seen.
     * @param textChunk raw content -- HTML entities have been decoded.
     */
    void text(String textChunk);
  }

  /**
   * Sanitizes the given HTML by applying the given policy to it.
   *
   * <p>
   * This method is not in the TCB.
   *
   * <p>
   * This method has no return value since policies are assumed to render things
   * they accept and do nothing on things they reject.
   * Use {@link HtmlStreamRenderer} to render content to an output buffer.
   *
   * @param html A snippet of HTML to sanitize.  {@code null} is treated as the
   *     empty string and will not result in a {@code NullPointerException}.
   * @param policy The Policy that will receive events based on the tokens in
   *     HTML.  Typically, this policy ends up routing the events to an
   *     {@link HtmlStreamRenderer} after filtering.
   *     {@link HtmlPolicyBuilder} provides an easy way to create policies.
   */
  public static void sanitize(@Nullable String html, final Policy policy) {
    if (html == null) { html = ""; }

    TagBalancingHtmlStreamEventReceiver balancer
        = new TagBalancingHtmlStreamEventReceiver(policy);

    // According to Opera the maximum table nesting depth seen in the wild is
    // 795, but 99.99% of documents have a table nesting depth of less than 22.
    // Since each table has a nesting depth of 4 (incl. TBODY), this leads to a
    // document depth of 90 (incl. HTML & BODY).
    // Obviously table nesting depth is not the same as whole document depth,
    // but it is the best proxy I have available.
    // See http://devfiles.myopera.com/articles/590/maxtabledepth-url.htm for
    // the original data.

    // Webkit defines the maximum HTML parser tree depth as 512.
    // http://trac.webkit.org/browser/trunk/Source/WebCore/page/Settings.h#L408
    // static const unsigned defaultMaximumHTMLParserDOMTreeDepth = 512;

    // The first number gives us a lower bound on the nesting depth we allow,
    // 90, and the second gives us an upper bound: 512.
    // We do not want to bump right up against that limit.
    // 256 is substantially larger than the lower bound and well clear of the
    // upper bound.
    balancer.setNestingLimit(256);

    balancer.openDocument();

    HtmlLexer lexer = new HtmlLexer(html);
    // Use a linked list so that policies can use Iterator.remove() in an O(1)
    // way.
    LinkedList<String> attrs = Lists.newLinkedList();
    while (lexer.hasNext()) {
      HtmlToken token = lexer.next();
      switch (token.type) {
        case TEXT:
          balancer.text(
              Encoding.decodeHtml(html.substring(token.start, token.end)));
          break;
        case UNESCAPED:
          balancer.text(Encoding.stripBannedCodeunits(
              html.substring(token.start, token.end)));
          break;
        case TAGBEGIN:
          if (html.charAt(token.start + 1) == '/') {  // A close tag.
            balancer.closeTag(HtmlLexer.canonicalName(
                html.substring(token.start + 2, token.end)));
            while (lexer.hasNext()
                   && lexer.next().type != HtmlTokenType.TAGEND) {
              // skip tokens until we see a ">"
            }
          } else {
            attrs.clear();

            boolean attrsReadyForName = true;
            tagBody:
            while (lexer.hasNext()) {
              HtmlToken tagBodyToken = lexer.next();
              switch (tagBodyToken.type) {
                case ATTRNAME:
                  if (!attrsReadyForName) {
                    // Last attribute added was valueless.
                    attrs.add(attrs.getLast());
                  } else {
                    attrsReadyForName = false;
                  }
                  attrs.add(HtmlLexer.canonicalName(
                      html.substring(tagBodyToken.start, tagBodyToken.end)));
                  break;
                case ATTRVALUE:
                  attrs.add(Encoding.decodeHtml(stripQuotes(
                      html.substring(tagBodyToken.start, tagBodyToken.end))));
                  attrsReadyForName = true;
                  break;
                case TAGEND:
                  break tagBody;
                default:
                  // Just drop anything not recognized
              }
            }
            if (!attrsReadyForName) {
              attrs.add(attrs.getLast());
            }
            balancer.openTag(
                HtmlLexer.canonicalName(
                    html.substring(token.start + 1, token.end)),
                attrs);
          }
          break;
        default:
          // Ignore comments, XML prologues, processing instructions, and other
          // stuff that shouldn't show up in the output.
          break;
      }
    }

    balancer.closeDocument();
  }

  private static String stripQuotes(String encodedAttributeValue) {
    int n = encodedAttributeValue.length();
    if (n > 0) {
      char last = encodedAttributeValue.charAt(n - 1);
      if (last == '"' || last == '\'') {
        int start = 0;
        if (n != 1 && last == encodedAttributeValue.charAt(0)) {
          start = 1;
        } else {
          // Browsers deal with missing left quotes : <img src=foo.png">
          // but generally do not deal with missing right : <img src="foo.png>
        }
        return encodedAttributeValue.substring(start, n - 1);
      }
    }
    return encodedAttributeValue;
  }

}
