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

import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import javax.annotation.Nullable;

import static org.owasp.shim.Java8Shim.j8;

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
     * Called when an HTML tag like {@code </foo>} is seen in the input, and
     * right after {@link #openTag} for a self-closing tag like
     * {@code <path/>} where browsers honor the self-closing flag: on
     * {@code <svg/>} and {@code <math/>}, and on most tags inside them.
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
  public static void sanitize(
      @Nullable String html, final Policy policy) {
    sanitize(html, policy, HtmlStreamEventProcessor.Processors.IDENTITY);
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
   * @param preprocessor A processor that may wrap the policy to reinterpret
   *     parse events.
   *     Since the policy encapsulates its output buffer, this is not in the
   *     policy's TCB.
   */
  public static void sanitize(
      @Nullable String html, final Policy policy,
      HtmlStreamEventProcessor preprocessor) {
    String htmlContent = html != null ? html : "";

    HtmlStreamEventReceiver receiver = initializePolicy(policy, preprocessor);

    receiver.openDocument();

    HtmlLexer lexer = new HtmlLexer(htmlContent);
    // Use a linked list so that policies can use Iterator.remove() in an O(1)
    // way.
    LinkedList<String> attrs = new LinkedList<>();
    // The number of <svg> and <math> start tags seen without a matching end
    // tag.  Browsers parse the content of those elements as foreign content,
    // where a start tag's self-closing flag is honored: <path/> is a whole,
    // empty element.  In HTML content the flag means nothing, and <path/>
    // opens an element that only an end tag closes.  Issue #122.
    int foreignContentDepth = 0;
    while (lexer.hasNext()) {
      HtmlToken token = lexer.next();
      switch (token.type) {
        case TEXT:
          receiver.text(
              Encoding.decodeHtml(htmlContent.substring(token.start, token.end), false));
          break;
        case UNESCAPED:
          receiver.text(Encoding.stripBannedCodeunits(
              htmlContent.substring(token.start, token.end)));
          break;
        case TAGBEGIN:
          if (htmlContent.charAt(token.start + 1) == '/') {  // A close tag.
            String elementName = HtmlLexer.canonicalElementName(
                htmlContent.substring(token.start + 2, token.end));
            receiver.closeTag(elementName);
            while (lexer.hasNext()
                   && lexer.next().type != HtmlTokenType.TAGEND) {
              // skip tokens until we see a ">"
            }
            if (foreignContentDepth != 0
                && isForeignContentRoot(elementName)) {
              --foreignContentDepth;
            }
          } else {
            attrs.clear();

            boolean attrsReadyForName = true;
            boolean selfClosing = false;
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
                  attrs.add(HtmlLexer.canonicalAttributeName(
                      htmlContent.substring(tagBodyToken.start, tagBodyToken.end)));
                  break;
                case ATTRVALUE:
                  String attributeContentRaw =
                          stripQuotes(htmlContent.substring(tagBodyToken.start, tagBodyToken.end));
                  attrs.add(Encoding.decodeHtml(attributeContentRaw, true));
                  attrsReadyForName = true;
                  break;
                case TAGEND:
                  // The lexer ends a start tag with a "/>" token only when
                  // the solidus immediately precedes the ">", which is when
                  // the WHATWG tokenizer sets the self-closing flag.
                  selfClosing = htmlContent.charAt(tagBodyToken.start) == '/';
                  break tagBody;
                default:
                  // Just drop anything not recognized
              }
            }
            if (!attrsReadyForName) {
              attrs.add(attrs.getLast());
            }
            String elementName = HtmlLexer.canonicalElementName(
                htmlContent.substring(token.start + 1, token.end));
            boolean foreignContentRoot = isForeignContentRoot(elementName);
            // Decided before the policy sees the attributes, since it may
            // edit them.
            boolean closesItself = selfClosing
                && (foreignContentRoot
                    || (foreignContentDepth != 0
                        && closesItselfInForeignContent(elementName, attrs)));
            receiver.openTag(elementName, attrs);
            if (closesItself) {
              receiver.closeTag(elementName);
            } else if (foreignContentRoot) {
              ++foreignContentDepth;
            }
          }
          break;
        default:
          // Ignore comments, XML prologues, processing instructions, and other
          // stuff that shouldn't show up in the output.
          break;
      }
    }

    receiver.closeDocument();
  }

  /**
   * True for the elements whose content browsers parse as foreign content
   * rather than as HTML.
   */
  private static boolean isForeignContentRoot(String canonElementName) {
    return "svg".equals(canonElementName) || "math".equals(canonElementName);
  }

  /**
   * True if a self-closing start tag for the named element, seen inside
   * {@code <svg>} or {@code <math>}, opens an element that closes at once.
   *
   * <p>That is what browsers do with a start tag processed under the rules
   * for foreign content.  The exceptions are the tags that break out of
   * foreign content, which browsers process as HTML, where the flag on a
   * non-void element is ignored, and the elements whose content the lexer
   * has already committed to treating as text.
   *
   * @param attrs alternating attribute names and values as the author wrote
   *     them, before any policy has edited them.
   */
  private static boolean closesItselfInForeignContent(
      String canonElementName, List<String> attrs) {
    if (HtmlTextEscapingMode.getModeForTag(canonElementName)
        != HtmlTextEscapingMode.PCDATA) {
      // A void element is empty already.  The lexer treats the content of
      // <style>, <title> and the other elements with literal content as text
      // up to the matching end tag, so the element stays open to hold it.
      return false;
    }
    if (FOREIGN_CONTENT_BREAKOUT_ELEMENT_NAMES.contains(canonElementName)) {
      return false;
    }
    if ("font".equals(canonElementName)) {
      for (Iterator<String> it = attrs.iterator(); it.hasNext();) {
        String name = it.next();
        if (it.hasNext()) { it.next(); }  // The value.
        if ("color".equals(name) || "face".equals(name)
            || "size".equals(name)) {
          return false;
        }
      }
    }
    return true;
  }

  /**
   * The start tags that end foreign content: inside {@code <svg>} or
   * {@code <math>}, a browser pops back out to HTML content and processes one
   * of these as HTML.  A {@code <font>} tag with a color, face or size
   * attribute does the same.
   *
   * @see <a href="https://html.spec.whatwg.org/multipage/parsing.html#parsing-main-inforeign"
   *     >The rules for parsing tokens in foreign content</a>
   */
  private static final Set<String> FOREIGN_CONTENT_BREAKOUT_ELEMENT_NAMES
      = j8().setOf(
          "b", "big", "blockquote", "body", "br", "center", "code", "dd",
          "div", "dl", "dt", "em", "embed", "h1", "h2", "h3", "h4", "h5",
          "h6", "head", "hr", "i", "img", "li", "listing", "menu", "meta",
          "nobr", "ol", "p", "pre", "ruby", "s", "small", "span", "strong",
          "strike", "sub", "sup", "table", "tt", "u", "ul", "var");

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


  private static HtmlStreamEventReceiver initializePolicy(
      Policy policy, HtmlStreamEventProcessor preprocessor) {
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
    return preprocessor.wrap(balancer);
  }
}
