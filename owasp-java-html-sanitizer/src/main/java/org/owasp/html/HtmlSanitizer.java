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

import java.util.ArrayList;
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
    ForeignContentContext foreignContent = new ForeignContentContext();
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
            foreignContent.processEndTag(elementName);
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
                  // HtmlInputSplitter only combines the solidus with the
                  // greater-than sign when the tokenizer is in a state where
                  // the solidus sets the self-closing flag.
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
            // Decided before the policy sees the attributes, since it may
            // edit them.
            boolean closesItself = foreignContent.processStartTag(
                elementName, attrs, selfClosing);
            if (closesItself
                && HtmlTextEscapingMode.isTagFollowedByLiteralContent(
                    elementName)) {
              // The splitter tentatively chose an HTML raw-text or RCDATA
              // mode from the name alone.  Foreign elements stay in the data
              // state, and this one has already closed.
              lexer.cancelPendingLiteralContent();
            }
            receiver.openTag(elementName, attrs);
            if (closesItself) {
              receiver.closeTag(elementName);
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

  /** Tracks the tree-construction context needed for self-closing flags. */
  private static final class ForeignContentContext {
    /** Match the sanitizer's output nesting limit without growing unchecked. */
    private static final int MAX_DEPTH = 256;

    /** Elements from the first open foreign root through the current node. */
    private final List<OpenElement> openElements = new ArrayList<>();

    /**
     * True once the bounded stack is exhausted.  The legacy HTML behavior is
     * the conservative fallback for ordinary tags from that point onward.
     */
    private boolean unknown;

    /**
     * Updates the context for a start tag and returns whether its self-closing
     * flag is honored by tree construction.
     */
    boolean processStartTag(
        String elementName, List<String> attrs, boolean selfClosing) {
      if (unknown) {
        return selfClosing && isForeignContentRoot(elementName);
      }

      OpenElement current = currentElement();
      boolean usesHtmlRules = usesHtmlRulesForStartTag(current, elementName);
      if (!usesHtmlRules
          && breaksOutOfForeignContent(elementName, attrs)) {
        popToHtmlOrIntegrationPoint();
        usesHtmlRules = true;
      }

      if (usesHtmlRules) {
        return processHtmlStartTag(elementName, attrs, selfClosing);
      }

      // Any other start tag in foreign content inherits the current
      // namespace, even one named "svg" or "math".
      if (!selfClosing) {
        push(new OpenElement(elementName, current.namespace, attrs));
      }
      return selfClosing;
    }

    /** Updates the context using the foreign-content or HTML end-tag rules. */
    void processEndTag(String elementName) {
      if (unknown || openElements.isEmpty()) { return; }

      OpenElement current = currentElement();
      if (current.namespace == Namespace.HTML) {
        processHtmlEndTag(elementName);
        return;
      }

      if ("br".equals(elementName) || "p".equals(elementName)) {
        popToHtmlOrIntegrationPoint();
        processHtmlEndTag(elementName);
        return;
      }

      // The foreign-content end-tag algorithm walks down from the current
      // node.  A foreign node with the tag name closes, along with every
      // node above it.  At the first HTML node the browser reprocesses the
      // token under the HTML rules instead, where an HTML node with the tag
      // name closes the same way, but a node in the special category, which
      // among foreign elements means an integration point, ends the search
      // and the token is ignored.
      boolean htmlRules = false;
      boolean sawIntegrationPoint = false;
      for (int i = openElements.size(); --i >= 0;) {
        OpenElement open = openElements.get(i);
        boolean isHtml = open.namespace == Namespace.HTML;
        boolean isIntegrationPoint
            = open.mathTextIntegrationPoint || open.htmlIntegrationPoint;
        if (isHtml) {
          htmlRules = true;
        } else if (htmlRules && isIntegrationPoint) {
          return;
        }
        if (isHtml == htmlRules
            && asciiEqualsIgnoreCase(open.elementName, elementName)) {
          openElements.subList(i, openElements.size()).clear();
          return;
        }
        sawIntegrationPoint |= isIntegrationPoint;
      }
      // Nothing tracked matched, so the token now applies to the HTML
      // elements below the first foreign root, which are not tracked.  No
      // HTML element is named svg or math, and an integration point in
      // between is special and stops the search, so the browser ignores the
      // token in those cases.  Otherwise the named element may well be
      // open below, in which case the browser closes it and every foreign
      // element above it.  Assume that it is: the cost of guessing wrong is
      // only that self-closing flags stop being honored in the rest of an
      // svg or math element whose author wrote a stray end tag, which is
      // how those tags were always processed before the flag was honored.
      if (isForeignContentRoot(elementName) || sawIntegrationPoint) {
        return;
      }
      openElements.clear();
    }

    private boolean processHtmlStartTag(
        String elementName, List<String> attrs, boolean selfClosing) {
      Namespace namespace;
      if ("svg".equals(elementName)) {
        namespace = Namespace.SVG;
      } else if ("math".equals(elementName)) {
        namespace = Namespace.MATHML;
      } else {
        if (!openElements.isEmpty()
            && !HtmlTextEscapingMode.isVoidElement(elementName)) {
          push(new OpenElement(elementName, Namespace.HTML, attrs));
        }
        // HTML ignores the self-closing flag on ordinary non-void elements.
        // Void elements are already empty and need no synthetic close event.
        return false;
      }

      if (!selfClosing) {
        push(new OpenElement(elementName, namespace, attrs));
      }
      return selfClosing;
    }

    private void processHtmlEndTag(String elementName) {
      for (int i = openElements.size(); --i >= 0;) {
        OpenElement open = openElements.get(i);
        if (open.namespace != Namespace.HTML) { return; }
        if (asciiEqualsIgnoreCase(open.elementName, elementName)) {
          openElements.subList(i, openElements.size()).clear();
          return;
        }
      }
    }

    private void popToHtmlOrIntegrationPoint() {
      while (!openElements.isEmpty()) {
        OpenElement current = currentElement();
        if (current.namespace == Namespace.HTML
            || current.mathTextIntegrationPoint
            || current.htmlIntegrationPoint) {
          return;
        }
        openElements.remove(openElements.size() - 1);
      }
    }

    private void push(OpenElement element) {
      if (openElements.size() == MAX_DEPTH) {
        openElements.clear();
        unknown = true;
      } else {
        openElements.add(element);
      }
    }

    private OpenElement currentElement() {
      int size = openElements.size();
      return size != 0 ? openElements.get(size - 1) : null;
    }

    private static boolean usesHtmlRulesForStartTag(
        @Nullable OpenElement current, String elementName) {
      if (current == null || current.namespace == Namespace.HTML) {
        return true;
      }
      if (current.mathTextIntegrationPoint
          && !"mglyph".equals(elementName)
          && !"malignmark".equals(elementName)) {
        return true;
      }
      return current.htmlIntegrationPoint
          || (current.namespace == Namespace.MATHML
              && "annotation-xml".equals(current.elementName)
              && "svg".equals(elementName));
    }
  }

  private enum Namespace {
    HTML,
    SVG,
    MATHML,
  }

  /** One element relevant to the foreign-content tree-construction state. */
  private static final class OpenElement {
    final String elementName;
    final Namespace namespace;
    final boolean mathTextIntegrationPoint;
    final boolean htmlIntegrationPoint;

    OpenElement(
        String elementName, Namespace namespace, List<String> attrs) {
      this.elementName = elementName;
      this.namespace = namespace;
      this.mathTextIntegrationPoint = namespace == Namespace.MATHML
          && MATHML_TEXT_INTEGRATION_POINT_NAMES.contains(elementName);
      this.htmlIntegrationPoint = isHtmlIntegrationPoint(
          elementName, namespace, attrs);
    }
  }

  private static boolean isForeignContentRoot(String canonElementName) {
    return "svg".equals(canonElementName) || "math".equals(canonElementName);
  }

  private static boolean isHtmlIntegrationPoint(
      String elementName, Namespace namespace, List<String> attrs) {
    if (namespace == Namespace.SVG) {
      return "desc".equals(elementName) || "title".equals(elementName)
          || asciiEqualsIgnoreCase("foreignObject", elementName);
    }
    if (namespace != Namespace.MATHML
        || !"annotation-xml".equals(elementName)) {
      return false;
    }
    for (Iterator<String> it = attrs.iterator(); it.hasNext();) {
      String name = it.next();
      String value = it.hasNext() ? it.next() : "";
      if ("encoding".equals(name)) {
        return asciiEqualsIgnoreCase("text/html", value)
            || asciiEqualsIgnoreCase("application/xhtml+xml", value);
      }
    }
    return false;
  }

  private static boolean asciiEqualsIgnoreCase(String a, String b) {
    int length = a.length();
    return b.length() == length
        && Strings.regionMatchesIgnoreCase(a, 0, b, 0, length);
  }

  private static boolean breaksOutOfForeignContent(
      String canonElementName, List<String> attrs) {
    if (FOREIGN_CONTENT_BREAKOUT_ELEMENT_NAMES.contains(canonElementName)) {
      return true;
    }
    if ("font".equals(canonElementName)) {
      for (Iterator<String> it = attrs.iterator(); it.hasNext();) {
        String name = it.next();
        if (it.hasNext()) { it.next(); }
        if ("color".equals(name) || "face".equals(name)
            || "size".equals(name)) {
          return true;
        }
      }
    }
    return false;
  }

  private static final Set<String> MATHML_TEXT_INTEGRATION_POINT_NAMES
      = j8().setOf("mi", "mo", "mn", "ms", "mtext");

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
