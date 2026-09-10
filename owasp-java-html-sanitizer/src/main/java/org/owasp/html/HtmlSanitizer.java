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
            boolean ended = false;
            while (lexer.hasNext()) {
              // skip tokens until we see a ">"
              if (lexer.next().type == HtmlTokenType.TAGEND) {
                ended = true;
                break;
              }
            }
            if (!ended) {
              // The input ended inside the tag.  A browser drops the tag
              // whole, so there is nothing to close.
              break;
            }
            receiver.closeTag(elementName);
            foreignContent.processEndTag(elementName);
          } else {
            attrs.clear();

            boolean attrsReadyForName = true;
            boolean selfClosing = false;
            boolean ended = false;
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
                  ended = true;
                  break tagBody;
                default:
                  // Just drop anything not recognized
              }
            }
            if (!ended) {
              // The input ended inside the tag.  A browser drops the tag
              // whole, attributes and all; the text before it stands.
              break;
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

    /** The form pointer is not bounded by an integration point. */
    private boolean formElementPointerSet;

    /** The form pointer's target, when that element is in the tracked region. */
    private @Nullable OpenElement trackedFormElement;

    /** A table inserted in known in-body mode, before any child tag. */
    private @Nullable OpenElement simpleTable;

    /** The mode to restore when {@link #simpleTable} closes. */
    private HtmlInsertionMode simpleTableReturnMode
        = HtmlInsertionMode.IN_BODY;

    /** The HTML mode that remains in force while foreign rules run. */
    private HtmlInsertionMode htmlInsertionMode = HtmlInsertionMode.IN_BODY;

    /** Bound the memory spent on untracked tables that never close. */
    private static final int MAX_UNTRACKED_TABLES = 32;

    /**
     * The tables open below the tracked region, innermost last.  Each is in
     * table scope, since a template makes the context unknown.
     */
    private final List<UntrackedTable> untrackedTables = new ArrayList<>();

    /**
     * True once the browser's context can no longer be derived from the
     * tracked elements: the bounded stack was exhausted, or a tag's effect
     * depended on untracked ancestors or on the insertion mode.  The legacy
     * HTML behavior is the conservative fallback for ordinary tags from that
     * point onward.
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
      if (unknown) { return; }
      if (openElements.isEmpty()) {
        if ("form".equals(elementName)) {
          formElementPointerSet = false;
          trackedFormElement = null;
        }
        trackUntrackedHtmlEndTag(elementName);
        return;
      }

      if (currentElement().namespace == Namespace.HTML) {
        processEndTagUnderHtmlRules(elementName);
        return;
      }

      if ("br".equals(elementName) || "p".equals(elementName)) {
        popToHtmlOrIntegrationPoint();
        processEndTagUnderHtmlRules(elementName);
        return;
      }

      // The foreign-content end-tag algorithm walks down from the current
      // node.  A foreign node with the tag name closes, along with every
      // node above it.  At the first HTML node the browser reprocesses the
      // token under the rules of its current HTML insertion mode instead.
      for (int i = openElements.size(); --i >= 0;) {
        OpenElement open = openElements.get(i);
        if (open.namespace == Namespace.HTML) { break; }
        if (asciiEqualsIgnoreCase(open.elementName, elementName)) {
          openElements.subList(i, openElements.size()).clear();
          return;
        }
      }
      processEndTagUnderHtmlRules(elementName);
    }

    /**
     * Applies an end tag that a browser processes under the rules of its
     * current HTML insertion mode.  Only outcomes that follow from the
     * tracked elements alone are modeled.  Anything that depends on the
     * untracked ancestors of the foreign root, on the insertion mode, or on
     * the list of active formatting elements makes the context unknown,
     * which fails closed: self-closing flags are no longer honored.
     */
    private void processEndTagUnderHtmlRules(String elementName) {
      if (simpleTable != null) {
        if ("table".equals(elementName)
            && currentElement() == simpleTable) {
          openElements.remove(openElements.size() - 1);
          simpleTable = null;
          htmlInsertionMode = simpleTableReturnMode;
        } else {
          becomeUnknown();
        }
        return;
      }
      if (TABLE_SCOPED_ELEMENT_NAMES.contains(elementName)
          || "template".equals(elementName)) {
        // Table scope is bounded only by html, table and template, so these
        // end tags reach past integration points to untracked ancestors,
        // and what they close depends on the insertion mode.
        becomeUnknown();
        return;
      }
      if (IGNORED_HTML_END_TAG_NAMES.contains(elementName)) {
        return;
      }
      if ("form".equals(elementName)) {
        OpenElement form = trackedFormElement;
        formElementPointerSet = false;
        trackedFormElement = null;
        if (form != null) {
          int formIndex = openElements.indexOf(form);
          if (formIndex >= 0 && isInDefaultScope(formIndex)) {
            // Outside template contents, </form> removes the form without
            // popping the elements above it.
            generateImpliedEndTags(null);
            openElements.remove(formIndex);
          }
        }
        return;
      }
      boolean anyOther = !SPECIFIC_END_TAG_RULE_NAMES.contains(elementName);
      boolean formatting = FORMATTING_ELEMENT_NAMES.contains(elementName);
      boolean heading = isHeadingName(elementName);
      for (int i = openElements.size(); --i >= 0;) {
        OpenElement open = openElements.get(i);
        if (open.namespace != Namespace.HTML) {
          // Integration points and annotation-xml are in the special
          // category and bound every scope.  Other foreign elements are
          // transparent to both kinds of search.
          if (open.special) { return; }
          continue;
        }
        String openName = open.elementName;
        if (asciiEqualsIgnoreCase(openName, elementName)
            || (heading && isHeadingName(openName))) {
          if (!popTrackedElementsFrom(
              i,
              ACTIVE_FORMATTING_MARKER_ELEMENT_NAMES.contains(elementName),
              formatting ? open : null)) {
            return;
          }
          return;
        }
        if (anyOther) {
          // "Any other end tag" stops at any element in the special
          // category.
          if (AMBIGUOUSLY_SPECIAL_HTML_ELEMENT_NAMES.contains(openName)) {
            becomeUnknown();
            return;
          }
          if (SPECIAL_HTML_ELEMENT_NAMES.contains(openName)) { return; }
          continue;
        }
        if (DEFAULT_SCOPE_BOUNDARY_NAMES.contains(openName)
            || ("li".equals(elementName)
                && ("ol".equals(openName) || "ul".equals(openName)))
            || ("p".equals(elementName) && "button".equals(openName))) {
          // Not in scope: the token is ignored, or for </p> an empty p is
          // inserted and closed at once.
          return;
        }
        if (formatting && SPECIAL_HTML_ELEMENT_NAMES.contains(openName)) {
          // The adoption agency algorithm restructures the stack around
          // this "furthest block", dropping the foreign nodes above it.
          becomeUnknown();
          return;
        }
      }
      if (openElements.isEmpty()) {
        return;
      }
      // Nothing tracked bounded the search, so whether the token closes the
      // whole foreign region depends on the untracked HTML ancestors.
      becomeUnknown();
    }

    private boolean processHtmlStartTag(
        String elementName, List<String> attrs, boolean selfClosing) {
      if (simpleTable != null) {
        // A child start tag is where the in-table modes start implying or
        // foster-parenting elements.  Keep the empty-table case exact and
        // fail closed for the rest.
        becomeUnknown();
        return selfClosing && isForeignContentRoot(elementName);
      }

      Namespace namespace;
      if ("svg".equals(elementName)) {
        namespace = Namespace.SVG;
      } else if ("math".equals(elementName)) {
        namespace = Namespace.MATHML;
      } else {
        if (openElements.isEmpty()) {
          trackUntrackedHtmlStartTag(elementName);
          if (unknown) { return false; }
        }
        if (UNMODELED_CONTEXT_CHANGING_START_TAG_NAMES.contains(elementName)) {
          becomeUnknown();
          return false;
        }
        if ("form".equals(elementName)) {
          if (htmlInsertionMode == HtmlInsertionMode.IN_TABLE) {
            // "In table" inserts a new form and immediately pops it.
            if (!formElementPointerSet) {
              formElementPointerSet = true;
              trackedFormElement = null;
            }
            return false;
          }
          processFormStartTag(attrs);
          return false;
        }
        if (openElements.isEmpty()) {
          return false;
        }
        if (TABLE_STRUCTURE_START_TAG_NAMES.contains(elementName)) {
          if (htmlInsertionMode != HtmlInsertionMode.IN_BODY) {
            becomeUnknown();
          }
          return false;
        }
        if (P_CLOSING_START_TAG_NAMES.contains(elementName)
            || "pre".equals(elementName)
            || "listing".equals(elementName)
            || "plaintext".equals(elementName)
            || "xmp".equals(elementName)) {
          if (!closePIfInButtonScope()) { return false; }
        } else if (isHeadingName(elementName)) {
          if (!closePIfInButtonScope()) { return false; }
          OpenElement current = currentElement();
          if (current.namespace == Namespace.HTML
              && isHeadingName(current.elementName)) {
            openElements.remove(openElements.size() - 1);
          }
        } else if ("li".equals(elementName)) {
          if (!closeListOrDescriptionItemForStart(true)
              || !closePIfInButtonScope()) {
            return false;
          }
        } else if ("dd".equals(elementName) || "dt".equals(elementName)) {
          if (!closeListOrDescriptionItemForStart(false)
              || !closePIfInButtonScope()) {
            return false;
          }
        } else if ("button".equals(elementName)) {
          int buttonIndex = findHtmlElementInDefaultScope("button", true);
          if (buttonIndex >= 0) {
            if (!popTrackedElementsFrom(buttonIndex, false, null)) {
              return false;
            }
          }
        } else if ("a".equals(elementName)) {
          if (findOpenHtmlElement("a") >= 0) {
            becomeUnknown();
            return false;
          }
        } else if ("nobr".equals(elementName)) {
          if (findHtmlElementInDefaultScope("nobr", false) >= 0) {
            becomeUnknown();
            return false;
          }
        } else if ("select".equals(elementName)) {
          int selectIndex = findHtmlElementInDefaultScope("select", false);
          if (selectIndex >= 0) {
            // A nested select start tag is ignored after popping the first.
            if (!popTrackedElementsFrom(selectIndex, false, null)) {
              return false;
            }
            return false;
          }
        } else if ("option".equals(elementName)) {
          if (findHtmlElementInDefaultScope("select", false) >= 0) {
            generateImpliedEndTags("optgroup");
          } else if (isCurrentHtmlElement("option")) {
            openElements.remove(openElements.size() - 1);
          }
        } else if ("optgroup".equals(elementName)) {
          if (findHtmlElementInDefaultScope("select", false) >= 0) {
            generateImpliedEndTags(null);
          } else if (isCurrentHtmlElement("option")) {
            openElements.remove(openElements.size() - 1);
          }
        } else if ("input".equals(elementName)) {
          if (htmlInsertionMode == HtmlInsertionMode.IN_TABLE
              && hasHiddenInputType(attrs)) {
            return false;
          }
          int selectIndex = findHtmlElementInDefaultScope("select", false);
          if (selectIndex >= 0) {
            if (!popTrackedElementsFrom(selectIndex, false, null)) {
              return false;
            }
          }
        } else if ("hr".equals(elementName)) {
          if (!closePIfInButtonScope()) { return false; }
          if (findHtmlElementInDefaultScope("select", false) >= 0) {
            generateImpliedEndTags(null);
          }
        } else if (UNMODELED_HTML_START_TAG_NAMES.contains(elementName)) {
          becomeUnknown();
          return false;
        } else if ("image".equals(elementName)) {
          // The in-body rules rewrite image to the void img element.
          return false;
        } else if ("table".equals(elementName)) {
          if (htmlInsertionMode == HtmlInsertionMode.IN_TABLE) {
            becomeUnknown();
            return false;
          }
          if (findHtmlElementInDefaultScope("p", true) >= 0) {
            // Only a no-quirks document closes the p, and the sanitizer
            // cannot know the mode of the document that embeds its output.
            becomeUnknown();
            return false;
          }
          OpenElement table = new OpenElement(
              elementName, Namespace.HTML, attrs);
          push(table);
          if (!unknown) {
            simpleTable = table;
            simpleTableReturnMode = htmlInsertionMode;
            htmlInsertionMode = HtmlInsertionMode.IN_TABLE;
          }
          return false;
        }

        if (!HTML_TREE_BUILDER_VOID_ELEMENT_NAMES.contains(elementName)
            && !IGNORED_HTML_START_TAG_NAMES.contains(elementName)) {
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

    private @Nullable UntrackedTable currentUntrackedTable() {
      int size = untrackedTables.size();
      return size != 0 ? untrackedTables.get(size - 1) : null;
    }

    /** Derives the HTML insertion mode from the innermost untracked table. */
    private void syncInsertionMode() {
      UntrackedTable table = currentUntrackedTable();
      if (table == null) {
        htmlInsertionMode = HtmlInsertionMode.IN_BODY;
      } else if (table.cellName != null) {
        // The cell and caption modes hand everything else to the in-body
        // rules, but hand table structure to the table rules.
        htmlInsertionMode = HtmlInsertionMode.IN_CELL;
      } else {
        htmlInsertionMode = HtmlInsertionMode.IN_TABLE;
      }
    }

    private void trackUntrackedHtmlStartTag(String elementName) {
      UntrackedTable table = currentUntrackedTable();
      if ("table".equals(elementName)) {
        if (table != null && table.cellName == null) {
          // The table modes pop the open table before reprocessing the
          // token; a cell or caption nests the new table instead.
          untrackedTables.remove(untrackedTables.size() - 1);
        }
        if (untrackedTables.size() == MAX_UNTRACKED_TABLES) {
          becomeUnknown();
          return;
        }
        untrackedTables.add(new UntrackedTable());
      } else if (table == null) {
        return;
      } else if ("td".equals(elementName) || "th".equals(elementName)) {
        table.cellName = elementName;
        if (table.sectionName == null) { table.sectionName = "tbody"; }
      } else if ("caption".equals(elementName)) {
        table.cellName = elementName;
        table.sectionName = null;
      } else if ("tr".equals(elementName)) {
        table.cellName = null;
        if (table.sectionName == null) { table.sectionName = "tbody"; }
      } else if ("tbody".equals(elementName) || "thead".equals(elementName)
                 || "tfoot".equals(elementName)) {
        table.cellName = null;
        table.sectionName = elementName;
      } else if ("col".equals(elementName) || "colgroup".equals(elementName)) {
        table.cellName = null;
        table.sectionName = null;
      }
      syncInsertionMode();
    }

    private void trackUntrackedHtmlEndTag(String elementName) {
      UntrackedTable table = currentUntrackedTable();
      if (table == null) { return; }
      if ("table".equals(elementName)) {
        untrackedTables.remove(untrackedTables.size() - 1);
      } else if ("td".equals(elementName) || "th".equals(elementName)
                 || "caption".equals(elementName)) {
        // Ignored unless it names the open cell or caption.
        if (elementName.equals(table.cellName)) { table.cellName = null; }
      } else if ("tr".equals(elementName)) {
        // A caption ignores it; a cell closes along with the row.
        if (!"caption".equals(table.cellName)) { table.cellName = null; }
      } else if ("tbody".equals(elementName) || "thead".equals(elementName)
                 || "tfoot".equals(elementName)) {
        // A caption ignores it, and so does a cell in another section.
        if (!"caption".equals(table.cellName)
            && elementName.equals(table.sectionName)) {
          table.cellName = null;
          table.sectionName = null;
        }
      }
      syncInsertionMode();
    }

    private void processFormStartTag(List<String> attrs) {
      if (formElementPointerSet) { return; }
      formElementPointerSet = true;
      if (openElements.isEmpty()) { return; }
      if (!closePIfInButtonScope()) { return; }
      OpenElement form = new OpenElement("form", Namespace.HTML, attrs);
      push(form);
      if (!unknown) { trackedFormElement = form; }
    }

    private boolean closePIfInButtonScope() {
      int pIndex = findHtmlElementInDefaultScope("p", true);
      if (pIndex >= 0) {
        return popTrackedElementsFrom(pIndex, false, null);
      }
      return true;
    }

    private boolean closeListOrDescriptionItemForStart(boolean listItem) {
      for (int i = openElements.size(); --i >= 0;) {
        OpenElement open = openElements.get(i);
        if (open.namespace == Namespace.HTML
            && (listItem
                ? "li".equals(open.elementName)
                : "dd".equals(open.elementName)
                    || "dt".equals(open.elementName))) {
          return popTrackedElementsFrom(i, false, null);
        }
        if (open.namespace == Namespace.HTML
            && AMBIGUOUSLY_SPECIAL_HTML_ELEMENT_NAMES.contains(
                open.elementName)) {
          becomeUnknown();
          return false;
        }
        if (isSpecial(open)
            && !isHtmlElement(open, "address")
            && !isHtmlElement(open, "div")
            && !isHtmlElement(open, "p")) {
          return true;
        }
      }
      return true;
    }

    /**
     * Pops a known suffix, or fails closed if doing so leaves formatting
     * elements only in the active formatting list.  A later start tag could
     * reconstruct those elements and put Chrome back in HTML content while
     * this bounded tracker believed that the current node was foreign.
     */
    private boolean popTrackedElementsFrom(
        int fromIndex,
        boolean allFormattingEntriesAreCleared,
        @Nullable OpenElement oneFormattingEntryRemoved) {
      if (!allFormattingEntriesAreCleared) {
        for (int i = openElements.size(); --i >= fromIndex;) {
          OpenElement open = openElements.get(i);
          if (open.namespace == Namespace.HTML
              && FORMATTING_ELEMENT_NAMES.contains(open.elementName)
              && open != oneFormattingEntryRemoved) {
            becomeUnknown();
            return false;
          }
        }
      }
      openElements.subList(fromIndex, openElements.size()).clear();
      return true;
    }

    private void generateImpliedEndTags(@Nullable String except) {
      while (!openElements.isEmpty()) {
        OpenElement current = currentElement();
        if (current.namespace != Namespace.HTML
            || !IMPLIED_END_TAG_NAMES.contains(current.elementName)
            || current.elementName.equals(except)) {
          return;
        }
        openElements.remove(openElements.size() - 1);
      }
    }

    private int findHtmlElementInDefaultScope(
        String elementName, boolean buttonScope) {
      for (int i = openElements.size(); --i >= 0;) {
        OpenElement open = openElements.get(i);
        if (isHtmlElement(open, elementName)) { return i; }
        if (open.namespace != Namespace.HTML) {
          if (open.special) { return -1; }
        } else if (DEFAULT_SCOPE_BOUNDARY_NAMES.contains(open.elementName)
                   || (buttonScope && "button".equals(open.elementName))) {
          return -1;
        }
      }
      return -1;
    }

    private boolean isInDefaultScope(int targetIndex) {
      for (int i = openElements.size(); --i > targetIndex;) {
        OpenElement open = openElements.get(i);
        if (open.namespace != Namespace.HTML) {
          if (open.special) { return false; }
        } else if (DEFAULT_SCOPE_BOUNDARY_NAMES.contains(open.elementName)) {
          return false;
        }
      }
      return true;
    }

    private int findOpenHtmlElement(String elementName) {
      for (int i = openElements.size(); --i >= 0;) {
        if (isHtmlElement(openElements.get(i), elementName)) { return i; }
      }
      return -1;
    }

    private boolean isCurrentHtmlElement(String elementName) {
      return isHtmlElement(currentElement(), elementName);
    }

    private static boolean isHtmlElement(
        OpenElement open, String elementName) {
      return open.namespace == Namespace.HTML
          && elementName.equals(open.elementName);
    }

    private static boolean isSpecial(OpenElement open) {
      return open.namespace == Namespace.HTML
          ? SPECIAL_HTML_ELEMENT_NAMES.contains(open.elementName)
          : open.special;
    }

    private static boolean hasHiddenInputType(List<String> attrs) {
      for (int i = 0; i + 1 < attrs.size(); i += 2) {
        if ("type".equals(attrs.get(i))) {
          // The tokenizer drops all but the first of duplicate attributes.
          return asciiEqualsIgnoreCase("hidden", attrs.get(i + 1));
        }
      }
      return false;
    }

    private void becomeUnknown() {
      openElements.clear();
      formElementPointerSet = false;
      trackedFormElement = null;
      simpleTable = null;
      untrackedTables.clear();
      unknown = true;
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
        becomeUnknown();
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

  private enum HtmlInsertionMode {
    IN_BODY,
    IN_TABLE,
    IN_CELL,
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
    /** In the special category, which bounds every scope. */
    final boolean special;

    OpenElement(
        String elementName, Namespace namespace, List<String> attrs) {
      this.elementName = elementName;
      this.namespace = namespace;
      this.mathTextIntegrationPoint = namespace == Namespace.MATHML
          && MATHML_TEXT_INTEGRATION_POINT_NAMES.contains(elementName);
      this.htmlIntegrationPoint = isHtmlIntegrationPoint(
          elementName, namespace, attrs);
      this.special = mathTextIntegrationPoint || htmlIntegrationPoint
          || (namespace == Namespace.MATHML
              && "annotation-xml".equals(elementName));
    }
  }

  /** A table open below the tracked region, and the part of it being filled. */
  private static final class UntrackedTable {
    /** td, th or caption while one is open. */
    @Nullable String cellName;
    /** tbody, thead or tfoot while one is open. */
    @Nullable String sectionName;
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


  /** True for h1 through h6, any of which an h1 through h6 end tag closes. */
  private static boolean isHeadingName(String canonElementName) {
    if (canonElementName.length() != 2 || canonElementName.charAt(0) != 'h') {
      return false;
    }
    char digit = canonElementName.charAt(1);
    return digit >= '1' && digit <= '6';
  }

  /** End tags whose effect is decided by table scope or the insertion mode. */
  private static final Set<String> TABLE_SCOPED_ELEMENT_NAMES
      = j8().setOf(
          "table", "caption", "tbody", "thead", "tfoot", "tr", "td", "th");

  /** HTML end tags that never pop the stack. */
  private static final Set<String> IGNORED_HTML_END_TAG_NAMES
      = j8().setOf(
          "svg", "math", "body", "html", "br", "col", "colgroup", "frame",
          "head");

  /**
   * End tags with their own "in body" rules, which search a scope rather
   * than stopping at the first element in the special category.
   */
  private static final Set<String> SPECIFIC_END_TAG_RULE_NAMES
      = j8().setOf(
          "address", "article", "aside", "blockquote", "button", "center",
          "details", "dialog", "dir", "div", "dl", "fieldset", "figcaption",
          "figure", "footer", "header", "hgroup", "listing", "main", "menu",
          "nav", "ol", "pre", "search", "section", "select", "summary",
          "ul", "form", "p", "li", "dd", "dt", "h1", "h2", "h3", "h4",
          "h5", "h6",
          "a", "b", "big", "code", "em", "font", "i", "nobr", "s", "small",
          "strike", "strong", "tt", "u", "applet", "marquee", "object");

  private static final Set<String> FORMATTING_ELEMENT_NAMES
      = j8().setOf(
          "a", "b", "big", "code", "em", "font", "i", "nobr", "s", "small",
          "strike", "strong", "tt", "u");

  /** Elements whose end tags clear the active formatting list to a marker. */
  private static final Set<String> ACTIVE_FORMATTING_MARKER_ELEMENT_NAMES
      = j8().setOf("applet", "marquee", "object");

  /** The HTML elements that bound the default scope. */
  private static final Set<String> DEFAULT_SCOPE_BOUNDARY_NAMES
      = j8().setOf(
          "applet", "caption", "html", "table", "td", "th", "marquee",
          "object", "select", "template");

  /** The HTML elements in the special category. */
  private static final Set<String> SPECIAL_HTML_ELEMENT_NAMES
      = j8().setOf(
          "address", "applet", "area", "article", "aside", "base",
          "basefont", "bgsound", "blockquote", "body", "br", "button",
          "caption", "center", "col", "colgroup", "dd", "details",
          "dialog", "dir", "div", "dl", "dt", "embed", "fieldset",
          "figcaption", "figure", "footer", "form", "frame", "frameset",
          "h1", "h2", "h3", "h4",
          "h5", "h6", "head", "header", "hgroup", "hr", "html", "iframe",
          "img", "input", "keygen", "li", "link", "listing", "main",
          "marquee", "menu", "meta", "nav", "noembed", "noframes",
          "noscript", "object", "ol", "p", "param", "plaintext", "pre",
          "script", "search", "section", "select", "source", "style",
          "summary", "table", "tbody", "td", "template", "textarea",
          "tfoot", "th", "thead", "title", "tr", "track", "ul", "wbr",
          "xmp");

  /**
   * Elements the specification puts in the special category but current
   * Chrome does not, so a walk that reaches one has an uncertain outcome.
   * {@code dialog} and {@code search} are both special in the WHATWG parsing
   * algorithm but absent from Chrome's special-node set.
   */
  private static final Set<String> AMBIGUOUSLY_SPECIAL_HTML_ELEMENT_NAMES
      = j8().setOf("dialog", "search");

  /** Start tags whose HTML stack effect this bounded tracker cannot derive. */
  private static final Set<String> UNMODELED_CONTEXT_CHANGING_START_TAG_NAMES
      = j8().setOf("template", "frameset");

  /** Ruby starts generate implied end tags using state outside this tracker. */
  private static final Set<String> UNMODELED_HTML_START_TAG_NAMES
      = j8().setOf("rb", "rtc", "rp", "rt");

  /** Start tags that close a p element in button scope before insertion. */
  private static final Set<String> P_CLOSING_START_TAG_NAMES
      = j8().setOf(
          "address", "article", "aside", "blockquote", "center", "details",
          "dialog", "dir", "div", "dl", "fieldset", "figcaption", "figure",
          "footer", "header", "hgroup", "main", "menu", "nav", "ol", "p",
          "search", "section", "summary", "ul");

  private static final Set<String> IMPLIED_END_TAG_NAMES
      = j8().setOf(
          "dd", "dt", "li", "optgroup", "option", "p", "rb", "rp", "rt",
          "rtc");

  private static final Set<String> TABLE_STRUCTURE_START_TAG_NAMES
      = j8().setOf(
          "caption", "col", "colgroup", "tbody", "thead", "tfoot", "tr",
          "td", "th");

  /** Start tags the current HTML tree builder inserts and immediately pops. */
  private static final Set<String> HTML_TREE_BUILDER_VOID_ELEMENT_NAMES
      = j8().setOf(
          "area", "base", "basefont", "bgsound", "br", "embed", "hr",
          "img", "input", "keygen", "link", "meta", "param", "source",
          "track", "wbr");

  /** Start tags that "in body" ignores or merges rather than inserting. */
  private static final Set<String> IGNORED_HTML_START_TAG_NAMES
      = j8().setOf(
          "html", "body", "head", "frame", "caption", "col", "colgroup",
          "tbody", "thead", "tfoot", "tr", "td", "th");

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
