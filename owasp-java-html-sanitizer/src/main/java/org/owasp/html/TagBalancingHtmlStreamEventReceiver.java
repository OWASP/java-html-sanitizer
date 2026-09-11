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
import java.util.Arrays;
import java.util.BitSet;
import java.util.List;

import javax.annotation.Nullable;

import org.owasp.html.HtmlElementTables.HtmlElementNames;

/**
 * Wraps an HTML stream event receiver to fill in missing close tags.
 * If the balancer is given the HTML {@code <p>1<p>2}, the wrapped receiver will
 * see events equivalent to {@code <p>1</p><p>2</p>}.
 *
 * @author Mike Samuel (mikesamuel@gmail.com)
 */
@TCB
public class TagBalancingHtmlStreamEventReceiver
    implements HtmlStreamEventReceiver {
  private final HtmlStreamEventReceiver underlying;
  private int nestingLimit = Integer.MAX_VALUE;
  private final IntVector openElements = new IntVector();
  /**
   * The element each entry in {@link #openElements} became after policy
   * application, or {@link #NO_OUTPUT_ELEMENT} when the policy dropped it.
   * When the receiver below cannot report that, the input name is used.
   */
  private final IntVector outputElements = new IntVector();
  private final IntVector toResumeInReverse = new IntVector();
  /**
   * Bit {@code i} is set while the element at {@code i} of
   * {@link #openElements} is closed in the output but still open here.
   * <p>
   * A browser keeps a table, and any row group and row open in it, on its
   * stack when content arrives that cannot go inside a table: it puts the
   * content in front of the table instead, foster parenting, and later table
   * content pops that content and carries on in the same table.  The output
   * cannot put anything in front of a tag already written, so the table is
   * closed there and the content written after it, and the table is written
   * again, as a new table, when its content resumes (#342).  Meanwhile its
   * entries stay here, so that table content finds them and comes back to
   * them, and so that they bound end tags for elements below them as they do
   * in a browser.  Such entries are contiguous, from a {@code table} up, and
   * are the only pushed-out entries below the content pushed out of them.
   */
  private final BitSet pushedOut = new BitSet();
  private static final HtmlElementTables METADATA = HtmlElementTables.get();
  private static final int UNRECOGNIZED_TAG =
      METADATA.indexForName(HtmlElementNames.CUSTOM_ELEMENT_NAME);
  private static final int A_TAG = METADATA.indexForName("a");
  private static final int BODY_TAG = METADATA.indexForName("body");
  private static final int TABLE_TAG = METADATA.indexForName("table");
  private static final int NO_OUTPUT_ELEMENT = -1;
  /**
   * The elements a browser keeps open, and later clears its stack back to,
   * when it foster-parents content that arrives inside them: a table and its
   * row groups and rows.  Not the cell, caption or template, inside which
   * content nests normally.
   */
  private static final BitSet TABLE_CONTEXT = new BitSet();
  /**
   * The elements whose arrival, in a browser, ends foster-parented content
   * and returns to the table: its parts, which clear the stack back to the
   * table, and a table itself, which pops the open table and takes its
   * place.
   */
  private static final BitSet TABLE_PARTS = new BitSet();
  static {
    for (String name : new String[] { "table", "tbody", "tfoot", "thead", "tr" }) {
      TABLE_CONTEXT.set(METADATA.indexForName(name));
    }
    for (String name : new String[] {
             "caption", "col", "colgroup", "table", "tbody", "td", "tfoot",
             "th", "thead", "tr",
         }) {
      TABLE_PARTS.set(METADATA.indexForName(name));
    }
  }
  /**
   * Elements on entering which a browser puts a marker on its list of
   * active formatting elements, so that an {@code a} opened inside one of
   * them does not end an {@code a} open outside it: the cell, caption and
   * template elements, and the legacy applet, marquee and object.
   */
  private static final BitSet FORMATTING_MARKERS = new BitSet();
  static {
    for (String name : new String[] {
             "applet", "caption", "marquee", "object", "td", "template", "th",
         }) {
      FORMATTING_MARKERS.set(METADATA.indexForName(name));
    }
  }

  private static final boolean DEBUG = false;

  /**
   * Receives notice of tags dropped because the output would otherwise nest
   * deeper than {@link #setNestingLimit}.
   *
   * <p>This exists because the tag balancer runs upstream of the policy, and
   * so upstream of {@link HtmlChangeReporter}, which notices a discarded tag
   * by watching for one that goes into the policy and does not come out.  A
   * tag the balancer drops never reaches the policy at all, so without this it
   * is invisible to a listener.
   */
  interface NestingLimitListener {
    /** @param elementName the tag that was not emitted. */
    void nestingLimitReached(String elementName);
  }

  /**
   * Implemented by a policy that suppresses the text inside dropped elements
   * beyond the fixed {@link
   * ElementAndAttributePolicyBasedSanitizerPolicy#SKIPPABLE_ELEMENT_CONTENT}
   * list, such as one built with {@code disallowTextIn}.
   *
   * <p>This receiver drops a start tag that would exceed the nesting limit
   * before the policy sees it, and keeps the content of such an element
   * suppressed on the policy's behalf (see {@link #droppedSkippableDepth}).
   * It knows the fixed list itself; for anything else it has to ask.
   */
  interface TextSuppressionPolicy {
    /**
     * @param canonElementName a canonical element name.
     * @return true if text directly inside a dropped {@code canonElementName}
     *     is suppressed rather than emitted where the element was.
     */
    boolean suppressesTextWhenDropped(String canonElementName);
  }

  /**
   * Implemented by a policy that can identify the element, if any, emitted
   * by its most recent {@link HtmlStreamEventReceiver#openTag} call.  The
   * balancer uses the output name when applying the formatting-marker rule
   * for nested links: a marker the policy dropped cannot affect how a browser
   * parses the sanitized output.
   */
  interface OpenTagOutputPolicy {
    /**
     * @return the canonical emitted name, or null if no element was emitted.
     */
    @Nullable String outputElementNameForLastOpenTag();
  }

  /**
   * How many elements whose content the policy would suppress -- {@code
   * <script>}, {@code <style>}, {@code <iframe>} and friends, plus any the
   * policy names through {@link TextSuppressionPolicy} -- have been dropped
   * for exceeding the nesting limit and not yet closed.
   *
   * <p>The policy decides to skip such an element's text when it sees the
   * element's start tag.  A tag this receiver drops never reaches the policy,
   * so the policy would render the content as ordinary text.  Counting them
   * here keeps that content suppressed.
   */
  private int droppedSkippableDepth;

  private boolean contentIsSkippable(String canonElementName) {
    if (ElementAndAttributePolicyBasedSanitizerPolicy
        .SKIPPABLE_ELEMENT_CONTENT.contains(canonElementName)) {
      return true;
    }
    return underlying instanceof TextSuppressionPolicy
        && ((TextSuppressionPolicy) underlying)
            .suppressesTextWhenDropped(canonElementName);
  }

  private void reportDroppedByNestingLimit(String elementName) {
    if (underlying instanceof NestingLimitListener) {
      ((NestingLimitListener) underlying).nestingLimitReached(elementName);
    }
  }

  /**
   * @param underlying An event receiver that should receive a stream of
   *     balanced events that is as close as possible to the stream of events
   *     received by this.
   */
  public TagBalancingHtmlStreamEventReceiver(
      HtmlStreamEventReceiver underlying) {
    this.underlying = underlying;
  }

  /**
   * Set the maximum element nesting depth.
   */
  public void setNestingLimit(int limit) {
    if (openElements.size() > limit) {
      throw new IllegalStateException();
    }
    this.nestingLimit = limit;
  }

  public void openDocument() {
    droppedSkippableDepth = 0;
    underlying.openDocument();
  }

  public void closeDocument() {
    for (int i = Math.min(nestingLimit, openElements.size()); --i >= 0;) {
      if (pushedOut.get(i)) { continue; }  // Already closed in the output.
      int elIndex = openElements.get(i);
      String elname = METADATA.canonNameForIndex(elIndex);
      underlying.closeTag(elname);
    }
    openElements.clear();
    outputElements.clear();
    pushedOut.clear();
    toResumeInReverse.clear();
    underlying.closeDocument();
  }

  public void openTag(String elementName, List<String> attrs) {
    if (DEBUG) {
      dumpState("open " + elementName);
    }
    String canonElementName = HtmlLexer.canonicalElementName(elementName);

    int elIndex = METADATA.indexForName(canonElementName);
    // Treat unrecognized tags as void, but emit closing tags in closeTag().
    if (elIndex == UNRECOGNIZED_TAG) {
      if (openElements.size() < nestingLimit) {
        underlying.openTag(elementName, attrs);
      } else {
        if (contentIsSkippable(canonElementName)) { ++droppedSkippableDepth; }
        reportDroppedByNestingLimit(elementName);
      }
      return;
    }

    prepareForContent(elIndex);

    if (openElements.size() < nestingLimit) {
      underlying.openTag(METADATA.canonNameForIndex(elIndex), attrs);
      if (!HtmlTextEscapingMode.isVoidElement(canonElementName)) {
        openElements.add(elIndex);
        outputElements.add(outputElementIndexForLastOpenTag(elIndex));
      }
    } else {
      if (contentIsSkippable(canonElementName)) { ++droppedSkippableDepth; }
      reportDroppedByNestingLimit(METADATA.canonNameForIndex(elIndex));
    }
  }

  /**
   * True if an {@code a} is open above the nearest formatting marker, which
   * is when a browser ends it before opening another {@code a}: the
   * adoption agency algorithm runs for an {@code a} on the list of active
   * formatting elements after the last marker, and a link inside a table
   * cell leaves one outside the table alone.
   */
  private boolean hasOpenLinkInFormattingScope() {
    for (int i = outputElements.size(); --i >= 0;) {
      int openElementIndex = outputElements.get(i);
      if (openElementIndex == A_TAG) { return true; }
      if (openElementIndex != NO_OUTPUT_ELEMENT
          && FORMATTING_MARKERS.get(openElementIndex)) {
        return false;
      }
    }
    return false;
  }

  /**
   * The output counterpart of an input element just sent downstream.
   * Receivers other than the library policy cannot provide this feedback, so
   * preserve the traditional input-based balancing for them.
   */
  private int outputElementIndexForLastOpenTag(int inputElementIndex) {
    if (underlying instanceof OpenTagOutputPolicy) {
      String outputElementName = ((OpenTagOutputPolicy) underlying)
          .outputElementNameForLastOpenTag();
      return outputElementName != null
          ? METADATA.indexForName(
              HtmlLexer.canonicalElementName(outputElementName))
          : NO_OUTPUT_ELEMENT;
    }
    return inputElementIndex;
  }

  private void prepareForContent(int elIndex) {
    if (!pushedOut.isEmpty()
        && elIndex != HtmlElementTables.TEXT_NODE
        && TABLE_PARTS.get(elIndex)) {
      returnToPushedOutTable(elIndex);
    }
    int nOpen = openElements.size();
    {
      int top = nOpen != 0 ? openElements.get(nOpen - 1) : BODY_TAG;
      // Open implied elements, such as list-items and table cells & rows.
      int[] impliedElIndices = METADATA.impliedElements(top, elIndex);
      if (impliedElIndices.length != 0) {
        List<String> attrs = new ArrayList<>();

        int startPos = 0;
        for (int i = 0, n = impliedElIndices.length; i < n; ++i) {
          int impliedElIndex = impliedElIndices[i];
          if (impliedElIndex == top) {
            startPos = i + 1;
            break;
          }
        }

        for (int i = startPos, n = impliedElIndices.length; i < n; ++i) {
          int impliedElIndex = impliedElIndices[i];
          String impliedElName = METADATA.canonNameForIndex(
              impliedElIndex);
          attrs.clear();
          underlying.openTag(impliedElName, attrs);
          openElements.add(impliedElIndex);
          outputElements.add(
              outputElementIndexForLastOpenTag(impliedElIndex));
          top = impliedElIndex;
          ++nOpen;
        }
      }
    }

    if (nOpen != 0) {
      int top = openElements.get(nOpen - 1);
      // Close all the elements that cannot contain the content to open.
      while (true) {
        // A link ends the link open before it, wherever that is: nested
        // links do not survive a browser's parse, so a table between them
        // cannot stay open either.
        boolean linkEndsLink =
            elIndex == A_TAG && hasOpenLinkInFormattingScope();
        boolean canContain = canContain(elIndex, top, nOpen - 1)
            && !linkEndsLink;
        if (canContain) {
          break;
        }
        if (!linkEndsLink
            && TABLE_CONTEXT.get(top) && isFosterParented(elIndex)) {
          // A browser puts the content in front of the table and keeps the
          // table open.  Close the table in the output, keep it here, and
          // open the content beside it.
          pushOutTable(nOpen - 1);
          break;
        }
        if (openElements.size() < nestingLimit && !pushedOut.get(nOpen - 1)) {
          underlying.closeTag(METADATA.canonNameForIndex(top));
        }
        openElements.remove(--nOpen);
        outputElements.remove(nOpen);
        pushedOut.clear(nOpen);
        if (METADATA.resumable(top) && top != elIndex) {
          toResumeInReverse.add(top);
        }
        if (nOpen == 0) { break; }
        top = openElements.get(nOpen - 1);
      }
    }

    while (!toResumeInReverse.isEmpty()) {
      int toResume = toResumeInReverse.getLast();
      // If toResume can contain elInfo AND the top of the stack can contain
      // toResume, then we push toResume.  A link is not resumed around
      // another link, or where one is open: a browser ends a link when the
      // next begins, and nested links do not survive a browser's parse, so
      // the output would not read back as written.
      nOpen = openElements.size();
      if ((nOpen == 0
          || canContain(toResume, openElements.get(nOpen - 1), nOpen))
          && canContain(elIndex, toResume, nOpen)
          && !(toResume == A_TAG
               && (elIndex == A_TAG || hasOpenLinkInFormattingScope()))) {
        toResumeInReverse.removeLast();
        int outputElementIndex = NO_OUTPUT_ELEMENT;
        if (openElements.size() < nestingLimit) {
          underlying.openTag(
              METADATA.canonNameForIndex(toResume),
              new ArrayList<>());
          outputElementIndex = outputElementIndexForLastOpenTag(toResume);
        }
        openElements.add(toResume);
        outputElements.add(outputElementIndex);
      } else {
        break;
      }
    }
  }

  /**
   * True if a browser puts content of this kind that arrives inside a table,
   * outside a cell or caption, in front of the table rather than in it: text,
   * and any element that is not one of a table's own parts.
   */
  private static boolean isFosterParented(int elIndex) {
    return elIndex == HtmlElementTables.TEXT_NODE || !TABLE_PARTS.get(elIndex);
  }

  /**
   * Closes in the output, innermost first, the row, row group and table that
   * the top of the stack is in, and marks them pushed out, keeping them here.
   * Entries already pushed out, by earlier content beside the same table, are
   * left as they are.
   */
  private void pushOutTable(int topIndex) {
    for (int i = topIndex; i >= 0; --i) {
      int elIndex = openElements.get(i);
      if (!TABLE_CONTEXT.get(elIndex)) { break; }
      if (!pushedOut.get(i)) {
        if (i < nestingLimit) {
          underlying.closeTag(METADATA.canonNameForIndex(elIndex));
        }
        pushedOut.set(i);
      }
      if (elIndex == TABLE_TAG) { break; }
    }
  }

  /**
   * Handles a table part, or a table, arriving while a table is pushed out,
   * as a browser does: closes the content that was put in front of the
   * nearest pushed-out table, pops the pushed-out entries that cannot hold
   * the part, even by implying elements between, which for a table is all of
   * them, and writes the rest again as a new table for the part to go in.
   * <p>
   * Not across a boundary of table scope, such as a {@code template} in the
   * pushed-out content: a browser looks for the table within that scope
   * only, so the part is handled where it arrived, as it would be with no
   * table pushed out.
   */
  private void returnToPushedOutTable(int elIndex) {
    int top = pushedOut.length() - 1;  // The nearest pushed-out entry.
    byte tableScope = SCOPE_FOR_END_TAG[TABLE_TAG];
    for (int i = openElements.size(); --i > top;) {
      if ((SCOPES_BY_ELEMENT[openElements.get(i)] & tableScope) != 0) {
        return;
      }
    }
    for (int i = openElements.size(); --i > top;) {
      int unclosed = openElements.remove(i);
      outputElements.remove(i);
      if (i < nestingLimit) {
        underlying.closeTag(METADATA.canonNameForIndex(unclosed));
      }
      if (METADATA.resumable(unclosed)) {
        toResumeInReverse.add(unclosed);
      }
    }
    while (top >= 0 && pushedOut.get(top)) {
      int entry = openElements.get(top);
      if (canContain(elIndex, entry, top)
          || METADATA.impliedElements(entry, elIndex).length != 0) {
        break;
      }
      openElements.remove(top);
      outputElements.remove(top);
      pushedOut.clear(top);
      --top;
    }
    if (top < 0 || !pushedOut.get(top)) { return; }
    int start = top;
    while (start > 0 && pushedOut.get(start - 1)) { --start; }
    // Pop the run and push it back, outermost first, opening each again.
    int n = top - start + 1;
    int[] run = new int[n];
    for (int i = n; --i >= 0;) {
      run[i] = openElements.remove(start + i);
      outputElements.remove(start + i);
      pushedOut.clear(start + i);
    }
    for (int i = 0; i < n; ++i) {
      int outputElementIndex = NO_OUTPUT_ELEMENT;
      if (openElements.size() < nestingLimit) {
        underlying.openTag(
            METADATA.canonNameForIndex(run[i]), new ArrayList<>());
        outputElementIndex = outputElementIndexForLastOpenTag(run[i]);
      }
      openElements.add(run[i]);
      outputElements.add(outputElementIndex);
    }
  }

  private static final BitSet TRANSPARENT = new BitSet();
  static {
    for (String transparentElement
        : new String[] {
            "a",
            "audio",
            "canvas",
            "del",
            "ins",
            "map",
            "object",
            "video",
        }) {
      TRANSPARENT.set(METADATA.indexForName(
          transparentElement));
    }
  }

  /**
   * Takes into account transparency when figuring out what
   * can be contained.
   */
  private boolean canContain(
      int child, int container, int containerIndexOnStack) {
    if (containerIndexOnStack < 0) {
      throw new IllegalArgumentException("negative container index");
    }
    if (child == HtmlElementTables.TEXT_NODE && hasSpecialTextMode(container)) {
      // If there's a select element on the stack, then we need to be extra careful.
      int selectElementIndex = METADATA.indexForName("select");
      for (int i = containerIndexOnStack; --i >= 0;) {
        if (selectElementIndex == openElements.get(i)) {
          return false;
        }
      }
    }
    int anc = container;
    int ancIndexOnStack = containerIndexOnStack;
    while (true) {
      if (METADATA.canContain(anc, child)) {
        return true;
      }
      if (!TRANSPARENT.get(anc)) {
        return false;
      }
      if (ancIndexOnStack == 0) {
        return METADATA.canContain(BODY_TAG, child);
      }
      --ancIndexOnStack;
      anc = openElements.get(ancIndexOnStack);
    }
  }

  public void closeTag(String elementName) {
    if (DEBUG) {
      dumpState("close " + elementName);
    }
    String canonElementName = HtmlLexer.canonicalElementName(elementName);

    if (droppedSkippableDepth != 0 && contentIsSkippable(canonElementName)) {
      --droppedSkippableDepth;
    }

    int elIndex = METADATA.indexForName(canonElementName);
    if (elIndex == UNRECOGNIZED_TAG) {  // Allow unrecognized end tags through.
      if (openElements.size() < nestingLimit) {
        underlying.closeTag(elementName);
      }
      return;
    }

    // Ensure that index is in the scope of closeable elements.
    // This approximates the "has an element in *** scope" predicates defined at
    // http://www.whatwg.org/specs/web-apps/current-work/multipage/syntax.html
    // #has-an-element-in-the-specific-scope
    int blockingScopes = SCOPE_FOR_END_TAG[elIndex];

    int index = -1;
    {
      if (isHeaderElementName(canonElementName)) {
        // Let any of </h1>, </h2>, ... close other header tags.
        for (int i = openElements.size(); -- i >= 0;) {
          int openElementIndex = openElements.get(i);
          if (isHeaderElement(openElementIndex)) {
            elIndex = openElementIndex;
            index = i;
            // This is a dead store, but not setting is a maintenance hazard.
            canonElementName = METADATA.canonNameForIndex(openElementIndex);
            break;
          }
          int openElementScope = SCOPES_BY_ELEMENT[openElementIndex];
          if ((openElementScope & blockingScopes) != 0) {
            break;
          }
        }
      } else {
        for (int i = openElements.size(); -- i >= 0;) {
          int openElementIndex = openElements.get(i);
          if (openElementIndex == elIndex) {
            index = i;
            break;
          }
          int openElementScope = SCOPES_BY_ELEMENT[openElementIndex];
          if ((openElementScope & blockingScopes) != 0) {
            break;
          }
        }
      }
    }
    if (index < 0) {
      return;  // Don't close unopened tags.
    }

    int last = openElements.size();
    // Close all the elements that cannot contain the element to open.
    while (--last > index) {
      int unclosed = openElements.remove(last);
      outputElements.remove(last);
      if (last + 1 < nestingLimit && !pushedOut.get(last)) {
        underlying.closeTag(METADATA.canonNameForIndex(unclosed));
      }
      pushedOut.clear(last);
      if (METADATA.resumable(unclosed)) {
        toResumeInReverse.add(unclosed);
      }
    }
    if (openElements.size() < nestingLimit && !pushedOut.get(index)) {
      underlying.closeTag(METADATA.canonNameForIndex(elIndex));
    }
    pushedOut.clear(index);
    openElements.remove(index);
    outputElements.remove(index);
  }

  /**
   * True if text is the value of an inter-element whitespace text node as
   * defined by HTML5.
   * <p>
   * This is the kind of text that is often inserted by
   * HTML authors to nicely indent their HTML documents and which
   * (modulo unconventional use of {@code white-space:pre}) are not apparent
   * to the end-user.
   */
  public static boolean isInterElementWhitespace(String text) {
    int n = text.length();
    for (int i = 0; i < n; ++i) {
      if (!Strings.isHtmlSpace(text.charAt(i))) {
        return false;
      }
    }
    return true;
  }

  public void text(String text) {
    if (DEBUG) {
      dumpState("text `" + text.replace("\n", "\\n") + "`");
    }
    boolean isInterElementWhitespace = isInterElementWhitespace(text);
    if (isInterElementWhitespace) {
      int nOpenElements = openElements.size();
      if (nOpenElements != 0) {
        int top = openElements.get(nOpenElements - 1);
        if (!METADATA.canContainText(top)
            // Use this as a proxy for whether or not a manufactured node is
            // needed.  If it is, then skip the inter-element space and don't
            // manufacture a node.
            || METADATA.impliedElements(top, A_TAG).length != 0) {
          return;
        }
      }
    } else {
      prepareForContent(HtmlElementTables.TEXT_NODE);
    }

    // The nesting limit bounds how deep the *output* nests; it is not a
    // licence to drop content.  Suppressing the text here meant that markup
    // nested past the limit came out as a well-formed stack of empty elements
    // with the author's text deleted from the middle of it, silently.  Emit
    // the text and let it flatten into the deepest element we did open, which
    // is what a browser's own depth limit does.  Text is escaped downstream,
    // so it cannot become markup.
    //
    // The exception is content the policy would have suppressed had it seen
    // the start tag we dropped: a <script> body must not resurface as visible
    // text just because it sat below the limit.
    if (droppedSkippableDepth == 0) {
      underlying.text(text);
    }
  }

  private static boolean isHeaderElement(int elIndex) {
    String canonElementName = METADATA.canonNameForIndex(elIndex);
    return isHeaderElementName(canonElementName);
  }

  private static boolean isHeaderElementName(String canonElementName) {
    return canonElementName.length() == 2
        && (canonElementName.charAt(0) | 32) == 'h'
        && canonElementName.charAt(1) <= '9';
  }

  private static boolean hasSpecialTextMode(int elementIndex) {
    String name = METADATA.canonNameForIndex(elementIndex);
    switch (HtmlTextEscapingMode.getModeForTag(name)) {
      case PCDATA: case VOID:
        return false;
      case CDATA: case CDATA_SOMETIMES: case RCDATA: case PLAIN_TEXT:
        return true;
    }
    throw new IllegalArgumentException(name);
  }

  private static final byte ALL_SCOPES;
  private static final byte[] SCOPES_BY_ELEMENT;
  private static final byte[] SCOPE_FOR_END_TAG;

  static {
    // w3c.github.io/html/single-page.html#as-that-element-in-the-specific-scope
    final byte IN = 1;
    final byte BUTTON = 2;
    final byte LIST_ITEM = 4;
    final byte TABLE = 8;
    final byte SELECT = 16;

    ALL_SCOPES = IN | BUTTON | LIST_ITEM | TABLE | SELECT;

    SCOPES_BY_ELEMENT = new byte[METADATA.nElementTypes()];

    String[] inScopeElements = {
        "applet",
        "caption",
        "html",
        "table",
        "td",
        "th",
        "marquee",
        "object",
        "template",
        // TODO: mathml and svg
    };
    for (String tn : inScopeElements) {
      SCOPES_BY_ELEMENT[METADATA.indexForName(tn)] |= IN;
    }

    String[] listItemScopeExtras = {
        "dir",
        "ol",
        "ul",
    };
    for (String[] tns
         : new String[][] { listItemScopeExtras, inScopeElements }) {
      for (String tn : tns) {
        SCOPES_BY_ELEMENT[METADATA.indexForName(tn)] |= LIST_ITEM;
      }
    }
    String[] buttonScopeExtras = {
        "button",
    };
    for (String[] tns
        : new String[][] { buttonScopeExtras, inScopeElements }) {
     for (String tn : tns) {
       SCOPES_BY_ELEMENT[METADATA.indexForName(tn)] |= BUTTON;
     }
   }

    String[] tableScopeElements = {
        "html",
        "table",
        "template",
    };
    for (String tn : tableScopeElements) {
      SCOPES_BY_ELEMENT[METADATA.indexForName(tn)] |= TABLE;
    }

    String[] selectScopeExceptions = {
        "optgroup",
        "option",
    };
    for (int i = 0, n = SCOPES_BY_ELEMENT.length; i < n; ++i) {
      SCOPES_BY_ELEMENT[i] |= SELECT;
    }
    for (String tn : selectScopeExceptions) {
      SCOPES_BY_ELEMENT[METADATA.indexForName(tn)] &= ~SELECT;
    }

    // The <nofeature> elements are weird.
    //     <table><noscript></table></noscript>...
    // is equivalent to
    //     <table>...
    // when scripts are enabled and is equivalent to
    //     <table></table>...
    // when not.
    //
    // We scope <noscript> so that, even when we parse and filter the content
    // as if it were tag content, we don't treat that content as escaping
    // which is consistent with the view that that content is ignored by the
    // browser as is usually the case.
    SCOPES_BY_ELEMENT[METADATA.indexForName("noembed")]
      = SCOPES_BY_ELEMENT[METADATA.indexForName("noframes")]
      = SCOPES_BY_ELEMENT[METADATA.indexForName("noscript")]
      = ALL_SCOPES;

    // Derived by looking at
    //     //dev.w3.org/html5/github-html/heartbeat/tokenization.html
    // and scanning for all lines matching one of
    //     "element in scope"
    //     "element in button scope"
    //     "element in list item scope"
    //     "element in select scope"
    //     "element in table scope"
    SCOPE_FOR_END_TAG = new byte[METADATA.nElementTypes()];
    Arrays.fill(SCOPE_FOR_END_TAG, IN);
    SCOPE_FOR_END_TAG[METADATA.indexForName("caption")]
      = SCOPE_FOR_END_TAG[METADATA.indexForName("col")]
      = SCOPE_FOR_END_TAG[METADATA.indexForName("colgroup")]
      = SCOPE_FOR_END_TAG[METADATA.indexForName("table")]
      = SCOPE_FOR_END_TAG[METADATA.indexForName("tbody")]
      = SCOPE_FOR_END_TAG[METADATA.indexForName("tfoot")]
      = SCOPE_FOR_END_TAG[METADATA.indexForName("thead")]
      = SCOPE_FOR_END_TAG[METADATA.indexForName("tr")]
      = SCOPE_FOR_END_TAG[METADATA.indexForName("td")]
      = SCOPE_FOR_END_TAG[METADATA.indexForName("th")]
      = TABLE;
    SCOPE_FOR_END_TAG[METADATA.indexForName("select")] = SELECT;
    SCOPE_FOR_END_TAG[METADATA.indexForName("p")] = BUTTON;  // really.
    SCOPE_FOR_END_TAG[METADATA.indexForName("li")] = LIST_ITEM;
  }

  private void dumpState(String msg) {
    System.err.println(msg);
    System.err.println("\tstack");
    int nOpen = openElements.size();
    int maxStackToDump = 5;
    if (nOpen > maxStackToDump) {
      System.err.println("\t\t" + (nOpen - maxStackToDump) + " elided");
    }
    for (int i = Math.max(0, nOpen - maxStackToDump); i < nOpen; ++i) {
      int idx = openElements.get(i);
      System.err.println("\t\t" + METADATA.canonNameForIndex(idx));
    }
    System.err.println("\tresumable");
    for (int i = 0, n = toResumeInReverse.size(); i < n; ++i) {
      int idx = toResumeInReverse.get(i);
      System.err.println("\t\t" + METADATA.canonNameForIndex(idx));
    }
  }
}
