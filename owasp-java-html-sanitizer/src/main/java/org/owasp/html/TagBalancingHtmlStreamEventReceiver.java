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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
  private HtmlSanitizer.ForeignContentContext foreignContent
      = new HtmlSanitizer.ForeignContentContext();
  /** Input name whose rendered foreign root closes before the table reopens. */
  private @Nullable String foreignRootPendingTableReturn;
  /**
   * An unrecognized input name emitted as HTML {@code textarea}.  The input
   * lexer does not enter RCDATA for that case-sensitive foreign name, but a
   * browser reparsing the output does.  Keep text in it, and close it before
   * forwarding the next tag event so markup cannot turn into RCDATA.
   */
  private @Nullable String pendingUnrecognizedHtmlTextElement;

  /** An unrecognized input may have produced a table known only downstream. */
  private boolean policyOnlyTableMayBeOpen;
  /** Prevents nested balancing from replacing a prepared policy result. */
  private boolean preparingPreparedPolicyStart;
  /**
   * Whether the tag or text being balanced is inserted under SVG or MathML
   * rules below.  A browser reconstructs its active formatting elements only
   * where it inserts HTML content, and an HTML formatting start tag in
   * foreign content would instead pop the foreign root, so no queued
   * formatting is resumed there.
   */
  private boolean insertionPointIsInForeignContent;
  /** Whether emitted bare parts may keep a browser-implied table open. */
  private boolean outputlessTablePartsMayBeOpen;
  /** Public open-tag event in which detached state first became true. */
  private int outputlessTablePartsOpenedAtEvent = -1;
  private int openTagEvent;
  /** Outputless logical tables into whose browser-implied table parts emitted. */
  private final BitSet outputlessTablesWithEmittedParts = new BitSet();
  /** Pushed logical tables whose mapped template remains physically open. */
  private final BitSet pushedMappedTemplateOutputOpen = new BitSet();
  /** Logical roots whose mapped foreign output has suppressed contents. */
  private final BitSet suppressedMappedForeignSubtrees = new BitSet();
  /** Formatting-queue depth before the active suppressed table started. */
  private int suppressedMappedForeignTableResumeDepth = -1;
  private final IntVector openElements = new IntVector();
  /**
   * For each entry in {@link #openElements}, the opaque identity that
   * {@link #foreignContent} gave the browser tree-construction node pushed by
   * the same start tag, or zero for an entry that was implied, resumed, or
   * not tracked there.  A foreign end tag pops nodes, and the entries it
   * closes are found by this identity rather than by local name, which a
   * dropped or already closed element with the same name could alias.
   */
  private final IntVector inputElementSerials = new IntVector();
  /**
   * Elements forwarded to the receiver below with no entry in
   * {@link #openElements}: names outside the containment metadata, such as
   * {@code svg} or a custom element, and table parts forwarded directly into
   * SVG or MathML output.  The receiver keeps each open until its end tag.
   * Each records the size of {@link #openElements} when it was forwarded, so
   * every entry added after it is known to be inside it, and the identity of
   * the tree-construction node its start tag pushed, or zero.  An end tag is
   * forwarded only for an element still listed here, after everything inside
   * it has been closed, and a stray end tag closes nothing.
   * <p>
   * Every name here is canonical: each is forwarded under the name the
   * policy is asked about.  {@link #passthroughIndicesByName} indexes them,
   * so an end tag finds its element without scanning the list, which a long
   * run of forwarded elements would otherwise make quadratic.
   * <p>
   * A forwarded element counts toward the nesting limit only where it is
   * known to nest the output: see {@link #effectiveNestingDepth}.
   */
  private final List<String> passthroughNames = new ArrayList<>();
  /** Indices into {@link #passthroughNames}, innermost last, by name. */
  private final Map<String, IntVector> passthroughIndicesByName =
      new HashMap<>();
  private final IntVector passthroughDepths = new IntVector();
  private final IntVector passthroughSerials = new IntVector();
  /**
   * Whether the policy emitted each forwarded element as an SVG or MathML
   * element, by index into {@link #passthroughNames}, and the indices of the
   * forwarded SVG and MathML roots, innermost last.  Together they say
   * whether the output entered the input's current foreign region: a root
   * the policy dropped, or renamed to an HTML element, leaves the elements
   * inside it as ordinary HTML in the output.
   */
  private final BitSet passthroughOutputForeign = new BitSet();
  private final IntVector passthroughForeignRoots = new IntVector();
  /**
   * The element each entry in {@link #openElements} became after policy
   * application, or {@link #NO_OUTPUT_ELEMENT} when the policy dropped it.
   * When the receiver below cannot report that, the input name is used.
   */
  private final IntVector outputElements = new IntVector();
  /**
   * Bit {@code i} is set when the open event for entry {@code i} of
   * {@link #openElements} was sent to {@link #underlying}.  Resumed formatting
   * and returned table entries can remain on the logical stack at or beyond
   * the nesting limit without an open event, and the limit may later change.
   */
  private final BitSet sentToUnderlying = new BitSet();
  /**
   * Bit {@code i} is set when the input element at {@code i} was inserted
   * using SVG or MathML rules.  Local names such as {@code form} and
   * {@code table} do not have their HTML scope behavior there.
   */
  private final BitSet inputElementsInForeignContent = new BitSet();
  /** The corresponding namespace information for the element policy emitted. */
  private final BitSet outputElementsInForeignContent = new BitSet();
  /** Whether the policy output at this logical index starts SVG or MathML. */
  private final BitSet outputElementsStartForeignContent = new BitSet();
  /**
   * Marks the stacked HTML form, if any, that the input form pointer names.
   * A form inserted directly in table structure is popped at once and has no
   * marked stack entry even though the pointer remains set.
   */
  private final BitSet formPointerTargets = new BitSet();
  /** Stacked output forms whose form pointer was cleared without popping. */
  private final BitSet clearedFormPointerTargets = new BitSet();
  /**
   * A subset of {@link #clearedFormPointerTargets} whose corresponding output
   * pointer could not yet be cleared without changing the output tree.
   */
  private final BitSet staleOutputFormPointerTargets = new BitSet();
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
  /** Logical tables inserted only to wrap orphan input table parts. */
  private final BitSet impliedInputTables = new BitSet();
  /**
   * Bit {@code i} is set when no output table remains for a logical entry
   * whose descendants still use table rules.  This happens when policy does
   * not emit a synthetic table while returning from {@link #pushedOut}, or
   * when an element renamed to table has to close before foster-parented
   * content.  Table-structure descendants cannot be emitted in that output
   * context without changing when a browser reparses them.
   */
  private final BitSet outputTableUnavailable = new BitSet();
  private static final HtmlElementTables METADATA = HtmlElementTables.get();
  private static final int UNRECOGNIZED_TAG =
      METADATA.indexForName(HtmlElementNames.CUSTOM_ELEMENT_NAME);
  private static final int A_TAG = METADATA.indexForName("a");
  private static final int BODY_TAG = METADATA.indexForName("body");
  private static final int COL_TAG = METADATA.indexForName("col");
  private static final int COLGROUP_TAG = METADATA.indexForName("colgroup");
  private static final int FORM_TAG = METADATA.indexForName("form");
  private static final int LI_TAG = METADATA.indexForName("li");
  private static final int OL_TAG = METADATA.indexForName("ol");
  private static final int OPTION_TAG = METADATA.indexForName("option");
  private static final int OPTGROUP_TAG = METADATA.indexForName("optgroup");
  private static final int UL_TAG = METADATA.indexForName("ul");
  private static final int SELECT_TAG = METADATA.indexForName("select");
  private static final int TABLE_TAG = METADATA.indexForName("table");
  private static final int CAPTION_TAG = METADATA.indexForName("caption");
  private static final int TD_TAG = METADATA.indexForName("td");
  private static final int TH_TAG = METADATA.indexForName("th");
  private static final int TEMPLATE_TAG = METADATA.indexForName("template");
  private static final int TBODY_TAG = METADATA.indexForName("tbody");
  private static final int TR_TAG = METADATA.indexForName("tr");
  private static final int NO_OUTPUT_ELEMENT = -1;
  private static final int POLICY_ONLY_TABLE_CONTEXT = -2;
  private static final int INPUT_ONLY_TABLE_CONTEXT = -3;
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
   * <p>
   * These are the same elements whose end tags are scoped to a table in
   * {@link #SCOPE_FOR_END_TAG}, which is built far below; the two lists are
   * written out separately because that one is not initialized yet here.
   */
  private static final BitSet TABLE_PARTS = new BitSet();
  /** Elements that bound the table context used for the special form rule. */
  private static final BitSet TABLE_FORM_SCOPE_BOUNDARIES = new BitSet();
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
    for (String name : new String[] {
             "caption", "select", "td", "template", "th",
         }) {
      TABLE_FORM_SCOPE_BOUNDARIES.set(METADATA.indexForName(name));
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
   * Receives notice of start tags this receiver drops: those that would nest
   * the output deeper than {@link #setNestingLimit}, and a form start a
   * browser ignores while its form element pointer is set.
   *
   * <p>This exists because the tag balancer runs upstream of the policy, and
   * so upstream of {@link HtmlChangeReporter}, which notices a discarded tag
   * by watching for one that goes into the policy and does not come out.  A
   * tag the balancer drops never reaches the policy at all, so without this it
   * is invisible to a listener.
   */
  interface NestingLimitListener {
    /**
     * @param canonElementName the canonical name of the tag that was not
     *     emitted, which is the name it would have been forwarded under.
     */
    void nestingLimitReached(String canonElementName);
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

    /** Whether that output element was inserted using SVG or MathML rules. */
    boolean outputElementForLastOpenTagUsedForeignContentRules();

    /** Number of non-void elements currently open in the emitted stream. */
    int outputNestingDepth();

    /** Innermost non-void element currently open in the emitted stream. */
    @Nullable String outputContainerElementName();
  }

  /**
   * Optional policy operations used to keep output around a pushed-out table
   * in a browser context that matches the logical input context.
   */
  interface PushedOutTablePolicy {
    /** Whether the operations below are available for the current policy. */
    boolean supportsPushedOutTableOperations();

    /** Applies element and text policy while deliberately emitting no tag. */
    void openTagWithoutOutput(String elementName, List<String> attrs);

    /** Applies policy while deliberately emitting neither tag nor contents. */
    void openTagWithoutOutputOrContent(
        String elementName, List<String> attrs);

    /** Emits a kept start while suppressing everything through its end. */
    void openTagWithSuppressedContent(
        String elementName, List<String> attrs);

    /** Whether a prior suppressed start still suppresses its input subtree. */
    boolean isSuppressingOutputAndContent();

    /** Emits a synthetic table only if policy keeps it as a table. */
    void openReopenedTable(List<String> attrs);

    /** Whether the last synthetic table was suppressed after being renamed. */
    boolean reopenedTableWasRenamed();

    /** Reports the browser context of the elements actually emitted. */
    boolean isOutputInForeignContent();

    @Nullable String outputForeignContentRootName();

    boolean outputStartTagUsesForeignContentRules(
        String elementName, List<String> attrs);

    /** Whether this start is foreign inside retained HTML template contents. */
    boolean outputTemplateStartTagUsesForeignContentRules(
        String elementName, List<String> attrs);

    /** Whether an HTML start is handled at a foreign integration point. */
    boolean outputStartTagUsesHtmlIntegrationPointRules(
        String elementName, List<String> attrs);

  }

  /** Optional normalization for the HTML form-element pointer. */
  interface FormPointerPolicy {
    /** Whether the policy output is in a table mode that pops a form at once. */
    boolean formStartTagUsesTableRules();

    /** Whether the policy output already has a non-null form pointer. */
    boolean outputFormElementPointerIsSet();

    /**
     * Prepares the next form open and reports whether it will emit an HTML
     * form.  The following open call consumes the prepared policy result.
     */
    boolean prepareForFormStart(List<String> attrs);

    /** Prepares any start tag and returns the output name, if emitted. */
    @Nullable String prepareForStartTag(String elementName, List<String> attrs);

    /** Whether the prepared form would be an HTML form outside a template. */
    boolean preparedFormStartWillEmitAsHtml();

    /** Discards a prepared form result when the output ignores its start. */
    void discardPreparedFormStart();

    /** True while an emitted literal-output element suppresses nested starts. */
    default boolean isInKeptLiteralElement() { return false; }

    /** Closes an incompatible output suffix before an HTML start is emitted. */
    void prepareOutputForHtmlStart(
        String adjustedElementName, List<String> attrs);

    /**
     * Clears an output form pointer while table scope keeps its form element
     * on the browser stack, using a balanced pair whose start is ignored.
     */
    boolean clearFormPointerWithBalancedPair();

    /** Closes an output table while preserving its logical descendants. */
    boolean retireOutputTableForForm(boolean allowInputTable);

    /** Closes an output select while preserving its logical descendants. */
    boolean retireOutputSelectKeepingLogicalDescendants();
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

  /** Number of untracked option starts inside a suppressed mapped select. */
  private int droppedSuppressedOptionDepth;

  /** Whether the untracked option run owns one policy-stack entry. */
  private boolean droppedSuppressedOptionOwnsPolicyEntry;

  /** Logical depth below descendants of a policy-only suppressed option. */
  private int droppedSuppressedOptionStackDepth = -1;

  /** Forwarded elements open before a policy-only suppressed option. */
  private int droppedSuppressedOptionPassthroughDepth = -1;

  /** Formatting entries queued before a policy-only suppressed option. */
  private int droppedSuppressedOptionResumeDepth = -1;

  /** Number of cap-dropped tables inside the active suppressed table. */
  private int droppedSuppressedTableDepth;

  private boolean contentIsSkippable(String canonElementName) {
    if (ElementAndAttributePolicyBasedSanitizerPolicy
        .SKIPPABLE_ELEMENT_CONTENT.contains(canonElementName)) {
      return true;
    }
    return underlying instanceof TextSuppressionPolicy
        && ((TextSuppressionPolicy) underlying)
            .suppressesTextWhenDropped(canonElementName);
  }

  /**
   * Tells the listener, if any, of a start tag dropped here, which the
   * policy therefore never sees: one the nesting limit drops, or a form
   * start a browser ignores while its form element pointer is set.
   *
   * @param canonElementName the dropped tag's canonical name.  Every start
   *     tag is forwarded under its canonical name, so that is the name the
   *     policy would have been asked about, and the name a tag the policy
   *     drops is reported under.  Reporting the same name here lets a
   *     listener hear one name for a tag however it was dropped, even when
   *     a pre-processor handed this receiver the name in another case.
   */
  private void reportDroppedStartTag(String canonElementName) {
    if (underlying instanceof NestingLimitListener) {
      ((NestingLimitListener) underlying)
          .nestingLimitReached(canonElementName);
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
   * Sets the maximum element nesting depth.  A start tag that would nest the
   * output deeper is dropped.  When the receiver below was built by
   * {@link PolicyFactory#apply(HtmlStreamEventReceiver, HtmlChangeListener,
   * Object)}, its listener hears of the dropped tag through
   * {@link HtmlChangeListener#discardedTag}.  The limit may be changed while
   * a document is open, but not to less than the depth already open.
   *
   * @param limit the greatest number of elements that may be open at once.
   * @throws IllegalStateException if elements are already open deeper than
   *     {@code limit}.  With no policy below to count its own output, the
   *     elements outside this receiver's containment metadata that it has
   *     forwarded, such as custom elements, count toward that depth.
   */
  public void setNestingLimit(int limit) {
    resetMappedForeignTableSuppressionIfPolicyEnded();
    resetDroppedSuppressedTableIfPolicyEnded();
    resetDroppedSuppressedOptionIfPolicyEnded();
    int depth = effectiveNestingDepth();
    if (depth > limit) {
      throw new IllegalStateException(
          "Cannot set the nesting limit to " + limit
          + ": elements are already open " + depth + " deep");
    }
    this.nestingLimit = limit;
  }

  /**
   * How deep the output nests, which is what the limit bounds.
   * <p>
   * A policy counts every element it has open, the forwarded ones it emitted
   * included, so its own depth already covers them.  One it dropped nests
   * nothing and must not consume the budget: counting those made a run of
   * unknown tags a policy drops, such as the {@code o:p} of pasted word
   * processor markup, strip everything after it.  With no policy to ask,
   * every forwarded element reached the receiver below and nests there.
   */
  private int effectiveNestingDepth() {
    int depth = openElements.size() - syntheticSelectListItemCount();
    if (underlying instanceof OpenTagOutputPolicy) {
      depth = Math.max(
          depth, ((OpenTagOutputPolicy) underlying).outputNestingDepth());
    } else {
      depth += passthroughNames.size();
    }
    return depth;
  }

  /**
   * How many synthetic select list items are on the stack.  One is never
   * sent below, so it nests nothing in the output and must not consume the
   * budget: a select's content that fit the limit when its wrapper was
   * implied by the content has to fit again when the wrapper is explicit.
   */
  private int syntheticSelectListItemCount() {
    int n = 0;
    for (int i = openElements.size(); --i > 0;) {
      if (isSyntheticSelectListItem(i)) { ++n; }
    }
    return n;
  }

  /** Whether the entry is the never-sent list item under a select. */
  private boolean isSyntheticSelectListItem(int stackIndex) {
    return stackIndex > 0
        && openElements.get(stackIndex) == LI_TAG
        && openElements.get(stackIndex - 1) == SELECT_TAG
        && outputElements.get(stackIndex) == NO_OUTPUT_ELEMENT
        && !sentToUnderlying.get(stackIndex);
  }

  public void openDocument() {
    resetDocumentState();
    underlying.openDocument();
  }

  public void closeDocument() {
    retirePendingUnrecognizedHtmlTextElement();
    resetMappedForeignTableSuppressionIfPolicyEnded();
    resetDroppedSuppressedTableIfPolicyEnded();
    resetDroppedSuppressedOptionIfPolicyEnded();
    for (int i = openElements.size(); --i >= 0;) {
      closePassthroughsInside(i, true);
      if (!shouldSendClose(i)) { continue; }
      int elIndex = openElements.get(i);
      String elname = METADATA.canonNameForIndex(elIndex);
      underlying.closeTag(elname);
    }
    while (!passthroughNames.isEmpty()) { popPassthrough(true); }
    resetDocumentState();
    underlying.closeDocument();
  }

  /**
   * Returns every field that describes the document being balanced to its
   * value in a new instance.  Both {@link #openDocument} and
   * {@link #closeDocument} call this, so nothing of one document is left for
   * a caller to see, or the next document to inherit, whichever of the two
   * is called next.  The nesting limit is configuration rather than document
   * state and is kept.
   */
  private void resetDocumentState() {
    openElements.clear();
    inputElementSerials.clear();
    outputElements.clear();
    sentToUnderlying.clear();
    inputElementsInForeignContent.clear();
    outputElementsInForeignContent.clear();
    outputElementsStartForeignContent.clear();
    formPointerTargets.clear();
    clearedFormPointerTargets.clear();
    staleOutputFormPointerTargets.clear();
    pushedOut.clear();
    impliedInputTables.clear();
    outputTableUnavailable.clear();
    toResumeInReverse.clear();
    passthroughNames.clear();
    passthroughIndicesByName.clear();
    passthroughDepths.clear();
    passthroughSerials.clear();
    passthroughOutputForeign.clear();
    passthroughForeignRoots.clear();
    outputlessTablesWithEmittedParts.clear();
    pushedMappedTemplateOutputOpen.clear();
    suppressedMappedForeignSubtrees.clear();
    foreignContent = new HtmlSanitizer.ForeignContentContext();
    foreignRootPendingTableReturn = null;
    pendingUnrecognizedHtmlTextElement = null;
    policyOnlyTableMayBeOpen = false;
    preparingPreparedPolicyStart = false;
    insertionPointIsInForeignContent = false;
    outputlessTablePartsMayBeOpen = false;
    outputlessTablePartsOpenedAtEvent = -1;
    openTagEvent = 0;
    droppedSkippableDepth = 0;
    droppedSuppressedOptionDepth = 0;
    droppedSuppressedOptionOwnsPolicyEntry = false;
    droppedSuppressedOptionStackDepth = -1;
    droppedSuppressedOptionPassthroughDepth = -1;
    droppedSuppressedOptionResumeDepth = -1;
    droppedSuppressedTableDepth = 0;
    suppressedMappedForeignTableResumeDepth = -1;
  }

  public void openTag(String elementName, List<String> attrs) {
    retirePendingUnrecognizedHtmlTextElement();
    resetMappedForeignTableSuppressionIfPolicyEnded();
    resetDroppedSuppressedTableIfPolicyEnded();
    ++openTagEvent;
    if (DEBUG) {
      dumpState("open " + elementName);
    }
    String canonElementName = HtmlLexer.canonicalElementName(elementName);

    int elIndex = METADATA.indexForName(canonElementName);
    boolean parsingTemplateContents =
        elIndex == FORM_TAG && hasOpenTemplateElement();
    boolean formElementPointerWasSet =
        elIndex == FORM_TAG && foreignContent.formElementPointerIsSet();
    String foreignRootBefore = foreignContent.outermostForeignElementName();
    String outputForeignRootBefore = outputForeignContentRootName();
    boolean outputUsesForeignContentRules =
        outputStartTagUsesForeignContentRules(canonElementName, attrs);
    boolean outputUsesHtmlIntegrationPointRules =
        outputStartTagUsesHtmlIntegrationPointRules(canonElementName, attrs);
    // Judged before this tag: queued formatting is resumed in front of it,
    // and a tag that breaks out of foreign content is still inserted after
    // the browser pops the foreign nodes, not before.
    insertionPointIsInForeignContent = textIsInForeignContent();
    foreignContent.processStartTag(canonElementName, attrs, false);
    boolean usesForeignContentRules =
        foreignContent.lastTagUsedForeignContentRules();
    // The HTML form-pointer rules apply to an HTML form outside template
    // contents.  When the input tracker can no longer tell HTML from foreign
    // content, follow the output: a browser parsing it consults the pointer
    // only outside SVG and MathML, so a form emitted inside a foreign root
    // must not be dropped, or latch the pointer, as if it were HTML.
    boolean formUsesHtmlPointerRules = elIndex == FORM_TAG
        && !usesForeignContentRules
        && !parsingTemplateContents
        && !(foreignContent.isUnknown() && outputForeignRootBefore != null);
    int startSerial = foreignContent.lastStartTagPushedSerial();
    PushedOutTablePolicy tablePolicyAtStart = pushedOutTablePolicy();
    boolean suppressingPolicySubtree = tablePolicyAtStart != null
        && tablePolicyAtStart.isSuppressingOutputAndContent();
    if (droppedSuppressedOptionDepth != 0
        && !suppressingPolicySubtree) {
      resetDroppedSuppressedOption();
    }
    boolean optionInForeignMappedSelect = elIndex == OPTION_TAG
        && outputUsesForeignContentRules
        && hasInputTableMappedToForeignSelectInScope();
    if (optionInForeignMappedSelect) {
      // The policy result cannot be queried without consuming its stateful
      // element policy.  If it renames option, the first and second parse use
      // different HTML/foreign insertion rules.  Fail closed for this rare
      // policy-produced context, including the option's contents.
      if (droppedSuppressedOptionDepth != 0) {
        if (droppedSuppressedOptionDepth != Integer.MAX_VALUE) {
          ++droppedSuppressedOptionDepth;
        }
        reportDroppedStartTag(canonElementName);
      } else if (effectiveNestingDepth() >= nestingLimit) {
        if (!suppressingPolicySubtree) {
          // The policy-only suppression entry owns a stack entry below even
          // though nothing is emitted for it.
          tablePolicyAtStart.openTagWithoutOutputOrContent(
              canonElementName, attrs);
          droppedSuppressedOptionOwnsPolicyEntry = true;
          droppedSuppressedOptionStackDepth = openElements.size();
          droppedSuppressedOptionPassthroughDepth = passthroughNames.size();
          droppedSuppressedOptionResumeDepth = toResumeInReverse.size();
        } else {
          droppedSuppressedOptionStackDepth = openElements.size();
          droppedSuppressedOptionResumeDepth = -1;
          reportDroppedStartTag(canonElementName);
        }
        droppedSuppressedOptionDepth = 1;
      } else {
        tablePolicyAtStart.openTagWithoutOutputOrContent(
            canonElementName, attrs);
        stackElementWithoutOutput(
            elIndex, usesForeignContentRules, startSerial);
      }
      return;
    }
    if (formUsesHtmlPointerRules) {
      if (formElementPointerWasSet) {
        // Outside template contents, a browser ignores another form start
        // while its form element pointer is set.  It never reaches the
        // policy, so a listener hears of it from here, as of a tag the
        // nesting limit drops.
        reportDroppedStartTag(canonElementName);
        return;
      }
      // ForeignContentContext may have become unknown while retaining the
      // independently knowable pointer state, so keep that state synchronized
      // here for forms accepted after the unknown region.
      foreignContent.markFormElementPointerSet();
    }
    if (!pushedOut.isEmpty()
        && foreignRootBefore != null
        && !usesForeignContentRules
        && foreignContent.outermostForeignElementName() == null) {
      foreignRootPendingTableReturn = outputForeignRootBefore != null
          ? foreignRootBefore : null;
    }
    boolean mayOpenAtNestingLimit = true;
    if (isForeignContentRoot(canonElementName)
        && !usesForeignContentRules
        && foreignRootArrivesInTableMode()) {
      // An SVG or MathML root that HTML rules insert in a table insertion
      // mode is foster-parented like any other content there, after an open
      // column group is popped.  Anywhere else a browser inserts it where it
      // is, so the containment metadata, which has no entry for it and would
      // imply a list item or select wrapper around it, is not consulted.
      mayOpenAtNestingLimit = prepareForContent(elIndex);
    }
    if ((usesForeignContentRules
            || foreignRootPendingTableReturn != null
            || hasPushedOutputlessTableWithEmittedParts())
        && outputUsesForeignContentRules
        && TABLE_PARTS.get(elIndex)
        && isOutputInForeignContent()) {
      // HTML table balancing does not apply to SVG or MathML descendants, even
      // when a local name happens to be a table part.
      // An HTML integration point makes ForeignContentContext report HTML
      // rules and deliberately does not take this path.
      if (effectiveNestingDepth() >= nestingLimit) {
        reportDroppedStartTag(canonElementName);
        return;
      }
      underlying.openTag(canonElementName, attrs);
      pushPassthrough(canonElementName, startSerial);
      return;
    }
    // Treat unrecognized tags as void, but emit closing tags in closeTag().
    // They go below under their canonical name, like recognized tags: the
    // policy prepares its result under that name, and a preprocessor can
    // hand this receiver a name in a case the lexer would not.
    if (elIndex == UNRECOGNIZED_TAG) {
      if (mayOpenAtNestingLimit && effectiveNestingDepth() < nestingLimit) {
        FormPointerPolicy policy = underlying instanceof FormPointerPolicy
            ? (FormPointerPolicy) underlying : null;
        boolean suppressPreparedOutput = false;
        boolean suppressForeignBreakoutBesidePushedTable = false;
        boolean leaveHtmlTextElementPending = false;
        @Nullable String preparedOutputName = null;
        if (policy != null && !suppressingPolicySubtree) {
          preparedOutputName = policy.prepareForStartTag(
              canonElementName, attrs);
          preparingPreparedPolicyStart = true;
          try {
            if (preparedOutputName != null) {
              int outputTableContext = outputTableContextForStart();
              // A foreign element beside a pushed-out table whose output
              // would be HTML, because the output's foreign root was popped
              // by an emitted breakout or the policy renamed the element,
              // lands where this receiver cannot follow it, so it is
              // suppressed with its contents.  That needs the output to have
              // entered the foreign region at all: when the policy dropped
              // the root, or renamed it to an HTML element, the elements
              // inside it are ordinary HTML beside the table, like their
              // siblings, and go through like them.
              suppressForeignBreakoutBesidePushedTable =
                  usesForeignContentRules
                  && !foreignContent.lastStartTagOpenedIntegrationPoint()
                  && !pushedOut.isEmpty()
                  && (outputForeignRootBefore != null
                      || forwardedForeignRootEnteredOutput())
                  && !"table".equals(HtmlLexer.canonicalElementName(
                      preparedOutputName))
                  && !outputStartTagUsesForeignContentRules(
                      preparedOutputName, attrs);
              if ((usesForeignContentRules
                      || "form".equals(HtmlLexer.canonicalElementName(
                          preparedOutputName))
                      || (outputContainerIsParagraph()
                          && !canonElementName.equals(
                              HtmlLexer.canonicalElementName(
                                  preparedOutputName)))
                      || (outputContainerIsAnchor()
                          && "a".equals(HtmlLexer.canonicalElementName(
                              preparedOutputName))))
                  && !suppressForeignBreakoutBesidePushedTable
                  && !(usesForeignContentRules
                      && foreignContent.lastStartTagOpenedIntegrationPoint()
                      && !"table".equals(HtmlLexer.canonicalElementName(
                          preparedOutputName)))
                  && !outputStartTagUsesForeignContentRules(
                      preparedOutputName, attrs)) {
                if (usesForeignContentRules && outputTableContext != -1) {
                  prepareForOutputStart(
                      preparedOutputName, attrs, outputTableContext);
                }
                policy.prepareOutputForHtmlStart(preparedOutputName, attrs);
                outputTableContext = outputTableContextForStart();
              }
              suppressPreparedOutput = shouldSuppressUnalignedOutputStart(
                  canonElementName, preparedOutputName,
                  outputTableContext, policy)
                  || suppressForeignBreakoutBesidePushedTable;
              int logicalTop = openElements.size() - 1;
              boolean exposedByExplicitOutputlessTable =
                  topIsOutputlessInputTable()
                  && !impliedInputTables.get(logicalTop)
                  && (outputlessTablePartsMayBeOpen
                      || outputlessTablesWithEmittedParts.get(logicalTop));
              boolean exposedByTemplateAboveOutputlessTable =
                  hasOutputTemplateAboveOutputlessTable()
                  && !hasOpenHtmlOutputSelect();
              boolean isDirectHtmlTextArea =
                  canonElementName.equals(preparedOutputName)
                  && "textarea".equals(Strings.toLowerCase(
                      preparedOutputName))
                  && !outputStartTagUsesForeignContentRules(
                      preparedOutputName, attrs)
                  && !hasOpenHtmlOutputTable();
              boolean deferHtmlTextElementClose =
                  isDirectHtmlTextArea
                  && exposedByTemplateAboveOutputlessTable;
              boolean directHtmlTextAreaOutsidePhysicalTable =
                  isDirectHtmlTextArea
                  && !exposedByExplicitOutputlessTable
                  && !exposedByTemplateAboveOutputlessTable;
              if (directHtmlTextAreaOutsidePhysicalTable
                  && topIsOutputlessInputTable()) {
                int top = openElements.size() - 1;
                closeStackFrom(top, TABLE_TAG);
              }
              if (!directHtmlTextAreaOutsidePhysicalTable
                  && !deferHtmlTextElementClose
                  && (outputTableContext != -1
                      || !pushedOut.isEmpty()
                      || hasUnavailableInputTableInScope()
                      || exposedByExplicitOutputlessTable)
                  && !outputStartTagUsesForeignContentRules(
                      preparedOutputName, attrs)
                  && hasSpecialTextMode(METADATA.indexForName(
                      Strings.toLowerCase(preparedOutputName)))) {
                suppressPreparedOutput = true;
              }
              leaveHtmlTextElementPending =
                  deferHtmlTextElementClose;
              if (!suppressPreparedOutput
                  && outputTableContext != -1
                  && outputStartNeedsTablePreparation(
                      canonElementName, preparedOutputName,
                      outputTableContext)) {
                prepareForOutputStart(
                    preparedOutputName, attrs, outputTableContext);
              }
              int preparedOutputIndex = METADATA.indexForName(
                  HtmlLexer.canonicalElementName(preparedOutputName));
              // A foreign root the policy emits is prepared like one the
              // input wrote: only where a browser foster-parents it.
              boolean preparedForeignRootInTableMode =
                  isForeignContentRoot(preparedOutputName)
                  && foreignRootArrivesInTableMode();
              if (!suppressPreparedOutput
                  && (!canonElementName.equals(preparedOutputName)
                      || preparedForeignRootInTableMode)
                  && (preparedOutputIndex != UNRECOGNIZED_TAG
                      || preparedForeignRootInTableMode)) {
                mayOpenAtNestingLimit &=
                    prepareForContent(preparedOutputIndex, false);
              }
            }
          } finally {
            preparingPreparedPolicyStart = false;
          }
        }
        if (!mayOpenAtNestingLimit
            || effectiveNestingDepth() >= nestingLimit) {
          if (policy != null) { policy.discardPreparedFormStart(); }
          if (contentIsSkippable(canonElementName)) {
            ++droppedSkippableDepth;
          }
          reportDroppedStartTag(canonElementName);
        } else if (suppressPreparedOutput) {
          PushedOutTablePolicy tablePolicy = pushedOutTablePolicy();
          if (suppressForeignBreakoutBesidePushedTable
              || (preparedOutputName != null
                  && "template".equals(HtmlLexer.canonicalElementName(
                      preparedOutputName)))) {
            tablePolicy.openTagWithoutOutputOrContent(
                canonElementName, attrs);
          } else {
            tablePolicy.openTagWithoutOutput(canonElementName, attrs);
          }
          pushPassthrough(canonElementName, startSerial);
        } else {
          underlying.openTag(canonElementName, attrs);
          pushPassthrough(canonElementName, startSerial);
          if (leaveHtmlTextElementPending
              && underlying instanceof OpenTagOutputPolicy
              && preparedOutputName.equals(
                  ((OpenTagOutputPolicy) underlying)
                      .outputElementNameForLastOpenTag())) {
            pendingUnrecognizedHtmlTextElement = canonElementName;
          }
          if (outputElementIndexForLastOpenTag(UNRECOGNIZED_TAG)
              == TABLE_TAG) {
            policyOnlyTableMayBeOpen = true;
          }
        }
      } else {
        if (contentIsSkippable(canonElementName)) { ++droppedSkippableDepth; }
        reportDroppedStartTag(canonElementName);
      }
      return;
    }

    if (elIndex == A_TAG) {
      // A browser ends a link when the next begins, and drops the old link
      // from its list of active formatting elements, so a link closed with an
      // earlier container and queued to resume is not resumed around content
      // after the new one either.
      forgetQueuedFormatting(A_TAG);
    }
    int formTableContext = elIndex == FORM_TAG
        ? formStartTagTableContext(
            usesForeignContentRules, outputUsesForeignContentRules)
        : -1;
    if (!suppressingPolicySubtree
        && (!outputUsesHtmlIntegrationPointRules || TABLE_PARTS.get(elIndex))
        && (elIndex != FORM_TAG
            || !usesForeignContentRules
            || !outputUsesForeignContentRules)) {
      mayOpenAtNestingLimit &= prepareForContent(
          elIndex,
          elIndex != TABLE_TAG || !hasUnavailableInputTableInScope());
    }
    suppressingPolicySubtree = tablePolicyAtStart != null
        && tablePolicyAtStart.isSuppressingOutputAndContent();

    if (mayOpenAtNestingLimit && effectiveNestingDepth() < nestingLimit) {
      FormPointerPolicy formPolicy = underlying instanceof FormPointerPolicy
          ? (FormPointerPolicy) underlying : null;
      boolean formStartPrepared = false;
      boolean preparedFormWillEmitAsHtml = false;
      boolean suppressPreparedOutputForm = false;
      boolean suppressedMappedForeignTemplateStart = false;
      boolean suppressMappedForeignTableContents = false;
      @Nullable String preparedOutputName = null;
      int outputTableContext = outputTableContextForStart();
      if (formPolicy != null && !suppressingPolicySubtree) {
        preparedOutputName = formPolicy.prepareForStartTag(
            canonElementName, attrs);
        preparingPreparedPolicyStart = true;
        try {
          formStartPrepared = elIndex == FORM_TAG;
          preparedFormWillEmitAsHtml = formStartPrepared
              && formPolicy.preparedFormStartWillEmitAsHtml();
          if (preparedOutputName != null
              && "style".equals(HtmlLexer.canonicalElementName(
                  preparedOutputName))
              && hasDroppedTableInSyntheticSelectListItemContext()) {
            formPolicy.retireOutputSelectKeepingLogicalDescendants();
          }
          if (preparedOutputName != null
              && (usesForeignContentRules
                  || (outputContainerIsParagraph()
                      && (!canonElementName.equals(
                              HtmlLexer.canonicalElementName(
                                  preparedOutputName))
                          || "p".equals(HtmlLexer.canonicalElementName(
                              preparedOutputName))
                          || (elIndex == FORM_TAG
                              && preparedFormWillEmitAsHtml
                              && !hasUnavailableInputTableInScope())))
                  || (outputContainerIsAnchor()
                      && "a".equals(HtmlLexer.canonicalElementName(
                          preparedOutputName))))
              && !(usesForeignContentRules
                  && foreignContent.lastStartTagOpenedIntegrationPoint()
                  && !"table".equals(HtmlLexer.canonicalElementName(
                      preparedOutputName)))
              && !outputStartTagUsesForeignContentRules(
                  preparedOutputName, attrs)) {
            int preparedOutputIndex = METADATA.indexForName(
                HtmlLexer.canonicalElementName(preparedOutputName));
            if (preparedOutputIndex != UNRECOGNIZED_TAG
                && (!canonElementName.equals(preparedOutputName)
                    || usesForeignContentRules)) {
              mayOpenAtNestingLimit &=
                  prepareForContent(preparedOutputIndex, false);
            }
            // A table part inside literal output will be deferred by the policy,
            // so it must not retire that literal output during preflight.
            if (!(TABLE_PARTS.get(elIndex)
                  && formPolicy.isInKeptLiteralElement()
                  && hasOpenLiteralOutputFromImpliedTable())) {
              formPolicy.prepareOutputForHtmlStart(preparedOutputName, attrs);
            }
            outputTableContext = outputTableContextForStart();
          }
          suppressPreparedOutputForm = elIndex != FORM_TAG
              && preparedOutputName != null
              && (shouldSuppressUnalignedOutputStart(
                      canonElementName, preparedOutputName,
                      outputTableContext, formPolicy)
                  || (!canonElementName.equals(
                          HtmlLexer.canonicalElementName(preparedOutputName))
                      && (outputTableContext != -1
                          || !pushedOut.isEmpty()
                          || hasUnavailableInputTableInScope())
                      && !outputStartTagUsesForeignContentRules(
                          preparedOutputName, attrs)
                      && hasSpecialTextMode(METADATA.indexForName(
                          Strings.toLowerCase(preparedOutputName)))));
          suppressedMappedForeignTemplateStart = suppressPreparedOutputForm
              && elIndex == TEMPLATE_TAG
              && isForeignContentRoot(preparedOutputName);
          suppressMappedForeignTableContents = elIndex == TABLE_TAG
              && preparedOutputName != null
              && "select".equals(HtmlLexer.canonicalElementName(
                  preparedOutputName))
              && !hasUnavailableInputTableInScope()
              && (outputStartTagUsesForeignContentRules(
                      preparedOutputName, attrs)
                  || outputTemplateStartTagUsesForeignContentRules(
                      preparedOutputName, attrs));
          if (preparedOutputName != null
              && outputTableContext != -1
              && outputStartNeedsTablePreparation(
                  canonElementName, preparedOutputName, outputTableContext)) {
            if (!suppressPreparedOutputForm) {
              prepareForOutputStart(
                  preparedOutputName, attrs, outputTableContext);
            }
            if (elIndex == FORM_TAG) {
              formTableContext = formStartTagTableContext(
                  usesForeignContentRules, outputUsesForeignContentRules);
            }
          }
        } finally {
          preparingPreparedPolicyStart = false;
        }
      }
      if (!mayOpenAtNestingLimit
          || effectiveNestingDepth() >= nestingLimit) {
        retireContainerForUnemittedListChild(elIndex);
        if (formPolicy != null) { formPolicy.discardPreparedFormStart(); }
        if (formUsesHtmlPointerRules) {
          // The pointer was set for this form above.  The form is not in
          // the output, so the output parser's pointer stays null, and a
          // later form must not be ignored on its account.
          foreignContent.clearFormElementPointer();
        }
        if (contentIsSkippable(canonElementName)) {
          ++droppedSkippableDepth;
        }
        reportDroppedStartTag(canonElementName);
        return;
      }
      if (elIndex == FORM_TAG
          && formTableContext != -1
          && formPolicy != null) {
        if (formPolicy.outputFormElementPointerIsSet()) {
          if (!formStartPrepared) {
            preparedFormWillEmitAsHtml =
                formPolicy.prepareForFormStart(attrs);
            formStartPrepared = true;
          }
          if (preparedFormWillEmitAsHtml) {
            // The output parser ignores this start because its pointer is set.
            // Do not send an end tag either: it would clear the existing pointer.
            formPolicy.discardPreparedFormStart();
            retireOutputTableForForm(formTableContext);
            if (usesForeignContentRules) {
              stackForeignFormWithoutOutput(startSerial);
            }
            return;
          }
        }
      }
      if (elIndex == FORM_TAG
          && !clearedFormPointerTargets.isEmpty()
          && (formStartPrepared
              ? preparedFormWillEmitAsHtml : formWillEmitAsHtml(attrs))) {
        retireClearedOutputFormPointer();
        formTableContext = formStartTagTableContext(
            usesForeignContentRules, outputUsesForeignContentRules);
      }
      int outputElementIndex;
      if (suppressPreparedOutputForm) {
        PushedOutTablePolicy tablePolicy = pushedOutTablePolicy();
        if (preparedOutputName != null
            && "template".equals(HtmlLexer.canonicalElementName(
                preparedOutputName))) {
          tablePolicy.openTagWithoutOutputOrContent(canonElementName, attrs);
        } else {
          tablePolicy.openTagWithoutOutput(canonElementName, attrs);
        }
        outputElementIndex = NO_OUTPUT_ELEMENT;
      } else if (suppressMappedForeignTableContents) {
        tablePolicyAtStart.openTagWithSuppressedContent(
            canonElementName, attrs);
        outputElementIndex = outputElementIndexForLastOpenTag(elIndex);
      } else {
        outputElementIndex = openElement(elIndex, attrs);
      }
      boolean outputElementIsForeign =
          lastOutputElementUsedForeignContentRules();
      if (formTableContext != -1) {
        // The in-table rule inserts the form and immediately pops it.  Send a
        // balanced empty element downstream, but leave the input form pointer
        // set until an actual </form> arrives.
        underlying.closeTag(canonElementName);
        retireOutputTableForForm(formTableContext);
        if (usesForeignContentRules) {
          stackForeignFormWithoutOutput(startSerial);
        }
      } else if (!HtmlTextEscapingMode.isVoidElement(canonElementName)) {
        int stackIndex = openElements.size();
        openElements.add(elIndex);
        inputElementSerials.add(startSerial);
        outputElements.add(outputElementIndex);
        outputlessTablesWithEmittedParts.clear(stackIndex);
        pushedMappedTemplateOutputOpen.clear(stackIndex);
        suppressedMappedForeignSubtrees.set(
            stackIndex,
            suppressedMappedForeignTemplateStart
                || suppressMappedForeignTableContents);
        if (suppressMappedForeignTableContents) {
          droppedSuppressedTableDepth = 0;
          suppressedMappedForeignTableResumeDepth =
              toResumeInReverse.size();
        }
        sentToUnderlying.set(stackIndex);
        inputElementsInForeignContent.set(stackIndex, usesForeignContentRules);
        outputElementsInForeignContent.set(
            stackIndex, outputElementIsForeign);
        outputElementsStartForeignContent.set(
            stackIndex, outputElementIndex != NO_OUTPUT_ELEMENT
                && lastOutputElementStartsForeignContent(canonElementName));
        clearedFormPointerTargets.clear(stackIndex);
        staleOutputFormPointerTargets.clear(stackIndex);
        impliedInputTables.clear(stackIndex);
        if (elIndex == TABLE_TAG
            && outputUsesHtmlIntegrationPointRules
            && outputElementIndex != TABLE_TAG
            && outputElementIndex != TEMPLATE_TAG
            && !outputElementIsForeign
            && !outputElementsStartForeignContent.get(stackIndex)) {
          outputTableUnavailable.set(stackIndex);
        }
        if (formUsesHtmlPointerRules) {
          formPointerTargets.clear();
          formPointerTargets.set(stackIndex);
        }
        recordEmittedPartForOutputlessTable(
            stackIndex + 1, outputElementIndex, outputElementIsForeign);
      }
    } else {
      retireContainerForUnemittedListChild(elIndex);
      if (formUsesHtmlPointerRules) {
        // Dropped at the limit, as above: not in the output, so no pointer.
        foreignContent.clearFormElementPointer();
      }
      if (elIndex == TABLE_TAG
          && suppressingPolicySubtree
          && suppressedMappedForeignTableIndex() >= 0
          && droppedSuppressedTableDepth != Integer.MAX_VALUE) {
        ++droppedSuppressedTableDepth;
      }
      if (contentIsSkippable(canonElementName)) { ++droppedSkippableDepth; }
      reportDroppedStartTag(canonElementName);
    }
  }

  /** Whether a policy rename lacks enough input structure to balance safely. */
  private boolean shouldSuppressUnalignedOutputStart(
      String inputElementName, String outputElementName, int tableContext,
      FormPointerPolicy policy) {
    if (inputElementName.equals(
            HtmlLexer.canonicalElementName(outputElementName))
        || pushedOutTablePolicy() == null) {
      return false;
    }
    int outputElement = METADATA.indexForName(
        HtmlLexer.canonicalElementName(outputElementName));
    boolean tableOrListStructure = TABLE_PARTS.get(outputElement)
        || outputElement == LI_TAG || outputElement == OPTION_TAG;
    if (tableContext == -1
        && pushedOut.isEmpty()
        && !(hasOpenHtmlOutputTemplate() && tableOrListStructure)) {
      return false;
    }
    if ("table".equals(inputElementName)
        && isForeignContentRoot(outputElementName)) {
      // SVG and MathML use their own insertion rules, so table-part local
      // names can remain children of the mapped root without table recovery.
      return false;
    }
    if (hasSpecialTextMode(outputElement)) {
      return true;
    }
    if ("form".equals(outputElementName)) {
      return tableContext != -1
          && policy.preparedFormStartWillEmitAsHtml();
    }
    return tableOrListStructure
        || outputElement == SELECT_TAG
        || outputElement == TEMPLATE_TAG
        || isForeignContentRoot(outputElementName);
  }

  /** The nearest represented or policy-only HTML table insertion context. */
  private int outputTableContextForStart() {
    if (policyOnlyTableMayBeOpen) {
      int policyContext = policyOnlyFormTableContext();
      if (policyContext != -1) { return policyContext; }
    }
    for (int i = openElements.size(); --i >= 0;) {
      if (!sentToUnderlying.get(i)
          || pushedOut.get(i)
          || outputElementsInForeignContent.get(i)) {
        continue;
      }
      int outputElement = outputElements.get(i);
      if (outputElement == NO_OUTPUT_ELEMENT) { continue; }
      if (TABLE_FORM_SCOPE_BOUNDARIES.get(outputElement)) { return -1; }
      if (outputElement == TABLE_TAG) { return i; }
    }
    return policyOnlyFormTableContext();
  }

  /** Prepares one policy result and balances the output table around it. */
  private boolean preparePolicyStartInOutputTable(
      String inputElementName, List<String> attrs) {
    if (preparingPreparedPolicyStart
        || !(underlying instanceof FormPointerPolicy)) {
      return false;
    }
    FormPointerPolicy policy = (FormPointerPolicy) underlying;
    String preparedOutputName = policy.prepareForStartTag(
        inputElementName, attrs);
    if (preparedOutputName == null) { return false; }
    int outputTableContext = outputTableContextForStart();
    if (outputTableContext == -1) { return false; }
    if (!"form".equals(inputElementName)
        && "form".equals(preparedOutputName)
        && pushedOutTablePolicy() != null
        && policy.preparedFormStartWillEmitAsHtml()) {
      // The output parser would insert this mapped form in table mode and
      // pop it immediately, while the input element may remain open.  Keep
      // the logical input entry but suppress the unstable mapped start.
      return true;
    }
    if (preparedOutputName != null) {
      if (outputStartNeedsTablePreparation(
          inputElementName, preparedOutputName, outputTableContext)) {
        prepareForOutputStart(
            preparedOutputName, attrs, outputTableContext);
      }
    }
    return false;
  }

  /** Whether input balancing alone cannot place this output start safely. */
  private boolean outputStartNeedsTablePreparation(
      String inputElementName, String outputElementName, int tableContext) {
    return !inputElementName.equals(
                HtmlLexer.canonicalElementName(outputElementName))
        || tableContext < 0
        || tableContext >= openElements.size()
        || openElements.get(tableContext) != outputElements.get(tableContext)
        || !outputSuffixMatchesInput(tableContext);
  }

  /** Balances a table before a prepared output tag that cannot stay in it. */
  private void prepareForOutputStart(
      String outputElementName, List<String> attrs, int tableContext) {
    if (outputStartTagUsesForeignContentRules(outputElementName, attrs)) {
      return;
    }
    int outputElement = METADATA.indexForName(
        HtmlLexer.canonicalElementName(outputElementName));
    if (outputElement != TABLE_TAG
        && METADATA.canContain(TABLE_TAG, outputElement)) {
      return;
    }
    retireOutputTableForFosteredContent(tableContext);
  }

  /** Closes an output table before content its insertion mode fosters out. */
  private void retireOutputTableForFosteredContent(int tableContext) {
    if (tableContext == POLICY_ONLY_TABLE_CONTEXT) {
      ((FormPointerPolicy) underlying).retireOutputTableForForm(false);
      return;
    }
    if (tableContext < 0 || tableContext >= openElements.size()) { return; }
    if (openElements.get(tableContext) != TABLE_TAG) {
      retireMappedOutputTable(tableContext);
      return;
    }
    if (outputSuffixMatchesInput(tableContext)) {
      int top = tableContext;
      for (int i = tableContext + 1, n = openElements.size(); i < n; ++i) {
        if (sentToUnderlying.get(i)
            && !pushedOut.get(i)
            && !outputElementsInForeignContent.get(i)
            && TABLE_CONTEXT.get(outputElements.get(i))) {
          top = i;
        }
      }
      pushOutTable(top);
      return;
    }
    if (underlying instanceof FormPointerPolicy
        && ((FormPointerPolicy) underlying)
            .retireOutputTableForForm(true)) {
      markRetiredTableDescendants(tableContext);
      pushedOut.set(tableContext);
      outputTableUnavailable.set(tableContext);
    }
  }

  /** Keeps an input foreign form from closing an older HTML form on its end. */
  private void stackForeignFormWithoutOutput(int serial) {
    int stackIndex = openElements.size();
    openElements.add(FORM_TAG);
    inputElementSerials.add(serial);
    outputElements.add(NO_OUTPUT_ELEMENT);
    outputlessTablesWithEmittedParts.clear(stackIndex);
    pushedMappedTemplateOutputOpen.clear(stackIndex);
    suppressedMappedForeignSubtrees.clear(stackIndex);
    sentToUnderlying.clear(stackIndex);
    inputElementsInForeignContent.set(stackIndex);
    outputElementsInForeignContent.clear(stackIndex);
    outputElementsStartForeignContent.clear(stackIndex);
    formPointerTargets.clear(stackIndex);
    clearedFormPointerTargets.clear(stackIndex);
    staleOutputFormPointerTargets.clear(stackIndex);
    pushedOut.clear(stackIndex);
    impliedInputTables.clear(stackIndex);
    outputTableUnavailable.clear(stackIndex);
  }

  /** Keeps a deliberately suppressed start available for its matching end. */
  private void stackElementWithoutOutput(
      int element, boolean inputUsesForeignContentRules, int serial) {
    int stackIndex = openElements.size();
    openElements.add(element);
    inputElementSerials.add(serial);
    outputElements.add(NO_OUTPUT_ELEMENT);
    sentToUnderlying.set(stackIndex);
    inputElementsInForeignContent.set(
        stackIndex, inputUsesForeignContentRules);
    outputElementsInForeignContent.clear(stackIndex);
    outputElementsStartForeignContent.clear(stackIndex);
    formPointerTargets.clear(stackIndex);
    clearedFormPointerTargets.clear(stackIndex);
    staleOutputFormPointerTargets.clear(stackIndex);
    pushedOut.clear(stackIndex);
    impliedInputTables.clear(stackIndex);
    outputTableUnavailable.clear(stackIndex);
    outputlessTablesWithEmittedParts.clear(stackIndex);
    pushedMappedTemplateOutputOpen.clear(stackIndex);
    suppressedMappedForeignSubtrees.clear(stackIndex);
  }

  /** Removes shadow entries whose policy-stack counterparts already closed. */
  private void discardStackSuffix(int fromIndex) {
    for (int i = openElements.size(); --i >= fromIndex;) {
      closePassthroughsInside(i, false);
      openElements.remove(i);
      inputElementSerials.remove(i);
      outputElements.remove(i);
      sentToUnderlying.clear(i);
      inputElementsInForeignContent.clear(i);
      outputElementsInForeignContent.clear(i);
      outputElementsStartForeignContent.clear(i);
      formPointerTargets.clear(i);
      clearedFormPointerTargets.clear(i);
      staleOutputFormPointerTargets.clear(i);
      pushedOut.clear(i);
      impliedInputTables.clear(i);
      outputTableUnavailable.clear(i);
      outputlessTablesWithEmittedParts.clear(i);
      pushedMappedTemplateOutputOpen.clear(i);
      suppressedMappedForeignSubtrees.clear(i);
    }
  }

  /** The table whose policy-produced foreign select suppresses its contents. */
  private int suppressedMappedForeignTableIndex() {
    // Asked on every event, and the scan can only find a marked table.
    if (suppressedMappedForeignSubtrees.isEmpty()) { return -1; }
    for (int i = openElements.size(); --i >= 0;) {
      if (openElements.get(i) == TABLE_TAG
          && suppressedMappedForeignSubtrees.get(i)) {
        return i;
      }
    }
    return -1;
  }

  /** Whether a tracked descendant table should consume the next table end. */
  private boolean hasOpenTableAbove(int stackIndex) {
    for (int i = openElements.size(); --i > stackIndex;) {
      if (openElements.get(i) == TABLE_TAG) { return true; }
    }
    return false;
  }

  /**
   * Removes logical state left after an ancestor end closed the policy's
   * suppressed select before the input table itself ended.
   */
  private void resetMappedForeignTableSuppressionIfPolicyEnded() {
    int tableIndex = suppressedMappedForeignTableIndex();
    if (tableIndex >= 0) {
      PushedOutTablePolicy policy = pushedOutTablePolicy();
      if (policy != null && policy.isSuppressingOutputAndContent()) { return; }
      discardStackSuffix(tableIndex);
    } else if (suppressedMappedForeignTableResumeDepth < 0) {
      return;
    }
    if (suppressedMappedForeignTableResumeDepth >= 0) {
      while (toResumeInReverse.size()
          > suppressedMappedForeignTableResumeDepth) {
        toResumeInReverse.removeLast();
      }
    }
    droppedSuppressedTableDepth = 0;
    droppedSuppressedOptionDepth = 0;
    droppedSuppressedOptionOwnsPolicyEntry = false;
    droppedSuppressedOptionStackDepth = -1;
    droppedSuppressedOptionPassthroughDepth = -1;
    droppedSuppressedOptionResumeDepth = -1;
    suppressedMappedForeignTableResumeDepth = -1;
  }

  /** Clears a dropped-table shadow when its suppression owner has ended. */
  private void resetDroppedSuppressedTableIfPolicyEnded() {
    if (droppedSuppressedTableDepth != 0
        && suppressedMappedForeignTableIndex() < 0) {
      droppedSuppressedTableDepth = 0;
    }
  }

  /** Retires logical and formatting state from a policy-suppressed option. */
  private void resetDroppedSuppressedOption() {
    if (droppedSuppressedOptionOwnsPolicyEntry
        && droppedSuppressedOptionStackDepth >= 0) {
      discardStackSuffix(droppedSuppressedOptionStackDepth);
      popPassthroughsForwardedSince(droppedSuppressedOptionPassthroughDepth);
    }
    if (droppedSuppressedOptionResumeDepth >= 0) {
      while (toResumeInReverse.size()
          > droppedSuppressedOptionResumeDepth) {
        toResumeInReverse.removeLast();
      }
    }
    droppedSuppressedOptionDepth = 0;
    droppedSuppressedOptionOwnsPolicyEntry = false;
    droppedSuppressedOptionStackDepth = -1;
    droppedSuppressedOptionPassthroughDepth = -1;
    droppedSuppressedOptionResumeDepth = -1;
  }

  /** Retires a virtual option after the policy has already closed it. */
  private void resetDroppedSuppressedOptionIfPolicyEnded() {
    if (droppedSuppressedOptionDepth == 0) { return; }
    PushedOutTablePolicy policy = pushedOutTablePolicy();
    if (policy == null || !policy.isSuppressingOutputAndContent()) {
      resetDroppedSuppressedOption();
    }
  }

  /** Whether a normal stacked option is inside the untracked option run. */
  private boolean hasTrackedOptionAtOrAbove(int stackIndex) {
    if (stackIndex < 0) { return false; }
    for (int i = openElements.size(); --i >= stackIndex;) {
      if (openElements.get(i) == OPTION_TAG) { return true; }
    }
    return false;
  }

  /** Whether an HTML form start is handled by the special in-table rule. */
  private int formStartTagTableContext(
      boolean inputUsesForeignContentRules,
      boolean outputUsesForeignContentRules) {
    if (inputUsesForeignContentRules && outputUsesForeignContentRules) {
      return -1;
    }
    for (int i = openElements.size(); --i >= 0;) {
      int inputElement = openElements.get(i);
      int outputElement = outputElements.get(i);
      if (outputTableUnavailable.get(i)) { return -1; }
      if (inputElement == TABLE_TAG) {
        if (pushedOut.get(i)) {
          int policyContext = policyOnlyFormTableContext();
          if (policyContext != -1) { return policyContext; }
          if (outputForeignContentRootName() != null) { return -1; }
          return impliedInputTables.get(i) ? -1 : INPUT_ONLY_TABLE_CONTEXT;
        }
        // A table that policy dropped or renamed cannot put the sanitized
        // output in a table insertion mode.  Following that output context
        // keeps a second sanitization from changing the form's extent.
        return outputElement == TABLE_TAG
            && !outputElementsInForeignContent.get(i) ? i : -1;
      }
      if (outputElement != NO_OUTPUT_ELEMENT
          && TABLE_FORM_SCOPE_BOUNDARIES.get(outputElement)) {
        return policyOnlyFormTableContext();
      }
      if (outputElement == TABLE_TAG
          && !outputElementsInForeignContent.get(i)) {
        return i;
      }
    }
    return policyOnlyFormTableContext();
  }

  /** Table context known only to the policy's more complete output stack. */
  private int policyOnlyFormTableContext() {
    return underlying instanceof FormPointerPolicy
        && ((FormPointerPolicy) underlying).formStartTagUsesTableRules()
        ? POLICY_ONLY_TABLE_CONTEXT : -1;
  }

  /** Retires a mapped table represented on either available output stack. */
  private void retireOutputTableForForm(int tableContext) {
    if (tableContext == INPUT_ONLY_TABLE_CONTEXT) {
      return;
    } else if (tableContext == POLICY_ONLY_TABLE_CONTEXT) {
      ((FormPointerPolicy) underlying).retireOutputTableForForm(false);
    } else if (tableContext >= 0
        && openElements.get(tableContext) == TABLE_TAG) {
      if (tableContext + 1 < openElements.size()
          && sentToUnderlying.get(tableContext)
          && !pushedOut.get(tableContext)
          && outputElements.get(tableContext) == TABLE_TAG
          && !outputElementsInForeignContent.get(tableContext)
          && outputSuffixChangesTableInsertionMode(tableContext)
          && underlying instanceof FormPointerPolicy
          && ((FormPointerPolicy) underlying)
              .retireOutputTableForForm(true)) {
        // A dropped or renamed template can leave the logical input context
        // above a physical output table.  Content after an output-ignored form
        // would be foster-parented from that table even though the logical
        // template contains it, so close the table now as the text path would
        // if the dropped boundary were absent.  A dropped row group or row is
        // no such boundary: the output parser implies it again, the form is
        // inserted in the row and popped, and the table stays open for the
        // cells that follow.
        markRetiredTableDescendants(tableContext);
        pushedOut.set(tableContext);
        outputTableUnavailable.set(tableContext);
      }
    } else {
      retireMappedOutputTable(tableContext);
    }
  }

  /** Whether the output suffix represents the same parser contexts as input. */
  private boolean outputSuffixMatchesInput(int tableContext) {
    for (int i = tableContext + 1, n = openElements.size(); i < n; ++i) {
      if (!sentToUnderlying.get(i)
          || pushedOut.get(i)
          || outputElements.get(i) != openElements.get(i)
          || outputElementsInForeignContent.get(i)
              != inputElementsInForeignContent.get(i)) {
        return false;
      }
    }
    return true;
  }

  /**
   * Whether the output between this table and the current position parses
   * in a different table insertion mode than the input did.  A {@code tbody}
   * or {@code tr} the policy dropped does not change it: those are exactly
   * what the output parser implies again for the row or cell that follows.
   * A dropped {@code thead} or {@code tfoot} does, since the parser implies a
   * {@code tbody} in its place and a policy that keeps tbody then emits one
   * on the next pass.  Anything else missing or renamed, such as a dropped
   * template, does too.
   */
  private boolean outputSuffixChangesTableInsertionMode(int tableContext) {
    for (int i = tableContext + 1, n = openElements.size(); i < n; ++i) {
      int inputElement = openElements.get(i);
      if (outputElements.get(i) == NO_OUTPUT_ELEMENT
          && !pushedOut.get(i)
          && (inputElement == TBODY_TAG || inputElement == TR_TAG)) {
        continue;
      }
      if (!sentToUnderlying.get(i)
          || pushedOut.get(i)
          || outputElements.get(i) != inputElement
          || outputElementsInForeignContent.get(i)
              != inputElementsInForeignContent.get(i)) {
        return true;
      }
    }
    return false;
  }

  /** Mirrors descendants that the policy retained without output elements. */
  private void markRetiredTableDescendants(int tableContext) {
    for (int i = tableContext + 1, n = openElements.size(); i < n; ++i) {
      outputElements.set(i, NO_OUTPUT_ELEMENT);
      outputElementsInForeignContent.clear(i);
      outputElementsStartForeignContent.clear(i);
      clearedFormPointerTargets.clear(i);
      staleOutputFormPointerTargets.clear(i);
      pushedMappedTemplateOutputOpen.clear(i);
    }
  }

  /** Whether the receiver below still has a logical entry to close. */
  private boolean shouldSendClose(int stackIndex) {
    return sentToUnderlying.get(stackIndex)
        && (!pushedOut.get(stackIndex)
            || isRetiredInputTable(stackIndex)
            || pushedMappedTemplateOutputOpen.get(stackIndex));
  }

  /** A pushed table retained as an outputless policy-stack entry. */
  private boolean isRetiredInputTable(int stackIndex) {
    return pushedOut.get(stackIndex)
        && outputTableUnavailable.get(stackIndex)
        && openElements.get(stackIndex) == TABLE_TAG;
  }

  /** A synthetic scope boundary that established no boundary in the output. */
  private boolean isOutputlessSyntheticScopeBoundary(int stackIndex) {
    if (outputElements.get(stackIndex) != NO_OUTPUT_ELEMENT) { return false; }
    return (impliedInputTables.get(stackIndex)
            && !(pushedOut.get(stackIndex)
                 && foreignRootPendingTableReturn != null))
        || (openElements.get(stackIndex) == LI_TAG
            && stackIndex > 0
            && openElements.get(stackIndex - 1) == SELECT_TAG);
  }

  /**
   * Closes a policy-produced table whose logical input element must remain
   * open.  Content after an in-table form is foster-parented out of that table
   * when the output is parsed, so it must be serialized after the table on
   * the first pass too.
   */
  private void retireMappedOutputTable(int tableContext) {
    if (tableContext < 0
        || tableContext >= openElements.size()
        || openElements.get(tableContext) == TABLE_TAG
        || outputElements.get(tableContext) != TABLE_TAG
        || !sentToUnderlying.get(tableContext)
        || pushedOut.get(tableContext)
        || outputElementsInForeignContent.get(tableContext)) {
      return;
    }
    if (tableContext + 1 == openElements.size()) {
      // The mapped table that triggers this rule is outside any row, cell or
      // caption context.  Closing by the input name keeps the policy's own
      // input/output stack synchronized.
      underlying.closeTag(
          METADATA.canonNameForIndex(openElements.get(tableContext)));
    } else {
      if (!(underlying instanceof FormPointerPolicy)
          || !((FormPointerPolicy) underlying)
              .retireOutputTableForForm(false)) {
        return;
      }
      // The policy closed the mapped table and its output descendants, then
      // retained the descendants as dropped logical input entries.  Mirror
      // that state here so later context checks and end tags see the same
      // stack in both layers.
      markRetiredTableDescendants(tableContext);
    }
    sentToUnderlying.clear(tableContext);
    outputElementsInForeignContent.clear(tableContext);
    outputElementsStartForeignContent.clear(tableContext);
    clearedFormPointerTargets.clear(tableContext);
    staleOutputFormPointerTargets.clear(tableContext);
    outputTableUnavailable.set(tableContext);
  }

  /** Whether the parser is currently processing template contents. */
  private boolean hasOpenTemplateElement() {
    for (int i = openElements.size(); --i >= 0;) {
      if (openElements.get(i) == TEMPLATE_TAG) { return true; }
    }
    return false;
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

  /** Whether the most recently emitted element is in SVG or MathML. */
  private boolean lastOutputElementUsedForeignContentRules() {
    return underlying instanceof OpenTagOutputPolicy
        && ((OpenTagOutputPolicy) underlying)
            .outputElementForLastOpenTagUsedForeignContentRules();
  }

  /** Whether policy renamed the most recent output to an SVG or MathML root. */
  private boolean lastOutputElementStartsForeignContent(
      String inputElementName) {
    if (!(underlying instanceof OpenTagOutputPolicy)) { return false; }
    @Nullable String outputName = ((OpenTagOutputPolicy) underlying)
        .outputElementNameForLastOpenTag();
    if (outputName == null) { return false; }
    String canonOutputName = HtmlLexer.canonicalElementName(outputName);
    return !inputElementName.equals(canonOutputName)
        && isForeignContentRoot(canonOutputName);
  }

  /**
   * Whether a foreign table-part token will actually be written in foreign
   * content.  A receiver without policy feedback keeps the legacy balancing
   * behavior, including its nesting-limit accounting.
   */
  private boolean isOutputInForeignContent() {
    PushedOutTablePolicy policy = pushedOutTablePolicy();
    return policy != null && policy.isOutputInForeignContent();
  }

  /**
   * Whether the insertion point is under SVG or MathML rules: the current
   * node below is foreign and not an integration point.  Asked as a start
   * tag for {@code a}, a name that does not break out of foreign content, so
   * the answer describes the insertion point rather than any particular tag.
   */
  private boolean textIsInForeignContent() {
    List<String> noAttrs = new ArrayList<>();
    PushedOutTablePolicy policy = pushedOutTablePolicy();
    return policy != null
        ? policy.outputStartTagUsesForeignContentRules("a", noAttrs)
        : foreignContent.startTagUsesForeignContentRules("a", noAttrs);
  }

  /** The outermost foreign root the policy has actually emitted, if known. */
  private @Nullable String outputForeignContentRootName() {
    PushedOutTablePolicy policy = pushedOutTablePolicy();
    return policy != null ? policy.outputForeignContentRootName() : null;
  }

  /** Whether the current output context applies foreign rules to this tag. */
  private boolean outputStartTagUsesForeignContentRules(
      String elementName, List<String> attrs) {
    PushedOutTablePolicy policy = pushedOutTablePolicy();
    return policy != null
        && policy.outputStartTagUsesForeignContentRules(elementName, attrs);
  }

  /** Whether retained template contents apply foreign rules to this start. */
  private boolean outputTemplateStartTagUsesForeignContentRules(
      String elementName, List<String> attrs) {
    PushedOutTablePolicy policy = pushedOutTablePolicy();
    return policy != null
        && policy.outputTemplateStartTagUsesForeignContentRules(
            elementName, attrs);
  }

  /** Whether output handles this HTML start at a foreign integration point. */
  private boolean outputStartTagUsesHtmlIntegrationPointRules(
      String elementName, List<String> attrs) {
    PushedOutTablePolicy policy = pushedOutTablePolicy();
    return policy != null
        && policy.outputStartTagUsesHtmlIntegrationPointRules(
            elementName, attrs);
  }

  /** Whether an HTML form start must close a policy-produced paragraph. */
  private boolean outputContainerIsParagraph() {
    if (!(underlying instanceof OpenTagOutputPolicy)) { return false; }
    @Nullable String parentName = ((OpenTagOutputPolicy) underlying)
        .outputContainerElementName();
    return "p".equals(parentName);
  }

  /** Whether an HTML start must close a policy-produced link. */
  private boolean outputContainerIsAnchor() {
    if (!(underlying instanceof OpenTagOutputPolicy)) { return false; }
    @Nullable String parentName = ((OpenTagOutputPolicy) underlying)
        .outputContainerElementName();
    return "a".equals(parentName);
  }

  /** The pushed-out-table operations supported by the current policy. */
  private @Nullable PushedOutTablePolicy pushedOutTablePolicy() {
    if (underlying instanceof PushedOutTablePolicy) {
      PushedOutTablePolicy policy = (PushedOutTablePolicy) underlying;
      if (policy.supportsPushedOutTableOperations()) { return policy; }
    }
    return null;
  }

  /**
   * Ends an HTML text element whose case-sensitive input name was not parsed
   * as one.  A browser treats the serialized name case-insensitively, so any
   * later tag would otherwise be swallowed as text on the next parse.
   */
  private void retirePendingUnrecognizedHtmlTextElement() {
    String pending = pendingUnrecognizedHtmlTextElement;
    if (pending == null) { return; }
    pendingUnrecognizedHtmlTextElement = null;
    int passthrough = indexOfPassthroughNamed(pending);
    if (passthrough >= 0) { closePassthrough(passthrough, true); }
  }

  /** Opens one logical element, suppressing unsafe table structure if needed. */
  private int openElement(int inputElementIndex, List<String> attrs) {
    return openElement(inputElementIndex, attrs, false);
  }

  /**
   * Opens one logical element, optionally treating an implied table as part
   * of the structure below a synthetic table that the policy did not emit.
   */
  private int openElement(
      int inputElementIndex, List<String> attrs, boolean implied) {
    String inputElementName = METADATA.canonNameForIndex(inputElementIndex);
    PushedOutTablePolicy policy = pushedOutTablePolicy();
    if (policy != null
        && shouldSuppressTablePart(inputElementIndex, implied)) {
      policy.openTagWithoutOutput(inputElementName, attrs);
      return NO_OUTPUT_ELEMENT;
    }
    underlying.openTag(inputElementName, attrs);
    return outputElementIndexForLastOpenTag(inputElementIndex);
  }

  /**
   * Whether the nearest logical table was not re-opened in the output, making
   * an emitted row, cell, section or column invalid there.
   */
  private boolean shouldSuppressTablePart(int elIndex) {
    return shouldSuppressTablePart(elIndex, false);
  }

  private boolean shouldSuppressTablePart(int elIndex, boolean includeTable) {
    if ((elIndex == TABLE_TAG && !includeTable) || !TABLE_PARTS.get(elIndex)) {
      return false;
    }
    for (int i = openElements.size(); --i >= 0;) {
      if (includeTable && openElements.get(i) == TEMPLATE_TAG) {
        return false;
      }
      if (outputTableUnavailable.get(i)) { return true; }
      if (openElements.get(i) == TABLE_TAG) {
        int outputElement = outputElements.get(i);
        return sentToUnderlying.get(i)
            && outputElement != NO_OUTPUT_ELEMENT
            && outputElement != TABLE_TAG
            && outputElement != TEMPLATE_TAG
            && !outputElementsInForeignContent.get(i)
            && !(outputElementsStartForeignContent.get(i)
                && isOutputInForeignContent());
      }
      if (sentToUnderlying.get(i)
              && !pushedOut.get(i)
              && outputElements.get(i) == TABLE_TAG
              && !outputElementsInForeignContent.get(i)) {
        return false;
      }
    }
    return false;
  }

  /** Whether an unavailable logical table also emitted no element. */
  private boolean hasUnavailableOutputlessTable() {
    for (int i = outputTableUnavailable.nextSetBit(0); i >= 0;
         i = outputTableUnavailable.nextSetBit(i + 1)) {
      if (outputElements.get(i) == NO_OUTPUT_ELEMENT) { return true; }
    }
    return false;
  }

  /** Whether a dropped or renamed template separates an output table. */
  private boolean hasOutputlessTemplateAbove(int tableContext) {
    for (int i = openElements.size(); --i > tableContext;) {
      if (openElements.get(i) == TEMPLATE_TAG
          && outputElements.get(i) != TEMPLATE_TAG) {
        return true;
      }
    }
    return false;
  }

  /** Whether policy suppressed a template that still affects input parsing. */
  private boolean hasDroppedTemplateAbove(int stackIndex) {
    for (int i = openElements.size(); --i > stackIndex;) {
      if (openElements.get(i) == TEMPLATE_TAG
          && outputElements.get(i) == NO_OUTPUT_ELEMENT) {
        return true;
      }
    }
    return false;
  }

  private boolean prepareForContent(int elIndex) {
    return prepareForContent(elIndex, true);
  }

  private boolean prepareForContent(
      int elIndex, boolean resumeFormatting) {
    return prepareForContent(elIndex, resumeFormatting, false);
  }

  private boolean prepareForContent(
      int elIndex, boolean resumeFormatting,
      boolean impliedTableEscapesSyntheticSelect) {
    boolean mayOpenAtNestingLimit = true;
    boolean retiredFormattingForImplicitOutputTable = false;
    impliedTableEscapesSyntheticSelect |=
        elIndex == COL_TAG
        && isInSyntheticSelectListItemContext();
    // The flags and the marked-table checks are cheap and usually false; the
    // scan of the whole stack for an output scope boundary comes last.
    if (elIndex != HtmlElementTables.TEXT_NODE
        && TABLE_PARTS.get(elIndex)
        && ((outputlessTablePartsMayBeOpen
                && outputlessTablePartsOpenedAtEvent != openTagEvent)
            || hasPushedOutputlessTableWithEmittedParts()
            || hasNestedOutputlessTableInCaptionWithEmittedParts())
        && outputAllowsImplicitTableReturn()) {
      retiredFormattingForImplicitOutputTable =
          retireFormattingAboveImplicitOutputTable();
    }
    if (!pushedOut.isEmpty()
        && elIndex != HtmlElementTables.TEXT_NODE
        && TABLE_PARTS.get(elIndex)) {
      returnToPushedOutTable(elIndex);
    }
    if (elIndex != HtmlElementTables.TEXT_NODE
        && elIndex != TABLE_TAG && TABLE_PARTS.get(elIndex)) {
      boolean preserveOuterOutputlessTableParts =
          hasNestedUnavailableTableAboveEmittedOutputlessTable();
      returnToTableContext(elIndex);
      int container = containerIndex();
      if (container >= 0
          && TABLE_CONTEXT.get(openElements.get(container))
          && !hasUnavailableInputTableInScope()) {
        // A table part clears a browser's stack back to the table context,
        // which pops any element forwarded inside it that has no entry here.
        // A table the policy dropped or renamed establishes no such context
        // in the output, and its logical parts keep the older path.
        closePassthroughsInside(container, true);
      }
      int top = effectiveContainer(elIndex, container);
      int[] implied = METADATA.impliedElements(top, elIndex);
      if (!preserveOuterOutputlessTableParts
          && implied.length != 0 && implied[0] == TABLE_TAG
          && (container < 0 || !canHold(elIndex, top, container))) {
        // A dropped raw-text container cannot hide an emitted paragraph from
        // the implied table that the output parser will place beside it.
        if (container >= 0
            && outputElements.get(container) == NO_OUTPUT_ELEMENT
            && contentIsSkippable(
                METADATA.canonNameForIndex(openElements.get(container)))) {
          ++droppedSkippableDepth;
          closeStackFrom(container, openElements.get(container));
        }
        // An orphan table part still needs its table wrapper, but that table
        // must close containers such as p before any of its structure opens.
        mayOpenAtNestingLimit &= prepareForContent(
            TABLE_TAG, false, impliedTableEscapesSyntheticSelect);
      }
    }
    // Push an open table out of the way before anything below asks what
    // contains the content: a browser puts content a table cannot hold in
    // front of the table, so what contains the table contains the content,
    // and it is what decides which elements are implied and what must close.
    if (needsFosterParenting(elIndex)) {
      int tableIndex = containerIndex();
      pushOutTable(tableIndex);
    }

    int stackDepthBeforeImpliedElements = openElements.size();
    {
      int container = containerIndex();
      int top = effectiveContainer(elIndex, container);
      // Open implied elements, such as list-items and table cells & rows.
      int[] impliedElIndices = METADATA.impliedElements(top, elIndex);
      if (impliedElIndices.length != 0) {
        int startPos = 0;
        for (int i = 0, n = impliedElIndices.length; i < n; ++i) {
          int impliedElIndex = impliedElIndices[i];
          if (impliedElIndex == top) {
            startPos = i + 1;
            break;
          }
        }

        // An option can imply a select where the current table context cannot
        // contain one, for example after a colgroup.  Prepare that implied
        // select like an explicit start tag, then recompute the path after it
        // has closed or pushed out the table.
        if (startPos < impliedElIndices.length
            && impliedElIndices[startPos] == SELECT_TAG
            && top == COLGROUP_TAG
            && container >= 0
            && openElements.get(container) != COLGROUP_TAG
            && retireMappedOutputContainer(COLGROUP_TAG)) {
          container = containerIndex();
          top = effectiveContainer(elIndex, container);
          impliedElIndices = METADATA.impliedElements(top, elIndex);
          startPos = 0;
          for (int i = 0, n = impliedElIndices.length; i < n; ++i) {
            if (impliedElIndices[i] == top) {
              startPos = i + 1;
              break;
            }
          }
        }
        if (startPos < impliedElIndices.length
            && impliedElIndices[startPos] == SELECT_TAG
            && container >= 0
            && !canHold(SELECT_TAG, top, container)) {
          mayOpenAtNestingLimit &= prepareForContent(
              SELECT_TAG, false, impliedTableEscapesSyntheticSelect);
          container = containerIndex();
          top = effectiveContainer(elIndex, container);
          impliedElIndices = METADATA.impliedElements(top, elIndex);
          startPos = 0;
          for (int i = 0, n = impliedElIndices.length; i < n; ++i) {
            if (impliedElIndices[i] == top) {
              startPos = i + 1;
              break;
            }
          }
        }

        List<String> attrs = new ArrayList<>();

        for (int i = startPos, n = impliedElIndices.length; i < n; ++i) {
          if (effectiveNestingDepth() >= nestingLimit) {
            mayOpenAtNestingLimit = false;
            break;
          }
          int impliedElIndex = impliedElIndices[i];
          attrs.clear();
          boolean suppressMappedImpliedTemplate = false;
          if (impliedElIndex == TABLE_TAG) {
            int outputTableContext = outputTableContextForStart();
            if (outputTableContext >= 0
                && hasOutputlessTemplateAbove(outputTableContext)) {
              preparePolicyStartInOutputTable("table", attrs);
            } else if (!preparingPreparedPolicyStart
                && (hasOpenHtmlOutputTemplate()
                    || impliedTableEscapesSyntheticSelect)
                && underlying instanceof FormPointerPolicy
                && pushedOutTablePolicy() != null) {
              @Nullable String preparedOutputName =
                  ((FormPointerPolicy) underlying).prepareForStartTag(
                      "table", attrs);
              suppressMappedImpliedTemplate = preparedOutputName != null
                  && "template".equals(
                      HtmlLexer.canonicalElementName(preparedOutputName));
            }
            if (outputContainerIsParagraph()
                && underlying instanceof FormPointerPolicy) {
              ((FormPointerPolicy) underlying).prepareOutputForHtmlStart(
                  "table", attrs);
            }
          }
          boolean suppressedImpliedTable = impliedElIndex == TABLE_TAG
              && shouldSuppressTablePart(impliedElIndex, true);
          // The containment metadata answers most children of a select with
          // a list item, so that they nest inside the select the way a
          // browser nests their text instead of closing it.  No browser
          // creates that element.  A receiver with no policy to drop it
          // would serialize it, so it is skipped there.  Below a policy it
          // stays on this stack as the container but is never sent: a policy
          // that allowed li emitted <select><li>x</li></select>, the next
          // pass wrapped that li in a ul and the ul in a li without bound,
          // and the emitted li bounded the select end tag's scope search, so
          // text after </select> landed inside the select (#492).
          boolean syntheticSelectListItem =
              top == SELECT_TAG && impliedElIndex == LI_TAG;
          if (syntheticSelectListItem && pushedOutTablePolicy() == null) {
            continue;
          }
          if (syntheticSelectListItem
              && elIndex != HtmlElementTables.TEXT_NODE
              && pushedTableRequiresSelectEscape()) {
            // Beside a pushed-out table, retaining the synthetic item on the
            // logical stack can hide the select from its explicit end tag on
            // a second sanitization.
            continue;
          }
          if ((impliedElIndex == UL_TAG || impliedElIndex == OL_TAG)
              && outputContainerIsParagraph()
              && underlying instanceof FormPointerPolicy) {
            ((FormPointerPolicy) underlying).prepareOutputForHtmlStart(
                METADATA.canonNameForIndex(impliedElIndex), attrs);
          }
          int outputElementIndex;
          if (syntheticSelectListItem) {
            outputElementIndex = NO_OUTPUT_ELEMENT;
          } else if (suppressMappedImpliedTemplate) {
            if (impliedTableEscapesSyntheticSelect) {
              pushedOutTablePolicy().openTagWithoutOutputOrContent(
                  "table", attrs);
            } else {
              pushedOutTablePolicy().openTagWithoutOutput("table", attrs);
            }
            outputElementIndex = NO_OUTPUT_ELEMENT;
          } else {
            outputElementIndex = openElement(impliedElIndex, attrs, true);
          }
          boolean outputElementIsForeign =
              lastOutputElementUsedForeignContentRules();
          int stackIndex = openElements.size();
          openElements.add(impliedElIndex);
          inputElementSerials.add(0);
          outputElements.add(outputElementIndex);
          outputlessTablesWithEmittedParts.clear(stackIndex);
          pushedMappedTemplateOutputOpen.clear(stackIndex);
          suppressedMappedForeignSubtrees.clear(stackIndex);
          sentToUnderlying.set(stackIndex, !syntheticSelectListItem);
          inputElementsInForeignContent.clear(stackIndex);
          outputElementsInForeignContent.set(
              stackIndex, outputElementIsForeign);
          outputElementsStartForeignContent.set(
              stackIndex, outputElementIndex != NO_OUTPUT_ELEMENT
                  && lastOutputElementStartsForeignContent(
                      METADATA.canonNameForIndex(impliedElIndex)));
          formPointerTargets.clear(stackIndex);
          clearedFormPointerTargets.clear(stackIndex);
          staleOutputFormPointerTargets.clear(stackIndex);
          impliedInputTables.set(stackIndex, impliedElIndex == TABLE_TAG);
          if (impliedElIndex == TABLE_TAG
              && (suppressedImpliedTable
                  || (outputElementIndex != NO_OUTPUT_ELEMENT
                      && outputElementIndex != TABLE_TAG
                      && outputElementIndex != TEMPLATE_TAG))) {
            outputTableUnavailable.set(stackIndex);
          }
          recordEmittedPartForOutputlessTable(
              stackIndex + 1, outputElementIndex, outputElementIsForeign);
        }
      }
    }
    // Close all the elements that cannot contain the content to open.
    boolean closedPreexistingContainer = false;
    while (true) {
      int container = containerIndex();
      if (container < 0) { break; }
      int top = openElements.get(container);
      // A link ends the link open before it, wherever that is: nested links
      // do not survive a browser's parse, so a table between them cannot
      // stay open either.
      boolean endsLink = endsAnOpenLink(elIndex);
      if (!endsLink && canContain(elIndex, top, container)) {
        break;
      }
      if (!endsLink
          && TABLE_CONTEXT.get(top) && isFosterParented(elIndex)) {
        // As above, for a table uncovered by closing what held it.
        pushOutTable(container);
        continue;
      }
      // Close the container, and with it anything put in front of a table
      // it holds, from the top down.
      closedPreexistingContainer |=
          container < stackDepthBeforeImpliedElements;
      for (int i = openElements.size(); --i >= container;) {
        int unclosed = openElements.get(i);
        closePassthroughsInside(i, true);
        if (shouldSendClose(i)) {
          underlying.closeTag(METADATA.canonNameForIndex(unclosed));
        }
        detachOutputlessTableWithEmittedParts(i);
        openElements.remove(i);
        inputElementSerials.remove(i);
        outputElements.remove(i);
        sentToUnderlying.clear(i);
        inputElementsInForeignContent.clear(i);
        outputElementsInForeignContent.clear(i);
        outputElementsStartForeignContent.clear(i);
        formPointerTargets.clear(i);
        clearedFormPointerTargets.clear(i);
        staleOutputFormPointerTargets.clear(i);
        pushedOut.clear(i);
        impliedInputTables.clear(i);
        outputTableUnavailable.clear(i);
        outputlessTablesWithEmittedParts.clear(i);
        pushedMappedTemplateOutputOpen.clear(i);
        suppressedMappedForeignSubtrees.clear(i);
        if (METADATA.resumable(unclosed) && unclosed != elIndex) {
          toResumeInReverse.add(unclosed);
        }
      }
    }

    // Closing a container can uncover a context that needs a different
    // implied path.  For example, after a thead closes for a col, the table
    // below it needs to imply a colgroup.  Re-run preparation from that new
    // top before resuming formatting elements.
    if (closedPreexistingContainer) {
      mayOpenAtNestingLimit &= prepareForContent(
          elIndex, false, impliedTableEscapesSyntheticSelect);
    }

    if (retiredFormattingForImplicitOutputTable) {
      resumeFormatting = false;
    }
    boolean resumed = false;
    while (resumeFormatting
        && !insertionPointIsInForeignContent
        && !toResumeInReverse.isEmpty()) {
      int toResume = toResumeInReverse.getLast();
      int nOpen;
      // If toResume can contain elInfo AND the top of the stack can contain
      // toResume, then we push toResume.  A link is not resumed around
      // another link, or where one is open: a browser ends a link when the
      // next begins, and nested links do not survive a browser's parse, so
      // the output would not read back as written.
      nOpen = openElements.size();
      // The resumed element has to hold the content directly.  One that
      // would need a wrapper implied inside it, such as the list around a
      // list item, stays queued for the content inside the tag, where a
      // browser reconstructs it.  Resuming it here put it inside the wrapper
      // already implied for the tag and then implied that wrapper again.
      if ((nOpen == 0
          || canContain(toResume, openElements.get(nOpen - 1), nOpen))
          && canContain(elIndex, toResume, nOpen)
          && canHold(elIndex, toResume, nOpen)
          && !(toResume == A_TAG
               && (elIndex == A_TAG || hasOpenLinkInFormattingScope()))) {
        toResumeInReverse.removeLast();
        int outputElementIndex = NO_OUTPUT_ELEMENT;
        boolean sent = effectiveNestingDepth() < nestingLimit;
        if (sent) {
          List<String> attrs = new ArrayList<>();
          String inputName = METADATA.canonNameForIndex(toResume);
          if (preparePolicyStartInOutputTable(inputName, attrs)) {
            pushedOutTablePolicy().openTagWithoutOutput(inputName, attrs);
          } else {
            outputElementIndex = openElement(toResume, attrs);
          }
        }
        boolean outputElementIsForeign = sent
            && lastOutputElementUsedForeignContentRules();
        int stackIndex = openElements.size();
        openElements.add(toResume);
        inputElementSerials.add(0);
        outputElements.add(outputElementIndex);
        outputlessTablesWithEmittedParts.clear(stackIndex);
        pushedMappedTemplateOutputOpen.clear(stackIndex);
        suppressedMappedForeignSubtrees.clear(stackIndex);
        sentToUnderlying.set(stackIndex, sent);
        inputElementsInForeignContent.clear(stackIndex);
        outputElementsInForeignContent.set(
            stackIndex, outputElementIsForeign);
        outputElementsStartForeignContent.set(
            stackIndex, sent && outputElementIndex != NO_OUTPUT_ELEMENT
                && lastOutputElementStartsForeignContent(
                    METADATA.canonNameForIndex(toResume)));
        formPointerTargets.clear(stackIndex);
        clearedFormPointerTargets.clear(stackIndex);
        staleOutputFormPointerTargets.clear(stackIndex);
        impliedInputTables.clear(stackIndex);
        resumed = true;
      } else {
        break;
      }
    }
    if (resumed) {
      mayOpenAtNestingLimit &= prepareForContent(
          elIndex, false, impliedTableEscapesSyntheticSelect);
    }
    return mayOpenAtNestingLimit;
  }

  /** Drops the innermost queued formatting element with this index, if any. */
  private void forgetQueuedFormatting(int elIndex) {
    for (int i = toResumeInReverse.size(); --i >= 0;) {
      if (toResumeInReverse.get(i) == elIndex) {
        toResumeInReverse.remove(i);
        return;
      }
    }
  }

  /** Closes an output wrapper whose required child did not fit the limit. */
  private void retireContainerForUnemittedListChild(int child) {
    if (child != LI_TAG && child != OPTION_TAG) { return; }
    int container = containerIndex();
    if (container < 0) { return; }
    int element = openElements.get(container);
    if ((child == OPTION_TAG && element == SELECT_TAG)
        || (child == LI_TAG && (element == UL_TAG || element == OL_TAG))) {
      closeStackFrom(container, element);
    }
  }

  /** Whether an outputless table is nested under the select's synthetic li. */
  private boolean hasDroppedTableInSyntheticSelectListItemContext() {
    int n = openElements.size();
    return n >= 3
        && openElements.get(n - 1) == TABLE_TAG
        && outputElements.get(n - 1) == NO_OUTPUT_ELEMENT
        && openElements.get(n - 2) == LI_TAG
        && outputElements.get(n - 2) == NO_OUTPUT_ELEMENT
        && openElements.get(n - 3) == SELECT_TAG
        && outputElements.get(n - 3) == SELECT_TAG
        && sentToUnderlying.get(n - 3)
        && !pushedOut.get(n - 3);
  }

  /** Whether the canned implied list item is still below an HTML select. */
  private boolean isInSyntheticSelectListItemContext() {
    for (int i = openElements.size(); --i > 0;) {
      int element = openElements.get(i);
      if (element == TABLE_TAG || element == TEMPLATE_TAG
          || element == TD_TAG || element == TH_TAG) {
        return false;
      }
      if (element == LI_TAG
          && outputElements.get(i) == NO_OUTPUT_ELEMENT
          && openElements.get(i - 1) == SELECT_TAG
          && outputElements.get(i - 1) == SELECT_TAG
          && sentToUnderlying.get(i - 1)
          && !pushedOut.get(i - 1)) {
        return true;
      }
    }
    return false;
  }

  /** Whether the serialized output still has an HTML table open. */
  private boolean hasOpenHtmlOutputTable() {
    if (policyOnlyFormTableContext() != -1) { return true; }
    for (int i = openElements.size(); --i >= 0;) {
      if (sentToUnderlying.get(i)
          && !pushedOut.get(i)
          && outputElements.get(i) == TABLE_TAG
          && !outputElementsInForeignContent.get(i)) {
        return true;
      }
    }
    return false;
  }

  /** Whether the serialized output still has an HTML select open. */
  private boolean hasOpenHtmlOutputSelect() {
    for (int i = openElements.size(); --i >= 0;) {
      if (sentToUnderlying.get(i)
          && !pushedOut.get(i)
          && outputElements.get(i) == SELECT_TAG
          && !outputElementsInForeignContent.get(i)) {
        return true;
      }
    }
    return false;
  }

  /** Closes a mapped HTML output container and its logical descendants. */
  private boolean retireMappedOutputContainer(int outputElement) {
    for (int i = openElements.size(); --i >= 0;) {
      if (!sentToUnderlying.get(i)
          || pushedOut.get(i)
          || outputElements.get(i) == NO_OUTPUT_ELEMENT) {
        continue;
      }
      if (outputElementsInForeignContent.get(i)
          || outputElements.get(i) != outputElement
          || openElements.get(i) == outputElement) {
        return false;
      }
      closeStackFrom(i, openElements.get(i));
      return true;
    }
    return false;
  }

  /** Whether an implied logical table owns the kept literal output. */
  private boolean hasOpenLiteralOutputFromImpliedTable() {
    for (int i = openElements.size(); --i >= 0;) {
      int outputElement = outputElements.get(i);
      if (impliedInputTables.get(i)
          && sentToUnderlying.get(i)
          && !pushedOut.get(i)
          && outputElement != NO_OUTPUT_ELEMENT
          && !outputElementsInForeignContent.get(i)
          && hasSpecialTextMode(outputElement)) {
        return true;
      }
    }
    return false;
  }

  /** Whether the nearest input table in scope has no usable output table. */
  private boolean hasUnavailableInputTableInScope() {
    int tableScope = SCOPE_FOR_END_TAG[TABLE_TAG];
    for (int i = openElements.size(); --i >= 0;) {
      int openElement = openElements.get(i);
      if (openElement == TABLE_TAG) {
        return outputTableUnavailable.get(i)
            || outputElements.get(i) != TABLE_TAG;
      }
      if ((SCOPES_BY_ELEMENT[openElement] & tableScope) != 0) {
        return false;
      }
    }
    return false;
  }

  /** Whether the nearest input table became a foreign {@code select}. */
  private boolean hasInputTableMappedToForeignSelectInScope() {
    int tableScope = SCOPE_FOR_END_TAG[TABLE_TAG];
    for (int i = openElements.size(); --i >= 0;) {
      int openElement = openElements.get(i);
      if (openElement == TABLE_TAG) {
        return sentToUnderlying.get(i)
            && !pushedOut.get(i)
            && outputElements.get(i) == SELECT_TAG
            && outputElementsInForeignContent.get(i);
      }
      if ((SCOPES_BY_ELEMENT[openElement] & tableScope) != 0) {
        return false;
      }
    }
    return false;
  }

  /** Whether the logical top is a table the policy did not emit. */
  private boolean topIsOutputlessInputTable() {
    int top = openElements.size() - 1;
    return top >= 0
        && !pushedOut.get(top)
        && openElements.get(top) == TABLE_TAG
        && outputElements.get(top) == NO_OUTPUT_ELEMENT;
  }

  /** Whether an output template exposes a missing table below it. */
  private boolean hasOutputTemplateAboveOutputlessTable() {
    boolean sawOutputTemplate = false;
    for (int i = openElements.size(); --i >= 0;) {
      if (openElements.get(i) == TEMPLATE_TAG
          && sentToUnderlying.get(i)
          && !pushedOut.get(i)
          && outputElements.get(i) == TEMPLATE_TAG
          && !outputElementsInForeignContent.get(i)) {
        sawOutputTemplate = true;
      }
      if (openElements.get(i) == TABLE_TAG) {
        return sawOutputTemplate && outputElements.get(i) != TABLE_TAG;
      }
    }
    return false;
  }

  /** Records a part emitted into an outputless logical table in scope. */
  private void recordEmittedPartForOutputlessTable(
      int stackIndex, int outputElementIndex, boolean outputIsForeign) {
    if (outputElementIndex == NO_OUTPUT_ELEMENT
        || outputIsForeign || !TABLE_PARTS.get(outputElementIndex)) {
      return;
    }
    int tableScope = SCOPE_FOR_END_TAG[TABLE_TAG];
    for (int i = stackIndex; --i >= 0;) {
      int openElement = openElements.get(i);
      if (openElement == TABLE_TAG) {
        if (outputElements.get(i) != TABLE_TAG
            || outputTableUnavailable.get(i)) {
          outputlessTablesWithEmittedParts.set(i);
        }
        return;
      }
      if ((SCOPES_BY_ELEMENT[openElement] & tableScope) != 0) { return; }
    }
  }

  /**
   * Whether a nested outputless implied table inside a caption emitted parts.
   * A later table part exits the caption in the output parser, so formatting
   * opened after the nested table cannot remain around that part.
   */
  private boolean hasNestedOutputlessTableInCaptionWithEmittedParts() {
    if (outputlessTablesWithEmittedParts.isEmpty()) { return false; }
    int innerTable = -1;
    for (int i = openElements.size(); --i >= 0;) {
      int openElement = openElements.get(i);
      if (openElement == TABLE_TAG) {
        if (!outputlessTablesWithEmittedParts.get(i)) { return false; }
        innerTable = i;
        break;
      }
      if (openElement == TEMPLATE_TAG
          || openElement == TD_TAG || openElement == TH_TAG) {
        return false;
      }
    }
    if (innerTable < 0) { return false; }
    boolean sawOutputCaption = false;
    for (int i = innerTable; --i >= 0;) {
      int openElement = openElements.get(i);
      if (openElement == CAPTION_TAG
          && sentToUnderlying.get(i)
          && !pushedOut.get(i)
          && outputElements.get(i) == CAPTION_TAG
          && !outputElementsInForeignContent.get(i)) {
        sawOutputCaption = true;
      }
      if (openElement == TABLE_TAG) {
        return sawOutputCaption && outputlessTablesWithEmittedParts.get(i);
      }
      if (openElement == TEMPLATE_TAG) { return false; }
    }
    return false;
  }

  /** Whether a marked outputless table is pushed out in table scope. */
  private boolean hasPushedOutputlessTableWithEmittedParts() {
    if (outputlessTablesWithEmittedParts.isEmpty()) { return false; }
    int tableScope = SCOPE_FOR_END_TAG[TABLE_TAG];
    for (int i = openElements.size(); --i >= 0;) {
      int openElement = openElements.get(i);
      if (openElement == TABLE_TAG) {
        return pushedOut.get(i) && outputlessTablesWithEmittedParts.get(i);
      }
      if ((SCOPES_BY_ELEMENT[openElement] & tableScope) != 0) { return false; }
    }
    return false;
  }

  /** Whether a nested missing table hides parts emitted for an outer one. */
  private boolean hasNestedUnavailableTableAboveEmittedOutputlessTable() {
    if (outputlessTablesWithEmittedParts.isEmpty()) { return false; }
    boolean sawUnavailableTable = false;
    for (int i = openElements.size(); --i >= 0;) {
      if (openElements.get(i) != TABLE_TAG) { continue; }
      if (sawUnavailableTable
          && impliedInputTables.get(i)
          && outputElements.get(i) == NO_OUTPUT_ELEMENT
          && outputlessTablesWithEmittedParts.get(i)) {
        return true;
      }
      if (outputTableUnavailable.get(i)
          && !impliedInputTables.get(i)
          && outputElements.get(i) == NO_OUTPUT_ELEMENT) {
        sawUnavailableTable = true;
      }
    }
    return false;
  }

  /** Whether no output scope boundary separates a detached implied table. */
  private boolean outputAllowsImplicitTableReturn() {
    if (isOutputInForeignContent()) { return false; }
    for (int i = openElements.size(); --i >= 0;) {
      if (!sentToUnderlying.get(i) || pushedOut.get(i)) { continue; }
      int outputElement = outputElements.get(i);
      if (outputElementsInForeignContent.get(i)
          || outputElement == TEMPLATE_TAG
          || (outputElement != NO_OUTPUT_ELEMENT
              && (hasSpecialTextMode(outputElement)
                  || "noscript".equals(
                      METADATA.canonNameForIndex(outputElement))))) {
        return false;
      }
    }
    return true;
  }

  /** Starts persistent state without making it visible recursively. */
  private void markOutputlessTablePartsMayBeOpen() {
    if (!outputlessTablePartsMayBeOpen) {
      outputlessTablePartsMayBeOpen = true;
      outputlessTablePartsOpenedAtEvent = openTagEvent;
    }
  }

  /** Carries an unclosed browser-implied table beyond its logical table. */
  private void detachOutputlessTableWithEmittedParts(int stackIndex) {
    if (openElements.get(stackIndex) == TABLE_TAG
        && outputlessTablesWithEmittedParts.get(stackIndex)) {
      markOutputlessTablePartsMayBeOpen();
    }
    outputlessTablesWithEmittedParts.clear(stackIndex);
  }

  /** Retires formatting fostered beside an output-only implied table. */
  private boolean retireFormattingAboveImplicitOutputTable() {
    int formatting = -1;
    for (int i = openElements.size(); --i >= 0;) {
      if (openElements.get(i) == TABLE_TAG) { return false; }
      if (METADATA.resumable(openElements.get(i))) {
        formatting = i;
        break;
      }
    }
    if (formatting < 0) { return false; }
    int formattingElement = openElements.get(formatting);
    closeStackFrom(formatting, formattingElement);
    toResumeInReverse.add(formattingElement);
    return true;
  }

  /** Whether a hidden select wrapper must not block return to a real table. */
  private boolean pushedTableRequiresSelectEscape() {
    for (int i = pushedOut.nextSetBit(0); i >= 0;
         i = pushedOut.nextSetBit(i + 1)) {
      if (openElements.get(i) == TABLE_TAG
          && (!impliedInputTables.get(i)
              || outputElements.get(i) != NO_OUTPUT_ELEMENT)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Returns a table part to the nearest table in table scope before implying
   * wrappers.  A row inside a cell's div ends the cell and row; it does not
   * start a second table in the div.  A template starts a separate context.
   *
   * @return false if the nearest logical table was not emitted as a table,
   *     in which case the caller preserves the older implied-element path
   */
  private boolean returnToTableContext(int elIndex) {
    int table = -1;
    int tableScope = SCOPE_FOR_END_TAG[TABLE_TAG];
    for (int i = openElements.size(); --i >= 0;) {
      int openElementIndex = openElements.get(i);
      if (openElementIndex == TABLE_TAG) {
        // A table that policy dropped or renamed does not establish table
        // context in the output.  Keep the older implied-table path for its
        // parts so the output does not acquire bare adjacent row groups.
        if (outputElements.get(i) != TABLE_TAG
            && (outputElements.get(i) != COL_TAG
                || outputElementsInForeignContent.get(i))) {
          return false;
        }
        table = i;
        break;
      }
      if ((SCOPES_BY_ELEMENT[openElementIndex] & tableScope) != 0) {
        return true;
      }
    }
    if (table < 0) { return true; }
    for (int i = openElements.size(); --i > table;) {
      if (canHold(elIndex, openElements.get(i), i)) { break; }
      int unclosed = openElements.get(i);
      boolean sendClose = shouldSendClose(i);
      closePassthroughsInside(i, true);
      openElements.remove(i);
      inputElementSerials.remove(i);
      outputElements.remove(i);
      if (sendClose) {
        underlying.closeTag(METADATA.canonNameForIndex(unclosed));
      }
      sentToUnderlying.clear(i);
      inputElementsInForeignContent.clear(i);
      outputElementsInForeignContent.clear(i);
      outputElementsStartForeignContent.clear(i);
      formPointerTargets.clear(i);
      clearedFormPointerTargets.clear(i);
      staleOutputFormPointerTargets.clear(i);
      pushedOut.clear(i);
      impliedInputTables.clear(i);
      outputTableUnavailable.clear(i);
      outputlessTablesWithEmittedParts.clear(i);
      pushedMappedTemplateOutputOpen.clear(i);
      suppressedMappedForeignSubtrees.clear(i);
    }
    return true;
  }

  /** Whether a browser would foster-parent this token out of an open table. */
  private boolean needsFosterParenting(int elIndex) {
    if (!isFosterParented(elIndex) || endsAnOpenLink(elIndex)) { return false; }
    int tableIndex = containerIndex();
    return tableIndex >= 0
        && TABLE_CONTEXT.get(openElements.get(tableIndex))
        && !canHold(elIndex, openElements.get(tableIndex), tableIndex);
  }

  /**
   * Whether an SVG or MathML root arriving under HTML rules is in a table
   * insertion mode: directly in a table, row group, row or column group,
   * where a browser foster-parents it in front of the table.
   */
  private boolean foreignRootArrivesInTableMode() {
    int container = containerIndex();
    if (container < 0) { return false; }
    int top = openElements.get(container);
    return TABLE_CONTEXT.get(top) || top == COLGROUP_TAG;
  }

  /**
   * True if a browser puts content of this kind that arrives inside a table,
   * outside a cell or caption, in front of the table rather than in it: text,
   * and any element that is not one of a table's own parts.  What a table
   * may hold directly, such as a {@code script} or a {@code form}, never
   * reaches this: the containment tables say the table can contain it.
   */
  private static boolean isFosterParented(int elIndex) {
    return elIndex == HtmlElementTables.TEXT_NODE || !TABLE_PARTS.get(elIndex);
  }

  /** Whether this name establishes SVG or MathML foreign content. */
  private static boolean isForeignContentRoot(String canonElementName) {
    return "svg".equals(canonElementName) || "math".equals(canonElementName);
  }

  /** True if a link is open that a browser ends before opening this one. */
  private boolean endsAnOpenLink(int elIndex) {
    return elIndex == A_TAG && hasOpenLinkInFormattingScope();
  }

  /**
   * The stack index of the element that content arriving now goes into: the
   * top, unless a pushed-out table is at the top, in which case the content
   * goes beside the table, so the element that contains the table is the one
   * that contains the content.
   */
  private int containerIndex() {
    int i = openElements.size();
    boolean retiredOutputlessSuffix = hasRetiredOutputlessTableSuffix();
    while (--i >= 0
        && (pushedOut.get(i)
            || (retiredOutputlessSuffix
                && outputElements.get(i) == NO_OUTPUT_ELEMENT))) {
      // Skip a table closed in the output but still open here, and logical
      // descendants whose output was retired with such a table.
    }
    return i;
  }

  /** Whether the top suffix exists only logically above a retired table. */
  private boolean hasRetiredOutputlessTableSuffix() {
    for (int i = openElements.size(); --i >= 0;) {
      if (openElements.get(i) == TABLE_TAG
          && pushedOut.get(i)
          && outputTableUnavailable.get(i)) {
        return true;
      }
      if (pushedOut.get(i)) { continue; }
      if (outputElements.get(i) != NO_OUTPUT_ELEMENT) { return false; }
    }
    return false;
  }

  /**
   * True if {@code container} can hold {@code elIndex}, with elements
   * implied between them where it needs them.  The implied path has to run
   * through the container: one that does not is a fresh table, or list, to
   * open inside it rather than a way into the one that is already open.
   */
  private boolean canHold(
      int elIndex, int container, int containerIndexOnStack) {
    if (containerIndexOnStack >= 0
        && containerIndexOnStack < openElements.size()) {
      container = effectiveContainer(elIndex, containerIndexOnStack);
    }
    // A col goes directly in a table's implicit colgroup.  The canned implied
    // path omits the table itself, unlike the other paths handled below.
    if (container == TABLE_TAG && elIndex == COL_TAG) {
      return true;
    }
    int[] implied = METADATA.impliedElements(container, elIndex);
    for (int i = 0, n = implied.length; i < n; ++i) {
      if (implied[i] == container) {
        return i + 1 < n
            || canContain(elIndex, container, containerIndexOnStack);
      }
    }
    return implied.length == 0
        && canContain(elIndex, container, containerIndexOnStack);
  }

  /** Uses a physically open mapped table for its input table-part tokens. */
  private int effectiveContainer(int child, int containerIndexOnStack) {
    if (child >= 0
        && TABLE_PARTS.get(child)
        && containerIndexOnStack >= 0
        && containerIndexOnStack < openElements.size()
        && suppressedMappedForeignSubtrees.get(containerIndexOnStack)
        && !(policyOnlyTableMayBeOpen
            && underlying instanceof OpenTagOutputPolicy
            && policyOnlyFormTableContext() == POLICY_ONLY_TABLE_CONTEXT
            && "table".equals(((OpenTagOutputPolicy) underlying)
                .outputContainerElementName()))) {
      return BODY_TAG;
    }
    if (child == OPTION_TAG
        && underlying instanceof OpenTagOutputPolicy
        && "select".equals(((OpenTagOutputPolicy) underlying)
            .outputContainerElementName())) {
      return SELECT_TAG;
    }
    if (child == OPTION_TAG
        && underlying instanceof OpenTagOutputPolicy
        && ((OpenTagOutputPolicy) underlying).outputContainerElementName()
            == null) {
      if (containerIndexOnStack >= 0
          && containerIndexOnStack < openElements.size()
          && (openElements.get(containerIndexOnStack) == SELECT_TAG
              || openElements.get(containerIndexOnStack) == OPTGROUP_TAG)) {
        // The option's select is open in the input; the policy dropped it and
        // everything around it.  A browser reading the output finds an option
        // with no select, which the containment metadata answers with an
        // implied select that the same policy drops again.  Preparing that
        // select under the dropped one also implied a list item, which was
        // emitted and held everything up to the enclosing block.  Nothing
        // needs implying: the option goes where its select would have been.
        return openElements.get(containerIndexOnStack);
      }
      return BODY_TAG;
    }
    if (child == OPTION_TAG
        && underlying instanceof OpenTagOutputPolicy
        && "noscript".equals(((OpenTagOutputPolicy) underlying)
            .outputContainerElementName())) {
      return METADATA.indexForName("noscript");
    }
    if (child == OPTION_TAG
        && isOutputInForeignContent()
        && hasUnavailableInputTableInScope()) {
      return BODY_TAG;
    }
    if (child == OPTION_TAG
        && underlying instanceof OpenTagOutputPolicy
        && !isOutputInForeignContent()
        && hasDroppedTemplateAbove(-1)
        && hasUnavailableOutputlessTable()) {
      String outputContainerName = ((OpenTagOutputPolicy) underlying)
          .outputContainerElementName();
      int outputContainer = METADATA.indexForName(
          HtmlLexer.canonicalElementName(outputContainerName));
      if (outputContainer != UNRECOGNIZED_TAG) {
        return outputContainer;
      }
    }
    if (child == OPTION_TAG
        && underlying instanceof OpenTagOutputPolicy
        && !isOutputInForeignContent()
        && containerIndexOnStack >= 0
        && containerIndexOnStack < openElements.size()) {
      int inputContainer = openElements.get(containerIndexOnStack);
      if (inputContainer == TD_TAG || inputContainer == TH_TAG) {
        String outputContainerName = ((OpenTagOutputPolicy) underlying)
            .outputContainerElementName();
        int outputContainer = METADATA.indexForName(
            HtmlLexer.canonicalElementName(outputContainerName));
        if (outputContainer != UNRECOGNIZED_TAG) {
          return outputContainer;
        }
      }
    }
    if (child == OPTION_TAG
        && containerIndexOnStack >= 0
        && containerIndexOnStack < openElements.size()
        && outputElements.get(containerIndexOnStack) == NO_OUTPUT_ELEMENT
        && (!pushedOut.isEmpty()
            || TABLE_PARTS.get(openElements.get(containerIndexOnStack)))
        && hasUnavailableOutputlessTable()) {
      return BODY_TAG;
    }
    if (child == OPTION_TAG
        && !pushedOut.isEmpty()
        && containerIndexOnStack >= 0
        && containerIndexOnStack < openElements.size()
        && openElements.get(containerIndexOnStack) == TEMPLATE_TAG
        && outputElements.get(containerIndexOnStack) != TEMPLATE_TAG) {
      return BODY_TAG;
    }
    boolean wrapperSensitiveChild = child >= 0
        && (TABLE_PARTS.get(child) || child == OPTION_TAG);
    if (wrapperSensitiveChild
        && containerIndexOnStack >= 0
        && containerIndexOnStack < openElements.size()
        && !sentToUnderlying.get(containerIndexOnStack)
        && outputElements.get(containerIndexOnStack) != NO_OUTPUT_ELEMENT) {
      for (int i = containerIndexOnStack; --i >= 0;) {
        if (!sentToUnderlying.get(i)
            || pushedOut.get(i)
            || outputElements.get(i) == NO_OUTPUT_ELEMENT) {
          continue;
        }
        if (outputElementsInForeignContent.get(i)) {
          return openElements.get(containerIndexOnStack);
        }
        return outputElements.get(i);
      }
      return BODY_TAG;
    }
    if (child >= 0
        && TABLE_PARTS.get(child)
        && policyOnlyTableMayBeOpen
        && underlying instanceof OpenTagOutputPolicy
        && policyOnlyFormTableContext() == POLICY_ONLY_TABLE_CONTEXT
        && "table".equals(((OpenTagOutputPolicy) underlying)
            .outputContainerElementName())) {
      // An unrecognized input element can be kept as a table by policy.  It
      // has no balancer-stack entry, but its parts must use that physically
      // open table instead of implying a nested one beside the logical top.
      return TABLE_TAG;
    }
    if (child >= 0
        && TABLE_PARTS.get(child)
        && containerIndexOnStack >= 0
        && containerIndexOnStack < openElements.size()
        && sentToUnderlying.get(containerIndexOnStack)
        && !pushedOut.get(containerIndexOnStack)
        && !outputTableUnavailable.get(containerIndexOnStack)
        && !outputElementsInForeignContent.get(containerIndexOnStack)
        && outputElements.get(containerIndexOnStack) == TABLE_TAG) {
      return TABLE_TAG;
    }
    if (child >= 0
        && (TABLE_PARTS.get(child) || child == OPTION_TAG)
        && containerIndexOnStack >= 0
        && containerIndexOnStack < openElements.size()
        && sentToUnderlying.get(containerIndexOnStack)
        && !pushedOut.get(containerIndexOnStack)
        && !outputTableUnavailable.get(containerIndexOnStack)
        && !outputElementsInForeignContent.get(containerIndexOnStack)
        && !outputElementsStartForeignContent.get(containerIndexOnStack)
        && outputForeignContentRootName() == null) {
      int outputContainer = outputElements.get(containerIndexOnStack);
      if (TABLE_PARTS.get(child)
          && openElements.get(containerIndexOnStack) == TABLE_TAG
          && outputContainer != TABLE_TAG
          && outputContainer != TEMPLATE_TAG) {
        // A table renamed to an ordinary HTML element cannot contain its
        // structural parts.  Keep using the logical table so those parts are
        // suppressed there instead of implying a second renamed table.
        return TABLE_TAG;
      }
      if (outputContainer != NO_OUTPUT_ELEMENT
          && outputContainer != openElements.get(containerIndexOnStack)
          && !(outputContainer == SELECT_TAG && TABLE_PARTS.get(child))
          && !(outputContainer == TEMPLATE_TAG
              && openElements.get(containerIndexOnStack) == TABLE_TAG
              && (TABLE_PARTS.get(child)
                  || (child == OPTION_TAG
                      && !hasOutputlessTemplateBelow(
                          containerIndexOnStack))))
          && impliedPathEndsInContainer(outputContainer, child)) {
        return outputContainer;
      }
    }
    return containerIndexOnStack >= 0
        ? openElements.get(containerIndexOnStack) : BODY_TAG;
  }

  /** Whether a generated wrapper path can actually contain the child. */
  private boolean impliedPathEndsInContainer(int container, int child) {
    int[] implied = METADATA.impliedElements(container, child);
    int innermost = implied.length == 0
        ? container : implied[implied.length - 1];
    return METADATA.canContain(innermost, child);
  }

  /** Whether a dropped logical template contains the stack entry. */
  private boolean hasOutputlessTemplateBelow(int stackIndex) {
    for (int i = stackIndex; --i >= 0;) {
      if (openElements.get(i) == TEMPLATE_TAG) {
        return outputElements.get(i) == NO_OUTPUT_ELEMENT;
      }
    }
    return false;
  }

  /**
   * Closes in the output, innermost first, the row, row group and table that
   * the top of the stack is in, and marks them pushed out, keeping them here.
   * Entries already pushed out, by earlier content beside the same table, are
   * left as they are.
   */
  private void pushOutTable(int topIndex) {
    boolean reachesTable = false;
    for (int i = topIndex; i >= 0 && TABLE_CONTEXT.get(openElements.get(i));
         --i) {
      if (openElements.get(i) == TABLE_TAG) {
        reachesTable = true;
        break;
      }
    }
    if (!reachesTable) {
      closeStackFrom(topIndex, openElements.get(topIndex));
      return;
    }
    for (int i = topIndex; i >= 0; --i) {
      int elIndex = openElements.get(i);
      if (!TABLE_CONTEXT.get(elIndex)) { break; }
      if (!pushedOut.get(i)) {
        boolean leaveMappedTemplateOpen = elIndex == TABLE_TAG
            && sentToUnderlying.get(i)
            && outputElements.get(i) == TEMPLATE_TAG
            && !outputElementsInForeignContent.get(i)
            && hasOutputlessTemplateBelow(i);
        if (sentToUnderlying.get(i) && !leaveMappedTemplateOpen) {
          closePassthroughsInside(i, true);
          underlying.closeTag(METADATA.canonNameForIndex(elIndex));
        }
        pushedOut.set(i);
        pushedMappedTemplateOutputOpen.set(i, leaveMappedTemplateOpen);
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
    int pushedTable = top;
    while (pushedTable >= 0
        && pushedOut.get(pushedTable)
        && openElements.get(pushedTable) != TABLE_TAG) {
      --pushedTable;
    }
    boolean tableWasPushedWithContext =
        pushedTable >= 0 && pushedTable < top;
    byte tableScope = SCOPE_FOR_END_TAG[TABLE_TAG];
    for (int i = openElements.size(); --i > top;) {
      if ((SCOPES_BY_ELEMENT[openElements.get(i)] & tableScope) != 0) {
        return;
      }
    }
    for (int i = openElements.size(); --i > top;) {
      closePassthroughsInside(i, true);
      int unclosed = openElements.remove(i);
      inputElementSerials.remove(i);
      outputElements.remove(i);
      if (sentToUnderlying.get(i)) {
        underlying.closeTag(METADATA.canonNameForIndex(unclosed));
      }
      sentToUnderlying.clear(i);
      inputElementsInForeignContent.clear(i);
      outputElementsInForeignContent.clear(i);
      outputElementsStartForeignContent.clear(i);
      formPointerTargets.clear(i);
      clearedFormPointerTargets.clear(i);
      staleOutputFormPointerTargets.clear(i);
      impliedInputTables.clear(i);
      if (METADATA.resumable(unclosed)) {
        toResumeInReverse.add(unclosed);
      }
      outputTableUnavailable.clear(i);
      outputlessTablesWithEmittedParts.clear(i);
      pushedMappedTemplateOutputOpen.clear(i);
      suppressedMappedForeignSubtrees.clear(i);
    }
    while (top >= 0 && pushedOut.get(top)) {
      if (canHold(elIndex, openElements.get(top), top)) { break; }
      closePassthroughsInside(top, true);
      if (isRetiredInputTable(top)
          || pushedMappedTemplateOutputOpen.get(top)) {
        underlying.closeTag("table");
      }
      detachOutputlessTableWithEmittedParts(top);
      openElements.remove(top);
      inputElementSerials.remove(top);
      outputElements.remove(top);
      sentToUnderlying.clear(top);
      inputElementsInForeignContent.clear(top);
      outputElementsInForeignContent.clear(top);
      outputElementsStartForeignContent.clear(top);
      formPointerTargets.clear(top);
      clearedFormPointerTargets.clear(top);
      staleOutputFormPointerTargets.clear(top);
      pushedOut.clear(top);
      impliedInputTables.clear(top);
      outputTableUnavailable.clear(top);
      pushedMappedTemplateOutputOpen.clear(top);
      suppressedMappedForeignSubtrees.clear(top);
      --top;
    }
    if (top < 0 || !pushedOut.get(top)) { return; }
    int start = top;
    while (start > 0 && pushedOut.get(start - 1)) { --start; }
    if (pushedTable >= 0
        && outputElements.get(pushedTable) == TABLE_TAG
        && !outputTableUnavailable.get(pushedTable)
        && !outputElementsInForeignContent.get(pushedTable)) {
      // A browser clears its stack back to the table context before it
      // reprocesses the part, so elements forwarded in front of the table
      // are closed before the table reopens.
      closePassthroughsInside(start, true);
    } else {
      // No table reopens in the output, so the elements forwarded in front
      // of the logical table stay open below and now precede its reopened
      // entries.
      for (int i = passthroughDepths.size();
           --i >= 0 && passthroughDepths.get(i) > start;) {
        passthroughDepths.set(i, start);
      }
    }
    // Pop the run and push it back, outermost first, opening each again.
    int n = top - start + 1;
    int[] run = new int[n];
    int[] runSerials = new int[n];
    boolean[] runInputForeign = new boolean[n];
    boolean[] runFormPointerTarget = new boolean[n];
    boolean[] runClearedFormPointerTarget = new boolean[n];
    boolean[] runStaleOutputFormPointerTarget = new boolean[n];
    boolean[] runImpliedInputTable = new boolean[n];
    boolean[] runOutputlessTableWithEmittedParts = new boolean[n];
    boolean[] runMappedTemplateOutputOpen = new boolean[n];
    boolean[] runSuppressedMappedForeignTemplates = new boolean[n];
    int[] runOutputElements = new int[n];
    boolean[] runOutputForeign = new boolean[n];
    boolean[] runOutputStartsForeign = new boolean[n];
    for (int i = n; --i >= 0;) {
      runInputForeign[i] = inputElementsInForeignContent.get(start + i);
      runFormPointerTarget[i] = formPointerTargets.get(start + i);
      runClearedFormPointerTarget[i] =
          clearedFormPointerTargets.get(start + i);
      runStaleOutputFormPointerTarget[i] =
          staleOutputFormPointerTargets.get(start + i);
      runImpliedInputTable[i] = impliedInputTables.get(start + i);
      runOutputlessTableWithEmittedParts[i] =
          outputlessTablesWithEmittedParts.get(start + i);
      runMappedTemplateOutputOpen[i] =
          pushedMappedTemplateOutputOpen.get(start + i);
      runSuppressedMappedForeignTemplates[i] =
          suppressedMappedForeignSubtrees.get(start + i);
      runOutputElements[i] = outputElements.get(start + i);
      runOutputForeign[i] = outputElementsInForeignContent.get(start + i);
      runOutputStartsForeign[i] =
          outputElementsStartForeignContent.get(start + i);
      if (isRetiredInputTable(start + i)) {
        underlying.closeTag("table");
      }
      runSerials[i] = inputElementSerials.get(start + i);
      run[i] = openElements.remove(start + i);
      inputElementSerials.remove(start + i);
      outputElements.remove(start + i);
      sentToUnderlying.clear(start + i);
      inputElementsInForeignContent.clear(start + i);
      outputElementsInForeignContent.clear(start + i);
      outputElementsStartForeignContent.clear(start + i);
      formPointerTargets.clear(start + i);
      clearedFormPointerTargets.clear(start + i);
      staleOutputFormPointerTargets.clear(start + i);
      pushedOut.clear(start + i);
      impliedInputTables.clear(start + i);
      outputTableUnavailable.clear(start + i);
      outputlessTablesWithEmittedParts.clear(start + i);
      pushedMappedTemplateOutputOpen.clear(start + i);
      suppressedMappedForeignSubtrees.clear(start + i);
    }
    foreignRootPendingTableReturn = null;
    PushedOutTablePolicy policy = pushedOutTablePolicy();
    for (int i = 0; i < n; ++i) {
      boolean mappedTemplateStillOpen = runMappedTemplateOutputOpen[i];
      int outputElementIndex = mappedTemplateStillOpen
          ? runOutputElements[i] : NO_OUTPUT_ELEMENT;
      boolean sent = mappedTemplateStillOpen
          || effectiveNestingDepth() < nestingLimit;
      if (sent && !mappedTemplateStillOpen) {
        List<String> attrs = new ArrayList<>();
        if (run[i] == TABLE_TAG && policy != null) {
          policy.openReopenedTable(attrs);
          outputElementIndex = outputElementIndexForLastOpenTag(run[i]);
        } else {
          outputElementIndex = openElement(run[i], attrs);
        }
      }
      boolean outputElementIsForeign = mappedTemplateStillOpen
          ? runOutputForeign[i]
          : sent && lastOutputElementUsedForeignContentRules();
      int stackIndex = openElements.size();
      openElements.add(run[i]);
      inputElementSerials.add(runSerials[i]);
      outputElements.add(outputElementIndex);
      sentToUnderlying.set(stackIndex, sent);
      inputElementsInForeignContent.set(stackIndex, runInputForeign[i]);
      outputElementsInForeignContent.set(
          stackIndex, outputElementIsForeign);
      outputElementsStartForeignContent.set(
          stackIndex, mappedTemplateStillOpen
              ? runOutputStartsForeign[i]
              : sent && outputElementIndex != NO_OUTPUT_ELEMENT
                  && lastOutputElementStartsForeignContent(
                      METADATA.canonNameForIndex(run[i])));
      formPointerTargets.set(stackIndex, runFormPointerTarget[i]);
      clearedFormPointerTargets.set(
          stackIndex, runClearedFormPointerTarget[i]);
      staleOutputFormPointerTargets.set(
          stackIndex, runStaleOutputFormPointerTarget[i]);
      impliedInputTables.set(stackIndex, runImpliedInputTable[i]);
      pushedMappedTemplateOutputOpen.clear(stackIndex);
      suppressedMappedForeignSubtrees.set(
          stackIndex, runSuppressedMappedForeignTemplates[i]);
      if (!mappedTemplateStillOpen
          && policy != null
          && run[i] == TABLE_TAG
          && outputElementIndex != TABLE_TAG
          && (!runImpliedInputTable[i]
              || tableWasPushedWithContext
              || policy.reopenedTableWasRenamed())) {
        outputTableUnavailable.set(stackIndex);
      }
      outputlessTablesWithEmittedParts.set(
          stackIndex, runOutputlessTableWithEmittedParts[i]);
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
    if (child == FORM_TAG) {
      if (container == FORM_TAG
          && (hasOpenHtmlOutputTemplate()
              || (clearedFormPointerTargets.get(containerIndexOnStack)
                  && !staleOutputFormPointerTargets.get(
                      containerIndexOnStack)))) {
        // Template contents do not use the form pointer, and an out-of-scope
        // form end can clear the pointer without removing its old target.  In
        // either case a browser can insert this form inside the earlier one.
        return true;
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
    if (pendingUnrecognizedHtmlTextElement != null) {
      boolean closesPendingTextElement =
          Strings.toLowerCase(pendingUnrecognizedHtmlTextElement).equals(
              Strings.toLowerCase(elementName));
      retirePendingUnrecognizedHtmlTextElement();
      if (closesPendingTextElement) { return; }
    }
    resetMappedForeignTableSuppressionIfPolicyEnded();
    resetDroppedSuppressedTableIfPolicyEnded();
    if (DEBUG) {
      dumpState("close " + elementName);
    }
    String canonElementName = HtmlLexer.canonicalElementName(elementName);

    int elIndex = METADATA.indexForName(canonElementName);
    boolean parsingTemplateContents =
        elIndex == FORM_TAG && hasOpenTemplateElement();
    boolean formElementPointerWasSet =
        elIndex == FORM_TAG && foreignContent.formElementPointerIsSet();
    String foreignRootBefore = foreignContent.outermostForeignElementName();
    String outputForeignRootBefore = outputForeignContentRootName();
    if (!pushedOut.isEmpty()
        && foreignContent.isInForeignContent()
        && !foreignContent.hasForeignElementNamed(canonElementName)
        && !hasOpenElementInScope(elIndex)) {
      // The foreign end-tag algorithm reprocesses this under HTML rules, but
      // the pushed-out table bounds its scope and there is no target before
      // that boundary, so the end tag is ignored.  Keeping the known foreign
      // current node prevents later foreign names from being balanced as
      // HTML or spuriously returning to the table.
      foreignContent.ignoreEndTagUnderHtmlRules();
    } else {
      foreignContent.processEndTag(canonElementName);
    }
    boolean usesForeignContentRules =
        foreignContent.lastTagUsedForeignContentRules();
    // As for a start tag, judged by the output once the tracker is unknown,
    // unless the form that holds the pointer is still open: this end tag then
    // closes it under the HTML rules its start was judged by, whatever the
    // output namespace is now, and the pointer goes with it.  Judging the end
    // afresh left the pointer set when a form in an integration point closed
    // after the tracker gave up, and every later form was dropped for it.
    boolean formUsesHtmlPointerRules = elIndex == FORM_TAG
        && !usesForeignContentRules
        && !parsingTemplateContents
        && (!(foreignContent.isUnknown() && outputForeignRootBefore != null)
            || formPointerTargets.previousSetBit(openElements.size() - 1)
                >= 0);
    if (formUsesHtmlPointerRules) {
      foreignContent.clearFormElementPointer();
    }
    if (elIndex == TABLE_TAG
        && droppedSuppressedTableDepth != 0) {
      int suppressedTable = suppressedMappedForeignTableIndex();
      if (suppressedTable >= 0
          && !hasOpenTableAbove(suppressedTable)) {
        --droppedSuppressedTableDepth;
        return;
      }
    }
    if (!pushedOut.isEmpty()
        && foreignRootBefore != null
        && !usesForeignContentRules
        && foreignContent.outermostForeignElementName() == null) {
      foreignRootPendingTableReturn = outputForeignRootBefore != null
          ? foreignRootBefore : null;
    }
    if (droppedSuppressedOptionDepth != 0) {
      PushedOutTablePolicy tablePolicy = pushedOutTablePolicy();
      if (tablePolicy == null
          || !tablePolicy.isSuppressingOutputAndContent()) {
        resetDroppedSuppressedOption();
      } else if (elIndex == OPTION_TAG
          && !hasTrackedOptionAtOrAbove(
              droppedSuppressedOptionStackDepth)) {
        --droppedSuppressedOptionDepth;
        if (droppedSuppressedOptionDepth == 0) {
          if (droppedSuppressedOptionOwnsPolicyEntry) {
            discardStackSuffix(droppedSuppressedOptionStackDepth);
            popPassthroughsForwardedSince(
                droppedSuppressedOptionPassthroughDepth);
            underlying.closeTag(canonElementName);
          }
          resetDroppedSuppressedOption();
        }
        return;
      }
    }
    if (droppedSkippableDepth != 0 && contentIsSkippable(canonElementName)) {
      --droppedSkippableDepth;
    }

    if (usesForeignContentRules) {
      // The end tag matched a foreign node, and a browser pops that node and
      // every node above it.  Close the entries for the popped nodes by
      // identity, innermost first.  Local names are never searched: a node
      // dropped at the nesting limit, or already closed, matches nothing and
      // so cannot reach an older element with the same name.
      closeForeignElementsPoppedByLastEndTag();
      return;
    }
    if (elIndex == UNRECOGNIZED_TAG) {
      // Forwarded only for an element the receiver below still has open,
      // after everything opened inside it.  A stray end tag closes nothing.
      int passthrough = indexOfPassthroughNamed(canonElementName);
      if (passthrough >= 0) { closePassthroughByName(passthrough); }
      return;
    }

    // Ensure that index is in the scope of closeable elements.
    // This approximates the "has an element in *** scope" predicates defined at
    // http://www.whatwg.org/specs/web-apps/current-work/multipage/syntax.html
    // #has-an-element-in-the-specific-scope
    int blockingScopes = SCOPE_FOR_END_TAG[elIndex];

    int index = -1;
    int pointerTarget = -1;
    boolean formEndUsesPointer = formUsesHtmlPointerRules;
    {
      if (formEndUsesPointer) {
        if (!formElementPointerWasSet) {
          // A foreign form can have been popped from the browser's stack by
          // an HTML breakout while its lexical output still needs balancing.
          // With no HTML form pointer to act on, close that logical entry by
          // name as the foreign end-tag path would have done.
          for (int i = openElements.size(); --i >= 0;) {
            if (openElements.get(i) == FORM_TAG
                && inputElementsInForeignContent.get(i)) {
              index = i;
              break;
            }
          }
          if (index < 0) { return; }
        } else {
          pointerTarget = formPointerTargets.previousSetBit(
              openElements.size() - 1);
          if (pointerTarget >= 0) {
            int foreignForm = emittedForeignFormAbove(pointerTarget);
            if (foreignForm >= 0) {
              // A later HTML breakout can leave a foreign form lexically
              // open after the browser has popped it.  Its explicit end tag
              // closes that lexical form but, under HTML rules, clears the
              // older form pointer without popping the descendants of the
              // older form.  Mirror both effects.
              boolean outputFormOwnsPointer =
                  sentToUnderlying.get(pointerTarget)
                  && outputElements.get(pointerTarget) == FORM_TAG
                  && !outputElementsInForeignContent.get(pointerTarget);
              formPointerTargets.clear(pointerTarget);
              if (outputFormOwnsPointer) {
                clearedFormPointerTargets.set(pointerTarget);
                staleOutputFormPointerTargets.clear(pointerTarget);
              }
              closeStackFrom(foreignForm, FORM_TAG);
              return;
            }
            boolean inScope = true;
            for (int i = openElements.size(); --i > pointerTarget;) {
              int openElement = openElements.get(i);
              if (!inputElementsInForeignContent.get(i)
                  && !isOutputlessSyntheticScopeBoundary(i)
                  && (SCOPES_BY_ELEMENT[openElement]
                      & blockingScopes) != 0) {
                inScope = false;
                break;
              }
            }
            if (inScope) { index = pointerTarget; }
          }
        }
      } else if (isHeaderElementName(canonElementName)) {
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
          if (!isOutputlessSyntheticScopeBoundary(i)
              && (openElementScope & blockingScopes) != 0) {
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
          if (!isOutputlessSyntheticScopeBoundary(i)
              && (openElementScope & blockingScopes) != 0) {
            break;
          }
        }
      }
    }
    {
      // A table part forwarded directly into foreign output is closed by name
      // when the foreign tracker no longer knows it, as after an HTML
      // breakout.  It is the innermost element of this name if it was
      // forwarded after the entry found above.
      int passthrough = indexOfPassthroughNamed(canonElementName);
      if (passthrough >= 0
          && (index < 0 || passthroughDepths.get(passthrough) > index)) {
        closePassthroughByName(passthrough);
        return;
      }
    }
    if (index < 0) {
      if (formEndUsesPointer && pointerTarget >= 0) {
        formPointerTargets.clear(pointerTarget);
        boolean outputFormOwnsPointer = sentToUnderlying.get(pointerTarget)
            && outputElements.get(pointerTarget) == FORM_TAG
            && !outputElementsInForeignContent.get(pointerTarget);
        if (outputFormOwnsPointer) {
          clearedFormPointerTargets.set(pointerTarget);
          boolean paired = hasOpenHtmlOutputTableAbove(pointerTarget)
              && clearFormPointerWithBalancedPair();
          if (!paired) {
            // Keep the form's extent unchanged unless a later output form
            // actually needs the pointer.  At that point the stale form is
            // closed immediately before the new one is emitted.
            staleOutputFormPointerTargets.set(pointerTarget);
          }
        }
      }
      // A formatting element closed with an earlier container and queued to
      // resume is not open, but the end tag is its: a browser drops such an
      // element from its list of active formatting elements, so it is not
      // reconstructed around later content.  Forget it here too.
      if (METADATA.resumable(elIndex)) { forgetQueuedFormatting(elIndex); }
      return;  // Don't close unopened tags.
    }

    closeStackFrom(index, elIndex);
  }

  /**
   * Closes, innermost first, the entries for the foreign nodes that the last
   * end tag popped, found by the identity of each node.  A popped node
   * whose entry is gone, or was never made because the nesting limit dropped
   * it, matches nothing and is never mistaken for an older node of the same
   * local name.  A popped node listed in {@link #passthroughNames} has its
   * end tag forwarded after everything inside it is closed; the end tag of
   * a popped node with an entry in {@link #openElements} is sent for that
   * entry as usual.
   */
  private void closeForeignElementsPoppedByLastEndTag() {
    int n = foreignContent.foreignElementsPoppedByLastEndTag().size();
    for (int j = 0; j < n; ++j) {
      int serial = foreignContent.foreignElementSerialPoppedByLastEndTag(j);
      int index = indexOfInputElementSerial(serial);
      if (index >= 0) {
        closeStackFrom(index, openElements.get(index));
        continue;
      }
      int passthrough = indexOfPassthroughSerial(serial);
      if (passthrough >= 0) {
        closePassthrough(passthrough, true);
      }
    }
  }

  /** The entry whose start tag pushed the node with this identity, or -1. */
  private int indexOfInputElementSerial(int serial) {
    if (serial == 0) { return -1; }
    for (int i = openElements.size(); --i >= 0;) {
      if (inputElementSerials.get(i) == serial) { return i; }
    }
    return -1;
  }

  /** Records an element forwarded below with no entry in openElements. */
  private void pushPassthrough(String canonElementName, int serial) {
    IntVector indices = passthroughIndicesByName.get(canonElementName);
    if (indices == null) {
      indices = new IntVector();
      passthroughIndicesByName.put(canonElementName, indices);
    }
    int index = passthroughNames.size();
    indices.add(index);
    passthroughNames.add(canonElementName);
    passthroughDepths.add(openElements.size());
    passthroughSerials.add(serial);
    passthroughOutputForeign.set(
        index,
        lastOutputElementUsedForeignContentRules()
            || lastOutputElementIsForeignRoot());
    if (isForeignContentRoot(canonElementName)) {
      passthroughForeignRoots.add(index);
    }
  }

  /** Whether the most recently emitted element is an SVG or MathML root. */
  private boolean lastOutputElementIsForeignRoot() {
    if (!(underlying instanceof OpenTagOutputPolicy)) { return false; }
    @Nullable String outputName = ((OpenTagOutputPolicy) underlying)
        .outputElementNameForLastOpenTag();
    return outputName != null
        && isForeignContentRoot(HtmlLexer.canonicalElementName(outputName));
  }

  /**
   * Whether the output entered the input's current foreign region: the
   * innermost forwarded SVG or MathML root was emitted as a foreign element.
   */
  private boolean forwardedForeignRootEnteredOutput() {
    return !passthroughForeignRoots.isEmpty()
        && passthroughOutputForeign.get(passthroughForeignRoots.getLast());
  }

  /** The innermost forwarded element with this canonical name, or -1. */
  private int indexOfPassthroughNamed(String canonElementName) {
    IntVector indices = passthroughIndicesByName.get(canonElementName);
    return indices == null || indices.isEmpty() ? -1 : indices.getLast();
  }

  /** The forwarded element whose start pushed the node with this identity. */
  private int indexOfPassthroughSerial(int serial) {
    if (serial == 0) { return -1; }
    for (int i = passthroughSerials.size(); --i >= 0;) {
      if (passthroughSerials.get(i) == serial) { return i; }
    }
    return -1;
  }

  /**
   * Closes, innermost first, the forwarded elements opened inside the entry
   * at {@code stackIndex}: those forwarded after it was added.  Called
   * before that entry's own close is sent, or before it is removed because
   * the receiver below already closed it, in which case nothing is sent.
   */
  private void closePassthroughsInside(int stackIndex, boolean emitCloseTags) {
    while (!passthroughDepths.isEmpty()
        && passthroughDepths.getLast() > stackIndex) {
      popPassthrough(emitCloseTags);
    }
  }

  /** Closes the innermost forwarded element, sending its end tag if asked. */
  private void popPassthrough(boolean emitCloseTag) {
    int last = passthroughNames.size() - 1;
    String canonElementName = passthroughNames.remove(last);
    IntVector indices = passthroughIndicesByName.get(canonElementName);
    indices.removeLast();
    if (indices.isEmpty()) {
      passthroughIndicesByName.remove(canonElementName);
    }
    passthroughDepths.removeLast();
    passthroughSerials.removeLast();
    passthroughOutputForeign.clear(last);
    if (!passthroughForeignRoots.isEmpty()
        && passthroughForeignRoots.getLast() == last) {
      passthroughForeignRoots.removeLast();
    }
    if (emitCloseTag) {
      underlying.closeTag(canonElementName);
    }
    if (foreignRootPendingTableReturn != null
        && foreignRootPendingTableReturn.equals(canonElementName)) {
      foreignRootPendingTableReturn = null;
    }
  }

  /**
   * Forgets, without sending anything, the forwarded elements recorded after
   * the first {@code count}: the receiver below has already popped them.
   */
  private void popPassthroughsForwardedSince(int count) {
    while (count >= 0 && passthroughNames.size() > count) {
      popPassthrough(false);
    }
  }

  /**
   * Closes a forwarded element whose end tag the foreign tracker did not
   * treat as popping it, either because HTML content was open inside an
   * integration point, where a browser ignores the end tag, or because the
   * tracker never knew the element.  The receiver below honors the end tag,
   * so the tracker follows what was written.
   */
  private void closePassthroughByName(int passthrough) {
    int serial = passthroughSerials.get(passthrough);
    closePassthrough(passthrough, true);
    foreignContent.popNodeWithSerial(serial);
  }

  /**
   * Closes the forwarded element at {@code passthrough}, after every entry
   * and forwarded element opened inside it, innermost first.  The entries
   * inside it are closed implicitly, so formatting among them resumes
   * around later content as a browser reconstructs it.
   */
  private void closePassthrough(int passthrough, boolean emitCloseTags) {
    int depth = passthroughDepths.get(passthrough);
    if (depth < openElements.size()) {
      closeStackEntriesFrom(depth, emitCloseTags);
    }
    while (passthroughNames.size() - 1 > passthrough) {
      popPassthrough(emitCloseTags);
    }
    popPassthrough(emitCloseTags);
  }

  /**
   * Implicitly closes every entry from {@code fromIndex} up, innermost
   * first, along with the forwarded elements inside each, as the descendants
   * of an explicitly closed element are closed in {@link #closeStackFrom}.
   */
  private void closeStackEntriesFrom(int fromIndex, boolean emitCloseTags) {
    boolean closesTemplate = false;
    for (int i = fromIndex, n = openElements.size(); i < n; ++i) {
      if (openElements.get(i) == TEMPLATE_TAG) { closesTemplate = true; }
    }
    if (closesTemplate) {
      // Formatting inside template content must not resume outside it.
      toResumeInReverse.clear();
    }
    for (int i = openElements.size(); --i >= fromIndex;) {
      int unclosed = openElements.get(i);
      closePassthroughsInside(i, emitCloseTags);
      if (emitCloseTags && shouldSendClose(i)) {
        underlying.closeTag(METADATA.canonNameForIndex(unclosed));
      }
      if (unclosed == TEMPLATE_TAG) {
        closesTemplate = false;
      } else if (!closesTemplate && METADATA.resumable(unclosed)) {
        toResumeInReverse.add(unclosed);
      }
      discardStackSuffix(i);
    }
  }

  /** Nearest emitted foreign form whose lexical close clears an older pointer. */
  private int emittedForeignFormAbove(int pointerTarget) {
    for (int i = openElements.size(); --i > pointerTarget;) {
      if (openElements.get(i) == FORM_TAG
          && inputElementsInForeignContent.get(i)
          && sentToUnderlying.get(i)
          && outputElements.get(i) == FORM_TAG
          && outputElementsInForeignContent.get(i)) {
        return i;
      }
    }
    return -1;
  }

  /** Closes and removes {@code index} and every logical descendant. */
  private void closeStackFrom(int index, int closedElement) {
    closeStackFrom(index, closedElement, true);
  }

  /** Removes a suffix, optionally emitting closes not already sent by policy. */
  private void closeStackFrom(
      int index, int closedElement, boolean emitCloseTags) {
    if (closedElement == TABLE_TAG
        && outputElements.get(index) == TABLE_TAG
        && sentToUnderlying.get(index)
        && !pushedOut.get(index)
        && !outputElementsInForeignContent.get(index)) {
      outputlessTablePartsMayBeOpen = false;
      outputlessTablePartsOpenedAtEvent = -1;
    }
    if (closedElement == TABLE_TAG
        && outputElements.get(index) != TABLE_TAG) {
      detachOutputlessTableWithEmittedParts(index);
      for (int i = index + 1, n = openElements.size(); i < n; ++i) {
        int outputElement = outputElements.get(i);
        if (sentToUnderlying.get(i)
            && !pushedOut.get(i)
            && outputElement != NO_OUTPUT_ELEMENT
            && TABLE_PARTS.get(outputElement)) {
          markOutputlessTablePartsMayBeOpen();
          break;
        }
      }
    }
    if (closedElement == TEMPLATE_TAG) {
      // Formatting inside template content must not resume outside it.
      toResumeInReverse.clear();
    }
    int last = openElements.size();
    while (--last > index) {
      int unclosed = openElements.get(last);
      boolean sendClose = emitCloseTags && shouldSendClose(last);
      closePassthroughsInside(last, emitCloseTags);
      openElements.remove(last);
      inputElementSerials.remove(last);
      outputElements.remove(last);
      if (sendClose) {
        underlying.closeTag(METADATA.canonNameForIndex(unclosed));
      }
      sentToUnderlying.clear(last);
      inputElementsInForeignContent.clear(last);
      outputElementsInForeignContent.clear(last);
      outputElementsStartForeignContent.clear(last);
      formPointerTargets.clear(last);
      clearedFormPointerTargets.clear(last);
      staleOutputFormPointerTargets.clear(last);
      pushedOut.clear(last);
      impliedInputTables.clear(last);
      outputTableUnavailable.clear(last);
      outputlessTablesWithEmittedParts.clear(last);
      pushedMappedTemplateOutputOpen.clear(last);
      suppressedMappedForeignSubtrees.clear(last);
      if (closedElement != TEMPLATE_TAG && METADATA.resumable(unclosed)) {
        toResumeInReverse.add(unclosed);
      }
    }
    closePassthroughsInside(index, emitCloseTags);
    if (emitCloseTags && shouldSendClose(index)) {
      underlying.closeTag(METADATA.canonNameForIndex(closedElement));
    }
    sentToUnderlying.clear(index);
    inputElementsInForeignContent.clear(index);
    outputElementsInForeignContent.clear(index);
    outputElementsStartForeignContent.clear(index);
    formPointerTargets.clear(index);
    clearedFormPointerTargets.clear(index);
    staleOutputFormPointerTargets.clear(index);
    pushedOut.clear(index);
    impliedInputTables.clear(index);
    outputTableUnavailable.clear(index);
    outputlessTablesWithEmittedParts.clear(index);
    pushedMappedTemplateOutputOpen.clear(index);
    suppressedMappedForeignSubtrees.clear(index);
    openElements.remove(index);
    inputElementSerials.remove(index);
    outputElements.remove(index);
  }

  /** Whether the policy will emit this input form as an HTML form. */
  private boolean formWillEmitAsHtml(List<String> attrs) {
    if (underlying instanceof FormPointerPolicy) {
      return ((FormPointerPolicy) underlying).prepareForFormStart(attrs);
    }
    // Without policy feedback, names pass through unchanged.
    return !(underlying instanceof OpenTagOutputPolicy);
  }

  /** Emits the ignored start and pointer-clearing end as a balanced pair. */
  private boolean clearFormPointerWithBalancedPair() {
    if (effectiveNestingDepth() >= nestingLimit) { return false; }
    if (underlying instanceof FormPointerPolicy) {
      return ((FormPointerPolicy) underlying)
          .clearFormPointerWithBalancedPair();
    }
    if (underlying instanceof OpenTagOutputPolicy) { return false; }
    List<String> noAttrs = new ArrayList<>();
    underlying.openTag("form", noAttrs);
    underlying.closeTag("form");
    return true;
  }

  /** Makes a later emitted HTML form stable against another sanitization. */
  private void retireClearedOutputFormPointer() {
    int index = clearedFormPointerTargets.previousSetBit(
        openElements.size() - 1);
    if (index < 0) { return; }
    if (!staleOutputFormPointerTargets.get(index)) {
      // The serialized reset pair already clears this pointer.  Keep the old
      // form open: a browser can insert the new form inside it, and the marker
      // remains useful after that new form closes.
      return;
    }
    if (hasOpenHtmlOutputTableAbove(index)) {
      if (!clearFormPointerWithBalancedPair()) {
        closeStackFrom(index, FORM_TAG);
      } else {
        staleOutputFormPointerTargets.clear(index);
      }
      return;
    }
    retireOutputFormKeepingLogicalDescendants(index);
  }

  /**
   * Closes a form and its output descendants while retaining their logical
   * input entries.  An input template or foreign element still determines
   * how later input end tags are interpreted even when the policy dropped it
   * or the output stack had to be retired first.
   */
  private void retireOutputFormKeepingLogicalDescendants(int formIndex) {
    int oldSize = openElements.size();
    int descendantCount = oldSize - formIndex - 1;
    int[] descendants = new int[descendantCount];
    int[] descendantSerials = new int[descendantCount];
    int[] descendantOutputs = new int[descendantCount];
    boolean[] descendantsAreForeign = new boolean[descendantCount];
    boolean[] descendantOutputsAreForeign = new boolean[descendantCount];
    boolean[] descendantOutputsStartForeign = new boolean[descendantCount];
    boolean[] descendantsWereSent = new boolean[descendantCount];
    boolean[] descendantFormPointerTargets = new boolean[descendantCount];
    boolean[] descendantClearedFormPointerTargets =
        new boolean[descendantCount];
    boolean[] descendantStaleFormPointerTargets =
        new boolean[descendantCount];
    boolean[] descendantsArePushedOut = new boolean[descendantCount];
    boolean[] descendantsAreImpliedInputTables =
        new boolean[descendantCount];
    boolean[] descendantOutputTablesWereUnavailable =
        new boolean[descendantCount];
    boolean[] descendantOutputlessTablesHadEmittedParts =
        new boolean[descendantCount];
    boolean[] descendantSuppressedMappedForeignTemplates =
        new boolean[descendantCount];
    for (int i = 0; i < descendantCount; ++i) {
      int stackIndex = formIndex + 1 + i;
      descendants[i] = openElements.get(stackIndex);
      descendantSerials[i] = inputElementSerials.get(stackIndex);
      descendantOutputs[i] = outputElements.get(stackIndex);
      descendantsAreForeign[i] = inputElementsInForeignContent.get(stackIndex);
      descendantOutputsAreForeign[i] =
          outputElementsInForeignContent.get(stackIndex);
      descendantOutputsStartForeign[i] =
          outputElementsStartForeignContent.get(stackIndex);
      descendantsWereSent[i] = sentToUnderlying.get(stackIndex);
      descendantFormPointerTargets[i] = formPointerTargets.get(stackIndex);
      descendantClearedFormPointerTargets[i] =
          clearedFormPointerTargets.get(stackIndex);
      descendantStaleFormPointerTargets[i] =
          staleOutputFormPointerTargets.get(stackIndex);
      descendantsArePushedOut[i] = pushedOut.get(stackIndex);
      descendantsAreImpliedInputTables[i] =
          impliedInputTables.get(stackIndex);
      descendantOutputTablesWereUnavailable[i] =
          outputTableUnavailable.get(stackIndex);
      descendantOutputlessTablesHadEmittedParts[i] =
          outputlessTablesWithEmittedParts.get(stackIndex);
      descendantSuppressedMappedForeignTemplates[i] =
          suppressedMappedForeignSubtrees.get(stackIndex);
    }
    // Close the output suffix explicitly.  The library policy would do this
    // itself when it sees </form>, but an arbitrary receiver only sees the
    // events we send it and must receive a balanced close for every open.
    for (int i = oldSize; --i > formIndex;) {
      closePassthroughsInside(i, true);
      if (shouldSendClose(i)) {
        underlying.closeTag(METADATA.canonNameForIndex(openElements.get(i)));
      }
    }
    closePassthroughsInside(formIndex, true);
    if (sentToUnderlying.get(formIndex) && !pushedOut.get(formIndex)) {
      underlying.closeTag("form");
    }
    for (int i = oldSize; --i >= formIndex;) {
      openElements.remove(i);
      inputElementSerials.remove(i);
      outputElements.remove(i);
      sentToUnderlying.clear(i);
      inputElementsInForeignContent.clear(i);
      outputElementsInForeignContent.clear(i);
      outputElementsStartForeignContent.clear(i);
      formPointerTargets.clear(i);
      clearedFormPointerTargets.clear(i);
      staleOutputFormPointerTargets.clear(i);
      pushedOut.clear(i);
      impliedInputTables.clear(i);
      outputTableUnavailable.clear(i);
      outputlessTablesWithEmittedParts.clear(i);
      pushedMappedTemplateOutputOpen.clear(i);
      suppressedMappedForeignSubtrees.clear(i);
    }
    for (int i = descendantCount; --i >= 0;) {
      if (METADATA.resumable(descendants[i])) {
        toResumeInReverse.add(descendants[i]);
      }
    }
    for (int i = 0; i < descendantCount; ++i) {
      if (METADATA.resumable(descendants[i])) { continue; }
      int stackIndex = openElements.size();
      openElements.add(descendants[i]);
      inputElementSerials.add(descendantSerials[i]);
      outputElements.add(descendantOutputs[i]);
      sentToUnderlying.set(
          stackIndex, descendantsArePushedOut[i] && descendantsWereSent[i]);
      inputElementsInForeignContent.set(
          stackIndex, descendantsAreForeign[i]);
      outputElementsInForeignContent.set(
          stackIndex, descendantOutputsAreForeign[i]);
      outputElementsStartForeignContent.set(
          stackIndex, descendantOutputsStartForeign[i]);
      formPointerTargets.set(
          stackIndex, descendantFormPointerTargets[i]);
      clearedFormPointerTargets.set(
          stackIndex, descendantClearedFormPointerTargets[i]);
      staleOutputFormPointerTargets.set(
          stackIndex, descendantStaleFormPointerTargets[i]);
      pushedOut.set(stackIndex, descendantsArePushedOut[i]);
      impliedInputTables.set(
          stackIndex, descendantsAreImpliedInputTables[i]);
      outputTableUnavailable.set(
          stackIndex, descendantOutputTablesWereUnavailable[i]);
      outputlessTablesWithEmittedParts.set(
          stackIndex, descendantOutputlessTablesHadEmittedParts[i]);
      pushedMappedTemplateOutputOpen.clear(stackIndex);
      suppressedMappedForeignSubtrees.set(
          stackIndex, descendantSuppressedMappedForeignTemplates[i]);
    }
  }

  /**
   * Whether an emitted HTML table is still physically open above the form,
   * with no emitted HTML template changing the form-end-tag rules.
   */
  private boolean hasOpenHtmlOutputTableAbove(int formIndex) {
    boolean sawTable = false;
    for (int i = formIndex + 1, n = openElements.size(); i < n; ++i) {
      if (!sentToUnderlying.get(i)
          || pushedOut.get(i)
          || outputElementsInForeignContent.get(i)) {
        continue;
      }
      int outputElement = outputElements.get(i);
      if (outputElement == TEMPLATE_TAG) { return false; }
      if (outputElement == TABLE_TAG) { sawTable = true; }
    }
    return sawTable;
  }

  /** Whether an emitted HTML template is open on the logical output stack. */
  private boolean hasOpenHtmlOutputTemplate() {
    for (int i = openElements.size(); --i >= 0;) {
      if (sentToUnderlying.get(i)
          && !pushedOut.get(i)
          && !outputElementsInForeignContent.get(i)
          && outputElements.get(i) == TEMPLATE_TAG) {
        return true;
      }
    }
    return false;
  }

  /** Whether {@code elIndex} occurs before its end-tag scope is bounded. */
  private boolean hasOpenElementInScope(int elIndex) {
    int blockingScopes = SCOPE_FOR_END_TAG[elIndex];
    for (int i = openElements.size(); --i >= 0;) {
      int openElementIndex = openElements.get(i);
      if (openElementIndex == elIndex) { return true; }
      if ((SCOPES_BY_ELEMENT[openElementIndex] & blockingScopes) != 0) {
        return false;
      }
    }
    return false;
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

  /** Whether downstream can still be in a physical table insertion mode. */
  private boolean mayHavePhysicalOutputTable() {
    if (policyOnlyTableMayBeOpen) { return true; }
    for (int i = openElements.size(); --i >= 0;) {
      if (sentToUnderlying.get(i)
          && !pushedOut.get(i)
          && outputElements.get(i) == TABLE_TAG
          && !outputElementsInForeignContent.get(i)) {
        return true;
      }
    }
    return false;
  }

  /** Whether input balancing missed text foster-parenting in the output. */
  private boolean outputTableNeedsTextPreparation(int tableContext) {
    // A literal-content element above a table consumes text in its own
    // tokenizer state instead of applying the table insertion mode.
    int last = tableContext >= 0 ? tableContext : -1;
    for (int i = openElements.size(); --i > last;) {
      if (!sentToUnderlying.get(i) || pushedOut.get(i)) { continue; }
      int outputElement = outputElements.get(i);
      if (outputElement == NO_OUTPUT_ELEMENT) { continue; }
      if (hasSpecialTextMode(outputElement)) { return false; }
      break;
    }
    if (tableContext == POLICY_ONLY_TABLE_CONTEXT) { return true; }
    return tableContext >= 0
        && tableContext < openElements.size()
        && (openElements.get(tableContext) != outputElements.get(tableContext)
            || !outputSuffixMatchesInput(tableContext));
  }

  public void text(String text) {
    resetMappedForeignTableSuppressionIfPolicyEnded();
    resetDroppedSuppressedTableIfPolicyEnded();
    if (DEBUG) {
      dumpState("text `" + text.replace("\n", "\\n") + "`");
    }
    boolean isInterElementWhitespace = isInterElementWhitespace(text);
    PushedOutTablePolicy tablePolicy = pushedOutTablePolicy();
    boolean suppressingPolicySubtree = tablePolicy != null
        && tablePolicy.isSuppressingOutputAndContent();
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
    } else if (!suppressingPolicySubtree) {
      insertionPointIsInForeignContent = textIsInForeignContent();
      prepareForContent(HtmlElementTables.TEXT_NODE);
      if (mayHavePhysicalOutputTable()) {
        int outputTableContext = outputTableContextForStart();
        if (outputTableContext != -1
            && outputTableNeedsTextPreparation(outputTableContext)) {
          retireOutputTableForFosteredContent(outputTableContext);
        }
      }
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
    int stackTopIndex = openElements.size() - 1;
    if (droppedSkippableDepth == 0
        && (stackTopIndex < 0
            || !suppressedMappedForeignSubtrees.get(stackTopIndex))) {
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
    final byte NOFEATURE = 32;

    ALL_SCOPES = IN | BUTTON | LIST_ITEM | TABLE | SELECT | NOFEATURE;

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
    // The in-head rule for </template> searches through table structure, but
    // a nofeature element remains a deliberate barrier so text its policy
    // suppresses cannot escape when a template end tag appears inside it.
    SCOPE_FOR_END_TAG[TEMPLATE_TAG] = NOFEATURE;
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
      int out = outputElements.get(i);
      System.err.println("\t\t" + i + ":"
          + METADATA.canonNameForIndex(idx) + "->"
          + (out == NO_OUTPUT_ELEMENT ? "-"
              : METADATA.canonNameForIndex(out))
          + " serial=" + inputElementSerials.get(i)
          + " sent=" + sentToUnderlying.get(i)
          + " pushed=" + pushedOut.get(i)
          + " unavailable=" + outputTableUnavailable.get(i)
          + " inputForeign=" + inputElementsInForeignContent.get(i)
          + " outputForeign=" + outputElementsInForeignContent.get(i));
    }
    System.err.println("\tpassthroughs");
    for (int i = 0, n = passthroughNames.size(); i < n; ++i) {
      System.err.println("\t\t" + passthroughNames.get(i)
          + " depth=" + passthroughDepths.get(i)
          + " serial=" + passthroughSerials.get(i));
    }
    System.err.println("\tresumable");
    for (int i = 0, n = toResumeInReverse.size(); i < n; ++i) {
      int idx = toResumeInReverse.get(i);
      System.err.println("\t\t" + METADATA.canonNameForIndex(idx));
    }
  }
}
