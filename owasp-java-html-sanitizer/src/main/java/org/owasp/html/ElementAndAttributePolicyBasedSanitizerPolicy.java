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
import java.util.ListIterator;
import java.util.Map;
import java.util.Set;

import javax.annotation.Nullable;
import javax.annotation.concurrent.NotThreadSafe;

import static org.owasp.shim.Java8Shim.j8;

/**
 * A sanitizer policy that applies element and attribute policies to tags.
 */
@TCB
@NotThreadSafe
class ElementAndAttributePolicyBasedSanitizerPolicy
    implements HtmlSanitizer.Policy,
               TagBalancingHtmlStreamEventReceiver.TextSuppressionPolicy,
               TagBalancingHtmlStreamEventReceiver.OpenTagOutputPolicy,
               TagBalancingHtmlStreamEventReceiver.OpenTagSuppressionPolicy,
               TagBalancingHtmlStreamEventReceiver.ReopenedTablePolicy,
               TagBalancingHtmlStreamEventReceiver.OutputContextPolicy,
               HtmlChangeReporter.AttributelessSkipPolicy,
               HtmlChangeReporter.DroppedTextSource,
               HtmlChangeReporter.DiscardedAttributeSource {
  final Map<String, ElementAndAttributePolicies> elAndAttrPolicies;
  final Set<String> allowedTextContainers;
  /**
   * Elements in which text is disallowed, from
   * {@link HtmlPolicyBuilder#disallowTextIn}, by the name the author wrote:
   * the rule holds whether the policy keeps, renames or drops the element.
   * Disjoint from {@link #allowedTextContainers}.
   */
  final Set<String> disallowedTextContainers;
  private final HtmlStreamEventReceiver out;
  /**
   * True to skip textual content.  Used to ignore the content of embedded CDATA
   * content that is not meant to be human-readable.
   * <p>
   * While a document is open, this is the gate {@link #openElementStack}
   * implies.  Text belongs to the nearest enclosing element the policy kept,
   * and is emitted only if that element is an allowed text container under
   * the name the author wrote, and, where the policy emitted it under a name
   * a browser reads literally, under that name too.  A dropped element between
   * the text and that container is not a container in the output, so it does
   * not decide -- unless its content is never meant to be read as text
   * ({@link #SKIPPABLE_ELEMENT_CONTENT}) or text in it was disallowed, either
   * of which suppresses the text.  Outside a document it is true, so stray
   * text is dropped.
   * <p>
   * The gate costs constant time per tag: each push derives the new value from
   * the old one, and {@link #skipTextBeforeOpen} remembers the old one so a
   * pop can restore it.  Re-deriving it by walking the stack would be
   * quadratic on a long run of unknown tags, which the balancer forwards
   * without counting them toward its nesting limit.
   */
  transient boolean skipText = true;
  /**
   * True while a kept element whose text the renderer emits unescaped, such
   * as {@code <style>}, {@code <script>} or {@code <iframe>}, is open as an
   * allowed text container, so {@link #text} knows to strip the tags the
   * lexer hands over as text.  Maintained like {@link #skipText}.
   */
  private boolean inKeptCdataElement;
  /**
   * The adjusted name of the outermost kept literal-content element, or null
   * outside one.  This accompanies {@link #inKeptCdataElement} so a listener
   * can identify the element whose text the policy filtered.
   */
  private @Nullable String keptCdataElementName;
  /**
   * True while a kept {@code svg} or {@code math} element is open, so that a
   * browser parses the content of every element inside it as markup.
   * Maintained like {@link #skipText}, and in step with the renderer's own
   * count of the same elements, since the renderer sees the tags this policy
   * emits.  {@link #isLiteralContentElement} says why it matters.
   */
  private boolean inForeignContent;
  /** Browser tree-construction context for the tags actually emitted. */
  private HtmlSanitizer.ForeignContentContext outputForeignContent
      = new HtmlSanitizer.ForeignContentContext();
  /**
   * The last few characters emitted for the kept literal-content element that
   * is open.  Text arrives in chunks, and {@link #stripTags} needs them to see
   * a comment delimiter that removing a tag would otherwise splice together
   * across a chunk boundary.
   */
  private String literalTextTail = "";
  /**
   * Alternating input names and adjusted names of elements opened by the
   * caller, for the input names a close tag can come for: the ones that are
   * not void.  The adjusted name is null where there is nothing to close in
   * the output, because the element was dropped or emitted as a void one.
   */
  private final List<String> openElementStack = new ArrayList<>();
  /**
   * Bit {@code k} is the value {@link #skipText} had before the {@code k}-th
   * element on {@link #openElementStack} was pushed, so that popping back to
   * {@code k} elements restores it.
   */
  private final BitSet skipTextBeforeOpen = new BitSet();
  /** The same for {@link #inKeptCdataElement}. */
  private final BitSet inKeptCdataBeforeOpen = new BitSet();
  /** The same for {@link #inForeignContent}. */
  private final BitSet inForeignContentBeforeOpen = new BitSet();
  /** The same for {@link #keptCdataElementName}; entries may be null. */
  private final List<String> keptCdataNameBeforeOpen = new ArrayList<>();
  /**
   * True if {@link #out} is the library's own renderer, possibly behind
   * {@link HtmlStreamEventReceiverWrapper} decorators, so that what it escapes
   * is known.  See {@link #isLiteralContentElement}.
   */
  private final boolean outIsLibraryRenderer;

  /** Told about filtered literal content; null while nobody is listening. */
  private @Nullable HtmlStreamRenderer.DroppedTextListener droppedTextListener;
  /** Told exactly which input attributes an attribute policy rejects. */
  private @Nullable HtmlChangeReporter.DiscardedAttributeListener
      discardedAttributeListener;
  /** The output name, if any, produced by the most recent open-tag call. */
  private transient @Nullable String outputElementNameForLastOpenTag;

  ElementAndAttributePolicyBasedSanitizerPolicy(
      HtmlStreamEventReceiver out,
      Map<String, ElementAndAttributePolicies> elAndAttrPolicies,
      Set<String> allowedTextContainers,
      Set<String> disallowedTextContainers) {
    this.out = out;
    this.elAndAttrPolicies = j8().mapCopyOf(elAndAttrPolicies);
    this.allowedTextContainers = j8().setCopyOf(allowedTextContainers);
    this.disallowedTextContainers = j8().setCopyOf(disallowedTextContainers);
    HtmlStreamEventReceiver sink = out;
    while (sink instanceof HtmlStreamEventReceiverWrapper) {
      sink = ((HtmlStreamEventReceiverWrapper) sink).underlying;
    }
    this.outIsLibraryRenderer = sink instanceof HtmlStreamRenderer;
  }

  /**
   * Elements whose own text the policy does not surface when it drops them:
   * script and style source, and fallback or metadata content that a browser
   * would hide in place.  Children the policy keeps still render.  The tag
   * balancer consults this list too, for start tags it drops at the nesting
   * limit before the policy sees them.
   */
  static final Set<String> SKIPPABLE_ELEMENT_CONTENT
      = j8().setOf(
          "script", "style", "noscript", "nostyle", "noembed", "noframes",
          "iframe", "object", "frame", "frameset", "title");

  /**
   * True after {@link #openTag} allowed the element but emitted no tag
   * because no attribute survived and the element is skipped when it has
   * none.  {@link HtmlChangeReporter} asks, so that it can report the
   * rejected attributes as the policy's doing rather than the element's.
   */
  private transient boolean skippedLastTagAsAttributeless;

  public void openDocument() {
    skipText = false;
    inKeptCdataElement = false;
    keptCdataElementName = null;
    inForeignContent = false;
    outputForeignContent = new HtmlSanitizer.ForeignContentContext();
    literalTextTail = "";
    droppedTextListener = null;
    discardedAttributeListener = null;
    outputElementNameForLastOpenTag = null;
    skippedLastTagAsAttributeless = false;
    openElementStack.clear();
    skipTextBeforeOpen.clear();
    inKeptCdataBeforeOpen.clear();
    inForeignContentBeforeOpen.clear();
    keptCdataNameBeforeOpen.clear();
    out.openDocument();
  }

  public void closeDocument() {
    for (int i = openElementStack.size() - 1; i >= 0; i -= 2) {
      String tagNameToClose = openElementStack.get(i);
      if (tagNameToClose != null) {
        outputForeignContent.processEndTag(tagNameToClose);
        out.closeTag(tagNameToClose);
      }
    }
    openElementStack.clear();
    skipTextBeforeOpen.clear();
    inKeptCdataBeforeOpen.clear();
    inForeignContentBeforeOpen.clear();
    keptCdataNameBeforeOpen.clear();
    skipText = true;
    inKeptCdataElement = false;
    keptCdataElementName = null;
    inForeignContent = false;
    outputElementNameForLastOpenTag = null;
    out.closeDocument();
  }

  public void reportDroppedTextTo(
      @Nullable HtmlStreamRenderer.DroppedTextListener listener) {
    this.droppedTextListener = listener;
  }

  public void reportDiscardedAttributesTo(
      @Nullable HtmlChangeReporter.DiscardedAttributeListener listener) {
    this.discardedAttributeListener = listener;
  }

  public @Nullable String outputElementNameForLastOpenTag() {
    return outputElementNameForLastOpenTag;
  }

  public boolean isOutputInForeignContent() {
    return outputForeignContent.isInForeignContent();
  }

  public @Nullable String outputForeignContentRootName() {
    return outputForeignContent.outermostForeignElementName();
  }

  public boolean outputStartTagUsesForeignContentRules(
      String elementName, List<String> attrs) {
    return outputForeignContent.startTagUsesForeignContentRules(
        elementName, attrs);
  }

  public void text(String textChunk) {
    if (!skipText) {
      // The renderer emits the text of a kept literal-content element as it
      // is, so a tag in it would reach the browser as written.  stripTags
      // says why none may.
      if (inKeptCdataElement && textChunk != null) {
        String elementName = keptCdataElementName;
        if (elementName == null) {
          throw new IllegalStateException("Missing literal-content element");
        }
        String filtered = textChunk.indexOf('<') < 0
            ? textChunk : stripTags(textChunk, elementName);
        rememberLiteralTextTail(filtered);
        out.text(filtered);
      } else {
        out.text(textChunk);
      }
    }
  }

  /**
   * Removes every tag from a chunk of the text of a kept literal-content
   * element such as {@code style}, {@code script} or {@code iframe}.
   * <p>
   * A browser reads such text literally, so a tag in it is at best noise.
   * It is also where the sanitizer and a browser can disagree about which
   * element the text is in: a browser with scripting on reads
   * {@code noscript} as raw text up to the first {@code </noscript>}, and
   * reads {@code noframes} and {@code noembed} that way always, while the
   * sanitizer treats all three as ordinary containers.  A
   * {@code </noscript>} inside a {@code style} nested in a {@code noscript}
   * therefore ends the {@code noscript} for the browser, and whatever
   * follows is parsed as markup (CVE-2025-66021).  So no end tag may
   * survive, whatever element it names, and no start tag is re-emitted:
   * an allowed element's start tag used to be copied through with its
   * attributes unvetted, which put an event handler after the breakout.
   * <p>
   * A tag is {@code <}, optional whitespace, an optional {@code /}, and a
   * well-formed name: an ASCII letter and then letters, digits, {@code -},
   * {@code _}, {@code :} or {@code .} up to whitespace, a {@code /} or the
   * {@code >}.  A {@code <} that opens no tag is text and stays, and the scan
   * resumes right after it rather than at the next {@code >}, which may
   * belong to a tag inside the span, as in {@code < </noscript>}.  Anything a
   * browser would only read as a tag in a markup context, such as the
   * {@code < b) { x(); } if (c >} in ordinary script text, therefore stays:
   * the text reaches a browser inside an element whose content it reads
   * literally, and the cases where it might not are closed elsewhere -- an
   * end tag that would break out of a raw-text element has a well-formed
   * name and goes, the renderer refuses content holding one anyway, text in a
   * literal element under a {@code select} is dropped by the tag balancer
   * (CVE-2021-42575), and in foreign content, where a browser parses
   * everything as markup, the renderer escapes the text instead of emitting
   * it as written.
   * <p>
   * A start tag goes together with everything up to its matching end tag
   * when this chunk has one, so that {@code <script>alert(1)</script>}
   * inside a style block goes entirely; a start tag with no matching end
   * tag goes alone and the text after it stays.  A {@code <} left at the end
   * of the output when a tag is dropped goes with the tag, since it would
   * otherwise meet whatever follows the tag, as {@code <<b>/noscript>} would
   * otherwise yield {@code </noscript>}.  Removing a tag also must not splice
   * a {@code <!--} or {@code -->} together out of the text on either side,
   * nor take one away, since the renderer refuses the whole content of an
   * element whose comments are unbalanced: a space goes in where a join would
   * make one, and a start tag that would take one along with its content is
   * dropped on its own instead.
   * <p>
   * Text arrives in chunks whose boundaries fall anywhere, so each chunk has
   * to be safe on its own.  A {@code <} with no {@code >} after it in the
   * chunk therefore goes, unless HTML whitespace follows it: a later chunk
   * could otherwise complete it into an end tag, or into a start tag that
   * the element's own end tag then closes for a browser already reading
   * markup, whereas no browser state starts a tag at {@code <} followed by
   * whitespace.
   * Each exact range removed is also sent to {@link #droppedTextListener}.
   */
  private String stripTags(String text, String elementName) {
    int len = text.length();
    StringBuilder result = new StringBuilder(len);
    int[] starts = unmatchedStarts;
    if (starts == null) {
      starts = unmatchedStarts = new int[MAX_UNMATCHED_STARTS * START_FIELDS];
    }
    // How much of starts holds unmatched start tags, innermost last.
    int nStarts = 0;
    // Where the last comment delimiter in result ends, or 0 for none, so that
    // a start tag that would take one with its content can be spotted.
    int lastDelimiterEnd = 0;
    // Text before this has been appended to result or dropped.
    int pos = 0;
    // Where the text appended since the last removal began, in the chunk and
    // in result, so that a '<' the removal leaves at the end of result can be
    // reported under the range it came from.  Nothing before it can end in
    // one, since every removal takes the one it would have left.
    int runInputStart = 0, runResultStart = 0;
    // Where dropTagStartsLeftAtTheEnd last left off.
    int tagStartsCheckedTo = 0;
    int i = 0;
    while (i < len) {
      int tagStart = text.indexOf('<', i);
      if (tagStart < 0) { break; }
      int p = skipBeforeTagName(text, tagStart + 1, len);
      boolean isEndTag = p < len && text.charAt(p) == '/';
      if (isEndTag) { p = skipBeforeTagName(text, p + 1, len); }
      int nameEnd = tagNameEnd(text, p, len);
      if (nameEnd < 0) {
        // Not a tag: "<!-- -->", "</>", "<3", "< b) {" and the like.  The '<'
        // is text, and the scan resumes right after it: a '>' later in the
        // chunk may end a tag that starts inside the span, as in
        // "< </noscript>".  The name is read before any '>' is looked for, so
        // that a chunk where no '<' opens a tag costs one pass over it and
        // not one pass for each '<'.
        i = tagStart + 1;
        continue;
      }
      int tagEnd = nameEnd < len && text.charAt(nameEnd) == '>'
          ? nameEnd : text.indexOf('>', nameEnd);
      if (tagEnd < 0) { break; }  // No '<' from here on starts a tag.
      // The text before the tag survives.
      if (pos < tagStart) {
        int delimiterEnd = lastCommentDelimiterEnd(text, pos, tagStart);
        runInputStart = pos;
        runResultStart = result.length();
        result.append(text, pos, tagStart);
        if (delimiterEnd >= 0) {
          lastDelimiterEnd = result.length() - (tagStart - delimiterEnd);
        }
      }
      int dropStart = tagStart;
      // Any '<'s that the dropped tag followed would meet what follows the
      // tag.  Take the whole adjacent run, lest "<<<b>img" become "<img".
      int last = result.length() - 1;
      while (last >= 0 && result.charAt(last) == '<') {
        result.setLength(last);
        dropStart -= 1;
        --last;
      }
      // Before the output is noted for an end tag to come back to, so that
      // what it comes back to is output this has already been over.
      tagStartsCheckedTo = dropTagStartsLeftAtTheEnd(
          result, tagStartsCheckedTo, runInputStart, runResultStart);
      int matched = isEndTag
          ? indexOfUnmatchedStart(text, starts, nStarts, p, nameEnd)
          : -1;
      if (matched >= 0
          && lastDelimiterEnd <= starts[matched + START_RESULT_LEN]) {
        // The start tag's content goes with it, and so do the start tags
        // inside, which the text that went took with it.
        result.setLength(starts[matched + START_RESULT_LEN]);
        dropStart = starts[matched + START_TAG_START];
        nStarts = matched;
        tagStartsCheckedTo = Math.min(tagStartsCheckedTo, result.length());
      } else if (!isEndTag && nStarts < starts.length) {
        starts[nStarts + START_TAG_START] = dropStart;
        starts[nStarts + START_NAME_START] = p;
        starts[nStarts + START_NAME_END] = nameEnd;
        starts[nStarts + START_RESULT_LEN] = result.length();
        nStarts += START_FIELDS;
      }
      pos = tagEnd + 1;
      i = pos;
      recordDroppedRange(dropStart, pos);
      appendSpaceIfJoinWouldMakeCommentDelimiter(result, text, pos);
    }
    // The rest holds no tag.  A '<' in it stays if a '>' follows it in this
    // chunk, since it opened no tag and nothing after it can change that,
    // or if HTML whitespace follows it, which starts no tag in any browser
    // state.  Otherwise it is left dangling, and a later chunk could
    // complete it, so it goes.
    int lastGt = text.lastIndexOf('>');
    if (pos < len) {
      runInputStart = pos;
      runResultStart = result.length();
    }
    for (int c = pos; c < len; ++c) {
      char ch = text.charAt(c);
      if (ch != '<' || c < lastGt
          || (c + 1 < len && Strings.isHtmlSpace(text.charAt(c + 1)))) {
        result.append(ch);
      } else {
        recordDroppedRange(c, c + 1);
        appendSpaceIfJoinWouldMakeCommentDelimiter(result, text, c + 1);
        runInputStart = c + 1;
        runResultStart = result.length();
      }
    }
    // What the element's own end tag, or a later chunk, would finish into a
    // tag goes too.
    dropTagStartsLeftAtTheEnd(
        result, tagStartsCheckedTo, runInputStart, runResultStart);
    reportDroppedRanges(elementName, text);
    return result.toString();
  }

  /**
   * Scratch for {@link #stripTags}, reused across chunks: the start tags it
   * has not matched an end tag to, as {@link #START_FIELDS} ints each.
   */
  private int[] unmatchedStarts;

  /**
   * How many unmatched start tags one chunk pairs end tags with.  Pairing only
   * keeps a dropped element's content with it, which buys no safety, since
   * whatever survives is tag-free text either way, so the bookkeeping is
   * bounded rather than growing with a count of tags an attacker chooses: the
   * filter's memory stays proportional to its output.  Literal text nested
   * deeper than this drops each tag on its own.
   */
  private static final int MAX_UNMATCHED_STARTS = 64;

  /** The fields {@link #stripTags} keeps for an unmatched start tag. */
  private static final int
      START_TAG_START = 0, START_NAME_START = 1, START_NAME_END = 2,
      START_RESULT_LEN = 3, START_FIELDS = 4;

  /**
   * Where in {@code starts} the innermost unmatched start tag whose name is
   * {@code text.substring(nameStart, nameEnd)} sits, or -1 if there is none.
   * Names are compared where they lie, so that pairing allocates nothing, and
   * case-insensitively, as a browser matches an end tag to a start tag.
   */
  private static int indexOfUnmatchedStart(
      String text, int[] starts, int nStarts, int nameStart, int nameEnd) {
    int nameLen = nameEnd - nameStart;
    for (int k = nStarts - START_FIELDS; k >= 0; k -= START_FIELDS) {
      int start = starts[k + START_NAME_START];
      if (starts[k + START_NAME_END] - start == nameLen
          && Strings.regionMatchesIgnoreCase(
                 text, start, text, nameStart, nameLen)) {
        return k;
      }
    }
    return -1;
  }

  /**
   * Skips what can lie between a tag's {@code <}, or its {@code /}, and its
   * name: HTML whitespace, which a browser tolerates in an end tag, and
   * anything the renderer elides, which would otherwise hide a name behind a
   * character that is not there in the output.
   */
  private static int skipBeforeTagName(String text, int start, int limit) {
    int i = start;
    while (i < limit) {
      char ch = text.charAt(i);
      if (!Strings.isHtmlSpace(ch) && !Encoding.isPossiblyElidedCodeunit(ch)) {
        break;
      }
      ++i;
    }
    return i;
  }

  /**
   * Where the tag name starting at {@code nameStart} ends, or -1 if what is
   * there is not one.  A name is an ASCII letter and then letters, digits,
   * {@code -}, {@code _}, {@code :} or {@code .}, and it ends at HTML
   * whitespace, a {@code /} or a {@code >}; running into any other character
   * the output keeps, or into the end of the chunk, makes it no name.
   * {@link #stripTags} says why that is the right line to draw.
   * <p>
   * A character the renderer elides ends the name instead, since eliding it
   * joins the name to what follows: an end tag spelt {@code </noscript}, a
   * NUL, {@code >} is {@code </noscript>} by the time it is emitted.
   */
  private static int tagNameEnd(String text, int nameStart, int limit) {
    if (nameStart >= limit) { return -1; }
    if (!isTagNameStart(text.charAt(nameStart))) { return -1; }
    for (int p = nameStart + 1; p < limit; ++p) {
      char ch = text.charAt(p);
      if (isTagNameChar(ch)) { continue; }
      return Strings.isHtmlSpace(ch) || ch == '/' || ch == '>'
          || Encoding.isPossiblyElidedCodeunit(ch) ? p : -1;
    }
    return -1;  // The chunk ends inside the name, so no '>' follows it.
  }

  /** True if a tag name can start with {@code ch}. */
  private static boolean isTagNameStart(char ch) {
    return ('a' <= ch && ch <= 'z') || ('A' <= ch && ch <= 'Z');
  }

  /** True if a tag name can go on with {@code ch}. */
  private static boolean isTagNameChar(char ch) {
    return isTagNameStart(ch) || ('0' <= ch && ch <= '9')
        || ch == '-' || ch == '_' || ch == ':' || ch == '.';
  }

  /**
   * Removes the {@code <} of anything that a removal, or the end of the chunk,
   * leaves able to open a tag.  Whatever comes next in the output -- the text
   * that followed a removed tag, the next chunk, or the {@code >} of the
   * element's own end tag -- would otherwise finish a {@code <b} or
   * {@code </b} that the text itself did not hold, and a browser that reads
   * markup here would act on it: {@code <b<svg> onmouseover=1>} must not become
   * {@code <b onmouseover=1>}, nor {@code </<b>noscript>} become
   * {@code </noscript>}.
   * <p>
   * Only the run of name characters, {@code <} and {@code /} that ends the
   * output can hold one, and in it only a {@code <} that a name follows, or
   * that the output ends before the name: a {@code <} before anything else
   * opens no tag however the text goes on, so {@code <3} and {@code < b} stay.
   * The run is read from the right, since what a {@code <} opens depends on
   * what survives after it, as the second {@code <} of {@code <<b} shows.
   * What follows one never changes once it has been read, so each is read
   * once.
   *
   * @param from where the last look left off, so that what it kept is not
   *     looked at again.
   * @return where this look left off.
   */
  private int dropTagStartsLeftAtTheEnd(
      StringBuilder result, int from, int runInputStart, int runResultStart) {
    int limit = Math.max(from, runResultStart);
    int regionStart = result.length();
    while (regionStart > limit
           && isTagRunChar(result.charAt(regionStart - 1))) {
      --regionStart;
    }
    // What survives is written to the right of a cursor as the run is read, so
    // that the run is rewritten once rather than closed up around each '<'.
    int w = result.length();
    char after = NOTHING, afterThat = NOTHING;
    for (int r = result.length() - 1; r >= regionStart; --r) {
      char ch = result.charAt(r);
      if (ch == '<' && startsTagName(after, afterThat)) {
        int lessThan = runInputStart + (r - runResultStart);
        recordDroppedRange(lessThan, lessThan + 1);
      } else {
        result.setCharAt(--w, ch);
        afterThat = after;
        after = ch;
      }
    }
    result.delete(regionStart, w);
    return result.length();
  }

  /**
   * Stands for the end of the output in {@link #startsTagName}.  No character
   * of a run that can end in an unfinished tag is this one.
   */
  private static final char NOTHING = '\0';

  /** True if {@code ch} can be part of a tag that the output ends inside. */
  private static boolean isTagRunChar(char ch) {
    return ch == '<' || ch == '/' || isTagNameChar(ch);
  }

  /**
   * True if a tag name follows a {@code <}, where {@code after} and
   * {@code afterThat} are the first two characters that survive after it and
   * {@link #NOTHING} says the output ends there, which what comes next may
   * continue into a name.
   */
  private static boolean startsTagName(char after, char afterThat) {
    if (after == NOTHING) { return true; }
    if (after == '/') {
      return afterThat == NOTHING || isTagNameStart(afterThat);
    }
    return isTagNameStart(after);
  }

  /**
   * Where the last {@code <!--} or {@code -->} in
   * {@code text.substring(start, end)} ends, or -1 if it holds neither.
   */
  private static int lastCommentDelimiterEnd(String text, int start, int end) {
    for (int i = end - 1; i > start; --i) {
      if (text.charAt(i) == '-' && text.charAt(i - 1) == '-') {
        if (i + 1 < end && text.charAt(i + 1) == '>') { return i + 2; }
        if (i - 3 >= start
            && text.charAt(i - 2) == '!' && text.charAt(i - 3) == '<') {
          return i + 1;
        }
      }
    }
    return -1;
  }

  /**
   * Appends a space to {@code result} if the text from {@code pos} on would
   * otherwise join what a removed range left before it into a {@code <!--} or
   * {@code -->}.  The renderer refuses the whole content of a literal element
   * whose comment delimiters do not balance, so removing a tag must not make
   * one.  What comes before may be in an earlier chunk and what follows may be
   * in a later one, and an unseen character is taken to be the worst one.
   */
  private void appendSpaceIfJoinWouldMakeCommentDelimiter(
      StringBuilder result, String text, int pos) {
    int len = text.length();
    char r0 = pos < len ? text.charAt(pos) : UNSEEN;
    char r1 = pos + 1 < len ? text.charAt(pos + 1) : UNSEEN;
    boolean joins
        // "-->" split by the join, as "--" + ">" or as "-" + "->".
        = (endsWith(result, "--") && (r0 == '>' || r0 == UNSEEN))
        || (endsWith(result, "-")
            && (r0 == '-' || r0 == UNSEEN) && (r1 == '>' || r1 == UNSEEN))
        // "<!--" the same way.  The third split, after the '<', cannot happen:
        // a '<' left before a removed range goes with it.
        || (endsWith(result, "<!")
            && (r0 == '-' || r0 == UNSEEN) && (r1 == '-' || r1 == UNSEEN))
        || (endsWith(result, "<!-") && (r0 == '-' || r0 == UNSEEN));
    if (joins) {
      result.append(' ');
    }
  }

  /** Stands for a character in another chunk, which may be any character. */
  private static final char UNSEEN = '\uFFFF';

  /**
   * True if the text emitted for this literal-content element so far ends with
   * {@code suffix}, looking into {@link #literalTextTail} for what an earlier
   * chunk emitted.
   */
  private boolean endsWith(StringBuilder result, String suffix) {
    int resultLen = result.length();
    for (int k = 0, n = suffix.length(); k < n; ++k) {
      char want = suffix.charAt(n - 1 - k);
      char got;
      if (k < resultLen) {
        got = result.charAt(resultLen - 1 - k);
      } else {
        int t = literalTextTail.length() - (k - resultLen) - 1;
        if (t < 0) { return false; }
        got = literalTextTail.charAt(t);
      }
      if (got != want) { return false; }
    }
    return true;
  }

  /** Keeps the end of a chunk for {@link #endsWith} to look back into. */
  private void rememberLiteralTextTail(String emitted) {
    int n = emitted.length();
    if (n >= LITERAL_TEXT_TAIL_LENGTH) {
      literalTextTail = emitted.substring(n - LITERAL_TEXT_TAIL_LENGTH);
    } else if (n != 0) {
      String tail = literalTextTail + emitted;
      int tailLen = tail.length();
      literalTextTail = tailLen <= LITERAL_TEXT_TAIL_LENGTH
          ? tail : tail.substring(tailLen - LITERAL_TEXT_TAIL_LENGTH);
    }
  }

  /** The longest part of a comment delimiter that can precede a join. */
  private static final int LITERAL_TEXT_TAIL_LENGTH = 3;

  /**
   * Pairs of offsets into the chunk {@link #stripTags} is filtering that it
   * has removed, held until the chunk is done because removing a start tag's
   * content subsumes the ranges recorded inside it.  Empty while nobody is
   * listening, so that a chunk full of tags costs nothing but its output.
   */
  private int[] droppedRanges = NO_RANGES;
  /** How much of {@link #droppedRanges} holds ranges. */
  private int nDroppedRanges;

  private static final int[] NO_RANGES = new int[0];

  /** Records one range removed from a literal-content text chunk. */
  private void recordDroppedRange(int start, int end) {
    if (droppedTextListener == null) { return; }
    int n = nDroppedRanges;
    // A range that covers ones already recorded replaces them: the text they
    // held went with it.
    while (n >= 2 && droppedRanges[n - 2] >= start && droppedRanges[n - 1] <= end) {
      n -= 2;
    }
    if (n + 2 > droppedRanges.length) {
      droppedRanges = Arrays.copyOf(
          droppedRanges, Math.max(16, droppedRanges.length * 2));
    }
    droppedRanges[n] = start;
    droppedRanges[n + 1] = end;
    nDroppedRanges = n + 2;
  }

  /** Reports the ranges removed from one chunk, in the order they lay. */
  private void reportDroppedRanges(String elementName, String text) {
    int n = nDroppedRanges;
    nDroppedRanges = 0;
    // A '<' that a removal left able to open a tag is found after the text
    // that follows it has been looked at, so the ranges can be a little out of
    // order.  Insertion sort, since they almost always are in it.
    for (int k = 2; k < n; k += 2) {
      int start = droppedRanges[k], end = droppedRanges[k + 1];
      int j = k;
      while (j > 0 && droppedRanges[j - 2] > start) {
        droppedRanges[j] = droppedRanges[j - 2];
        droppedRanges[j + 1] = droppedRanges[j - 1];
        j -= 2;
      }
      droppedRanges[j] = start;
      droppedRanges[j + 1] = end;
    }
    for (int k = 0; k < n; k += 2) {
      droppedTextListener.droppedText(
          elementName,
          text.substring(droppedRanges[k], droppedRanges[k + 1]));
    }
  }

  /**
   * True if the text of an element kept as {@code adjustedElementName} reaches
   * a browser as written, so that a tag in it would be a tag to the browser
   * and {@link #stripTags} has to run over it.
   * <p>
   * {@link HtmlStreamRenderer} escapes the text of the elements it renames --
   * {@code xmp}, {@code listing} and {@code plaintext} become {@code pre} --
   * and escapes the content of every element inside {@code svg} or
   * {@code math}, which a browser parses as markup.  Where the output is one
   * of those renderers the filter follows it exactly, so that nothing is
   * stripped from text the renderer escapes anyway.  Any other
   * {@link HtmlStreamEventReceiver} may write the text as it stands, under the
   * name the policy gives it, so for those every element whose content the
   * lexer read as raw text is filtered, wherever it sits.
   */
  private boolean isLiteralContentElement(String adjustedElementName) {
    return outIsLibraryRenderer
        ? HtmlStreamRenderer.emitsContentLiterally(
              HtmlStreamRenderer.safeName(adjustedElementName),
              inForeignContent)
        : HtmlStreamRenderer.emitsContentLiterally(adjustedElementName, false);
  }

  public void openTag(String elementName, List<String> attrs) {
    openTag(elementName, attrs, OpenTagMode.NORMAL);
  }

  public void openTagWithoutOutput(String elementName, List<String> attrs) {
    openTag(elementName, attrs, OpenTagMode.SUPPRESS);
  }

  public void openReopenedTable(List<String> attrs) {
    openTag("table", attrs, OpenTagMode.REOPENED_TABLE);
  }

  private void openTag(
      String elementName, List<String> attrs, OpenTagMode mode) {
    outputElementNameForLastOpenTag = null;
    ElementAndAttributePolicies policies = elAndAttrPolicies.get(elementName);
    String adjustedElementName = applyPolicies(elementName, attrs, policies);
    skippedLastTagAsAttributeless = false;
    if (adjustedElementName != null) {
      if (!(attrs.isEmpty() && policies.htmlTagSkipType.skipAvailability())) {
        if (mode == OpenTagMode.NORMAL
            || (mode == OpenTagMode.REOPENED_TABLE
                && "table".equals(adjustedElementName))) {
          writeOpenTag(policies, adjustedElementName, attrs);
        } else if (!HtmlTextEscapingMode.isVoidElement(elementName)) {
          push(elementName, null);
          skipText = !allowedTextContainers.contains(elementName)
              || disallowedTextContainers.contains(elementName)
              // An emitted HTML breakout can leave the renderer's lexical
              // SVG/Math nesting open after the browser context has left it.
              // Text from a suppressed table part cannot be placed safely in
              // that stale lexical context, so fail closed for that text.
              || (inForeignContent
                  && !outputForeignContent.isInForeignContent());
        }
        return;
      }
      // The element was allowed; it goes only because no attribute survived.
      skippedLastTagAsAttributeless = true;
    }
    deferOpenTag(elementName);
  }

  private enum OpenTagMode {
    NORMAL,
    REOPENED_TABLE,
    SUPPRESS,
  }

  public boolean skippedLastTagAsAttributeless() {
    return skippedLastTagAsAttributeless;
  }

  private @Nullable String applyPolicies(
      String elementName, List<String> attrs,
      ElementAndAttributePolicies policies) {
    String adjustedElementName;
    if (policies != null) {
      for (ListIterator<String> attrsIt = attrs.listIterator();
           attrsIt.hasNext();) {
        String name = attrsIt.next();
        AttributePolicy attrPolicy
            = policies.attrPolicies.get(name);
        if (attrPolicy == null) {
          attrsIt.remove();
          String value = attrsIt.next();
          reportDiscardedAttribute(name, value);
          attrsIt.remove();
        } else {
          String value = attrsIt.next();
          String adjustedValue = attrPolicy.apply(elementName, name, value);
          if (adjustedValue == null) {
            reportDiscardedAttribute(name, value);
            attrsIt.remove();
            attrsIt.previous();
            attrsIt.remove();
          } else {
            attrsIt.set(adjustedValue);
          }
        }
      }

      // Now that we know which attributes are allowed, make sure the names
      // are unique.
      removeDuplicateAttributes(attrs);

      adjustedElementName = policies.elPolicy.apply(elementName, attrs);
      if (adjustedElementName != null) {
        adjustedElementName =
            HtmlLexer.canonicalElementName(adjustedElementName);
      }
    } else {
      adjustedElementName = null;
    }
    return adjustedElementName;
  }

  /** Reports an attribute-policy rejection without invoking user code. */
  private void reportDiscardedAttribute(String name, String value) {
    if (discardedAttributeListener != null) {
      discardedAttributeListener.discardedAttribute(name, value);
    }
  }

  public void closeTag(String elementName) {
    int n = openElementStack.size();
    for (int i = n; i > 0;) {
      i -= 2;
      String openElementName = openElementStack.get(i);
      if (elementName.equals(openElementName)) {
        for (int j = n - 1; j > i; j -= 2) {
          String tagNameToClose = openElementStack.get(j);
          if (tagNameToClose != null) {
            outputForeignContent.processEndTag(tagNameToClose);
            out.closeTag(tagNameToClose);
          }
        }
        openElementStack.subList(i, n).clear();
        skipText = skipTextBeforeOpen.get(i / 2);
        inKeptCdataElement = inKeptCdataBeforeOpen.get(i / 2);
        inForeignContent = inForeignContentBeforeOpen.get(i / 2);
        keptCdataElementName = keptCdataNameBeforeOpen.get(i / 2);
        keptCdataNameBeforeOpen.subList(
            i / 2, keptCdataNameBeforeOpen.size()).clear();
        break;
      }
    }
  }

  void writeOpenTag(
      ElementAndAttributePolicies policies, String adjustedElementName,
      List<String> attrs) {
    outputElementNameForLastOpenTag = adjustedElementName;
    String elementName = policies.elementName;
    // Whether a close tag will come for this element depends on the name the
    // author wrote, which is the one the lexer and the tag balancer see, not
    // on the name the policy emitted it under.  The stack follows suit, so
    // that every entry on it is one a close tag can pop.
    if (HtmlTextEscapingMode.isVoidElement(elementName)) {
      boolean adjustedIsVoid =
          HtmlTextEscapingMode.isVoidElement(adjustedElementName);
      outputForeignContent.processStartTag(
          adjustedElementName, attrs, adjustedIsVoid);
      out.openTag(adjustedElementName, attrs);
      if (!adjustedIsVoid) {
        // Renamed to an element that needs closing, which nothing upstream
        // will do: closed at once, so it does not swallow what follows.
        outputForeignContent.processEndTag(adjustedElementName);
        out.closeTag(adjustedElementName);
      }
      return;
    }
    if (HtmlTextEscapingMode.isVoidElement(adjustedElementName)) {
      // Renamed to a void element.  The close tag that comes for the input
      // name has nothing to close in the output, and the text between is
      // not inside the element there, so the gate stays as it was, as after
      // a dropped element.
      push(elementName, null);
      skipText = skipText || suppressesTextWhenDropped(elementName);
      outputForeignContent.processStartTag(adjustedElementName, attrs, true);
      out.openTag(adjustedElementName, attrs);
      return;
    }
    push(elementName, adjustedElementName);
    // A kept element is the container for the text inside it.  Whether it may
    // hold text was said of the name the author wrote, which is the name the
    // builder's methods take, so that is the name judged.  An element the
    // policy emits under a name a browser reads literally, such as style, is
    // held to the same bar as one written under that name: text in it needs
    // allowTextIn on that name too.
    boolean literal = isLiteralContentElement(adjustedElementName);
    skipText = !allowedTextContainers.contains(elementName)
        || disallowedTextContainers.contains(elementName)
        || (literal && !allowedTextContainers.contains(adjustedElementName));
    boolean enteringKeptCdata = literal && !skipText;
    if (!inKeptCdataElement && enteringKeptCdata) {
      keptCdataElementName = adjustedElementName;
      literalTextTail = "";
    }
    inKeptCdataElement = inKeptCdataElement || enteringKeptCdata;
    // Judged before this element is in foreign content itself: a browser
    // parses the content of an svg or math element as markup, but the
    // element's own tag sits in whatever contains it.
    inForeignContent = inForeignContent
        || HtmlStreamRenderer.FOREIGN_CONTENT_ROOT_ELEMENT_NAMES.contains(
               adjustedElementName);
    outputForeignContent.processStartTag(adjustedElementName, attrs, false);
    out.openTag(adjustedElementName, attrs);
  }

  void deferOpenTag(String elementName) {
    if (!HtmlTextEscapingMode.isVoidElement(elementName)) {
      push(elementName, null);
      // A dropped element is not a container in the output, so the gate stays
      // as it was -- unless the element's content must not surface as text.
      skipText = skipText || suppressesTextWhenDropped(elementName);
    }
  }

  /**
   * Pushes an element onto {@link #openElementStack}, remembering the gates in
   * effect before it so that {@link #closeTag} can restore them.
   */
  private void push(String elementName, @Nullable String adjustedElementName) {
    int depth = openElementStack.size() / 2;
    skipTextBeforeOpen.set(depth, skipText);
    inKeptCdataBeforeOpen.set(depth, inKeptCdataElement);
    inForeignContentBeforeOpen.set(depth, inForeignContent);
    keptCdataNameBeforeOpen.add(keptCdataElementName);
    openElementStack.add(elementName);
    openElementStack.add(adjustedElementName);
  }

  /**
   * True if text directly inside a dropped {@code elementName} is suppressed
   * rather than emitted where the element was: its content is never meant to
   * be read as text, or the policy disallowed text in it.
   */
  public boolean suppressesTextWhenDropped(String elementName) {
    return SKIPPABLE_ELEMENT_CONTENT.contains(elementName)
        || disallowedTextContainers.contains(elementName);
  }

  /**
   * Remove attributes with the same name.
   * <p>
   * <a href="http://www.w3.org/TR/html5/syntax.html#attributes-0">HTML5</a>
   * says
   * <blockquote>
   * There must never be two or more attributes on the same start tag whose
   * names are an ASCII case-insensitive match for each other.
   * </blockquote>
   * <p>
   * Empirically, given
   * {@code
   * <!doctype html><html><body>
   * <script id="first" id="last">
   * var scriptElement = document.getElementsByTagName('script')[0];
   * document.body.appendChild(
   *   document.createTextNode(scriptElement.getAttribute('id')));
   * </script>}
   * Firefox, Safari and Chrome all show "first" so we eliminate from the right.
   */
  private static void removeDuplicateAttributes(List<String> attrs) {
    int firstLetterMask = 0;
    int n = attrs.size();
    // attrs.subList(0, k) contains the non-duplicate parts of attrs that
    // have been processed thus far.
    int k = 0;
    attrLoop:
    for (int i = 0; i < n; i += 2) {
      String name = attrs.get(i);

      if (name.length() == 0) {
        continue attrLoop;
      }

      int firstCharIndex = name.charAt(0) - 'a';
      checkForDuplicate: {
        // Don't be O(n**2) in the common case by checking whether the first
        // letter has been seen on any other attribute.
        if (0 <= firstCharIndex && firstCharIndex < 26) {
          int firstCharBit = 1 << firstCharIndex;
          if ((firstLetterMask & firstCharBit) == 0) {
            firstLetterMask = firstLetterMask | firstCharBit;
            break checkForDuplicate;
          }
        }
        // Look for a duplicate.  attrs alternates names and values, so step
        // by two to compare against names only; comparing against a value
        // would drop an attribute whose name matches an earlier value.
        for (int j = k - 2; j >= 0; j -= 2) {
          if (attrs.get(j).equals(name)) {
            continue attrLoop;
          }
        }
      }

      // Preserve the attribute.
      if (k != i) {
        attrs.set(k, name);
        attrs.set(k + 1, attrs.get(i + 1));
      }
      k += 2;
    }
    if (k != n) {
      attrs.subList(k, n).clear();
    }
  }
}
