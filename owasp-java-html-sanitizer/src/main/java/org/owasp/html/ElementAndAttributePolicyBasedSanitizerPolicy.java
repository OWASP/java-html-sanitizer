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

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.Deque;
import java.util.HashMap;
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
   * and is emitted only if that element is an allowed text container whose
   * input name is not one text was disallowed in.  A dropped element between
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
   * Alternating input names and adjusted names of elements opened by the
   * caller.
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
  /** The same for {@link #keptCdataElementName}; entries may be null. */
  private final List<String> keptCdataNameBeforeOpen = new ArrayList<>();

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
    droppedTextListener = null;
    discardedAttributeListener = null;
    outputElementNameForLastOpenTag = null;
    skippedLastTagAsAttributeless = false;
    openElementStack.clear();
    skipTextBeforeOpen.clear();
    inKeptCdataBeforeOpen.clear();
    keptCdataNameBeforeOpen.clear();
    out.openDocument();
  }

  public void closeDocument() {
    for (int i = openElementStack.size() - 1; i >= 0; i -= 2) {
      String tagNameToClose = openElementStack.get(i);
      if (tagNameToClose != null) {
        out.closeTag(tagNameToClose);
      }
    }
    openElementStack.clear();
    skipTextBeforeOpen.clear();
    inKeptCdataBeforeOpen.clear();
    keptCdataNameBeforeOpen.clear();
    skipText = true;
    inKeptCdataElement = false;
    keptCdataElementName = null;
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

  public void text(String textChunk) {
    if (!skipText) {
      // The renderer emits the text of a kept literal-content element as it
      // is, so a tag in it would reach the browser as written.  stripTags
      // says why none may.
      if (inKeptCdataElement
          && textChunk != null && textChunk.indexOf('<') >= 0) {
        String elementName = keptCdataElementName;
        if (elementName == null) {
          throw new IllegalStateException("Missing literal-content element");
        }
        out.text(stripTags(textChunk, elementName));
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
   * A start tag goes together with everything up to its matching end tag
   * when this chunk has one, so that {@code <script>alert(1)</script>}
   * inside a style block goes entirely; a start tag with no matching end
   * tag goes alone and the text after it stays.  A {@code <} that opens no
   * tag is text and stays, and the scan resumes right after it rather than
   * at the next {@code >}, which may belong to a tag inside the span, as in
   * {@code < </noscript>}.  A {@code <} left at the end of the output when
   * a tag is dropped goes with the tag, since it would otherwise meet
   * whatever follows the tag, as {@code <<b>/noscript>} would otherwise
   * yield {@code </noscript>}.
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
    // Find every tag, and pair each start tag with the end tag that matches
    // it, counting nested tags of the same name, the way brackets pair.  One
    // pass, so that a chunk full of unmatched start tags stays linear.
    List<int[]> tags = new ArrayList<>();
    Map<String, Deque<Integer>> unmatchedStarts = new HashMap<>();
    int i = 0;
    while (i < len) {
      int tagStart = text.indexOf('<', i);
      if (tagStart < 0) { break; }
      int nameStart = skipTrimSpace(text, tagStart + 1);
      if (nameStart == len) { break; }
      boolean isEndTag = text.charAt(nameStart) == '/';
      if (isEndTag) {
        nameStart = skipTrimSpace(text, nameStart + 1);
        if (nameStart == len) { break; }
      }
      if (!Character.isLetter(text.charAt(nameStart))) {
        // Not a tag: "<!-- -->", "</>", "<3" and the like.  The '<' is text,
        // and the scan resumes right after it.  In particular, do not search
        // for a '>' until the prefix is known to open a tag: repeatedly
        // searching the same suffix makes a long run of '<' quadratic.
        i = tagStart + 1;
        continue;
      }
      int tagEnd = text.indexOf('>', nameStart + 1);
      if (tagEnd < 0) { break; }  // No '<' from here on starts a tag.
      int bodyEnd = tagEnd;
      while (bodyEnd > nameStart && text.charAt(bodyEnd - 1) <= ' ') {
        --bodyEnd;
      }
      int nameEnd = nameStart + 1;
      while (nameEnd < bodyEnd
          && !isRegexWhitespace(text.charAt(nameEnd))) {
        ++nameEnd;
      }
      String tagName = HtmlLexer.canonicalElementName(
          text.substring(nameStart, nameEnd));
      int kind = isEndTag ? END_TAG : START_TAG;
      int[] tag = { tagStart, tagEnd + 1, -1, kind };
      if (kind == START_TAG) {
        Deque<Integer> starts = unmatchedStarts.get(tagName);
        if (starts == null) {
          starts = new ArrayDeque<>();
          unmatchedStarts.put(tagName, starts);
        }
        starts.push(tags.size());
      } else if (kind == END_TAG) {
        Deque<Integer> starts = unmatchedStarts.get(tagName);
        if (starts != null && !starts.isEmpty()) {
          tags.get(starts.pop())[MATCH_END] = tagEnd + 1;
        }
      }
      tags.add(tag);
      i = tagEnd + 1;
    }

    StringBuilder result = new StringBuilder(len);
    int pos = 0;
    for (int[] tag : tags) {
      if (tag[TAG_START] < pos) { continue; }  // Inside dropped content.
      result.append(text, pos, tag[TAG_START]);
      int dropStart = tag[TAG_START];
      pos = tag[KIND] == END_TAG || tag[MATCH_END] < 0
          ? tag[TAG_END] : tag[MATCH_END];
      // Any '<'s that the dropped tag followed would meet what follows the
      // tag.  Take the whole adjacent run, lest "<<<b>img" become "<img".
      int last = result.length() - 1;
      while (last >= 0 && result.charAt(last) == '<') {
        result.setLength(last);
        dropStart -= 1;
        --last;
      }
      reportDroppedText(elementName, text, dropStart, pos);
    }
    // The rest holds no tag.  A '<' in it stays if a '>' follows it in this
    // chunk, since it opened no tag and nothing after it can change that,
    // or if HTML whitespace follows it, which starts no tag in any browser
    // state.  Otherwise it is left dangling, and a later chunk could
    // complete it, so it goes.
    int lastGt = text.lastIndexOf('>');
    for (int c = pos; c < len; ++c) {
      char ch = text.charAt(c);
      if (ch != '<' || c < lastGt
          || (c + 1 < len && Strings.isHtmlSpace(text.charAt(c + 1)))) {
        result.append(ch);
      } else {
        reportDroppedText(elementName, text, c, c + 1);
      }
    }
    return result.toString();
  }

  /** Reports one exact range removed from a literal-content text chunk. */
  private void reportDroppedText(
      String elementName, String text, int start, int end) {
    if (droppedTextListener != null) {
      droppedTextListener.droppedText(elementName, text.substring(start, end));
    }
  }

  /** Indices into the records {@link #stripTags} keeps for each tag. */
  private static final int TAG_START = 0, TAG_END = 1, MATCH_END = 2, KIND = 3;
  /** The kinds of record. */
  private static final int START_TAG = 0, END_TAG = 1;

  /** Skips characters that {@link String#trim} treats as whitespace. */
  private static int skipTrimSpace(String s, int start) {
    int i = start;
    while (i < s.length() && s.charAt(i) <= ' ') { ++i; }
    return i;
  }

  /** The Java 8 regular-expression meaning of {@code \\s}. */
  private static boolean isRegexWhitespace(char ch) {
    switch (ch) {
      case ' ':
      case '\t':
      case '\n':
      case '\u000b':
      case '\f':
      case '\r':
        return true;
      default:
        return false;
    }
  }

  /**
   * True if the renderer emits the element's text as it is, without
   * escaping, so that a tag in that text would reach the browser as written.
   * Judged by the name the renderer emits: it renames {@code xmp},
   * {@code listing} and {@code plaintext} to {@code pre} and escapes their
   * text.
   */
  private static boolean isLiteralContentElement(String elementName) {
    switch (HtmlTextEscapingMode.getModeForTag(
                HtmlStreamRenderer.safeName(elementName))) {
      case CDATA:
      case CDATA_SOMETIMES:
      case PLAIN_TEXT:
        return true;
      default:
        return false;
    }
  }

  public void openTag(String elementName, List<String> attrs) {
    outputElementNameForLastOpenTag = null;
    ElementAndAttributePolicies policies = elAndAttrPolicies.get(elementName);
    String adjustedElementName = applyPolicies(elementName, attrs, policies);
    skippedLastTagAsAttributeless = false;
    if (adjustedElementName != null) {
      if (!(attrs.isEmpty() && policies.htmlTagSkipType.skipAvailability())) {
        writeOpenTag(policies, adjustedElementName, attrs);
        return;
      }
      // The element was allowed; it goes only because no attribute survived.
      skippedLastTagAsAttributeless = true;
    }
    deferOpenTag(elementName);
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
            out.closeTag(tagNameToClose);
          }
        }
        openElementStack.subList(i, n).clear();
        skipText = skipTextBeforeOpen.get(i / 2);
        inKeptCdataElement = inKeptCdataBeforeOpen.get(i / 2);
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
    if (!HtmlTextEscapingMode.isVoidElement(adjustedElementName)) {
      push(policies.elementName, adjustedElementName);
      // A kept element is the container for the text inside it.  It is judged
      // by the name it was kept under, and by the name the author wrote when
      // text was disallowed in that.
      skipText = !allowedTextContainers.contains(adjustedElementName)
          || disallowedTextContainers.contains(policies.elementName);
      boolean enteringKeptCdata = isLiteralContentElement(adjustedElementName)
          && allowedTextContainers.contains(adjustedElementName);
      if (!inKeptCdataElement && enteringKeptCdata) {
        keptCdataElementName = adjustedElementName;
      }
      inKeptCdataElement = inKeptCdataElement || enteringKeptCdata;
    }
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
