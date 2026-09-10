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
               HtmlChangeReporter.AttributelessSkipPolicy {
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
   * True while a kept {@code <style>} or {@code <script>} that is an allowed
   * text container is open, so {@link #text} knows to vet its content for the
   * tags the lexer hands over as text.  Maintained like {@link #skipText}.
   */
  private boolean inKeptCdataElement;
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
    skippedLastTagAsAttributeless = false;
    openElementStack.clear();
    skipTextBeforeOpen.clear();
    inKeptCdataBeforeOpen.clear();
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
    skipText = true;
    inKeptCdataElement = false;
    out.closeDocument();
  }

  public void text(String textChunk) {
    if (!skipText) {
      // Note: Only style and script are CDATA elements; noscript/noembed/noframes are PCDATA
      // If inside a CDATA element (style/script) with allowTextIn, we need to filter out 
      // HTML tags that aren't allowed because tags inside these blocks are reclassified 
      // as UNESCAPED text by the lexer
      if (inKeptCdataElement
          && textChunk != null && textChunk.indexOf('<') >= 0) {
        // Strip out HTML tags that aren't in the allowed elements list
        String filtered = stripDisallowedTags(textChunk);
        out.text(filtered);
      } else {
        out.text(textChunk);
      }
    }
  }
  
  /**
   * Strips out HTML tags that aren't in the allowed elements list from text content.
   * This is used when tags appear inside text containers (like style blocks) where
   * they're treated as text but should still be validated.
   */
  private String stripDisallowedTags(String text) {
    if (text == null) {
      return text;
    }
    
    StringBuilder result = new StringBuilder();
    int len = text.length();
    int i = 0;
    
    while (i < len) {
      int tagStart = text.indexOf('<', i);
      if (tagStart < 0) {
        // No more tags, append the rest
        result.append(text.substring(i));
        break;
      }
      
      // Append text before the tag
      if (tagStart > i) {
        result.append(text.substring(i, tagStart));
      }
      
      // Find the end of the tag (either '>' or end of string)
      int tagEnd = text.indexOf('>', tagStart + 1);
      if (tagEnd < 0) {
        // Unclosed tag, skip it
        i = tagStart + 1;
        continue;
      }
      
      // Extract the tag content (between < and >)
      String tagContent = text.substring(tagStart + 1, tagEnd);
      
      // Only process if this looks like a valid HTML element tag
      // Valid tags start with a letter or / followed by a letter
      // Skip things like <, </>, <3, etc.
      // Also handle tags with leading whitespace like < script>
      boolean isValidTag = false;
      String tagName = null;
      
      // Trim leading whitespace for tag name detection
      String trimmedTagContent = tagContent.trim();
      
      if (trimmedTagContent.startsWith("/")) {
        // Closing tag - must have / followed by a letter
        if (trimmedTagContent.length() > 1) {
          char firstChar = trimmedTagContent.charAt(1);
          if (Character.isLetter(firstChar)) {
            isValidTag = true;
            tagName = trimmedTagContent.substring(1).trim().split("\\s")[0];
            tagName = HtmlLexer.canonicalElementName(tagName);
          }
        }
      } else {
        // Opening tag - must start with a letter (after trimming whitespace)
        if (trimmedTagContent.length() > 0) {
          char firstChar = trimmedTagContent.charAt(0);
          if (Character.isLetter(firstChar)) {
            isValidTag = true;
            tagName = trimmedTagContent.split("\\s")[0];
            tagName = HtmlLexer.canonicalElementName(tagName);
          }
        }
      }
      
      if (!isValidTag) {
        // Not a valid HTML tag, just append it as-is
        result.append('<').append(tagContent).append('>');
        i = tagEnd + 1;
        continue;
      }
      
      // Check if it's a closing tag
      if (tagContent.startsWith("/")) {
        // Only allow closing tags if the element is allowed
        if (elAndAttrPolicies.containsKey(tagName)) {
          result.append('<').append(tagContent).append('>');
        }
        // Otherwise skip the closing tag
        i = tagEnd + 1;
      } else {
        // Opening tag - only allow tags if the element is in the allowed list
        if (elAndAttrPolicies.containsKey(tagName)) {
          result.append('<').append(tagContent).append('>');
          i = tagEnd + 1;
        } else {
          // Skip disallowed tag and its content until matching closing tag
          i = tagEnd + 1;
          // Track nesting level to find the matching closing tag
          int nestingLevel = 1;
          while (i < len && nestingLevel > 0) {
            int nextTagStart = text.indexOf('<', i);
            if (nextTagStart < 0) {
              // No more tags, skip to end
              i = len;
              break;
            }
            int nextTagEnd = text.indexOf('>', nextTagStart + 1);
            if (nextTagEnd < 0) {
              // Unclosed tag, skip to end
              i = len;
              break;
            }
            String nextTagContent = text.substring(nextTagStart + 1, nextTagEnd);
            String trimmedNextTagContent = nextTagContent.trim();
            String nextTagName = trimmedNextTagContent.split("\\s")[0];
            if (trimmedNextTagContent.startsWith("/")) {
              // Closing tag
              nextTagName = nextTagName.substring(1);
              nextTagName = HtmlLexer.canonicalElementName(nextTagName);
              if (nextTagName.equals(tagName)) {
                nestingLevel--;
                if (nestingLevel == 0) {
                  // Found matching closing tag, skip it and continue
                  i = nextTagEnd + 1;
                  break;
                }
              }
            } else {
              // Opening tag
              nextTagName = HtmlLexer.canonicalElementName(nextTagName);
              if (nextTagName.equals(tagName)) {
                nestingLevel++;
              }
            }
            i = nextTagEnd + 1;
          }
        }
      }
    }
    
    return result.toString();
  }

  public void openTag(String elementName, List<String> attrs) {
    // StylingPolicy repeats some of this code because it is more complicated
    // to refactor it into multiple method bodies, so if you change this,
    // check the override of it in that class.
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

  static final @Nullable String applyPolicies(
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
          attrsIt.next();
          attrsIt.remove();
        } else {
          String value = attrsIt.next();
          String adjustedValue = attrPolicy.apply(elementName, name, value);
          if (adjustedValue == null) {
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
        adjustedElementName = HtmlLexer.canonicalElementName(adjustedElementName);
      }
    } else {
      adjustedElementName = null;
    }
    return adjustedElementName;
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
        break;
      }
    }
  }

  void writeOpenTag(
      ElementAndAttributePolicies policies, String adjustedElementName,
      List<String> attrs) {
    if (!HtmlTextEscapingMode.isVoidElement(adjustedElementName)) {
      push(policies.elementName, adjustedElementName);
      // A kept element is the container for the text inside it.  It is judged
      // by the name it was kept under, and by the name the author wrote when
      // text was disallowed in that.
      skipText = !allowedTextContainers.contains(adjustedElementName)
          || disallowedTextContainers.contains(policies.elementName);
      inKeptCdataElement = inKeptCdataElement
          || (("style".equals(adjustedElementName)
               || "script".equals(adjustedElementName))
              && allowedTextContainers.contains(adjustedElementName));
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
