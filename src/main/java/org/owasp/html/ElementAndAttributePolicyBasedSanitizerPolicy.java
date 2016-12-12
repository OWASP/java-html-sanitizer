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
import java.util.ListIterator;

import javax.annotation.Nullable;
import javax.annotation.concurrent.NotThreadSafe;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Lists;

/**
 * A sanitizer policy that applies element and attribute policies to tags.
 */
@TCB
@NotThreadSafe
class ElementAndAttributePolicyBasedSanitizerPolicy
    implements HtmlSanitizer.Policy {
  final ImmutableMap<String, ElementAndAttributePolicies> elAndAttrPolicies;
  final ImmutableSet<String> allowedTextContainers;
  private final HtmlStreamEventReceiver out;
  /**
   * True to skip textual content.  Used to ignore the content of embedded CDATA
   * content that is not meant to be human-readable.
   */
  transient boolean skipText = true;
  /**
   * Alternating input names and adjusted names of elements opened by the
   * caller.
   */
  private final List<String> openElementStack = Lists.newArrayList();

  ElementAndAttributePolicyBasedSanitizerPolicy(
      HtmlStreamEventReceiver out,
      ImmutableMap<String, ElementAndAttributePolicies> elAndAttrPolicies,
      ImmutableSet<String> allowedTextContainers) {
    this.out = out;
    this.elAndAttrPolicies = elAndAttrPolicies;
    this.allowedTextContainers = allowedTextContainers;
  }

  static final ImmutableSet<String> SKIPPABLE_ELEMENT_CONTENT
      = ImmutableSet.of(
          "script", "style", "noscript", "nostyle", "noembed", "noframes",
          "iframe", "object", "frame", "frameset", "title");

  public void openDocument() {
    skipText = false;
    openElementStack.clear();
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
    skipText = true;
    out.closeDocument();
  }

  public void text(String textChunk) {
    if (!skipText) {
      out.text(textChunk);
    }
  }

  public void openTag(String elementName, List<String> attrs) {
    // StylingPolicy repeats some of this code because it is more complicated
    // to refactor it into multiple method bodies, so if you change this,
    // check the override of it in that class.
    ElementAndAttributePolicies policies = elAndAttrPolicies.get(elementName);
    String adjustedElementName = applyPolicies(elementName, attrs, policies);
    if (adjustedElementName != null
        && !(attrs.isEmpty() && policies.skipIfEmpty)) {
      writeOpenTag(policies, adjustedElementName, attrs);
      return;
    }
    deferOpenTag(elementName);
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
        adjustedElementName = HtmlLexer.canonicalName(adjustedElementName);
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
        break;
      }
    }
    skipText = false;
    for (int i = openElementStack.size() - 1; i >= 0; i -= 2) {
      String adjustedName = openElementStack.get(i);
      if (adjustedName != null) {
        skipText = !(allowedTextContainers.contains(adjustedName));
        break;
      }
    }
  }

  void writeOpenTag(
      ElementAndAttributePolicies policies, String adjustedElementName,
      List<String> attrs) {
    if (!HtmlTextEscapingMode.isVoidElement(adjustedElementName)) {
      openElementStack.add(policies.elementName);
      openElementStack.add(adjustedElementName);
      skipText = !allowedTextContainers.contains(adjustedElementName);
    }
    out.openTag(adjustedElementName, attrs);
  }

  void deferOpenTag(String elementName) {
    if (!HtmlTextEscapingMode.isVoidElement(elementName)) {
      openElementStack.add(elementName);
      openElementStack.add(null);
    }
    skipText = SKIPPABLE_ELEMENT_CONTENT.contains(elementName);
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
        if (0 <= firstCharIndex && firstCharIndex <= 26) {
          int firstCharBit = 1 << firstCharIndex;
          if ((firstLetterMask & firstCharBit) == 0) {
            firstLetterMask = firstLetterMask | firstCharBit;
            break checkForDuplicate;
          }
        }
        // Look for a duplicate.
        for (int j = k; --j >= 0;) {
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
