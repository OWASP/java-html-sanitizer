package org.owasp.html;

import java.util.List;
import java.util.ListIterator;

import javax.annotation.Nullable;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Lists;

/**
 * A sanitizer policy that applies element and attribute policies to tags.
 */
@TCB
class ElementAndAttributePolicyBasedSanitizerPolicy
    implements HtmlSanitizer.Policy {
  final ImmutableMap<String, ElementAndAttributePolicies> elAndAttrPolicies;
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
      ImmutableMap<String, ElementAndAttributePolicies> elAndAttrPolicies) {
    this.out = out;
    this.elAndAttrPolicies = elAndAttrPolicies;
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
      skipText = false;
      writeOpenTag(policies, adjustedElementName, attrs);
      return;
    }
    deferOpenTag(elementName);
  }

  final @Nullable String applyPolicies(
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
      adjustedElementName = policies.elPolicy.apply(elementName, attrs);
    } else {
      adjustedElementName = null;
    }
    return adjustedElementName;
  }

  public void closeTag(String elementName) {
    skipText = false;
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
        return;
      }
    }
  }

  void writeOpenTag(
      ElementAndAttributePolicies policies, String adjustedElementName,
      List<String> attrs) {
    if (!policies.isVoid) {
      openElementStack.add(policies.elementName);
      openElementStack.add(adjustedElementName);
    }
    out.openTag(adjustedElementName, attrs);
  }

  void deferOpenTag(String elementName) {
    if (HtmlTextEscapingMode.isVoidElement(elementName)) {
      openElementStack.add(elementName);
      openElementStack.add(null);
    }
    skipText = SKIPPABLE_ELEMENT_CONTENT.contains(elementName);
  }

  void synthesizeOpenTag(String adjustedElementName, List<String> attrs) {
    openElementStack.add(null);
    openElementStack.add(adjustedElementName);
    out.openTag(adjustedElementName, attrs);
  }
}