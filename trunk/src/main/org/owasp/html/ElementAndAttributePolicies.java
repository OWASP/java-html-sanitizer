package org.owasp.html;

import java.util.Map;

import javax.annotation.concurrent.Immutable;

import com.google.common.collect.ImmutableMap;

/**
 * Encapsulates all the information needed by the
 * {@link ElementAndAttributePolicyBasedSanitizerPolicy} to sanitize one kind
 * of element.
 */
@Immutable
final class ElementAndAttributePolicies {
  final String elementName;
  final boolean isVoid;
  final ElementPolicy elPolicy;
  final ImmutableMap<String, AttributePolicy> attrPolicies;
  final boolean skipIfEmpty;

  ElementAndAttributePolicies(
      String elementName,
      ElementPolicy elPolicy,
      Map<? extends String, ? extends AttributePolicy>
        attrPolicies,
      boolean skipIfEmpty) {
    this.elementName = elementName;
    this.isVoid = HtmlTextEscapingMode.isVoidElement(elementName);
    this.elPolicy = elPolicy;
    this.attrPolicies = ImmutableMap.copyOf(attrPolicies);
    this.skipIfEmpty = skipIfEmpty;
  }
}
