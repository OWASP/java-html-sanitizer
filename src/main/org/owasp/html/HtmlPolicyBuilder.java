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
import java.util.Map;
import java.util.Set;

import javax.annotation.concurrent.NotThreadSafe;

import com.google.common.base.Function;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;


/**
 * Conveniences for configuring policies for the {@link HtmlSanitizer}.
 *
 * <h3>Usage</h3>
 * <p>
 * To create a policy, first construct an instance of this class; then call
 * <code>allow&hellip;</code> methods to turn on tags, attributes, and other
 * processing modes; and finally call <code>build()</code> or
 * <code>toFactory()</code>.
 * </p>
 * <pre class="prettyprint lang-java">
 * // Define the policy.
 * Function<HtmlStreamEventReceiver, HtmlSanitizer.Policy> policyDefinition
 *     = new HtmlPolicyBuilder()
 *         .allowElements("a", "p")
 *         .allowAttributesOnElement("a", "href")
 *         .toFactory();
 *
 * // Sanitize your output.
 * HtmlSanitizer.sanitize(myHtml. policyDefinition.apply(myHtmlStreamRenderer));
 * </pre>
 *
 * <h3>Embedded Content</h3>
 * <p>
 * Embedded URLs are filtered by
 * {@link HtmlPolicyBuilder#allowUrlProtocols protocol}.
 * There is a {@link HtmlPolicyBuilder#allowStandardUrlProtocols canned policy}
 * so you can easily white-list widely used policies that don't violate the
 * current pages origin.  See "Customization" below for ways to do further
 * filtering.  If you allow links it might be worthwhile to
 * {@link HtmlPolicyBuilder#requireRelNofollowOnLinks() require}
 * {@code rel=nofollow}.
 * </p>
 * <p>
 * This class simply throws out all embedded JS.
 * Use a custom element or attribute policy to allow through
 * signed or otherwise known-safe code.
 * Check out the Caja project if you need a way to contain third-party JS.
 * </p>
 * <p>
 * This class does not attempt to faithfully parse and sanitize CSS.
 * It does provide {@link HtmlPolicyBuilder#allowStyling() one} styling option
 * that allows through a few CSS properties that allow textual styling, but that
 * disallow image loading, history stealing, layout breaking, code execution,
 * etc.
 * </p>
 *
 * <h3>Customization</h3>
 * <p>
 * You can easily do custom processing on tags and attributes by supplying your
 * own {@link ElementPolicy element policy} or
 * {@link AttributePolicy attribute policy} when calling
 * <code>allow&hellip;</code>.
 * E.g. to convert headers into {@code <div>}s, you could use an element policy
 * </p>
 * <pre class="prettyprint lang-java">
 *     new HtmlPolicyBuilder
 *         .allowElement(
 *         new ElementPolicy() {
 *           public String apply(String elementName, List<String> attributes) {
 *             attributes.add("class");
 *             attributes.add("header-" + elementName);
 *             return "div";
 *           }
 *         },
 *         "h1", "h2", "h3", "h4", "h5", "h6")
 *         .build(outputChannel)
 * </pre>
 *
 * <h3>Rules of Thumb</h3>
 * <p>
 * Throughout this class, several rules hold:
 * <ul>
 *   <li>Everything is denied by default.  There are
 *     <code>disallow&hellip;</code> methods, but those reverse
 *     allows instead of rolling back overly permissive defaults.
 *   <li>The order of allows and disallows does not matter.
 *     Disallows trump allows whether they occur before or after them.
 *     The only method that needs to be called in a particular place is
 *     {@link HtmlPolicyBuilder#build}.
 *     Allows or disallows after {@code build} is called have no
 *     effect on the already built policy.
 *   <li>Element and attribute policies are applied in the following order:
 *     element specific attribute policy, global attribute policy, element
 *     policy.
 *     Element policies come last so they can observe all the post-processed
 *     attributes, and so they can add attributes that are exempt from
 *     attribute policies.
 *     Element specific policies go first, so they can normalize content to
 *     a form that might be acceptable to a more simplistic global policy.
 * </ul>
 *
 * <h3>Thread safety and efficiency</h3>
 * <p>
 * This class is not thread-safe.  The resulting policy will not violate its
 * security guarantees as a result of race conditions, but is not thread safe
 * because it maintains state to track whether text inside disallowed elements
 * should be suppressed.
 * <p>
 * The resulting policy can be reused, but if you use the
 * {@link HtmlPolicyBuilder#toFactory()} method instead of {@link #build}, then
 * binding policies to output channels is cheap so there's no need.
 * </p>
 *
 * @author Mike Samuel <mikesamuel@gmail.com>
 */
@TCB
@NotThreadSafe
public class HtmlPolicyBuilder {
  /**
   * The default set of elements that are removed if they have no attributes.
   * Since {@code <img>} is in this set, by default, a policy will remove
   * {@code <img src=javascript:alert(1337)>} because its URL is not allowed
   * and it has no other attributes that would warrant it appearing in the
   * output.
   */
  public static final ImmutableSet<String> DEFAULT_SKIP_IF_EMPTY
      = ImmutableSet.of("a", "font", "img", "input", "span");

  private final Map<String, ElementPolicy> elPolicies = Maps.newLinkedHashMap();
  private final Map<String, Map<String, AttributePolicy>> attrPolicies
      = Maps.newLinkedHashMap();
  private final Map<String, AttributePolicy> globalAttrPolicies
      = Maps.newLinkedHashMap();
  private final Set<String> allowedProtocols = Sets.newLinkedHashSet();
  private final Set<String> skipIfEmpty = Sets.newLinkedHashSet(
      DEFAULT_SKIP_IF_EMPTY);
  private boolean requireRelNofollowOnLinks, allowStyling;

  /**
   * Allows the named elements.
   */
  public HtmlPolicyBuilder allowElements(String... elementName) {
    return allowElements(ElementPolicy.IDENTITY_ELEMENT_POLICY, elementName);
  }

  /**
   * Disallows the named elements.  Elements are disallowed by default, so
   * there is no need to disallow elements, unless you are making an exception
   * based on an earlier allow.
   */
  public HtmlPolicyBuilder disallowElements(String... elementName) {
    return allowElements(ElementPolicy.REJECT_ALL_ELEMENT_POLICY, elementName);
  }

  /**
   * Allow the given elements with the given policy.
   *
   * @param policy May remove or add attributes, change the element name, or
   *    deny the element.
   */
  public HtmlPolicyBuilder allowElements(
      ElementPolicy policy, String... elementNames) {
    invalidateCompiledState();
    for (String elementName : elementNames) {
      elementName = HtmlLexer.canonicalName(elementName);
      ElementPolicy newPolicy = ElementPolicy.Util.join(
          elPolicies.get(elementName), policy);
      // Don't remove if newPolicy is the always reject policy since we want
      // that to infect later allowElement calls for this particular element
      // name.  rejects should have higher priority than allows.
      elPolicies.put(elementName, newPolicy);
    }
    return this;
  }

  /**
   * A canned policy that allows a number of common formatting elements.
   */
  public HtmlPolicyBuilder allowCommonInlineFormattingElements() {
    return allowElements(
        "b", "i", "font", "s", "u", "o", "sup", "sub", "ins", "del", "strong",
        "strike", "tt", "code", "big", "small", "br", "span");
  }

  /**
   * A canned policy that allows a number of common block elements.
   */
  public HtmlPolicyBuilder allowCommonBlockElements() {
    return allowElements(
        "p", "div", "h1", "h2", "h3", "h4", "h5", "h6", "ul", "ol", "li",
        "blockquote");
  }

  /**
   * Assuming the given elements are allowed, allows them to appear without
   * attributes.
   *
   * @see #DEFAULT_SKIP_IF_EMPTY
   * @see #disallowWithoutAttributes
   */
  public HtmlPolicyBuilder allowWithoutAttributes(String... elementNames) {
    invalidateCompiledState();
    for (String elementName : elementNames) {
      elementName = HtmlLexer.canonicalName(elementName);
      skipIfEmpty.remove(elementName);
    }
    return this;
  }

  /**
   * Disallows the given elements from appearing without attributes.
   *
   * @see #DEFAULT_SKIP_IF_EMPTY
   * @see #allowWithoutAttributes
   */
  public HtmlPolicyBuilder disallowWithoutAttributes(String... elementNames) {
    invalidateCompiledState();
    for (String elementName : elementNames) {
      elementName = HtmlLexer.canonicalName(elementName);
      skipIfEmpty.add(elementName);
    }
    return this;
  }

  /**
   * Allows the given attributes on any elements.
   * Be careful of using this with attributes like <code>type</code> which have
   * different meanings on different attributes.
   */
  public HtmlPolicyBuilder allowAttributesGlobally(String... attributeNames) {
    return allowAttributesGlobally(
        AttributePolicy.IDENTITY_ATTRIBUTE_POLICY, attributeNames);
  }

  /**
   * Disallows the given attributes on any elements.
   * Attributes are disallowed unless explicitly allowed, so there is no need
   * to call this except to reverse an earlier
   * {@link #allowAttributesGlobally allow}.
   * Disallowing an attribute globally also disallows it on specific elements.
   */
  public HtmlPolicyBuilder disallowAttributesGlobally(
      String... attributeNames) {
    return allowAttributesGlobally(
        AttributePolicy.REJECT_ALL_ATTRIBUTE_POLICY, attributeNames);
  }

  /**
   * Allows the given attributes on any elements.
   * Global attribute policies are applied after element specific policies.
   * Be careful of using this with attributes like <code>type</code> which have
   * different meanings on different attributes.
   * Also be careful of allowing globally attributes like <code>href</code>
   * which can have more far-reaching effects on tags like
   * <code>&lt;base&gt;</code> and <code>&lt;link&gt;</code> than on
   * <code>&lt;a&gt;</code> because in the former, they have an effect without
   * user interaction and can change the behavior of the current page.
   *
   * @param policy Can allow, specify a different value for, or deny the
   *     attribute.
   */
  public HtmlPolicyBuilder allowAttributesGlobally(
      AttributePolicy policy, String... attributeNames) {
    invalidateCompiledState();
    for (String attributeName : attributeNames) {
      attributeName = HtmlLexer.canonicalName(attributeName);
      // We reinterpret the identity policy later via policy joining since its
      // the default passed from the policy-less method, but we don't do
      // anything here since we don't know until build() is called whether the
      // policy author wants to allow certain URL protocols or wants to deal
      // with styles.
      AttributePolicy oldPolicy = globalAttrPolicies.get(attributeName);
      globalAttrPolicies.put(
          attributeName, AttributePolicy.Util.join(oldPolicy, policy));
    }
    return this;
  }

  /**
   * Allows the named attributes on the given element.
   */
  public HtmlPolicyBuilder allowAttributesOnElement(
      String elementName, String... attributeNames) {
    return allowAttributesOnElement(
        AttributePolicy.IDENTITY_ATTRIBUTE_POLICY, elementName, attributeNames);
  }

  /**
   * Allows the named attributes on the given element.
   *
   * @param policy Can allow, specify a different value for, or deny the
   *     attribute.
   */
  public HtmlPolicyBuilder allowAttributesOnElement(
      AttributePolicy policy, String elementName, String... attributeNames) {
    invalidateCompiledState();
    elementName = HtmlLexer.canonicalName(elementName);
    Map<String, AttributePolicy> policies = attrPolicies.get(elementName);
    if (policies == null) {
      policies = Maps.newLinkedHashMap();
      attrPolicies.put(elementName, policies);
    }
    for (String attributeName : attributeNames) {
      attributeName = HtmlLexer.canonicalName(attributeName);
      AttributePolicy oldPolicy = policies.get(attributeName);
      policies.put(
          attributeName,
          AttributePolicy.Util.join(oldPolicy, policy));
    }
    return this;
  }

  /**
   * Reverse an earlier element-specific attribute
   * {@link #allowAttributesOnElement allow}.
   * <p>
   * Attributes are disallowed by default, so there is no need to call this
   * with a laundry list of attribute/element pairs.
   */
  public HtmlPolicyBuilder disallowAttributesOnElement(
      String elementName, String... attributeNames) {
    return allowAttributesOnElement(
        AttributePolicy.REJECT_ALL_ATTRIBUTE_POLICY,
        elementName, attributeNames);
  }

  /**
   * Adds <a href="http://en.wikipedia.org/wiki/Nofollow"><code>rel=nofollow</code></a>
   * to links.
   */
  public HtmlPolicyBuilder requireRelNofollowOnLinks() {
    invalidateCompiledState();
    this.requireRelNofollowOnLinks = true;
    return this;
  }

  /**
   * Adds to the set of protocols that are allowed in URL attributes.
   * For each URL attribute that is allowed, we further constrain it by
   * only allowing the value through if it specifies no protocol, or if it
   * specifies one in the allowedProtocols white-list.
   * This is done regardless of whether any protocols have been allowed, so
   * allowing the attribute "href" globally with the identity policy but
   * not white-listing any protocols, effectively disallows the "href"
   * attribute globally.
   * <p>
   * Do not allow any <code>*script</code> such as <code>javascript</code>
   * protocols if you might use this policy with untrusted code.
   */
  public HtmlPolicyBuilder allowUrlProtocols(String... protocols) {
    invalidateCompiledState();
    // If there is at least one allowed protocol, then allow URLs and
    // add a filter that checks href and src values.

    // Do not allow href and srcs through otherwise, and only allow on images
    // and links.
    for (String protocol : protocols) {
      protocol = Strings.toLowerCase(protocol);
      allowedProtocols.add(protocol);
    }
    return this;
  }

  /**
   * Reverses a decision made by {@link #allowUrlProtocols}.
   */
  public HtmlPolicyBuilder disallowUrlProtocols(String... protocols) {
    invalidateCompiledState();
    for (String protocol : protocols) {
      protocol = Strings.toLowerCase(protocol);
      allowedProtocols.remove(protocol);
    }
    return this;
  }

  /**
   * A canned URL protocol policy that allows <code>http</code>,
   * <code>https</code>, and <code>mailto</code>.
   */
  public HtmlPolicyBuilder allowStandardUrlProtocols() {
    return allowUrlProtocols("http", "https", "mailto");
  }

  /**
   * Convert <code>style="&lt;CSS&gt;"</code> to simple non-JS containing
   * <code>&lt;font&gt;</code> tags to allow color, font-size, typeface, and
   * other styling.
   */
  public HtmlPolicyBuilder allowStyling() {
    invalidateCompiledState();
    allowStyling = true;
    return this;
  }

  /**
   * Names of attributes from HTML 4 whose values are URLs.
   * Other attributes, e.g. <code>style</code> may contain URLs even though
   * there values are not URLs.
   */
  private static final Set<String> URL_ATTRIBUTE_NAMES = ImmutableSet.of(
      "action", "archive", "background", "cite", "classid", "codebase", "data",
      "dsync", "href", "longdesc", "src", "usemap");

  /**
   * Produces a policy based on the allow and disallow calls previously made.
   *
   * @param out receives calls to open only tags allowed by
   *      previous calls to this object.
   *      Typically a {@link HtmlStreamRenderer}.
   */
  public HtmlSanitizer.Policy build(HtmlStreamEventReceiver out) {
    return toFactory().apply(out);
  }

  /**
   * Like {@link #build} but can be reused to create many different policies
   * each backed by a different output channel.
   */
  public Function<HtmlStreamEventReceiver, HtmlSanitizer.Policy> toFactory() {
    return new Factory(compilePolicies(), allowStyling);
  }

  // Speed up subsequent builds by caching the compiled policies.
  private transient ImmutableMap<String, ElementAndAttributePolicies>
      compiledPolicies;

  /** Called by mutators to signal that any compiled policy is out-of-date. */
  private void invalidateCompiledState() {
    compiledPolicies = null;
  }

  private ImmutableMap<String, ElementAndAttributePolicies> compilePolicies() {
    if (compiledPolicies != null) { return compiledPolicies; }

    // Copy maps before normalizing in case builder is reused.
    Map<String, ElementPolicy> elPolicies
        = Maps.newLinkedHashMap(this.elPolicies);
    Map<String, Map<String, AttributePolicy>> attrPolicies
        = Maps.newLinkedHashMap(this.attrPolicies);
    for (Map.Entry<String, Map<String, AttributePolicy>> e :
         attrPolicies.entrySet()) {
      e.setValue(Maps.newLinkedHashMap(e.getValue()));
    }
    Map<String, AttributePolicy> globalAttrPolicies
        = Maps.newLinkedHashMap(this.globalAttrPolicies);
    Set<String> allowedProtocols = ImmutableSet.copyOf(this.allowedProtocols);

    // Implement requireRelNofollowOnLinks
    if (requireRelNofollowOnLinks) {
      elPolicies.put(
          "a",
          ElementPolicy.Util.join(
              elPolicies.get("a"),
              new ElementPolicy() {
                public String apply(String elementName, List<String> attrs) {
                  for (int i = 0, n = attrs.size(); i < n; i += 2) {
                    if ("href".equals(attrs.get(i))) {
                      attrs.add("rel");
                      attrs.add("nofollow");
                      break;
                    }
                  }
                  return elementName;
                }
              }));
    }

    // Implement protocol policies.
    // For each URL attribute that is allowed, we further constrain it by
    // only allowing the value through if it specifies no protocol, or if it
    // specifies one in the allowedProtocols white-list.
    // This is done regardless of whether any protocols have been allowed, so
    // allowing the attribute "href" globally with the identity policy but
    // not white-listing any protocols, effectively disallows the "href"
    // attribute globally.
    {
      AttributePolicy urlAttributePolicy;
      if (allowedProtocols.size() == 3
          && allowedProtocols.contains("mailto")
          && allowedProtocols.contains("http")
          && allowedProtocols.contains("https")) {
        urlAttributePolicy = StandardUrlAttributePolicy.INSTANCE;
      } else {
        urlAttributePolicy = new FilterUrlByProtocolAttributePolicy(
            allowedProtocols);
      }
      Set<String> toGuard = Sets.newLinkedHashSet(URL_ATTRIBUTE_NAMES);
      for (String urlAttributeName : URL_ATTRIBUTE_NAMES) {
        if (globalAttrPolicies.containsKey(urlAttributeName)) {
          toGuard.remove(urlAttributeName);
          globalAttrPolicies.put(urlAttributeName, AttributePolicy.Util.join(
              urlAttributePolicy, globalAttrPolicies.get(urlAttributeName)));
        }
      }
      // Implement guards not implemented on global policies in the per-element
      // policy maps.
      for (Map.Entry<String, Map<String, AttributePolicy>> e
           : attrPolicies.entrySet()) {
        Map<String, AttributePolicy> policies = e.getValue();
        for (String urlAttributeName : toGuard) {
          if (policies.containsKey(urlAttributeName)) {
            policies.put(urlAttributeName, AttributePolicy.Util.join(
                urlAttributePolicy, policies.get(urlAttributeName)));
          }
        }
      }
    }

    ImmutableMap.Builder<String, ElementAndAttributePolicies> policiesBuilder
        = ImmutableMap.builder();
    for (Map.Entry<String, ElementPolicy> e : elPolicies.entrySet()) {
      String elementName = e.getKey();
      ElementPolicy elPolicy = e.getValue();
      if (ElementPolicy.REJECT_ALL_ELEMENT_POLICY.equals(elPolicy)) {
        continue;
      }

      Map<String, AttributePolicy> elAttrPolicies
          = attrPolicies.get(elementName);
      if (elAttrPolicies == null) { elAttrPolicies = ImmutableMap.of(); }
      ImmutableMap.Builder<String, AttributePolicy> attrs
          = ImmutableMap.builder();
      for (Map.Entry<String, AttributePolicy> ape : elAttrPolicies.entrySet()) {
        String attributeName = ape.getKey();
        if (globalAttrPolicies.containsKey(attributeName)) { continue; }
        AttributePolicy policy = ape.getValue();
        if (!AttributePolicy.REJECT_ALL_ATTRIBUTE_POLICY.equals(policy)) {
          attrs.put(attributeName, policy);
        }
      }
      for (Map.Entry<String, AttributePolicy> ape
           : globalAttrPolicies.entrySet()) {
        String attributeName = ape.getKey();
        AttributePolicy policy = AttributePolicy.Util.join(
            elAttrPolicies.get(attributeName), ape.getValue());
        if (!AttributePolicy.REJECT_ALL_ATTRIBUTE_POLICY.equals(policy)) {
          attrs.put(attributeName, policy);
        }
      }

      policiesBuilder.put(
          elementName,
          new ElementAndAttributePolicies(
              elementName,
              elPolicy, attrs.build(), skipIfEmpty.contains(elementName)));
    }
    return compiledPolicies = policiesBuilder.build();
  }
}

final class Factory
    implements Function<HtmlStreamEventReceiver, HtmlSanitizer.Policy> {
  private final ImmutableMap<String, ElementAndAttributePolicies> policies;
  private final boolean allowStyling;

  Factory(
      ImmutableMap<String, ElementAndAttributePolicies> policies,
      boolean allowStyling) {
    this.policies = policies;
    this.allowStyling = allowStyling;
  }

  public HtmlSanitizer.Policy apply(HtmlStreamEventReceiver out) {
    if (allowStyling) {
      return new StylingPolicy(out, policies);
    } else {
      return new ElementAndAttributePolicyBasedSanitizerPolicy(
          out, policies);
    }
  }
}
