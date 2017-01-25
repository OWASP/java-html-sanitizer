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
import java.util.regex.Pattern;

import javax.annotation.Nullable;
import javax.annotation.concurrent.NotThreadSafe;

import org.owasp.html.ElementPolicy.JoinableElementPolicy;

import com.google.common.base.Function;
import com.google.common.base.Joiner;
import com.google.common.base.Preconditions;
import com.google.common.base.Predicate;
import com.google.common.collect.ImmutableList;
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
 * processing modes; and finally call <code>build(renderer)</code> or
 * <code>toFactory()</code>.
 * </p>
 * <pre class="prettyprint lang-java">
 * // Define the policy.
 * Function&lt;HtmlStreamEventReceiver, HtmlSanitizer.Policy&gt; policy
 *     = new HtmlPolicyBuilder()
 *         .allowElements("a", "p")
 *         .allowAttributes("href").onElements("a")
 *         .toFactory();
 *
 * // Sanitize your output.
 * HtmlSanitizer.sanitize(myHtml, policy.apply(myHtmlStreamRenderer));
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
 * new HtmlPolicyBuilder()
 *   .allowElement(
 *     new ElementPolicy() {
 *       public String apply(String elementName, List&lt;String&gt; attributes){
 *         attributes.add("class");
 *         attributes.add("header-" + elementName);
 *         return "div";
 *       }
 *     },
 *     "h1", "h2", "h3", "h4", "h5", "h6")
 *   .build(outputChannel)
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
 * @author Mike Samuel (mikesamuel@gmail.com)
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

  /**
   * These
   * <a href="https://developer.mozilla.org/en-US/docs/Web/HTML/Link_types"
   * >{@code rel}</a> attribute values leaking information to the linked site,
   * and prevents the linked page from redirecting your page to a phishing site
   * when opened from a third-party link from your site.
   *
   * @see <a href="https://mathiasbynens.github.io/rel-noopener/"
   *      >About rel=noopener</a>
   */
  public static final ImmutableSet<String> DEFAULT_RELS_ON_TARGETTED_LINKS
      = ImmutableSet.of("noopener", "noreferrer");

  static final String DEFAULT_RELS_ON_TARGETTED_LINKS_STR
      = Joiner.on(' ').join(DEFAULT_RELS_ON_TARGETTED_LINKS);

  private final Map<String, ElementPolicy> elPolicies = Maps.newLinkedHashMap();
  private final Map<String, Map<String, AttributePolicy>> attrPolicies
      = Maps.newLinkedHashMap();
  private final Map<String, AttributePolicy> globalAttrPolicies
      = Maps.newLinkedHashMap();
  private final Set<String> allowedProtocols = Sets.newLinkedHashSet();
  private final Set<String> skipIfEmpty = Sets.newLinkedHashSet(
      DEFAULT_SKIP_IF_EMPTY);
  private final Map<String, Boolean> textContainers = Maps.newLinkedHashMap();
  private HtmlStreamEventProcessor postprocessor =
      HtmlStreamEventProcessor.Processors.IDENTITY;
  private HtmlStreamEventProcessor preprocessor =
      HtmlStreamEventProcessor.Processors.IDENTITY;
  private CssSchema stylingPolicySchema = null;
  private AttributePolicy styleUrlPolicy =
      AttributePolicy.REJECT_ALL_ATTRIBUTE_POLICY;
  private Set<String> extraRelsForLinks;
  private Set<String> skipRelsForLinks;

  /**
   * Allows the named elements.
   */
  public HtmlPolicyBuilder allowElements(String... elementNames) {
    return allowElements(ElementPolicy.IDENTITY_ELEMENT_POLICY, elementNames);
  }

  /**
   * Disallows the named elements.  Elements are disallowed by default, so
   * there is no need to disallow elements, unless you are making an exception
   * based on an earlier allow.
   */
  public HtmlPolicyBuilder disallowElements(String... elementNames) {
    return allowElements(ElementPolicy.REJECT_ALL_ELEMENT_POLICY, elementNames);
  }

  private static HtmlElementTables METADATA = HtmlElementTables.get();
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
      if (!textContainers.containsKey(elementName)) {
        if (METADATA.canContainPlainText(METADATA.indexForName(elementName))) {
          textContainers.put(elementName, true);
        }
      }
    }
    return this;
  }

  /**
   * A canned policy that allows a number of common formatting elements.
   */
  public HtmlPolicyBuilder allowCommonInlineFormattingElements() {
    return allowElements(
        "b", "i", "font", "s", "u", "o", "sup", "sub", "ins", "del", "strong",
        "strike", "tt", "code", "big", "small", "br", "span", "em");
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
   * Allows text content in the named elements.
   * By default, text content is allowed in any
   * {@link #allowElements allowed elements} that can contain character data per
   * the HTML5 spec, but text content is not allowed by default in elements that
   * contain content of other kinds (like JavaScript in {@code <script>}
   * elements.
   * <p>
   * To write a policy that whitelists {@code <script>} or {@code <style>}
   * elements, first {@code allowTextIn("script")}.
   */
  public HtmlPolicyBuilder allowTextIn(String... elementNames) {
    invalidateCompiledState();
    for (String elementName : elementNames) {
      elementName = HtmlLexer.canonicalName(elementName);
      textContainers.put(elementName, true);
    }
    return this;
  }

  /**
   * Disallows text in elements with the given name.
   * <p>
   * This is useful when an element contains text that is not meant to be
   * displayed to the end-user.
   * Typically these elements are styled {@code display:none} in browsers'
   * default stylesheets, or, like {@code <template>} contain text nodes that
   * are eventually for human consumption, but which are created in a separate
   * document fragment.
   */
  public HtmlPolicyBuilder disallowTextIn(String... elementNames) {
    invalidateCompiledState();
    for (String elementName : elementNames) {
      elementName = HtmlLexer.canonicalName(elementName);
      textContainers.put(elementName, false);
    }
    return this;
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
   * Returns an object that lets you associate policies with the given
   * attributes, and allow them globally or on specific elements.
   */
  public AttributeBuilder allowAttributes(String... attributeNames) {
    ImmutableList.Builder<String> b = ImmutableList.builder();
    for (String attributeName : attributeNames) {
      b.add(HtmlLexer.canonicalName(attributeName));
    }
    return new AttributeBuilder(b.build());
  }

  /**
   * Reverse an earlier attribute {@link #allowAttributes allow}.
   * <p>
   * For this to have an effect you must call at least one of
   * {@link AttributeBuilder#globally} and {@link AttributeBuilder#onElements}.
   * <p>
   * Attributes are disallowed by default, so there is no need to call this
   * with a laundry list of attribute/element pairs.
   */
  public AttributeBuilder disallowAttributes(String... attributeNames) {
    return this.allowAttributes(attributeNames)
        .matching(AttributePolicy.REJECT_ALL_ATTRIBUTE_POLICY);
  }


  private HtmlPolicyBuilder allowAttributesGlobally(
      AttributePolicy policy, List<String> attributeNames) {
    invalidateCompiledState();
    for (String attributeName : attributeNames) {
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

  private HtmlPolicyBuilder allowAttributesOnElements(
      AttributePolicy policy, List<String> attributeNames,
      List<String> elementNames) {
    invalidateCompiledState();
    for (String elementName : elementNames) {
      Map<String, AttributePolicy> policies = attrPolicies.get(elementName);
      if (policies == null) {
        policies = Maps.newLinkedHashMap();
        attrPolicies.put(elementName, policies);
      }
      for (String attributeName : attributeNames) {
        AttributePolicy oldPolicy = policies.get(attributeName);
        policies.put(
            attributeName,
            AttributePolicy.Util.join(oldPolicy, policy));
      }
    }
    return this;
  }

  /**
   * Adds
   * <a href="https://developer.mozilla.org/en-US/docs/Web/HTML/Link_types"
   * >{@code rel=nofollow}</a>
   * to links.
   *
   * @see #DEFAULT_RELS_ON_TARGETTED_LINKS
   * @see #skipRelsOnLinks
   */
  public HtmlPolicyBuilder requireRelNofollowOnLinks() {
    return requireRelsOnLinks("nofollow");
  }

  /**
   * Adds
   * <a href="https://developer.mozilla.org/en-US/docs/Web/HTML/Link_types"
   * >{@code rel="..."}</a> to {@code <a href="...">} tags beyond those in
   * {@link #DEFAULT_RELS_ON_TARGETTED_LINKS}.
   * <p>
   * @see #skipRelsOnLinks
   */
  public HtmlPolicyBuilder requireRelsOnLinks(String... linkValues) {
    this.invalidateCompiledState();
    if (this.extraRelsForLinks == null) {
      this.extraRelsForLinks = Sets.newLinkedHashSet();
    }
    for (String linkValue : linkValues) {
      linkValue = HtmlLexer.canonicalName(linkValue);
      Preconditions.checkArgument(
          !Strings.containsHtmlSpace(linkValue),
          "spaces in input.  use f(\"foo\", \"bar\") not f(\"foo bar\")");
      this.extraRelsForLinks.add(linkValue);
    }
    if (this.skipRelsForLinks != null) {
      this.skipRelsForLinks.removeAll(this.extraRelsForLinks);
    }
    return this;
  }

  /**
   * Opts out of some of the {@link #DEFAULT_RELS_ON_TARGETTED_LINKS} from being added
   * to links, and reverses pre
   *
   * @see #requireRelsOnLinks
   */
  public HtmlPolicyBuilder skipRelsOnLinks(String... linkValues) {
    this.invalidateCompiledState();
    if (this.skipRelsForLinks == null) {
      this.skipRelsForLinks = Sets.newLinkedHashSet();
    }
    for (String linkValue : linkValues) {
      linkValue = HtmlLexer.canonicalName(linkValue);
      Preconditions.checkArgument(
          !Strings.containsHtmlSpace(linkValue),
          "spaces in input.  use f(\"foo\", \"bar\") not f(\"foo bar\")");
      this.skipRelsForLinks.add(linkValue);
    }
    if (this.extraRelsForLinks != null) {
      this.extraRelsForLinks.removeAll(this.skipRelsForLinks);
    }
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
   * Convert <code>style="&lt;CSS&gt;"</code> to sanitized CSS which allows
   * color, font-size, type-face, and other styling using the default schema;
   * but which does not allow content to escape its clipping context.
   */
  public HtmlPolicyBuilder allowStyling() {
    allowStyling(CssSchema.DEFAULT);
    return this;
  }

  /**
   * Convert <code>style="&lt;CSS&gt;"</code> to sanitized CSS which allows
   * color, font-size, type-face, and other styling using the given schema.
   */
  public HtmlPolicyBuilder allowStyling(CssSchema whitelist) {
    invalidateCompiledState();

    // Allow the style attribute, and then we will fix it up later.  This allows
    // us to attach the final URL policy to the style attribute policy, while
    // still not allowing styles when allowStyling is followed by a call to
    // disallowAttributesGlobally("style").
    this.allowAttributesGlobally(
        AttributePolicy.IDENTITY_ATTRIBUTE_POLICY, ImmutableList.of("style"));

    this.stylingPolicySchema =
        this.stylingPolicySchema == null
        ? whitelist
        : CssSchema.union(stylingPolicySchema, whitelist);
    return this;
  }

  /**
   * Allow URLs in CSS styles.
   * For example,
   * {@code <span style="background-image: url(http://example.com/image.png)">}.
   * <p>
   * URLs in CSS are typically loaded without user-interaction, the way links
   * are, so a greater degree of scrutiny is warranted.
   *
   * @param newStyleUrlPolicy receives URLs from the CSS that pass the allowed
   *     protocol policies, and may return null to veto the URL or the URL
   *     to use.  URLs will be reported as content in {@code <img src=...>}.
   */
  public HtmlPolicyBuilder allowUrlsInStyles(
      AttributePolicy newStyleUrlPolicy) {
    this.invalidateCompiledState();
    this.styleUrlPolicy = newStyleUrlPolicy;
    return this;
  }

  /**
   * Inserts a pre-processor into the pipeline between the lexer and the policy.
   * Pre-processors receive HTML events before the policy, so the policy will
   * be applied to anything they add.
   * Pre-processors are not in the TCB since they cannot bypass the policy.
   */
  public HtmlPolicyBuilder withPreprocessor(HtmlStreamEventProcessor pp) {
    this.preprocessor = HtmlStreamEventProcessor.Processors.compose(
        this.preprocessor, pp);
    return this;
  }

  /**
   * Inserts a post-processor into the pipeline between the policy and the
   * output sink.
   * Post-processors can insert events into the stream that are not vetted
   * by the policy, so they are in the TCB.
   * <p>
   * Try doing what you want with a pre-processor instead of a post-processor
   * but if you're thinking of doing search/replace on a sanitized string, then
   * definitely use either a pre or post-processor instead.
   */
  public HtmlPolicyBuilder withPostprocessor(HtmlStreamEventProcessor pp) {
    this.postprocessor = HtmlStreamEventProcessor.Processors.compose(
        this.postprocessor, pp);
    return this;
  }

  /**
   * Names of attributes from HTML 4 whose values are URLs.
   * Other attributes, e.g. <code>style</code> may contain URLs even though
   * there values are not URLs.
   */
  private static final Set<String> URL_ATTRIBUTE_NAMES = ImmutableSet.of(
      "action", "archive", "background", "cite", "classid", "codebase", "data",
      "dsync", "formaction", "href", "icon", "longdesc", "manifest", "poster",
      "profile", "src", "srcset", "usemap");

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
   * Produces a policy based on the allow and disallow calls previously made.
   *
   * @param out receives calls to open only tags allowed by
   *      previous calls to this object.
   *      Typically a {@link HtmlStreamRenderer}.
   * @param listener is notified of dropped tags and attributes so that
   *      intrusion detection systems can be alerted to questionable HTML.
   *      If {@code null} then no notifications are sent.
   * @param context if {@code (listener != null)} then the context value passed
   *      with alerts.  This can be used to let the listener know from which
   *      connection or request the questionable HTML was received.
   */
  public <CTX> HtmlSanitizer.Policy build(
      HtmlStreamEventReceiver out,
      @Nullable HtmlChangeListener<? super CTX> listener,
      @Nullable CTX context) {
    return toFactory().apply(out, listener, context);
  }

  /**
   * Like {@link #build} but can be reused to create many different policies
   * each backed by a different output channel.
   */
  public PolicyFactory toFactory() {
    ImmutableSet.Builder<String> textContainerSet = ImmutableSet.builder();
    for (Map.Entry<String, Boolean> textContainer
         : this.textContainers.entrySet()) {
      if (Boolean.TRUE.equals(textContainer.getValue())) {
        textContainerSet.add(textContainer.getKey());
      }
    }
    return new PolicyFactory(compilePolicies(), textContainerSet.build(),
                             ImmutableMap.copyOf(globalAttrPolicies),
                             preprocessor, postprocessor);
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
    @SuppressWarnings("hiding")
    Map<String, ElementPolicy> elPolicies
        = Maps.newLinkedHashMap(this.elPolicies);
    @SuppressWarnings("hiding")
    Map<String, Map<String, AttributePolicy>> attrPolicies
        = Maps.newLinkedHashMap(this.attrPolicies);
    for (Map.Entry<String, Map<String, AttributePolicy>> e :
         attrPolicies.entrySet()) {
      e.setValue(Maps.newLinkedHashMap(e.getValue()));
    }
    @SuppressWarnings("hiding")
    Map<String, AttributePolicy> globalAttrPolicies
        = Maps.newLinkedHashMap(this.globalAttrPolicies);
    @SuppressWarnings("hiding")
    Set<String> allowedProtocols = ImmutableSet.copyOf(this.allowedProtocols);

    // Implement requireRelsOnLinks & skip...
    {
      ElementPolicy linkPolicy = elPolicies.get("a");
      if (linkPolicy != null) {
        RelsOnLinksPolicy relsOnLinksPolicy = RelsOnLinksPolicy.create(
            this.extraRelsForLinks != null
            ? this.extraRelsForLinks : ImmutableSet.<String>of(),
            this.skipRelsForLinks != null
            ? this.skipRelsForLinks : ImmutableSet.<String>of());
        elPolicies.put(
            "a",
            ElementPolicy.Util.join(linkPolicy, relsOnLinksPolicy));
      }
    }

    // Implement protocol policies.
    // For each URL attribute that is allowed, we further constrain it by
    // only allowing the value through if it specifies no protocol, or if it
    // specifies one in the allowedProtocols white-list.
    // This is done regardless of whether any protocols have been allowed, so
    // allowing the attribute "href" globally with the identity policy but
    // not white-listing any protocols, effectively disallows the "href"
    // attribute globally.
    StylingPolicy stylingPolicy = null;
    {
      final AttributePolicy urlAttributePolicy;
      if (allowedProtocols.size() == 3
          && allowedProtocols.contains("mailto")
          && allowedProtocols.contains("http")
          && allowedProtocols.contains("https")) {
        urlAttributePolicy = StandardUrlAttributePolicy.INSTANCE;
      } else {
        urlAttributePolicy = new FilterUrlByProtocolAttributePolicy(
            allowedProtocols);
      }

      if (this.stylingPolicySchema != null) {
        final AttributePolicy styleUrlPolicyFinal = AttributePolicy.Util.join(
            styleUrlPolicy, urlAttributePolicy);
        stylingPolicy = new StylingPolicy(
            stylingPolicySchema,
            new Function<String, String>() {
              public String apply(String url) {
                return styleUrlPolicyFinal.apply("img", "src", url);
              }
            });
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
        // Handle below so we don't end up putting the same key into the map
        // twice.  ImmutableMap.Builder hates that.
        if (globalAttrPolicies.containsKey(attributeName)) { continue; }
        AttributePolicy policy = ape.getValue();
        if ("style".equals(attributeName)) {
          policy = AttributePolicy.Util.join(policy, stylingPolicy);
        }
        if (!AttributePolicy.REJECT_ALL_ATTRIBUTE_POLICY.equals(policy)) {
          attrs.put(attributeName, policy);
        }
      }
      for (Map.Entry<String, AttributePolicy> ape
           : globalAttrPolicies.entrySet()) {
        String attributeName = ape.getKey();
        AttributePolicy policy = AttributePolicy.Util.join(
            elAttrPolicies.get(attributeName), ape.getValue());
        if ("style".equals(attributeName)) {
          policy = AttributePolicy.Util.join(policy, stylingPolicy);
        }
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

  /**
   * Builds the relationship between attributes, the values that they may have,
   * and the elements on which they may appear.
   *
   * @author Mike Samuel
   */
  public final class AttributeBuilder {
    private final List<String> attributeNames;
    private AttributePolicy policy = AttributePolicy.IDENTITY_ATTRIBUTE_POLICY;

    AttributeBuilder(List<? extends String> attributeNames) {
      this.attributeNames = ImmutableList.copyOf(attributeNames);
    }

    /**
     * Filters and/or transforms the attribute values
     * allowed by later {@code allow*} calls.
     * Multiple calls to {@code matching} are combined so that the policies
     * receive the value in order, each seeing the value after any
     * transformation by a previous policy.
     */
    public AttributeBuilder matching(AttributePolicy attrPolicy) {
      this.policy = AttributePolicy.Util.join(this.policy, attrPolicy);
      return this;
    }

    /**
     * Restrict the values allowed by later {@code allow*} calls to those
     * matching the pattern.
     * Multiple calls to {@code matching} are combined to restrict to the
     * intersection of possible matched values.
     */
    public AttributeBuilder matching(final Pattern pattern) {
      return matching(new AttributePolicy() {
        public @Nullable String apply(
            String elementName, String attributeName, String value) {
          return pattern.matcher(value).matches() ? value : null;
        }
      });
    }

    /**
     * Restrict the values allowed by later {@code allow*} calls to those
     * matching the given predicate.
     * Multiple calls to {@code matching} are combined to restrict to the
     * intersection of possible matched values.
     */
    public AttributeBuilder matching(
        final Predicate<? super String> filter) {
      return matching(new AttributePolicy() {
        public @Nullable String apply(
            String elementName, String attributeName, String value) {
          return filter.apply(value) ? value : null;
        }
      });
    }

    /**
     * Restrict the values allowed by later {@code allow*} calls to those
     * supplied.
     * Multiple calls to {@code matching} are combined to restrict to the
     * intersection of possible matched values.
     */
    public AttributeBuilder matching(
        boolean ignoreCase, String... allowedValues) {
      return matching(ignoreCase, ImmutableSet.copyOf(allowedValues));
    }

    /**
     * Restrict the values allowed by later {@code allow*} calls to those
     * supplied.
     * Multiple calls to {@code matching} are combined to restrict to the
     * intersection of possible matched values.
     */
    public AttributeBuilder matching(
        final boolean ignoreCase, Set<? extends String> allowedValues) {
      final ImmutableSet<String> allowed = ImmutableSet.copyOf(allowedValues);
      return matching(new AttributePolicy() {
        public @Nullable String apply(
            String elementName, String attributeName, String uncanonValue) {
          String value = ignoreCase
              ? Strings.toLowerCase(uncanonValue)
              : uncanonValue;
          return allowed.contains(value) ? value : null;
        }
      });
    }

    /**
     * Allows the given attributes on any elements but filters the
     * attributes' values based on previous calls to {@code matching(...)}.
     * Global attribute policies are applied after element specific policies.
     * Be careful of using this with attributes like <code>type</code> which
     * have different meanings on different attributes.
     * Also be careful of allowing globally attributes like <code>href</code>
     * which can have more far-reaching effects on tags like
     * <code>&lt;base&gt;</code> and <code>&lt;link&gt;</code> than on
     * <code>&lt;a&gt;</code> because in the former, they have an effect without
     * user interaction and can change the behavior of the current page.
     */
    @SuppressWarnings("synthetic-access")
    public HtmlPolicyBuilder globally() {
      return HtmlPolicyBuilder.this.allowAttributesGlobally(
          policy, attributeNames);
    }

    /**
     * Allows the named attributes on the given elements but filters the
     * attributes' values based on previous calls to {@code matching(...)}.
     */
    @SuppressWarnings("synthetic-access")
    public HtmlPolicyBuilder onElements(String... elementNames) {
      ImmutableList.Builder<String> b = ImmutableList.builder();
      for (String elementName : elementNames) {
        b.add(HtmlLexer.canonicalName(elementName));
      }
      return HtmlPolicyBuilder.this.allowAttributesOnElements(
          policy, attributeNames, b.build());
    }
  }


  private static final class RelsOnLinksPolicy
      implements ElementPolicy.JoinableElementPolicy {
    final ImmutableSet<String> extra;
    final ImmutableSet<String> skip;
    final ImmutableSet<String> whenTargetPresent;

    static final RelsOnLinksPolicy EMPTY = new RelsOnLinksPolicy(
        ImmutableSet.<String>of(), ImmutableSet.<String>of());

    static RelsOnLinksPolicy create(
        Set<? extends String> extra,
        Set<? extends String> skip) {
      if (extra.isEmpty() && skip.isEmpty()) { return EMPTY; }
      return new RelsOnLinksPolicy(extra, skip);
    }

    RelsOnLinksPolicy(
        Set<? extends String> extra,
        Set<? extends String> skip) {
      this.extra = ImmutableSet.copyOf(extra);
      this.skip = ImmutableSet.copyOf(skip);
      Set<String> targetOnly = Sets.newLinkedHashSet();
      targetOnly.addAll(DEFAULT_RELS_ON_TARGETTED_LINKS);
      targetOnly.removeAll(extra);
      targetOnly.removeAll(skip);
      this.whenTargetPresent = ImmutableSet.copyOf(targetOnly);
    }

    private static int indexOfAttributeValue(
        String canonAttrName, List<String> attrs) {
      for (int i = 0, n = attrs.size(); i < n; i += 2) {
        if (canonAttrName.equals(attrs.get(i))) {
          return i + 1;
        }
      }
      return -1;
    }

    public String apply(String elementName, List<String> attrs) {
      if (indexOfAttributeValue("href", attrs) >= 0) {
        // It's a link.
        boolean hasTarget = indexOfAttributeValue("target", attrs) >= 0;
        if (hasTarget || !extra.isEmpty()) {
          int relIndex = indexOfAttributeValue("rel", attrs);
          String relValue;
          if (relIndex < 0 && hasTarget && extra.isEmpty() && skip.isEmpty()) {
            relValue = DEFAULT_RELS_ON_TARGETTED_LINKS_STR;
          } else {
            StringBuilder sb = new StringBuilder();
            if (relIndex >= 0) {
              sb.append(attrs.get(relIndex)).append(' ');
            }
            for (String s : extra) {
              sb.append(s).append(' ');
            }
            if (hasTarget) {
              for (String s : whenTargetPresent) {
                sb.append(s).append(' ');
              }
            }
            relValue = sb.substring(0, sb.length() - 1);
          }
          if (relIndex < 0) {
            attrs.add("rel");
            attrs.add(relValue);
          } else {
            attrs.set(relIndex, relValue);
          }
        }
      }
      return elementName;
    }

    public Joinable.JoinStrategy<JoinableElementPolicy>
    getJoinStrategy() {
      return JoinRelsOnLinksPolicies.INSTANCE;
    }
  }

  static final class JoinRelsOnLinksPolicies
  implements Joinable.JoinStrategy<JoinableElementPolicy> {

    static final JoinRelsOnLinksPolicies INSTANCE
        = new JoinRelsOnLinksPolicies();

    public JoinableElementPolicy join(
        Iterable<? extends JoinableElementPolicy> toJoin) {
      Set<String> extra = Sets.newLinkedHashSet();
      Set<String> skip = Sets.newLinkedHashSet();
      for (JoinableElementPolicy ep : toJoin) {
        RelsOnLinksPolicy p = (RelsOnLinksPolicy) ep;
        extra.addAll(p.extra);
        skip.addAll(p.skip);
      }
      extra.removeAll(skip);
      return RelsOnLinksPolicy.create(extra, skip);
    }
  }
}

