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

import java.util.Map;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.ThreadSafe;

import com.google.common.base.Function;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;

/**
 * A factory that can be used to link a sanitizer to an output receiver and that
 * provides a convenient <code>{@link PolicyFactory#sanitize sanitize}</code>
 * method and a <code>{@link PolicyFactory#and and}</code> method to compose
 * policies.
 *
 * @author Mike Samuel (mikesamuel@gmail.com)
 */
@ThreadSafe
@Immutable
@TCB
public final class PolicyFactory
    implements Function<HtmlStreamEventReceiver, HtmlSanitizer.Policy> {

  private final ImmutableMap<String, ElementAndAttributePolicies> policies;
  private final ImmutableMap<String, AttributePolicy> globalAttrPolicies;
  private final ImmutableSet<String> textContainers;

  PolicyFactory(
      ImmutableMap<String, ElementAndAttributePolicies> policies,
      ImmutableSet<String> textContainers,
      ImmutableMap<String, AttributePolicy> globalAttrPolicies) {
    this.policies = policies;
    this.textContainers = textContainers;
    this.globalAttrPolicies = globalAttrPolicies;
  }

  /** Produces a sanitizer that emits tokens to {@code out}. */
  public HtmlSanitizer.Policy apply(@Nonnull HtmlStreamEventReceiver out) {
    return new ElementAndAttributePolicyBasedSanitizerPolicy(
        out, policies, textContainers);
  }

  /**
   * Produces a sanitizer that emits tokens to {@code out} and that notifies
   * any {@code listener} of any dropped tags and attributes.
   * @param out a renderer that receives approved tokens only.
   * @param listener if non-null, receives notifications of tags and attributes
   *     that were rejected by the policy.  This may tie into intrusion
   *     detection systems.
   * @param context if {@code (listener != null)} then the context value passed
   *     with notifications.  This can be used to let the listener know from
   *     which connection or request the questionable HTML was received.
   */
  public <CTX> HtmlSanitizer.Policy apply(
      HtmlStreamEventReceiver out, @Nullable HtmlChangeListener<CTX> listener,
      @Nullable CTX context) {
    if (listener == null) {
      return apply(out);
    } else {
      HtmlChangeReporter<CTX> r = new HtmlChangeReporter<CTX>(
          out, listener, context);
      r.setPolicy(apply(r.getWrappedRenderer()));
      return r.getWrappedPolicy();
    }
  }

  /** A convenience function that sanitizes a string of HTML. */
  public String sanitize(@Nullable String html) {
    return sanitize(html, null, null);
  }

  /**
   * A convenience function that sanitizes a string of HTML and reports
   * the names of rejected element and attributes to listener.
   * @param html the string of HTML to sanitize.
   * @param listener if non-null, receives notifications of tags and attributes
   *     that were rejected by the policy.  This may tie into intrusion
   *     detection systems.
   * @param context if {@code (listener != null)} then the context value passed
   *     with notifications.  This can be used to let the listener know from
   *     which connection or request the questionable HTML was received.
   * @return a string of HTML that complies with this factory's policy.
   */
  public <CTX> String sanitize(
      @Nullable String html,
      @Nullable HtmlChangeListener<CTX> listener, @Nullable CTX context) {
    if (html == null) { return ""; }
    StringBuilder out = new StringBuilder(html.length());
    HtmlSanitizer.sanitize(
        html,
        apply(HtmlStreamRenderer.create(out, Handler.DO_NOTHING),
              listener, context));
    return out.toString();
  }

  /**
   * Produces a factory that allows the union of the grants, and intersects
   * policies where they overlap on a particular granted attribute or element
   * name.
   */
  public PolicyFactory and(PolicyFactory f) {
    ImmutableMap.Builder<String, ElementAndAttributePolicies> b
        = ImmutableMap.builder();
    // Merge this and f into a map of element names to attribute policies.
    for (Map.Entry<String, ElementAndAttributePolicies> e
        : policies.entrySet()) {
      String elName = e.getKey();
      ElementAndAttributePolicies p = e.getValue();
      ElementAndAttributePolicies q = f.policies.get(elName);
      if (q != null) {
        p = p.and(q);
      } else {
        // Mix in any globals that are not already taken into account in this.
        p = p.andGlobals(f.globalAttrPolicies);
      }
      b.put(elName, p);
    }
    // Handle keys that are in f but not in this.
    for (Map.Entry<String, ElementAndAttributePolicies> e
        : f.policies.entrySet()) {
      String elName = e.getKey();
      if (!policies.containsKey(elName)) {
        ElementAndAttributePolicies p = e.getValue();
        // Mix in any globals that are not already taken into account in this.
        p = p.andGlobals(globalAttrPolicies);
        b.put(elName, p);
      }
    }
    ImmutableSet<String> allTextContainers;
    if (this.textContainers.containsAll(f.textContainers)) {
      allTextContainers = this.textContainers;
    } else if (f.textContainers.containsAll(this.textContainers)) {
      allTextContainers = f.textContainers;
    } else {
      allTextContainers = ImmutableSet.<String>builder()
        .addAll(this.textContainers)
        .addAll(f.textContainers)
        .build();
    }
    ImmutableMap<String, AttributePolicy> allGlobalAttrPolicies;
    if (f.globalAttrPolicies.isEmpty()) {
      allGlobalAttrPolicies = this.globalAttrPolicies;
    } else if (this.globalAttrPolicies.isEmpty()) {
      allGlobalAttrPolicies = f.globalAttrPolicies;
    } else {
      ImmutableMap.Builder<String, AttributePolicy> ab = ImmutableMap.builder();
      for (Map.Entry<String, AttributePolicy> e
          : this.globalAttrPolicies.entrySet()) {
        String attrName = e.getKey();
        ab.put(
            attrName,
            AttributePolicy.Util.join(
                e.getValue(), f.globalAttrPolicies.get(attrName)));
      }
      for (Map.Entry<String, AttributePolicy> e
          : f.globalAttrPolicies.entrySet()) {
        String attrName = e.getKey();
        if (!this.globalAttrPolicies.containsKey(attrName)) {
          ab.put(attrName, e.getValue());
        }
      }
      allGlobalAttrPolicies = ab.build();
    }
    return new PolicyFactory(b.build(), allTextContainers, allGlobalAttrPolicies);
  }
}
