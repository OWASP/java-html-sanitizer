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

import javax.annotation.Nullable;

import com.google.common.base.Function;
import com.google.common.collect.ImmutableMap;

/**
 * A factory that can be used to link a sanitizer to an output receiver and that
 * provides a convenient <code>{@link PolicyFactory#sanitize sanitize}</code>
 * method and a <code>{@link PolicyFactory#and and}</code> method to compose
 * policies.
 *
 * @author Mike Samuel <mikesamuel@gmail.com>
 */
public final class PolicyFactory
    implements Function<HtmlStreamEventReceiver, HtmlSanitizer.Policy> {

  private final ImmutableMap<String, ElementAndAttributePolicies> policies;
  private final boolean allowStyling;

  PolicyFactory(ImmutableMap<String, ElementAndAttributePolicies> policies,
          boolean allowStyling) {
    this.policies = policies;
    this.allowStyling = allowStyling;
  }

  /** Produces a sanitizer that emits tokens to out. */
  public HtmlSanitizer.Policy apply(HtmlStreamEventReceiver out) {
    if (allowStyling) {
      return new StylingPolicy(out, policies);
    } else {
      return new ElementAndAttributePolicyBasedSanitizerPolicy(
          out, policies);
    }
  }

  /** A convenience function that sanitizes a string of HTML. */
  public String sanitize(@Nullable String html) {
    if (html == null) { return ""; }
    StringBuilder out = new StringBuilder(html.length());
    HtmlSanitizer.sanitize(
        html, apply(HtmlStreamRenderer.create(out, Handler.DO_NOTHING)));
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
    for (Map.Entry<String, ElementAndAttributePolicies> e
        : policies.entrySet()) {
      String elName = e.getKey();
      ElementAndAttributePolicies p = e.getValue();
      ElementAndAttributePolicies q = f.policies.get(elName);
      if (q != null) {
        p = p.and(q);
      }
      b.put(elName, p);
    }
    for (Map.Entry<String, ElementAndAttributePolicies> e
        : f.policies.entrySet()) {
      String elName = e.getKey();
      if (!policies.containsKey(elName)) {
        b.put(elName, e.getValue());
      }
    }
    return new PolicyFactory(b.build(), allowStyling || f.allowStyling);
  }
}
