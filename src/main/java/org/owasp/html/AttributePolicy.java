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

import com.google.common.collect.ImmutableList;
import java.util.Collection;
import java.util.Set;
import java.util.LinkedHashSet;
import javax.annotation.CheckReturnValue;
import javax.annotation.Nullable;
import javax.annotation.concurrent.Immutable;

/**
 * A policy that can be applied to an HTML attribute to decide whether or not to
 * allow it in the output, possibly after transforming its value.
 *
 * @author Mike Samuel (mikesamuel@gmail.com)
 * @see HtmlPolicyBuilder.AttributeBuilder#matching(AttributePolicy)
 */
@TCB public interface AttributePolicy {

  /**
   * @param elementName the lower-case element name.
   * @param attributeName the lower-case attribute name.
   * @param value the attribute value without quotes and with HTML entities
   *     decoded.
   *
   * @return {@code null} to disallow the attribute or the adjusted value if
   *     allowed.
   */
  public @Nullable String apply(
      String elementName, String attributeName, String value);


  /** Utilities for working with attribute policies. */
  public static final class Util {

    /**
     * An attribute policy equivalent to applying all the given policies in
     * order, failing early if any of them fails.
     */
    @CheckReturnValue
    public static final AttributePolicy join(AttributePolicy... policies) {
      Set<AttributePolicy> uniq = new LinkedHashSet<AttributePolicy>();
      for (AttributePolicy p : policies) {
        if (p instanceof JoinedAttributePolicy) {
          uniq.addAll(((JoinedAttributePolicy) p).policies);
        } else if (p != null) {
          uniq.add(p);
        }
      }

      if (uniq.contains(REJECT_ALL_ATTRIBUTE_POLICY)) {
        return REJECT_ALL_ATTRIBUTE_POLICY;
      }
      uniq.remove(IDENTITY_ATTRIBUTE_POLICY);
      switch (uniq.size()) {
        case 0:  return IDENTITY_ATTRIBUTE_POLICY;
        case 1:  return uniq.iterator().next();
        default: return new JoinedAttributePolicy(uniq);
      }
    }
  }

  /** An attribute policy that returns the value unchanged. */
  public static final AttributePolicy IDENTITY_ATTRIBUTE_POLICY
      = new AttributePolicy() {
        public String apply(
            String elementName, String attributeName, String value) {
          return value;
        }
      };

  /** An attribute policy that rejects all values. */
  public static final AttributePolicy REJECT_ALL_ATTRIBUTE_POLICY
      = new AttributePolicy() {
        public @Nullable String apply(
            String elementName, String attributeName, String value) {
          return null;
        }
      };

}

@Immutable
final class JoinedAttributePolicy implements AttributePolicy {
  final ImmutableList<AttributePolicy> policies;

  JoinedAttributePolicy(Collection<? extends AttributePolicy> policies) {
    this.policies = ImmutableList.copyOf(policies);
  }

  public @Nullable String apply(
      String elementName, String attributeName, @Nullable String rawValue) {
    String value = rawValue;
    for (AttributePolicy p : policies) {
      if (value == null) { break; }
      value = p.apply(elementName, attributeName, value);
    }
    return value;
  }

  @Override
  public boolean equals(Object o) {
    return o != null && this.getClass() == o.getClass()
        && policies.equals(((JoinedAttributePolicy) o).policies);
  }

  @Override
  public int hashCode() {
    return policies.hashCode();
  }
}
