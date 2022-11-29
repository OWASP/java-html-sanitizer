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

import com.google.common.base.Optional;
import com.google.common.collect.ImmutableList;

import java.util.Set;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nullable;

import org.owasp.html.Joinable.JoinHelper;

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
      AttributePolicyJoiner joiner = new AttributePolicyJoiner();

      for (AttributePolicy p : policies) {
        if (p != null) {
          joiner.unroll(p);
        }
      }

      return joiner.join();
    }

    static final class AttributePolicyJoiner
    extends JoinHelper<AttributePolicy, JoinableAttributePolicy> {

      AttributePolicyJoiner() {
        super(AttributePolicy.class,
            JoinableAttributePolicy.class,
            REJECT_ALL_ATTRIBUTE_POLICY,
            IDENTITY_ATTRIBUTE_POLICY);
      }

      @Override
      Optional<ImmutableList<AttributePolicy>> split(AttributePolicy x) {
        if (x instanceof JoinedAttributePolicy) {
          return Optional.of(((JoinedAttributePolicy) x).policies);
        } else {
          return Optional.absent();
        }
      }

      @Override
      AttributePolicy rejoin(Set<? extends AttributePolicy> xs) {
        return new JoinedAttributePolicy(xs);
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

  /** An attribute policy that is joinable. */
  static interface JoinableAttributePolicy
  extends AttributePolicy, Joinable<JoinableAttributePolicy> {
    // Parameterized Appropriately.
  }
}
