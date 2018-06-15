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

import java.util.Collections;
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
   * @deprecated prefer {@link V2#apply(String, String, String, Context)}
   */
  @Deprecated
  public @Nullable String apply(
      String elementName, String attributeName, String value);


  /**
   * Extends AttributePolicy that receives the embedding document context.
   */
  public interface V2 extends AttributePolicy {
    /**
     * @param elementName the lower-case element name.
     * @param attributeName the lower-case attribute name.
     * @param value the attribute value without quotes and with HTML entities
     *     decoded.
     * @param context about the document in which the sanitized attribute will
     *     be embedded.
     *
     * @return {@code null} to disallow the attribute or the adjusted value if
     *     allowed.
     */
    public @Nullable String apply(
        String elementName, String attributeName, String value,
        Context context);
  }


  /** Utilities for working with attribute policies. */
  public static final class Util {

    static Iterable<AttributePolicy.V2> unjoin(AttributePolicy.V2 p) {
      if (p instanceof JoinedAttributePolicy) {
        return ((JoinedAttributePolicy) p).policies;
      } else {
        return Collections.singleton(p);
      }
    }

    /** Adapts an old-style attribute policy to the new interface. */
    public static V2 adapt(AttributePolicy p) {
      if (p instanceof V2) {
        return (V2) p;
      }
      return new AttributePolicyAdapter(p);
    }

    /**
     * An attribute policy equivalent to applying all the given policies in
     * order, failing early if any of them fails.
     */
    @CheckReturnValue
    public static final AttributePolicy.V2 join(AttributePolicy... policies) {
      AttributePolicyJoiner joiner = new AttributePolicyJoiner();

      for (AttributePolicy p : policies) {
        if (p != null) {
          joiner.unroll(adapt(p));
        }
      }

      return joiner.join();
    }

    static final class AttributePolicyJoiner
    extends JoinHelper<AttributePolicy.V2, JoinableAttributePolicy> {

      AttributePolicyJoiner() {
        super(AttributePolicy.V2.class,
            JoinableAttributePolicy.class,
            REJECT_ALL_ATTRIBUTE_POLICY,
            IDENTITY_ATTRIBUTE_POLICY);
      }

      @Override
      Optional<ImmutableList<AttributePolicy.V2>> split(AttributePolicy.V2 x) {
        if (x instanceof JoinedAttributePolicy) {
          return Optional.of(((JoinedAttributePolicy) x).policies);
        } else {
          return Optional.absent();
        }
      }

      @Override
      AttributePolicy.V2 rejoin(Set<? extends AttributePolicy.V2> xs) {
        return new JoinedAttributePolicy(xs);
      }

    }

    /** The old apply method forwards a null context to the V2 apply method. */
    public static abstract class AbstractV2AttributePolicy implements V2 {
      public final @Nullable String apply(
          String elementName, String attributeName, String value) {
        return apply(elementName, attributeName, value, null);
      }
    }

    static final class AttributePolicyAdapter
    extends AbstractV2AttributePolicy {

      final AttributePolicy p;

      AttributePolicyAdapter(AttributePolicy p) {
        this.p = p;
      }

      public String apply(
          String elementName, String attributeName, String value,
          Context context) {
        return p.apply(elementName, attributeName, value);
      }

    }
  }


  /** An attribute policy that returns the value unchanged. */
  public static final AttributePolicy.V2 IDENTITY_ATTRIBUTE_POLICY
      = new Util.AbstractV2AttributePolicy() {
        public String apply(
            String elementName, String attributeName, String value,
            Context context) {
          return value;
        }
      };

  /** An attribute policy that rejects all values. */
  public static final AttributePolicy.V2 REJECT_ALL_ATTRIBUTE_POLICY
      = new Util.AbstractV2AttributePolicy() {
        public @Nullable String apply(
            String elementName, String attributeName, String value,
            Context context) {
          return null;
        }
      };

  /** An attribute policy that is joinable. */
  static interface JoinableAttributePolicy
  extends AttributePolicy.V2, Joinable<JoinableAttributePolicy> {
    // Parameterized Appropriately.
  }
}
