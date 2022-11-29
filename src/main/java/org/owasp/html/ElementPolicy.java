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
import java.util.Set;

import javax.annotation.Nullable;
import javax.annotation.concurrent.Immutable;

import org.owasp.html.Joinable.JoinHelper;

import com.google.common.base.Optional;
import com.google.common.collect.ImmutableList;

/**
 * A policy that can be applied to an element to decide whether or not to
 * allow it in the output, possibly after transforming attributes.
 * <p>
 * Element policies are applied <strong>after</strong>
 * {@link AttributePolicy attribute policies} so
 * they can be used to add extra attributes.
 *
 * @author Mike Samuel (mikesamuel@gmail.com)
 * @see HtmlPolicyBuilder#allowElements(ElementPolicy, String...)
 */
@TCB public interface ElementPolicy {
  /**
   * @param elementName the lower-case element name.
   * @param attrs a list of alternating attribute names and values.
   *    The list may be added to or removed from.  When removing, be
   *    careful to remove both the name and its associated value.
   *
   * @return {@code null} to disallow the element, or the adjusted element name.
   */
  public @Nullable String apply(String elementName, List<String> attrs);


  /** Utilities for working with element policies. */
  public static final class Util {
    private Util() { /* uninstantiable */ }

    /**
     * Given zero or more element policies, returns an element policy equivalent
     * to applying them in order failing early if any of them fails.
     */
    public static final ElementPolicy join(ElementPolicy... policies) {
      PolicyJoiner joiner = new PolicyJoiner();
      for (ElementPolicy p : policies) {
        if (p != null) {
          joiner.unroll(p);
        }
      }
      return joiner.join();
    }

    static final class PolicyJoiner
        extends JoinHelper<ElementPolicy, JoinableElementPolicy> {

      PolicyJoiner() {
        super(
            ElementPolicy.class, JoinableElementPolicy.class,
            REJECT_ALL_ELEMENT_POLICY, IDENTITY_ELEMENT_POLICY);
      }

      @Override
      Optional<ImmutableList<ElementPolicy>> split(ElementPolicy x) {
        if (x instanceof JoinedElementPolicy) {
          return Optional.of(((JoinedElementPolicy) x).policies);
        }
        return Optional.absent();
      }

      @Override
      ElementPolicy rejoin(Set<? extends ElementPolicy> xs) {
        return new JoinedElementPolicy(xs);
      }
    }
  }

  /** An element policy that returns the element unchanged. */
  public static final ElementPolicy IDENTITY_ELEMENT_POLICY
      = new ElementPolicy() {
    public String apply(String elementName, List<String> attrs) {
      return elementName;
    }
  };

  /** An element policy that rejects all elements. */
  public static final ElementPolicy REJECT_ALL_ELEMENT_POLICY
      = new ElementPolicy() {
    public @Nullable String apply(String elementName, List<String> attrs) {
      return null;
    }
  };

  @SuppressWarnings("javadoc")
  static interface JoinableElementPolicy
  extends ElementPolicy, Joinable<JoinableElementPolicy> {
    // Parameterized appropriately.
  }
}

@Immutable
final class JoinedElementPolicy implements ElementPolicy {
  final ImmutableList<ElementPolicy> policies;

  JoinedElementPolicy(Iterable<? extends ElementPolicy> policies) {
    this.policies = ImmutableList.copyOf(policies);
  }

  public @Nullable String apply(String elementName, List<String> attrs) {
    String filteredElementName = elementName;
    for (ElementPolicy part : policies) {
      filteredElementName = part.apply(filteredElementName, attrs);
      if (filteredElementName == null) { break; }
    }
    return filteredElementName;
  }
}
