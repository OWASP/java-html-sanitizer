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

import javax.annotation.Nullable;
import javax.annotation.concurrent.Immutable;


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
