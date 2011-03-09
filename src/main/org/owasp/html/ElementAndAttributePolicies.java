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
