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

import javax.annotation.Nullable;

/**
 * Receives events when an HTML tag, or attribute is discarded.
 * This can be hooked into an intrusion detection system to alert code when
 * suspicious HTML passes through the sanitizer.
 * <p>
 * Note: If a string sanitizes with no change notifications, it is not the case
 * that the input string is necessarily safe to use.
 * Only use the output of the sanitizer.
 * The sanitizer ensures that the output is in a sub-set of HTML that commonly
 * used HTML parsers will agree on the meaning of, but the absence of
 * notifications does not mean that the input is in such a sub-set,
 * only that it does not contain structural features that were removed.
 * </p>
 */
public interface HtmlChangeListener<T> {

  /** Called when a tag is discarded from the input. */
  public void discardedTag(@Nullable T context, String elementName);

  /**
   * Called when attributes are discarded
   * from the input but the containing tag is not.
   */
  public void discardedAttributes(
      @Nullable T context, String tagName, String... attributeNames);
}
