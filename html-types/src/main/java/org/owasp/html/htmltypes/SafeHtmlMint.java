// Copyright (c) 2016, Mike Samuel
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

package org.owasp.html.htmltypes;

import javax.annotation.Nullable;

import com.google.common.html.types.SafeHtml;
import com.google.common.html.types.UncheckedConversions;

import org.owasp.html.HtmlChangeListener;
import org.owasp.html.PolicyFactory;

/**
 * Sanitizes a chunk of HTML producing a SafeHtml instance instead of
 * appending chars to an output buffer.
 *
 * <h3>Caveats</h3>
 * <p>
 * This class is safe when the policy factories passed to it are safe.
 * <a href="https://github.com/mikesamuel/fences-maven-enforcer-rule">Fences</a>
 * can be used to control access to {@link SafeHtmlMint#fromPolicyFactory}
 * as needed, and <a href="https://github.com/mikesamuel/fences-maven-enforcer-rule/blob/master/src/site/markdown/caveats.md">the plausible deniability</a>
 * standard can be extended to writing policies that white-list known-unsafe
 * content.
 */
public final class SafeHtmlMint {
  /**
   * Sanitizes a chunk of HTML producing a SafeHtml instance instead of
   * appending chars to an output buffer.
   */
  public static SafeHtmlMint fromPolicyFactory(PolicyFactory f) {
    return new SafeHtmlMint(f);
  }

  private final PolicyFactory f;

  private SafeHtmlMint(PolicyFactory f) {
    if (f == null) { throw new NullPointerException(); }
    this.f = f;
  }

  /** A convenience function that sanitizes a string of HTML. */
  public SafeHtml sanitize(@Nullable String html) {
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
   * @return a string of safe HTML assuming the input policy factory produces
   *     safe HTML.
   */
  public <CTX> SafeHtml sanitize(
      @Nullable String html,
      @Nullable HtmlChangeListener<CTX> listener, @Nullable CTX context) {
    if (html == null) { return SafeHtml.EMPTY; }
    return UncheckedConversions.safeHtmlFromStringKnownToSatisfyTypeContract(
        f.sanitize(html, listener, context));
  }
}
