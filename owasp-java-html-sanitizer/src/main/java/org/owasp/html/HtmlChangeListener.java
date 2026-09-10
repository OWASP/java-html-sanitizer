// Copyright (c) 2011, Mike Samuel
// All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause
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
 * Receives events when an HTML tag, attribute, or text is discarded.
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
   * Called when attributes are discarded from a tag that the policy allowed.
   * <p>
   * Usually the tag itself survives without them.  When every attribute is
   * rejected and the element is one the policy skips when it has none, the
   * {@link HtmlPolicyBuilder#DEFAULT_SKIP_IF_EMPTY default set} unless
   * {@link HtmlPolicyBuilder#allowWithoutAttributes} or
   * {@link HtmlPolicyBuilder#disallowWithoutAttributes} said otherwise, the
   * tag is discarded as a consequence: {@link #discardedTag}
   * reports the tag, and this method still reports the attributes, since
   * rejecting them is what the policy did.  Attributes on a tag that the
   * policy did not allow are not reported; {@code discardedTag} covers the
   * whole tag.
   * <p>
   * A repeated attribute name counts once per dropped copy.
   */
  public void discardedAttributes(
      @Nullable T context, String tagName, String... attributeNames);

  /**
   * Called once for each attribute named in a {@link #discardedAttributes}
   * report, after that report, with the value the attribute had in the input.
   * The value is as the author wrote it, after character references have
   * been decoded, and has not been vetted by any policy, so treat it as
   * untrusted.
   * <p>
   * The default implementation does nothing.
   */
  public default void discardedAttribute(
      @Nullable T context, String tagName, String attributeName,
      String attributeValue) {
    // Listeners that do not need values need not override this.
  }

  /**
   * Called when text is discarded from an element the policy kept.  The
   * policy removes tag-shaped ranges from literal content such as
   * {@code <style>x<div>y</div></style>}, because a browser would receive
   * those ranges as markup without their passing through element and
   * attribute policies.  The renderer may instead drop all the remaining
   * content when a browser would read it differently, such as a {@code -->}
   * with no {@code <!--} before it.
   * <p>
   * Text inside a discarded element is not reported here; the
   * {@link #discardedTag} report covers it.  Policy drops are reported with
   * any output receiver.  Renderer drops are reported only with an
   * {@link HtmlStreamRenderer}, seen through any
   * {@link HtmlStreamEventReceiverWrapper} around it;
   * {@link PolicyFactory#sanitize(String, HtmlChangeListener, Object)} always
   * uses one.
   * <p>
   * One input text chunk may result in multiple calls.  Callers must not rely
   * on the boundaries between calls.  Treat the text as untrusted; it may
   * contain attacker-controlled markup.
   * <p>
   * The default implementation does nothing.
   *
   * @param elementName the name under which the policy kept the element.
   * @param text the content that was dropped.
   */
  public default void discardedText(
      @Nullable T context, String elementName, String text) {
    // Listeners that do not need text need not override this.
  }
}
