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

import java.util.ArrayList;
import java.util.List;

import javax.annotation.Nullable;

import org.owasp.html.TagBalancingHtmlStreamEventReceiver.TextSuppressionPolicy;

/**
 * Sits between the HTML parser, the policy, and the renderer so that it
 * can report dropped elements and attributes to an {@link HtmlChangeListener}.
 *
 * <pre>
 * HtmlChangeReporter&lt;T&gt; hcr = new HtmlChangeReporter&lt;T&gt;(
 *   renderer, htmlChangeListener, context);
 * hcr.setPolicy(policyFactory.apply(hcr.getWrappedRenderer()));
 * HtmlSanitizer.sanitize(html, hcr.getWrappedPolicy());
 * </pre>
 *
 * The renderer receives events from the policy unchanged, but the reporter
 * notices differences between the events from the lexer and those from the
 * policy.
 *
 * @param <T> The type of context value passed to the
 */
public final class HtmlChangeReporter<T> {
  private final OutputChannel output;
  private final InputChannel<T> input;

  /**
   * @param context forwarded to listener along with any reports.
   */
  public HtmlChangeReporter(
      HtmlStreamEventReceiver renderer,
      HtmlChangeListener<? super T> listener, @Nullable T context) {
    this.output = new OutputChannel(renderer);
    this.input = new InputChannel<>(output, listener, context);
  }

  /**
   * Associates an input channel.  {@code this} receives events and forwards
   * them to input.
   */
  public void setPolicy(HtmlSanitizer.Policy policy) {
    this.input.policy = policy;
  }

  /**
   * The underlying renderer.
   */
  public HtmlStreamEventReceiver getWrappedRenderer() { return output; }

  /**
   * The underlying policy.
   */
  public HtmlSanitizer.Policy getWrappedPolicy() { return input; }

  private static final class InputChannel<T>
      implements HtmlSanitizer.Policy,
                 TagBalancingHtmlStreamEventReceiver.NestingLimitListener,
                 TextSuppressionPolicy {
    HtmlStreamEventReceiver policy;
    final OutputChannel output;
    final T context;
    final HtmlChangeListener<? super T> listener;

    InputChannel(
        OutputChannel output, HtmlChangeListener<? super T> listener,
        @Nullable T context) {
      this.output = output;
      this.context = context;
      this.listener = listener;
    }

    /**
     * The tag balancer sits upstream of this channel, so a tag it drops for
     * exceeding the nesting limit never reaches the policy and would otherwise
     * go unreported.  It tells us directly instead.
     */
    public void nestingLimitReached(String elementName) {
      listener.discardedTag(context, elementName);
    }

    /**
     * For the same reason: before dropping a start tag at the limit, the
     * balancer asks whether the element's text is suppressed, and the policy
     * that knows sits behind this channel.
     */
    public boolean suppressesTextWhenDropped(String canonElementName) {
      return policy instanceof TextSuppressionPolicy
          && ((TextSuppressionPolicy) policy)
              .suppressesTextWhenDropped(canonElementName);
    }

    public void openDocument() {
      policy.openDocument();
    }

    public void closeDocument() {
      policy.closeDocument();
    }

    public void openTag(String elementName, List<String> attrs) {
      output.openedElementName = null;
      output.expectedAttrNames.clear();
      for (int i = 0, n = attrs.size(); i < n; i += 2) {
        output.expectedAttrNames.add(attrs.get(i));
      }
      policy.openTag(elementName, attrs);
      {
        // Gather the notification details to avoid any problems with the
        // listener re-entering the stream event receiver.  This shouldn't
        // occur, but if it does it will be a source of subtle confusing bugs.
        //
        // The tag survived if the policy opened anything in response.  Its
        // name is not compared with the input name: an ElementPolicy may
        // rename the element, and a renamed element was kept, not dropped.
        boolean discarded = output.openedElementName == null;
        output.openedElementName = null;
        int nExpected = output.expectedAttrNames.size();
        String[] discardedAttrNames =
            nExpected != 0 && !discarded
            ? output.expectedAttrNames.toArray(new String[nExpected])
            : ZERO_STRINGS;
        output.expectedAttrNames.clear();
        // Dispatch notifications to the listener, under the input name,
        // which is the one the listener can relate to what came in.
        if (discarded) {
          listener.discardedTag(context, elementName);
        }
        if (discardedAttrNames.length != 0) {
          listener.discardedAttributes(
              context, elementName, discardedAttrNames);
        }
      }
    }

    public void closeTag(String elementName) {
      policy.closeTag(elementName);
    }

    public void text(String textChunk) {
      policy.text(textChunk);
    }

    private static final String[] ZERO_STRINGS = new String[0];
  }

  private static final class OutputChannel implements HtmlStreamEventReceiver {
    private final HtmlStreamEventReceiver renderer;
    /**
     * The name of the tag the policy has opened in response to the tag being
     * opened, or null while it has opened none.
     */
    String openedElementName;
    /**
     * Names of the attributes on the tag being opened that have not turned up
     * in the output yet.  A list rather than a set: a name repeated on one tag
     * is two attributes, and HTML forbids that, so the sanitizer keeps the
     * first and drops the rest.  Collapsing the copies here would leave the
     * surviving one accounting for all of them, and the drops would go
     * unreported.
     */
    List<String> expectedAttrNames = new ArrayList<>();

    OutputChannel(HtmlStreamEventReceiver renderer) {
      this.renderer = renderer;
    }

    public void openDocument() {
      renderer.openDocument();
    }

    public void closeDocument() {
      renderer.closeDocument();
    }

    public void openTag(String elementName, List<String> attrs) {
      openedElementName = elementName;
      for (int i = 0, n = attrs.size(); i < n; i += 2) {
        // Accounts for one copy of the name, so repeats the policy dropped
        // stay behind to be reported.
        expectedAttrNames.remove(attrs.get(i));
      }
      renderer.openTag(elementName, attrs);
    }

    public void closeTag(String elementName) {
      renderer.closeTag(elementName);
    }

    public void text(String text) {
      renderer.text(text);
    }
  }
}
