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
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import javax.annotation.Nullable;

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
                 TagBalancingHtmlStreamEventReceiver.NestingLimitListener {
    HtmlStreamEventReceiver policy;
    final OutputChannel output;
    final T context;
    final HtmlChangeListener<? super T> listener;
    /** Repeated attribute names on the tag currently being opened. */
    private final List<String> duplicateAttrNames = new ArrayList<>();

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

    public void openDocument() {
      policy.openDocument();
    }

    public void closeDocument() {
      policy.closeDocument();
    }

    public void openTag(String elementName, List<String> attrs) {
      output.expectedElementName = elementName;
      output.expectedAttrNames.clear();
      duplicateAttrNames.clear();
      for (int i = 0, n = attrs.size(); i < n; i += 2) {
        String attrName = attrs.get(i);
        if (!output.expectedAttrNames.add(attrName)) {
          // HTML forbids repeating an attribute name on one tag, so the
          // sanitizer keeps the first and drops the rest.  The diff against
          // the output below cannot see that, since the surviving attribute
          // leaves the name present in both, so note it here instead.
          duplicateAttrNames.add(attrName);
        }
      }
      policy.openTag(elementName, attrs);
      {
        // Gather the notification details to avoid any problems with the
        // listener re-entering the stream event receiver.  This shouldn't
        // occur, but if it does it will be a source of subtle confusing bugs.
        String discardedElementName = output.expectedElementName;
        output.expectedElementName = null;
        String[] discardedAttrNames = discardedElementName == null
            ? namesOfDiscardedAttrs(
                output.expectedAttrNames, duplicateAttrNames)
            : ZERO_STRINGS;
        output.expectedAttrNames.clear();
        duplicateAttrNames.clear();
        // Dispatch notifications to the listener.
        if (discardedElementName != null) {
          listener.discardedTag(context, discardedElementName);
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

    /**
     * The names of the attributes that did not make it to the output: those
     * the policy rejected, followed by those dropped as repeats of a name
     * already on the tag.
     */
    private static String[] namesOfDiscardedAttrs(
        Set<String> rejected, List<String> duplicates) {
      int nRejected = rejected.size();
      if (duplicates.isEmpty()) {
        return nRejected != 0
            ? rejected.toArray(new String[nRejected])
            : ZERO_STRINGS;
      }
      List<String> discarded = new ArrayList<>(nRejected + duplicates.size());
      discarded.addAll(rejected);
      discarded.addAll(duplicates);
      return discarded.toArray(ZERO_STRINGS);
    }

    private static final String[] ZERO_STRINGS = new String[0];
  }

  private static final class OutputChannel implements HtmlStreamEventReceiver {
    private final HtmlStreamEventReceiver renderer;
    String expectedElementName;
    Set<String> expectedAttrNames = new LinkedHashSet<>();

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
      if (elementName.equals(expectedElementName)) {
        expectedElementName = null;
      }
      for (int i = 0, n = attrs.size(); i < n; i += 2) {
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
