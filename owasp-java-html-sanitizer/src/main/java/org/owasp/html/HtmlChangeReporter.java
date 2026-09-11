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
import java.util.BitSet;
import java.util.List;

import javax.annotation.Nullable;

import org.owasp.html.TagBalancingHtmlStreamEventReceiver.TextSuppressionPolicy;
import org.owasp.html.TagBalancingHtmlStreamEventReceiver.OpenTagOutputPolicy;

/**
 * Sits between the HTML parser, the policy, and the renderer so that it
 * can report dropped elements, attributes and text to an
 * {@link HtmlChangeListener}.
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
 * policy, and receives notice of text the policy or renderer drops.
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

  /**
   * Implemented by a policy that can say, after
   * {@link HtmlSanitizer.Policy#openTag}, whether it allowed the element but
   * emitted no tag because every attribute had been rejected and the element
   * is skipped when it has none.  Attributes rejected from such an element
   * are the policy's doing and are reported; attributes on a rejected
   * element go with it and are not.
   */
  interface AttributelessSkipPolicy {
    /**
     * @return true if the most recent start tag was allowed by the element
     *     policy and dropped only for having no attributes left.
     */
    boolean skippedLastTagAsAttributeless();
  }

  /**
   * Implemented by a policy that can report text it drops after keeping the
   * element that contained it.
   */
  interface DroppedTextSource {
    /** Sends dropped text to {@code listener}, or to nobody when null. */
    void reportDroppedTextTo(
        @Nullable HtmlStreamRenderer.DroppedTextListener listener);
  }

  /** Receives exact input attributes rejected by an attribute policy. */
  interface DiscardedAttributeListener {
    void discardedAttribute(String name, String value);
  }

  /** Implemented by a policy that can identify attribute-policy rejections. */
  interface DiscardedAttributeSource {
    /** Sends rejections to {@code listener}, or to nobody when null. */
    void reportDiscardedAttributesTo(
        @Nullable DiscardedAttributeListener listener);
  }

  private static final class InputChannel<T>
      implements HtmlSanitizer.Policy,
                 TagBalancingHtmlStreamEventReceiver.NestingLimitListener,
                 TextSuppressionPolicy,
                 OpenTagOutputPolicy,
                 HtmlStreamRenderer.DroppedTextListener {
    HtmlStreamEventReceiver policy;
    final OutputChannel output;
    final T context;
    final HtmlChangeListener<? super T> listener;
    /** Alternating element names and text, gathered before user callbacks. */
    final List<String> pendingDroppedText = new ArrayList<>();
    /** Output name produced in response to the most recent input start tag. */
    private @Nullable String outputElementNameForLastOpenTag;

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

    /**
     * The renderer sits downstream and drops literal content it cannot emit
     * without a browser reading it differently.  It tells us directly, as
     * the balancer does for the nesting limit.
     */
    public void droppedText(String elementName, String text) {
      pendingDroppedText.add(elementName);
      pendingDroppedText.add(text);
    }

    public @Nullable String outputElementNameForLastOpenTag() {
      return outputElementNameForLastOpenTag;
    }

    public void openDocument() {
      pendingDroppedText.clear();
      outputElementNameForLastOpenTag = null;
      policy.openDocument();
      if (policy instanceof DroppedTextSource) {
        ((DroppedTextSource) policy).reportDroppedTextTo(this);
      }
      if (policy instanceof DiscardedAttributeSource) {
        ((DiscardedAttributeSource) policy)
            .reportDiscardedAttributesTo(output);
      }
      // The renderer decides on its own to drop literal content it cannot
      // emit, so it has to tell us; any other receiver keeps that to itself.
      // Bound once the renderer has opened the document, which forgets any
      // earlier listener, and for this document only, so that a renderer
      // reused without this reporter does not go on reporting to it.
      output.listenForDroppedText(this);
    }

    public void closeDocument() {
      // Closing may flush and drop pending literal content, so listen until
      // the renderer is done.
      policy.closeDocument();
      if (policy instanceof DroppedTextSource) {
        ((DroppedTextSource) policy).reportDroppedTextTo(null);
      }
      if (policy instanceof DiscardedAttributeSource) {
        ((DiscardedAttributeSource) policy)
            .reportDiscardedAttributesTo(null);
      }
      output.listenForDroppedText(null);
      dispatchDroppedText();
    }

    public void openTag(String elementName, List<String> attrs) {
      output.openedElementName = null;
      // Copied before the policy runs: it removes rejected attributes from
      // attrs in place, and their values are wanted for the report.
      output.expectAttributes(attrs);
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
        outputElementNameForLastOpenTag = output.openedElementName;
        output.openedElementName = null;
        // Attributes go unreported with a tag the policy rejected: the tag
        // report covers them.  Not so when the policy allowed the element and
        // dropped it only because none of its attributes survived: rejecting
        // them was the policy's decision, and the tag went as a consequence.
        boolean attrsRejectedOnTheirOwn = !discarded
            || (policy instanceof AttributelessSkipPolicy
                && ((AttributelessSkipPolicy) policy)
                    .skippedLastTagAsAttributeless());
        String[] discardedAttrs = attrsRejectedOnTheirOwn
            ? output.discardedAttributes()
            : ZERO_STRINGS;
        int nDiscarded = discardedAttrs.length / 2;
        output.clearExpectedAttributes();
        // Dispatch notifications to the listener, under the input name,
        // which is the one the listener can relate to what came in.
        if (discarded) {
          listener.discardedTag(context, elementName);
        }
        if (nDiscarded != 0) {
          String[] discardedAttrNames = new String[nDiscarded];
          for (int i = 0; i < nDiscarded; ++i) {
            discardedAttrNames[i] = discardedAttrs[i * 2];
          }
          listener.discardedAttributes(
              context, elementName, discardedAttrNames);
          for (int i = 0; i < nDiscarded; ++i) {
            listener.discardedAttribute(
                context, elementName,
                discardedAttrs[i * 2], discardedAttrs[i * 2 + 1]);
          }
        }
      }
    }

    public void closeTag(String elementName) {
      policy.closeTag(elementName);
      dispatchDroppedText();
    }

    public void text(String textChunk) {
      policy.text(textChunk);
      dispatchDroppedText();
    }

    /** Dispatches outside the policy call that decided to drop the text. */
    private void dispatchDroppedText() {
      if (!pendingDroppedText.isEmpty()) {
        String[] dropped = pendingDroppedText.toArray(
            new String[pendingDroppedText.size()]);
        pendingDroppedText.clear();
        for (int i = 0; i < dropped.length; i += 2) {
          listener.discardedText(context, dropped[i], dropped[i + 1]);
        }
      }
    }

    private static final String[] ZERO_STRINGS = new String[0];
  }

  /**
   * Forwards to the renderer, and is one of the library's own decorators so
   * that the policy can see the renderer behind it and know what it escapes.
   */
  private static final class OutputChannel
      extends HtmlStreamEventReceiverWrapper
      implements DiscardedAttributeListener {
    /**
     * The name of the tag the policy has opened in response to the tag being
     * opened, or null while it has opened none.
     */
    String openedElementName;
    /**
     * The attributes on the tag being opened, as original name and value
     * pairs.  A list rather than a map: a
     * name repeated on one tag is two attributes, and HTML forbids that, so
     * the sanitizer keeps the first and drops the rest.  Collapsing the copies
     * here would leave the surviving one accounting for all of them, and the
     * drops would go unreported.  The values ride along so that the drops can
     * be reported with them.
     */
    final List<String> expectedAttrs = new ArrayList<>();
    /** Input pairs an attribute policy explicitly rejected. */
    final BitSet rejectedAttrs = new BitSet();
    /** Input pairs accounted for by attributes the policy emitted. */
    final BitSet emittedAttrs = new BitSet();

    OutputChannel(HtmlStreamEventReceiver renderer) {
      super(renderer);
    }

    /** Starts accounting for the attributes on one input start tag. */
    void expectAttributes(List<String> attrs) {
      expectedAttrs.clear();
      expectedAttrs.addAll(attrs);
      rejectedAttrs.clear();
      emittedAttrs.clear();
    }

    public void discardedAttribute(String name, String value) {
      for (int i = 0, n = expectedAttrs.size() / 2; i < n; ++i) {
        int pair = i * 2;
        if (!rejectedAttrs.get(i) && !emittedAttrs.get(i)
            && name.equals(expectedAttrs.get(pair))
            && value.equals(expectedAttrs.get(pair + 1))) {
          rejectedAttrs.set(i);
          return;
        }
      }
    }

    /** Returns original pairs not accounted for by emitted attributes. */
    String[] discardedAttributes() {
      int n = expectedAttrs.size() / 2;
      int nDiscarded = n - emittedAttrs.cardinality();
      if (nDiscarded == 0) { return InputChannel.ZERO_STRINGS; }
      String[] discarded = new String[nDiscarded * 2];
      int out = 0;
      for (int i = 0; i < n; ++i) {
        if (!emittedAttrs.get(i)) {
          discarded[out++] = expectedAttrs.get(i * 2);
          discarded[out++] = expectedAttrs.get(i * 2 + 1);
        }
      }
      return discarded;
    }

    void clearExpectedAttributes() {
      expectedAttrs.clear();
      rejectedAttrs.clear();
      emittedAttrs.clear();
    }

    /**
     * Has the renderer report dropped literal content to {@code listener},
     * or to nobody when null, if it is one that can.  The library's own
     * decorator, which a postprocessor or a logging wrapper is likely to
     * extend, is seen through.
     */
    void listenForDroppedText(
        @Nullable HtmlStreamRenderer.DroppedTextListener listener) {
      HtmlStreamEventReceiver r = underlying;
      while (r instanceof HtmlStreamEventReceiverWrapper) {
        r = ((HtmlStreamEventReceiverWrapper) r).underlying;
      }
      if (r instanceof HtmlStreamRenderer) {
        ((HtmlStreamRenderer) r).reportDroppedTextTo(listener);
      }
    }

    @Override
    public void openTag(String elementName, List<String> attrs) {
      openedElementName = elementName;
      for (int i = 0, n = attrs.size(); i < n; i += 2) {
        // Accounts for one copy of the name, so repeats the policy dropped
        // stay behind to be reported.
        markFirstEmitted(attrs.get(i));
      }
      underlying.openTag(elementName, attrs);
    }

    /** Accounts for the first eligible input copy of an emitted name. */
    private void markFirstEmitted(String name) {
      for (int i = 0, n = expectedAttrs.size() / 2; i < n; ++i) {
        if (!rejectedAttrs.get(i) && !emittedAttrs.get(i)
            && name.equals(expectedAttrs.get(i * 2))) {
          emittedAttrs.set(i);
          return;
        }
      }
    }
  }
}
