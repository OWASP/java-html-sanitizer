// SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause

package org.owasp.html;

/**
 * Receives the output sink to allow user-code to post-process events.
 *
 * <p><b>Thread safety:</b> a single processor is shared by every sanitization
 * that uses the policy it was installed on, including concurrent ones, so a
 * processor must be safe to call {@link #wrap} on from several threads.
 * {@code wrap} is called once per sanitization, though, and the receiver it
 * returns is used by that sanitization alone.  So per-document state -- "am I
 * inside a {@code <style>} element?", a depth counter, a buffer -- belongs in
 * the returned receiver, not in a field of the processor:
 *
 * <pre>{@code
 * // Correct: the flag lives in the per-sanitization wrapper.
 * new HtmlStreamEventProcessor() {
 *   public HtmlStreamEventReceiver wrap(HtmlStreamEventReceiver sink) {
 *     return new HtmlStreamEventReceiverWrapper(sink) {
 *       private boolean inStyle;
 *       ...
 *     };
 *   }
 * }
 * }</pre>
 *
 * A flag hoisted into the processor itself would be shared by concurrent
 * sanitizations, which corrupts output rather than security: one document's
 * events cannot escape the policy, but they can make another document's
 * wrapper act on the wrong text.
 */
public interface HtmlStreamEventProcessor {
  /**
   * @param sink an HTML stream event receiver that can take events from a
   *    sanitizer policy to build a safe output on an appropriate buffer.
   * @return  an HTML stream event receiver that can take events from a
   *    sanitizer policy to build a safe output on an appropriate buffer by
   *    sending events to sink.  It is used by one sanitization only, so it is
   *    the right place for any state the processor needs to keep.
   */
  HtmlStreamEventReceiver wrap(HtmlStreamEventReceiver sink);

  /** */
  public static final class Processors {
    /**
     * A post-processor that returns the sink without wrapping it to do any
     * additional work.
     */
    public static final HtmlStreamEventProcessor IDENTITY =
        new HtmlStreamEventProcessor() {

      public HtmlStreamEventReceiver wrap(HtmlStreamEventReceiver sink) {
        return sink;
      }

      @Override
      public String toString() {
        return "[identity]";
      }
    };

    /**
     * @return a processor whose that wraps its input in f wrapped in g.
     */
    public static HtmlStreamEventProcessor compose(
        final HtmlStreamEventProcessor g, final HtmlStreamEventProcessor f) {
      if (f == IDENTITY) { return g; }
      if (g == IDENTITY) { return f; }
      return new HtmlStreamEventProcessor() {
        public HtmlStreamEventReceiver wrap(HtmlStreamEventReceiver sink) {
          return g.wrap(f.wrap(sink));
        }
        @Override
        public String toString() {
          return "(" + g + " \u2218 " + f + ")";
        }
      };
    }
  }
}
