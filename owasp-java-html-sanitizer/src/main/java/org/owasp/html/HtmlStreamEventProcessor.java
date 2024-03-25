package org.owasp.html;

/**
 * Receives the output sink to allow user-code to post-process events.
 */
public interface HtmlStreamEventProcessor {
  /**
   * @param sink an HTML stream event receiver that can take events from a
   *    sanitizer policy to build a safe output on an appropriate buffer.
   * @return  an HTML stream event receiver that can take events from a
   *    sanitizer policy to build a safe output on an appropriate buffer by
   *    sending events to sink.
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
