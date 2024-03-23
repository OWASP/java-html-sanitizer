package org.owasp.html;

import java.util.List;

/**
 * An event receiver that delegates to an underlying receiver and which may
 * be overridden to do additional work.
 */
public abstract class HtmlStreamEventReceiverWrapper
implements HtmlStreamEventReceiver, AutoCloseable {

  protected final HtmlStreamEventReceiver underlying;

  /**
   * @param underlying delegated to.
   */
  public HtmlStreamEventReceiverWrapper(HtmlStreamEventReceiver underlying) {
    this.underlying = underlying;
  }

  public void openDocument() {
    this.underlying.openDocument();
  }

  public void closeDocument() {
    this.underlying.closeDocument();
  }

  public void openTag(String elementName, List<String> attrs) {
    this.underlying.openTag(elementName, attrs);
  }

  public void closeTag(String elementName) {
    this.underlying.closeTag(elementName);
  }

  public void text(String text) {
    this.underlying.text(text);
  }

  public void close() throws Exception {
    if (underlying instanceof AutoCloseable) {
      ((AutoCloseable) underlying).close();
    }
  }
}
