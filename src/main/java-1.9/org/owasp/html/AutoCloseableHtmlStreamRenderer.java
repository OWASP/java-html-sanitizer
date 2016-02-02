package org.owasp.html;

import java.io.IOException;
import javax.annotation.WillCloseWhenClosed;

final class AutoCloseableHtmlStreamRenderer extends HtmlStreamRenderer
  implements AutoCloseable {
  private final AutoCloseable closeable;

  static boolean isAutoCloseable(Object o) {
    return o instanceof AutoCloseable;
  }

  static AutoCloseableHtmlStreamRenderer createAutoCloseableHtmlStreamRenderer(
      @WillCloseWhenClosed
      Appendable output, Handler<? super IOException> errorHandler,
      Handler<? super String> badHtmlHandler) {
    return new AutoCloseableHtmlStreamRenderer(
        output, errorHandler, badHtmlHandler);
  }

  private AutoCloseableHtmlStreamRenderer(
      @WillCloseWhenClosed
      Appendable output, Handler<? super IOException> errorHandler,
      Handler<? super String> badHtmlHandler) {
    super(output, errorHandler, badHtmlHandler);
    this.closeable = (AutoCloseable) output;
  }

  public void close() throws Exception {
    if (isDocumentOpen()) { closeDocument(); }
    closeable.close();
  }
}
