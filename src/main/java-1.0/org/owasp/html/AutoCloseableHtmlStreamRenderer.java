package org.owasp.html;

import java.io.IOException;
import javax.annotation.WillCloseWhenClosed;

final class AutoCloseableHtmlStreamRenderer extends HtmlStreamRenderer {

  static boolean isAutoCloseable(Object o) {
    return false;
  }

  static AutoCloseableHtmlStreamRenderer createAutoCloseableHtmlStreamRenderer(
      @WillCloseWhenClosed
      Appendable output, Handler<? super IOException> errorHandler,
      Handler<? super String> badHtmlHandler) {
    throw new UnsupportedOperationException();
  }

  AutoCloseableHtmlStreamRenderer(
      @WillCloseWhenClosed
      Appendable output, Handler<? super IOException> errorHandler,
      Handler<? super String> badHtmlHandler) {
    super(output, errorHandler, badHtmlHandler);
  }
}
