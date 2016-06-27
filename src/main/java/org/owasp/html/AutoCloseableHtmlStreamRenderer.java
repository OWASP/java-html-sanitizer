package org.owasp.html;

import java.io.Closeable;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import javax.annotation.WillCloseWhenClosed;

import com.google.common.base.Throwables;

final class AutoCloseableHtmlStreamRenderer extends HtmlStreamRenderer
  // This is available on JDK6 and makes this class extend AutoCloseable.
  implements Closeable {
  private final Object closeable;

  private static final Class<?> CLASS_AUTO_CLOSEABLE;

  static {
    Class<?> classAutoCloseable = null;
    for (Class<?> superInterface : Closeable.class.getInterfaces()) {
      if ("java.lang.AutoCloseable".equals(superInterface.getName())) {
        classAutoCloseable = superInterface;
        break;
      }
    }
    CLASS_AUTO_CLOSEABLE = classAutoCloseable;
  }

  private static final Method METHOD_CLOSE;

  static {
    Method methodClose = null;
    if (CLASS_AUTO_CLOSEABLE != null) {
      try {
        methodClose = CLASS_AUTO_CLOSEABLE.getMethod("close");
      } catch (NoSuchMethodException ex) {
        throw (NoSuchMethodError) new NoSuchMethodError().initCause(ex);
      }
    }
    METHOD_CLOSE = methodClose;
  }

  static boolean isAutoCloseable(Object o) {
    return o instanceof Closeable
        || CLASS_AUTO_CLOSEABLE != null && CLASS_AUTO_CLOSEABLE.isInstance(o);
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
    this.closeable = output;
  }

  private static final Object[] ZERO_OBJECTS = new Object[0];

  public void close() throws IOException {
    if (isDocumentOpen()) { closeDocument(); }
    closeIfAnyCloseable(closeable);
  }

  static void closeIfAnyCloseable(Object closeable) throws IOException {
    if (closeable instanceof Closeable) {
      ((Closeable) closeable).close();
    } else if (METHOD_CLOSE != null) {
      try {
        METHOD_CLOSE.invoke(closeable, ZERO_OBJECTS);
      } catch (IllegalAccessException ex) {
        AssertionError ae = new AssertionError("close not public");
        ae.initCause(ex);
        throw ae;
      } catch (InvocationTargetException ex) {
        Throwable tgt = ex.getTargetException();
        if (tgt instanceof IOException) {
          throw (IOException) tgt;
        } else {
          Throwables.propagate(tgt);
        }
      }
    }
  }
}
