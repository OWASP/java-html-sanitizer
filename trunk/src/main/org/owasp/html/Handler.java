package org.owasp.html;

import com.google.common.base.Throwables;

/**
 * Receives notification of problems.
 *
 * @author Mike Samuel <mikesamuel@gmail.com>
 */
public interface Handler<T> {

  void handle(T x);

  /** A handler that does nothing given any input. */
  public static final Handler<?> DO_NOTHING = new Handler<Object>() {
    public void handle(Object x) {
      // Really, do nothing.
    }
  };

  /**
   * A handler that re-raises an error, wrapping it in a runtime exception if
   * necessary.
   */
  public static final Handler<Throwable> PROPAGATE = new Handler<Throwable>() {
    public void handle(Throwable th) {
      Throwables.propagate(th);
    }
  };
}
