package org.owasp.html;

import com.google.common.base.Throwables;

public interface Handler<T> {
  void handle(T x);

  public static final Handler<?> DO_NOTHING = new Handler<Object>() {
    public void handle(Object x) {
      // Really, do nothing.
    }
  };

  public static final Handler<Throwable> PROPAGATE = new Handler<Throwable>() {
    public void handle(Throwable th) {
      Throwables.propagate(th);
    }
  };
}
