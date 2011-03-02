package org.owasp.html;

import javax.annotation.Nullable;

public class ParseException extends Exception {
  static final long serialVersionUID = 8485186712334520567L;

  public ParseException(@Nullable String message) {
    super(message);
  }

  public ParseException(@Nullable Throwable cause) {
    super(cause);
  }

  public ParseException(@Nullable String message, @Nullable Throwable cause) {
    super(message, cause);
  }
}
