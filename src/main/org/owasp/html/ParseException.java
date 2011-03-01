package org.owasp.html;

import javax.annotation.Nullable;

public class ParseException extends Exception {
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
