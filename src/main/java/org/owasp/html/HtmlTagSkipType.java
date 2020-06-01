package org.owasp.html;

public enum HtmlTagSkipType {
  SKIP(true),
  SKIP_BY_DEFAULT(true),
  DO_NOT_SKIP(false),
  DO_NOT_SKIP_BY_DEFAULT(false);

  private final boolean skipAvailability;

  HtmlTagSkipType(boolean skipAvailability) {
    this.skipAvailability = skipAvailability;
  }

  public HtmlTagSkipType and(HtmlTagSkipType s) {
    if (this == s || s == SKIP_BY_DEFAULT) {
      return this;
    }

    if (s == DO_NOT_SKIP) {
      return s;
    }

    if (s == DO_NOT_SKIP_BY_DEFAULT) {
      return this;
    }

    return SKIP;
  }

  public boolean skipAvailability() {
    return this.skipAvailability;
  }
}
