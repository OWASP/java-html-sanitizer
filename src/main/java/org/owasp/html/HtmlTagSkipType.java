package org.owasp.html;

public enum HtmlTagSkipType {
  SKIP_BY_DEFAULT(true),
  SKIP(true),
  DO_NOT_SKIP(false),
  NONE(false);

  private final boolean skip;

  HtmlTagSkipType(boolean skip) {
    this.skip = skip;
  }

  public HtmlTagSkipType and(HtmlTagSkipType s) {
    if (this == s || s == SKIP_BY_DEFAULT) {
      return this;
    }

    if (s == DO_NOT_SKIP) {
      return s;
    }

    if (s == NONE) {
      return this;
    }

    return SKIP;
  }

  public boolean skip() {
    return this.skip;
  }
}
