package org.owasp.html;

import javax.annotation.concurrent.Immutable;

@Immutable
final class HtmlToken {
  final int start;
  final int end;
  final HtmlTokenType type;

  static HtmlToken instance(int start, int end, HtmlTokenType type) {
    return new HtmlToken(start, end, type);
  }

  boolean tokenInContextMatches(String context, String match) {
    int n = end - start;
    if (n != match.length()) { return false; }
    return context.regionMatches(start, match, 0, n);
  }

  private HtmlToken(int start, int end, HtmlTokenType type) {
    this.start = start;
    this.end = end;
    this.type = type;
  }
}
