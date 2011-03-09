package org.owasp.html;

/**
 * A URL checker optimized to avoid object allocation for the common case:
 * {@code http}, {@code https}, {@code mailto}.
 */
@TCB
final class StandardUrlAttributePolicy implements AttributePolicy {

  static final StandardUrlAttributePolicy INSTANCE
      = new StandardUrlAttributePolicy();

  private StandardUrlAttributePolicy() { /* singleton */ }

  public String apply(String elementName, String attributeName, String s) {
    protocol_loop:
    for (int i = 0, n = s.length(); i < n; ++i) {
      switch (s.charAt(i)) {
        case '/': case '#': case '?':  // No protocol.
          break protocol_loop;
        case ':':
          switch (i) {
            case 4:
              if (!Strings.regionMatchesIgnoreCase("http", 0, s, 0, 4)) {
                return null;
              }
              break;
            case 5:
              if (!Strings.regionMatchesIgnoreCase("https", 0, s, 0, 5)) {
                return null;
              }
              break;
            case 6:
              if (!Strings.regionMatchesIgnoreCase("mailto", 0, s, 0, 6)) {
                return null;
              }
              break;
            default: return null;
          }
          break protocol_loop;
      }
    }
    return FilterUrlByProtocolAttributePolicy.normalizeUri(s);
  }

}