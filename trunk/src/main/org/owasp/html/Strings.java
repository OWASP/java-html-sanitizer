package org.owasp.html;

import javax.annotation.Nullable;

/**
 * Locale independent versions of String case-insensitive operations.
 * <p>
 * The normal case insensitive operators {@link String#toLowerCase}
 * and {@link String#equalsIgnoreCase} depend upon the current locale.
 * They will fold the letters "i" and "I" differently if the locale is
 * Turkish than if it is English.
 * <p>
 * These operations ignore all case folding for non-Roman letters, and are
 * independent of the current locale.
 * Lower-casing is exactly equivalent to {@code tr/A-Z/a-z/}, upper-casing to
 * {@code tr/a-z/A-Z/}, and case insensitive comparison is equivalent to
 * lower-casing both then comparing by code-unit.
 * <p>
 * Because of this simpler case folding, it is the case that for all Strings s
 * <code>
 * Strings.toUpperCase(s).equals(Strings.toUpperCase(Strings.toLowerCase(s)))
 * </code>.
 *
 * @author Mike Samuel <mikesamuel@gmail.com>
 */
final class Strings {
  public static boolean equalsIgnoreCase(
      @Nullable String a, @Nullable String b) {
    if (a == null) { return b == null; }
    if (b == null) { return false; }
    int length = a.length();
    if (b.length() != length) { return false; }
    return regionMatchesIgnoreCase(a, 0, b, 0, length);
  }

  public static boolean regionMatchesIgnoreCase(
      String a, int aoffset, String b, int boffset, int n) {
    for (int i = n; --i >= 0;) {
      char c = a.charAt(aoffset + i), d = b.charAt(boffset + i);
      if (c != d) {
        if (c <= 'z' && c >= 'A') {
          if (c <= 'Z') { c |= 0x20; }
          if (d <= 'Z' && d >= 'A') { d |= 0x20; }
          if (c == d) { continue; }
        }
        return false;
      }
    }
    return true;
  }

  /** True iff {@code s.equals(String.toLowerCase(s))}. */
  public static boolean isLowerCase(CharSequence s) {
    for (int i = s.length(); --i >= 0;) {
      char c = s.charAt(i);
      if (c <= 'Z' && c >= 'A') {
        return false;
      }
    }
    return true;
  }

  private static final char[] LCASE_CHARS = new char['Z' + 1];
  private static final char[] UCASE_CHARS = new char['z' + 1];
  static {
    for (int i = 0; i < 'A'; ++i) { LCASE_CHARS[i] = (char) i; }
    for (int i = 'A'; i <= 'Z'; ++i) { LCASE_CHARS[i] = (char) (i | 0x20); }
    for (int i = 0; i < 'a'; ++i) { UCASE_CHARS[i] = (char) i; }
    for (int i = 'a'; i <= 'z'; ++i) { UCASE_CHARS[i] = (char) (i & ~0x20); }
  }
  public static String toLowerCase(String s) {
    for (int i = s.length(); --i >= 0;) {
      char c = s.charAt(i);
      if (c <= 'Z' && c >= 'A') {
        char[] chars = s.toCharArray();
        chars[i] = LCASE_CHARS[c];
        while (--i >= 0) {
          c = chars[i];
          if (c <= 'Z') {
            chars[i] = LCASE_CHARS[c];
          }
        }
        return String.valueOf(chars);
      }
    }
    return s;
  }

  public static String toUpperCase(String s) {
    for (int i = s.length(); --i >= 0;) {
      char c = s.charAt(i);
      if (c <= 'z' && c >= 'a') {
        char[] chars = s.toCharArray();
        chars[i] = UCASE_CHARS[c];
        while (--i >= 0) {
          c = chars[i];
          if (c <= 'z') {
            chars[i] = UCASE_CHARS[c];
          }
        }
        return String.valueOf(chars);
      }
    }
    return s;
  }

  private Strings() { /* uninstantiable */ }
}
