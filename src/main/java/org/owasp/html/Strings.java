// Copyright (c) 2011, Mike Samuel
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
// Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
// Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
// Neither the name of the OWASP nor the names of its contributors may
// be used to endorse or promote products derived from this software
// without specific prior written permission.
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
// ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package org.owasp.html;

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
 * @author Mike Samuel (mikesamuel@gmail.com)
 */
final class Strings {
  /*
  public static boolean equalsIgnoreCase(
      @Nullable String a, @Nullable String b) {
    if (a == null) { return b == null; }
    if (b == null) { return false; }
    int length = a.length();
    if (b.length() != length) { return false; }
    for (int i = length; --i >= 0;) {
      char c = a.charAt(i), d = b.charAt(i);
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
  */

  public static boolean regionMatchesIgnoreCase(
      CharSequence a, int aoffset, CharSequence b, int boffset, int n) {
    if (aoffset + n > a.length() || boffset + n > b.length()) { return false; }
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
  /*
  public static boolean isLowerCase(CharSequence s) {
    for (int i = s.length(); --i >= 0;) {
      char c = s.charAt(i);
      if (c <= 'Z' && c >= 'A') {
        return false;
      }
    }
    return true;
  }
  */

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

  /*
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
  */

  private static final long HTML_SPACE_CHAR_BITMASK =
      (1L << ' ')
    | (1L << '\t')
    | (1L << '\n')
    | (1L << '\u000c')
    | (1L << '\r');

  static boolean isHtmlSpace(int ch) {
    return ch <= 0x20 && (HTML_SPACE_CHAR_BITMASK & (1L << ch)) != 0;
  }

  static boolean containsHtmlSpace(String s) {
    for (int i = 0, n = s.length(); i < n; ++i) {
      if (isHtmlSpace(s.charAt(i))) { return true; }
    }
    return false;
  }

  static String stripHtmlSpaces(String s) {
    int i = 0, n = s.length();
    for (; n > i; --n) {
      if (!isHtmlSpace(s.charAt(n - 1))) {
        break;
      }
    }
    for (; i < n; ++i) {
      if (!isHtmlSpace(s.charAt(i))) {
        break;
      }
    }
    if (i == 0 && n == s.length()) {
      return s;
    }
    return s.substring(i, n);
  }

  /**
   * Parses a valid floating point number per the HTML5 spec.
   * https://html.spec.whatwg.org/multipage/common-microsyntaxes.html#valid-floating-point-number
   *
   * @param start the start of the floating point number on s.
   * @return the end of the floating point number if valid or -1 if not.
   */
  static int skipValidFloatingPointNumber(String value, int start) {
    // A string is a valid floating-point number if it consists of:
    int i = start;
    final int n = value.length();

    if (i >= n) {
      return -1;
    }

    // 1. Optionally, a U+002D HYPHEN-MINUS character (-).
    if (value.charAt(i) == '-') {
      ++i;
    }
    // 2. One or both of the following, in the given order:
    boolean hasMantissa = false;
    //    1. A series of one or more ASCII digits.
    while (i < n) {
      char ch = value.charAt(i);
      if ('0' <= ch && ch <= '9') {
        ++i;
        hasMantissa = true;
      } else {
        break;
      }
    }
    //    2. Both of the following, in the given order:
    //       1. A single U+002E FULL STOP character (.).
    //       2. A series of one or more ASCII digits.
    if (i < n && value.charAt(i) == '.') {
      ++i;
      // Even if there's an integer, you need digits after the decimal point.
      hasMantissa = false;
      while (i < n) {
        char ch = value.charAt(i);
        if ('0' <= ch && ch <= '9') {
          ++i;
          hasMantissa = true;
        } else {
          break;
        }
      }
    }
    if (!hasMantissa) {
      return -1;
    }
    // 3. Optionally:
    //    1. Either a U+0065 LATIN SMALL LETTER E character (e)
    //       or a U+0045 LATIN CAPITAL LETTER E character (E).
    if (i < n && (value.charAt(i) | 32) == 'e') {
      ++i;
      //    2. Optionally, a U+002D HYPHEN-MINUS character (-) or
      //       U+002B PLUS SIGN character (+).
      if (i < n) {
        char ch = value.charAt(i);
        if (ch == '+' || ch == '-') {
          ++i;
        }
      }
      //    3. A series of one or more ASCII digits.
      boolean hasExponent = false;
      while (i < n) {
        char ch = value.charAt(i);
        if ('0' <= ch && ch <= '9') {
          ++i;
          hasExponent = true;
        } else {
          break;
        }
      }
      if (!hasExponent) {
        return -1;
      }
    }
    return i;
  }

  private Strings() { /* uninstantiable */ }
}
