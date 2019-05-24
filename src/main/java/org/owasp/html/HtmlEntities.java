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

import java.util.Map;

import com.google.common.collect.ImmutableMap;

/**
 * Utilities for decoding HTML entities, e.g., {@code &amp;}.
 */
final class HtmlEntities {

  private static final int LONGEST_ENTITY_NAME;

  static {
    int longestEntityName = 0;
    for (String entityName : getEntityNameToCodePointMap().keySet()) {
      if (entityName.length() > longestEntityName) {
        longestEntityName = entityName.length();
      }
    }
    LONGEST_ENTITY_NAME = longestEntityName;
  }

  /**
   * Decodes any HTML entity at the given location.  This handles both named and
   * numeric entities.
   *
   * @param html HTML text.
   * @param offset the position of the sequence to decode.
   * @param limit the last position in chars that could be part of the sequence
   *    to decode.
   * @return The offset after the end of the decoded sequence and the decoded
   *    code-point or code-unit packed into a long.
   *    The first 32 bits are the offset, and the second 32 bits are a
   *    code-point or a code-unit.
   */
  public static long decodeEntityAt(String html, int offset, int limit) {
    char ch = html.charAt(offset);
    if ('&' != ch) {
      return ((offset + 1L) << 32) | ch;
    }

    int entityLimit = Math.min(limit, offset + LONGEST_ENTITY_NAME + 2); // + 2 for & and ; characters
    int end = -1;
    int tail = -1;
    if (entityLimit == limit) {
      // Assume a broken entity that ends at the end until shown otherwise.
      end = tail = entityLimit;
    }
    entityloop:
    for (int i = offset + 1; i < entityLimit; ++i) {
      switch (html.charAt(i)) {
        case ';':  // An unbroken entity.
          end = i;
          tail = end + 1;
          break entityloop;
        case '#':
        case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
        case 'G': case 'H': case 'I': case 'J': case 'K': case 'L':
        case 'M': case 'N': case 'O': case 'P': case 'Q': case 'R':
        case 'S': case 'T': case 'U': case 'V': case 'W': case 'X':
        case 'Y': case 'Z':
        case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
        case 'g': case 'h': case 'i': case 'j': case 'k': case 'l':
        case 'm': case 'n': case 'o': case 'p': case 'q': case 'r':
        case 's': case 't': case 'u': case 'v': case 'w': case 'x':
        case 'y': case 'z':
        case '0': case '1': case '2': case '3': case '4': case '5':
        case '6': case '7': case '8': case '9':
          break;
        case '=':
          // An equal sign after an entity missing a closing semicolon should
          // never have the semicolon inserted since that causes trouble with
          // parameters in partially encoded URLs.
          return ((offset + 1L) << 32) | '&';
        default:  // A possible broken entity.
          end = i;
          tail = i;
          break entityloop;
      }
    }
    if (end < 0 || offset + 2 >= end) {
      return ((offset + 1L) << 32) | '&';
    }
    // Now we know where the entity ends, and that there is at least one
    // character in the entity name
    char ch1 = html.charAt(offset + 1);
    char ch2 = html.charAt(offset + 2);
    int codepoint = -1;
    if ('#' == ch1) {
      // numeric entity
      if ('x' == ch2 || 'X' == ch2) {
        if (end == offset + 3) {  // No digits
          return ((offset + 1L) << 32) | '&';
        }
        codepoint = 0;
        // hex literal
        digloop:
        for (int i = offset + 3; i < end; ++i) {
          char digit = html.charAt(i);
          switch (digit & 0xfff8) {
            case 0x30: case 0x38: // ASCII 48-57 are '0'-'9'
              int decDig = digit & 0xf;
              if (decDig < 10) {
                codepoint = (codepoint << 4) | decDig;
              } else {
                codepoint = -1;
                break digloop;
              }
              break;
            // ASCII 65-70 and 97-102 are 'A'-'Z' && 'a'-'z'
            case 0x40: case 0x60:
              int hexDig = (digit & 0x7);
              if (hexDig != 0 && hexDig < 7) {
                codepoint = (codepoint << 4) | (hexDig + 9);
              } else {
                codepoint = -1;
                break digloop;
              }
              break;
            default:
              codepoint = -1;
              break digloop;
          }
        }
        if (codepoint > Character.MAX_CODE_POINT) {
          codepoint = 0xfffd;  // Unknown.
        }
      } else {
        codepoint = 0;
        // decimal literal
        digloop:
        for (int i = offset + 2; i < end; ++i) {
          char digit = html.charAt(i);
          switch (digit & 0xfff8) {
            case 0x30: case 0x38: // ASCII 48-57 are '0'-'9'
              int decDig = digit - '0';
              if (decDig < 10) {
                codepoint = (codepoint * 10) + decDig;
              } else {
                codepoint = -1;
                break digloop;
              }
              break;
            default:
              codepoint = -1;
              break digloop;
          }
        }
        if (codepoint > Character.MAX_CODE_POINT) {
          codepoint = 0xfffd;  // Unknown.
        }
      }
    } else {
      Trie t = ENTITY_TRIE;
      for (int i = offset + 1; i < end; ++i) {
        char nameChar = html.charAt(i);
        t = t.lookup(nameChar);
        if (t == null) { break; }
      }
      if (t == null) {
        t = ENTITY_TRIE;
        for (int i = offset + 1; i < end; ++i) {
          char nameChar = html.charAt(i);
          if ('Z' >= nameChar && nameChar >= 'A') { nameChar |= 32; }
          t = t.lookup(nameChar);
          if (t == null) { break; }
        }
      }
      if (t != null && t.isTerminal()) {
        codepoint = t.getValue();
      }
    }
    if (codepoint < 0) {
      return ((offset + 1L) << 32) | '&';
    } else {
      return (((long) tail) << 32) | codepoint;
    }
  }

//  /** A possible entity name like "amp" or "gt". */
//  public static boolean isEntityName(String name) {
//    Trie t = ENTITY_TRIE;
//    int n = name.length();
//
//    // Treat AMP the same amp, but not Amp.
//    boolean isUcase = true;
//    for (int i = 0; i < n; ++i) {
//      char ch = name.charAt(i);
//      if (!('A' <= ch && ch <= 'Z')) {
//        isUcase = false;
//        break;
//      }
//    }
//
//    if (isUcase) { name = Strings.toLowerCase(name); }
//
//    for (int i = 0; i < n; ++i) {
//      t = t.lookup(name.charAt(i));
//      if (t == null) { return false; }
//    }
//    return t.isTerminal();
//  }

  /** A trie that maps entity names to codepoints. */
  public static final Trie ENTITY_TRIE = new Trie(getEntityNameToCodePointMap());

  private static Map<String, Integer> getEntityNameToCodePointMap() {
    final ImmutableMap.Builder<String, Integer> builder = ImmutableMap.builder();

    // C0 Controls and Basic Latin
    builder.put("Tab", Integer.valueOf('\u0009')); // CHARACTER TABULATION
    builder.put("NewLine", Integer.valueOf('\n')); // LINE FEED (LF)
    builder.put("excl", Integer.valueOf('\u0021')); // EXCLAMATION MARK
    builder.put("quot", Integer.valueOf('\u0022')); // QUOTATION MARK
    builder.put("QUOT", Integer.valueOf('\u0022')); // QUOTATION MARK
    builder.put("num", Integer.valueOf('\u0023')); // NUMBER SIGN
    builder.put("dollar", Integer.valueOf('\u0024')); // DOLLAR SIGN
    builder.put("percnt", Integer.valueOf('\u0025')); // PERCENT SIGN
    builder.put("amp", Integer.valueOf('\u0026')); // AMPERSAND
    builder.put("AMP", Integer.valueOf('\u0026')); // AMPERSAND
    builder.put("apos", Integer.valueOf('\'')); // APOSTROPHE
    builder.put("lpar", Integer.valueOf('\u0028')); // LEFT PARENTHESIS
    builder.put("rpar", Integer.valueOf('\u0029')); // RIGHT PARENTHESIS
    builder.put("ast", Integer.valueOf('\u002a')); // ASTERISK
    builder.put("midast", Integer.valueOf('\u002a')); // ASTERISK
    builder.put("plus", Integer.valueOf('\u002b')); // PLUS SIGN
    builder.put("comma", Integer.valueOf('\u002c')); // COMMA
    builder.put("period", Integer.valueOf('\u002e')); // FULL STOP
    builder.put("sol", Integer.valueOf('\u002f')); // SOLIDUS
    builder.put("colon", Integer.valueOf('\u003a')); // COLON
    builder.put("semi", Integer.valueOf('\u003b')); // SEMICOLON
    builder.put("lt", Integer.valueOf('\u003c')); // LESS-THAN SIGN
    builder.put("LT", Integer.valueOf('\u003c')); // LESS-THAN SIGN
    builder.put("equals", Integer.valueOf('\u003d')); // EQUALS SIGN
    builder.put("gt", Integer.valueOf('\u003e')); // GREATER-THAN SIGN
    builder.put("GT", Integer.valueOf('\u003e')); // GREATER-THAN SIGN
    builder.put("quest", Integer.valueOf('\u003f')); // QUESTION MARK
    builder.put("commat", Integer.valueOf('\u0040')); // COMMERCIAL AT
    builder.put("lsqb", Integer.valueOf('\u005b')); // LEFT SQUARE BRACKET
    builder.put("lbrack", Integer.valueOf('\u005b')); // LEFT SQUARE BRACKET
    builder.put("bsol", Integer.valueOf('\\')); // REVERSE SOLIDUS
    builder.put("rsqb", Integer.valueOf('\u005d')); // RIGHT SQUARE BRACKET
    builder.put("rbrack", Integer.valueOf('\u005d')); // RIGHT SQUARE BRACKET
    builder.put("Hat", Integer.valueOf('\u005e')); // CIRCUMFLEX ACCENT
    builder.put("lowbar", Integer.valueOf('\u005f')); // LOW LINE
    builder.put("grave", Integer.valueOf('\u0060')); // GRAVE ACCENT
    builder.put("DiacriticalGrave", Integer.valueOf('\u0060')); // GRAVE ACCENT
    builder.put("lcub", Integer.valueOf('\u007b')); // LEFT CURLY BRACKET
    builder.put("lbrace", Integer.valueOf('\u007b')); // LEFT CURLY BRACKET
    builder.put("verbar", Integer.valueOf('\u007c')); // VERTICAL LINE
    builder.put("vert", Integer.valueOf('\u007c')); // VERTICAL LINE
    builder.put("VerticalLine", Integer.valueOf('\u007c')); // VERTICAL LINE
    builder.put("rcub", Integer.valueOf('\u007d')); // RIGHT CURLY BRACKET
    builder.put("rbrace", Integer.valueOf('\u007d')); // RIGHT CURLY BRACKET

    // C1 Controls and Latin-1 Supplement
    builder.put("nbsp", Integer.valueOf('\u00a0')); // NO-BREAK SPACE
    builder.put("NonBreakingSpace", Integer.valueOf('\u00a0')); // NO-BREAK SPACE
    builder.put("iexcl", Integer.valueOf('\u00a1')); // INVERTED EXCLAMATION MARK
    builder.put("cent", Integer.valueOf('\u00a2')); // CENT SIGN
    builder.put("pound", Integer.valueOf('\u00a3')); // POUND SIGN
    builder.put("curren", Integer.valueOf('\u00a4')); // CURRENCY SIGN
    builder.put("yen", Integer.valueOf('\u00a5')); // YEN SIGN
    builder.put("brvbar", Integer.valueOf('\u00a6')); // BROKEN BAR
    builder.put("sect", Integer.valueOf('\u00a7')); // SECTION SIGN
    builder.put("Dot", Integer.valueOf('\u00a8')); // DIAERESIS
    builder.put("die", Integer.valueOf('\u00a8')); // DIAERESIS
    builder.put("DoubleDot", Integer.valueOf('\u00a8')); // DIAERESIS
    builder.put("uml", Integer.valueOf('\u00a8')); // DIAERESIS
    builder.put("copy", Integer.valueOf('\u00a9')); // COPYRIGHT SIGN
    builder.put("COPY", Integer.valueOf('\u00a9')); // COPYRIGHT SIGN
    builder.put("ordf", Integer.valueOf('\u00aa')); // FEMININE ORDINAL INDICATOR
    builder.put("laquo", Integer.valueOf('\u00ab')); // LEFT-POINTING DOUBLE ANGLE QUOTATION MARK
    builder.put("not", Integer.valueOf('\u00ac')); // NOT SIGN
    builder.put("shy", Integer.valueOf('\u00ad')); // SOFT HYPHEN
    builder.put("reg", Integer.valueOf('\u00ae')); // REGISTERED SIGN
    builder.put("circledR", Integer.valueOf('\u00ae')); // REGISTERED SIGN
    builder.put("REG", Integer.valueOf('\u00ae')); // REGISTERED SIGN
    builder.put("macr", Integer.valueOf('\u00af')); // MACRON
    builder.put("OverBar", Integer.valueOf('\u00af')); // MACRON
    builder.put("strns", Integer.valueOf('\u00af')); // MACRON
    builder.put("deg", Integer.valueOf('\u00b0')); // DEGREE SIGN
    builder.put("plusmn", Integer.valueOf('\u00b1')); // PLUS-MINUS SIGN
    builder.put("pm", Integer.valueOf('\u00b1')); // PLUS-MINUS SIGN
    builder.put("PlusMinus", Integer.valueOf('\u00b1')); // PLUS-MINUS SIGN
    builder.put("sup2", Integer.valueOf('\u00b2')); // SUPERSCRIPT TWO
    builder.put("sup3", Integer.valueOf('\u00b3')); // SUPERSCRIPT THREE
    builder.put("acute", Integer.valueOf('\u00b4')); // ACUTE ACCENT
    builder.put("DiacriticalAcute", Integer.valueOf('\u00b4')); // ACUTE ACCENT
    builder.put("micro", Integer.valueOf('\u00b5')); // MICRO SIGN
    builder.put("para", Integer.valueOf('\u00b6')); // PILCROW SIGN
    builder.put("middot", Integer.valueOf('\u00b7')); // MIDDLE DOT
    builder.put("centerdot", Integer.valueOf('\u00b7')); // MIDDLE DOT
    builder.put("CenterDot", Integer.valueOf('\u00b7')); // MIDDLE DOT
    builder.put("cedil", Integer.valueOf('\u00b8')); // CEDILLA
    builder.put("Cedilla", Integer.valueOf('\u00b8')); // CEDILLA
    builder.put("sup1", Integer.valueOf('\u00b9')); // SUPERSCRIPT ONE
    builder.put("ordm", Integer.valueOf('\u00ba')); // MASCULINE ORDINAL INDICATOR
    builder.put("raquo", Integer.valueOf('\u00bb')); // RIGHT-POINTING DOUBLE ANGLE QUOTATION MARK
    builder.put("frac14", Integer.valueOf('\u00bc')); // VULGAR FRACTION ONE QUARTER
    builder.put("frac12", Integer.valueOf('\u00bd')); // VULGAR FRACTION ONE HALF
    builder.put("half", Integer.valueOf('\u00bd')); // VULGAR FRACTION ONE HALF
    builder.put("frac34", Integer.valueOf('\u00be')); // VULGAR FRACTION THREE QUARTERS
    builder.put("iquest", Integer.valueOf('\u00bf')); // INVERTED QUESTION MARK
    builder.put("Agrave", Integer.valueOf('\u00c0')); // LATIN CAPITAL LETTER A WITH GRAVE
    builder.put("Aacute", Integer.valueOf('\u00c1')); // LATIN CAPITAL LETTER A WITH ACUTE
    builder.put("Acirc", Integer.valueOf('\u00c2')); // LATIN CAPITAL LETTER A WITH CIRCUMFLEX
    builder.put("Atilde", Integer.valueOf('\u00c3')); // LATIN CAPITAL LETTER A WITH TILDE
    builder.put("Auml", Integer.valueOf('\u00c4')); // LATIN CAPITAL LETTER A WITH DIAERESIS
    builder.put("Aring", Integer.valueOf('\u00c5')); // LATIN CAPITAL LETTER A WITH RING ABOVE
    builder.put("AElig", Integer.valueOf('\u00c6')); // LATIN CAPITAL LETTER AE
    builder.put("Ccedil", Integer.valueOf('\u00c7')); // LATIN CAPITAL LETTER C WITH CEDILLA
    builder.put("Egrave", Integer.valueOf('\u00c8')); // LATIN CAPITAL LETTER E WITH GRAVE
    builder.put("Eacute", Integer.valueOf('\u00c9')); // LATIN CAPITAL LETTER E WITH ACUTE
    builder.put("Ecirc", Integer.valueOf('\u00ca')); // LATIN CAPITAL LETTER E WITH CIRCUMFLEX
    builder.put("Euml", Integer.valueOf('\u00cb')); // LATIN CAPITAL LETTER E WITH DIAERESIS
    builder.put("Igrave", Integer.valueOf('\u00cc')); // LATIN CAPITAL LETTER I WITH GRAVE
    builder.put("Iacute", Integer.valueOf('\u00cd')); // LATIN CAPITAL LETTER I WITH ACUTE
    builder.put("Icirc", Integer.valueOf('\u00ce')); // LATIN CAPITAL LETTER I WITH CIRCUMFLEX
    builder.put("Iuml", Integer.valueOf('\u00cf')); // LATIN CAPITAL LETTER I WITH DIAERESIS
    builder.put("ETH", Integer.valueOf('\u00d0')); // LATIN CAPITAL LETTER ETH
    builder.put("Ntilde", Integer.valueOf('\u00d1')); // LATIN CAPITAL LETTER N WITH TILDE
    builder.put("Ograve", Integer.valueOf('\u00d2')); // LATIN CAPITAL LETTER O WITH GRAVE
    builder.put("Oacute", Integer.valueOf('\u00d3')); // LATIN CAPITAL LETTER O WITH ACUTE
    builder.put("Ocirc", Integer.valueOf('\u00d4')); // LATIN CAPITAL LETTER O WITH CIRCUMFLEX
    builder.put("Otilde", Integer.valueOf('\u00d5')); // LATIN CAPITAL LETTER O WITH TILDE
    builder.put("Ouml", Integer.valueOf('\u00d6')); // LATIN CAPITAL LETTER O WITH DIAERESIS
    builder.put("times", Integer.valueOf('\u00d7')); // MULTIPLICATION SIGN
    builder.put("Oslash", Integer.valueOf('\u00d8')); // LATIN CAPITAL LETTER O WITH STROKE
    builder.put("Ugrave", Integer.valueOf('\u00d9')); // LATIN CAPITAL LETTER U WITH GRAVE
    builder.put("Uacute", Integer.valueOf('\u00da')); // LATIN CAPITAL LETTER U WITH ACUTE
    builder.put("Ucirc", Integer.valueOf('\u00db')); // LATIN CAPITAL LETTER U WITH CIRCUMFLEX
    builder.put("Uuml", Integer.valueOf('\u00dc')); // LATIN CAPITAL LETTER U WITH DIAERESIS
    builder.put("Yacute", Integer.valueOf('\u00dd')); // LATIN CAPITAL LETTER Y WITH ACUTE
    builder.put("THORN", Integer.valueOf('\u00de')); // LATIN CAPITAL LETTER THORN
    builder.put("szlig", Integer.valueOf('\u00df')); // LATIN SMALL LETTER SHARP S
    builder.put("agrave", Integer.valueOf('\u00e0')); // LATIN SMALL LETTER A WITH GRAVE
    builder.put("aacute", Integer.valueOf('\u00e1')); // LATIN SMALL LETTER A WITH ACUTE
    builder.put("acirc", Integer.valueOf('\u00e2')); // LATIN SMALL LETTER A WITH CIRCUMFLEX
    builder.put("atilde", Integer.valueOf('\u00e3')); // LATIN SMALL LETTER A WITH TILDE
    builder.put("auml", Integer.valueOf('\u00e4')); // LATIN SMALL LETTER A WITH DIAERESIS
    builder.put("aring", Integer.valueOf('\u00e5')); // LATIN SMALL LETTER A WITH RING ABOVE
    builder.put("aelig", Integer.valueOf('\u00e6')); // LATIN SMALL LETTER AE
    builder.put("ccedil", Integer.valueOf('\u00e7')); // LATIN SMALL LETTER C WITH CEDILLA
    builder.put("egrave", Integer.valueOf('\u00e8')); // LATIN SMALL LETTER E WITH GRAVE
    builder.put("eacute", Integer.valueOf('\u00e9')); // LATIN SMALL LETTER E WITH ACUTE
    builder.put("ecirc", Integer.valueOf('\u00ea')); // LATIN SMALL LETTER E WITH CIRCUMFLEX
    builder.put("euml", Integer.valueOf('\u00eb')); // LATIN SMALL LETTER E WITH DIAERESIS
    builder.put("igrave", Integer.valueOf('\u00ec')); // LATIN SMALL LETTER I WITH GRAVE
    builder.put("iacute", Integer.valueOf('\u00ed')); // LATIN SMALL LETTER I WITH ACUTE
    builder.put("icirc", Integer.valueOf('\u00ee')); // LATIN SMALL LETTER I WITH CIRCUMFLEX
    builder.put("iuml", Integer.valueOf('\u00ef')); // LATIN SMALL LETTER I WITH DIAERESIS
    builder.put("eth", Integer.valueOf('\u00f0')); // LATIN SMALL LETTER ETH
    builder.put("ntilde", Integer.valueOf('\u00f1')); // LATIN SMALL LETTER N WITH TILDE
    builder.put("ograve", Integer.valueOf('\u00f2')); // LATIN SMALL LETTER O WITH GRAVE
    builder.put("oacute", Integer.valueOf('\u00f3')); // LATIN SMALL LETTER O WITH ACUTE
    builder.put("ocirc", Integer.valueOf('\u00f4')); // LATIN SMALL LETTER O WITH CIRCUMFLEX
    builder.put("otilde", Integer.valueOf('\u00f5')); // LATIN SMALL LETTER O WITH TILDE
    builder.put("ouml", Integer.valueOf('\u00f6')); // LATIN SMALL LETTER O WITH DIAERESIS
    builder.put("divide", Integer.valueOf('\u00f7')); // DIVISION SIGN
    builder.put("div", Integer.valueOf('\u00f7')); // DIVISION SIGN
    builder.put("oslash", Integer.valueOf('\u00f8')); // LATIN SMALL LETTER O WITH STROKE
    builder.put("ugrave", Integer.valueOf('\u00f9')); // LATIN SMALL LETTER U WITH GRAVE
    builder.put("uacute", Integer.valueOf('\u00fa')); // LATIN SMALL LETTER U WITH ACUTE
    builder.put("ucirc", Integer.valueOf('\u00fb')); // LATIN SMALL LETTER U WITH CIRCUMFLEX
    builder.put("uuml", Integer.valueOf('\u00fc')); // LATIN SMALL LETTER U WITH DIAERESIS
    builder.put("yacute", Integer.valueOf('\u00fd')); // LATIN SMALL LETTER Y WITH ACUTE
    builder.put("thorn", Integer.valueOf('\u00fe')); // LATIN SMALL LETTER THORN
    builder.put("yuml", Integer.valueOf('\u00ff')); // LATIN SMALL LETTER Y WITH DIAERESIS

    // Latin Extended-A
    builder.put("Amacr", Integer.valueOf('\u0100')); // LATIN CAPITAL LETTER A WITH MACRON
    builder.put("amacr", Integer.valueOf('\u0101')); // LATIN SMALL LETTER A WITH MACRON
    builder.put("Abreve", Integer.valueOf('\u0102')); // LATIN CAPITAL LETTER A WITH BREVE
    builder.put("abreve", Integer.valueOf('\u0103')); // LATIN SMALL LETTER A WITH BREVE
    builder.put("Aogon", Integer.valueOf('\u0104')); // LATIN CAPITAL LETTER A WITH OGONEK
    builder.put("aogon", Integer.valueOf('\u0105')); // LATIN SMALL LETTER A WITH OGONEK
    builder.put("Cacute", Integer.valueOf('\u0106')); // LATIN CAPITAL LETTER C WITH ACUTE
    builder.put("cacute", Integer.valueOf('\u0107')); // LATIN SMALL LETTER C WITH ACUTE
    builder.put("Ccirc", Integer.valueOf('\u0108')); // LATIN CAPITAL LETTER C WITH CIRCUMFLEX
    builder.put("ccirc", Integer.valueOf('\u0109')); // LATIN SMALL LETTER C WITH CIRCUMFLEX
    builder.put("Cdot", Integer.valueOf('\u010a')); // LATIN CAPITAL LETTER C WITH DOT ABOVE
    builder.put("cdot", Integer.valueOf('\u010b')); // LATIN SMALL LETTER C WITH DOT ABOVE
    builder.put("Ccaron", Integer.valueOf('\u010c')); // LATIN CAPITAL LETTER C WITH CARON
    builder.put("ccaron", Integer.valueOf('\u010d')); // LATIN SMALL LETTER C WITH CARON
    builder.put("Dcaron", Integer.valueOf('\u010e')); // LATIN CAPITAL LETTER D WITH CARON
    builder.put("dcaron", Integer.valueOf('\u010f')); // LATIN SMALL LETTER D WITH CARON
    builder.put("Dstrok", Integer.valueOf('\u0110')); // LATIN CAPITAL LETTER D WITH STROKE
    builder.put("dstrok", Integer.valueOf('\u0111')); // LATIN SMALL LETTER D WITH STROKE
    builder.put("Emacr", Integer.valueOf('\u0112')); // LATIN CAPITAL LETTER E WITH MACRON
    builder.put("emacr", Integer.valueOf('\u0113')); // LATIN SMALL LETTER E WITH MACRON
    builder.put("Edot", Integer.valueOf('\u0116')); // LATIN CAPITAL LETTER E WITH DOT ABOVE
    builder.put("edot", Integer.valueOf('\u0117')); // LATIN SMALL LETTER E WITH DOT ABOVE
    builder.put("Eogon", Integer.valueOf('\u0118')); // LATIN CAPITAL LETTER E WITH OGONEK
    builder.put("eogon", Integer.valueOf('\u0119')); // LATIN SMALL LETTER E WITH OGONEK
    builder.put("Ecaron", Integer.valueOf('\u011a')); // LATIN CAPITAL LETTER E WITH CARON
    builder.put("ecaron", Integer.valueOf('\u011b')); // LATIN SMALL LETTER E WITH CARON
    builder.put("Gcirc", Integer.valueOf('\u011c')); // LATIN CAPITAL LETTER G WITH CIRCUMFLEX
    builder.put("gcirc", Integer.valueOf('\u011d')); // LATIN SMALL LETTER G WITH CIRCUMFLEX
    builder.put("Gbreve", Integer.valueOf('\u011e')); // LATIN CAPITAL LETTER G WITH BREVE
    builder.put("gbreve", Integer.valueOf('\u011f')); // LATIN SMALL LETTER G WITH BREVE
    builder.put("Gdot", Integer.valueOf('\u0120')); // LATIN CAPITAL LETTER G WITH DOT ABOVE
    builder.put("gdot", Integer.valueOf('\u0121')); // LATIN SMALL LETTER G WITH DOT ABOVE
    builder.put("Gcedil", Integer.valueOf('\u0122')); // LATIN CAPITAL LETTER G WITH CEDILLA
    builder.put("Hcirc", Integer.valueOf('\u0124')); // LATIN CAPITAL LETTER H WITH CIRCUMFLEX
    builder.put("hcirc", Integer.valueOf('\u0125')); // LATIN SMALL LETTER H WITH CIRCUMFLEX
    builder.put("Hstrok", Integer.valueOf('\u0126')); // LATIN CAPITAL LETTER H WITH STROKE
    builder.put("hstrok", Integer.valueOf('\u0127')); // LATIN SMALL LETTER H WITH STROKE
    builder.put("Itilde", Integer.valueOf('\u0128')); // LATIN CAPITAL LETTER I WITH TILDE
    builder.put("itilde", Integer.valueOf('\u0129')); // LATIN SMALL LETTER I WITH TILDE
    builder.put("Imacr", Integer.valueOf('\u012a')); // LATIN CAPITAL LETTER I WITH MACRON
    builder.put("imacr", Integer.valueOf('\u012b')); // LATIN SMALL LETTER I WITH MACRON
    builder.put("Iogon", Integer.valueOf('\u012e')); // LATIN CAPITAL LETTER I WITH OGONEK
    builder.put("iogon", Integer.valueOf('\u012f')); // LATIN SMALL LETTER I WITH OGONEK
    builder.put("Idot", Integer.valueOf('\u0130')); // LATIN CAPITAL LETTER I WITH DOT ABOVE
    builder.put("imath", Integer.valueOf('\u0131')); // LATIN SMALL LETTER DOTLESS I
    builder.put("inodot", Integer.valueOf('\u0131')); // LATIN SMALL LETTER DOTLESS I
    builder.put("IJlig", Integer.valueOf('\u0132')); // LATIN CAPITAL LIGATURE IJ
    builder.put("ijlig", Integer.valueOf('\u0133')); // LATIN SMALL LIGATURE IJ
    builder.put("Jcirc", Integer.valueOf('\u0134')); // LATIN CAPITAL LETTER J WITH CIRCUMFLEX
    builder.put("jcirc", Integer.valueOf('\u0135')); // LATIN SMALL LETTER J WITH CIRCUMFLEX
    builder.put("Kcedil", Integer.valueOf('\u0136')); // LATIN CAPITAL LETTER K WITH CEDILLA
    builder.put("kcedil", Integer.valueOf('\u0137')); // LATIN SMALL LETTER K WITH CEDILLA
    builder.put("kgreen", Integer.valueOf('\u0138')); // LATIN SMALL LETTER KRA
    builder.put("Lacute", Integer.valueOf('\u0139')); // LATIN CAPITAL LETTER L WITH ACUTE
    builder.put("lacute", Integer.valueOf('\u013a')); // LATIN SMALL LETTER L WITH ACUTE
    builder.put("Lcedil", Integer.valueOf('\u013b')); // LATIN CAPITAL LETTER L WITH CEDILLA
    builder.put("lcedil", Integer.valueOf('\u013c')); // LATIN SMALL LETTER L WITH CEDILLA
    builder.put("Lcaron", Integer.valueOf('\u013d')); // LATIN CAPITAL LETTER L WITH CARON
    builder.put("lcaron", Integer.valueOf('\u013e')); // LATIN SMALL LETTER L WITH CARON
    builder.put("Lmidot", Integer.valueOf('\u013f')); // LATIN CAPITAL LETTER L WITH MIDDLE DOT
    builder.put("lmidot", Integer.valueOf('\u0140')); // LATIN SMALL LETTER L WITH MIDDLE DOT
    builder.put("Lstrok", Integer.valueOf('\u0141')); // LATIN CAPITAL LETTER L WITH STROKE
    builder.put("lstrok", Integer.valueOf('\u0142')); // LATIN SMALL LETTER L WITH STROKE
    builder.put("Nacute", Integer.valueOf('\u0143')); // LATIN CAPITAL LETTER N WITH ACUTE
    builder.put("nacute", Integer.valueOf('\u0144')); // LATIN SMALL LETTER N WITH ACUTE
    builder.put("Ncedil", Integer.valueOf('\u0145')); // LATIN CAPITAL LETTER N WITH CEDILLA
    builder.put("ncedil", Integer.valueOf('\u0146')); // LATIN SMALL LETTER N WITH CEDILLA
    builder.put("Ncaron", Integer.valueOf('\u0147')); // LATIN CAPITAL LETTER N WITH CARON
    builder.put("ncaron", Integer.valueOf('\u0148')); // LATIN SMALL LETTER N WITH CARON
    builder.put("napos", Integer.valueOf('\u0149')); // LATIN SMALL LETTER N PRECEDED BY APOSTROPHE
    builder.put("ENG", Integer.valueOf('\u014a')); // LATIN CAPITAL LETTER ENG
    builder.put("eng", Integer.valueOf('\u014b')); // LATIN SMALL LETTER ENG
    builder.put("Omacr", Integer.valueOf('\u014c')); // LATIN CAPITAL LETTER O WITH MACRON
    builder.put("omacr", Integer.valueOf('\u014d')); // LATIN SMALL LETTER O WITH MACRON
    builder.put("Odblac", Integer.valueOf('\u0150')); // LATIN CAPITAL LETTER O WITH DOUBLE ACUTE
    builder.put("odblac", Integer.valueOf('\u0151')); // LATIN SMALL LETTER O WITH DOUBLE ACUTE
    builder.put("OElig", Integer.valueOf('\u0152')); // LATIN CAPITAL LIGATURE OE
    builder.put("oelig", Integer.valueOf('\u0153')); // LATIN SMALL LIGATURE OE
    builder.put("Racute", Integer.valueOf('\u0154')); // LATIN CAPITAL LETTER R WITH ACUTE
    builder.put("racute", Integer.valueOf('\u0155')); // LATIN SMALL LETTER R WITH ACUTE
    builder.put("Rcedil", Integer.valueOf('\u0156')); // LATIN CAPITAL LETTER R WITH CEDILLA
    builder.put("rcedil", Integer.valueOf('\u0157')); // LATIN SMALL LETTER R WITH CEDILLA
    builder.put("Rcaron", Integer.valueOf('\u0158')); // LATIN CAPITAL LETTER R WITH CARON
    builder.put("rcaron", Integer.valueOf('\u0159')); // LATIN SMALL LETTER R WITH CARON
    builder.put("Sacute", Integer.valueOf('\u015a')); // LATIN CAPITAL LETTER S WITH ACUTE
    builder.put("sacute", Integer.valueOf('\u015b')); // LATIN SMALL LETTER S WITH ACUTE
    builder.put("Scirc", Integer.valueOf('\u015c')); // LATIN CAPITAL LETTER S WITH CIRCUMFLEX
    builder.put("scirc", Integer.valueOf('\u015d')); // LATIN SMALL LETTER S WITH CIRCUMFLEX
    builder.put("Scedil", Integer.valueOf('\u015e')); // LATIN CAPITAL LETTER S WITH CEDILLA
    builder.put("scedil", Integer.valueOf('\u015f')); // LATIN SMALL LETTER S WITH CEDILLA
    builder.put("Scaron", Integer.valueOf('\u0160')); // LATIN CAPITAL LETTER S WITH CARON
    builder.put("scaron", Integer.valueOf('\u0161')); // LATIN SMALL LETTER S WITH CARON
    builder.put("Tcedil", Integer.valueOf('\u0162')); // LATIN CAPITAL LETTER T WITH CEDILLA
    builder.put("tcedil", Integer.valueOf('\u0163')); // LATIN SMALL LETTER T WITH CEDILLA
    builder.put("Tcaron", Integer.valueOf('\u0164')); // LATIN CAPITAL LETTER T WITH CARON
    builder.put("tcaron", Integer.valueOf('\u0165')); // LATIN SMALL LETTER T WITH CARON
    builder.put("Tstrok", Integer.valueOf('\u0166')); // LATIN CAPITAL LETTER T WITH STROKE
    builder.put("tstrok", Integer.valueOf('\u0167')); // LATIN SMALL LETTER T WITH STROKE
    builder.put("Utilde", Integer.valueOf('\u0168')); // LATIN CAPITAL LETTER U WITH TILDE
    builder.put("utilde", Integer.valueOf('\u0169')); // LATIN SMALL LETTER U WITH TILDE
    builder.put("Umacr", Integer.valueOf('\u016a')); // LATIN CAPITAL LETTER U WITH MACRON
    builder.put("umacr", Integer.valueOf('\u016b')); // LATIN SMALL LETTER U WITH MACRON
    builder.put("Ubreve", Integer.valueOf('\u016c')); // LATIN CAPITAL LETTER U WITH BREVE
    builder.put("ubreve", Integer.valueOf('\u016d')); // LATIN SMALL LETTER U WITH BREVE
    builder.put("Uring", Integer.valueOf('\u016e')); // LATIN CAPITAL LETTER U WITH RING ABOVE
    builder.put("uring", Integer.valueOf('\u016f')); // LATIN SMALL LETTER U WITH RING ABOVE
    builder.put("Udblac", Integer.valueOf('\u0170')); // LATIN CAPITAL LETTER U WITH DOUBLE ACUTE
    builder.put("udblac", Integer.valueOf('\u0171')); // LATIN SMALL LETTER U WITH DOUBLE ACUTE
    builder.put("Uogon", Integer.valueOf('\u0172')); // LATIN CAPITAL LETTER U WITH OGONEK
    builder.put("uogon", Integer.valueOf('\u0173')); // LATIN SMALL LETTER U WITH OGONEK
    builder.put("Wcirc", Integer.valueOf('\u0174')); // LATIN CAPITAL LETTER W WITH CIRCUMFLEX
    builder.put("wcirc", Integer.valueOf('\u0175')); // LATIN SMALL LETTER W WITH CIRCUMFLEX
    builder.put("Ycirc", Integer.valueOf('\u0176')); // LATIN CAPITAL LETTER Y WITH CIRCUMFLEX
    builder.put("ycirc", Integer.valueOf('\u0177')); // LATIN SMALL LETTER Y WITH CIRCUMFLEX
    builder.put("Yuml", Integer.valueOf('\u0178')); // LATIN CAPITAL LETTER Y WITH DIAERESIS
    builder.put("Zacute", Integer.valueOf('\u0179')); // LATIN CAPITAL LETTER Z WITH ACUTE
    builder.put("zacute", Integer.valueOf('\u017a')); // LATIN SMALL LETTER Z WITH ACUTE
    builder.put("Zdot", Integer.valueOf('\u017b')); // LATIN CAPITAL LETTER Z WITH DOT ABOVE
    builder.put("zdot", Integer.valueOf('\u017c')); // LATIN SMALL LETTER Z WITH DOT ABOVE
    builder.put("Zcaron", Integer.valueOf('\u017d')); // LATIN CAPITAL LETTER Z WITH CARON
    builder.put("zcaron", Integer.valueOf('\u017e')); // LATIN SMALL LETTER Z WITH CARON

    // Latin Extended-B
    builder.put("fnof", Integer.valueOf('\u0192')); // LATIN SMALL LETTER F WITH HOOK
    builder.put("imped", Integer.valueOf('\u01b5')); // LATIN CAPITAL LETTER Z WITH STROKE
    builder.put("gacute", Integer.valueOf('\u01f5')); // LATIN SMALL LETTER G WITH ACUTE
    builder.put("jmath", Integer.valueOf('\u0237')); // LATIN SMALL LETTER DOTLESS J

    // Spacing Modifier Letters
    builder.put("circ", Integer.valueOf('\u02c6')); // MODIFIER LETTER CIRCUMFLEX ACCENT
    builder.put("caron", Integer.valueOf('\u02c7')); // CARON
    builder.put("Hacek", Integer.valueOf('\u02c7')); // CARON
    builder.put("breve", Integer.valueOf('\u02d8')); // BREVE
    builder.put("Breve", Integer.valueOf('\u02d8')); // BREVE
    builder.put("dot", Integer.valueOf('\u02d9')); // DOT ABOVE
    builder.put("DiacriticalDot", Integer.valueOf('\u02d9')); // DOT ABOVE
    builder.put("ring", Integer.valueOf('\u02da')); // RING ABOVE
    builder.put("ogon", Integer.valueOf('\u02db')); // OGONEK
    builder.put("tilde", Integer.valueOf('\u02dc')); // SMALL TILDE
    builder.put("DiacriticalTilde", Integer.valueOf('\u02dc')); // SMALL TILDE
    builder.put("dblac", Integer.valueOf('\u02dd')); // DOUBLE ACUTE ACCENT
    builder.put("DiacriticalDoubleAcute", Integer.valueOf('\u02dd')); // DOUBLE ACUTE ACCENT

    // Combining Diacritical Marks
    builder.put("DownBreve", Integer.valueOf('\u0311')); // COMBINING INVERTED BREVE
    builder.put("UnderBar", Integer.valueOf('\u0332')); // COMBINING LOW LINE

    // Greek and Coptic
    builder.put("Alpha", Integer.valueOf('\u0391')); // GREEK CAPITAL LETTER ALPHA
    builder.put("Beta", Integer.valueOf('\u0392')); // GREEK CAPITAL LETTER BETA
    builder.put("Gamma", Integer.valueOf('\u0393')); // GREEK CAPITAL LETTER GAMMA
    builder.put("Delta", Integer.valueOf('\u0394')); // GREEK CAPITAL LETTER DELTA
    builder.put("Epsilon", Integer.valueOf('\u0395')); // GREEK CAPITAL LETTER EPSILON
    builder.put("Zeta", Integer.valueOf('\u0396')); // GREEK CAPITAL LETTER ZETA
    builder.put("Eta", Integer.valueOf('\u0397')); // GREEK CAPITAL LETTER ETA
    builder.put("Theta", Integer.valueOf('\u0398')); // GREEK CAPITAL LETTER THETA
    builder.put("Iota", Integer.valueOf('\u0399')); // GREEK CAPITAL LETTER IOTA
    builder.put("Kappa", Integer.valueOf('\u039a')); // GREEK CAPITAL LETTER KAPPA
    builder.put("Lambda", Integer.valueOf('\u039b')); // GREEK CAPITAL LETTER LAMDA
    builder.put("Mu", Integer.valueOf('\u039c')); // GREEK CAPITAL LETTER MU
    builder.put("Nu", Integer.valueOf('\u039d')); // GREEK CAPITAL LETTER NU
    builder.put("Xi", Integer.valueOf('\u039e')); // GREEK CAPITAL LETTER XI
    builder.put("Omicron", Integer.valueOf('\u039f')); // GREEK CAPITAL LETTER OMICRON
    builder.put("Pi", Integer.valueOf('\u03a0')); // GREEK CAPITAL LETTER PI
    builder.put("Rho", Integer.valueOf('\u03a1')); // GREEK CAPITAL LETTER RHO
    builder.put("Sigma", Integer.valueOf('\u03a3')); // GREEK CAPITAL LETTER SIGMA
    builder.put("Tau", Integer.valueOf('\u03a4')); // GREEK CAPITAL LETTER TAU
    builder.put("Upsilon", Integer.valueOf('\u03a5')); // GREEK CAPITAL LETTER UPSILON
    builder.put("Phi", Integer.valueOf('\u03a6')); // GREEK CAPITAL LETTER PHI
    builder.put("Chi", Integer.valueOf('\u03a7')); // GREEK CAPITAL LETTER CHI
    builder.put("Psi", Integer.valueOf('\u03a8')); // GREEK CAPITAL LETTER PSI
    builder.put("Omega", Integer.valueOf('\u03a9')); // GREEK CAPITAL LETTER OMEGA
    builder.put("alpha", Integer.valueOf('\u03b1')); // GREEK SMALL LETTER ALPHA
    builder.put("beta", Integer.valueOf('\u03b2')); // GREEK SMALL LETTER BETA
    builder.put("gamma", Integer.valueOf('\u03b3')); // GREEK SMALL LETTER GAMMA
    builder.put("delta", Integer.valueOf('\u03b4')); // GREEK SMALL LETTER DELTA
    builder.put("epsiv", Integer.valueOf('\u03b5')); // GREEK SMALL LETTER EPSILON
    builder.put("varepsilon", Integer.valueOf('\u03b5')); // GREEK SMALL LETTER EPSILON
    builder.put("epsilon", Integer.valueOf('\u03b5')); // GREEK SMALL LETTER EPSILON
    builder.put("zeta", Integer.valueOf('\u03b6')); // GREEK SMALL LETTER ZETA
    builder.put("eta", Integer.valueOf('\u03b7')); // GREEK SMALL LETTER ETA
    builder.put("theta", Integer.valueOf('\u03b8')); // GREEK SMALL LETTER THETA
    builder.put("iota", Integer.valueOf('\u03b9')); // GREEK SMALL LETTER IOTA
    builder.put("kappa", Integer.valueOf('\u03ba')); // GREEK SMALL LETTER KAPPA
    builder.put("lambda", Integer.valueOf('\u03bb')); // GREEK SMALL LETTER LAMDA
    builder.put("mu", Integer.valueOf('\u03bc')); // GREEK SMALL LETTER MU
    builder.put("nu", Integer.valueOf('\u03bd')); // GREEK SMALL LETTER NU
    builder.put("xi", Integer.valueOf('\u03be')); // GREEK SMALL LETTER XI
    builder.put("omicron", Integer.valueOf('\u03bf')); // GREEK SMALL LETTER OMICRON
    builder.put("pi", Integer.valueOf('\u03c0')); // GREEK SMALL LETTER PI
    builder.put("rho", Integer.valueOf('\u03c1')); // GREEK SMALL LETTER RHO
    builder.put("sigmav", Integer.valueOf('\u03c2')); // GREEK SMALL LETTER FINAL SIGMA
    builder.put("varsigma", Integer.valueOf('\u03c2')); // GREEK SMALL LETTER FINAL SIGMA
    builder.put("sigmaf", Integer.valueOf('\u03c2')); // GREEK SMALL LETTER FINAL SIGMA
    builder.put("sigma", Integer.valueOf('\u03c3')); // GREEK SMALL LETTER SIGMA
    builder.put("tau", Integer.valueOf('\u03c4')); // GREEK SMALL LETTER TAU
    builder.put("upsi", Integer.valueOf('\u03c5')); // GREEK SMALL LETTER UPSILON
    builder.put("upsilon", Integer.valueOf('\u03c5')); // GREEK SMALL LETTER UPSILON
    builder.put("phi", Integer.valueOf('\u03c6')); // GREEK SMALL LETTER PHI
    builder.put("phiv", Integer.valueOf('\u03c6')); // GREEK SMALL LETTER PHI
    builder.put("varphi", Integer.valueOf('\u03c6')); // GREEK SMALL LETTER PHI
    builder.put("chi", Integer.valueOf('\u03c7')); // GREEK SMALL LETTER CHI
    builder.put("psi", Integer.valueOf('\u03c8')); // GREEK SMALL LETTER PSI
    builder.put("omega", Integer.valueOf('\u03c9')); // GREEK SMALL LETTER OMEGA
    builder.put("thetav", Integer.valueOf('\u03d1')); // GREEK THETA SYMBOL
    builder.put("vartheta", Integer.valueOf('\u03d1')); // GREEK THETA SYMBOL
    builder.put("thetasym", Integer.valueOf('\u03d1')); // GREEK THETA SYMBOL
    builder.put("Upsi", Integer.valueOf('\u03d2')); // GREEK UPSILON WITH HOOK SYMBOL
    builder.put("upsih", Integer.valueOf('\u03d2')); // GREEK UPSILON WITH HOOK SYMBOL
    builder.put("straightphi", Integer.valueOf('\u03d5')); // GREEK PHI SYMBOL
    builder.put("piv", Integer.valueOf('\u03d6')); // GREEK PI SYMBOL
    builder.put("varpi", Integer.valueOf('\u03d6')); // GREEK PI SYMBOL
    builder.put("Gammad", Integer.valueOf('\u03dc')); // GREEK LETTER DIGAMMA
    builder.put("gammad", Integer.valueOf('\u03dd')); // GREEK SMALL LETTER DIGAMMA
    builder.put("digamma", Integer.valueOf('\u03dd')); // GREEK SMALL LETTER DIGAMMA
    builder.put("kappav", Integer.valueOf('\u03f0')); // GREEK KAPPA SYMBOL
    builder.put("varkappa", Integer.valueOf('\u03f0')); // GREEK KAPPA SYMBOL
    builder.put("rhov", Integer.valueOf('\u03f1')); // GREEK RHO SYMBOL
    builder.put("varrho", Integer.valueOf('\u03f1')); // GREEK RHO SYMBOL
    builder.put("epsi", Integer.valueOf('\u03f5')); // GREEK LUNATE EPSILON SYMBOL
    builder.put("straightepsilon", Integer.valueOf('\u03f5')); // GREEK LUNATE EPSILON SYMBOL
    builder.put("bepsi", Integer.valueOf('\u03f6')); // GREEK REVERSED LUNATE EPSILON SYMBOL
    builder.put("backepsilon", Integer.valueOf('\u03f6')); // GREEK REVERSED LUNATE EPSILON SYMBOL

    // Cyrillic
    builder.put("IOcy", Integer.valueOf('\u0401')); // CYRILLIC CAPITAL LETTER IO
    builder.put("DJcy", Integer.valueOf('\u0402')); // CYRILLIC CAPITAL LETTER DJE
    builder.put("GJcy", Integer.valueOf('\u0403')); // CYRILLIC CAPITAL LETTER GJE
    builder.put("Jukcy", Integer.valueOf('\u0404')); // CYRILLIC CAPITAL LETTER UKRAINIAN IE
    builder.put("DScy", Integer.valueOf('\u0405')); // CYRILLIC CAPITAL LETTER DZE
    builder.put("Iukcy", Integer.valueOf('\u0406')); // CYRILLIC CAPITAL LETTER BYELORUSSIAN-UKRAINIAN I
    builder.put("YIcy", Integer.valueOf('\u0407')); // CYRILLIC CAPITAL LETTER YI
    builder.put("Jsercy", Integer.valueOf('\u0408')); // CYRILLIC CAPITAL LETTER JE
    builder.put("LJcy", Integer.valueOf('\u0409')); // CYRILLIC CAPITAL LETTER LJE
    builder.put("NJcy", Integer.valueOf('\u040a')); // CYRILLIC CAPITAL LETTER NJE
    builder.put("TSHcy", Integer.valueOf('\u040b')); // CYRILLIC CAPITAL LETTER TSHE
    builder.put("KJcy", Integer.valueOf('\u040c')); // CYRILLIC CAPITAL LETTER KJE
    builder.put("Ubrcy", Integer.valueOf('\u040e')); // CYRILLIC CAPITAL LETTER SHORT U
    builder.put("DZcy", Integer.valueOf('\u040f')); // CYRILLIC CAPITAL LETTER DZHE
    builder.put("Acy", Integer.valueOf('\u0410')); // CYRILLIC CAPITAL LETTER A
    builder.put("Bcy", Integer.valueOf('\u0411')); // CYRILLIC CAPITAL LETTER BE
    builder.put("Vcy", Integer.valueOf('\u0412')); // CYRILLIC CAPITAL LETTER VE
    builder.put("Gcy", Integer.valueOf('\u0413')); // CYRILLIC CAPITAL LETTER GHE
    builder.put("Dcy", Integer.valueOf('\u0414')); // CYRILLIC CAPITAL LETTER DE
    builder.put("IEcy", Integer.valueOf('\u0415')); // CYRILLIC CAPITAL LETTER IE
    builder.put("ZHcy", Integer.valueOf('\u0416')); // CYRILLIC CAPITAL LETTER ZHE
    builder.put("Zcy", Integer.valueOf('\u0417')); // CYRILLIC CAPITAL LETTER ZE
    builder.put("Icy", Integer.valueOf('\u0418')); // CYRILLIC CAPITAL LETTER I
    builder.put("Jcy", Integer.valueOf('\u0419')); // CYRILLIC CAPITAL LETTER SHORT I
    builder.put("Kcy", Integer.valueOf('\u041a')); // CYRILLIC CAPITAL LETTER KA
    builder.put("Lcy", Integer.valueOf('\u041b')); // CYRILLIC CAPITAL LETTER EL
    builder.put("Mcy", Integer.valueOf('\u041c')); // CYRILLIC CAPITAL LETTER EM
    builder.put("Ncy", Integer.valueOf('\u041d')); // CYRILLIC CAPITAL LETTER EN
    builder.put("Ocy", Integer.valueOf('\u041e')); // CYRILLIC CAPITAL LETTER O
    builder.put("Pcy", Integer.valueOf('\u041f')); // CYRILLIC CAPITAL LETTER PE
    builder.put("Rcy", Integer.valueOf('\u0420')); // CYRILLIC CAPITAL LETTER ER
    builder.put("Scy", Integer.valueOf('\u0421')); // CYRILLIC CAPITAL LETTER ES
    builder.put("Tcy", Integer.valueOf('\u0422')); // CYRILLIC CAPITAL LETTER TE
    builder.put("Ucy", Integer.valueOf('\u0423')); // CYRILLIC CAPITAL LETTER U
    builder.put("Fcy", Integer.valueOf('\u0424')); // CYRILLIC CAPITAL LETTER EF
    builder.put("KHcy", Integer.valueOf('\u0425')); // CYRILLIC CAPITAL LETTER HA
    builder.put("TScy", Integer.valueOf('\u0426')); // CYRILLIC CAPITAL LETTER TSE
    builder.put("CHcy", Integer.valueOf('\u0427')); // CYRILLIC CAPITAL LETTER CHE
    builder.put("SHcy", Integer.valueOf('\u0428')); // CYRILLIC CAPITAL LETTER SHA
    builder.put("SHCHcy", Integer.valueOf('\u0429')); // CYRILLIC CAPITAL LETTER SHCHA
    builder.put("HARDcy", Integer.valueOf('\u042a')); // CYRILLIC CAPITAL LETTER HARD SIGN
    builder.put("Ycy", Integer.valueOf('\u042b')); // CYRILLIC CAPITAL LETTER YERU
    builder.put("SOFTcy", Integer.valueOf('\u042c')); // CYRILLIC CAPITAL LETTER SOFT SIGN
    builder.put("Ecy", Integer.valueOf('\u042d')); // CYRILLIC CAPITAL LETTER E
    builder.put("YUcy", Integer.valueOf('\u042e')); // CYRILLIC CAPITAL LETTER YU
    builder.put("YAcy", Integer.valueOf('\u042f')); // CYRILLIC CAPITAL LETTER YA
    builder.put("acy", Integer.valueOf('\u0430')); // CYRILLIC SMALL LETTER A
    builder.put("bcy", Integer.valueOf('\u0431')); // CYRILLIC SMALL LETTER BE
    builder.put("vcy", Integer.valueOf('\u0432')); // CYRILLIC SMALL LETTER VE
    builder.put("gcy", Integer.valueOf('\u0433')); // CYRILLIC SMALL LETTER GHE
    builder.put("dcy", Integer.valueOf('\u0434')); // CYRILLIC SMALL LETTER DE
    builder.put("iecy", Integer.valueOf('\u0435')); // CYRILLIC SMALL LETTER IE
    builder.put("zhcy", Integer.valueOf('\u0436')); // CYRILLIC SMALL LETTER ZHE
    builder.put("zcy", Integer.valueOf('\u0437')); // CYRILLIC SMALL LETTER ZE
    builder.put("icy", Integer.valueOf('\u0438')); // CYRILLIC SMALL LETTER I
    builder.put("jcy", Integer.valueOf('\u0439')); // CYRILLIC SMALL LETTER SHORT I
    builder.put("kcy", Integer.valueOf('\u043a')); // CYRILLIC SMALL LETTER KA
    builder.put("lcy", Integer.valueOf('\u043b')); // CYRILLIC SMALL LETTER EL
    builder.put("mcy", Integer.valueOf('\u043c')); // CYRILLIC SMALL LETTER EM
    builder.put("ncy", Integer.valueOf('\u043d')); // CYRILLIC SMALL LETTER EN
    builder.put("ocy", Integer.valueOf('\u043e')); // CYRILLIC SMALL LETTER O
    builder.put("pcy", Integer.valueOf('\u043f')); // CYRILLIC SMALL LETTER PE
    builder.put("rcy", Integer.valueOf('\u0440')); // CYRILLIC SMALL LETTER ER
    builder.put("scy", Integer.valueOf('\u0441')); // CYRILLIC SMALL LETTER ES
    builder.put("tcy", Integer.valueOf('\u0442')); // CYRILLIC SMALL LETTER TE
    builder.put("ucy", Integer.valueOf('\u0443')); // CYRILLIC SMALL LETTER U
    builder.put("fcy", Integer.valueOf('\u0444')); // CYRILLIC SMALL LETTER EF
    builder.put("khcy", Integer.valueOf('\u0445')); // CYRILLIC SMALL LETTER HA
    builder.put("tscy", Integer.valueOf('\u0446')); // CYRILLIC SMALL LETTER TSE
    builder.put("chcy", Integer.valueOf('\u0447')); // CYRILLIC SMALL LETTER CHE
    builder.put("shcy", Integer.valueOf('\u0448')); // CYRILLIC SMALL LETTER SHA
    builder.put("shchcy", Integer.valueOf('\u0449')); // CYRILLIC SMALL LETTER SHCHA
    builder.put("hardcy", Integer.valueOf('\u044a')); // CYRILLIC SMALL LETTER HARD SIGN
    builder.put("ycy", Integer.valueOf('\u044b')); // CYRILLIC SMALL LETTER YERU
    builder.put("softcy", Integer.valueOf('\u044c')); // CYRILLIC SMALL LETTER SOFT SIGN
    builder.put("ecy", Integer.valueOf('\u044d')); // CYRILLIC SMALL LETTER E
    builder.put("yucy", Integer.valueOf('\u044e')); // CYRILLIC SMALL LETTER YU
    builder.put("yacy", Integer.valueOf('\u044f')); // CYRILLIC SMALL LETTER YA
    builder.put("iocy", Integer.valueOf('\u0451')); // CYRILLIC SMALL LETTER IO
    builder.put("djcy", Integer.valueOf('\u0452')); // CYRILLIC SMALL LETTER DJE
    builder.put("gjcy", Integer.valueOf('\u0453')); // CYRILLIC SMALL LETTER GJE
    builder.put("jukcy", Integer.valueOf('\u0454')); // CYRILLIC SMALL LETTER UKRAINIAN IE
    builder.put("dscy", Integer.valueOf('\u0455')); // CYRILLIC SMALL LETTER DZE
    builder.put("iukcy", Integer.valueOf('\u0456')); // CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I
    builder.put("yicy", Integer.valueOf('\u0457')); // CYRILLIC SMALL LETTER YI
    builder.put("jsercy", Integer.valueOf('\u0458')); // CYRILLIC SMALL LETTER JE
    builder.put("ljcy", Integer.valueOf('\u0459')); // CYRILLIC SMALL LETTER LJE
    builder.put("njcy", Integer.valueOf('\u045a')); // CYRILLIC SMALL LETTER NJE
    builder.put("tshcy", Integer.valueOf('\u045b')); // CYRILLIC SMALL LETTER TSHE
    builder.put("kjcy", Integer.valueOf('\u045c')); // CYRILLIC SMALL LETTER KJE
    builder.put("ubrcy", Integer.valueOf('\u045e')); // CYRILLIC SMALL LETTER SHORT U
    builder.put("dzcy", Integer.valueOf('\u045f')); // CYRILLIC SMALL LETTER DZHE

    // General Punctuation
    builder.put("ensp", Integer.valueOf('\u2002')); // EN SPACE
    builder.put("emsp", Integer.valueOf('\u2003')); // EM SPACE
    builder.put("emsp13", Integer.valueOf('\u2004')); // THREE-PER-EM SPACE
    builder.put("emsp14", Integer.valueOf('\u2005')); // FOUR-PER-EM SPACE
    builder.put("numsp", Integer.valueOf('\u2007')); // FIGURE SPACE
    builder.put("puncsp", Integer.valueOf('\u2008')); // PUNCTUATION SPACE
    builder.put("thinsp", Integer.valueOf('\u2009')); // THIN SPACE
    builder.put("ThinSpace", Integer.valueOf('\u2009')); // THIN SPACE
    builder.put("hairsp", Integer.valueOf('\u200a')); // HAIR SPACE
    builder.put("VeryThinSpace", Integer.valueOf('\u200a')); // HAIR SPACE
    builder.put("ZeroWidthSpace", Integer.valueOf('\u200b')); // ZERO WIDTH SPACE
    builder.put("NegativeVeryThinSpace", Integer.valueOf('\u200b')); // ZERO WIDTH SPACE
    builder.put("NegativeThinSpace", Integer.valueOf('\u200b')); // ZERO WIDTH SPACE
    builder.put("NegativeMediumSpace", Integer.valueOf('\u200b')); // ZERO WIDTH SPACE
    builder.put("NegativeThickSpace", Integer.valueOf('\u200b')); // ZERO WIDTH SPACE
    builder.put("zwnj", Integer.valueOf('\u200c')); // ZERO WIDTH NON-JOINER
    builder.put("zwj", Integer.valueOf('\u200d')); // ZERO WIDTH JOINER
    builder.put("lrm", Integer.valueOf('\u200e')); // LEFT-TO-RIGHT MARK
    builder.put("rlm", Integer.valueOf('\u200f')); // RIGHT-TO-LEFT MARK
    builder.put("hyphen", Integer.valueOf('\u2010')); // HYPHEN
    builder.put("dash", Integer.valueOf('\u2010')); // HYPHEN
    builder.put("ndash", Integer.valueOf('\u2013')); // EN DASH
    builder.put("mdash", Integer.valueOf('\u2014')); // EM DASH
    builder.put("horbar", Integer.valueOf('\u2015')); // HORIZONTAL BAR
    builder.put("Verbar", Integer.valueOf('\u2016')); // DOUBLE VERTICAL LINE
    builder.put("Vert", Integer.valueOf('\u2016')); // DOUBLE VERTICAL LINE
    builder.put("lsquo", Integer.valueOf('\u2018')); // LEFT SINGLE QUOTATION MARK
    builder.put("OpenCurlyQuote", Integer.valueOf('\u2018')); // LEFT SINGLE QUOTATION MARK
    builder.put("rsquo", Integer.valueOf('\u2019')); // RIGHT SINGLE QUOTATION MARK
    builder.put("rsquor", Integer.valueOf('\u2019')); // RIGHT SINGLE QUOTATION MARK
    builder.put("CloseCurlyQuote", Integer.valueOf('\u2019')); // RIGHT SINGLE QUOTATION MARK
    builder.put("lsquor", Integer.valueOf('\u201a')); // SINGLE LOW-9 QUOTATION MARK
    builder.put("sbquo", Integer.valueOf('\u201a')); // SINGLE LOW-9 QUOTATION MARK
    builder.put("ldquo", Integer.valueOf('\u201c')); // LEFT DOUBLE QUOTATION MARK
    builder.put("OpenCurlyDoubleQuote", Integer.valueOf('\u201c')); // LEFT DOUBLE QUOTATION MARK
    builder.put("rdquo", Integer.valueOf('\u201d')); // RIGHT DOUBLE QUOTATION MARK
    builder.put("rdquor", Integer.valueOf('\u201d')); // RIGHT DOUBLE QUOTATION MARK
    builder.put("CloseCurlyDoubleQuote", Integer.valueOf('\u201d')); // RIGHT DOUBLE QUOTATION MARK
    builder.put("ldquor", Integer.valueOf('\u201e')); // DOUBLE LOW-9 QUOTATION MARK
    builder.put("bdquo", Integer.valueOf('\u201e')); // DOUBLE LOW-9 QUOTATION MARK
    builder.put("dagger", Integer.valueOf('\u2020')); // DAGGER
    builder.put("Dagger", Integer.valueOf('\u2021')); // DOUBLE DAGGER
    builder.put("ddagger", Integer.valueOf('\u2021')); // DOUBLE DAGGER
    builder.put("bull", Integer.valueOf('\u2022')); // BULLET
    builder.put("bullet", Integer.valueOf('\u2022')); // BULLET
    builder.put("nldr", Integer.valueOf('\u2025')); // TWO DOT LEADER
    builder.put("hellip", Integer.valueOf('\u2026')); // HORIZONTAL ELLIPSIS
    builder.put("mldr", Integer.valueOf('\u2026')); // HORIZONTAL ELLIPSIS
    builder.put("permil", Integer.valueOf('\u2030')); // PER MILLE SIGN
    builder.put("pertenk", Integer.valueOf('\u2031')); // PER TEN THOUSAND SIGN
    builder.put("prime", Integer.valueOf('\u2032')); // PRIME
    builder.put("Prime", Integer.valueOf('\u2033')); // DOUBLE PRIME
    builder.put("tprime", Integer.valueOf('\u2034')); // TRIPLE PRIME
    builder.put("bprime", Integer.valueOf('\u2035')); // REVERSED PRIME
    builder.put("backprime", Integer.valueOf('\u2035')); // REVERSED PRIME
    builder.put("lsaquo", Integer.valueOf('\u2039')); // SINGLE LEFT-POINTING ANGLE QUOTATION MARK
    builder.put("rsaquo", Integer.valueOf('\u203a')); // SINGLE RIGHT-POINTING ANGLE QUOTATION MARK
    builder.put("oline", Integer.valueOf('\u203e')); // OVERLINE
    builder.put("caret", Integer.valueOf('\u2041')); // CARET INSERTION POINT
    builder.put("hybull", Integer.valueOf('\u2043')); // HYPHEN BULLET
    builder.put("frasl", Integer.valueOf('\u2044')); // FRACTION SLASH
    builder.put("bsemi", Integer.valueOf('\u204f')); // REVERSED SEMICOLON
    builder.put("qprime", Integer.valueOf('\u2057')); // QUADRUPLE PRIME
    builder.put("MediumSpace", Integer.valueOf('\u205f')); // MEDIUM MATHEMATICAL SPACE
    builder.put("NoBreak", Integer.valueOf('\u2060')); // WORD JOINER
    builder.put("ApplyFunction", Integer.valueOf('\u2061')); // FUNCTION APPLICATION
    builder.put("af", Integer.valueOf('\u2061')); // FUNCTION APPLICATION
    builder.put("InvisibleTimes", Integer.valueOf('\u2062')); // INVISIBLE TIMES
    builder.put("it", Integer.valueOf('\u2062')); // INVISIBLE TIMES
    builder.put("InvisibleComma", Integer.valueOf('\u2063')); // INVISIBLE SEPARATOR
    builder.put("ic", Integer.valueOf('\u2063')); // INVISIBLE SEPARATOR

    // Currency Symbols
    builder.put("euro", Integer.valueOf('\u20ac')); // EURO SIGN

    // Combining Diacritical Marks for Symbols
    builder.put("tdot", Integer.valueOf('\u20db')); // COMBINING THREE DOTS ABOVE
    builder.put("TripleDot", Integer.valueOf('\u20db')); // COMBINING THREE DOTS ABOVE
    builder.put("DotDot", Integer.valueOf('\u20dc')); // COMBINING FOUR DOTS ABOVE

    // Letterlike Symbols
    builder.put("Copf", Integer.valueOf('\u2102')); // DOUBLE-STRUCK CAPITAL C
    builder.put("complexes", Integer.valueOf('\u2102')); // DOUBLE-STRUCK CAPITAL C
    builder.put("incare", Integer.valueOf('\u2105')); // CARE OF
    builder.put("gscr", Integer.valueOf('\u210a')); // SCRIPT SMALL G
    builder.put("hamilt", Integer.valueOf('\u210b')); // SCRIPT CAPITAL H
    builder.put("HilbertSpace", Integer.valueOf('\u210b')); // SCRIPT CAPITAL H
    builder.put("Hscr", Integer.valueOf('\u210b')); // SCRIPT CAPITAL H
    builder.put("Hfr", Integer.valueOf('\u210c')); // BLACK-LETTER CAPITAL H
    builder.put("Poincareplane", Integer.valueOf('\u210c')); // BLACK-LETTER CAPITAL H
    builder.put("quaternions", Integer.valueOf('\u210d')); // DOUBLE-STRUCK CAPITAL H
    builder.put("Hopf", Integer.valueOf('\u210d')); // DOUBLE-STRUCK CAPITAL H
    builder.put("planckh", Integer.valueOf('\u210e')); // PLANCK CONSTANT
    builder.put("planck", Integer.valueOf('\u210f')); // PLANCK CONSTANT OVER TWO PI
    builder.put("hbar", Integer.valueOf('\u210f')); // PLANCK CONSTANT OVER TWO PI
    builder.put("plankv", Integer.valueOf('\u210f')); // PLANCK CONSTANT OVER TWO PI
    builder.put("hslash", Integer.valueOf('\u210f')); // PLANCK CONSTANT OVER TWO PI
    builder.put("Iscr", Integer.valueOf('\u2110')); // SCRIPT CAPITAL I
    builder.put("imagline", Integer.valueOf('\u2110')); // SCRIPT CAPITAL I
    builder.put("image", Integer.valueOf('\u2111')); // BLACK-LETTER CAPITAL I
    builder.put("Im", Integer.valueOf('\u2111')); // BLACK-LETTER CAPITAL I
    builder.put("imagpart", Integer.valueOf('\u2111')); // BLACK-LETTER CAPITAL I
    builder.put("Ifr", Integer.valueOf('\u2111')); // BLACK-LETTER CAPITAL I
    builder.put("Lscr", Integer.valueOf('\u2112')); // SCRIPT CAPITAL L
    builder.put("lagran", Integer.valueOf('\u2112')); // SCRIPT CAPITAL L
    builder.put("Laplacetrf", Integer.valueOf('\u2112')); // SCRIPT CAPITAL L
    builder.put("ell", Integer.valueOf('\u2113')); // SCRIPT SMALL L
    builder.put("Nopf", Integer.valueOf('\u2115')); // DOUBLE-STRUCK CAPITAL N
    builder.put("naturals", Integer.valueOf('\u2115')); // DOUBLE-STRUCK CAPITAL N
    builder.put("numero", Integer.valueOf('\u2116')); // NUMERO SIGN
    builder.put("copysr", Integer.valueOf('\u2117')); // SOUND RECORDING COPYRIGHT
    builder.put("weierp", Integer.valueOf('\u2118')); // SCRIPT CAPITAL P
    builder.put("wp", Integer.valueOf('\u2118')); // SCRIPT CAPITAL P
    builder.put("Popf", Integer.valueOf('\u2119')); // DOUBLE-STRUCK CAPITAL P
    builder.put("primes", Integer.valueOf('\u2119')); // DOUBLE-STRUCK CAPITAL P
    builder.put("rationals", Integer.valueOf('\u211a')); // DOUBLE-STRUCK CAPITAL Q
    builder.put("Qopf", Integer.valueOf('\u211a')); // DOUBLE-STRUCK CAPITAL Q
    builder.put("Rscr", Integer.valueOf('\u211b')); // SCRIPT CAPITAL R
    builder.put("realine", Integer.valueOf('\u211b')); // SCRIPT CAPITAL R
    builder.put("real", Integer.valueOf('\u211c')); // BLACK-LETTER CAPITAL R
    builder.put("Re", Integer.valueOf('\u211c')); // BLACK-LETTER CAPITAL R
    builder.put("realpart", Integer.valueOf('\u211c')); // BLACK-LETTER CAPITAL R
    builder.put("Rfr", Integer.valueOf('\u211c')); // BLACK-LETTER CAPITAL R
    builder.put("reals", Integer.valueOf('\u211d')); // DOUBLE-STRUCK CAPITAL R
    builder.put("Ropf", Integer.valueOf('\u211d')); // DOUBLE-STRUCK CAPITAL R
    builder.put("rx", Integer.valueOf('\u211e')); // PRESCRIPTION TAKE
    builder.put("trade", Integer.valueOf('\u2122')); // TRADE MARK SIGN
    builder.put("TRADE", Integer.valueOf('\u2122')); // TRADE MARK SIGN
    builder.put("integers", Integer.valueOf('\u2124')); // DOUBLE-STRUCK CAPITAL Z
    builder.put("Zopf", Integer.valueOf('\u2124')); // DOUBLE-STRUCK CAPITAL Z
    builder.put("ohm", Integer.valueOf('\u2126')); // OHM SIGN
    builder.put("mho", Integer.valueOf('\u2127')); // INVERTED OHM SIGN
    builder.put("Zfr", Integer.valueOf('\u2128')); // BLACK-LETTER CAPITAL Z
    builder.put("zeetrf", Integer.valueOf('\u2128')); // BLACK-LETTER CAPITAL Z
    builder.put("iiota", Integer.valueOf('\u2129')); // TURNED GREEK SMALL LETTER IOTA
    builder.put("angst", Integer.valueOf('\u212b')); // ANGSTROM SIGN
    builder.put("bernou", Integer.valueOf('\u212c')); // SCRIPT CAPITAL B
    builder.put("Bernoullis", Integer.valueOf('\u212c')); // SCRIPT CAPITAL B
    builder.put("Bscr", Integer.valueOf('\u212c')); // SCRIPT CAPITAL B
    builder.put("Cfr", Integer.valueOf('\u212d')); // BLACK-LETTER CAPITAL C
    builder.put("Cayleys", Integer.valueOf('\u212d')); // BLACK-LETTER CAPITAL C
    builder.put("escr", Integer.valueOf('\u212f')); // SCRIPT SMALL E
    builder.put("Escr", Integer.valueOf('\u2130')); // SCRIPT CAPITAL E
    builder.put("expectation", Integer.valueOf('\u2130')); // SCRIPT CAPITAL E
    builder.put("Fscr", Integer.valueOf('\u2131')); // SCRIPT CAPITAL F
    builder.put("Fouriertrf", Integer.valueOf('\u2131')); // SCRIPT CAPITAL F
    builder.put("phmmat", Integer.valueOf('\u2133')); // SCRIPT CAPITAL M
    builder.put("Mellintrf", Integer.valueOf('\u2133')); // SCRIPT CAPITAL M
    builder.put("Mscr", Integer.valueOf('\u2133')); // SCRIPT CAPITAL M
    builder.put("order", Integer.valueOf('\u2134')); // SCRIPT SMALL O
    builder.put("orderof", Integer.valueOf('\u2134')); // SCRIPT SMALL O
    builder.put("oscr", Integer.valueOf('\u2134')); // SCRIPT SMALL O
    builder.put("alefsym", Integer.valueOf('\u2135')); // ALEF SYMBOL
    builder.put("aleph", Integer.valueOf('\u2135')); // ALEF SYMBOL
    builder.put("beth", Integer.valueOf('\u2136')); // BET SYMBOL
    builder.put("gimel", Integer.valueOf('\u2137')); // GIMEL SYMBOL
    builder.put("daleth", Integer.valueOf('\u2138')); // DALET SYMBOL
    builder.put("CapitalDifferentialD", Integer.valueOf('\u2145')); // DOUBLE-STRUCK ITALIC CAPITAL D
    builder.put("DD", Integer.valueOf('\u2145')); // DOUBLE-STRUCK ITALIC CAPITAL D
    builder.put("DifferentialD", Integer.valueOf('\u2146')); // DOUBLE-STRUCK ITALIC SMALL D
    builder.put("dd", Integer.valueOf('\u2146')); // DOUBLE-STRUCK ITALIC SMALL D
    builder.put("ExponentialE", Integer.valueOf('\u2147')); // DOUBLE-STRUCK ITALIC SMALL E
    builder.put("exponentiale", Integer.valueOf('\u2147')); // DOUBLE-STRUCK ITALIC SMALL E
    builder.put("ee", Integer.valueOf('\u2147')); // DOUBLE-STRUCK ITALIC SMALL E
    builder.put("ImaginaryI", Integer.valueOf('\u2148')); // DOUBLE-STRUCK ITALIC SMALL I
    builder.put("ii", Integer.valueOf('\u2148')); // DOUBLE-STRUCK ITALIC SMALL I

    // Number Forms
    builder.put("frac13", Integer.valueOf('\u2153')); // VULGAR FRACTION ONE THIRD
    builder.put("frac23", Integer.valueOf('\u2154')); // VULGAR FRACTION TWO THIRDS
    builder.put("frac15", Integer.valueOf('\u2155')); // VULGAR FRACTION ONE FIFTH
    builder.put("frac25", Integer.valueOf('\u2156')); // VULGAR FRACTION TWO FIFTHS
    builder.put("frac35", Integer.valueOf('\u2157')); // VULGAR FRACTION THREE FIFTHS
    builder.put("frac45", Integer.valueOf('\u2158')); // VULGAR FRACTION FOUR FIFTHS
    builder.put("frac16", Integer.valueOf('\u2159')); // VULGAR FRACTION ONE SIXTH
    builder.put("frac56", Integer.valueOf('\u215a')); // VULGAR FRACTION FIVE SIXTHS
    builder.put("frac18", Integer.valueOf('\u215b')); // VULGAR FRACTION ONE EIGHTH
    builder.put("frac38", Integer.valueOf('\u215c')); // VULGAR FRACTION THREE EIGHTHS
    builder.put("frac58", Integer.valueOf('\u215d')); // VULGAR FRACTION FIVE EIGHTHS
    builder.put("frac78", Integer.valueOf('\u215e')); // VULGAR FRACTION SEVEN EIGHTHS

    // Arrows
    builder.put("larr", Integer.valueOf('\u2190')); // LEFTWARDS ARROW
    builder.put("leftarrow", Integer.valueOf('\u2190')); // LEFTWARDS ARROW
    builder.put("LeftArrow", Integer.valueOf('\u2190')); // LEFTWARDS ARROW
    builder.put("slarr", Integer.valueOf('\u2190')); // LEFTWARDS ARROW
    builder.put("ShortLeftArrow", Integer.valueOf('\u2190')); // LEFTWARDS ARROW
    builder.put("uarr", Integer.valueOf('\u2191')); // UPWARDS ARROW
    builder.put("uparrow", Integer.valueOf('\u2191')); // UPWARDS ARROW
    builder.put("UpArrow", Integer.valueOf('\u2191')); // UPWARDS ARROW
    builder.put("ShortUpArrow", Integer.valueOf('\u2191')); // UPWARDS ARROW
    builder.put("rarr", Integer.valueOf('\u2192')); // RIGHTWARDS ARROW
    builder.put("rightarrow", Integer.valueOf('\u2192')); // RIGHTWARDS ARROW
    builder.put("RightArrow", Integer.valueOf('\u2192')); // RIGHTWARDS ARROW
    builder.put("srarr", Integer.valueOf('\u2192')); // RIGHTWARDS ARROW
    builder.put("ShortRightArrow", Integer.valueOf('\u2192')); // RIGHTWARDS ARROW
    builder.put("darr", Integer.valueOf('\u2193')); // DOWNWARDS ARROW
    builder.put("downarrow", Integer.valueOf('\u2193')); // DOWNWARDS ARROW
    builder.put("DownArrow", Integer.valueOf('\u2193')); // DOWNWARDS ARROW
    builder.put("ShortDownArrow", Integer.valueOf('\u2193')); // DOWNWARDS ARROW
    builder.put("harr", Integer.valueOf('\u2194')); // LEFT RIGHT ARROW
    builder.put("leftrightarrow", Integer.valueOf('\u2194')); // LEFT RIGHT ARROW
    builder.put("LeftRightArrow", Integer.valueOf('\u2194')); // LEFT RIGHT ARROW
    builder.put("varr", Integer.valueOf('\u2195')); // UP DOWN ARROW
    builder.put("updownarrow", Integer.valueOf('\u2195')); // UP DOWN ARROW
    builder.put("UpDownArrow", Integer.valueOf('\u2195')); // UP DOWN ARROW
    builder.put("nwarr", Integer.valueOf('\u2196')); // NORTH WEST ARROW
    builder.put("UpperLeftArrow", Integer.valueOf('\u2196')); // NORTH WEST ARROW
    builder.put("nwarrow", Integer.valueOf('\u2196')); // NORTH WEST ARROW
    builder.put("nearr", Integer.valueOf('\u2197')); // NORTH EAST ARROW
    builder.put("UpperRightArrow", Integer.valueOf('\u2197')); // NORTH EAST ARROW
    builder.put("nearrow", Integer.valueOf('\u2197')); // NORTH EAST ARROW
    builder.put("searr", Integer.valueOf('\u2198')); // SOUTH EAST ARROW
    builder.put("searrow", Integer.valueOf('\u2198')); // SOUTH EAST ARROW
    builder.put("LowerRightArrow", Integer.valueOf('\u2198')); // SOUTH EAST ARROW
    builder.put("swarr", Integer.valueOf('\u2199')); // SOUTH WEST ARROW
    builder.put("swarrow", Integer.valueOf('\u2199')); // SOUTH WEST ARROW
    builder.put("LowerLeftArrow", Integer.valueOf('\u2199')); // SOUTH WEST ARROW
    builder.put("nlarr", Integer.valueOf('\u219a')); // LEFTWARDS ARROW WITH STROKE
    builder.put("nleftarrow", Integer.valueOf('\u219a')); // LEFTWARDS ARROW WITH STROKE
    builder.put("nrarr", Integer.valueOf('\u219b')); // RIGHTWARDS ARROW WITH STROKE
    builder.put("nrightarrow", Integer.valueOf('\u219b')); // RIGHTWARDS ARROW WITH STROKE
    builder.put("rarrw", Integer.valueOf('\u219d')); // RIGHTWARDS WAVE ARROW
    builder.put("rightsquigarrow", Integer.valueOf('\u219d')); // RIGHTWARDS WAVE ARROW
    builder.put("Larr", Integer.valueOf('\u219e')); // LEFTWARDS TWO HEADED ARROW
    builder.put("twoheadleftarrow", Integer.valueOf('\u219e')); // LEFTWARDS TWO HEADED ARROW
    builder.put("Uarr", Integer.valueOf('\u219f')); // UPWARDS TWO HEADED ARROW
    builder.put("Rarr", Integer.valueOf('\u21a0')); // RIGHTWARDS TWO HEADED ARROW
    builder.put("twoheadrightarrow", Integer.valueOf('\u21a0')); // RIGHTWARDS TWO HEADED ARROW
    builder.put("Darr", Integer.valueOf('\u21a1')); // DOWNWARDS TWO HEADED ARROW
    builder.put("larrtl", Integer.valueOf('\u21a2')); // LEFTWARDS ARROW WITH TAIL
    builder.put("leftarrowtail", Integer.valueOf('\u21a2')); // LEFTWARDS ARROW WITH TAIL
    builder.put("rarrtl", Integer.valueOf('\u21a3')); // RIGHTWARDS ARROW WITH TAIL
    builder.put("rightarrowtail", Integer.valueOf('\u21a3')); // RIGHTWARDS ARROW WITH TAIL
    builder.put("LeftTeeArrow", Integer.valueOf('\u21a4')); // LEFTWARDS ARROW FROM BAR
    builder.put("mapstoleft", Integer.valueOf('\u21a4')); // LEFTWARDS ARROW FROM BAR
    builder.put("UpTeeArrow", Integer.valueOf('\u21a5')); // UPWARDS ARROW FROM BAR
    builder.put("mapstoup", Integer.valueOf('\u21a5')); // UPWARDS ARROW FROM BAR
    builder.put("map", Integer.valueOf('\u21a6')); // RIGHTWARDS ARROW FROM BAR
    builder.put("RightTeeArrow", Integer.valueOf('\u21a6')); // RIGHTWARDS ARROW FROM BAR
    builder.put("mapsto", Integer.valueOf('\u21a6')); // RIGHTWARDS ARROW FROM BAR
    builder.put("DownTeeArrow", Integer.valueOf('\u21a7')); // DOWNWARDS ARROW FROM BAR
    builder.put("mapstodown", Integer.valueOf('\u21a7')); // DOWNWARDS ARROW FROM BAR
    builder.put("larrhk", Integer.valueOf('\u21a9')); // LEFTWARDS ARROW WITH HOOK
    builder.put("hookleftarrow", Integer.valueOf('\u21a9')); // LEFTWARDS ARROW WITH HOOK
    builder.put("rarrhk", Integer.valueOf('\u21aa')); // RIGHTWARDS ARROW WITH HOOK
    builder.put("hookrightarrow", Integer.valueOf('\u21aa')); // RIGHTWARDS ARROW WITH HOOK
    builder.put("larrlp", Integer.valueOf('\u21ab')); // LEFTWARDS ARROW WITH LOOP
    builder.put("looparrowleft", Integer.valueOf('\u21ab')); // LEFTWARDS ARROW WITH LOOP
    builder.put("rarrlp", Integer.valueOf('\u21ac')); // RIGHTWARDS ARROW WITH LOOP
    builder.put("looparrowright", Integer.valueOf('\u21ac')); // RIGHTWARDS ARROW WITH LOOP
    builder.put("harrw", Integer.valueOf('\u21ad')); // LEFT RIGHT WAVE ARROW
    builder.put("leftrightsquigarrow", Integer.valueOf('\u21ad')); // LEFT RIGHT WAVE ARROW
    builder.put("nharr", Integer.valueOf('\u21ae')); // LEFT RIGHT ARROW WITH STROKE
    builder.put("nleftrightarrow", Integer.valueOf('\u21ae')); // LEFT RIGHT ARROW WITH STROKE
    builder.put("lsh", Integer.valueOf('\u21b0')); // UPWARDS ARROW WITH TIP LEFTWARDS
    builder.put("Lsh", Integer.valueOf('\u21b0')); // UPWARDS ARROW WITH TIP LEFTWARDS
    builder.put("rsh", Integer.valueOf('\u21b1')); // UPWARDS ARROW WITH TIP RIGHTWARDS
    builder.put("Rsh", Integer.valueOf('\u21b1')); // UPWARDS ARROW WITH TIP RIGHTWARDS
    builder.put("ldsh", Integer.valueOf('\u21b2')); // DOWNWARDS ARROW WITH TIP LEFTWARDS
    builder.put("rdsh", Integer.valueOf('\u21b3')); // DOWNWARDS ARROW WITH TIP RIGHTWARDS
    builder.put("crarr", Integer.valueOf('\u21b5')); // DOWNWARDS ARROW WITH CORNER LEFTWARDS
    builder.put("cularr", Integer.valueOf('\u21b6')); // ANTICLOCKWISE TOP SEMICIRCLE ARROW
    builder.put("curvearrowleft", Integer.valueOf('\u21b6')); // ANTICLOCKWISE TOP SEMICIRCLE ARROW
    builder.put("curarr", Integer.valueOf('\u21b7')); // CLOCKWISE TOP SEMICIRCLE ARROW
    builder.put("curvearrowright", Integer.valueOf('\u21b7')); // CLOCKWISE TOP SEMICIRCLE ARROW
    builder.put("olarr", Integer.valueOf('\u21ba')); // ANTICLOCKWISE OPEN CIRCLE ARROW
    builder.put("circlearrowleft", Integer.valueOf('\u21ba')); // ANTICLOCKWISE OPEN CIRCLE ARROW
    builder.put("orarr", Integer.valueOf('\u21bb')); // CLOCKWISE OPEN CIRCLE ARROW
    builder.put("circlearrowright", Integer.valueOf('\u21bb')); // CLOCKWISE OPEN CIRCLE ARROW
    builder.put("lharu", Integer.valueOf('\u21bc')); // LEFTWARDS HARPOON WITH BARB UPWARDS
    builder.put("LeftVector", Integer.valueOf('\u21bc')); // LEFTWARDS HARPOON WITH BARB UPWARDS
    builder.put("leftharpoonup", Integer.valueOf('\u21bc')); // LEFTWARDS HARPOON WITH BARB UPWARDS
    builder.put("lhard", Integer.valueOf('\u21bd')); // LEFTWARDS HARPOON WITH BARB DOWNWARDS
    builder.put("leftharpoondown", Integer.valueOf('\u21bd')); // LEFTWARDS HARPOON WITH BARB DOWNWARDS
    builder.put("DownLeftVector", Integer.valueOf('\u21bd')); // LEFTWARDS HARPOON WITH BARB DOWNWARDS
    builder.put("uharr", Integer.valueOf('\u21be')); // UPWARDS HARPOON WITH BARB RIGHTWARDS
    builder.put("upharpoonright", Integer.valueOf('\u21be')); // UPWARDS HARPOON WITH BARB RIGHTWARDS
    builder.put("RightUpVector", Integer.valueOf('\u21be')); // UPWARDS HARPOON WITH BARB RIGHTWARDS
    builder.put("uharl", Integer.valueOf('\u21bf')); // UPWARDS HARPOON WITH BARB LEFTWARDS
    builder.put("upharpoonleft", Integer.valueOf('\u21bf')); // UPWARDS HARPOON WITH BARB LEFTWARDS
    builder.put("LeftUpVector", Integer.valueOf('\u21bf')); // UPWARDS HARPOON WITH BARB LEFTWARDS
    builder.put("rharu", Integer.valueOf('\u21c0')); // RIGHTWARDS HARPOON WITH BARB UPWARDS
    builder.put("RightVector", Integer.valueOf('\u21c0')); // RIGHTWARDS HARPOON WITH BARB UPWARDS
    builder.put("rightharpoonup", Integer.valueOf('\u21c0')); // RIGHTWARDS HARPOON WITH BARB UPWARDS
    builder.put("rhard", Integer.valueOf('\u21c1')); // RIGHTWARDS HARPOON WITH BARB DOWNWARDS
    builder.put("rightharpoondown", Integer.valueOf('\u21c1')); // RIGHTWARDS HARPOON WITH BARB DOWNWARDS
    builder.put("DownRightVector", Integer.valueOf('\u21c1')); // RIGHTWARDS HARPOON WITH BARB DOWNWARDS
    builder.put("dharr", Integer.valueOf('\u21c2')); // DOWNWARDS HARPOON WITH BARB RIGHTWARDS
    builder.put("RightDownVector", Integer.valueOf('\u21c2')); // DOWNWARDS HARPOON WITH BARB RIGHTWARDS
    builder.put("downharpoonright", Integer.valueOf('\u21c2')); // DOWNWARDS HARPOON WITH BARB RIGHTWARDS
    builder.put("dharl", Integer.valueOf('\u21c3')); // DOWNWARDS HARPOON WITH BARB LEFTWARDS
    builder.put("LeftDownVector", Integer.valueOf('\u21c3')); // DOWNWARDS HARPOON WITH BARB LEFTWARDS
    builder.put("downharpoonleft", Integer.valueOf('\u21c3')); // DOWNWARDS HARPOON WITH BARB LEFTWARDS
    builder.put("rlarr", Integer.valueOf('\u21c4')); // RIGHTWARDS ARROW OVER LEFTWARDS ARROW
    builder.put("rightleftarrows", Integer.valueOf('\u21c4')); // RIGHTWARDS ARROW OVER LEFTWARDS ARROW
    builder.put("RightArrowLeftArrow", Integer.valueOf('\u21c4')); // RIGHTWARDS ARROW OVER LEFTWARDS ARROW
    builder.put("udarr", Integer.valueOf('\u21c5')); // UPWARDS ARROW LEFTWARDS OF DOWNWARDS ARROW
    builder.put("UpArrowDownArrow", Integer.valueOf('\u21c5')); // UPWARDS ARROW LEFTWARDS OF DOWNWARDS ARROW
    builder.put("lrarr", Integer.valueOf('\u21c6')); // LEFTWARDS ARROW OVER RIGHTWARDS ARROW
    builder.put("leftrightarrows", Integer.valueOf('\u21c6')); // LEFTWARDS ARROW OVER RIGHTWARDS ARROW
    builder.put("LeftArrowRightArrow", Integer.valueOf('\u21c6')); // LEFTWARDS ARROW OVER RIGHTWARDS ARROW
    builder.put("llarr", Integer.valueOf('\u21c7')); // LEFTWARDS PAIRED ARROWS
    builder.put("leftleftarrows", Integer.valueOf('\u21c7')); // LEFTWARDS PAIRED ARROWS
    builder.put("uuarr", Integer.valueOf('\u21c8')); // UPWARDS PAIRED ARROWS
    builder.put("upuparrows", Integer.valueOf('\u21c8')); // UPWARDS PAIRED ARROWS
    builder.put("rrarr", Integer.valueOf('\u21c9')); // RIGHTWARDS PAIRED ARROWS
    builder.put("rightrightarrows", Integer.valueOf('\u21c9')); // RIGHTWARDS PAIRED ARROWS
    builder.put("ddarr", Integer.valueOf('\u21ca')); // DOWNWARDS PAIRED ARROWS
    builder.put("downdownarrows", Integer.valueOf('\u21ca')); // DOWNWARDS PAIRED ARROWS
    builder.put("lrhar", Integer.valueOf('\u21cb')); // LEFTWARDS HARPOON OVER RIGHTWARDS HARPOON
    builder.put("ReverseEquilibrium", Integer.valueOf('\u21cb')); // LEFTWARDS HARPOON OVER RIGHTWARDS HARPOON
    builder.put("leftrightharpoons", Integer.valueOf('\u21cb')); // LEFTWARDS HARPOON OVER RIGHTWARDS HARPOON
    builder.put("rlhar", Integer.valueOf('\u21cc')); // RIGHTWARDS HARPOON OVER LEFTWARDS HARPOON
    builder.put("rightleftharpoons", Integer.valueOf('\u21cc')); // RIGHTWARDS HARPOON OVER LEFTWARDS HARPOON
    builder.put("Equilibrium", Integer.valueOf('\u21cc')); // RIGHTWARDS HARPOON OVER LEFTWARDS HARPOON
    builder.put("nlArr", Integer.valueOf('\u21cd')); // LEFTWARDS DOUBLE ARROW WITH STROKE
    builder.put("nLeftarrow", Integer.valueOf('\u21cd')); // LEFTWARDS DOUBLE ARROW WITH STROKE
    builder.put("nhArr", Integer.valueOf('\u21ce')); // LEFT RIGHT DOUBLE ARROW WITH STROKE
    builder.put("nLeftrightarrow", Integer.valueOf('\u21ce')); // LEFT RIGHT DOUBLE ARROW WITH STROKE
    builder.put("nrArr", Integer.valueOf('\u21cf')); // RIGHTWARDS DOUBLE ARROW WITH STROKE
    builder.put("nRightarrow", Integer.valueOf('\u21cf')); // RIGHTWARDS DOUBLE ARROW WITH STROKE
    builder.put("lArr", Integer.valueOf('\u21d0')); // LEFTWARDS DOUBLE ARROW
    builder.put("Leftarrow", Integer.valueOf('\u21d0')); // LEFTWARDS DOUBLE ARROW
    builder.put("DoubleLeftArrow", Integer.valueOf('\u21d0')); // LEFTWARDS DOUBLE ARROW
    builder.put("uArr", Integer.valueOf('\u21d1')); // UPWARDS DOUBLE ARROW
    builder.put("Uparrow", Integer.valueOf('\u21d1')); // UPWARDS DOUBLE ARROW
    builder.put("DoubleUpArrow", Integer.valueOf('\u21d1')); // UPWARDS DOUBLE ARROW
    builder.put("rArr", Integer.valueOf('\u21d2')); // RIGHTWARDS DOUBLE ARROW
    builder.put("Rightarrow", Integer.valueOf('\u21d2')); // RIGHTWARDS DOUBLE ARROW
    builder.put("Implies", Integer.valueOf('\u21d2')); // RIGHTWARDS DOUBLE ARROW
    builder.put("DoubleRightArrow", Integer.valueOf('\u21d2')); // RIGHTWARDS DOUBLE ARROW
    builder.put("dArr", Integer.valueOf('\u21d3')); // DOWNWARDS DOUBLE ARROW
    builder.put("Downarrow", Integer.valueOf('\u21d3')); // DOWNWARDS DOUBLE ARROW
    builder.put("DoubleDownArrow", Integer.valueOf('\u21d3')); // DOWNWARDS DOUBLE ARROW
    builder.put("hArr", Integer.valueOf('\u21d4')); // LEFT RIGHT DOUBLE ARROW
    builder.put("Leftrightarrow", Integer.valueOf('\u21d4')); // LEFT RIGHT DOUBLE ARROW
    builder.put("DoubleLeftRightArrow", Integer.valueOf('\u21d4')); // LEFT RIGHT DOUBLE ARROW
    builder.put("iff", Integer.valueOf('\u21d4')); // LEFT RIGHT DOUBLE ARROW
    builder.put("vArr", Integer.valueOf('\u21d5')); // UP DOWN DOUBLE ARROW
    builder.put("Updownarrow", Integer.valueOf('\u21d5')); // UP DOWN DOUBLE ARROW
    builder.put("DoubleUpDownArrow", Integer.valueOf('\u21d5')); // UP DOWN DOUBLE ARROW
    builder.put("nwArr", Integer.valueOf('\u21d6')); // NORTH WEST DOUBLE ARROW
    builder.put("neArr", Integer.valueOf('\u21d7')); // NORTH EAST DOUBLE ARROW
    builder.put("seArr", Integer.valueOf('\u21d8')); // SOUTH EAST DOUBLE ARROW
    builder.put("swArr", Integer.valueOf('\u21d9')); // SOUTH WEST DOUBLE ARROW
    builder.put("lAarr", Integer.valueOf('\u21da')); // LEFTWARDS TRIPLE ARROW
    builder.put("Lleftarrow", Integer.valueOf('\u21da')); // LEFTWARDS TRIPLE ARROW
    builder.put("rAarr", Integer.valueOf('\u21db')); // RIGHTWARDS TRIPLE ARROW
    builder.put("Rrightarrow", Integer.valueOf('\u21db')); // RIGHTWARDS TRIPLE ARROW
    builder.put("zigrarr", Integer.valueOf('\u21dd')); // RIGHTWARDS SQUIGGLE ARROW
    builder.put("larrb", Integer.valueOf('\u21e4')); // LEFTWARDS ARROW TO BAR
    builder.put("LeftArrowBar", Integer.valueOf('\u21e4')); // LEFTWARDS ARROW TO BAR
    builder.put("rarrb", Integer.valueOf('\u21e5')); // RIGHTWARDS ARROW TO BAR
    builder.put("RightArrowBar", Integer.valueOf('\u21e5')); // RIGHTWARDS ARROW TO BAR
    builder.put("duarr", Integer.valueOf('\u21f5')); // DOWNWARDS ARROW LEFTWARDS OF UPWARDS ARROW
    builder.put("DownArrowUpArrow", Integer.valueOf('\u21f5')); // DOWNWARDS ARROW LEFTWARDS OF UPWARDS ARROW
    builder.put("loarr", Integer.valueOf('\u21fd')); // LEFTWARDS OPEN-HEADED ARROW
    builder.put("roarr", Integer.valueOf('\u21fe')); // RIGHTWARDS OPEN-HEADED ARROW
    builder.put("hoarr", Integer.valueOf('\u21ff')); // LEFT RIGHT OPEN-HEADED ARROW

    // Mathematical Operators
    builder.put("forall", Integer.valueOf('\u2200')); // FOR ALL
    builder.put("ForAll", Integer.valueOf('\u2200')); // FOR ALL
    builder.put("comp", Integer.valueOf('\u2201')); // COMPLEMENT
    builder.put("complement", Integer.valueOf('\u2201')); // COMPLEMENT
    builder.put("part", Integer.valueOf('\u2202')); // PARTIAL DIFFERENTIAL
    builder.put("PartialD", Integer.valueOf('\u2202')); // PARTIAL DIFFERENTIAL
    builder.put("exist", Integer.valueOf('\u2203')); // THERE EXISTS
    builder.put("Exists", Integer.valueOf('\u2203')); // THERE EXISTS
    builder.put("nexist", Integer.valueOf('\u2204')); // THERE DOES NOT EXIST
    builder.put("NotExists", Integer.valueOf('\u2204')); // THERE DOES NOT EXIST
    builder.put("nexists", Integer.valueOf('\u2204')); // THERE DOES NOT EXIST
    builder.put("empty", Integer.valueOf('\u2205')); // EMPTY SET
    builder.put("emptyset", Integer.valueOf('\u2205')); // EMPTY SET
    builder.put("emptyv", Integer.valueOf('\u2205')); // EMPTY SET
    builder.put("varnothing", Integer.valueOf('\u2205')); // EMPTY SET
    builder.put("nabla", Integer.valueOf('\u2207')); // NABLA
    builder.put("Del", Integer.valueOf('\u2207')); // NABLA
    builder.put("isin", Integer.valueOf('\u2208')); // ELEMENT OF
    builder.put("isinv", Integer.valueOf('\u2208')); // ELEMENT OF
    builder.put("Element", Integer.valueOf('\u2208')); // ELEMENT OF
    builder.put("in", Integer.valueOf('\u2208')); // ELEMENT OF
    builder.put("notin", Integer.valueOf('\u2209')); // NOT AN ELEMENT OF
    builder.put("NotElement", Integer.valueOf('\u2209')); // NOT AN ELEMENT OF
    builder.put("notinva", Integer.valueOf('\u2209')); // NOT AN ELEMENT OF
    builder.put("niv", Integer.valueOf('\u220b')); // CONTAINS AS MEMBER
    builder.put("ReverseElement", Integer.valueOf('\u220b')); // CONTAINS AS MEMBER
    builder.put("ni", Integer.valueOf('\u220b')); // CONTAINS AS MEMBER
    builder.put("SuchThat", Integer.valueOf('\u220b')); // CONTAINS AS MEMBER
    builder.put("notni", Integer.valueOf('\u220c')); // DOES NOT CONTAIN AS MEMBER
    builder.put("notniva", Integer.valueOf('\u220c')); // DOES NOT CONTAIN AS MEMBER
    builder.put("NotReverseElement", Integer.valueOf('\u220c')); // DOES NOT CONTAIN AS MEMBER
    builder.put("prod", Integer.valueOf('\u220f')); // N-ARY PRODUCT
    builder.put("Product", Integer.valueOf('\u220f')); // N-ARY PRODUCT
    builder.put("coprod", Integer.valueOf('\u2210')); // N-ARY COPRODUCT
    builder.put("Coproduct", Integer.valueOf('\u2210')); // N-ARY COPRODUCT
    builder.put("sum", Integer.valueOf('\u2211')); // N-ARY SUMMATION
    builder.put("Sum", Integer.valueOf('\u2211')); // N-ARY SUMMATION
    builder.put("minus", Integer.valueOf('\u2212')); // MINUS SIGN
    builder.put("mnplus", Integer.valueOf('\u2213')); // MINUS-OR-PLUS SIGN
    builder.put("mp", Integer.valueOf('\u2213')); // MINUS-OR-PLUS SIGN
    builder.put("MinusPlus", Integer.valueOf('\u2213')); // MINUS-OR-PLUS SIGN
    builder.put("plusdo", Integer.valueOf('\u2214')); // DOT PLUS
    builder.put("dotplus", Integer.valueOf('\u2214')); // DOT PLUS
    builder.put("setmn", Integer.valueOf('\u2216')); // SET MINUS
    builder.put("setminus", Integer.valueOf('\u2216')); // SET MINUS
    builder.put("Backslash", Integer.valueOf('\u2216')); // SET MINUS
    builder.put("ssetmn", Integer.valueOf('\u2216')); // SET MINUS
    builder.put("smallsetminus", Integer.valueOf('\u2216')); // SET MINUS
    builder.put("lowast", Integer.valueOf('\u2217')); // ASTERISK OPERATOR
    builder.put("compfn", Integer.valueOf('\u2218')); // RING OPERATOR
    builder.put("SmallCircle", Integer.valueOf('\u2218')); // RING OPERATOR
    builder.put("radic", Integer.valueOf('\u221a')); // SQUARE ROOT
    builder.put("Sqrt", Integer.valueOf('\u221a')); // SQUARE ROOT
    builder.put("prop", Integer.valueOf('\u221d')); // PROPORTIONAL TO
    builder.put("propto", Integer.valueOf('\u221d')); // PROPORTIONAL TO
    builder.put("Proportional", Integer.valueOf('\u221d')); // PROPORTIONAL TO
    builder.put("vprop", Integer.valueOf('\u221d')); // PROPORTIONAL TO
    builder.put("varpropto", Integer.valueOf('\u221d')); // PROPORTIONAL TO
    builder.put("infin", Integer.valueOf('\u221e')); // INFINITY
    builder.put("angrt", Integer.valueOf('\u221f')); // RIGHT ANGLE
    builder.put("ang", Integer.valueOf('\u2220')); // ANGLE
    builder.put("angle", Integer.valueOf('\u2220')); // ANGLE
    builder.put("angmsd", Integer.valueOf('\u2221')); // MEASURED ANGLE
    builder.put("measuredangle", Integer.valueOf('\u2221')); // MEASURED ANGLE
    builder.put("angsph", Integer.valueOf('\u2222')); // SPHERICAL ANGLE
    builder.put("mid", Integer.valueOf('\u2223')); // DIVIDES
    builder.put("VerticalBar", Integer.valueOf('\u2223')); // DIVIDES
    builder.put("smid", Integer.valueOf('\u2223')); // DIVIDES
    builder.put("shortmid", Integer.valueOf('\u2223')); // DIVIDES
    builder.put("nmid", Integer.valueOf('\u2224')); // DOES NOT DIVIDE
    builder.put("NotVerticalBar", Integer.valueOf('\u2224')); // DOES NOT DIVIDE
    builder.put("nsmid", Integer.valueOf('\u2224')); // DOES NOT DIVIDE
    builder.put("nshortmid", Integer.valueOf('\u2224')); // DOES NOT DIVIDE
    builder.put("par", Integer.valueOf('\u2225')); // PARALLEL TO
    builder.put("parallel", Integer.valueOf('\u2225')); // PARALLEL TO
    builder.put("DoubleVerticalBar", Integer.valueOf('\u2225')); // PARALLEL TO
    builder.put("spar", Integer.valueOf('\u2225')); // PARALLEL TO
    builder.put("shortparallel", Integer.valueOf('\u2225')); // PARALLEL TO
    builder.put("npar", Integer.valueOf('\u2226')); // NOT PARALLEL TO
    builder.put("nparallel", Integer.valueOf('\u2226')); // NOT PARALLEL TO
    builder.put("NotDoubleVerticalBar", Integer.valueOf('\u2226')); // NOT PARALLEL TO
    builder.put("nspar", Integer.valueOf('\u2226')); // NOT PARALLEL TO
    builder.put("nshortparallel", Integer.valueOf('\u2226')); // NOT PARALLEL TO
    builder.put("and", Integer.valueOf('\u2227')); // LOGICAL AND
    builder.put("wedge", Integer.valueOf('\u2227')); // LOGICAL AND
    builder.put("or", Integer.valueOf('\u2228')); // LOGICAL OR
    builder.put("vee", Integer.valueOf('\u2228')); // LOGICAL OR
    builder.put("cap", Integer.valueOf('\u2229')); // INTERSECTION
    builder.put("cup", Integer.valueOf('\u222a')); // UNION
    builder.put("int", Integer.valueOf('\u222b')); // INTEGRAL
    builder.put("Integral", Integer.valueOf('\u222b')); // INTEGRAL
    builder.put("Int", Integer.valueOf('\u222c')); // DOUBLE INTEGRAL
    builder.put("tint", Integer.valueOf('\u222d')); // TRIPLE INTEGRAL
    builder.put("iiint", Integer.valueOf('\u222d')); // TRIPLE INTEGRAL
    builder.put("conint", Integer.valueOf('\u222e')); // CONTOUR INTEGRAL
    builder.put("oint", Integer.valueOf('\u222e')); // CONTOUR INTEGRAL
    builder.put("ContourIntegral", Integer.valueOf('\u222e')); // CONTOUR INTEGRAL
    builder.put("Conint", Integer.valueOf('\u222f')); // SURFACE INTEGRAL
    builder.put("DoubleContourIntegral", Integer.valueOf('\u222f')); // SURFACE INTEGRAL
    builder.put("Cconint", Integer.valueOf('\u2230')); // VOLUME INTEGRAL
    builder.put("cwint", Integer.valueOf('\u2231')); // CLOCKWISE INTEGRAL
    builder.put("cwconint", Integer.valueOf('\u2232')); // CLOCKWISE CONTOUR INTEGRAL
    builder.put("ClockwiseContourIntegral", Integer.valueOf('\u2232')); // CLOCKWISE CONTOUR INTEGRAL
    builder.put("awconint", Integer.valueOf('\u2233')); // ANTICLOCKWISE CONTOUR INTEGRAL
    builder.put("CounterClockwiseContourIntegral", Integer.valueOf('\u2233')); // ANTICLOCKWISE CONTOUR INTEGRAL
    builder.put("there4", Integer.valueOf('\u2234')); // THEREFORE
    builder.put("therefore", Integer.valueOf('\u2234')); // THEREFORE
    builder.put("Therefore", Integer.valueOf('\u2234')); // THEREFORE
    builder.put("becaus", Integer.valueOf('\u2235')); // BECAUSE
    builder.put("because", Integer.valueOf('\u2235')); // BECAUSE
    builder.put("Because", Integer.valueOf('\u2235')); // BECAUSE
    builder.put("ratio", Integer.valueOf('\u2236')); // RATIO
    builder.put("Colon", Integer.valueOf('\u2237')); // PROPORTION
    builder.put("Proportion", Integer.valueOf('\u2237')); // PROPORTION
    builder.put("minusd", Integer.valueOf('\u2238')); // DOT MINUS
    builder.put("dotminus", Integer.valueOf('\u2238')); // DOT MINUS
    builder.put("mDDot", Integer.valueOf('\u223a')); // GEOMETRIC PROPORTION
    builder.put("homtht", Integer.valueOf('\u223b')); // HOMOTHETIC
    builder.put("sim", Integer.valueOf('\u223c')); // TILDE OPERATOR
    builder.put("Tilde", Integer.valueOf('\u223c')); // TILDE OPERATOR
    builder.put("thksim", Integer.valueOf('\u223c')); // TILDE OPERATOR
    builder.put("thicksim", Integer.valueOf('\u223c')); // TILDE OPERATOR
    builder.put("bsim", Integer.valueOf('\u223d')); // REVERSED TILDE
    builder.put("backsim", Integer.valueOf('\u223d')); // REVERSED TILDE
    builder.put("ac", Integer.valueOf('\u223e')); // INVERTED LAZY S
    builder.put("mstpos", Integer.valueOf('\u223e')); // INVERTED LAZY S
    builder.put("acd", Integer.valueOf('\u223f')); // SINE WAVE
    builder.put("wreath", Integer.valueOf('\u2240')); // WREATH PRODUCT
    builder.put("VerticalTilde", Integer.valueOf('\u2240')); // WREATH PRODUCT
    builder.put("wr", Integer.valueOf('\u2240')); // WREATH PRODUCT
    builder.put("nsim", Integer.valueOf('\u2241')); // NOT TILDE
    builder.put("NotTilde", Integer.valueOf('\u2241')); // NOT TILDE
    builder.put("esim", Integer.valueOf('\u2242')); // MINUS TILDE
    builder.put("EqualTilde", Integer.valueOf('\u2242')); // MINUS TILDE
    builder.put("eqsim", Integer.valueOf('\u2242')); // MINUS TILDE
    builder.put("sime", Integer.valueOf('\u2243')); // ASYMPTOTICALLY EQUAL TO
    builder.put("TildeEqual", Integer.valueOf('\u2243')); // ASYMPTOTICALLY EQUAL TO
    builder.put("simeq", Integer.valueOf('\u2243')); // ASYMPTOTICALLY EQUAL TO
    builder.put("nsime", Integer.valueOf('\u2244')); // NOT ASYMPTOTICALLY EQUAL TO
    builder.put("nsimeq", Integer.valueOf('\u2244')); // NOT ASYMPTOTICALLY EQUAL TO
    builder.put("NotTildeEqual", Integer.valueOf('\u2244')); // NOT ASYMPTOTICALLY EQUAL TO
    builder.put("cong", Integer.valueOf('\u2245')); // APPROXIMATELY EQUAL TO
    builder.put("TildeFullEqual", Integer.valueOf('\u2245')); // APPROXIMATELY EQUAL TO
    builder.put("simne", Integer.valueOf('\u2246')); // APPROXIMATELY BUT NOT ACTUALLY EQUAL TO
    builder.put("ncong", Integer.valueOf('\u2247')); // NEITHER APPROXIMATELY NOR ACTUALLY EQUAL TO
    builder.put("NotTildeFullEqual", Integer.valueOf('\u2247')); // NEITHER APPROXIMATELY NOR ACTUALLY EQUAL TO
    builder.put("asymp", Integer.valueOf('\u2248')); // ALMOST EQUAL TO
    builder.put("ap", Integer.valueOf('\u2248')); // ALMOST EQUAL TO
    builder.put("TildeTilde", Integer.valueOf('\u2248')); // ALMOST EQUAL TO
    builder.put("approx", Integer.valueOf('\u2248')); // ALMOST EQUAL TO
    builder.put("thkap", Integer.valueOf('\u2248')); // ALMOST EQUAL TO
    builder.put("thickapprox", Integer.valueOf('\u2248')); // ALMOST EQUAL TO
    builder.put("nap", Integer.valueOf('\u2249')); // NOT ALMOST EQUAL TO
    builder.put("NotTildeTilde", Integer.valueOf('\u2249')); // NOT ALMOST EQUAL TO
    builder.put("napprox", Integer.valueOf('\u2249')); // NOT ALMOST EQUAL TO
    builder.put("ape", Integer.valueOf('\u224a')); // ALMOST EQUAL OR EQUAL TO
    builder.put("approxeq", Integer.valueOf('\u224a')); // ALMOST EQUAL OR EQUAL TO
    builder.put("apid", Integer.valueOf('\u224b')); // TRIPLE TILDE
    builder.put("bcong", Integer.valueOf('\u224c')); // ALL EQUAL TO
    builder.put("backcong", Integer.valueOf('\u224c')); // ALL EQUAL TO
    builder.put("asympeq", Integer.valueOf('\u224d')); // EQUIVALENT TO
    builder.put("CupCap", Integer.valueOf('\u224d')); // EQUIVALENT TO
    builder.put("bump", Integer.valueOf('\u224e')); // GEOMETRICALLY EQUIVALENT TO
    builder.put("HumpDownHump", Integer.valueOf('\u224e')); // GEOMETRICALLY EQUIVALENT TO
    builder.put("Bumpeq", Integer.valueOf('\u224e')); // GEOMETRICALLY EQUIVALENT TO
    builder.put("bumpe", Integer.valueOf('\u224f')); // DIFFERENCE BETWEEN
    builder.put("HumpEqual", Integer.valueOf('\u224f')); // DIFFERENCE BETWEEN
    builder.put("bumpeq", Integer.valueOf('\u224f')); // DIFFERENCE BETWEEN
    builder.put("esdot", Integer.valueOf('\u2250')); // APPROACHES THE LIMIT
    builder.put("DotEqual", Integer.valueOf('\u2250')); // APPROACHES THE LIMIT
    builder.put("doteq", Integer.valueOf('\u2250')); // APPROACHES THE LIMIT
    builder.put("eDot", Integer.valueOf('\u2251')); // GEOMETRICALLY EQUAL TO
    builder.put("doteqdot", Integer.valueOf('\u2251')); // GEOMETRICALLY EQUAL TO
    builder.put("efDot", Integer.valueOf('\u2252')); // APPROXIMATELY EQUAL TO OR THE IMAGE OF
    builder.put("fallingdotseq", Integer.valueOf('\u2252')); // APPROXIMATELY EQUAL TO OR THE IMAGE OF
    builder.put("erDot", Integer.valueOf('\u2253')); // IMAGE OF OR APPROXIMATELY EQUAL TO
    builder.put("risingdotseq", Integer.valueOf('\u2253')); // IMAGE OF OR APPROXIMATELY EQUAL TO
    builder.put("colone", Integer.valueOf('\u2254')); // COLON EQUALS
    builder.put("coloneq", Integer.valueOf('\u2254')); // COLON EQUALS
    builder.put("Assign", Integer.valueOf('\u2254')); // COLON EQUALS
    builder.put("ecolon", Integer.valueOf('\u2255')); // EQUALS COLON
    builder.put("eqcolon", Integer.valueOf('\u2255')); // EQUALS COLON
    builder.put("ecir", Integer.valueOf('\u2256')); // RING IN EQUAL TO
    builder.put("eqcirc", Integer.valueOf('\u2256')); // RING IN EQUAL TO
    builder.put("cire", Integer.valueOf('\u2257')); // RING EQUAL TO
    builder.put("circeq", Integer.valueOf('\u2257')); // RING EQUAL TO
    builder.put("wedgeq", Integer.valueOf('\u2259')); // ESTIMATES
    builder.put("veeeq", Integer.valueOf('\u225a')); // EQUIANGULAR TO
    builder.put("trie", Integer.valueOf('\u225c')); // DELTA EQUAL TO
    builder.put("triangleq", Integer.valueOf('\u225c')); // DELTA EQUAL TO
    builder.put("equest", Integer.valueOf('\u225f')); // QUESTIONED EQUAL TO
    builder.put("questeq", Integer.valueOf('\u225f')); // QUESTIONED EQUAL TO
    builder.put("ne", Integer.valueOf('\u2260')); // NOT EQUAL TO
    builder.put("NotEqual", Integer.valueOf('\u2260')); // NOT EQUAL TO
    builder.put("equiv", Integer.valueOf('\u2261')); // IDENTICAL TO
    builder.put("Congruent", Integer.valueOf('\u2261')); // IDENTICAL TO
    builder.put("nequiv", Integer.valueOf('\u2262')); // NOT IDENTICAL TO
    builder.put("NotCongruent", Integer.valueOf('\u2262')); // NOT IDENTICAL TO
    builder.put("le", Integer.valueOf('\u2264')); // LESS-THAN OR EQUAL TO
    builder.put("leq", Integer.valueOf('\u2264')); // LESS-THAN OR EQUAL TO
    builder.put("ge", Integer.valueOf('\u2265')); // GREATER-THAN OR EQUAL TO
    builder.put("GreaterEqual", Integer.valueOf('\u2265')); // GREATER-THAN OR EQUAL TO
    builder.put("geq", Integer.valueOf('\u2265')); // GREATER-THAN OR EQUAL TO
    builder.put("lE", Integer.valueOf('\u2266')); // LESS-THAN OVER EQUAL TO
    builder.put("LessFullEqual", Integer.valueOf('\u2266')); // LESS-THAN OVER EQUAL TO
    builder.put("leqq", Integer.valueOf('\u2266')); // LESS-THAN OVER EQUAL TO
    builder.put("gE", Integer.valueOf('\u2267')); // GREATER-THAN OVER EQUAL TO
    builder.put("GreaterFullEqual", Integer.valueOf('\u2267')); // GREATER-THAN OVER EQUAL TO
    builder.put("geqq", Integer.valueOf('\u2267')); // GREATER-THAN OVER EQUAL TO
    builder.put("lnE", Integer.valueOf('\u2268')); // LESS-THAN BUT NOT EQUAL TO
    builder.put("lneqq", Integer.valueOf('\u2268')); // LESS-THAN BUT NOT EQUAL TO
    builder.put("gnE", Integer.valueOf('\u2269')); // GREATER-THAN BUT NOT EQUAL TO
    builder.put("gneqq", Integer.valueOf('\u2269')); // GREATER-THAN BUT NOT EQUAL TO
    builder.put("Lt", Integer.valueOf('\u226a')); // MUCH LESS-THAN
    builder.put("NestedLessLess", Integer.valueOf('\u226a')); // MUCH LESS-THAN
    builder.put("ll", Integer.valueOf('\u226a')); // MUCH LESS-THAN
    builder.put("Gt", Integer.valueOf('\u226b')); // MUCH GREATER-THAN
    builder.put("NestedGreaterGreater", Integer.valueOf('\u226b')); // MUCH GREATER-THAN
    builder.put("gg", Integer.valueOf('\u226b')); // MUCH GREATER-THAN
    builder.put("twixt", Integer.valueOf('\u226c')); // BETWEEN
    builder.put("between", Integer.valueOf('\u226c')); // BETWEEN
    builder.put("NotCupCap", Integer.valueOf('\u226d')); // NOT EQUIVALENT TO
    builder.put("nlt", Integer.valueOf('\u226e')); // NOT LESS-THAN
    builder.put("NotLess", Integer.valueOf('\u226e')); // NOT LESS-THAN
    builder.put("nless", Integer.valueOf('\u226e')); // NOT LESS-THAN
    builder.put("ngt", Integer.valueOf('\u226f')); // NOT GREATER-THAN
    builder.put("NotGreater", Integer.valueOf('\u226f')); // NOT GREATER-THAN
    builder.put("ngtr", Integer.valueOf('\u226f')); // NOT GREATER-THAN
    builder.put("nle", Integer.valueOf('\u2270')); // NEITHER LESS-THAN NOR EQUAL TO
    builder.put("NotLessEqual", Integer.valueOf('\u2270')); // NEITHER LESS-THAN NOR EQUAL TO
    builder.put("nleq", Integer.valueOf('\u2270')); // NEITHER LESS-THAN NOR EQUAL TO
    builder.put("nge", Integer.valueOf('\u2271')); // NEITHER GREATER-THAN NOR EQUAL TO
    builder.put("NotGreaterEqual", Integer.valueOf('\u2271')); // NEITHER GREATER-THAN NOR EQUAL TO
    builder.put("ngeq", Integer.valueOf('\u2271')); // NEITHER GREATER-THAN NOR EQUAL TO
    builder.put("lsim", Integer.valueOf('\u2272')); // LESS-THAN OR EQUIVALENT TO
    builder.put("LessTilde", Integer.valueOf('\u2272')); // LESS-THAN OR EQUIVALENT TO
    builder.put("lesssim", Integer.valueOf('\u2272')); // LESS-THAN OR EQUIVALENT TO
    builder.put("gsim", Integer.valueOf('\u2273')); // GREATER-THAN OR EQUIVALENT TO
    builder.put("gtrsim", Integer.valueOf('\u2273')); // GREATER-THAN OR EQUIVALENT TO
    builder.put("GreaterTilde", Integer.valueOf('\u2273')); // GREATER-THAN OR EQUIVALENT TO
    builder.put("nlsim", Integer.valueOf('\u2274')); // NEITHER LESS-THAN NOR EQUIVALENT TO
    builder.put("NotLessTilde", Integer.valueOf('\u2274')); // NEITHER LESS-THAN NOR EQUIVALENT TO
    builder.put("ngsim", Integer.valueOf('\u2275')); // NEITHER GREATER-THAN NOR EQUIVALENT TO
    builder.put("NotGreaterTilde", Integer.valueOf('\u2275')); // NEITHER GREATER-THAN NOR EQUIVALENT TO
    builder.put("lg", Integer.valueOf('\u2276')); // LESS-THAN OR GREATER-THAN
    builder.put("lessgtr", Integer.valueOf('\u2276')); // LESS-THAN OR GREATER-THAN
    builder.put("LessGreater", Integer.valueOf('\u2276')); // LESS-THAN OR GREATER-THAN
    builder.put("gl", Integer.valueOf('\u2277')); // GREATER-THAN OR LESS-THAN
    builder.put("gtrless", Integer.valueOf('\u2277')); // GREATER-THAN OR LESS-THAN
    builder.put("GreaterLess", Integer.valueOf('\u2277')); // GREATER-THAN OR LESS-THAN
    builder.put("ntlg", Integer.valueOf('\u2278')); // NEITHER LESS-THAN NOR GREATER-THAN
    builder.put("NotLessGreater", Integer.valueOf('\u2278')); // NEITHER LESS-THAN NOR GREATER-THAN
    builder.put("ntgl", Integer.valueOf('\u2279')); // NEITHER GREATER-THAN NOR LESS-THAN
    builder.put("NotGreaterLess", Integer.valueOf('\u2279')); // NEITHER GREATER-THAN NOR LESS-THAN
    builder.put("pr", Integer.valueOf('\u227a')); // PRECEDES
    builder.put("Precedes", Integer.valueOf('\u227a')); // PRECEDES
    builder.put("prec", Integer.valueOf('\u227a')); // PRECEDES
    builder.put("sc", Integer.valueOf('\u227b')); // SUCCEEDS
    builder.put("Succeeds", Integer.valueOf('\u227b')); // SUCCEEDS
    builder.put("succ", Integer.valueOf('\u227b')); // SUCCEEDS
    builder.put("prcue", Integer.valueOf('\u227c')); // PRECEDES OR EQUAL TO
    builder.put("PrecedesSlantEqual", Integer.valueOf('\u227c')); // PRECEDES OR EQUAL TO
    builder.put("preccurlyeq", Integer.valueOf('\u227c')); // PRECEDES OR EQUAL TO
    builder.put("sccue", Integer.valueOf('\u227d')); // SUCCEEDS OR EQUAL TO
    builder.put("SucceedsSlantEqual", Integer.valueOf('\u227d')); // SUCCEEDS OR EQUAL TO
    builder.put("succcurlyeq", Integer.valueOf('\u227d')); // SUCCEEDS OR EQUAL TO
    builder.put("prsim", Integer.valueOf('\u227e')); // PRECEDES OR EQUIVALENT TO
    builder.put("precsim", Integer.valueOf('\u227e')); // PRECEDES OR EQUIVALENT TO
    builder.put("PrecedesTilde", Integer.valueOf('\u227e')); // PRECEDES OR EQUIVALENT TO
    builder.put("scsim", Integer.valueOf('\u227f')); // SUCCEEDS OR EQUIVALENT TO
    builder.put("succsim", Integer.valueOf('\u227f')); // SUCCEEDS OR EQUIVALENT TO
    builder.put("SucceedsTilde", Integer.valueOf('\u227f')); // SUCCEEDS OR EQUIVALENT TO
    builder.put("npr", Integer.valueOf('\u2280')); // DOES NOT PRECEDE
    builder.put("nprec", Integer.valueOf('\u2280')); // DOES NOT PRECEDE
    builder.put("NotPrecedes", Integer.valueOf('\u2280')); // DOES NOT PRECEDE
    builder.put("nsc", Integer.valueOf('\u2281')); // DOES NOT SUCCEED
    builder.put("nsucc", Integer.valueOf('\u2281')); // DOES NOT SUCCEED
    builder.put("NotSucceeds", Integer.valueOf('\u2281')); // DOES NOT SUCCEED
    builder.put("sub", Integer.valueOf('\u2282')); // SUBSET OF
    builder.put("subset", Integer.valueOf('\u2282')); // SUBSET OF
    builder.put("sup", Integer.valueOf('\u2283')); // SUPERSET OF
    builder.put("supset", Integer.valueOf('\u2283')); // SUPERSET OF
    builder.put("Superset", Integer.valueOf('\u2283')); // SUPERSET OF
    builder.put("nsub", Integer.valueOf('\u2284')); // NOT A SUBSET OF
    builder.put("nsup", Integer.valueOf('\u2285')); // NOT A SUPERSET OF
    builder.put("sube", Integer.valueOf('\u2286')); // SUBSET OF OR EQUAL TO
    builder.put("SubsetEqual", Integer.valueOf('\u2286')); // SUBSET OF OR EQUAL TO
    builder.put("subseteq", Integer.valueOf('\u2286')); // SUBSET OF OR EQUAL TO
    builder.put("supe", Integer.valueOf('\u2287')); // SUPERSET OF OR EQUAL TO
    builder.put("supseteq", Integer.valueOf('\u2287')); // SUPERSET OF OR EQUAL TO
    builder.put("SupersetEqual", Integer.valueOf('\u2287')); // SUPERSET OF OR EQUAL TO
    builder.put("nsube", Integer.valueOf('\u2288')); // NEITHER A SUBSET OF NOR EQUAL TO
    builder.put("nsubseteq", Integer.valueOf('\u2288')); // NEITHER A SUBSET OF NOR EQUAL TO
    builder.put("NotSubsetEqual", Integer.valueOf('\u2288')); // NEITHER A SUBSET OF NOR EQUAL TO
    builder.put("nsupe", Integer.valueOf('\u2289')); // NEITHER A SUPERSET OF NOR EQUAL TO
    builder.put("nsupseteq", Integer.valueOf('\u2289')); // NEITHER A SUPERSET OF NOR EQUAL TO
    builder.put("NotSupersetEqual", Integer.valueOf('\u2289')); // NEITHER A SUPERSET OF NOR EQUAL TO
    builder.put("subne", Integer.valueOf('\u228a')); // SUBSET OF WITH NOT EQUAL TO
    builder.put("subsetneq", Integer.valueOf('\u228a')); // SUBSET OF WITH NOT EQUAL TO
    builder.put("supne", Integer.valueOf('\u228b')); // SUPERSET OF WITH NOT EQUAL TO
    builder.put("supsetneq", Integer.valueOf('\u228b')); // SUPERSET OF WITH NOT EQUAL TO
    builder.put("cupdot", Integer.valueOf('\u228d')); // MULTISET MULTIPLICATION
    builder.put("uplus", Integer.valueOf('\u228e')); // MULTISET UNION
    builder.put("UnionPlus", Integer.valueOf('\u228e')); // MULTISET UNION
    builder.put("sqsub", Integer.valueOf('\u228f')); // SQUARE IMAGE OF
    builder.put("SquareSubset", Integer.valueOf('\u228f')); // SQUARE IMAGE OF
    builder.put("sqsubset", Integer.valueOf('\u228f')); // SQUARE IMAGE OF
    builder.put("sqsup", Integer.valueOf('\u2290')); // SQUARE ORIGINAL OF
    builder.put("SquareSuperset", Integer.valueOf('\u2290')); // SQUARE ORIGINAL OF
    builder.put("sqsupset", Integer.valueOf('\u2290')); // SQUARE ORIGINAL OF
    builder.put("sqsube", Integer.valueOf('\u2291')); // SQUARE IMAGE OF OR EQUAL TO
    builder.put("SquareSubsetEqual", Integer.valueOf('\u2291')); // SQUARE IMAGE OF OR EQUAL TO
    builder.put("sqsubseteq", Integer.valueOf('\u2291')); // SQUARE IMAGE OF OR EQUAL TO
    builder.put("sqsupe", Integer.valueOf('\u2292')); // SQUARE ORIGINAL OF OR EQUAL TO
    builder.put("SquareSupersetEqual", Integer.valueOf('\u2292')); // SQUARE ORIGINAL OF OR EQUAL TO
    builder.put("sqsupseteq", Integer.valueOf('\u2292')); // SQUARE ORIGINAL OF OR EQUAL TO
    builder.put("sqcap", Integer.valueOf('\u2293')); // SQUARE CAP
    builder.put("SquareIntersection", Integer.valueOf('\u2293')); // SQUARE CAP
    builder.put("sqcup", Integer.valueOf('\u2294')); // SQUARE CUP
    builder.put("SquareUnion", Integer.valueOf('\u2294')); // SQUARE CUP
    builder.put("oplus", Integer.valueOf('\u2295')); // CIRCLED PLUS
    builder.put("CirclePlus", Integer.valueOf('\u2295')); // CIRCLED PLUS
    builder.put("ominus", Integer.valueOf('\u2296')); // CIRCLED MINUS
    builder.put("CircleMinus", Integer.valueOf('\u2296')); // CIRCLED MINUS
    builder.put("otimes", Integer.valueOf('\u2297')); // CIRCLED TIMES
    builder.put("CircleTimes", Integer.valueOf('\u2297')); // CIRCLED TIMES
    builder.put("osol", Integer.valueOf('\u2298')); // CIRCLED DIVISION SLASH
    builder.put("odot", Integer.valueOf('\u2299')); // CIRCLED DOT OPERATOR
    builder.put("CircleDot", Integer.valueOf('\u2299')); // CIRCLED DOT OPERATOR
    builder.put("ocir", Integer.valueOf('\u229a')); // CIRCLED RING OPERATOR
    builder.put("circledcirc", Integer.valueOf('\u229a')); // CIRCLED RING OPERATOR
    builder.put("oast", Integer.valueOf('\u229b')); // CIRCLED ASTERISK OPERATOR
    builder.put("circledast", Integer.valueOf('\u229b')); // CIRCLED ASTERISK OPERATOR
    builder.put("odash", Integer.valueOf('\u229d')); // CIRCLED DASH
    builder.put("circleddash", Integer.valueOf('\u229d')); // CIRCLED DASH
    builder.put("plusb", Integer.valueOf('\u229e')); // SQUARED PLUS
    builder.put("boxplus", Integer.valueOf('\u229e')); // SQUARED PLUS
    builder.put("minusb", Integer.valueOf('\u229f')); // SQUARED MINUS
    builder.put("boxminus", Integer.valueOf('\u229f')); // SQUARED MINUS
    builder.put("timesb", Integer.valueOf('\u22a0')); // SQUARED TIMES
    builder.put("boxtimes", Integer.valueOf('\u22a0')); // SQUARED TIMES
    builder.put("sdotb", Integer.valueOf('\u22a1')); // SQUARED DOT OPERATOR
    builder.put("dotsquare", Integer.valueOf('\u22a1')); // SQUARED DOT OPERATOR
    builder.put("vdash", Integer.valueOf('\u22a2')); // RIGHT TACK
    builder.put("RightTee", Integer.valueOf('\u22a2')); // RIGHT TACK
    builder.put("dashv", Integer.valueOf('\u22a3')); // LEFT TACK
    builder.put("LeftTee", Integer.valueOf('\u22a3')); // LEFT TACK
    builder.put("top", Integer.valueOf('\u22a4')); // DOWN TACK
    builder.put("DownTee", Integer.valueOf('\u22a4')); // DOWN TACK
    builder.put("bottom", Integer.valueOf('\u22a5')); // UP TACK
    builder.put("bot", Integer.valueOf('\u22a5')); // UP TACK
    builder.put("perp", Integer.valueOf('\u22a5')); // UP TACK
    builder.put("UpTee", Integer.valueOf('\u22a5')); // UP TACK
    builder.put("models", Integer.valueOf('\u22a7')); // MODELS
    builder.put("vDash", Integer.valueOf('\u22a8')); // TRUE
    builder.put("DoubleRightTee", Integer.valueOf('\u22a8')); // TRUE
    builder.put("Vdash", Integer.valueOf('\u22a9')); // FORCES
    builder.put("Vvdash", Integer.valueOf('\u22aa')); // TRIPLE VERTICAL BAR RIGHT TURNSTILE
    builder.put("VDash", Integer.valueOf('\u22ab')); // DOUBLE VERTICAL BAR DOUBLE RIGHT TURNSTILE
    builder.put("nvdash", Integer.valueOf('\u22ac')); // DOES NOT PROVE
    builder.put("nvDash", Integer.valueOf('\u22ad')); // NOT TRUE
    builder.put("nVdash", Integer.valueOf('\u22ae')); // DOES NOT FORCE
    builder.put("nVDash", Integer.valueOf('\u22af')); // NEGATED DOUBLE VERTICAL BAR DOUBLE RIGHT TURNSTILE
    builder.put("prurel", Integer.valueOf('\u22b0')); // PRECEDES UNDER RELATION
    builder.put("vltri", Integer.valueOf('\u22b2')); // NORMAL SUBGROUP OF
    builder.put("vartriangleleft", Integer.valueOf('\u22b2')); // NORMAL SUBGROUP OF
    builder.put("LeftTriangle", Integer.valueOf('\u22b2')); // NORMAL SUBGROUP OF
    builder.put("vrtri", Integer.valueOf('\u22b3')); // CONTAINS AS NORMAL SUBGROUP
    builder.put("vartriangleright", Integer.valueOf('\u22b3')); // CONTAINS AS NORMAL SUBGROUP
    builder.put("RightTriangle", Integer.valueOf('\u22b3')); // CONTAINS AS NORMAL SUBGROUP
    builder.put("ltrie", Integer.valueOf('\u22b4')); // NORMAL SUBGROUP OF OR EQUAL TO
    builder.put("trianglelefteq", Integer.valueOf('\u22b4')); // NORMAL SUBGROUP OF OR EQUAL TO
    builder.put("LeftTriangleEqual", Integer.valueOf('\u22b4')); // NORMAL SUBGROUP OF OR EQUAL TO
    builder.put("rtrie", Integer.valueOf('\u22b5')); // CONTAINS AS NORMAL SUBGROUP OR EQUAL TO
    builder.put("trianglerighteq", Integer.valueOf('\u22b5')); // CONTAINS AS NORMAL SUBGROUP OR EQUAL TO
    builder.put("RightTriangleEqual", Integer.valueOf('\u22b5')); // CONTAINS AS NORMAL SUBGROUP OR EQUAL TO
    builder.put("origof", Integer.valueOf('\u22b6')); // ORIGINAL OF
    builder.put("imof", Integer.valueOf('\u22b7')); // IMAGE OF
    builder.put("mumap", Integer.valueOf('\u22b8')); // MULTIMAP
    builder.put("multimap", Integer.valueOf('\u22b8')); // MULTIMAP
    builder.put("hercon", Integer.valueOf('\u22b9')); // HERMITIAN CONJUGATE MATRIX
    builder.put("intcal", Integer.valueOf('\u22ba')); // INTERCALATE
    builder.put("intercal", Integer.valueOf('\u22ba')); // INTERCALATE
    builder.put("veebar", Integer.valueOf('\u22bb')); // XOR
    builder.put("barvee", Integer.valueOf('\u22bd')); // NOR
    builder.put("angrtvb", Integer.valueOf('\u22be')); // RIGHT ANGLE WITH ARC
    builder.put("lrtri", Integer.valueOf('\u22bf')); // RIGHT TRIANGLE
    builder.put("xwedge", Integer.valueOf('\u22c0')); // N-ARY LOGICAL AND
    builder.put("Wedge", Integer.valueOf('\u22c0')); // N-ARY LOGICAL AND
    builder.put("bigwedge", Integer.valueOf('\u22c0')); // N-ARY LOGICAL AND
    builder.put("xvee", Integer.valueOf('\u22c1')); // N-ARY LOGICAL OR
    builder.put("Vee", Integer.valueOf('\u22c1')); // N-ARY LOGICAL OR
    builder.put("bigvee", Integer.valueOf('\u22c1')); // N-ARY LOGICAL OR
    builder.put("xcap", Integer.valueOf('\u22c2')); // N-ARY INTERSECTION
    builder.put("Intersection", Integer.valueOf('\u22c2')); // N-ARY INTERSECTION
    builder.put("bigcap", Integer.valueOf('\u22c2')); // N-ARY INTERSECTION
    builder.put("xcup", Integer.valueOf('\u22c3')); // N-ARY UNION
    builder.put("Union", Integer.valueOf('\u22c3')); // N-ARY UNION
    builder.put("bigcup", Integer.valueOf('\u22c3')); // N-ARY UNION
    builder.put("diam", Integer.valueOf('\u22c4')); // DIAMOND OPERATOR
    builder.put("diamond", Integer.valueOf('\u22c4')); // DIAMOND OPERATOR
    builder.put("Diamond", Integer.valueOf('\u22c4')); // DIAMOND OPERATOR
    builder.put("sdot", Integer.valueOf('\u22c5')); // DOT OPERATOR
    builder.put("sstarf", Integer.valueOf('\u22c6')); // STAR OPERATOR
    builder.put("Star", Integer.valueOf('\u22c6')); // STAR OPERATOR
    builder.put("divonx", Integer.valueOf('\u22c7')); // DIVISION TIMES
    builder.put("divideontimes", Integer.valueOf('\u22c7')); // DIVISION TIMES
    builder.put("bowtie", Integer.valueOf('\u22c8')); // BOWTIE
    builder.put("ltimes", Integer.valueOf('\u22c9')); // LEFT NORMAL FACTOR SEMIDIRECT PRODUCT
    builder.put("rtimes", Integer.valueOf('\u22ca')); // RIGHT NORMAL FACTOR SEMIDIRECT PRODUCT
    builder.put("lthree", Integer.valueOf('\u22cb')); // LEFT SEMIDIRECT PRODUCT
    builder.put("leftthreetimes", Integer.valueOf('\u22cb')); // LEFT SEMIDIRECT PRODUCT
    builder.put("rthree", Integer.valueOf('\u22cc')); // RIGHT SEMIDIRECT PRODUCT
    builder.put("rightthreetimes", Integer.valueOf('\u22cc')); // RIGHT SEMIDIRECT PRODUCT
    builder.put("bsime", Integer.valueOf('\u22cd')); // REVERSED TILDE EQUALS
    builder.put("backsimeq", Integer.valueOf('\u22cd')); // REVERSED TILDE EQUALS
    builder.put("cuvee", Integer.valueOf('\u22ce')); // CURLY LOGICAL OR
    builder.put("curlyvee", Integer.valueOf('\u22ce')); // CURLY LOGICAL OR
    builder.put("cuwed", Integer.valueOf('\u22cf')); // CURLY LOGICAL AND
    builder.put("curlywedge", Integer.valueOf('\u22cf')); // CURLY LOGICAL AND
    builder.put("Sub", Integer.valueOf('\u22d0')); // DOUBLE SUBSET
    builder.put("Subset", Integer.valueOf('\u22d0')); // DOUBLE SUBSET
    builder.put("Sup", Integer.valueOf('\u22d1')); // DOUBLE SUPERSET
    builder.put("Supset", Integer.valueOf('\u22d1')); // DOUBLE SUPERSET
    builder.put("Cap", Integer.valueOf('\u22d2')); // DOUBLE INTERSECTION
    builder.put("Cup", Integer.valueOf('\u22d3')); // DOUBLE UNION
    builder.put("fork", Integer.valueOf('\u22d4')); // PITCHFORK
    builder.put("pitchfork", Integer.valueOf('\u22d4')); // PITCHFORK
    builder.put("epar", Integer.valueOf('\u22d5')); // EQUAL AND PARALLEL TO
    builder.put("ltdot", Integer.valueOf('\u22d6')); // LESS-THAN WITH DOT
    builder.put("lessdot", Integer.valueOf('\u22d6')); // LESS-THAN WITH DOT
    builder.put("gtdot", Integer.valueOf('\u22d7')); // GREATER-THAN WITH DOT
    builder.put("gtrdot", Integer.valueOf('\u22d7')); // GREATER-THAN WITH DOT
    builder.put("Ll", Integer.valueOf('\u22d8')); // VERY MUCH LESS-THAN
    builder.put("Gg", Integer.valueOf('\u22d9')); // VERY MUCH GREATER-THAN
    builder.put("ggg", Integer.valueOf('\u22d9')); // VERY MUCH GREATER-THAN
    builder.put("leg", Integer.valueOf('\u22da')); // LESS-THAN EQUAL TO OR GREATER-THAN
    builder.put("LessEqualGreater", Integer.valueOf('\u22da')); // LESS-THAN EQUAL TO OR GREATER-THAN
    builder.put("lesseqgtr", Integer.valueOf('\u22da')); // LESS-THAN EQUAL TO OR GREATER-THAN
    builder.put("gel", Integer.valueOf('\u22db')); // GREATER-THAN EQUAL TO OR LESS-THAN
    builder.put("gtreqless", Integer.valueOf('\u22db')); // GREATER-THAN EQUAL TO OR LESS-THAN
    builder.put("GreaterEqualLess", Integer.valueOf('\u22db')); // GREATER-THAN EQUAL TO OR LESS-THAN
    builder.put("cuepr", Integer.valueOf('\u22de')); // EQUAL TO OR PRECEDES
    builder.put("curlyeqprec", Integer.valueOf('\u22de')); // EQUAL TO OR PRECEDES
    builder.put("cuesc", Integer.valueOf('\u22df')); // EQUAL TO OR SUCCEEDS
    builder.put("curlyeqsucc", Integer.valueOf('\u22df')); // EQUAL TO OR SUCCEEDS
    builder.put("nprcue", Integer.valueOf('\u22e0')); // DOES NOT PRECEDE OR EQUAL
    builder.put("NotPrecedesSlantEqual", Integer.valueOf('\u22e0')); // DOES NOT PRECEDE OR EQUAL
    builder.put("nsccue", Integer.valueOf('\u22e1')); // DOES NOT SUCCEED OR EQUAL
    builder.put("NotSucceedsSlantEqual", Integer.valueOf('\u22e1')); // DOES NOT SUCCEED OR EQUAL
    builder.put("nsqsube", Integer.valueOf('\u22e2')); // NOT SQUARE IMAGE OF OR EQUAL TO
    builder.put("NotSquareSubsetEqual", Integer.valueOf('\u22e2')); // NOT SQUARE IMAGE OF OR EQUAL TO
    builder.put("nsqsupe", Integer.valueOf('\u22e3')); // NOT SQUARE ORIGINAL OF OR EQUAL TO
    builder.put("NotSquareSupersetEqual", Integer.valueOf('\u22e3')); // NOT SQUARE ORIGINAL OF OR EQUAL TO
    builder.put("lnsim", Integer.valueOf('\u22e6')); // LESS-THAN BUT NOT EQUIVALENT TO
    builder.put("gnsim", Integer.valueOf('\u22e7')); // GREATER-THAN BUT NOT EQUIVALENT TO
    builder.put("prnsim", Integer.valueOf('\u22e8')); // PRECEDES BUT NOT EQUIVALENT TO
    builder.put("precnsim", Integer.valueOf('\u22e8')); // PRECEDES BUT NOT EQUIVALENT TO
    builder.put("scnsim", Integer.valueOf('\u22e9')); // SUCCEEDS BUT NOT EQUIVALENT TO
    builder.put("succnsim", Integer.valueOf('\u22e9')); // SUCCEEDS BUT NOT EQUIVALENT TO
    builder.put("nltri", Integer.valueOf('\u22ea')); // NOT NORMAL SUBGROUP OF
    builder.put("ntriangleleft", Integer.valueOf('\u22ea')); // NOT NORMAL SUBGROUP OF
    builder.put("NotLeftTriangle", Integer.valueOf('\u22ea')); // NOT NORMAL SUBGROUP OF
    builder.put("nrtri", Integer.valueOf('\u22eb')); // DOES NOT CONTAIN AS NORMAL SUBGROUP
    builder.put("ntriangleright", Integer.valueOf('\u22eb')); // DOES NOT CONTAIN AS NORMAL SUBGROUP
    builder.put("NotRightTriangle", Integer.valueOf('\u22eb')); // DOES NOT CONTAIN AS NORMAL SUBGROUP
    builder.put("nltrie", Integer.valueOf('\u22ec')); // NOT NORMAL SUBGROUP OF OR EQUAL TO
    builder.put("ntrianglelefteq", Integer.valueOf('\u22ec')); // NOT NORMAL SUBGROUP OF OR EQUAL TO
    builder.put("NotLeftTriangleEqual", Integer.valueOf('\u22ec')); // NOT NORMAL SUBGROUP OF OR EQUAL TO
    builder.put("nrtrie", Integer.valueOf('\u22ed')); // DOES NOT CONTAIN AS NORMAL SUBGROUP OR EQUAL
    builder.put("ntrianglerighteq", Integer.valueOf('\u22ed')); // DOES NOT CONTAIN AS NORMAL SUBGROUP OR EQUAL
    builder.put("NotRightTriangleEqual", Integer.valueOf('\u22ed')); // DOES NOT CONTAIN AS NORMAL SUBGROUP OR EQUAL
    builder.put("vellip", Integer.valueOf('\u22ee')); // VERTICAL ELLIPSIS
    builder.put("ctdot", Integer.valueOf('\u22ef')); // MIDLINE HORIZONTAL ELLIPSIS
    builder.put("utdot", Integer.valueOf('\u22f0')); // UP RIGHT DIAGONAL ELLIPSIS
    builder.put("dtdot", Integer.valueOf('\u22f1')); // DOWN RIGHT DIAGONAL ELLIPSIS
    builder.put("disin", Integer.valueOf('\u22f2')); // ELEMENT OF WITH LONG HORIZONTAL STROKE
    builder.put("isinsv", Integer.valueOf('\u22f3')); // ELEMENT OF WITH VERTICAL BAR AT END OF HORIZONTAL STROKE
    builder.put("isins", Integer.valueOf('\u22f4')); // SMALL ELEMENT OF WITH VERTICAL BAR AT END OF HORIZONTAL STROKE
    builder.put("isindot", Integer.valueOf('\u22f5')); // ELEMENT OF WITH DOT ABOVE
    builder.put("notinvc", Integer.valueOf('\u22f6')); // ELEMENT OF WITH OVERBAR
    builder.put("notinvb", Integer.valueOf('\u22f7')); // SMALL ELEMENT OF WITH OVERBAR
    builder.put("isinE", Integer.valueOf('\u22f9')); // ELEMENT OF WITH TWO HORIZONTAL STROKES
    builder.put("nisd", Integer.valueOf('\u22fa')); // CONTAINS WITH LONG HORIZONTAL STROKE
    builder.put("xnis", Integer.valueOf('\u22fb')); // CONTAINS WITH VERTICAL BAR AT END OF HORIZONTAL STROKE
    builder.put("nis", Integer.valueOf('\u22fc')); // SMALL CONTAINS WITH VERTICAL BAR AT END OF HORIZONTAL STROKE
    builder.put("notnivc", Integer.valueOf('\u22fd')); // CONTAINS WITH OVERBAR
    builder.put("notnivb", Integer.valueOf('\u22fe')); // SMALL CONTAINS WITH OVERBAR

    // Miscellaneous Technical
    builder.put("barwed", Integer.valueOf('\u2305')); // PROJECTIVE
    builder.put("barwedge", Integer.valueOf('\u2305')); // PROJECTIVE
    builder.put("Barwed", Integer.valueOf('\u2306')); // PERSPECTIVE
    builder.put("doublebarwedge", Integer.valueOf('\u2306')); // PERSPECTIVE
    builder.put("lceil", Integer.valueOf('\u2308')); // LEFT CEILING
    builder.put("LeftCeiling", Integer.valueOf('\u2308')); // LEFT CEILING
    builder.put("rceil", Integer.valueOf('\u2309')); // RIGHT CEILING
    builder.put("RightCeiling", Integer.valueOf('\u2309')); // RIGHT CEILING
    builder.put("lfloor", Integer.valueOf('\u230a')); // LEFT FLOOR
    builder.put("LeftFloor", Integer.valueOf('\u230a')); // LEFT FLOOR
    builder.put("rfloor", Integer.valueOf('\u230b')); // RIGHT FLOOR
    builder.put("RightFloor", Integer.valueOf('\u230b')); // RIGHT FLOOR
    builder.put("drcrop", Integer.valueOf('\u230c')); // BOTTOM RIGHT CROP
    builder.put("dlcrop", Integer.valueOf('\u230d')); // BOTTOM LEFT CROP
    builder.put("urcrop", Integer.valueOf('\u230e')); // TOP RIGHT CROP
    builder.put("ulcrop", Integer.valueOf('\u230f')); // TOP LEFT CROP
    builder.put("bnot", Integer.valueOf('\u2310')); // REVERSED NOT SIGN
    builder.put("profline", Integer.valueOf('\u2312')); // ARC
    builder.put("profsurf", Integer.valueOf('\u2313')); // SEGMENT
    builder.put("telrec", Integer.valueOf('\u2315')); // TELEPHONE RECORDER
    builder.put("target", Integer.valueOf('\u2316')); // POSITION INDICATOR
    builder.put("ulcorn", Integer.valueOf('\u231c')); // TOP LEFT CORNER
    builder.put("ulcorner", Integer.valueOf('\u231c')); // TOP LEFT CORNER
    builder.put("urcorn", Integer.valueOf('\u231d')); // TOP RIGHT CORNER
    builder.put("urcorner", Integer.valueOf('\u231d')); // TOP RIGHT CORNER
    builder.put("dlcorn", Integer.valueOf('\u231e')); // BOTTOM LEFT CORNER
    builder.put("llcorner", Integer.valueOf('\u231e')); // BOTTOM LEFT CORNER
    builder.put("drcorn", Integer.valueOf('\u231f')); // BOTTOM RIGHT CORNER
    builder.put("lrcorner", Integer.valueOf('\u231f')); // BOTTOM RIGHT CORNER
    builder.put("frown", Integer.valueOf('\u2322')); // FROWN
    builder.put("sfrown", Integer.valueOf('\u2322')); // FROWN
    builder.put("smile", Integer.valueOf('\u2323')); // SMILE
    builder.put("ssmile", Integer.valueOf('\u2323')); // SMILE
    builder.put("cylcty", Integer.valueOf('\u232d')); // CYLINDRICITY
    builder.put("profalar", Integer.valueOf('\u232e')); // ALL AROUND-PROFILE
    builder.put("topbot", Integer.valueOf('\u2336')); // APL FUNCTIONAL SYMBOL I-BEAM
    builder.put("ovbar", Integer.valueOf('\u233d')); // APL FUNCTIONAL SYMBOL CIRCLE STILE
    builder.put("solbar", Integer.valueOf('\u233f')); // APL FUNCTIONAL SYMBOL SLASH BAR
    builder.put("angzarr", Integer.valueOf('\u237c')); // RIGHT ANGLE WITH DOWNWARDS ZIGZAG ARROW
    builder.put("lmoust", Integer.valueOf('\u23b0')); // UPPER LEFT OR LOWER RIGHT CURLY BRACKET SECTION
    builder.put("lmoustache", Integer.valueOf('\u23b0')); // UPPER LEFT OR LOWER RIGHT CURLY BRACKET SECTION
    builder.put("rmoust", Integer.valueOf('\u23b1')); // UPPER RIGHT OR LOWER LEFT CURLY BRACKET SECTION
    builder.put("rmoustache", Integer.valueOf('\u23b1')); // UPPER RIGHT OR LOWER LEFT CURLY BRACKET SECTION
    builder.put("tbrk", Integer.valueOf('\u23b4')); // TOP SQUARE BRACKET
    builder.put("OverBracket", Integer.valueOf('\u23b4')); // TOP SQUARE BRACKET
    builder.put("bbrk", Integer.valueOf('\u23b5')); // BOTTOM SQUARE BRACKET
    builder.put("UnderBracket", Integer.valueOf('\u23b5')); // BOTTOM SQUARE BRACKET
    builder.put("bbrktbrk", Integer.valueOf('\u23b6')); // BOTTOM SQUARE BRACKET OVER TOP SQUARE BRACKET
    builder.put("OverParenthesis", Integer.valueOf('\u23dc')); // TOP PARENTHESIS
    builder.put("UnderParenthesis", Integer.valueOf('\u23dd')); // BOTTOM PARENTHESIS
    builder.put("OverBrace", Integer.valueOf('\u23de')); // TOP CURLY BRACKET
    builder.put("UnderBrace", Integer.valueOf('\u23df')); // BOTTOM CURLY BRACKET
    builder.put("trpezium", Integer.valueOf('\u23e2')); // WHITE TRAPEZIUM
    builder.put("elinters", Integer.valueOf('\u23e7')); // ELECTRICAL INTERSECTION

    // Control Pictures
    builder.put("blank", Integer.valueOf('\u2423')); // OPEN BOX

    // Enclosed Alphanumerics
    builder.put("oS", Integer.valueOf('\u24c8')); // CIRCLED LATIN CAPITAL LETTER S
    builder.put("circledS", Integer.valueOf('\u24c8')); // CIRCLED LATIN CAPITAL LETTER S

    // Box Drawing
    builder.put("boxh", Integer.valueOf('\u2500')); // BOX DRAWINGS LIGHT HORIZONTAL
    builder.put("HorizontalLine", Integer.valueOf('\u2500')); // BOX DRAWINGS LIGHT HORIZONTAL
    builder.put("boxv", Integer.valueOf('\u2502')); // BOX DRAWINGS LIGHT VERTICAL
    builder.put("boxdr", Integer.valueOf('\u250c')); // BOX DRAWINGS LIGHT DOWN AND RIGHT
    builder.put("boxdl", Integer.valueOf('\u2510')); // BOX DRAWINGS LIGHT DOWN AND LEFT
    builder.put("boxur", Integer.valueOf('\u2514')); // BOX DRAWINGS LIGHT UP AND RIGHT
    builder.put("boxul", Integer.valueOf('\u2518')); // BOX DRAWINGS LIGHT UP AND LEFT
    builder.put("boxvr", Integer.valueOf('\u251c')); // BOX DRAWINGS LIGHT VERTICAL AND RIGHT
    builder.put("boxvl", Integer.valueOf('\u2524')); // BOX DRAWINGS LIGHT VERTICAL AND LEFT
    builder.put("boxhd", Integer.valueOf('\u252c')); // BOX DRAWINGS LIGHT DOWN AND HORIZONTAL
    builder.put("boxhu", Integer.valueOf('\u2534')); // BOX DRAWINGS LIGHT UP AND HORIZONTAL
    builder.put("boxvh", Integer.valueOf('\u253c')); // BOX DRAWINGS LIGHT VERTICAL AND HORIZONTAL
    builder.put("boxH", Integer.valueOf('\u2550')); // BOX DRAWINGS DOUBLE HORIZONTAL
    builder.put("boxV", Integer.valueOf('\u2551')); // BOX DRAWINGS DOUBLE VERTICAL
    builder.put("boxdR", Integer.valueOf('\u2552')); // BOX DRAWINGS DOWN SINGLE AND RIGHT DOUBLE
    builder.put("boxDr", Integer.valueOf('\u2553')); // BOX DRAWINGS DOWN DOUBLE AND RIGHT SINGLE
    builder.put("boxDR", Integer.valueOf('\u2554')); // BOX DRAWINGS DOUBLE DOWN AND RIGHT
    builder.put("boxdL", Integer.valueOf('\u2555')); // BOX DRAWINGS DOWN SINGLE AND LEFT DOUBLE
    builder.put("boxDl", Integer.valueOf('\u2556')); // BOX DRAWINGS DOWN DOUBLE AND LEFT SINGLE
    builder.put("boxDL", Integer.valueOf('\u2557')); // BOX DRAWINGS DOUBLE DOWN AND LEFT
    builder.put("boxuR", Integer.valueOf('\u2558')); // BOX DRAWINGS UP SINGLE AND RIGHT DOUBLE
    builder.put("boxUr", Integer.valueOf('\u2559')); // BOX DRAWINGS UP DOUBLE AND RIGHT SINGLE
    builder.put("boxUR", Integer.valueOf('\u255a')); // BOX DRAWINGS DOUBLE UP AND RIGHT
    builder.put("boxuL", Integer.valueOf('\u255b')); // BOX DRAWINGS UP SINGLE AND LEFT DOUBLE
    builder.put("boxUl", Integer.valueOf('\u255c')); // BOX DRAWINGS UP DOUBLE AND LEFT SINGLE
    builder.put("boxUL", Integer.valueOf('\u255d')); // BOX DRAWINGS DOUBLE UP AND LEFT
    builder.put("boxvR", Integer.valueOf('\u255e')); // BOX DRAWINGS VERTICAL SINGLE AND RIGHT DOUBLE
    builder.put("boxVr", Integer.valueOf('\u255f')); // BOX DRAWINGS VERTICAL DOUBLE AND RIGHT SINGLE
    builder.put("boxVR", Integer.valueOf('\u2560')); // BOX DRAWINGS DOUBLE VERTICAL AND RIGHT
    builder.put("boxvL", Integer.valueOf('\u2561')); // BOX DRAWINGS VERTICAL SINGLE AND LEFT DOUBLE
    builder.put("boxVl", Integer.valueOf('\u2562')); // BOX DRAWINGS VERTICAL DOUBLE AND LEFT SINGLE
    builder.put("boxVL", Integer.valueOf('\u2563')); // BOX DRAWINGS DOUBLE VERTICAL AND LEFT
    builder.put("boxHd", Integer.valueOf('\u2564')); // BOX DRAWINGS DOWN SINGLE AND HORIZONTAL DOUBLE
    builder.put("boxhD", Integer.valueOf('\u2565')); // BOX DRAWINGS DOWN DOUBLE AND HORIZONTAL SINGLE
    builder.put("boxHD", Integer.valueOf('\u2566')); // BOX DRAWINGS DOUBLE DOWN AND HORIZONTAL
    builder.put("boxHu", Integer.valueOf('\u2567')); // BOX DRAWINGS UP SINGLE AND HORIZONTAL DOUBLE
    builder.put("boxhU", Integer.valueOf('\u2568')); // BOX DRAWINGS UP DOUBLE AND HORIZONTAL SINGLE
    builder.put("boxHU", Integer.valueOf('\u2569')); // BOX DRAWINGS DOUBLE UP AND HORIZONTAL
    builder.put("boxvH", Integer.valueOf('\u256a')); // BOX DRAWINGS VERTICAL SINGLE AND HORIZONTAL DOUBLE
    builder.put("boxVh", Integer.valueOf('\u256b')); // BOX DRAWINGS VERTICAL DOUBLE AND HORIZONTAL SINGLE
    builder.put("boxVH", Integer.valueOf('\u256c')); // BOX DRAWINGS DOUBLE VERTICAL AND HORIZONTAL

    // Block Elements
    builder.put("uhblk", Integer.valueOf('\u2580')); // UPPER HALF BLOCK
    builder.put("lhblk", Integer.valueOf('\u2584')); // LOWER HALF BLOCK
    builder.put("block", Integer.valueOf('\u2588')); // FULL BLOCK
    builder.put("blk14", Integer.valueOf('\u2591')); // LIGHT SHADE
    builder.put("blk12", Integer.valueOf('\u2592')); // MEDIUM SHADE
    builder.put("blk34", Integer.valueOf('\u2593')); // DARK SHADE

    // Geometric Shapes
    builder.put("squ", Integer.valueOf('\u25a1')); // WHITE SQUARE
    builder.put("square", Integer.valueOf('\u25a1')); // WHITE SQUARE
    builder.put("Square", Integer.valueOf('\u25a1')); // WHITE SQUARE
    builder.put("squf", Integer.valueOf('\u25aa')); // BLACK SMALL SQUARE
    builder.put("squarf", Integer.valueOf('\u25aa')); // BLACK SMALL SQUARE
    builder.put("blacksquare", Integer.valueOf('\u25aa')); // BLACK SMALL SQUARE
    builder.put("FilledVerySmallSquare", Integer.valueOf('\u25aa')); // BLACK SMALL SQUARE
    builder.put("EmptyVerySmallSquare", Integer.valueOf('\u25ab')); // WHITE SMALL SQUARE
    builder.put("rect", Integer.valueOf('\u25ad')); // WHITE RECTANGLE
    builder.put("marker", Integer.valueOf('\u25ae')); // BLACK VERTICAL RECTANGLE
    builder.put("fltns", Integer.valueOf('\u25b1')); // WHITE PARALLELOGRAM
    builder.put("xutri", Integer.valueOf('\u25b3')); // WHITE UP-POINTING TRIANGLE
    builder.put("bigtriangleup", Integer.valueOf('\u25b3')); // WHITE UP-POINTING TRIANGLE
    builder.put("utrif", Integer.valueOf('\u25b4')); // BLACK UP-POINTING SMALL TRIANGLE
    builder.put("blacktriangle", Integer.valueOf('\u25b4')); // BLACK UP-POINTING SMALL TRIANGLE
    builder.put("utri", Integer.valueOf('\u25b5')); // WHITE UP-POINTING SMALL TRIANGLE
    builder.put("triangle", Integer.valueOf('\u25b5')); // WHITE UP-POINTING SMALL TRIANGLE
    builder.put("rtrif", Integer.valueOf('\u25b8')); // BLACK RIGHT-POINTING SMALL TRIANGLE
    builder.put("blacktriangleright", Integer.valueOf('\u25b8')); // BLACK RIGHT-POINTING SMALL TRIANGLE
    builder.put("rtri", Integer.valueOf('\u25b9')); // WHITE RIGHT-POINTING SMALL TRIANGLE
    builder.put("triangleright", Integer.valueOf('\u25b9')); // WHITE RIGHT-POINTING SMALL TRIANGLE
    builder.put("xdtri", Integer.valueOf('\u25bd')); // WHITE DOWN-POINTING TRIANGLE
    builder.put("bigtriangledown", Integer.valueOf('\u25bd')); // WHITE DOWN-POINTING TRIANGLE
    builder.put("dtrif", Integer.valueOf('\u25be')); // BLACK DOWN-POINTING SMALL TRIANGLE
    builder.put("blacktriangledown", Integer.valueOf('\u25be')); // BLACK DOWN-POINTING SMALL TRIANGLE
    builder.put("dtri", Integer.valueOf('\u25bf')); // WHITE DOWN-POINTING SMALL TRIANGLE
    builder.put("triangledown", Integer.valueOf('\u25bf')); // WHITE DOWN-POINTING SMALL TRIANGLE
    builder.put("ltrif", Integer.valueOf('\u25c2')); // BLACK LEFT-POINTING SMALL TRIANGLE
    builder.put("blacktriangleleft", Integer.valueOf('\u25c2')); // BLACK LEFT-POINTING SMALL TRIANGLE
    builder.put("ltri", Integer.valueOf('\u25c3')); // WHITE LEFT-POINTING SMALL TRIANGLE
    builder.put("triangleleft", Integer.valueOf('\u25c3')); // WHITE LEFT-POINTING SMALL TRIANGLE
    builder.put("loz", Integer.valueOf('\u25ca')); // LOZENGE
    builder.put("lozenge", Integer.valueOf('\u25ca')); // LOZENGE
    builder.put("cir", Integer.valueOf('\u25cb')); // WHITE CIRCLE
    builder.put("tridot", Integer.valueOf('\u25ec')); // WHITE UP-POINTING TRIANGLE WITH DOT
    builder.put("xcirc", Integer.valueOf('\u25ef')); // LARGE CIRCLE
    builder.put("bigcirc", Integer.valueOf('\u25ef')); // LARGE CIRCLE
    builder.put("ultri", Integer.valueOf('\u25f8')); // UPPER LEFT TRIANGLE
    builder.put("urtri", Integer.valueOf('\u25f9')); // UPPER RIGHT TRIANGLE
    builder.put("lltri", Integer.valueOf('\u25fa')); // LOWER LEFT TRIANGLE
    builder.put("EmptySmallSquare", Integer.valueOf('\u25fb')); // WHITE MEDIUM SQUARE
    builder.put("FilledSmallSquare", Integer.valueOf('\u25fc')); // BLACK MEDIUM SQUARE

    // Miscellaneous Symbols
    builder.put("starf", Integer.valueOf('\u2605')); // BLACK STAR
    builder.put("bigstar", Integer.valueOf('\u2605')); // BLACK STAR
    builder.put("star", Integer.valueOf('\u2606')); // WHITE STAR
    builder.put("phone", Integer.valueOf('\u260e')); // BLACK TELEPHONE
    builder.put("female", Integer.valueOf('\u2640')); // FEMALE SIGN
    builder.put("male", Integer.valueOf('\u2642')); // MALE SIGN
    builder.put("spades", Integer.valueOf('\u2660')); // BLACK SPADE SUIT
    builder.put("spadesuit", Integer.valueOf('\u2660')); // BLACK SPADE SUIT
    builder.put("clubs", Integer.valueOf('\u2663')); // BLACK CLUB SUIT
    builder.put("clubsuit", Integer.valueOf('\u2663')); // BLACK CLUB SUIT
    builder.put("hearts", Integer.valueOf('\u2665')); // BLACK HEART SUIT
    builder.put("heartsuit", Integer.valueOf('\u2665')); // BLACK HEART SUIT
    builder.put("diams", Integer.valueOf('\u2666')); // BLACK DIAMOND SUIT
    builder.put("diamondsuit", Integer.valueOf('\u2666')); // BLACK DIAMOND SUIT
    builder.put("sung", Integer.valueOf('\u266a')); // EIGHTH NOTE
    builder.put("flat", Integer.valueOf('\u266d')); // MUSIC FLAT SIGN
    builder.put("natur", Integer.valueOf('\u266e')); // MUSIC NATURAL SIGN
    builder.put("natural", Integer.valueOf('\u266e')); // MUSIC NATURAL SIGN
    builder.put("sharp", Integer.valueOf('\u266f')); // MUSIC SHARP SIGN

    // Dingbats
    builder.put("check", Integer.valueOf('\u2713')); // CHECK MARK
    builder.put("checkmark", Integer.valueOf('\u2713')); // CHECK MARK
    builder.put("cross", Integer.valueOf('\u2717')); // BALLOT X
    builder.put("malt", Integer.valueOf('\u2720')); // MALTESE CROSS
    builder.put("maltese", Integer.valueOf('\u2720')); // MALTESE CROSS
    builder.put("sext", Integer.valueOf('\u2736')); // SIX POINTED BLACK STAR
    builder.put("VerticalSeparator", Integer.valueOf('\u2758')); // LIGHT VERTICAL BAR
    builder.put("lbbrk", Integer.valueOf('\u2772')); // LIGHT LEFT TORTOISE SHELL BRACKET ORNAMENT
    builder.put("rbbrk", Integer.valueOf('\u2773')); // LIGHT RIGHT TORTOISE SHELL BRACKET ORNAMENT

    // Miscellaneous Mathematical Symbols-A
    builder.put("lobrk", Integer.valueOf('\u27e6')); // MATHEMATICAL LEFT WHITE SQUARE BRACKET
    builder.put("LeftDoubleBracket", Integer.valueOf('\u27e6')); // MATHEMATICAL LEFT WHITE SQUARE BRACKET
    builder.put("robrk", Integer.valueOf('\u27e7')); // MATHEMATICAL RIGHT WHITE SQUARE BRACKET
    builder.put("RightDoubleBracket", Integer.valueOf('\u27e7')); // MATHEMATICAL RIGHT WHITE SQUARE BRACKET
    builder.put("lang", Integer.valueOf('\u27e8')); // MATHEMATICAL LEFT ANGLE BRACKET
    builder.put("LeftAngleBracket", Integer.valueOf('\u27e8')); // MATHEMATICAL LEFT ANGLE BRACKET
    builder.put("langle", Integer.valueOf('\u27e8')); // MATHEMATICAL LEFT ANGLE BRACKET
    builder.put("rang", Integer.valueOf('\u27e9')); // MATHEMATICAL RIGHT ANGLE BRACKET
    builder.put("RightAngleBracket", Integer.valueOf('\u27e9')); // MATHEMATICAL RIGHT ANGLE BRACKET
    builder.put("rangle", Integer.valueOf('\u27e9')); // MATHEMATICAL RIGHT ANGLE BRACKET
    builder.put("Lang", Integer.valueOf('\u27ea')); // MATHEMATICAL LEFT DOUBLE ANGLE BRACKET
    builder.put("Rang", Integer.valueOf('\u27eb')); // MATHEMATICAL RIGHT DOUBLE ANGLE BRACKET
    builder.put("loang", Integer.valueOf('\u27ec')); // MATHEMATICAL LEFT WHITE TORTOISE SHELL BRACKET
    builder.put("roang", Integer.valueOf('\u27ed')); // MATHEMATICAL RIGHT WHITE TORTOISE SHELL BRACKET

    // Supplemental Arrows-A
    builder.put("xlarr", Integer.valueOf('\u27f5')); // LONG LEFTWARDS ARROW
    builder.put("longleftarrow", Integer.valueOf('\u27f5')); // LONG LEFTWARDS ARROW
    builder.put("LongLeftArrow", Integer.valueOf('\u27f5')); // LONG LEFTWARDS ARROW
    builder.put("xrarr", Integer.valueOf('\u27f6')); // LONG RIGHTWARDS ARROW
    builder.put("longrightarrow", Integer.valueOf('\u27f6')); // LONG RIGHTWARDS ARROW
    builder.put("LongRightArrow", Integer.valueOf('\u27f6')); // LONG RIGHTWARDS ARROW
    builder.put("xharr", Integer.valueOf('\u27f7')); // LONG LEFT RIGHT ARROW
    builder.put("longleftrightarrow", Integer.valueOf('\u27f7')); // LONG LEFT RIGHT ARROW
    builder.put("LongLeftRightArrow", Integer.valueOf('\u27f7')); // LONG LEFT RIGHT ARROW
    builder.put("xlArr", Integer.valueOf('\u27f8')); // LONG LEFTWARDS DOUBLE ARROW
    builder.put("Longleftarrow", Integer.valueOf('\u27f8')); // LONG LEFTWARDS DOUBLE ARROW
    builder.put("DoubleLongLeftArrow", Integer.valueOf('\u27f8')); // LONG LEFTWARDS DOUBLE ARROW
    builder.put("xrArr", Integer.valueOf('\u27f9')); // LONG RIGHTWARDS DOUBLE ARROW
    builder.put("Longrightarrow", Integer.valueOf('\u27f9')); // LONG RIGHTWARDS DOUBLE ARROW
    builder.put("DoubleLongRightArrow", Integer.valueOf('\u27f9')); // LONG RIGHTWARDS DOUBLE ARROW
    builder.put("xhArr", Integer.valueOf('\u27fa')); // LONG LEFT RIGHT DOUBLE ARROW
    builder.put("Longleftrightarrow", Integer.valueOf('\u27fa')); // LONG LEFT RIGHT DOUBLE ARROW
    builder.put("DoubleLongLeftRightArrow", Integer.valueOf('\u27fa')); // LONG LEFT RIGHT DOUBLE ARROW
    builder.put("xmap", Integer.valueOf('\u27fc')); // LONG RIGHTWARDS ARROW FROM BAR
    builder.put("longmapsto", Integer.valueOf('\u27fc')); // LONG RIGHTWARDS ARROW FROM BAR
    builder.put("dzigrarr", Integer.valueOf('\u27ff')); // LONG RIGHTWARDS SQUIGGLE ARROW

    // Supplemental Arrows-B
    builder.put("nvlArr", Integer.valueOf('\u2902')); // LEFTWARDS DOUBLE ARROW WITH VERTICAL STROKE
    builder.put("nvrArr", Integer.valueOf('\u2903')); // RIGHTWARDS DOUBLE ARROW WITH VERTICAL STROKE
    builder.put("nvHarr", Integer.valueOf('\u2904')); // LEFT RIGHT DOUBLE ARROW WITH VERTICAL STROKE
    builder.put("Map", Integer.valueOf('\u2905')); // RIGHTWARDS TWO-HEADED ARROW FROM BAR
    builder.put("lbarr", Integer.valueOf('\u290c')); // LEFTWARDS DOUBLE DASH ARROW
    builder.put("rbarr", Integer.valueOf('\u290d')); // RIGHTWARDS DOUBLE DASH ARROW
    builder.put("bkarow", Integer.valueOf('\u290d')); // RIGHTWARDS DOUBLE DASH ARROW
    builder.put("lBarr", Integer.valueOf('\u290e')); // LEFTWARDS TRIPLE DASH ARROW
    builder.put("rBarr", Integer.valueOf('\u290f')); // RIGHTWARDS TRIPLE DASH ARROW
    builder.put("dbkarow", Integer.valueOf('\u290f')); // RIGHTWARDS TRIPLE DASH ARROW
    builder.put("RBarr", Integer.valueOf('\u2910')); // RIGHTWARDS TWO-HEADED TRIPLE DASH ARROW
    builder.put("drbkarow", Integer.valueOf('\u2910')); // RIGHTWARDS TWO-HEADED TRIPLE DASH ARROW
    builder.put("DDotrahd", Integer.valueOf('\u2911')); // RIGHTWARDS ARROW WITH DOTTED STEM
    builder.put("UpArrowBar", Integer.valueOf('\u2912')); // UPWARDS ARROW TO BAR
    builder.put("DownArrowBar", Integer.valueOf('\u2913')); // DOWNWARDS ARROW TO BAR
    builder.put("Rarrtl", Integer.valueOf('\u2916')); // RIGHTWARDS TWO-HEADED ARROW WITH TAIL
    builder.put("latail", Integer.valueOf('\u2919')); // LEFTWARDS ARROW-TAIL
    builder.put("ratail", Integer.valueOf('\u291a')); // RIGHTWARDS ARROW-TAIL
    builder.put("lAtail", Integer.valueOf('\u291b')); // LEFTWARDS DOUBLE ARROW-TAIL
    builder.put("rAtail", Integer.valueOf('\u291c')); // RIGHTWARDS DOUBLE ARROW-TAIL
    builder.put("larrfs", Integer.valueOf('\u291d')); // LEFTWARDS ARROW TO BLACK DIAMOND
    builder.put("rarrfs", Integer.valueOf('\u291e')); // RIGHTWARDS ARROW TO BLACK DIAMOND
    builder.put("larrbfs", Integer.valueOf('\u291f')); // LEFTWARDS ARROW FROM BAR TO BLACK DIAMOND
    builder.put("rarrbfs", Integer.valueOf('\u2920')); // RIGHTWARDS ARROW FROM BAR TO BLACK DIAMOND
    builder.put("nwarhk", Integer.valueOf('\u2923')); // NORTH WEST ARROW WITH HOOK
    builder.put("nearhk", Integer.valueOf('\u2924')); // NORTH EAST ARROW WITH HOOK
    builder.put("searhk", Integer.valueOf('\u2925')); // SOUTH EAST ARROW WITH HOOK
    builder.put("hksearow", Integer.valueOf('\u2925')); // SOUTH EAST ARROW WITH HOOK
    builder.put("swarhk", Integer.valueOf('\u2926')); // SOUTH WEST ARROW WITH HOOK
    builder.put("hkswarow", Integer.valueOf('\u2926')); // SOUTH WEST ARROW WITH HOOK
    builder.put("nwnear", Integer.valueOf('\u2927')); // NORTH WEST ARROW AND NORTH EAST ARROW
    builder.put("nesear", Integer.valueOf('\u2928')); // NORTH EAST ARROW AND SOUTH EAST ARROW
    builder.put("toea", Integer.valueOf('\u2928')); // NORTH EAST ARROW AND SOUTH EAST ARROW
    builder.put("seswar", Integer.valueOf('\u2929')); // SOUTH EAST ARROW AND SOUTH WEST ARROW
    builder.put("tosa", Integer.valueOf('\u2929')); // SOUTH EAST ARROW AND SOUTH WEST ARROW
    builder.put("swnwar", Integer.valueOf('\u292a')); // SOUTH WEST ARROW AND NORTH WEST ARROW
    builder.put("rarrc", Integer.valueOf('\u2933')); // WAVE ARROW POINTING DIRECTLY RIGHT
    builder.put("cudarrr", Integer.valueOf('\u2935')); // ARROW POINTING RIGHTWARDS THEN CURVING DOWNWARDS
    builder.put("ldca", Integer.valueOf('\u2936')); // ARROW POINTING DOWNWARDS THEN CURVING LEFTWARDS
    builder.put("rdca", Integer.valueOf('\u2937')); // ARROW POINTING DOWNWARDS THEN CURVING RIGHTWARDS
    builder.put("cudarrl", Integer.valueOf('\u2938')); // RIGHT-SIDE ARC CLOCKWISE ARROW
    builder.put("larrpl", Integer.valueOf('\u2939')); // LEFT-SIDE ARC ANTICLOCKWISE ARROW
    builder.put("curarrm", Integer.valueOf('\u293c')); // TOP ARC CLOCKWISE ARROW WITH MINUS
    builder.put("cularrp", Integer.valueOf('\u293d')); // TOP ARC ANTICLOCKWISE ARROW WITH PLUS
    builder.put("rarrpl", Integer.valueOf('\u2945')); // RIGHTWARDS ARROW WITH PLUS BELOW
    builder.put("harrcir", Integer.valueOf('\u2948')); // LEFT RIGHT ARROW THROUGH SMALL CIRCLE
    builder.put("Uarrocir", Integer.valueOf('\u2949')); // UPWARDS TWO-HEADED ARROW FROM SMALL CIRCLE
    builder.put("lurdshar", Integer.valueOf('\u294a')); // LEFT BARB UP RIGHT BARB DOWN HARPOON
    builder.put("ldrushar", Integer.valueOf('\u294b')); // LEFT BARB DOWN RIGHT BARB UP HARPOON
    builder.put("LeftRightVector", Integer.valueOf('\u294e')); // LEFT BARB UP RIGHT BARB UP HARPOON
    builder.put("RightUpDownVector", Integer.valueOf('\u294f')); // UP BARB RIGHT DOWN BARB RIGHT HARPOON
    builder.put("DownLeftRightVector", Integer.valueOf('\u2950')); // LEFT BARB DOWN RIGHT BARB DOWN HARPOON
    builder.put("LeftUpDownVector", Integer.valueOf('\u2951')); // UP BARB LEFT DOWN BARB LEFT HARPOON
    builder.put("LeftVectorBar", Integer.valueOf('\u2952')); // LEFTWARDS HARPOON WITH BARB UP TO BAR
    builder.put("RightVectorBar", Integer.valueOf('\u2953')); // RIGHTWARDS HARPOON WITH BARB UP TO BAR
    builder.put("RightUpVectorBar", Integer.valueOf('\u2954')); // UPWARDS HARPOON WITH BARB RIGHT TO BAR
    builder.put("RightDownVectorBar", Integer.valueOf('\u2955')); // DOWNWARDS HARPOON WITH BARB RIGHT TO BAR
    builder.put("DownLeftVectorBar", Integer.valueOf('\u2956')); // LEFTWARDS HARPOON WITH BARB DOWN TO BAR
    builder.put("DownRightVectorBar", Integer.valueOf('\u2957')); // RIGHTWARDS HARPOON WITH BARB DOWN TO BAR
    builder.put("LeftUpVectorBar", Integer.valueOf('\u2958')); // UPWARDS HARPOON WITH BARB LEFT TO BAR
    builder.put("LeftDownVectorBar", Integer.valueOf('\u2959')); // DOWNWARDS HARPOON WITH BARB LEFT TO BAR
    builder.put("LeftTeeVector", Integer.valueOf('\u295a')); // LEFTWARDS HARPOON WITH BARB UP FROM BAR
    builder.put("RightTeeVector", Integer.valueOf('\u295b')); // RIGHTWARDS HARPOON WITH BARB UP FROM BAR
    builder.put("RightUpTeeVector", Integer.valueOf('\u295c')); // UPWARDS HARPOON WITH BARB RIGHT FROM BAR
    builder.put("RightDownTeeVector", Integer.valueOf('\u295d')); // DOWNWARDS HARPOON WITH BARB RIGHT FROM BAR
    builder.put("DownLeftTeeVector", Integer.valueOf('\u295e')); // LEFTWARDS HARPOON WITH BARB DOWN FROM BAR
    builder.put("DownRightTeeVector", Integer.valueOf('\u295f')); // RIGHTWARDS HARPOON WITH BARB DOWN FROM BAR
    builder.put("LeftUpTeeVector", Integer.valueOf('\u2960')); // UPWARDS HARPOON WITH BARB LEFT FROM BAR
    builder.put("LeftDownTeeVector", Integer.valueOf('\u2961')); // DOWNWARDS HARPOON WITH BARB LEFT FROM BAR
    builder.put("lHar", Integer.valueOf('\u2962')); // LEFTWARDS HARPOON WITH BARB UP ABOVE LEFTWARDS HARPOON WITH BARB DOWN
    builder.put("uHar", Integer.valueOf('\u2963')); // UPWARDS HARPOON WITH BARB LEFT BESIDE UPWARDS HARPOON WITH BARB RIGHT
    builder.put("rHar", Integer.valueOf('\u2964')); // RIGHTWARDS HARPOON WITH BARB UP ABOVE RIGHTWARDS HARPOON WITH BARB DOWN
    builder.put("dHar", Integer.valueOf('\u2965')); // DOWNWARDS HARPOON WITH BARB LEFT BESIDE DOWNWARDS HARPOON WITH BARB RIGHT
    builder.put("luruhar", Integer.valueOf('\u2966')); // LEFTWARDS HARPOON WITH BARB UP ABOVE RIGHTWARDS HARPOON WITH BARB UP
    builder.put("ldrdhar", Integer.valueOf('\u2967')); // LEFTWARDS HARPOON WITH BARB DOWN ABOVE RIGHTWARDS HARPOON WITH BARB DOWN
    builder.put("ruluhar", Integer.valueOf('\u2968')); // RIGHTWARDS HARPOON WITH BARB UP ABOVE LEFTWARDS HARPOON WITH BARB UP
    builder.put("rdldhar", Integer.valueOf('\u2969')); // RIGHTWARDS HARPOON WITH BARB DOWN ABOVE LEFTWARDS HARPOON WITH BARB DOWN
    builder.put("lharul", Integer.valueOf('\u296a')); // LEFTWARDS HARPOON WITH BARB UP ABOVE LONG DASH
    builder.put("llhard", Integer.valueOf('\u296b')); // LEFTWARDS HARPOON WITH BARB DOWN BELOW LONG DASH
    builder.put("rharul", Integer.valueOf('\u296c')); // RIGHTWARDS HARPOON WITH BARB UP ABOVE LONG DASH
    builder.put("lrhard", Integer.valueOf('\u296d')); // RIGHTWARDS HARPOON WITH BARB DOWN BELOW LONG DASH
    builder.put("udhar", Integer.valueOf('\u296e')); // UPWARDS HARPOON WITH BARB LEFT BESIDE DOWNWARDS HARPOON WITH BARB RIGHT
    builder.put("UpEquilibrium", Integer.valueOf('\u296e')); // UPWARDS HARPOON WITH BARB LEFT BESIDE DOWNWARDS HARPOON WITH BARB RIGHT
    builder.put("duhar", Integer.valueOf('\u296f')); // DOWNWARDS HARPOON WITH BARB LEFT BESIDE UPWARDS HARPOON WITH BARB RIGHT
    builder.put("ReverseUpEquilibrium", Integer.valueOf('\u296f')); // DOWNWARDS HARPOON WITH BARB LEFT BESIDE UPWARDS HARPOON WITH BARB RIGHT
    builder.put("RoundImplies", Integer.valueOf('\u2970')); // RIGHT DOUBLE ARROW WITH ROUNDED HEAD
    builder.put("erarr", Integer.valueOf('\u2971')); // EQUALS SIGN ABOVE RIGHTWARDS ARROW
    builder.put("simrarr", Integer.valueOf('\u2972')); // TILDE OPERATOR ABOVE RIGHTWARDS ARROW
    builder.put("larrsim", Integer.valueOf('\u2973')); // LEFTWARDS ARROW ABOVE TILDE OPERATOR
    builder.put("rarrsim", Integer.valueOf('\u2974')); // RIGHTWARDS ARROW ABOVE TILDE OPERATOR
    builder.put("rarrap", Integer.valueOf('\u2975')); // RIGHTWARDS ARROW ABOVE ALMOST EQUAL TO
    builder.put("ltlarr", Integer.valueOf('\u2976')); // LESS-THAN ABOVE LEFTWARDS ARROW
    builder.put("gtrarr", Integer.valueOf('\u2978')); // GREATER-THAN ABOVE RIGHTWARDS ARROW
    builder.put("subrarr", Integer.valueOf('\u2979')); // SUBSET ABOVE RIGHTWARDS ARROW
    builder.put("suplarr", Integer.valueOf('\u297b')); // SUPERSET ABOVE LEFTWARDS ARROW
    builder.put("lfisht", Integer.valueOf('\u297c')); // LEFT FISH TAIL
    builder.put("rfisht", Integer.valueOf('\u297d')); // RIGHT FISH TAIL
    builder.put("ufisht", Integer.valueOf('\u297e')); // UP FISH TAIL
    builder.put("dfisht", Integer.valueOf('\u297f')); // DOWN FISH TAIL

    // Miscellaneous Mathematical Symbols-B
    builder.put("lopar", Integer.valueOf('\u2985')); // LEFT WHITE PARENTHESIS
    builder.put("ropar", Integer.valueOf('\u2986')); // RIGHT WHITE PARENTHESIS
    builder.put("lbrke", Integer.valueOf('\u298b')); // LEFT SQUARE BRACKET WITH UNDERBAR
    builder.put("rbrke", Integer.valueOf('\u298c')); // RIGHT SQUARE BRACKET WITH UNDERBAR
    builder.put("lbrkslu", Integer.valueOf('\u298d')); // LEFT SQUARE BRACKET WITH TICK IN TOP CORNER
    builder.put("rbrksld", Integer.valueOf('\u298e')); // RIGHT SQUARE BRACKET WITH TICK IN BOTTOM CORNER
    builder.put("lbrksld", Integer.valueOf('\u298f')); // LEFT SQUARE BRACKET WITH TICK IN BOTTOM CORNER
    builder.put("rbrkslu", Integer.valueOf('\u2990')); // RIGHT SQUARE BRACKET WITH TICK IN TOP CORNER
    builder.put("langd", Integer.valueOf('\u2991')); // LEFT ANGLE BRACKET WITH DOT
    builder.put("rangd", Integer.valueOf('\u2992')); // RIGHT ANGLE BRACKET WITH DOT
    builder.put("lparlt", Integer.valueOf('\u2993')); // LEFT ARC LESS-THAN BRACKET
    builder.put("rpargt", Integer.valueOf('\u2994')); // RIGHT ARC GREATER-THAN BRACKET
    builder.put("gtlPar", Integer.valueOf('\u2995')); // DOUBLE LEFT ARC GREATER-THAN BRACKET
    builder.put("ltrPar", Integer.valueOf('\u2996')); // DOUBLE RIGHT ARC LESS-THAN BRACKET
    builder.put("vzigzag", Integer.valueOf('\u299a')); // VERTICAL ZIGZAG LINE
    builder.put("vangrt", Integer.valueOf('\u299c')); // RIGHT ANGLE VARIANT WITH SQUARE
    builder.put("angrtvbd", Integer.valueOf('\u299d')); // MEASURED RIGHT ANGLE WITH DOT
    builder.put("ange", Integer.valueOf('\u29a4')); // ANGLE WITH UNDERBAR
    builder.put("range", Integer.valueOf('\u29a5')); // REVERSED ANGLE WITH UNDERBAR
    builder.put("dwangle", Integer.valueOf('\u29a6')); // OBLIQUE ANGLE OPENING UP
    builder.put("uwangle", Integer.valueOf('\u29a7')); // OBLIQUE ANGLE OPENING DOWN
    builder.put("angmsdaa", Integer.valueOf('\u29a8')); // MEASURED ANGLE WITH OPEN ARM ENDING IN ARROW POINTING UP AND RIGHT
    builder.put("angmsdab", Integer.valueOf('\u29a9')); // MEASURED ANGLE WITH OPEN ARM ENDING IN ARROW POINTING UP AND LEFT
    builder.put("angmsdac", Integer.valueOf('\u29aa')); // MEASURED ANGLE WITH OPEN ARM ENDING IN ARROW POINTING DOWN AND RIGHT
    builder.put("angmsdad", Integer.valueOf('\u29ab')); // MEASURED ANGLE WITH OPEN ARM ENDING IN ARROW POINTING DOWN AND LEFT
    builder.put("angmsdae", Integer.valueOf('\u29ac')); // MEASURED ANGLE WITH OPEN ARM ENDING IN ARROW POINTING RIGHT AND UP
    builder.put("angmsdaf", Integer.valueOf('\u29ad')); // MEASURED ANGLE WITH OPEN ARM ENDING IN ARROW POINTING LEFT AND UP
    builder.put("angmsdag", Integer.valueOf('\u29ae')); // MEASURED ANGLE WITH OPEN ARM ENDING IN ARROW POINTING RIGHT AND DOWN
    builder.put("angmsdah", Integer.valueOf('\u29af')); // MEASURED ANGLE WITH OPEN ARM ENDING IN ARROW POINTING LEFT AND DOWN
    builder.put("bemptyv", Integer.valueOf('\u29b0')); // REVERSED EMPTY SET
    builder.put("demptyv", Integer.valueOf('\u29b1')); // EMPTY SET WITH OVERBAR
    builder.put("cemptyv", Integer.valueOf('\u29b2')); // EMPTY SET WITH SMALL CIRCLE ABOVE
    builder.put("raemptyv", Integer.valueOf('\u29b3')); // EMPTY SET WITH RIGHT ARROW ABOVE
    builder.put("laemptyv", Integer.valueOf('\u29b4')); // EMPTY SET WITH LEFT ARROW ABOVE
    builder.put("ohbar", Integer.valueOf('\u29b5')); // CIRCLE WITH HORIZONTAL BAR
    builder.put("omid", Integer.valueOf('\u29b6')); // CIRCLED VERTICAL BAR
    builder.put("opar", Integer.valueOf('\u29b7')); // CIRCLED PARALLEL
    builder.put("operp", Integer.valueOf('\u29b9')); // CIRCLED PERPENDICULAR
    builder.put("olcross", Integer.valueOf('\u29bb')); // CIRCLE WITH SUPERIMPOSED X
    builder.put("odsold", Integer.valueOf('\u29bc')); // CIRCLED ANTICLOCKWISE-ROTATED DIVISION SIGN
    builder.put("olcir", Integer.valueOf('\u29be')); // CIRCLED WHITE BULLET
    builder.put("ofcir", Integer.valueOf('\u29bf')); // CIRCLED BULLET
    builder.put("olt", Integer.valueOf('\u29c0')); // CIRCLED LESS-THAN
    builder.put("ogt", Integer.valueOf('\u29c1')); // CIRCLED GREATER-THAN
    builder.put("cirscir", Integer.valueOf('\u29c2')); // CIRCLE WITH SMALL CIRCLE TO THE RIGHT
    builder.put("cirE", Integer.valueOf('\u29c3')); // CIRCLE WITH TWO HORIZONTAL STROKES TO THE RIGHT
    builder.put("solb", Integer.valueOf('\u29c4')); // SQUARED RISING DIAGONAL SLASH
    builder.put("bsolb", Integer.valueOf('\u29c5')); // SQUARED FALLING DIAGONAL SLASH
    builder.put("boxbox", Integer.valueOf('\u29c9')); // TWO JOINED SQUARES
    builder.put("trisb", Integer.valueOf('\u29cd')); // TRIANGLE WITH SERIFS AT BOTTOM
    builder.put("rtriltri", Integer.valueOf('\u29ce')); // RIGHT TRIANGLE ABOVE LEFT TRIANGLE
    builder.put("LeftTriangleBar", Integer.valueOf('\u29cf')); // LEFT TRIANGLE BESIDE VERTICAL BAR
    builder.put("RightTriangleBar", Integer.valueOf('\u29d0')); // VERTICAL BAR BESIDE RIGHT TRIANGLE
    builder.put("race", Integer.valueOf('\u29da')); // LEFT DOUBLE WIGGLY FENCE
    builder.put("iinfin", Integer.valueOf('\u29dc')); // INCOMPLETE INFINITY
    builder.put("infintie", Integer.valueOf('\u29dd')); // TIE OVER INFINITY
    builder.put("nvinfin", Integer.valueOf('\u29de')); // INFINITY NEGATED WITH VERTICAL BAR
    builder.put("eparsl", Integer.valueOf('\u29e3')); // EQUALS SIGN AND SLANTED PARALLEL
    builder.put("smeparsl", Integer.valueOf('\u29e4')); // EQUALS SIGN AND SLANTED PARALLEL WITH TILDE ABOVE
    builder.put("eqvparsl", Integer.valueOf('\u29e5')); // IDENTICAL TO AND SLANTED PARALLEL
    builder.put("lozf", Integer.valueOf('\u29eb')); // BLACK LOZENGE
    builder.put("blacklozenge", Integer.valueOf('\u29eb')); // BLACK LOZENGE
    builder.put("RuleDelayed", Integer.valueOf('\u29f4')); // RULE-DELAYED
    builder.put("dsol", Integer.valueOf('\u29f6')); // SOLIDUS WITH OVERBAR

    // Supplemental Mathematical Operators
    builder.put("xodot", Integer.valueOf('\u2a00')); // N-ARY CIRCLED DOT OPERATOR
    builder.put("bigodot", Integer.valueOf('\u2a00')); // N-ARY CIRCLED DOT OPERATOR
    builder.put("xoplus", Integer.valueOf('\u2a01')); // N-ARY CIRCLED PLUS OPERATOR
    builder.put("bigoplus", Integer.valueOf('\u2a01')); // N-ARY CIRCLED PLUS OPERATOR
    builder.put("xotime", Integer.valueOf('\u2a02')); // N-ARY CIRCLED TIMES OPERATOR
    builder.put("bigotimes", Integer.valueOf('\u2a02')); // N-ARY CIRCLED TIMES OPERATOR
    builder.put("xuplus", Integer.valueOf('\u2a04')); // N-ARY UNION OPERATOR WITH PLUS
    builder.put("biguplus", Integer.valueOf('\u2a04')); // N-ARY UNION OPERATOR WITH PLUS
    builder.put("xsqcup", Integer.valueOf('\u2a06')); // N-ARY SQUARE UNION OPERATOR
    builder.put("bigsqcup", Integer.valueOf('\u2a06')); // N-ARY SQUARE UNION OPERATOR
    builder.put("qint", Integer.valueOf('\u2a0c')); // QUADRUPLE INTEGRAL OPERATOR
    builder.put("iiiint", Integer.valueOf('\u2a0c')); // QUADRUPLE INTEGRAL OPERATOR
    builder.put("fpartint", Integer.valueOf('\u2a0d')); // FINITE PART INTEGRAL
    builder.put("cirfnint", Integer.valueOf('\u2a10')); // CIRCULATION FUNCTION
    builder.put("awint", Integer.valueOf('\u2a11')); // ANTICLOCKWISE INTEGRATION
    builder.put("rppolint", Integer.valueOf('\u2a12')); // LINE INTEGRATION WITH RECTANGULAR PATH AROUND POLE
    builder.put("scpolint", Integer.valueOf('\u2a13')); // LINE INTEGRATION WITH SEMICIRCULAR PATH AROUND POLE
    builder.put("npolint", Integer.valueOf('\u2a14')); // LINE INTEGRATION NOT INCLUDING THE POLE
    builder.put("pointint", Integer.valueOf('\u2a15')); // INTEGRAL AROUND A POINT OPERATOR
    builder.put("quatint", Integer.valueOf('\u2a16')); // QUATERNION INTEGRAL OPERATOR
    builder.put("intlarhk", Integer.valueOf('\u2a17')); // INTEGRAL WITH LEFTWARDS ARROW WITH HOOK
    builder.put("pluscir", Integer.valueOf('\u2a22')); // PLUS SIGN WITH SMALL CIRCLE ABOVE
    builder.put("plusacir", Integer.valueOf('\u2a23')); // PLUS SIGN WITH CIRCUMFLEX ACCENT ABOVE
    builder.put("simplus", Integer.valueOf('\u2a24')); // PLUS SIGN WITH TILDE ABOVE
    builder.put("plusdu", Integer.valueOf('\u2a25')); // PLUS SIGN WITH DOT BELOW
    builder.put("plussim", Integer.valueOf('\u2a26')); // PLUS SIGN WITH TILDE BELOW
    builder.put("plustwo", Integer.valueOf('\u2a27')); // PLUS SIGN WITH SUBSCRIPT TWO
    builder.put("mcomma", Integer.valueOf('\u2a29')); // MINUS SIGN WITH COMMA ABOVE
    builder.put("minusdu", Integer.valueOf('\u2a2a')); // MINUS SIGN WITH DOT BELOW
    builder.put("loplus", Integer.valueOf('\u2a2d')); // PLUS SIGN IN LEFT HALF CIRCLE
    builder.put("roplus", Integer.valueOf('\u2a2e')); // PLUS SIGN IN RIGHT HALF CIRCLE
    builder.put("Cross", Integer.valueOf('\u2a2f')); // VECTOR OR CROSS PRODUCT
    builder.put("timesd", Integer.valueOf('\u2a30')); // MULTIPLICATION SIGN WITH DOT ABOVE
    builder.put("timesbar", Integer.valueOf('\u2a31')); // MULTIPLICATION SIGN WITH UNDERBAR
    builder.put("smashp", Integer.valueOf('\u2a33')); // SMASH PRODUCT
    builder.put("lotimes", Integer.valueOf('\u2a34')); // MULTIPLICATION SIGN IN LEFT HALF CIRCLE
    builder.put("rotimes", Integer.valueOf('\u2a35')); // MULTIPLICATION SIGN IN RIGHT HALF CIRCLE
    builder.put("otimesas", Integer.valueOf('\u2a36')); // CIRCLED MULTIPLICATION SIGN WITH CIRCUMFLEX ACCENT
    builder.put("Otimes", Integer.valueOf('\u2a37')); // MULTIPLICATION SIGN IN DOUBLE CIRCLE
    builder.put("odiv", Integer.valueOf('\u2a38')); // CIRCLED DIVISION SIGN
    builder.put("triplus", Integer.valueOf('\u2a39')); // PLUS SIGN IN TRIANGLE
    builder.put("triminus", Integer.valueOf('\u2a3a')); // MINUS SIGN IN TRIANGLE
    builder.put("tritime", Integer.valueOf('\u2a3b')); // MULTIPLICATION SIGN IN TRIANGLE
    builder.put("iprod", Integer.valueOf('\u2a3c')); // INTERIOR PRODUCT
    builder.put("intprod", Integer.valueOf('\u2a3c')); // INTERIOR PRODUCT
    builder.put("amalg", Integer.valueOf('\u2a3f')); // AMALGAMATION OR COPRODUCT
    builder.put("capdot", Integer.valueOf('\u2a40')); // INTERSECTION WITH DOT
    builder.put("ncup", Integer.valueOf('\u2a42')); // UNION WITH OVERBAR
    builder.put("ncap", Integer.valueOf('\u2a43')); // INTERSECTION WITH OVERBAR
    builder.put("capand", Integer.valueOf('\u2a44')); // INTERSECTION WITH LOGICAL AND
    builder.put("cupor", Integer.valueOf('\u2a45')); // UNION WITH LOGICAL OR
    builder.put("cupcap", Integer.valueOf('\u2a46')); // UNION ABOVE INTERSECTION
    builder.put("capcup", Integer.valueOf('\u2a47')); // INTERSECTION ABOVE UNION
    builder.put("cupbrcap", Integer.valueOf('\u2a48')); // UNION ABOVE BAR ABOVE INTERSECTION
    builder.put("capbrcup", Integer.valueOf('\u2a49')); // INTERSECTION ABOVE BAR ABOVE UNION
    builder.put("cupcup", Integer.valueOf('\u2a4a')); // UNION BESIDE AND JOINED WITH UNION
    builder.put("capcap", Integer.valueOf('\u2a4b')); // INTERSECTION BESIDE AND JOINED WITH INTERSECTION
    builder.put("ccups", Integer.valueOf('\u2a4c')); // CLOSED UNION WITH SERIFS
    builder.put("ccaps", Integer.valueOf('\u2a4d')); // CLOSED INTERSECTION WITH SERIFS
    builder.put("ccupssm", Integer.valueOf('\u2a50')); // CLOSED UNION WITH SERIFS AND SMASH PRODUCT
    builder.put("And", Integer.valueOf('\u2a53')); // DOUBLE LOGICAL AND
    builder.put("Or", Integer.valueOf('\u2a54')); // DOUBLE LOGICAL OR
    builder.put("andand", Integer.valueOf('\u2a55')); // TWO INTERSECTING LOGICAL AND
    builder.put("oror", Integer.valueOf('\u2a56')); // TWO INTERSECTING LOGICAL OR
    builder.put("orslope", Integer.valueOf('\u2a57')); // SLOPING LARGE OR
    builder.put("andslope", Integer.valueOf('\u2a58')); // SLOPING LARGE AND
    builder.put("andv", Integer.valueOf('\u2a5a')); // LOGICAL AND WITH MIDDLE STEM
    builder.put("orv", Integer.valueOf('\u2a5b')); // LOGICAL OR WITH MIDDLE STEM
    builder.put("andd", Integer.valueOf('\u2a5c')); // LOGICAL AND WITH HORIZONTAL DASH
    builder.put("ord", Integer.valueOf('\u2a5d')); // LOGICAL OR WITH HORIZONTAL DASH
    builder.put("wedbar", Integer.valueOf('\u2a5f')); // LOGICAL AND WITH UNDERBAR
    builder.put("sdote", Integer.valueOf('\u2a66')); // EQUALS SIGN WITH DOT BELOW
    builder.put("simdot", Integer.valueOf('\u2a6a')); // TILDE OPERATOR WITH DOT ABOVE
    builder.put("congdot", Integer.valueOf('\u2a6d')); // CONGRUENT WITH DOT ABOVE
    builder.put("easter", Integer.valueOf('\u2a6e')); // EQUALS WITH ASTERISK
    builder.put("apacir", Integer.valueOf('\u2a6f')); // ALMOST EQUAL TO WITH CIRCUMFLEX ACCENT
    builder.put("apE", Integer.valueOf('\u2a70')); // APPROXIMATELY EQUAL OR EQUAL TO
    builder.put("eplus", Integer.valueOf('\u2a71')); // EQUALS SIGN ABOVE PLUS SIGN
    builder.put("pluse", Integer.valueOf('\u2a72')); // PLUS SIGN ABOVE EQUALS SIGN
    builder.put("Esim", Integer.valueOf('\u2a73')); // EQUALS SIGN ABOVE TILDE OPERATOR
    builder.put("Colone", Integer.valueOf('\u2a74')); // DOUBLE COLON EQUAL
    builder.put("Equal", Integer.valueOf('\u2a75')); // TWO CONSECUTIVE EQUALS SIGNS
    builder.put("eDDot", Integer.valueOf('\u2a77')); // EQUALS SIGN WITH TWO DOTS ABOVE AND TWO DOTS BELOW
    builder.put("ddotseq", Integer.valueOf('\u2a77')); // EQUALS SIGN WITH TWO DOTS ABOVE AND TWO DOTS BELOW
    builder.put("equivDD", Integer.valueOf('\u2a78')); // EQUIVALENT WITH FOUR DOTS ABOVE
    builder.put("ltcir", Integer.valueOf('\u2a79')); // LESS-THAN WITH CIRCLE INSIDE
    builder.put("gtcir", Integer.valueOf('\u2a7a')); // GREATER-THAN WITH CIRCLE INSIDE
    builder.put("ltquest", Integer.valueOf('\u2a7b')); // LESS-THAN WITH QUESTION MARK ABOVE
    builder.put("gtquest", Integer.valueOf('\u2a7c')); // GREATER-THAN WITH QUESTION MARK ABOVE
    builder.put("les", Integer.valueOf('\u2a7d')); // LESS-THAN OR SLANTED EQUAL TO
    builder.put("LessSlantEqual", Integer.valueOf('\u2a7d')); // LESS-THAN OR SLANTED EQUAL TO
    builder.put("leqslant", Integer.valueOf('\u2a7d')); // LESS-THAN OR SLANTED EQUAL TO
    builder.put("ges", Integer.valueOf('\u2a7e')); // GREATER-THAN OR SLANTED EQUAL TO
    builder.put("GreaterSlantEqual", Integer.valueOf('\u2a7e')); // GREATER-THAN OR SLANTED EQUAL TO
    builder.put("geqslant", Integer.valueOf('\u2a7e')); // GREATER-THAN OR SLANTED EQUAL TO
    builder.put("lesdot", Integer.valueOf('\u2a7f')); // LESS-THAN OR SLANTED EQUAL TO WITH DOT INSIDE
    builder.put("gesdot", Integer.valueOf('\u2a80')); // GREATER-THAN OR SLANTED EQUAL TO WITH DOT INSIDE
    builder.put("lesdoto", Integer.valueOf('\u2a81')); // LESS-THAN OR SLANTED EQUAL TO WITH DOT ABOVE
    builder.put("gesdoto", Integer.valueOf('\u2a82')); // GREATER-THAN OR SLANTED EQUAL TO WITH DOT ABOVE
    builder.put("lesdotor", Integer.valueOf('\u2a83')); // LESS-THAN OR SLANTED EQUAL TO WITH DOT ABOVE RIGHT
    builder.put("gesdotol", Integer.valueOf('\u2a84')); // GREATER-THAN OR SLANTED EQUAL TO WITH DOT ABOVE LEFT
    builder.put("lap", Integer.valueOf('\u2a85')); // LESS-THAN OR APPROXIMATE
    builder.put("lessapprox", Integer.valueOf('\u2a85')); // LESS-THAN OR APPROXIMATE
    builder.put("gap", Integer.valueOf('\u2a86')); // GREATER-THAN OR APPROXIMATE
    builder.put("gtrapprox", Integer.valueOf('\u2a86')); // GREATER-THAN OR APPROXIMATE
    builder.put("lne", Integer.valueOf('\u2a87')); // LESS-THAN AND SINGLE-LINE NOT EQUAL TO
    builder.put("lneq", Integer.valueOf('\u2a87')); // LESS-THAN AND SINGLE-LINE NOT EQUAL TO
    builder.put("gne", Integer.valueOf('\u2a88')); // GREATER-THAN AND SINGLE-LINE NOT EQUAL TO
    builder.put("gneq", Integer.valueOf('\u2a88')); // GREATER-THAN AND SINGLE-LINE NOT EQUAL TO
    builder.put("lnap", Integer.valueOf('\u2a89')); // LESS-THAN AND NOT APPROXIMATE
    builder.put("lnapprox", Integer.valueOf('\u2a89')); // LESS-THAN AND NOT APPROXIMATE
    builder.put("gnap", Integer.valueOf('\u2a8a')); // GREATER-THAN AND NOT APPROXIMATE
    builder.put("gnapprox", Integer.valueOf('\u2a8a')); // GREATER-THAN AND NOT APPROXIMATE
    builder.put("lEg", Integer.valueOf('\u2a8b')); // LESS-THAN ABOVE DOUBLE-LINE EQUAL ABOVE GREATER-THAN
    builder.put("lesseqqgtr", Integer.valueOf('\u2a8b')); // LESS-THAN ABOVE DOUBLE-LINE EQUAL ABOVE GREATER-THAN
    builder.put("gEl", Integer.valueOf('\u2a8c')); // GREATER-THAN ABOVE DOUBLE-LINE EQUAL ABOVE LESS-THAN
    builder.put("gtreqqless", Integer.valueOf('\u2a8c')); // GREATER-THAN ABOVE DOUBLE-LINE EQUAL ABOVE LESS-THAN
    builder.put("lsime", Integer.valueOf('\u2a8d')); // LESS-THAN ABOVE SIMILAR OR EQUAL
    builder.put("gsime", Integer.valueOf('\u2a8e')); // GREATER-THAN ABOVE SIMILAR OR EQUAL
    builder.put("lsimg", Integer.valueOf('\u2a8f')); // LESS-THAN ABOVE SIMILAR ABOVE GREATER-THAN
    builder.put("gsiml", Integer.valueOf('\u2a90')); // GREATER-THAN ABOVE SIMILAR ABOVE LESS-THAN
    builder.put("lgE", Integer.valueOf('\u2a91')); // LESS-THAN ABOVE GREATER-THAN ABOVE DOUBLE-LINE EQUAL
    builder.put("glE", Integer.valueOf('\u2a92')); // GREATER-THAN ABOVE LESS-THAN ABOVE DOUBLE-LINE EQUAL
    builder.put("lesges", Integer.valueOf('\u2a93')); // LESS-THAN ABOVE SLANTED EQUAL ABOVE GREATER-THAN ABOVE SLANTED EQUAL
    builder.put("gesles", Integer.valueOf('\u2a94')); // GREATER-THAN ABOVE SLANTED EQUAL ABOVE LESS-THAN ABOVE SLANTED EQUAL
    builder.put("els", Integer.valueOf('\u2a95')); // SLANTED EQUAL TO OR LESS-THAN
    builder.put("eqslantless", Integer.valueOf('\u2a95')); // SLANTED EQUAL TO OR LESS-THAN
    builder.put("egs", Integer.valueOf('\u2a96')); // SLANTED EQUAL TO OR GREATER-THAN
    builder.put("eqslantgtr", Integer.valueOf('\u2a96')); // SLANTED EQUAL TO OR GREATER-THAN
    builder.put("elsdot", Integer.valueOf('\u2a97')); // SLANTED EQUAL TO OR LESS-THAN WITH DOT INSIDE
    builder.put("egsdot", Integer.valueOf('\u2a98')); // SLANTED EQUAL TO OR GREATER-THAN WITH DOT INSIDE
    builder.put("el", Integer.valueOf('\u2a99')); // DOUBLE-LINE EQUAL TO OR LESS-THAN
    builder.put("eg", Integer.valueOf('\u2a9a')); // DOUBLE-LINE EQUAL TO OR GREATER-THAN
    builder.put("siml", Integer.valueOf('\u2a9d')); // SIMILAR OR LESS-THAN
    builder.put("simg", Integer.valueOf('\u2a9e')); // SIMILAR OR GREATER-THAN
    builder.put("simlE", Integer.valueOf('\u2a9f')); // SIMILAR ABOVE LESS-THAN ABOVE EQUALS SIGN
    builder.put("simgE", Integer.valueOf('\u2aa0')); // SIMILAR ABOVE GREATER-THAN ABOVE EQUALS SIGN
    builder.put("LessLess", Integer.valueOf('\u2aa1')); // DOUBLE NESTED LESS-THAN
    builder.put("GreaterGreater", Integer.valueOf('\u2aa2')); // DOUBLE NESTED GREATER-THAN
    builder.put("glj", Integer.valueOf('\u2aa4')); // GREATER-THAN OVERLAPPING LESS-THAN
    builder.put("gla", Integer.valueOf('\u2aa5')); // GREATER-THAN BESIDE LESS-THAN
    builder.put("ltcc", Integer.valueOf('\u2aa6')); // LESS-THAN CLOSED BY CURVE
    builder.put("gtcc", Integer.valueOf('\u2aa7')); // GREATER-THAN CLOSED BY CURVE
    builder.put("lescc", Integer.valueOf('\u2aa8')); // LESS-THAN CLOSED BY CURVE ABOVE SLANTED EQUAL
    builder.put("gescc", Integer.valueOf('\u2aa9')); // GREATER-THAN CLOSED BY CURVE ABOVE SLANTED EQUAL
    builder.put("smt", Integer.valueOf('\u2aaa')); // SMALLER THAN
    builder.put("lat", Integer.valueOf('\u2aab')); // LARGER THAN
    builder.put("smte", Integer.valueOf('\u2aac')); // SMALLER THAN OR EQUAL TO
    builder.put("late", Integer.valueOf('\u2aad')); // LARGER THAN OR EQUAL TO
    builder.put("bumpE", Integer.valueOf('\u2aae')); // EQUALS SIGN WITH BUMPY ABOVE
    builder.put("pre", Integer.valueOf('\u2aaf')); // PRECEDES ABOVE SINGLE-LINE EQUALS SIGN
    builder.put("preceq", Integer.valueOf('\u2aaf')); // PRECEDES ABOVE SINGLE-LINE EQUALS SIGN
    builder.put("PrecedesEqual", Integer.valueOf('\u2aaf')); // PRECEDES ABOVE SINGLE-LINE EQUALS SIGN
    builder.put("sce", Integer.valueOf('\u2ab0')); // SUCCEEDS ABOVE SINGLE-LINE EQUALS SIGN
    builder.put("succeq", Integer.valueOf('\u2ab0')); // SUCCEEDS ABOVE SINGLE-LINE EQUALS SIGN
    builder.put("SucceedsEqual", Integer.valueOf('\u2ab0')); // SUCCEEDS ABOVE SINGLE-LINE EQUALS SIGN
    builder.put("prE", Integer.valueOf('\u2ab3')); // PRECEDES ABOVE EQUALS SIGN
    builder.put("scE", Integer.valueOf('\u2ab4')); // SUCCEEDS ABOVE EQUALS SIGN
    builder.put("prnE", Integer.valueOf('\u2ab5')); // PRECEDES ABOVE NOT EQUAL TO
    builder.put("precneqq", Integer.valueOf('\u2ab5')); // PRECEDES ABOVE NOT EQUAL TO
    builder.put("scnE", Integer.valueOf('\u2ab6')); // SUCCEEDS ABOVE NOT EQUAL TO
    builder.put("succneqq", Integer.valueOf('\u2ab6')); // SUCCEEDS ABOVE NOT EQUAL TO
    builder.put("prap", Integer.valueOf('\u2ab7')); // PRECEDES ABOVE ALMOST EQUAL TO
    builder.put("precapprox", Integer.valueOf('\u2ab7')); // PRECEDES ABOVE ALMOST EQUAL TO
    builder.put("scap", Integer.valueOf('\u2ab8')); // SUCCEEDS ABOVE ALMOST EQUAL TO
    builder.put("succapprox", Integer.valueOf('\u2ab8')); // SUCCEEDS ABOVE ALMOST EQUAL TO
    builder.put("prnap", Integer.valueOf('\u2ab9')); // PRECEDES ABOVE NOT ALMOST EQUAL TO
    builder.put("precnapprox", Integer.valueOf('\u2ab9')); // PRECEDES ABOVE NOT ALMOST EQUAL TO
    builder.put("scnap", Integer.valueOf('\u2aba')); // SUCCEEDS ABOVE NOT ALMOST EQUAL TO
    builder.put("succnapprox", Integer.valueOf('\u2aba')); // SUCCEEDS ABOVE NOT ALMOST EQUAL TO
    builder.put("Pr", Integer.valueOf('\u2abb')); // DOUBLE PRECEDES
    builder.put("Sc", Integer.valueOf('\u2abc')); // DOUBLE SUCCEEDS
    builder.put("subdot", Integer.valueOf('\u2abd')); // SUBSET WITH DOT
    builder.put("supdot", Integer.valueOf('\u2abe')); // SUPERSET WITH DOT
    builder.put("subplus", Integer.valueOf('\u2abf')); // SUBSET WITH PLUS SIGN BELOW
    builder.put("supplus", Integer.valueOf('\u2ac0')); // SUPERSET WITH PLUS SIGN BELOW
    builder.put("submult", Integer.valueOf('\u2ac1')); // SUBSET WITH MULTIPLICATION SIGN BELOW
    builder.put("supmult", Integer.valueOf('\u2ac2')); // SUPERSET WITH MULTIPLICATION SIGN BELOW
    builder.put("subedot", Integer.valueOf('\u2ac3')); // SUBSET OF OR EQUAL TO WITH DOT ABOVE
    builder.put("supedot", Integer.valueOf('\u2ac4')); // SUPERSET OF OR EQUAL TO WITH DOT ABOVE
    builder.put("subE", Integer.valueOf('\u2ac5')); // SUBSET OF ABOVE EQUALS SIGN
    builder.put("subseteqq", Integer.valueOf('\u2ac5')); // SUBSET OF ABOVE EQUALS SIGN
    builder.put("supE", Integer.valueOf('\u2ac6')); // SUPERSET OF ABOVE EQUALS SIGN
    builder.put("supseteqq", Integer.valueOf('\u2ac6')); // SUPERSET OF ABOVE EQUALS SIGN
    builder.put("subsim", Integer.valueOf('\u2ac7')); // SUBSET OF ABOVE TILDE OPERATOR
    builder.put("supsim", Integer.valueOf('\u2ac8')); // SUPERSET OF ABOVE TILDE OPERATOR
    builder.put("subnE", Integer.valueOf('\u2acb')); // SUBSET OF ABOVE NOT EQUAL TO
    builder.put("subsetneqq", Integer.valueOf('\u2acb')); // SUBSET OF ABOVE NOT EQUAL TO
    builder.put("supnE", Integer.valueOf('\u2acc')); // SUPERSET OF ABOVE NOT EQUAL TO
    builder.put("supsetneqq", Integer.valueOf('\u2acc')); // SUPERSET OF ABOVE NOT EQUAL TO
    builder.put("csub", Integer.valueOf('\u2acf')); // CLOSED SUBSET
    builder.put("csup", Integer.valueOf('\u2ad0')); // CLOSED SUPERSET
    builder.put("csube", Integer.valueOf('\u2ad1')); // CLOSED SUBSET OR EQUAL TO
    builder.put("csupe", Integer.valueOf('\u2ad2')); // CLOSED SUPERSET OR EQUAL TO
    builder.put("subsup", Integer.valueOf('\u2ad3')); // SUBSET ABOVE SUPERSET
    builder.put("supsub", Integer.valueOf('\u2ad4')); // SUPERSET ABOVE SUBSET
    builder.put("subsub", Integer.valueOf('\u2ad5')); // SUBSET ABOVE SUBSET
    builder.put("supsup", Integer.valueOf('\u2ad6')); // SUPERSET ABOVE SUPERSET
    builder.put("suphsub", Integer.valueOf('\u2ad7')); // SUPERSET BESIDE SUBSET
    builder.put("supdsub", Integer.valueOf('\u2ad8')); // SUPERSET BESIDE AND JOINED BY DASH WITH SUBSET
    builder.put("forkv", Integer.valueOf('\u2ad9')); // ELEMENT OF OPENING DOWNWARDS
    builder.put("topfork", Integer.valueOf('\u2ada')); // PITCHFORK WITH TEE TOP
    builder.put("mlcp", Integer.valueOf('\u2adb')); // TRANSVERSAL INTERSECTION
    builder.put("Dashv", Integer.valueOf('\u2ae4')); // VERTICAL BAR DOUBLE LEFT TURNSTILE
    builder.put("DoubleLeftTee", Integer.valueOf('\u2ae4')); // VERTICAL BAR DOUBLE LEFT TURNSTILE
    builder.put("Vdashl", Integer.valueOf('\u2ae6')); // LONG DASH FROM LEFT MEMBER OF DOUBLE VERTICAL
    builder.put("Barv", Integer.valueOf('\u2ae7')); // SHORT DOWN TACK WITH OVERBAR
    builder.put("vBar", Integer.valueOf('\u2ae8')); // SHORT UP TACK WITH UNDERBAR
    builder.put("vBarv", Integer.valueOf('\u2ae9')); // SHORT UP TACK ABOVE SHORT DOWN TACK
    builder.put("Vbar", Integer.valueOf('\u2aeb')); // DOUBLE UP TACK
    builder.put("Not", Integer.valueOf('\u2aec')); // DOUBLE STROKE NOT SIGN
    builder.put("bNot", Integer.valueOf('\u2aed')); // REVERSED DOUBLE STROKE NOT SIGN
    builder.put("rnmid", Integer.valueOf('\u2aee')); // DOES NOT DIVIDE WITH REVERSED NEGATION SLASH
    builder.put("cirmid", Integer.valueOf('\u2aef')); // VERTICAL LINE WITH CIRCLE ABOVE
    builder.put("midcir", Integer.valueOf('\u2af0')); // VERTICAL LINE WITH CIRCLE BELOW
    builder.put("topcir", Integer.valueOf('\u2af1')); // DOWN TACK WITH CIRCLE BELOW
    builder.put("nhpar", Integer.valueOf('\u2af2')); // PARALLEL WITH HORIZONTAL STROKE
    builder.put("parsim", Integer.valueOf('\u2af3')); // PARALLEL WITH TILDE OPERATOR
    builder.put("parsl", Integer.valueOf('\u2afd')); // DOUBLE SOLIDUS OPERATOR

    // Alphabetic Presentation Forms
    builder.put("fflig", Integer.valueOf('\ufb00')); // LATIN SMALL LIGATURE FF
    builder.put("filig", Integer.valueOf('\ufb01')); // LATIN SMALL LIGATURE FI
    builder.put("fllig", Integer.valueOf('\ufb02')); // LATIN SMALL LIGATURE FL
    builder.put("ffilig", Integer.valueOf('\ufb03')); // LATIN SMALL LIGATURE FFI
    builder.put("ffllig", Integer.valueOf('\ufb04')); // LATIN SMALL LIGATURE FFL

    // Mathematical Alphanumeric Symbols
    builder.put("Ascr", Character.toCodePoint('\ud835', '\udc9c')); // MATHEMATICAL SCRIPT CAPITAL A
    builder.put("Cscr", Character.toCodePoint('\ud835', '\udc9e')); // MATHEMATICAL SCRIPT CAPITAL C
    builder.put("Dscr", Character.toCodePoint('\ud835', '\udc9f')); // MATHEMATICAL SCRIPT CAPITAL D
    builder.put("Gscr", Character.toCodePoint('\ud835', '\udca2')); // MATHEMATICAL SCRIPT CAPITAL G
    builder.put("Jscr", Character.toCodePoint('\ud835', '\udca5')); // MATHEMATICAL SCRIPT CAPITAL J
    builder.put("Kscr", Character.toCodePoint('\ud835', '\udca6')); // MATHEMATICAL SCRIPT CAPITAL K
    builder.put("Nscr", Character.toCodePoint('\ud835', '\udca9')); // MATHEMATICAL SCRIPT CAPITAL N
    builder.put("Oscr", Character.toCodePoint('\ud835', '\udcaa')); // MATHEMATICAL SCRIPT CAPITAL O
    builder.put("Pscr", Character.toCodePoint('\ud835', '\udcab')); // MATHEMATICAL SCRIPT CAPITAL P
    builder.put("Qscr", Character.toCodePoint('\ud835', '\udcac')); // MATHEMATICAL SCRIPT CAPITAL Q
    builder.put("Sscr", Character.toCodePoint('\ud835', '\udcae')); // MATHEMATICAL SCRIPT CAPITAL S
    builder.put("Tscr", Character.toCodePoint('\ud835', '\udcaf')); // MATHEMATICAL SCRIPT CAPITAL T
    builder.put("Uscr", Character.toCodePoint('\ud835', '\udcb0')); // MATHEMATICAL SCRIPT CAPITAL U
    builder.put("Vscr", Character.toCodePoint('\ud835', '\udcb1')); // MATHEMATICAL SCRIPT CAPITAL V
    builder.put("Wscr", Character.toCodePoint('\ud835', '\udcb2')); // MATHEMATICAL SCRIPT CAPITAL W
    builder.put("Xscr", Character.toCodePoint('\ud835', '\udcb3')); // MATHEMATICAL SCRIPT CAPITAL X
    builder.put("Yscr", Character.toCodePoint('\ud835', '\udcb4')); // MATHEMATICAL SCRIPT CAPITAL Y
    builder.put("Zscr", Character.toCodePoint('\ud835', '\udcb5')); // MATHEMATICAL SCRIPT CAPITAL Z
    builder.put("ascr", Character.toCodePoint('\ud835', '\udcb6')); // MATHEMATICAL SCRIPT SMALL A
    builder.put("bscr", Character.toCodePoint('\ud835', '\udcb7')); // MATHEMATICAL SCRIPT SMALL B
    builder.put("cscr", Character.toCodePoint('\ud835', '\udcb8')); // MATHEMATICAL SCRIPT SMALL C
    builder.put("dscr", Character.toCodePoint('\ud835', '\udcb9')); // MATHEMATICAL SCRIPT SMALL D
    builder.put("fscr", Character.toCodePoint('\ud835', '\udcbb')); // MATHEMATICAL SCRIPT SMALL F
    builder.put("hscr", Character.toCodePoint('\ud835', '\udcbd')); // MATHEMATICAL SCRIPT SMALL H
    builder.put("iscr", Character.toCodePoint('\ud835', '\udcbe')); // MATHEMATICAL SCRIPT SMALL I
    builder.put("jscr", Character.toCodePoint('\ud835', '\udcbf')); // MATHEMATICAL SCRIPT SMALL J
    builder.put("kscr", Character.toCodePoint('\ud835', '\udcc0')); // MATHEMATICAL SCRIPT SMALL K
    builder.put("lscr", Character.toCodePoint('\ud835', '\udcc1')); // MATHEMATICAL SCRIPT SMALL L
    builder.put("mscr", Character.toCodePoint('\ud835', '\udcc2')); // MATHEMATICAL SCRIPT SMALL M
    builder.put("nscr", Character.toCodePoint('\ud835', '\udcc3')); // MATHEMATICAL SCRIPT SMALL N
    builder.put("pscr", Character.toCodePoint('\ud835', '\udcc5')); // MATHEMATICAL SCRIPT SMALL P
    builder.put("qscr", Character.toCodePoint('\ud835', '\udcc6')); // MATHEMATICAL SCRIPT SMALL Q
    builder.put("rscr", Character.toCodePoint('\ud835', '\udcc7')); // MATHEMATICAL SCRIPT SMALL R
    builder.put("sscr", Character.toCodePoint('\ud835', '\udcc8')); // MATHEMATICAL SCRIPT SMALL S
    builder.put("tscr", Character.toCodePoint('\ud835', '\udcc9')); // MATHEMATICAL SCRIPT SMALL T
    builder.put("uscr", Character.toCodePoint('\ud835', '\udcca')); // MATHEMATICAL SCRIPT SMALL U
    builder.put("vscr", Character.toCodePoint('\ud835', '\udccb')); // MATHEMATICAL SCRIPT SMALL V
    builder.put("wscr", Character.toCodePoint('\ud835', '\udccc')); // MATHEMATICAL SCRIPT SMALL W
    builder.put("xscr", Character.toCodePoint('\ud835', '\udccd')); // MATHEMATICAL SCRIPT SMALL X
    builder.put("yscr", Character.toCodePoint('\ud835', '\udcce')); // MATHEMATICAL SCRIPT SMALL Y
    builder.put("zscr", Character.toCodePoint('\ud835', '\udccf')); // MATHEMATICAL SCRIPT SMALL Z
    builder.put("Afr", Character.toCodePoint('\ud835', '\udd04')); // MATHEMATICAL FRAKTUR CAPITAL A
    builder.put("Bfr", Character.toCodePoint('\ud835', '\udd05')); // MATHEMATICAL FRAKTUR CAPITAL B
    builder.put("Dfr", Character.toCodePoint('\ud835', '\udd07')); // MATHEMATICAL FRAKTUR CAPITAL D
    builder.put("Efr", Character.toCodePoint('\ud835', '\udd08')); // MATHEMATICAL FRAKTUR CAPITAL E
    builder.put("Ffr", Character.toCodePoint('\ud835', '\udd09')); // MATHEMATICAL FRAKTUR CAPITAL F
    builder.put("Gfr", Character.toCodePoint('\ud835', '\udd0a')); // MATHEMATICAL FRAKTUR CAPITAL G
    builder.put("Jfr", Character.toCodePoint('\ud835', '\udd0d')); // MATHEMATICAL FRAKTUR CAPITAL J
    builder.put("Kfr", Character.toCodePoint('\ud835', '\udd0e')); // MATHEMATICAL FRAKTUR CAPITAL K
    builder.put("Lfr", Character.toCodePoint('\ud835', '\udd0f')); // MATHEMATICAL FRAKTUR CAPITAL L
    builder.put("Mfr", Character.toCodePoint('\ud835', '\udd10')); // MATHEMATICAL FRAKTUR CAPITAL M
    builder.put("Nfr", Character.toCodePoint('\ud835', '\udd11')); // MATHEMATICAL FRAKTUR CAPITAL N
    builder.put("Ofr", Character.toCodePoint('\ud835', '\udd12')); // MATHEMATICAL FRAKTUR CAPITAL O
    builder.put("Pfr", Character.toCodePoint('\ud835', '\udd13')); // MATHEMATICAL FRAKTUR CAPITAL P
    builder.put("Qfr", Character.toCodePoint('\ud835', '\udd14')); // MATHEMATICAL FRAKTUR CAPITAL Q
    builder.put("Sfr", Character.toCodePoint('\ud835', '\udd16')); // MATHEMATICAL FRAKTUR CAPITAL S
    builder.put("Tfr", Character.toCodePoint('\ud835', '\udd17')); // MATHEMATICAL FRAKTUR CAPITAL T
    builder.put("Ufr", Character.toCodePoint('\ud835', '\udd18')); // MATHEMATICAL FRAKTUR CAPITAL U
    builder.put("Vfr", Character.toCodePoint('\ud835', '\udd19')); // MATHEMATICAL FRAKTUR CAPITAL V
    builder.put("Wfr", Character.toCodePoint('\ud835', '\udd1a')); // MATHEMATICAL FRAKTUR CAPITAL W
    builder.put("Xfr", Character.toCodePoint('\ud835', '\udd1b')); // MATHEMATICAL FRAKTUR CAPITAL X
    builder.put("Yfr", Character.toCodePoint('\ud835', '\udd1c')); // MATHEMATICAL FRAKTUR CAPITAL Y
    builder.put("afr", Character.toCodePoint('\ud835', '\udd1e')); // MATHEMATICAL FRAKTUR SMALL A
    builder.put("bfr", Character.toCodePoint('\ud835', '\udd1f')); // MATHEMATICAL FRAKTUR SMALL B
    builder.put("cfr", Character.toCodePoint('\ud835', '\udd20')); // MATHEMATICAL FRAKTUR SMALL C
    builder.put("dfr", Character.toCodePoint('\ud835', '\udd21')); // MATHEMATICAL FRAKTUR SMALL D
    builder.put("efr", Character.toCodePoint('\ud835', '\udd22')); // MATHEMATICAL FRAKTUR SMALL E
    builder.put("ffr", Character.toCodePoint('\ud835', '\udd23')); // MATHEMATICAL FRAKTUR SMALL F
    builder.put("gfr", Character.toCodePoint('\ud835', '\udd24')); // MATHEMATICAL FRAKTUR SMALL G
    builder.put("hfr", Character.toCodePoint('\ud835', '\udd25')); // MATHEMATICAL FRAKTUR SMALL H
    builder.put("ifr", Character.toCodePoint('\ud835', '\udd26')); // MATHEMATICAL FRAKTUR SMALL I
    builder.put("jfr", Character.toCodePoint('\ud835', '\udd27')); // MATHEMATICAL FRAKTUR SMALL J
    builder.put("kfr", Character.toCodePoint('\ud835', '\udd28')); // MATHEMATICAL FRAKTUR SMALL K
    builder.put("lfr", Character.toCodePoint('\ud835', '\udd29')); // MATHEMATICAL FRAKTUR SMALL L
    builder.put("mfr", Character.toCodePoint('\ud835', '\udd2a')); // MATHEMATICAL FRAKTUR SMALL M
    builder.put("nfr", Character.toCodePoint('\ud835', '\udd2b')); // MATHEMATICAL FRAKTUR SMALL N
    builder.put("ofr", Character.toCodePoint('\ud835', '\udd2c')); // MATHEMATICAL FRAKTUR SMALL O
    builder.put("pfr", Character.toCodePoint('\ud835', '\udd2d')); // MATHEMATICAL FRAKTUR SMALL P
    builder.put("qfr", Character.toCodePoint('\ud835', '\udd2e')); // MATHEMATICAL FRAKTUR SMALL Q
    builder.put("rfr", Character.toCodePoint('\ud835', '\udd2f')); // MATHEMATICAL FRAKTUR SMALL R
    builder.put("sfr", Character.toCodePoint('\ud835', '\udd30')); // MATHEMATICAL FRAKTUR SMALL S
    builder.put("tfr", Character.toCodePoint('\ud835', '\udd31')); // MATHEMATICAL FRAKTUR SMALL T
    builder.put("ufr", Character.toCodePoint('\ud835', '\udd32')); // MATHEMATICAL FRAKTUR SMALL U
    builder.put("vfr", Character.toCodePoint('\ud835', '\udd33')); // MATHEMATICAL FRAKTUR SMALL V
    builder.put("wfr", Character.toCodePoint('\ud835', '\udd34')); // MATHEMATICAL FRAKTUR SMALL W
    builder.put("xfr", Character.toCodePoint('\ud835', '\udd35')); // MATHEMATICAL FRAKTUR SMALL X
    builder.put("yfr", Character.toCodePoint('\ud835', '\udd36')); // MATHEMATICAL FRAKTUR SMALL Y
    builder.put("zfr", Character.toCodePoint('\ud835', '\udd37')); // MATHEMATICAL FRAKTUR SMALL Z
    builder.put("Aopf", Character.toCodePoint('\ud835', '\udd38')); // MATHEMATICAL DOUBLE-STRUCK CAPITAL A
    builder.put("Bopf", Character.toCodePoint('\ud835', '\udd39')); // MATHEMATICAL DOUBLE-STRUCK CAPITAL B
    builder.put("Dopf", Character.toCodePoint('\ud835', '\udd3b')); // MATHEMATICAL DOUBLE-STRUCK CAPITAL D
    builder.put("Eopf", Character.toCodePoint('\ud835', '\udd3c')); // MATHEMATICAL DOUBLE-STRUCK CAPITAL E
    builder.put("Fopf", Character.toCodePoint('\ud835', '\udd3d')); // MATHEMATICAL DOUBLE-STRUCK CAPITAL F
    builder.put("Gopf", Character.toCodePoint('\ud835', '\udd3e')); // MATHEMATICAL DOUBLE-STRUCK CAPITAL G
    builder.put("Iopf", Character.toCodePoint('\ud835', '\udd40')); // MATHEMATICAL DOUBLE-STRUCK CAPITAL I
    builder.put("Jopf", Character.toCodePoint('\ud835', '\udd41')); // MATHEMATICAL DOUBLE-STRUCK CAPITAL J
    builder.put("Kopf", Character.toCodePoint('\ud835', '\udd42')); // MATHEMATICAL DOUBLE-STRUCK CAPITAL K
    builder.put("Lopf", Character.toCodePoint('\ud835', '\udd43')); // MATHEMATICAL DOUBLE-STRUCK CAPITAL L
    builder.put("Mopf", Character.toCodePoint('\ud835', '\udd44')); // MATHEMATICAL DOUBLE-STRUCK CAPITAL M
    builder.put("Oopf", Character.toCodePoint('\ud835', '\udd46')); // MATHEMATICAL DOUBLE-STRUCK CAPITAL O
    builder.put("Sopf", Character.toCodePoint('\ud835', '\udd4a')); // MATHEMATICAL DOUBLE-STRUCK CAPITAL S
    builder.put("Topf", Character.toCodePoint('\ud835', '\udd4b')); // MATHEMATICAL DOUBLE-STRUCK CAPITAL T
    builder.put("Uopf", Character.toCodePoint('\ud835', '\udd4c')); // MATHEMATICAL DOUBLE-STRUCK CAPITAL U
    builder.put("Vopf", Character.toCodePoint('\ud835', '\udd4d')); // MATHEMATICAL DOUBLE-STRUCK CAPITAL V
    builder.put("Wopf", Character.toCodePoint('\ud835', '\udd4e')); // MATHEMATICAL DOUBLE-STRUCK CAPITAL W
    builder.put("Xopf", Character.toCodePoint('\ud835', '\udd4f')); // MATHEMATICAL DOUBLE-STRUCK CAPITAL X
    builder.put("Yopf", Character.toCodePoint('\ud835', '\udd50')); // MATHEMATICAL DOUBLE-STRUCK CAPITAL Y
    builder.put("aopf", Character.toCodePoint('\ud835', '\udd52')); // MATHEMATICAL DOUBLE-STRUCK SMALL A
    builder.put("bopf", Character.toCodePoint('\ud835', '\udd53')); // MATHEMATICAL DOUBLE-STRUCK SMALL B
    builder.put("copf", Character.toCodePoint('\ud835', '\udd54')); // MATHEMATICAL DOUBLE-STRUCK SMALL C
    builder.put("dopf", Character.toCodePoint('\ud835', '\udd55')); // MATHEMATICAL DOUBLE-STRUCK SMALL D
    builder.put("eopf", Character.toCodePoint('\ud835', '\udd56')); // MATHEMATICAL DOUBLE-STRUCK SMALL E
    builder.put("fopf", Character.toCodePoint('\ud835', '\udd57')); // MATHEMATICAL DOUBLE-STRUCK SMALL F
    builder.put("gopf", Character.toCodePoint('\ud835', '\udd58')); // MATHEMATICAL DOUBLE-STRUCK SMALL G
    builder.put("hopf", Character.toCodePoint('\ud835', '\udd59')); // MATHEMATICAL DOUBLE-STRUCK SMALL H
    builder.put("iopf", Character.toCodePoint('\ud835', '\udd5a')); // MATHEMATICAL DOUBLE-STRUCK SMALL I
    builder.put("jopf", Character.toCodePoint('\ud835', '\udd5b')); // MATHEMATICAL DOUBLE-STRUCK SMALL J
    builder.put("kopf", Character.toCodePoint('\ud835', '\udd5c')); // MATHEMATICAL DOUBLE-STRUCK SMALL K
    builder.put("lopf", Character.toCodePoint('\ud835', '\udd5d')); // MATHEMATICAL DOUBLE-STRUCK SMALL L
    builder.put("mopf", Character.toCodePoint('\ud835', '\udd5e')); // MATHEMATICAL DOUBLE-STRUCK SMALL M
    builder.put("nopf", Character.toCodePoint('\ud835', '\udd5f')); // MATHEMATICAL DOUBLE-STRUCK SMALL N
    builder.put("oopf", Character.toCodePoint('\ud835', '\udd60')); // MATHEMATICAL DOUBLE-STRUCK SMALL O
    builder.put("popf", Character.toCodePoint('\ud835', '\udd61')); // MATHEMATICAL DOUBLE-STRUCK SMALL P
    builder.put("qopf", Character.toCodePoint('\ud835', '\udd62')); // MATHEMATICAL DOUBLE-STRUCK SMALL Q
    builder.put("ropf", Character.toCodePoint('\ud835', '\udd63')); // MATHEMATICAL DOUBLE-STRUCK SMALL R
    builder.put("sopf", Character.toCodePoint('\ud835', '\udd64')); // MATHEMATICAL DOUBLE-STRUCK SMALL S
    builder.put("topf", Character.toCodePoint('\ud835', '\udd65')); // MATHEMATICAL DOUBLE-STRUCK SMALL T
    builder.put("uopf", Character.toCodePoint('\ud835', '\udd66')); // MATHEMATICAL DOUBLE-STRUCK SMALL U
    builder.put("vopf", Character.toCodePoint('\ud835', '\udd67')); // MATHEMATICAL DOUBLE-STRUCK SMALL V
    builder.put("wopf", Character.toCodePoint('\ud835', '\udd68')); // MATHEMATICAL DOUBLE-STRUCK SMALL W
    builder.put("xopf", Character.toCodePoint('\ud835', '\udd69')); // MATHEMATICAL DOUBLE-STRUCK SMALL X
    builder.put("yopf", Character.toCodePoint('\ud835', '\udd6a')); // MATHEMATICAL DOUBLE-STRUCK SMALL Y
    builder.put("zopf", Character.toCodePoint('\ud835', '\udd6b')); // MATHEMATICAL DOUBLE-STRUCK SMALL Z

    return builder.build();
  }

  private HtmlEntities() { /* uninstantiable */ }
}
