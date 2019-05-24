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

import com.google.common.collect.ImmutableMap;

/**
 * Utilities for decoding HTML entities, e.g., {@code &amp;}.
 */
final class HtmlEntities {

  private static final int LONGEST_ENTITY_NAME = 31; // CounterClockwiseContourIntegral

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
  public static final Trie ENTITY_TRIE = new Trie(
      ImmutableMap.<String, Integer>builder()
    // C0 Controls and Basic Latin
      .put("Tab", Integer.valueOf('\u0009')) // CHARACTER TABULATION
      .put("NewLine", Integer.valueOf('\n')) // LINE FEED (LF)
      .put("excl", Integer.valueOf('\u0021')) // EXCLAMATION MARK
      .put("quot", Integer.valueOf('\u0022')) // QUOTATION MARK
      .put("QUOT", Integer.valueOf('\u0022')) // QUOTATION MARK
      .put("num", Integer.valueOf('\u0023')) // NUMBER SIGN
      .put("dollar", Integer.valueOf('\u0024')) // DOLLAR SIGN
      .put("percnt", Integer.valueOf('\u0025')) // PERCENT SIGN
      .put("amp", Integer.valueOf('\u0026')) // AMPERSAND
      .put("AMP", Integer.valueOf('\u0026')) // AMPERSAND
      .put("apos", Integer.valueOf('\'')) // APOSTROPHE
      .put("lpar", Integer.valueOf('\u0028')) // LEFT PARENTHESIS
      .put("rpar", Integer.valueOf('\u0029')) // RIGHT PARENTHESIS
      .put("ast", Integer.valueOf('\u002a')) // ASTERISK
      .put("midast", Integer.valueOf('\u002a')) // ASTERISK
      .put("plus", Integer.valueOf('\u002b')) // PLUS SIGN
      .put("comma", Integer.valueOf('\u002c')) // COMMA
      .put("period", Integer.valueOf('\u002e')) // FULL STOP
      .put("sol", Integer.valueOf('\u002f')) // SOLIDUS
      .put("colon", Integer.valueOf('\u003a')) // COLON
      .put("semi", Integer.valueOf('\u003b')) // SEMICOLON
      .put("lt", Integer.valueOf('\u003c')) // LESS-THAN SIGN
      .put("LT", Integer.valueOf('\u003c')) // LESS-THAN SIGN
      .put("equals", Integer.valueOf('\u003d')) // EQUALS SIGN
      .put("gt", Integer.valueOf('\u003e')) // GREATER-THAN SIGN
      .put("GT", Integer.valueOf('\u003e')) // GREATER-THAN SIGN
      .put("quest", Integer.valueOf('\u003f')) // QUESTION MARK
      .put("commat", Integer.valueOf('\u0040')) // COMMERCIAL AT
      .put("lsqb", Integer.valueOf('\u005b')) // LEFT SQUARE BRACKET
      .put("lbrack", Integer.valueOf('\u005b')) // LEFT SQUARE BRACKET
      .put("bsol", Integer.valueOf('\\')) // REVERSE SOLIDUS
      .put("rsqb", Integer.valueOf('\u005d')) // RIGHT SQUARE BRACKET
      .put("rbrack", Integer.valueOf('\u005d')) // RIGHT SQUARE BRACKET
      .put("Hat", Integer.valueOf('\u005e')) // CIRCUMFLEX ACCENT
      .put("lowbar", Integer.valueOf('\u005f')) // LOW LINE
      .put("grave", Integer.valueOf('\u0060')) // GRAVE ACCENT
      .put("DiacriticalGrave", Integer.valueOf('\u0060')) // GRAVE ACCENT
      .put("lcub", Integer.valueOf('\u007b')) // LEFT CURLY BRACKET
      .put("lbrace", Integer.valueOf('\u007b')) // LEFT CURLY BRACKET
      .put("verbar", Integer.valueOf('\u007c')) // VERTICAL LINE
      .put("vert", Integer.valueOf('\u007c')) // VERTICAL LINE
      .put("VerticalLine", Integer.valueOf('\u007c')) // VERTICAL LINE
      .put("rcub", Integer.valueOf('\u007d')) // RIGHT CURLY BRACKET
      .put("rbrace", Integer.valueOf('\u007d')) // RIGHT CURLY BRACKET

    // C1 Controls and Latin-1 Supplement
      .put("nbsp", Integer.valueOf('\u00a0')) // NO-BREAK SPACE
      .put("NonBreakingSpace", Integer.valueOf('\u00a0')) // NO-BREAK SPACE
      .put("iexcl", Integer.valueOf('\u00a1')) // INVERTED EXCLAMATION MARK
      .put("cent", Integer.valueOf('\u00a2')) // CENT SIGN
      .put("pound", Integer.valueOf('\u00a3')) // POUND SIGN
      .put("curren", Integer.valueOf('\u00a4')) // CURRENCY SIGN
      .put("yen", Integer.valueOf('\u00a5')) // YEN SIGN
      .put("brvbar", Integer.valueOf('\u00a6')) // BROKEN BAR
      .put("sect", Integer.valueOf('\u00a7')) // SECTION SIGN
      .put("Dot", Integer.valueOf('\u00a8')) // DIAERESIS
      .put("die", Integer.valueOf('\u00a8')) // DIAERESIS
      .put("DoubleDot", Integer.valueOf('\u00a8')) // DIAERESIS
      .put("uml", Integer.valueOf('\u00a8')) // DIAERESIS
      .put("copy", Integer.valueOf('\u00a9')) // COPYRIGHT SIGN
      .put("COPY", Integer.valueOf('\u00a9')) // COPYRIGHT SIGN
      .put("ordf", Integer.valueOf('\u00aa')) // FEMININE ORDINAL INDICATOR
      .put("laquo", Integer.valueOf('\u00ab')) // LEFT-POINTING DOUBLE ANGLE QUOTATION MARK
      .put("not", Integer.valueOf('\u00ac')) // NOT SIGN
      .put("shy", Integer.valueOf('\u00ad')) // SOFT HYPHEN
      .put("reg", Integer.valueOf('\u00ae')) // REGISTERED SIGN
      .put("circledR", Integer.valueOf('\u00ae')) // REGISTERED SIGN
      .put("REG", Integer.valueOf('\u00ae')) // REGISTERED SIGN
      .put("macr", Integer.valueOf('\u00af')) // MACRON
      .put("OverBar", Integer.valueOf('\u00af')) // MACRON
      .put("strns", Integer.valueOf('\u00af')) // MACRON
      .put("deg", Integer.valueOf('\u00b0')) // DEGREE SIGN
      .put("plusmn", Integer.valueOf('\u00b1')) // PLUS-MINUS SIGN
      .put("pm", Integer.valueOf('\u00b1')) // PLUS-MINUS SIGN
      .put("PlusMinus", Integer.valueOf('\u00b1')) // PLUS-MINUS SIGN
      .put("sup2", Integer.valueOf('\u00b2')) // SUPERSCRIPT TWO
      .put("sup3", Integer.valueOf('\u00b3')) // SUPERSCRIPT THREE
      .put("acute", Integer.valueOf('\u00b4')) // ACUTE ACCENT
      .put("DiacriticalAcute", Integer.valueOf('\u00b4')) // ACUTE ACCENT
      .put("micro", Integer.valueOf('\u00b5')) // MICRO SIGN
      .put("para", Integer.valueOf('\u00b6')) // PILCROW SIGN
      .put("middot", Integer.valueOf('\u00b7')) // MIDDLE DOT
      .put("centerdot", Integer.valueOf('\u00b7')) // MIDDLE DOT
      .put("CenterDot", Integer.valueOf('\u00b7')) // MIDDLE DOT
      .put("cedil", Integer.valueOf('\u00b8')) // CEDILLA
      .put("Cedilla", Integer.valueOf('\u00b8')) // CEDILLA
      .put("sup1", Integer.valueOf('\u00b9')) // SUPERSCRIPT ONE
      .put("ordm", Integer.valueOf('\u00ba')) // MASCULINE ORDINAL INDICATOR
      .put("raquo", Integer.valueOf('\u00bb')) // RIGHT-POINTING DOUBLE ANGLE QUOTATION MARK
      .put("frac14", Integer.valueOf('\u00bc')) // VULGAR FRACTION ONE QUARTER
      .put("frac12", Integer.valueOf('\u00bd')) // VULGAR FRACTION ONE HALF
      .put("half", Integer.valueOf('\u00bd')) // VULGAR FRACTION ONE HALF
      .put("frac34", Integer.valueOf('\u00be')) // VULGAR FRACTION THREE QUARTERS
      .put("iquest", Integer.valueOf('\u00bf')) // INVERTED QUESTION MARK
      .put("Agrave", Integer.valueOf('\u00c0')) // LATIN CAPITAL LETTER A WITH GRAVE
      .put("Aacute", Integer.valueOf('\u00c1')) // LATIN CAPITAL LETTER A WITH ACUTE
      .put("Acirc", Integer.valueOf('\u00c2')) // LATIN CAPITAL LETTER A WITH CIRCUMFLEX
      .put("Atilde", Integer.valueOf('\u00c3')) // LATIN CAPITAL LETTER A WITH TILDE
      .put("Auml", Integer.valueOf('\u00c4')) // LATIN CAPITAL LETTER A WITH DIAERESIS
      .put("Aring", Integer.valueOf('\u00c5')) // LATIN CAPITAL LETTER A WITH RING ABOVE
      .put("AElig", Integer.valueOf('\u00c6')) // LATIN CAPITAL LETTER AE
      .put("Ccedil", Integer.valueOf('\u00c7')) // LATIN CAPITAL LETTER C WITH CEDILLA
      .put("Egrave", Integer.valueOf('\u00c8')) // LATIN CAPITAL LETTER E WITH GRAVE
      .put("Eacute", Integer.valueOf('\u00c9')) // LATIN CAPITAL LETTER E WITH ACUTE
      .put("Ecirc", Integer.valueOf('\u00ca')) // LATIN CAPITAL LETTER E WITH CIRCUMFLEX
      .put("Euml", Integer.valueOf('\u00cb')) // LATIN CAPITAL LETTER E WITH DIAERESIS
      .put("Igrave", Integer.valueOf('\u00cc')) // LATIN CAPITAL LETTER I WITH GRAVE
      .put("Iacute", Integer.valueOf('\u00cd')) // LATIN CAPITAL LETTER I WITH ACUTE
      .put("Icirc", Integer.valueOf('\u00ce')) // LATIN CAPITAL LETTER I WITH CIRCUMFLEX
      .put("Iuml", Integer.valueOf('\u00cf')) // LATIN CAPITAL LETTER I WITH DIAERESIS
      .put("ETH", Integer.valueOf('\u00d0')) // LATIN CAPITAL LETTER ETH
      .put("Ntilde", Integer.valueOf('\u00d1')) // LATIN CAPITAL LETTER N WITH TILDE
      .put("Ograve", Integer.valueOf('\u00d2')) // LATIN CAPITAL LETTER O WITH GRAVE
      .put("Oacute", Integer.valueOf('\u00d3')) // LATIN CAPITAL LETTER O WITH ACUTE
      .put("Ocirc", Integer.valueOf('\u00d4')) // LATIN CAPITAL LETTER O WITH CIRCUMFLEX
      .put("Otilde", Integer.valueOf('\u00d5')) // LATIN CAPITAL LETTER O WITH TILDE
      .put("Ouml", Integer.valueOf('\u00d6')) // LATIN CAPITAL LETTER O WITH DIAERESIS
      .put("times", Integer.valueOf('\u00d7')) // MULTIPLICATION SIGN
      .put("Oslash", Integer.valueOf('\u00d8')) // LATIN CAPITAL LETTER O WITH STROKE
      .put("Ugrave", Integer.valueOf('\u00d9')) // LATIN CAPITAL LETTER U WITH GRAVE
      .put("Uacute", Integer.valueOf('\u00da')) // LATIN CAPITAL LETTER U WITH ACUTE
      .put("Ucirc", Integer.valueOf('\u00db')) // LATIN CAPITAL LETTER U WITH CIRCUMFLEX
      .put("Uuml", Integer.valueOf('\u00dc')) // LATIN CAPITAL LETTER U WITH DIAERESIS
      .put("Yacute", Integer.valueOf('\u00dd')) // LATIN CAPITAL LETTER Y WITH ACUTE
      .put("THORN", Integer.valueOf('\u00de')) // LATIN CAPITAL LETTER THORN
      .put("szlig", Integer.valueOf('\u00df')) // LATIN SMALL LETTER SHARP S
      .put("agrave", Integer.valueOf('\u00e0')) // LATIN SMALL LETTER A WITH GRAVE
      .put("aacute", Integer.valueOf('\u00e1')) // LATIN SMALL LETTER A WITH ACUTE
      .put("acirc", Integer.valueOf('\u00e2')) // LATIN SMALL LETTER A WITH CIRCUMFLEX
      .put("atilde", Integer.valueOf('\u00e3')) // LATIN SMALL LETTER A WITH TILDE
      .put("auml", Integer.valueOf('\u00e4')) // LATIN SMALL LETTER A WITH DIAERESIS
      .put("aring", Integer.valueOf('\u00e5')) // LATIN SMALL LETTER A WITH RING ABOVE
      .put("aelig", Integer.valueOf('\u00e6')) // LATIN SMALL LETTER AE
      .put("ccedil", Integer.valueOf('\u00e7')) // LATIN SMALL LETTER C WITH CEDILLA
      .put("egrave", Integer.valueOf('\u00e8')) // LATIN SMALL LETTER E WITH GRAVE
      .put("eacute", Integer.valueOf('\u00e9')) // LATIN SMALL LETTER E WITH ACUTE
      .put("ecirc", Integer.valueOf('\u00ea')) // LATIN SMALL LETTER E WITH CIRCUMFLEX
      .put("euml", Integer.valueOf('\u00eb')) // LATIN SMALL LETTER E WITH DIAERESIS
      .put("igrave", Integer.valueOf('\u00ec')) // LATIN SMALL LETTER I WITH GRAVE
      .put("iacute", Integer.valueOf('\u00ed')) // LATIN SMALL LETTER I WITH ACUTE
      .put("icirc", Integer.valueOf('\u00ee')) // LATIN SMALL LETTER I WITH CIRCUMFLEX
      .put("iuml", Integer.valueOf('\u00ef')) // LATIN SMALL LETTER I WITH DIAERESIS
      .put("eth", Integer.valueOf('\u00f0')) // LATIN SMALL LETTER ETH
      .put("ntilde", Integer.valueOf('\u00f1')) // LATIN SMALL LETTER N WITH TILDE
      .put("ograve", Integer.valueOf('\u00f2')) // LATIN SMALL LETTER O WITH GRAVE
      .put("oacute", Integer.valueOf('\u00f3')) // LATIN SMALL LETTER O WITH ACUTE
      .put("ocirc", Integer.valueOf('\u00f4')) // LATIN SMALL LETTER O WITH CIRCUMFLEX
      .put("otilde", Integer.valueOf('\u00f5')) // LATIN SMALL LETTER O WITH TILDE
      .put("ouml", Integer.valueOf('\u00f6')) // LATIN SMALL LETTER O WITH DIAERESIS
      .put("divide", Integer.valueOf('\u00f7')) // DIVISION SIGN
      .put("div", Integer.valueOf('\u00f7')) // DIVISION SIGN
      .put("oslash", Integer.valueOf('\u00f8')) // LATIN SMALL LETTER O WITH STROKE
      .put("ugrave", Integer.valueOf('\u00f9')) // LATIN SMALL LETTER U WITH GRAVE
      .put("uacute", Integer.valueOf('\u00fa')) // LATIN SMALL LETTER U WITH ACUTE
      .put("ucirc", Integer.valueOf('\u00fb')) // LATIN SMALL LETTER U WITH CIRCUMFLEX
      .put("uuml", Integer.valueOf('\u00fc')) // LATIN SMALL LETTER U WITH DIAERESIS
      .put("yacute", Integer.valueOf('\u00fd')) // LATIN SMALL LETTER Y WITH ACUTE
      .put("thorn", Integer.valueOf('\u00fe')) // LATIN SMALL LETTER THORN
      .put("yuml", Integer.valueOf('\u00ff')) // LATIN SMALL LETTER Y WITH DIAERESIS

    // Latin Extended-A
      .put("Amacr", Integer.valueOf('\u0100')) // LATIN CAPITAL LETTER A WITH MACRON
      .put("amacr", Integer.valueOf('\u0101')) // LATIN SMALL LETTER A WITH MACRON
      .put("Abreve", Integer.valueOf('\u0102')) // LATIN CAPITAL LETTER A WITH BREVE
      .put("abreve", Integer.valueOf('\u0103')) // LATIN SMALL LETTER A WITH BREVE
      .put("Aogon", Integer.valueOf('\u0104')) // LATIN CAPITAL LETTER A WITH OGONEK
      .put("aogon", Integer.valueOf('\u0105')) // LATIN SMALL LETTER A WITH OGONEK
      .put("Cacute", Integer.valueOf('\u0106')) // LATIN CAPITAL LETTER C WITH ACUTE
      .put("cacute", Integer.valueOf('\u0107')) // LATIN SMALL LETTER C WITH ACUTE
      .put("Ccirc", Integer.valueOf('\u0108')) // LATIN CAPITAL LETTER C WITH CIRCUMFLEX
      .put("ccirc", Integer.valueOf('\u0109')) // LATIN SMALL LETTER C WITH CIRCUMFLEX
      .put("Cdot", Integer.valueOf('\u010a')) // LATIN CAPITAL LETTER C WITH DOT ABOVE
      .put("cdot", Integer.valueOf('\u010b')) // LATIN SMALL LETTER C WITH DOT ABOVE
      .put("Ccaron", Integer.valueOf('\u010c')) // LATIN CAPITAL LETTER C WITH CARON
      .put("ccaron", Integer.valueOf('\u010d')) // LATIN SMALL LETTER C WITH CARON
      .put("Dcaron", Integer.valueOf('\u010e')) // LATIN CAPITAL LETTER D WITH CARON
      .put("dcaron", Integer.valueOf('\u010f')) // LATIN SMALL LETTER D WITH CARON
      .put("Dstrok", Integer.valueOf('\u0110')) // LATIN CAPITAL LETTER D WITH STROKE
      .put("dstrok", Integer.valueOf('\u0111')) // LATIN SMALL LETTER D WITH STROKE
      .put("Emacr", Integer.valueOf('\u0112')) // LATIN CAPITAL LETTER E WITH MACRON
      .put("emacr", Integer.valueOf('\u0113')) // LATIN SMALL LETTER E WITH MACRON
      .put("Edot", Integer.valueOf('\u0116')) // LATIN CAPITAL LETTER E WITH DOT ABOVE
      .put("edot", Integer.valueOf('\u0117')) // LATIN SMALL LETTER E WITH DOT ABOVE
      .put("Eogon", Integer.valueOf('\u0118')) // LATIN CAPITAL LETTER E WITH OGONEK
      .put("eogon", Integer.valueOf('\u0119')) // LATIN SMALL LETTER E WITH OGONEK
      .put("Ecaron", Integer.valueOf('\u011a')) // LATIN CAPITAL LETTER E WITH CARON
      .put("ecaron", Integer.valueOf('\u011b')) // LATIN SMALL LETTER E WITH CARON
      .put("Gcirc", Integer.valueOf('\u011c')) // LATIN CAPITAL LETTER G WITH CIRCUMFLEX
      .put("gcirc", Integer.valueOf('\u011d')) // LATIN SMALL LETTER G WITH CIRCUMFLEX
      .put("Gbreve", Integer.valueOf('\u011e')) // LATIN CAPITAL LETTER G WITH BREVE
      .put("gbreve", Integer.valueOf('\u011f')) // LATIN SMALL LETTER G WITH BREVE
      .put("Gdot", Integer.valueOf('\u0120')) // LATIN CAPITAL LETTER G WITH DOT ABOVE
      .put("gdot", Integer.valueOf('\u0121')) // LATIN SMALL LETTER G WITH DOT ABOVE
      .put("Gcedil", Integer.valueOf('\u0122')) // LATIN CAPITAL LETTER G WITH CEDILLA
      .put("Hcirc", Integer.valueOf('\u0124')) // LATIN CAPITAL LETTER H WITH CIRCUMFLEX
      .put("hcirc", Integer.valueOf('\u0125')) // LATIN SMALL LETTER H WITH CIRCUMFLEX
      .put("Hstrok", Integer.valueOf('\u0126')) // LATIN CAPITAL LETTER H WITH STROKE
      .put("hstrok", Integer.valueOf('\u0127')) // LATIN SMALL LETTER H WITH STROKE
      .put("Itilde", Integer.valueOf('\u0128')) // LATIN CAPITAL LETTER I WITH TILDE
      .put("itilde", Integer.valueOf('\u0129')) // LATIN SMALL LETTER I WITH TILDE
      .put("Imacr", Integer.valueOf('\u012a')) // LATIN CAPITAL LETTER I WITH MACRON
      .put("imacr", Integer.valueOf('\u012b')) // LATIN SMALL LETTER I WITH MACRON
      .put("Iogon", Integer.valueOf('\u012e')) // LATIN CAPITAL LETTER I WITH OGONEK
      .put("iogon", Integer.valueOf('\u012f')) // LATIN SMALL LETTER I WITH OGONEK
      .put("Idot", Integer.valueOf('\u0130')) // LATIN CAPITAL LETTER I WITH DOT ABOVE
      .put("imath", Integer.valueOf('\u0131')) // LATIN SMALL LETTER DOTLESS I
      .put("inodot", Integer.valueOf('\u0131')) // LATIN SMALL LETTER DOTLESS I
      .put("IJlig", Integer.valueOf('\u0132')) // LATIN CAPITAL LIGATURE IJ
      .put("ijlig", Integer.valueOf('\u0133')) // LATIN SMALL LIGATURE IJ
      .put("Jcirc", Integer.valueOf('\u0134')) // LATIN CAPITAL LETTER J WITH CIRCUMFLEX
      .put("jcirc", Integer.valueOf('\u0135')) // LATIN SMALL LETTER J WITH CIRCUMFLEX
      .put("Kcedil", Integer.valueOf('\u0136')) // LATIN CAPITAL LETTER K WITH CEDILLA
      .put("kcedil", Integer.valueOf('\u0137')) // LATIN SMALL LETTER K WITH CEDILLA
      .put("kgreen", Integer.valueOf('\u0138')) // LATIN SMALL LETTER KRA
      .put("Lacute", Integer.valueOf('\u0139')) // LATIN CAPITAL LETTER L WITH ACUTE
      .put("lacute", Integer.valueOf('\u013a')) // LATIN SMALL LETTER L WITH ACUTE
      .put("Lcedil", Integer.valueOf('\u013b')) // LATIN CAPITAL LETTER L WITH CEDILLA
      .put("lcedil", Integer.valueOf('\u013c')) // LATIN SMALL LETTER L WITH CEDILLA
      .put("Lcaron", Integer.valueOf('\u013d')) // LATIN CAPITAL LETTER L WITH CARON
      .put("lcaron", Integer.valueOf('\u013e')) // LATIN SMALL LETTER L WITH CARON
      .put("Lmidot", Integer.valueOf('\u013f')) // LATIN CAPITAL LETTER L WITH MIDDLE DOT
      .put("lmidot", Integer.valueOf('\u0140')) // LATIN SMALL LETTER L WITH MIDDLE DOT
      .put("Lstrok", Integer.valueOf('\u0141')) // LATIN CAPITAL LETTER L WITH STROKE
      .put("lstrok", Integer.valueOf('\u0142')) // LATIN SMALL LETTER L WITH STROKE
      .put("Nacute", Integer.valueOf('\u0143')) // LATIN CAPITAL LETTER N WITH ACUTE
      .put("nacute", Integer.valueOf('\u0144')) // LATIN SMALL LETTER N WITH ACUTE
      .put("Ncedil", Integer.valueOf('\u0145')) // LATIN CAPITAL LETTER N WITH CEDILLA
      .put("ncedil", Integer.valueOf('\u0146')) // LATIN SMALL LETTER N WITH CEDILLA
      .put("Ncaron", Integer.valueOf('\u0147')) // LATIN CAPITAL LETTER N WITH CARON
      .put("ncaron", Integer.valueOf('\u0148')) // LATIN SMALL LETTER N WITH CARON
      .put("napos", Integer.valueOf('\u0149')) // LATIN SMALL LETTER N PRECEDED BY APOSTROPHE
      .put("ENG", Integer.valueOf('\u014a')) // LATIN CAPITAL LETTER ENG
      .put("eng", Integer.valueOf('\u014b')) // LATIN SMALL LETTER ENG
      .put("Omacr", Integer.valueOf('\u014c')) // LATIN CAPITAL LETTER O WITH MACRON
      .put("omacr", Integer.valueOf('\u014d')) // LATIN SMALL LETTER O WITH MACRON
      .put("Odblac", Integer.valueOf('\u0150')) // LATIN CAPITAL LETTER O WITH DOUBLE ACUTE
      .put("odblac", Integer.valueOf('\u0151')) // LATIN SMALL LETTER O WITH DOUBLE ACUTE
      .put("OElig", Integer.valueOf('\u0152')) // LATIN CAPITAL LIGATURE OE
      .put("oelig", Integer.valueOf('\u0153')) // LATIN SMALL LIGATURE OE
      .put("Racute", Integer.valueOf('\u0154')) // LATIN CAPITAL LETTER R WITH ACUTE
      .put("racute", Integer.valueOf('\u0155')) // LATIN SMALL LETTER R WITH ACUTE
      .put("Rcedil", Integer.valueOf('\u0156')) // LATIN CAPITAL LETTER R WITH CEDILLA
      .put("rcedil", Integer.valueOf('\u0157')) // LATIN SMALL LETTER R WITH CEDILLA
      .put("Rcaron", Integer.valueOf('\u0158')) // LATIN CAPITAL LETTER R WITH CARON
      .put("rcaron", Integer.valueOf('\u0159')) // LATIN SMALL LETTER R WITH CARON
      .put("Sacute", Integer.valueOf('\u015a')) // LATIN CAPITAL LETTER S WITH ACUTE
      .put("sacute", Integer.valueOf('\u015b')) // LATIN SMALL LETTER S WITH ACUTE
      .put("Scirc", Integer.valueOf('\u015c')) // LATIN CAPITAL LETTER S WITH CIRCUMFLEX
      .put("scirc", Integer.valueOf('\u015d')) // LATIN SMALL LETTER S WITH CIRCUMFLEX
      .put("Scedil", Integer.valueOf('\u015e')) // LATIN CAPITAL LETTER S WITH CEDILLA
      .put("scedil", Integer.valueOf('\u015f')) // LATIN SMALL LETTER S WITH CEDILLA
      .put("Scaron", Integer.valueOf('\u0160')) // LATIN CAPITAL LETTER S WITH CARON
      .put("scaron", Integer.valueOf('\u0161')) // LATIN SMALL LETTER S WITH CARON
      .put("Tcedil", Integer.valueOf('\u0162')) // LATIN CAPITAL LETTER T WITH CEDILLA
      .put("tcedil", Integer.valueOf('\u0163')) // LATIN SMALL LETTER T WITH CEDILLA
      .put("Tcaron", Integer.valueOf('\u0164')) // LATIN CAPITAL LETTER T WITH CARON
      .put("tcaron", Integer.valueOf('\u0165')) // LATIN SMALL LETTER T WITH CARON
      .put("Tstrok", Integer.valueOf('\u0166')) // LATIN CAPITAL LETTER T WITH STROKE
      .put("tstrok", Integer.valueOf('\u0167')) // LATIN SMALL LETTER T WITH STROKE
      .put("Utilde", Integer.valueOf('\u0168')) // LATIN CAPITAL LETTER U WITH TILDE
      .put("utilde", Integer.valueOf('\u0169')) // LATIN SMALL LETTER U WITH TILDE
      .put("Umacr", Integer.valueOf('\u016a')) // LATIN CAPITAL LETTER U WITH MACRON
      .put("umacr", Integer.valueOf('\u016b')) // LATIN SMALL LETTER U WITH MACRON
      .put("Ubreve", Integer.valueOf('\u016c')) // LATIN CAPITAL LETTER U WITH BREVE
      .put("ubreve", Integer.valueOf('\u016d')) // LATIN SMALL LETTER U WITH BREVE
      .put("Uring", Integer.valueOf('\u016e')) // LATIN CAPITAL LETTER U WITH RING ABOVE
      .put("uring", Integer.valueOf('\u016f')) // LATIN SMALL LETTER U WITH RING ABOVE
      .put("Udblac", Integer.valueOf('\u0170')) // LATIN CAPITAL LETTER U WITH DOUBLE ACUTE
      .put("udblac", Integer.valueOf('\u0171')) // LATIN SMALL LETTER U WITH DOUBLE ACUTE
      .put("Uogon", Integer.valueOf('\u0172')) // LATIN CAPITAL LETTER U WITH OGONEK
      .put("uogon", Integer.valueOf('\u0173')) // LATIN SMALL LETTER U WITH OGONEK
      .put("Wcirc", Integer.valueOf('\u0174')) // LATIN CAPITAL LETTER W WITH CIRCUMFLEX
      .put("wcirc", Integer.valueOf('\u0175')) // LATIN SMALL LETTER W WITH CIRCUMFLEX
      .put("Ycirc", Integer.valueOf('\u0176')) // LATIN CAPITAL LETTER Y WITH CIRCUMFLEX
      .put("ycirc", Integer.valueOf('\u0177')) // LATIN SMALL LETTER Y WITH CIRCUMFLEX
      .put("Yuml", Integer.valueOf('\u0178')) // LATIN CAPITAL LETTER Y WITH DIAERESIS
      .put("Zacute", Integer.valueOf('\u0179')) // LATIN CAPITAL LETTER Z WITH ACUTE
      .put("zacute", Integer.valueOf('\u017a')) // LATIN SMALL LETTER Z WITH ACUTE
      .put("Zdot", Integer.valueOf('\u017b')) // LATIN CAPITAL LETTER Z WITH DOT ABOVE
      .put("zdot", Integer.valueOf('\u017c')) // LATIN SMALL LETTER Z WITH DOT ABOVE
      .put("Zcaron", Integer.valueOf('\u017d')) // LATIN CAPITAL LETTER Z WITH CARON
      .put("zcaron", Integer.valueOf('\u017e')) // LATIN SMALL LETTER Z WITH CARON

    // Latin Extended-B
      .put("fnof", Integer.valueOf('\u0192')) // LATIN SMALL LETTER F WITH HOOK
      .put("imped", Integer.valueOf('\u01b5')) // LATIN CAPITAL LETTER Z WITH STROKE
      .put("gacute", Integer.valueOf('\u01f5')) // LATIN SMALL LETTER G WITH ACUTE
      .put("jmath", Integer.valueOf('\u0237')) // LATIN SMALL LETTER DOTLESS J

    // Spacing Modifier Letters
      .put("circ", Integer.valueOf('\u02c6')) // MODIFIER LETTER CIRCUMFLEX ACCENT
      .put("caron", Integer.valueOf('\u02c7')) // CARON
      .put("Hacek", Integer.valueOf('\u02c7')) // CARON
      .put("breve", Integer.valueOf('\u02d8')) // BREVE
      .put("Breve", Integer.valueOf('\u02d8')) // BREVE
      .put("dot", Integer.valueOf('\u02d9')) // DOT ABOVE
      .put("DiacriticalDot", Integer.valueOf('\u02d9')) // DOT ABOVE
      .put("ring", Integer.valueOf('\u02da')) // RING ABOVE
      .put("ogon", Integer.valueOf('\u02db')) // OGONEK
      .put("tilde", Integer.valueOf('\u02dc')) // SMALL TILDE
      .put("DiacriticalTilde", Integer.valueOf('\u02dc')) // SMALL TILDE
      .put("dblac", Integer.valueOf('\u02dd')) // DOUBLE ACUTE ACCENT
      .put("DiacriticalDoubleAcute", Integer.valueOf('\u02dd')) // DOUBLE ACUTE ACCENT

    // Combining Diacritical Marks
      .put("DownBreve", Integer.valueOf('\u0311')) // COMBINING INVERTED BREVE
      .put("UnderBar", Integer.valueOf('\u0332')) // COMBINING LOW LINE

    // Greek and Coptic
      .put("Alpha", Integer.valueOf('\u0391')) // GREEK CAPITAL LETTER ALPHA
      .put("Beta", Integer.valueOf('\u0392')) // GREEK CAPITAL LETTER BETA
      .put("Gamma", Integer.valueOf('\u0393')) // GREEK CAPITAL LETTER GAMMA
      .put("Delta", Integer.valueOf('\u0394')) // GREEK CAPITAL LETTER DELTA
      .put("Epsilon", Integer.valueOf('\u0395')) // GREEK CAPITAL LETTER EPSILON
      .put("Zeta", Integer.valueOf('\u0396')) // GREEK CAPITAL LETTER ZETA
      .put("Eta", Integer.valueOf('\u0397')) // GREEK CAPITAL LETTER ETA
      .put("Theta", Integer.valueOf('\u0398')) // GREEK CAPITAL LETTER THETA
      .put("Iota", Integer.valueOf('\u0399')) // GREEK CAPITAL LETTER IOTA
      .put("Kappa", Integer.valueOf('\u039a')) // GREEK CAPITAL LETTER KAPPA
      .put("Lambda", Integer.valueOf('\u039b')) // GREEK CAPITAL LETTER LAMDA
      .put("Mu", Integer.valueOf('\u039c')) // GREEK CAPITAL LETTER MU
      .put("Nu", Integer.valueOf('\u039d')) // GREEK CAPITAL LETTER NU
      .put("Xi", Integer.valueOf('\u039e')) // GREEK CAPITAL LETTER XI
      .put("Omicron", Integer.valueOf('\u039f')) // GREEK CAPITAL LETTER OMICRON
      .put("Pi", Integer.valueOf('\u03a0')) // GREEK CAPITAL LETTER PI
      .put("Rho", Integer.valueOf('\u03a1')) // GREEK CAPITAL LETTER RHO
      .put("Sigma", Integer.valueOf('\u03a3')) // GREEK CAPITAL LETTER SIGMA
      .put("Tau", Integer.valueOf('\u03a4')) // GREEK CAPITAL LETTER TAU
      .put("Upsilon", Integer.valueOf('\u03a5')) // GREEK CAPITAL LETTER UPSILON
      .put("Phi", Integer.valueOf('\u03a6')) // GREEK CAPITAL LETTER PHI
      .put("Chi", Integer.valueOf('\u03a7')) // GREEK CAPITAL LETTER CHI
      .put("Psi", Integer.valueOf('\u03a8')) // GREEK CAPITAL LETTER PSI
      .put("Omega", Integer.valueOf('\u03a9')) // GREEK CAPITAL LETTER OMEGA
      .put("alpha", Integer.valueOf('\u03b1')) // GREEK SMALL LETTER ALPHA
      .put("beta", Integer.valueOf('\u03b2')) // GREEK SMALL LETTER BETA
      .put("gamma", Integer.valueOf('\u03b3')) // GREEK SMALL LETTER GAMMA
      .put("delta", Integer.valueOf('\u03b4')) // GREEK SMALL LETTER DELTA
      .put("epsiv", Integer.valueOf('\u03b5')) // GREEK SMALL LETTER EPSILON
      .put("varepsilon", Integer.valueOf('\u03b5')) // GREEK SMALL LETTER EPSILON
      .put("epsilon", Integer.valueOf('\u03b5')) // GREEK SMALL LETTER EPSILON
      .put("zeta", Integer.valueOf('\u03b6')) // GREEK SMALL LETTER ZETA
      .put("eta", Integer.valueOf('\u03b7')) // GREEK SMALL LETTER ETA
      .put("theta", Integer.valueOf('\u03b8')) // GREEK SMALL LETTER THETA
      .put("iota", Integer.valueOf('\u03b9')) // GREEK SMALL LETTER IOTA
      .put("kappa", Integer.valueOf('\u03ba')) // GREEK SMALL LETTER KAPPA
      .put("lambda", Integer.valueOf('\u03bb')) // GREEK SMALL LETTER LAMDA
      .put("mu", Integer.valueOf('\u03bc')) // GREEK SMALL LETTER MU
      .put("nu", Integer.valueOf('\u03bd')) // GREEK SMALL LETTER NU
      .put("xi", Integer.valueOf('\u03be')) // GREEK SMALL LETTER XI
      .put("omicron", Integer.valueOf('\u03bf')) // GREEK SMALL LETTER OMICRON
      .put("pi", Integer.valueOf('\u03c0')) // GREEK SMALL LETTER PI
      .put("rho", Integer.valueOf('\u03c1')) // GREEK SMALL LETTER RHO
      .put("sigmav", Integer.valueOf('\u03c2')) // GREEK SMALL LETTER FINAL SIGMA
      .put("varsigma", Integer.valueOf('\u03c2')) // GREEK SMALL LETTER FINAL SIGMA
      .put("sigmaf", Integer.valueOf('\u03c2')) // GREEK SMALL LETTER FINAL SIGMA
      .put("sigma", Integer.valueOf('\u03c3')) // GREEK SMALL LETTER SIGMA
      .put("tau", Integer.valueOf('\u03c4')) // GREEK SMALL LETTER TAU
      .put("upsi", Integer.valueOf('\u03c5')) // GREEK SMALL LETTER UPSILON
      .put("upsilon", Integer.valueOf('\u03c5')) // GREEK SMALL LETTER UPSILON
      .put("phi", Integer.valueOf('\u03c6')) // GREEK SMALL LETTER PHI
      .put("phiv", Integer.valueOf('\u03c6')) // GREEK SMALL LETTER PHI
      .put("varphi", Integer.valueOf('\u03c6')) // GREEK SMALL LETTER PHI
      .put("chi", Integer.valueOf('\u03c7')) // GREEK SMALL LETTER CHI
      .put("psi", Integer.valueOf('\u03c8')) // GREEK SMALL LETTER PSI
      .put("omega", Integer.valueOf('\u03c9')) // GREEK SMALL LETTER OMEGA
      .put("thetav", Integer.valueOf('\u03d1')) // GREEK THETA SYMBOL
      .put("vartheta", Integer.valueOf('\u03d1')) // GREEK THETA SYMBOL
      .put("thetasym", Integer.valueOf('\u03d1')) // GREEK THETA SYMBOL
      .put("Upsi", Integer.valueOf('\u03d2')) // GREEK UPSILON WITH HOOK SYMBOL
      .put("upsih", Integer.valueOf('\u03d2')) // GREEK UPSILON WITH HOOK SYMBOL
      .put("straightphi", Integer.valueOf('\u03d5')) // GREEK PHI SYMBOL
      .put("piv", Integer.valueOf('\u03d6')) // GREEK PI SYMBOL
      .put("varpi", Integer.valueOf('\u03d6')) // GREEK PI SYMBOL
      .put("Gammad", Integer.valueOf('\u03dc')) // GREEK LETTER DIGAMMA
      .put("gammad", Integer.valueOf('\u03dd')) // GREEK SMALL LETTER DIGAMMA
      .put("digamma", Integer.valueOf('\u03dd')) // GREEK SMALL LETTER DIGAMMA
      .put("kappav", Integer.valueOf('\u03f0')) // GREEK KAPPA SYMBOL
      .put("varkappa", Integer.valueOf('\u03f0')) // GREEK KAPPA SYMBOL
      .put("rhov", Integer.valueOf('\u03f1')) // GREEK RHO SYMBOL
      .put("varrho", Integer.valueOf('\u03f1')) // GREEK RHO SYMBOL
      .put("epsi", Integer.valueOf('\u03f5')) // GREEK LUNATE EPSILON SYMBOL
      .put("straightepsilon", Integer.valueOf('\u03f5')) // GREEK LUNATE EPSILON SYMBOL
      .put("bepsi", Integer.valueOf('\u03f6')) // GREEK REVERSED LUNATE EPSILON SYMBOL
      .put("backepsilon", Integer.valueOf('\u03f6')) // GREEK REVERSED LUNATE EPSILON SYMBOL

    // Cyrillic
      .put("IOcy", Integer.valueOf('\u0401')) // CYRILLIC CAPITAL LETTER IO
      .put("DJcy", Integer.valueOf('\u0402')) // CYRILLIC CAPITAL LETTER DJE
      .put("GJcy", Integer.valueOf('\u0403')) // CYRILLIC CAPITAL LETTER GJE
      .put("Jukcy", Integer.valueOf('\u0404')) // CYRILLIC CAPITAL LETTER UKRAINIAN IE
      .put("DScy", Integer.valueOf('\u0405')) // CYRILLIC CAPITAL LETTER DZE
      .put("Iukcy", Integer.valueOf('\u0406')) // CYRILLIC CAPITAL LETTER BYELORUSSIAN-UKRAINIAN I
      .put("YIcy", Integer.valueOf('\u0407')) // CYRILLIC CAPITAL LETTER YI
      .put("Jsercy", Integer.valueOf('\u0408')) // CYRILLIC CAPITAL LETTER JE
      .put("LJcy", Integer.valueOf('\u0409')) // CYRILLIC CAPITAL LETTER LJE
      .put("NJcy", Integer.valueOf('\u040a')) // CYRILLIC CAPITAL LETTER NJE
      .put("TSHcy", Integer.valueOf('\u040b')) // CYRILLIC CAPITAL LETTER TSHE
      .put("KJcy", Integer.valueOf('\u040c')) // CYRILLIC CAPITAL LETTER KJE
      .put("Ubrcy", Integer.valueOf('\u040e')) // CYRILLIC CAPITAL LETTER SHORT U
      .put("DZcy", Integer.valueOf('\u040f')) // CYRILLIC CAPITAL LETTER DZHE
      .put("Acy", Integer.valueOf('\u0410')) // CYRILLIC CAPITAL LETTER A
      .put("Bcy", Integer.valueOf('\u0411')) // CYRILLIC CAPITAL LETTER BE
      .put("Vcy", Integer.valueOf('\u0412')) // CYRILLIC CAPITAL LETTER VE
      .put("Gcy", Integer.valueOf('\u0413')) // CYRILLIC CAPITAL LETTER GHE
      .put("Dcy", Integer.valueOf('\u0414')) // CYRILLIC CAPITAL LETTER DE
      .put("IEcy", Integer.valueOf('\u0415')) // CYRILLIC CAPITAL LETTER IE
      .put("ZHcy", Integer.valueOf('\u0416')) // CYRILLIC CAPITAL LETTER ZHE
      .put("Zcy", Integer.valueOf('\u0417')) // CYRILLIC CAPITAL LETTER ZE
      .put("Icy", Integer.valueOf('\u0418')) // CYRILLIC CAPITAL LETTER I
      .put("Jcy", Integer.valueOf('\u0419')) // CYRILLIC CAPITAL LETTER SHORT I
      .put("Kcy", Integer.valueOf('\u041a')) // CYRILLIC CAPITAL LETTER KA
      .put("Lcy", Integer.valueOf('\u041b')) // CYRILLIC CAPITAL LETTER EL
      .put("Mcy", Integer.valueOf('\u041c')) // CYRILLIC CAPITAL LETTER EM
      .put("Ncy", Integer.valueOf('\u041d')) // CYRILLIC CAPITAL LETTER EN
      .put("Ocy", Integer.valueOf('\u041e')) // CYRILLIC CAPITAL LETTER O
      .put("Pcy", Integer.valueOf('\u041f')) // CYRILLIC CAPITAL LETTER PE
      .put("Rcy", Integer.valueOf('\u0420')) // CYRILLIC CAPITAL LETTER ER
      .put("Scy", Integer.valueOf('\u0421')) // CYRILLIC CAPITAL LETTER ES
      .put("Tcy", Integer.valueOf('\u0422')) // CYRILLIC CAPITAL LETTER TE
      .put("Ucy", Integer.valueOf('\u0423')) // CYRILLIC CAPITAL LETTER U
      .put("Fcy", Integer.valueOf('\u0424')) // CYRILLIC CAPITAL LETTER EF
      .put("KHcy", Integer.valueOf('\u0425')) // CYRILLIC CAPITAL LETTER HA
      .put("TScy", Integer.valueOf('\u0426')) // CYRILLIC CAPITAL LETTER TSE
      .put("CHcy", Integer.valueOf('\u0427')) // CYRILLIC CAPITAL LETTER CHE
      .put("SHcy", Integer.valueOf('\u0428')) // CYRILLIC CAPITAL LETTER SHA
      .put("SHCHcy", Integer.valueOf('\u0429')) // CYRILLIC CAPITAL LETTER SHCHA
      .put("HARDcy", Integer.valueOf('\u042a')) // CYRILLIC CAPITAL LETTER HARD SIGN
      .put("Ycy", Integer.valueOf('\u042b')) // CYRILLIC CAPITAL LETTER YERU
      .put("SOFTcy", Integer.valueOf('\u042c')) // CYRILLIC CAPITAL LETTER SOFT SIGN
      .put("Ecy", Integer.valueOf('\u042d')) // CYRILLIC CAPITAL LETTER E
      .put("YUcy", Integer.valueOf('\u042e')) // CYRILLIC CAPITAL LETTER YU
      .put("YAcy", Integer.valueOf('\u042f')) // CYRILLIC CAPITAL LETTER YA
      .put("acy", Integer.valueOf('\u0430')) // CYRILLIC SMALL LETTER A
      .put("bcy", Integer.valueOf('\u0431')) // CYRILLIC SMALL LETTER BE
      .put("vcy", Integer.valueOf('\u0432')) // CYRILLIC SMALL LETTER VE
      .put("gcy", Integer.valueOf('\u0433')) // CYRILLIC SMALL LETTER GHE
      .put("dcy", Integer.valueOf('\u0434')) // CYRILLIC SMALL LETTER DE
      .put("iecy", Integer.valueOf('\u0435')) // CYRILLIC SMALL LETTER IE
      .put("zhcy", Integer.valueOf('\u0436')) // CYRILLIC SMALL LETTER ZHE
      .put("zcy", Integer.valueOf('\u0437')) // CYRILLIC SMALL LETTER ZE
      .put("icy", Integer.valueOf('\u0438')) // CYRILLIC SMALL LETTER I
      .put("jcy", Integer.valueOf('\u0439')) // CYRILLIC SMALL LETTER SHORT I
      .put("kcy", Integer.valueOf('\u043a')) // CYRILLIC SMALL LETTER KA
      .put("lcy", Integer.valueOf('\u043b')) // CYRILLIC SMALL LETTER EL
      .put("mcy", Integer.valueOf('\u043c')) // CYRILLIC SMALL LETTER EM
      .put("ncy", Integer.valueOf('\u043d')) // CYRILLIC SMALL LETTER EN
      .put("ocy", Integer.valueOf('\u043e')) // CYRILLIC SMALL LETTER O
      .put("pcy", Integer.valueOf('\u043f')) // CYRILLIC SMALL LETTER PE
      .put("rcy", Integer.valueOf('\u0440')) // CYRILLIC SMALL LETTER ER
      .put("scy", Integer.valueOf('\u0441')) // CYRILLIC SMALL LETTER ES
      .put("tcy", Integer.valueOf('\u0442')) // CYRILLIC SMALL LETTER TE
      .put("ucy", Integer.valueOf('\u0443')) // CYRILLIC SMALL LETTER U
      .put("fcy", Integer.valueOf('\u0444')) // CYRILLIC SMALL LETTER EF
      .put("khcy", Integer.valueOf('\u0445')) // CYRILLIC SMALL LETTER HA
      .put("tscy", Integer.valueOf('\u0446')) // CYRILLIC SMALL LETTER TSE
      .put("chcy", Integer.valueOf('\u0447')) // CYRILLIC SMALL LETTER CHE
      .put("shcy", Integer.valueOf('\u0448')) // CYRILLIC SMALL LETTER SHA
      .put("shchcy", Integer.valueOf('\u0449')) // CYRILLIC SMALL LETTER SHCHA
      .put("hardcy", Integer.valueOf('\u044a')) // CYRILLIC SMALL LETTER HARD SIGN
      .put("ycy", Integer.valueOf('\u044b')) // CYRILLIC SMALL LETTER YERU
      .put("softcy", Integer.valueOf('\u044c')) // CYRILLIC SMALL LETTER SOFT SIGN
      .put("ecy", Integer.valueOf('\u044d')) // CYRILLIC SMALL LETTER E
      .put("yucy", Integer.valueOf('\u044e')) // CYRILLIC SMALL LETTER YU
      .put("yacy", Integer.valueOf('\u044f')) // CYRILLIC SMALL LETTER YA
      .put("iocy", Integer.valueOf('\u0451')) // CYRILLIC SMALL LETTER IO
      .put("djcy", Integer.valueOf('\u0452')) // CYRILLIC SMALL LETTER DJE
      .put("gjcy", Integer.valueOf('\u0453')) // CYRILLIC SMALL LETTER GJE
      .put("jukcy", Integer.valueOf('\u0454')) // CYRILLIC SMALL LETTER UKRAINIAN IE
      .put("dscy", Integer.valueOf('\u0455')) // CYRILLIC SMALL LETTER DZE
      .put("iukcy", Integer.valueOf('\u0456')) // CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I
      .put("yicy", Integer.valueOf('\u0457')) // CYRILLIC SMALL LETTER YI
      .put("jsercy", Integer.valueOf('\u0458')) // CYRILLIC SMALL LETTER JE
      .put("ljcy", Integer.valueOf('\u0459')) // CYRILLIC SMALL LETTER LJE
      .put("njcy", Integer.valueOf('\u045a')) // CYRILLIC SMALL LETTER NJE
      .put("tshcy", Integer.valueOf('\u045b')) // CYRILLIC SMALL LETTER TSHE
      .put("kjcy", Integer.valueOf('\u045c')) // CYRILLIC SMALL LETTER KJE
      .put("ubrcy", Integer.valueOf('\u045e')) // CYRILLIC SMALL LETTER SHORT U
      .put("dzcy", Integer.valueOf('\u045f')) // CYRILLIC SMALL LETTER DZHE

    // General Punctuation
      .put("ensp", Integer.valueOf('\u2002')) // EN SPACE
      .put("emsp", Integer.valueOf('\u2003')) // EM SPACE
      .put("emsp13", Integer.valueOf('\u2004')) // THREE-PER-EM SPACE
      .put("emsp14", Integer.valueOf('\u2005')) // FOUR-PER-EM SPACE
      .put("numsp", Integer.valueOf('\u2007')) // FIGURE SPACE
      .put("puncsp", Integer.valueOf('\u2008')) // PUNCTUATION SPACE
      .put("thinsp", Integer.valueOf('\u2009')) // THIN SPACE
      .put("ThinSpace", Integer.valueOf('\u2009')) // THIN SPACE
      .put("hairsp", Integer.valueOf('\u200a')) // HAIR SPACE
      .put("VeryThinSpace", Integer.valueOf('\u200a')) // HAIR SPACE
      .put("ZeroWidthSpace", Integer.valueOf('\u200b')) // ZERO WIDTH SPACE
      .put("NegativeVeryThinSpace", Integer.valueOf('\u200b')) // ZERO WIDTH SPACE
      .put("NegativeThinSpace", Integer.valueOf('\u200b')) // ZERO WIDTH SPACE
      .put("NegativeMediumSpace", Integer.valueOf('\u200b')) // ZERO WIDTH SPACE
      .put("NegativeThickSpace", Integer.valueOf('\u200b')) // ZERO WIDTH SPACE
      .put("zwnj", Integer.valueOf('\u200c')) // ZERO WIDTH NON-JOINER
      .put("zwj", Integer.valueOf('\u200d')) // ZERO WIDTH JOINER
      .put("lrm", Integer.valueOf('\u200e')) // LEFT-TO-RIGHT MARK
      .put("rlm", Integer.valueOf('\u200f')) // RIGHT-TO-LEFT MARK
      .put("hyphen", Integer.valueOf('\u2010')) // HYPHEN
      .put("dash", Integer.valueOf('\u2010')) // HYPHEN
      .put("ndash", Integer.valueOf('\u2013')) // EN DASH
      .put("mdash", Integer.valueOf('\u2014')) // EM DASH
      .put("horbar", Integer.valueOf('\u2015')) // HORIZONTAL BAR
      .put("Verbar", Integer.valueOf('\u2016')) // DOUBLE VERTICAL LINE
      .put("Vert", Integer.valueOf('\u2016')) // DOUBLE VERTICAL LINE
      .put("lsquo", Integer.valueOf('\u2018')) // LEFT SINGLE QUOTATION MARK
      .put("OpenCurlyQuote", Integer.valueOf('\u2018')) // LEFT SINGLE QUOTATION MARK
      .put("rsquo", Integer.valueOf('\u2019')) // RIGHT SINGLE QUOTATION MARK
      .put("rsquor", Integer.valueOf('\u2019')) // RIGHT SINGLE QUOTATION MARK
      .put("CloseCurlyQuote", Integer.valueOf('\u2019')) // RIGHT SINGLE QUOTATION MARK
      .put("lsquor", Integer.valueOf('\u201a')) // SINGLE LOW-9 QUOTATION MARK
      .put("sbquo", Integer.valueOf('\u201a')) // SINGLE LOW-9 QUOTATION MARK
      .put("ldquo", Integer.valueOf('\u201c')) // LEFT DOUBLE QUOTATION MARK
      .put("OpenCurlyDoubleQuote", Integer.valueOf('\u201c')) // LEFT DOUBLE QUOTATION MARK
      .put("rdquo", Integer.valueOf('\u201d')) // RIGHT DOUBLE QUOTATION MARK
      .put("rdquor", Integer.valueOf('\u201d')) // RIGHT DOUBLE QUOTATION MARK
      .put("CloseCurlyDoubleQuote", Integer.valueOf('\u201d')) // RIGHT DOUBLE QUOTATION MARK
      .put("ldquor", Integer.valueOf('\u201e')) // DOUBLE LOW-9 QUOTATION MARK
      .put("bdquo", Integer.valueOf('\u201e')) // DOUBLE LOW-9 QUOTATION MARK
      .put("dagger", Integer.valueOf('\u2020')) // DAGGER
      .put("Dagger", Integer.valueOf('\u2021')) // DOUBLE DAGGER
      .put("ddagger", Integer.valueOf('\u2021')) // DOUBLE DAGGER
      .put("bull", Integer.valueOf('\u2022')) // BULLET
      .put("bullet", Integer.valueOf('\u2022')) // BULLET
      .put("nldr", Integer.valueOf('\u2025')) // TWO DOT LEADER
      .put("hellip", Integer.valueOf('\u2026')) // HORIZONTAL ELLIPSIS
      .put("mldr", Integer.valueOf('\u2026')) // HORIZONTAL ELLIPSIS
      .put("permil", Integer.valueOf('\u2030')) // PER MILLE SIGN
      .put("pertenk", Integer.valueOf('\u2031')) // PER TEN THOUSAND SIGN
      .put("prime", Integer.valueOf('\u2032')) // PRIME
      .put("Prime", Integer.valueOf('\u2033')) // DOUBLE PRIME
      .put("tprime", Integer.valueOf('\u2034')) // TRIPLE PRIME
      .put("bprime", Integer.valueOf('\u2035')) // REVERSED PRIME
      .put("backprime", Integer.valueOf('\u2035')) // REVERSED PRIME
      .put("lsaquo", Integer.valueOf('\u2039')) // SINGLE LEFT-POINTING ANGLE QUOTATION MARK
      .put("rsaquo", Integer.valueOf('\u203a')) // SINGLE RIGHT-POINTING ANGLE QUOTATION MARK
      .put("oline", Integer.valueOf('\u203e')) // OVERLINE
      .put("caret", Integer.valueOf('\u2041')) // CARET INSERTION POINT
      .put("hybull", Integer.valueOf('\u2043')) // HYPHEN BULLET
      .put("frasl", Integer.valueOf('\u2044')) // FRACTION SLASH
      .put("bsemi", Integer.valueOf('\u204f')) // REVERSED SEMICOLON
      .put("qprime", Integer.valueOf('\u2057')) // QUADRUPLE PRIME
      .put("MediumSpace", Integer.valueOf('\u205f')) // MEDIUM MATHEMATICAL SPACE
      .put("NoBreak", Integer.valueOf('\u2060')) // WORD JOINER
      .put("ApplyFunction", Integer.valueOf('\u2061')) // FUNCTION APPLICATION
      .put("af", Integer.valueOf('\u2061')) // FUNCTION APPLICATION
      .put("InvisibleTimes", Integer.valueOf('\u2062')) // INVISIBLE TIMES
      .put("it", Integer.valueOf('\u2062')) // INVISIBLE TIMES
      .put("InvisibleComma", Integer.valueOf('\u2063')) // INVISIBLE SEPARATOR
      .put("ic", Integer.valueOf('\u2063')) // INVISIBLE SEPARATOR

    // Currency Symbols
      .put("euro", Integer.valueOf('\u20ac')) // EURO SIGN

    // Combining Diacritical Marks for Symbols
      .put("tdot", Integer.valueOf('\u20db')) // COMBINING THREE DOTS ABOVE
      .put("TripleDot", Integer.valueOf('\u20db')) // COMBINING THREE DOTS ABOVE
      .put("DotDot", Integer.valueOf('\u20dc')) // COMBINING FOUR DOTS ABOVE

    // Letterlike Symbols
      .put("Copf", Integer.valueOf('\u2102')) // DOUBLE-STRUCK CAPITAL C
      .put("complexes", Integer.valueOf('\u2102')) // DOUBLE-STRUCK CAPITAL C
      .put("incare", Integer.valueOf('\u2105')) // CARE OF
      .put("gscr", Integer.valueOf('\u210a')) // SCRIPT SMALL G
      .put("hamilt", Integer.valueOf('\u210b')) // SCRIPT CAPITAL H
      .put("HilbertSpace", Integer.valueOf('\u210b')) // SCRIPT CAPITAL H
      .put("Hscr", Integer.valueOf('\u210b')) // SCRIPT CAPITAL H
      .put("Hfr", Integer.valueOf('\u210c')) // BLACK-LETTER CAPITAL H
      .put("Poincareplane", Integer.valueOf('\u210c')) // BLACK-LETTER CAPITAL H
      .put("quaternions", Integer.valueOf('\u210d')) // DOUBLE-STRUCK CAPITAL H
      .put("Hopf", Integer.valueOf('\u210d')) // DOUBLE-STRUCK CAPITAL H
      .put("planckh", Integer.valueOf('\u210e')) // PLANCK CONSTANT
      .put("planck", Integer.valueOf('\u210f')) // PLANCK CONSTANT OVER TWO PI
      .put("hbar", Integer.valueOf('\u210f')) // PLANCK CONSTANT OVER TWO PI
      .put("plankv", Integer.valueOf('\u210f')) // PLANCK CONSTANT OVER TWO PI
      .put("hslash", Integer.valueOf('\u210f')) // PLANCK CONSTANT OVER TWO PI
      .put("Iscr", Integer.valueOf('\u2110')) // SCRIPT CAPITAL I
      .put("imagline", Integer.valueOf('\u2110')) // SCRIPT CAPITAL I
      .put("image", Integer.valueOf('\u2111')) // BLACK-LETTER CAPITAL I
      .put("Im", Integer.valueOf('\u2111')) // BLACK-LETTER CAPITAL I
      .put("imagpart", Integer.valueOf('\u2111')) // BLACK-LETTER CAPITAL I
      .put("Ifr", Integer.valueOf('\u2111')) // BLACK-LETTER CAPITAL I
      .put("Lscr", Integer.valueOf('\u2112')) // SCRIPT CAPITAL L
      .put("lagran", Integer.valueOf('\u2112')) // SCRIPT CAPITAL L
      .put("Laplacetrf", Integer.valueOf('\u2112')) // SCRIPT CAPITAL L
      .put("ell", Integer.valueOf('\u2113')) // SCRIPT SMALL L
      .put("Nopf", Integer.valueOf('\u2115')) // DOUBLE-STRUCK CAPITAL N
      .put("naturals", Integer.valueOf('\u2115')) // DOUBLE-STRUCK CAPITAL N
      .put("numero", Integer.valueOf('\u2116')) // NUMERO SIGN
      .put("copysr", Integer.valueOf('\u2117')) // SOUND RECORDING COPYRIGHT
      .put("weierp", Integer.valueOf('\u2118')) // SCRIPT CAPITAL P
      .put("wp", Integer.valueOf('\u2118')) // SCRIPT CAPITAL P
      .put("Popf", Integer.valueOf('\u2119')) // DOUBLE-STRUCK CAPITAL P
      .put("primes", Integer.valueOf('\u2119')) // DOUBLE-STRUCK CAPITAL P
      .put("rationals", Integer.valueOf('\u211a')) // DOUBLE-STRUCK CAPITAL Q
      .put("Qopf", Integer.valueOf('\u211a')) // DOUBLE-STRUCK CAPITAL Q
      .put("Rscr", Integer.valueOf('\u211b')) // SCRIPT CAPITAL R
      .put("realine", Integer.valueOf('\u211b')) // SCRIPT CAPITAL R
      .put("real", Integer.valueOf('\u211c')) // BLACK-LETTER CAPITAL R
      .put("Re", Integer.valueOf('\u211c')) // BLACK-LETTER CAPITAL R
      .put("realpart", Integer.valueOf('\u211c')) // BLACK-LETTER CAPITAL R
      .put("Rfr", Integer.valueOf('\u211c')) // BLACK-LETTER CAPITAL R
      .put("reals", Integer.valueOf('\u211d')) // DOUBLE-STRUCK CAPITAL R
      .put("Ropf", Integer.valueOf('\u211d')) // DOUBLE-STRUCK CAPITAL R
      .put("rx", Integer.valueOf('\u211e')) // PRESCRIPTION TAKE
      .put("trade", Integer.valueOf('\u2122')) // TRADE MARK SIGN
      .put("TRADE", Integer.valueOf('\u2122')) // TRADE MARK SIGN
      .put("integers", Integer.valueOf('\u2124')) // DOUBLE-STRUCK CAPITAL Z
      .put("Zopf", Integer.valueOf('\u2124')) // DOUBLE-STRUCK CAPITAL Z
      .put("ohm", Integer.valueOf('\u2126')) // OHM SIGN
      .put("mho", Integer.valueOf('\u2127')) // INVERTED OHM SIGN
      .put("Zfr", Integer.valueOf('\u2128')) // BLACK-LETTER CAPITAL Z
      .put("zeetrf", Integer.valueOf('\u2128')) // BLACK-LETTER CAPITAL Z
      .put("iiota", Integer.valueOf('\u2129')) // TURNED GREEK SMALL LETTER IOTA
      .put("angst", Integer.valueOf('\u212b')) // ANGSTROM SIGN
      .put("bernou", Integer.valueOf('\u212c')) // SCRIPT CAPITAL B
      .put("Bernoullis", Integer.valueOf('\u212c')) // SCRIPT CAPITAL B
      .put("Bscr", Integer.valueOf('\u212c')) // SCRIPT CAPITAL B
      .put("Cfr", Integer.valueOf('\u212d')) // BLACK-LETTER CAPITAL C
      .put("Cayleys", Integer.valueOf('\u212d')) // BLACK-LETTER CAPITAL C
      .put("escr", Integer.valueOf('\u212f')) // SCRIPT SMALL E
      .put("Escr", Integer.valueOf('\u2130')) // SCRIPT CAPITAL E
      .put("expectation", Integer.valueOf('\u2130')) // SCRIPT CAPITAL E
      .put("Fscr", Integer.valueOf('\u2131')) // SCRIPT CAPITAL F
      .put("Fouriertrf", Integer.valueOf('\u2131')) // SCRIPT CAPITAL F
      .put("phmmat", Integer.valueOf('\u2133')) // SCRIPT CAPITAL M
      .put("Mellintrf", Integer.valueOf('\u2133')) // SCRIPT CAPITAL M
      .put("Mscr", Integer.valueOf('\u2133')) // SCRIPT CAPITAL M
      .put("order", Integer.valueOf('\u2134')) // SCRIPT SMALL O
      .put("orderof", Integer.valueOf('\u2134')) // SCRIPT SMALL O
      .put("oscr", Integer.valueOf('\u2134')) // SCRIPT SMALL O
      .put("alefsym", Integer.valueOf('\u2135')) // ALEF SYMBOL
      .put("aleph", Integer.valueOf('\u2135')) // ALEF SYMBOL
      .put("beth", Integer.valueOf('\u2136')) // BET SYMBOL
      .put("gimel", Integer.valueOf('\u2137')) // GIMEL SYMBOL
      .put("daleth", Integer.valueOf('\u2138')) // DALET SYMBOL
      .put("CapitalDifferentialD", Integer.valueOf('\u2145')) // DOUBLE-STRUCK ITALIC CAPITAL D
      .put("DD", Integer.valueOf('\u2145')) // DOUBLE-STRUCK ITALIC CAPITAL D
      .put("DifferentialD", Integer.valueOf('\u2146')) // DOUBLE-STRUCK ITALIC SMALL D
      .put("dd", Integer.valueOf('\u2146')) // DOUBLE-STRUCK ITALIC SMALL D
      .put("ExponentialE", Integer.valueOf('\u2147')) // DOUBLE-STRUCK ITALIC SMALL E
      .put("exponentiale", Integer.valueOf('\u2147')) // DOUBLE-STRUCK ITALIC SMALL E
      .put("ee", Integer.valueOf('\u2147')) // DOUBLE-STRUCK ITALIC SMALL E
      .put("ImaginaryI", Integer.valueOf('\u2148')) // DOUBLE-STRUCK ITALIC SMALL I
      .put("ii", Integer.valueOf('\u2148')) // DOUBLE-STRUCK ITALIC SMALL I

    // Number Forms
      .put("frac13", Integer.valueOf('\u2153')) // VULGAR FRACTION ONE THIRD
      .put("frac23", Integer.valueOf('\u2154')) // VULGAR FRACTION TWO THIRDS
      .put("frac15", Integer.valueOf('\u2155')) // VULGAR FRACTION ONE FIFTH
      .put("frac25", Integer.valueOf('\u2156')) // VULGAR FRACTION TWO FIFTHS
      .put("frac35", Integer.valueOf('\u2157')) // VULGAR FRACTION THREE FIFTHS
      .put("frac45", Integer.valueOf('\u2158')) // VULGAR FRACTION FOUR FIFTHS
      .put("frac16", Integer.valueOf('\u2159')) // VULGAR FRACTION ONE SIXTH
      .put("frac56", Integer.valueOf('\u215a')) // VULGAR FRACTION FIVE SIXTHS
      .put("frac18", Integer.valueOf('\u215b')) // VULGAR FRACTION ONE EIGHTH
      .put("frac38", Integer.valueOf('\u215c')) // VULGAR FRACTION THREE EIGHTHS
      .put("frac58", Integer.valueOf('\u215d')) // VULGAR FRACTION FIVE EIGHTHS
      .put("frac78", Integer.valueOf('\u215e')) // VULGAR FRACTION SEVEN EIGHTHS

    // Arrows
      .put("larr", Integer.valueOf('\u2190')) // LEFTWARDS ARROW
      .put("leftarrow", Integer.valueOf('\u2190')) // LEFTWARDS ARROW
      .put("LeftArrow", Integer.valueOf('\u2190')) // LEFTWARDS ARROW
      .put("slarr", Integer.valueOf('\u2190')) // LEFTWARDS ARROW
      .put("ShortLeftArrow", Integer.valueOf('\u2190')) // LEFTWARDS ARROW
      .put("uarr", Integer.valueOf('\u2191')) // UPWARDS ARROW
      .put("uparrow", Integer.valueOf('\u2191')) // UPWARDS ARROW
      .put("UpArrow", Integer.valueOf('\u2191')) // UPWARDS ARROW
      .put("ShortUpArrow", Integer.valueOf('\u2191')) // UPWARDS ARROW
      .put("rarr", Integer.valueOf('\u2192')) // RIGHTWARDS ARROW
      .put("rightarrow", Integer.valueOf('\u2192')) // RIGHTWARDS ARROW
      .put("RightArrow", Integer.valueOf('\u2192')) // RIGHTWARDS ARROW
      .put("srarr", Integer.valueOf('\u2192')) // RIGHTWARDS ARROW
      .put("ShortRightArrow", Integer.valueOf('\u2192')) // RIGHTWARDS ARROW
      .put("darr", Integer.valueOf('\u2193')) // DOWNWARDS ARROW
      .put("downarrow", Integer.valueOf('\u2193')) // DOWNWARDS ARROW
      .put("DownArrow", Integer.valueOf('\u2193')) // DOWNWARDS ARROW
      .put("ShortDownArrow", Integer.valueOf('\u2193')) // DOWNWARDS ARROW
      .put("harr", Integer.valueOf('\u2194')) // LEFT RIGHT ARROW
      .put("leftrightarrow", Integer.valueOf('\u2194')) // LEFT RIGHT ARROW
      .put("LeftRightArrow", Integer.valueOf('\u2194')) // LEFT RIGHT ARROW
      .put("varr", Integer.valueOf('\u2195')) // UP DOWN ARROW
      .put("updownarrow", Integer.valueOf('\u2195')) // UP DOWN ARROW
      .put("UpDownArrow", Integer.valueOf('\u2195')) // UP DOWN ARROW
      .put("nwarr", Integer.valueOf('\u2196')) // NORTH WEST ARROW
      .put("UpperLeftArrow", Integer.valueOf('\u2196')) // NORTH WEST ARROW
      .put("nwarrow", Integer.valueOf('\u2196')) // NORTH WEST ARROW
      .put("nearr", Integer.valueOf('\u2197')) // NORTH EAST ARROW
      .put("UpperRightArrow", Integer.valueOf('\u2197')) // NORTH EAST ARROW
      .put("nearrow", Integer.valueOf('\u2197')) // NORTH EAST ARROW
      .put("searr", Integer.valueOf('\u2198')) // SOUTH EAST ARROW
      .put("searrow", Integer.valueOf('\u2198')) // SOUTH EAST ARROW
      .put("LowerRightArrow", Integer.valueOf('\u2198')) // SOUTH EAST ARROW
      .put("swarr", Integer.valueOf('\u2199')) // SOUTH WEST ARROW
      .put("swarrow", Integer.valueOf('\u2199')) // SOUTH WEST ARROW
      .put("LowerLeftArrow", Integer.valueOf('\u2199')) // SOUTH WEST ARROW
      .put("nlarr", Integer.valueOf('\u219a')) // LEFTWARDS ARROW WITH STROKE
      .put("nleftarrow", Integer.valueOf('\u219a')) // LEFTWARDS ARROW WITH STROKE
      .put("nrarr", Integer.valueOf('\u219b')) // RIGHTWARDS ARROW WITH STROKE
      .put("nrightarrow", Integer.valueOf('\u219b')) // RIGHTWARDS ARROW WITH STROKE
      .put("rarrw", Integer.valueOf('\u219d')) // RIGHTWARDS WAVE ARROW
      .put("rightsquigarrow", Integer.valueOf('\u219d')) // RIGHTWARDS WAVE ARROW
      .put("Larr", Integer.valueOf('\u219e')) // LEFTWARDS TWO HEADED ARROW
      .put("twoheadleftarrow", Integer.valueOf('\u219e')) // LEFTWARDS TWO HEADED ARROW
      .put("Uarr", Integer.valueOf('\u219f')) // UPWARDS TWO HEADED ARROW
      .put("Rarr", Integer.valueOf('\u21a0')) // RIGHTWARDS TWO HEADED ARROW
      .put("twoheadrightarrow", Integer.valueOf('\u21a0')) // RIGHTWARDS TWO HEADED ARROW
      .put("Darr", Integer.valueOf('\u21a1')) // DOWNWARDS TWO HEADED ARROW
      .put("larrtl", Integer.valueOf('\u21a2')) // LEFTWARDS ARROW WITH TAIL
      .put("leftarrowtail", Integer.valueOf('\u21a2')) // LEFTWARDS ARROW WITH TAIL
      .put("rarrtl", Integer.valueOf('\u21a3')) // RIGHTWARDS ARROW WITH TAIL
      .put("rightarrowtail", Integer.valueOf('\u21a3')) // RIGHTWARDS ARROW WITH TAIL
      .put("LeftTeeArrow", Integer.valueOf('\u21a4')) // LEFTWARDS ARROW FROM BAR
      .put("mapstoleft", Integer.valueOf('\u21a4')) // LEFTWARDS ARROW FROM BAR
      .put("UpTeeArrow", Integer.valueOf('\u21a5')) // UPWARDS ARROW FROM BAR
      .put("mapstoup", Integer.valueOf('\u21a5')) // UPWARDS ARROW FROM BAR
      .put("map", Integer.valueOf('\u21a6')) // RIGHTWARDS ARROW FROM BAR
      .put("RightTeeArrow", Integer.valueOf('\u21a6')) // RIGHTWARDS ARROW FROM BAR
      .put("mapsto", Integer.valueOf('\u21a6')) // RIGHTWARDS ARROW FROM BAR
      .put("DownTeeArrow", Integer.valueOf('\u21a7')) // DOWNWARDS ARROW FROM BAR
      .put("mapstodown", Integer.valueOf('\u21a7')) // DOWNWARDS ARROW FROM BAR
      .put("larrhk", Integer.valueOf('\u21a9')) // LEFTWARDS ARROW WITH HOOK
      .put("hookleftarrow", Integer.valueOf('\u21a9')) // LEFTWARDS ARROW WITH HOOK
      .put("rarrhk", Integer.valueOf('\u21aa')) // RIGHTWARDS ARROW WITH HOOK
      .put("hookrightarrow", Integer.valueOf('\u21aa')) // RIGHTWARDS ARROW WITH HOOK
      .put("larrlp", Integer.valueOf('\u21ab')) // LEFTWARDS ARROW WITH LOOP
      .put("looparrowleft", Integer.valueOf('\u21ab')) // LEFTWARDS ARROW WITH LOOP
      .put("rarrlp", Integer.valueOf('\u21ac')) // RIGHTWARDS ARROW WITH LOOP
      .put("looparrowright", Integer.valueOf('\u21ac')) // RIGHTWARDS ARROW WITH LOOP
      .put("harrw", Integer.valueOf('\u21ad')) // LEFT RIGHT WAVE ARROW
      .put("leftrightsquigarrow", Integer.valueOf('\u21ad')) // LEFT RIGHT WAVE ARROW
      .put("nharr", Integer.valueOf('\u21ae')) // LEFT RIGHT ARROW WITH STROKE
      .put("nleftrightarrow", Integer.valueOf('\u21ae')) // LEFT RIGHT ARROW WITH STROKE
      .put("lsh", Integer.valueOf('\u21b0')) // UPWARDS ARROW WITH TIP LEFTWARDS
      .put("Lsh", Integer.valueOf('\u21b0')) // UPWARDS ARROW WITH TIP LEFTWARDS
      .put("rsh", Integer.valueOf('\u21b1')) // UPWARDS ARROW WITH TIP RIGHTWARDS
      .put("Rsh", Integer.valueOf('\u21b1')) // UPWARDS ARROW WITH TIP RIGHTWARDS
      .put("ldsh", Integer.valueOf('\u21b2')) // DOWNWARDS ARROW WITH TIP LEFTWARDS
      .put("rdsh", Integer.valueOf('\u21b3')) // DOWNWARDS ARROW WITH TIP RIGHTWARDS
      .put("crarr", Integer.valueOf('\u21b5')) // DOWNWARDS ARROW WITH CORNER LEFTWARDS
      .put("cularr", Integer.valueOf('\u21b6')) // ANTICLOCKWISE TOP SEMICIRCLE ARROW
      .put("curvearrowleft", Integer.valueOf('\u21b6')) // ANTICLOCKWISE TOP SEMICIRCLE ARROW
      .put("curarr", Integer.valueOf('\u21b7')) // CLOCKWISE TOP SEMICIRCLE ARROW
      .put("curvearrowright", Integer.valueOf('\u21b7')) // CLOCKWISE TOP SEMICIRCLE ARROW
      .put("olarr", Integer.valueOf('\u21ba')) // ANTICLOCKWISE OPEN CIRCLE ARROW
      .put("circlearrowleft", Integer.valueOf('\u21ba')) // ANTICLOCKWISE OPEN CIRCLE ARROW
      .put("orarr", Integer.valueOf('\u21bb')) // CLOCKWISE OPEN CIRCLE ARROW
      .put("circlearrowright", Integer.valueOf('\u21bb')) // CLOCKWISE OPEN CIRCLE ARROW
      .put("lharu", Integer.valueOf('\u21bc')) // LEFTWARDS HARPOON WITH BARB UPWARDS
      .put("LeftVector", Integer.valueOf('\u21bc')) // LEFTWARDS HARPOON WITH BARB UPWARDS
      .put("leftharpoonup", Integer.valueOf('\u21bc')) // LEFTWARDS HARPOON WITH BARB UPWARDS
      .put("lhard", Integer.valueOf('\u21bd')) // LEFTWARDS HARPOON WITH BARB DOWNWARDS
      .put("leftharpoondown", Integer.valueOf('\u21bd')) // LEFTWARDS HARPOON WITH BARB DOWNWARDS
      .put("DownLeftVector", Integer.valueOf('\u21bd')) // LEFTWARDS HARPOON WITH BARB DOWNWARDS
      .put("uharr", Integer.valueOf('\u21be')) // UPWARDS HARPOON WITH BARB RIGHTWARDS
      .put("upharpoonright", Integer.valueOf('\u21be')) // UPWARDS HARPOON WITH BARB RIGHTWARDS
      .put("RightUpVector", Integer.valueOf('\u21be')) // UPWARDS HARPOON WITH BARB RIGHTWARDS
      .put("uharl", Integer.valueOf('\u21bf')) // UPWARDS HARPOON WITH BARB LEFTWARDS
      .put("upharpoonleft", Integer.valueOf('\u21bf')) // UPWARDS HARPOON WITH BARB LEFTWARDS
      .put("LeftUpVector", Integer.valueOf('\u21bf')) // UPWARDS HARPOON WITH BARB LEFTWARDS
      .put("rharu", Integer.valueOf('\u21c0')) // RIGHTWARDS HARPOON WITH BARB UPWARDS
      .put("RightVector", Integer.valueOf('\u21c0')) // RIGHTWARDS HARPOON WITH BARB UPWARDS
      .put("rightharpoonup", Integer.valueOf('\u21c0')) // RIGHTWARDS HARPOON WITH BARB UPWARDS
      .put("rhard", Integer.valueOf('\u21c1')) // RIGHTWARDS HARPOON WITH BARB DOWNWARDS
      .put("rightharpoondown", Integer.valueOf('\u21c1')) // RIGHTWARDS HARPOON WITH BARB DOWNWARDS
      .put("DownRightVector", Integer.valueOf('\u21c1')) // RIGHTWARDS HARPOON WITH BARB DOWNWARDS
      .put("dharr", Integer.valueOf('\u21c2')) // DOWNWARDS HARPOON WITH BARB RIGHTWARDS
      .put("RightDownVector", Integer.valueOf('\u21c2')) // DOWNWARDS HARPOON WITH BARB RIGHTWARDS
      .put("downharpoonright", Integer.valueOf('\u21c2')) // DOWNWARDS HARPOON WITH BARB RIGHTWARDS
      .put("dharl", Integer.valueOf('\u21c3')) // DOWNWARDS HARPOON WITH BARB LEFTWARDS
      .put("LeftDownVector", Integer.valueOf('\u21c3')) // DOWNWARDS HARPOON WITH BARB LEFTWARDS
      .put("downharpoonleft", Integer.valueOf('\u21c3')) // DOWNWARDS HARPOON WITH BARB LEFTWARDS
      .put("rlarr", Integer.valueOf('\u21c4')) // RIGHTWARDS ARROW OVER LEFTWARDS ARROW
      .put("rightleftarrows", Integer.valueOf('\u21c4')) // RIGHTWARDS ARROW OVER LEFTWARDS ARROW
      .put("RightArrowLeftArrow", Integer.valueOf('\u21c4')) // RIGHTWARDS ARROW OVER LEFTWARDS ARROW
      .put("udarr", Integer.valueOf('\u21c5')) // UPWARDS ARROW LEFTWARDS OF DOWNWARDS ARROW
      .put("UpArrowDownArrow", Integer.valueOf('\u21c5')) // UPWARDS ARROW LEFTWARDS OF DOWNWARDS ARROW
      .put("lrarr", Integer.valueOf('\u21c6')) // LEFTWARDS ARROW OVER RIGHTWARDS ARROW
      .put("leftrightarrows", Integer.valueOf('\u21c6')) // LEFTWARDS ARROW OVER RIGHTWARDS ARROW
      .put("LeftArrowRightArrow", Integer.valueOf('\u21c6')) // LEFTWARDS ARROW OVER RIGHTWARDS ARROW
      .put("llarr", Integer.valueOf('\u21c7')) // LEFTWARDS PAIRED ARROWS
      .put("leftleftarrows", Integer.valueOf('\u21c7')) // LEFTWARDS PAIRED ARROWS
      .put("uuarr", Integer.valueOf('\u21c8')) // UPWARDS PAIRED ARROWS
      .put("upuparrows", Integer.valueOf('\u21c8')) // UPWARDS PAIRED ARROWS
      .put("rrarr", Integer.valueOf('\u21c9')) // RIGHTWARDS PAIRED ARROWS
      .put("rightrightarrows", Integer.valueOf('\u21c9')) // RIGHTWARDS PAIRED ARROWS
      .put("ddarr", Integer.valueOf('\u21ca')) // DOWNWARDS PAIRED ARROWS
      .put("downdownarrows", Integer.valueOf('\u21ca')) // DOWNWARDS PAIRED ARROWS
      .put("lrhar", Integer.valueOf('\u21cb')) // LEFTWARDS HARPOON OVER RIGHTWARDS HARPOON
      .put("ReverseEquilibrium", Integer.valueOf('\u21cb')) // LEFTWARDS HARPOON OVER RIGHTWARDS HARPOON
      .put("leftrightharpoons", Integer.valueOf('\u21cb')) // LEFTWARDS HARPOON OVER RIGHTWARDS HARPOON
      .put("rlhar", Integer.valueOf('\u21cc')) // RIGHTWARDS HARPOON OVER LEFTWARDS HARPOON
      .put("rightleftharpoons", Integer.valueOf('\u21cc')) // RIGHTWARDS HARPOON OVER LEFTWARDS HARPOON
      .put("Equilibrium", Integer.valueOf('\u21cc')) // RIGHTWARDS HARPOON OVER LEFTWARDS HARPOON
      .put("nlArr", Integer.valueOf('\u21cd')) // LEFTWARDS DOUBLE ARROW WITH STROKE
      .put("nLeftarrow", Integer.valueOf('\u21cd')) // LEFTWARDS DOUBLE ARROW WITH STROKE
      .put("nhArr", Integer.valueOf('\u21ce')) // LEFT RIGHT DOUBLE ARROW WITH STROKE
      .put("nLeftrightarrow", Integer.valueOf('\u21ce')) // LEFT RIGHT DOUBLE ARROW WITH STROKE
      .put("nrArr", Integer.valueOf('\u21cf')) // RIGHTWARDS DOUBLE ARROW WITH STROKE
      .put("nRightarrow", Integer.valueOf('\u21cf')) // RIGHTWARDS DOUBLE ARROW WITH STROKE
      .put("lArr", Integer.valueOf('\u21d0')) // LEFTWARDS DOUBLE ARROW
      .put("Leftarrow", Integer.valueOf('\u21d0')) // LEFTWARDS DOUBLE ARROW
      .put("DoubleLeftArrow", Integer.valueOf('\u21d0')) // LEFTWARDS DOUBLE ARROW
      .put("uArr", Integer.valueOf('\u21d1')) // UPWARDS DOUBLE ARROW
      .put("Uparrow", Integer.valueOf('\u21d1')) // UPWARDS DOUBLE ARROW
      .put("DoubleUpArrow", Integer.valueOf('\u21d1')) // UPWARDS DOUBLE ARROW
      .put("rArr", Integer.valueOf('\u21d2')) // RIGHTWARDS DOUBLE ARROW
      .put("Rightarrow", Integer.valueOf('\u21d2')) // RIGHTWARDS DOUBLE ARROW
      .put("Implies", Integer.valueOf('\u21d2')) // RIGHTWARDS DOUBLE ARROW
      .put("DoubleRightArrow", Integer.valueOf('\u21d2')) // RIGHTWARDS DOUBLE ARROW
      .put("dArr", Integer.valueOf('\u21d3')) // DOWNWARDS DOUBLE ARROW
      .put("Downarrow", Integer.valueOf('\u21d3')) // DOWNWARDS DOUBLE ARROW
      .put("DoubleDownArrow", Integer.valueOf('\u21d3')) // DOWNWARDS DOUBLE ARROW
      .put("hArr", Integer.valueOf('\u21d4')) // LEFT RIGHT DOUBLE ARROW
      .put("Leftrightarrow", Integer.valueOf('\u21d4')) // LEFT RIGHT DOUBLE ARROW
      .put("DoubleLeftRightArrow", Integer.valueOf('\u21d4')) // LEFT RIGHT DOUBLE ARROW
      .put("iff", Integer.valueOf('\u21d4')) // LEFT RIGHT DOUBLE ARROW
      .put("vArr", Integer.valueOf('\u21d5')) // UP DOWN DOUBLE ARROW
      .put("Updownarrow", Integer.valueOf('\u21d5')) // UP DOWN DOUBLE ARROW
      .put("DoubleUpDownArrow", Integer.valueOf('\u21d5')) // UP DOWN DOUBLE ARROW
      .put("nwArr", Integer.valueOf('\u21d6')) // NORTH WEST DOUBLE ARROW
      .put("neArr", Integer.valueOf('\u21d7')) // NORTH EAST DOUBLE ARROW
      .put("seArr", Integer.valueOf('\u21d8')) // SOUTH EAST DOUBLE ARROW
      .put("swArr", Integer.valueOf('\u21d9')) // SOUTH WEST DOUBLE ARROW
      .put("lAarr", Integer.valueOf('\u21da')) // LEFTWARDS TRIPLE ARROW
      .put("Lleftarrow", Integer.valueOf('\u21da')) // LEFTWARDS TRIPLE ARROW
      .put("rAarr", Integer.valueOf('\u21db')) // RIGHTWARDS TRIPLE ARROW
      .put("Rrightarrow", Integer.valueOf('\u21db')) // RIGHTWARDS TRIPLE ARROW
      .put("zigrarr", Integer.valueOf('\u21dd')) // RIGHTWARDS SQUIGGLE ARROW
      .put("larrb", Integer.valueOf('\u21e4')) // LEFTWARDS ARROW TO BAR
      .put("LeftArrowBar", Integer.valueOf('\u21e4')) // LEFTWARDS ARROW TO BAR
      .put("rarrb", Integer.valueOf('\u21e5')) // RIGHTWARDS ARROW TO BAR
      .put("RightArrowBar", Integer.valueOf('\u21e5')) // RIGHTWARDS ARROW TO BAR
      .put("duarr", Integer.valueOf('\u21f5')) // DOWNWARDS ARROW LEFTWARDS OF UPWARDS ARROW
      .put("DownArrowUpArrow", Integer.valueOf('\u21f5')) // DOWNWARDS ARROW LEFTWARDS OF UPWARDS ARROW
      .put("loarr", Integer.valueOf('\u21fd')) // LEFTWARDS OPEN-HEADED ARROW
      .put("roarr", Integer.valueOf('\u21fe')) // RIGHTWARDS OPEN-HEADED ARROW
      .put("hoarr", Integer.valueOf('\u21ff')) // LEFT RIGHT OPEN-HEADED ARROW

    // Mathematical Operators
      .put("forall", Integer.valueOf('\u2200')) // FOR ALL
      .put("ForAll", Integer.valueOf('\u2200')) // FOR ALL
      .put("comp", Integer.valueOf('\u2201')) // COMPLEMENT
      .put("complement", Integer.valueOf('\u2201')) // COMPLEMENT
      .put("part", Integer.valueOf('\u2202')) // PARTIAL DIFFERENTIAL
      .put("PartialD", Integer.valueOf('\u2202')) // PARTIAL DIFFERENTIAL
      .put("exist", Integer.valueOf('\u2203')) // THERE EXISTS
      .put("Exists", Integer.valueOf('\u2203')) // THERE EXISTS
      .put("nexist", Integer.valueOf('\u2204')) // THERE DOES NOT EXIST
      .put("NotExists", Integer.valueOf('\u2204')) // THERE DOES NOT EXIST
      .put("nexists", Integer.valueOf('\u2204')) // THERE DOES NOT EXIST
      .put("empty", Integer.valueOf('\u2205')) // EMPTY SET
      .put("emptyset", Integer.valueOf('\u2205')) // EMPTY SET
      .put("emptyv", Integer.valueOf('\u2205')) // EMPTY SET
      .put("varnothing", Integer.valueOf('\u2205')) // EMPTY SET
      .put("nabla", Integer.valueOf('\u2207')) // NABLA
      .put("Del", Integer.valueOf('\u2207')) // NABLA
      .put("isin", Integer.valueOf('\u2208')) // ELEMENT OF
      .put("isinv", Integer.valueOf('\u2208')) // ELEMENT OF
      .put("Element", Integer.valueOf('\u2208')) // ELEMENT OF
      .put("in", Integer.valueOf('\u2208')) // ELEMENT OF
      .put("notin", Integer.valueOf('\u2209')) // NOT AN ELEMENT OF
      .put("NotElement", Integer.valueOf('\u2209')) // NOT AN ELEMENT OF
      .put("notinva", Integer.valueOf('\u2209')) // NOT AN ELEMENT OF
      .put("niv", Integer.valueOf('\u220b')) // CONTAINS AS MEMBER
      .put("ReverseElement", Integer.valueOf('\u220b')) // CONTAINS AS MEMBER
      .put("ni", Integer.valueOf('\u220b')) // CONTAINS AS MEMBER
      .put("SuchThat", Integer.valueOf('\u220b')) // CONTAINS AS MEMBER
      .put("notni", Integer.valueOf('\u220c')) // DOES NOT CONTAIN AS MEMBER
      .put("notniva", Integer.valueOf('\u220c')) // DOES NOT CONTAIN AS MEMBER
      .put("NotReverseElement", Integer.valueOf('\u220c')) // DOES NOT CONTAIN AS MEMBER
      .put("prod", Integer.valueOf('\u220f')) // N-ARY PRODUCT
      .put("Product", Integer.valueOf('\u220f')) // N-ARY PRODUCT
      .put("coprod", Integer.valueOf('\u2210')) // N-ARY COPRODUCT
      .put("Coproduct", Integer.valueOf('\u2210')) // N-ARY COPRODUCT
      .put("sum", Integer.valueOf('\u2211')) // N-ARY SUMMATION
      .put("Sum", Integer.valueOf('\u2211')) // N-ARY SUMMATION
      .put("minus", Integer.valueOf('\u2212')) // MINUS SIGN
      .put("mnplus", Integer.valueOf('\u2213')) // MINUS-OR-PLUS SIGN
      .put("mp", Integer.valueOf('\u2213')) // MINUS-OR-PLUS SIGN
      .put("MinusPlus", Integer.valueOf('\u2213')) // MINUS-OR-PLUS SIGN
      .put("plusdo", Integer.valueOf('\u2214')) // DOT PLUS
      .put("dotplus", Integer.valueOf('\u2214')) // DOT PLUS
      .put("setmn", Integer.valueOf('\u2216')) // SET MINUS
      .put("setminus", Integer.valueOf('\u2216')) // SET MINUS
      .put("Backslash", Integer.valueOf('\u2216')) // SET MINUS
      .put("ssetmn", Integer.valueOf('\u2216')) // SET MINUS
      .put("smallsetminus", Integer.valueOf('\u2216')) // SET MINUS
      .put("lowast", Integer.valueOf('\u2217')) // ASTERISK OPERATOR
      .put("compfn", Integer.valueOf('\u2218')) // RING OPERATOR
      .put("SmallCircle", Integer.valueOf('\u2218')) // RING OPERATOR
      .put("radic", Integer.valueOf('\u221a')) // SQUARE ROOT
      .put("Sqrt", Integer.valueOf('\u221a')) // SQUARE ROOT
      .put("prop", Integer.valueOf('\u221d')) // PROPORTIONAL TO
      .put("propto", Integer.valueOf('\u221d')) // PROPORTIONAL TO
      .put("Proportional", Integer.valueOf('\u221d')) // PROPORTIONAL TO
      .put("vprop", Integer.valueOf('\u221d')) // PROPORTIONAL TO
      .put("varpropto", Integer.valueOf('\u221d')) // PROPORTIONAL TO
      .put("infin", Integer.valueOf('\u221e')) // INFINITY
      .put("angrt", Integer.valueOf('\u221f')) // RIGHT ANGLE
      .put("ang", Integer.valueOf('\u2220')) // ANGLE
      .put("angle", Integer.valueOf('\u2220')) // ANGLE
      .put("angmsd", Integer.valueOf('\u2221')) // MEASURED ANGLE
      .put("measuredangle", Integer.valueOf('\u2221')) // MEASURED ANGLE
      .put("angsph", Integer.valueOf('\u2222')) // SPHERICAL ANGLE
      .put("mid", Integer.valueOf('\u2223')) // DIVIDES
      .put("VerticalBar", Integer.valueOf('\u2223')) // DIVIDES
      .put("smid", Integer.valueOf('\u2223')) // DIVIDES
      .put("shortmid", Integer.valueOf('\u2223')) // DIVIDES
      .put("nmid", Integer.valueOf('\u2224')) // DOES NOT DIVIDE
      .put("NotVerticalBar", Integer.valueOf('\u2224')) // DOES NOT DIVIDE
      .put("nsmid", Integer.valueOf('\u2224')) // DOES NOT DIVIDE
      .put("nshortmid", Integer.valueOf('\u2224')) // DOES NOT DIVIDE
      .put("par", Integer.valueOf('\u2225')) // PARALLEL TO
      .put("parallel", Integer.valueOf('\u2225')) // PARALLEL TO
      .put("DoubleVerticalBar", Integer.valueOf('\u2225')) // PARALLEL TO
      .put("spar", Integer.valueOf('\u2225')) // PARALLEL TO
      .put("shortparallel", Integer.valueOf('\u2225')) // PARALLEL TO
      .put("npar", Integer.valueOf('\u2226')) // NOT PARALLEL TO
      .put("nparallel", Integer.valueOf('\u2226')) // NOT PARALLEL TO
      .put("NotDoubleVerticalBar", Integer.valueOf('\u2226')) // NOT PARALLEL TO
      .put("nspar", Integer.valueOf('\u2226')) // NOT PARALLEL TO
      .put("nshortparallel", Integer.valueOf('\u2226')) // NOT PARALLEL TO
      .put("and", Integer.valueOf('\u2227')) // LOGICAL AND
      .put("wedge", Integer.valueOf('\u2227')) // LOGICAL AND
      .put("or", Integer.valueOf('\u2228')) // LOGICAL OR
      .put("vee", Integer.valueOf('\u2228')) // LOGICAL OR
      .put("cap", Integer.valueOf('\u2229')) // INTERSECTION
      .put("cup", Integer.valueOf('\u222a')) // UNION
      .put("int", Integer.valueOf('\u222b')) // INTEGRAL
      .put("Integral", Integer.valueOf('\u222b')) // INTEGRAL
      .put("Int", Integer.valueOf('\u222c')) // DOUBLE INTEGRAL
      .put("tint", Integer.valueOf('\u222d')) // TRIPLE INTEGRAL
      .put("iiint", Integer.valueOf('\u222d')) // TRIPLE INTEGRAL
      .put("conint", Integer.valueOf('\u222e')) // CONTOUR INTEGRAL
      .put("oint", Integer.valueOf('\u222e')) // CONTOUR INTEGRAL
      .put("ContourIntegral", Integer.valueOf('\u222e')) // CONTOUR INTEGRAL
      .put("Conint", Integer.valueOf('\u222f')) // SURFACE INTEGRAL
      .put("DoubleContourIntegral", Integer.valueOf('\u222f')) // SURFACE INTEGRAL
      .put("Cconint", Integer.valueOf('\u2230')) // VOLUME INTEGRAL
      .put("cwint", Integer.valueOf('\u2231')) // CLOCKWISE INTEGRAL
      .put("cwconint", Integer.valueOf('\u2232')) // CLOCKWISE CONTOUR INTEGRAL
      .put("ClockwiseContourIntegral", Integer.valueOf('\u2232')) // CLOCKWISE CONTOUR INTEGRAL
      .put("awconint", Integer.valueOf('\u2233')) // ANTICLOCKWISE CONTOUR INTEGRAL
      .put("CounterClockwiseContourIntegral", Integer.valueOf('\u2233')) // ANTICLOCKWISE CONTOUR INTEGRAL
      .put("there4", Integer.valueOf('\u2234')) // THEREFORE
      .put("therefore", Integer.valueOf('\u2234')) // THEREFORE
      .put("Therefore", Integer.valueOf('\u2234')) // THEREFORE
      .put("becaus", Integer.valueOf('\u2235')) // BECAUSE
      .put("because", Integer.valueOf('\u2235')) // BECAUSE
      .put("Because", Integer.valueOf('\u2235')) // BECAUSE
      .put("ratio", Integer.valueOf('\u2236')) // RATIO
      .put("Colon", Integer.valueOf('\u2237')) // PROPORTION
      .put("Proportion", Integer.valueOf('\u2237')) // PROPORTION
      .put("minusd", Integer.valueOf('\u2238')) // DOT MINUS
      .put("dotminus", Integer.valueOf('\u2238')) // DOT MINUS
      .put("mDDot", Integer.valueOf('\u223a')) // GEOMETRIC PROPORTION
      .put("homtht", Integer.valueOf('\u223b')) // HOMOTHETIC
      .put("sim", Integer.valueOf('\u223c')) // TILDE OPERATOR
      .put("Tilde", Integer.valueOf('\u223c')) // TILDE OPERATOR
      .put("thksim", Integer.valueOf('\u223c')) // TILDE OPERATOR
      .put("thicksim", Integer.valueOf('\u223c')) // TILDE OPERATOR
      .put("bsim", Integer.valueOf('\u223d')) // REVERSED TILDE
      .put("backsim", Integer.valueOf('\u223d')) // REVERSED TILDE
      .put("ac", Integer.valueOf('\u223e')) // INVERTED LAZY S
      .put("mstpos", Integer.valueOf('\u223e')) // INVERTED LAZY S
      .put("acd", Integer.valueOf('\u223f')) // SINE WAVE
      .put("wreath", Integer.valueOf('\u2240')) // WREATH PRODUCT
      .put("VerticalTilde", Integer.valueOf('\u2240')) // WREATH PRODUCT
      .put("wr", Integer.valueOf('\u2240')) // WREATH PRODUCT
      .put("nsim", Integer.valueOf('\u2241')) // NOT TILDE
      .put("NotTilde", Integer.valueOf('\u2241')) // NOT TILDE
      .put("esim", Integer.valueOf('\u2242')) // MINUS TILDE
      .put("EqualTilde", Integer.valueOf('\u2242')) // MINUS TILDE
      .put("eqsim", Integer.valueOf('\u2242')) // MINUS TILDE
      .put("sime", Integer.valueOf('\u2243')) // ASYMPTOTICALLY EQUAL TO
      .put("TildeEqual", Integer.valueOf('\u2243')) // ASYMPTOTICALLY EQUAL TO
      .put("simeq", Integer.valueOf('\u2243')) // ASYMPTOTICALLY EQUAL TO
      .put("nsime", Integer.valueOf('\u2244')) // NOT ASYMPTOTICALLY EQUAL TO
      .put("nsimeq", Integer.valueOf('\u2244')) // NOT ASYMPTOTICALLY EQUAL TO
      .put("NotTildeEqual", Integer.valueOf('\u2244')) // NOT ASYMPTOTICALLY EQUAL TO
      .put("cong", Integer.valueOf('\u2245')) // APPROXIMATELY EQUAL TO
      .put("TildeFullEqual", Integer.valueOf('\u2245')) // APPROXIMATELY EQUAL TO
      .put("simne", Integer.valueOf('\u2246')) // APPROXIMATELY BUT NOT ACTUALLY EQUAL TO
      .put("ncong", Integer.valueOf('\u2247')) // NEITHER APPROXIMATELY NOR ACTUALLY EQUAL TO
      .put("NotTildeFullEqual", Integer.valueOf('\u2247')) // NEITHER APPROXIMATELY NOR ACTUALLY EQUAL TO
      .put("asymp", Integer.valueOf('\u2248')) // ALMOST EQUAL TO
      .put("ap", Integer.valueOf('\u2248')) // ALMOST EQUAL TO
      .put("TildeTilde", Integer.valueOf('\u2248')) // ALMOST EQUAL TO
      .put("approx", Integer.valueOf('\u2248')) // ALMOST EQUAL TO
      .put("thkap", Integer.valueOf('\u2248')) // ALMOST EQUAL TO
      .put("thickapprox", Integer.valueOf('\u2248')) // ALMOST EQUAL TO
      .put("nap", Integer.valueOf('\u2249')) // NOT ALMOST EQUAL TO
      .put("NotTildeTilde", Integer.valueOf('\u2249')) // NOT ALMOST EQUAL TO
      .put("napprox", Integer.valueOf('\u2249')) // NOT ALMOST EQUAL TO
      .put("ape", Integer.valueOf('\u224a')) // ALMOST EQUAL OR EQUAL TO
      .put("approxeq", Integer.valueOf('\u224a')) // ALMOST EQUAL OR EQUAL TO
      .put("apid", Integer.valueOf('\u224b')) // TRIPLE TILDE
      .put("bcong", Integer.valueOf('\u224c')) // ALL EQUAL TO
      .put("backcong", Integer.valueOf('\u224c')) // ALL EQUAL TO
      .put("asympeq", Integer.valueOf('\u224d')) // EQUIVALENT TO
      .put("CupCap", Integer.valueOf('\u224d')) // EQUIVALENT TO
      .put("bump", Integer.valueOf('\u224e')) // GEOMETRICALLY EQUIVALENT TO
      .put("HumpDownHump", Integer.valueOf('\u224e')) // GEOMETRICALLY EQUIVALENT TO
      .put("Bumpeq", Integer.valueOf('\u224e')) // GEOMETRICALLY EQUIVALENT TO
      .put("bumpe", Integer.valueOf('\u224f')) // DIFFERENCE BETWEEN
      .put("HumpEqual", Integer.valueOf('\u224f')) // DIFFERENCE BETWEEN
      .put("bumpeq", Integer.valueOf('\u224f')) // DIFFERENCE BETWEEN
      .put("esdot", Integer.valueOf('\u2250')) // APPROACHES THE LIMIT
      .put("DotEqual", Integer.valueOf('\u2250')) // APPROACHES THE LIMIT
      .put("doteq", Integer.valueOf('\u2250')) // APPROACHES THE LIMIT
      .put("eDot", Integer.valueOf('\u2251')) // GEOMETRICALLY EQUAL TO
      .put("doteqdot", Integer.valueOf('\u2251')) // GEOMETRICALLY EQUAL TO
      .put("efDot", Integer.valueOf('\u2252')) // APPROXIMATELY EQUAL TO OR THE IMAGE OF
      .put("fallingdotseq", Integer.valueOf('\u2252')) // APPROXIMATELY EQUAL TO OR THE IMAGE OF
      .put("erDot", Integer.valueOf('\u2253')) // IMAGE OF OR APPROXIMATELY EQUAL TO
      .put("risingdotseq", Integer.valueOf('\u2253')) // IMAGE OF OR APPROXIMATELY EQUAL TO
      .put("colone", Integer.valueOf('\u2254')) // COLON EQUALS
      .put("coloneq", Integer.valueOf('\u2254')) // COLON EQUALS
      .put("Assign", Integer.valueOf('\u2254')) // COLON EQUALS
      .put("ecolon", Integer.valueOf('\u2255')) // EQUALS COLON
      .put("eqcolon", Integer.valueOf('\u2255')) // EQUALS COLON
      .put("ecir", Integer.valueOf('\u2256')) // RING IN EQUAL TO
      .put("eqcirc", Integer.valueOf('\u2256')) // RING IN EQUAL TO
      .put("cire", Integer.valueOf('\u2257')) // RING EQUAL TO
      .put("circeq", Integer.valueOf('\u2257')) // RING EQUAL TO
      .put("wedgeq", Integer.valueOf('\u2259')) // ESTIMATES
      .put("veeeq", Integer.valueOf('\u225a')) // EQUIANGULAR TO
      .put("trie", Integer.valueOf('\u225c')) // DELTA EQUAL TO
      .put("triangleq", Integer.valueOf('\u225c')) // DELTA EQUAL TO
      .put("equest", Integer.valueOf('\u225f')) // QUESTIONED EQUAL TO
      .put("questeq", Integer.valueOf('\u225f')) // QUESTIONED EQUAL TO
      .put("ne", Integer.valueOf('\u2260')) // NOT EQUAL TO
      .put("NotEqual", Integer.valueOf('\u2260')) // NOT EQUAL TO
      .put("equiv", Integer.valueOf('\u2261')) // IDENTICAL TO
      .put("Congruent", Integer.valueOf('\u2261')) // IDENTICAL TO
      .put("nequiv", Integer.valueOf('\u2262')) // NOT IDENTICAL TO
      .put("NotCongruent", Integer.valueOf('\u2262')) // NOT IDENTICAL TO
      .put("le", Integer.valueOf('\u2264')) // LESS-THAN OR EQUAL TO
      .put("leq", Integer.valueOf('\u2264')) // LESS-THAN OR EQUAL TO
      .put("ge", Integer.valueOf('\u2265')) // GREATER-THAN OR EQUAL TO
      .put("GreaterEqual", Integer.valueOf('\u2265')) // GREATER-THAN OR EQUAL TO
      .put("geq", Integer.valueOf('\u2265')) // GREATER-THAN OR EQUAL TO
      .put("lE", Integer.valueOf('\u2266')) // LESS-THAN OVER EQUAL TO
      .put("LessFullEqual", Integer.valueOf('\u2266')) // LESS-THAN OVER EQUAL TO
      .put("leqq", Integer.valueOf('\u2266')) // LESS-THAN OVER EQUAL TO
      .put("gE", Integer.valueOf('\u2267')) // GREATER-THAN OVER EQUAL TO
      .put("GreaterFullEqual", Integer.valueOf('\u2267')) // GREATER-THAN OVER EQUAL TO
      .put("geqq", Integer.valueOf('\u2267')) // GREATER-THAN OVER EQUAL TO
      .put("lnE", Integer.valueOf('\u2268')) // LESS-THAN BUT NOT EQUAL TO
      .put("lneqq", Integer.valueOf('\u2268')) // LESS-THAN BUT NOT EQUAL TO
      .put("gnE", Integer.valueOf('\u2269')) // GREATER-THAN BUT NOT EQUAL TO
      .put("gneqq", Integer.valueOf('\u2269')) // GREATER-THAN BUT NOT EQUAL TO
      .put("Lt", Integer.valueOf('\u226a')) // MUCH LESS-THAN
      .put("NestedLessLess", Integer.valueOf('\u226a')) // MUCH LESS-THAN
      .put("ll", Integer.valueOf('\u226a')) // MUCH LESS-THAN
      .put("Gt", Integer.valueOf('\u226b')) // MUCH GREATER-THAN
      .put("NestedGreaterGreater", Integer.valueOf('\u226b')) // MUCH GREATER-THAN
      .put("gg", Integer.valueOf('\u226b')) // MUCH GREATER-THAN
      .put("twixt", Integer.valueOf('\u226c')) // BETWEEN
      .put("between", Integer.valueOf('\u226c')) // BETWEEN
      .put("NotCupCap", Integer.valueOf('\u226d')) // NOT EQUIVALENT TO
      .put("nlt", Integer.valueOf('\u226e')) // NOT LESS-THAN
      .put("NotLess", Integer.valueOf('\u226e')) // NOT LESS-THAN
      .put("nless", Integer.valueOf('\u226e')) // NOT LESS-THAN
      .put("ngt", Integer.valueOf('\u226f')) // NOT GREATER-THAN
      .put("NotGreater", Integer.valueOf('\u226f')) // NOT GREATER-THAN
      .put("ngtr", Integer.valueOf('\u226f')) // NOT GREATER-THAN
      .put("nle", Integer.valueOf('\u2270')) // NEITHER LESS-THAN NOR EQUAL TO
      .put("NotLessEqual", Integer.valueOf('\u2270')) // NEITHER LESS-THAN NOR EQUAL TO
      .put("nleq", Integer.valueOf('\u2270')) // NEITHER LESS-THAN NOR EQUAL TO
      .put("nge", Integer.valueOf('\u2271')) // NEITHER GREATER-THAN NOR EQUAL TO
      .put("NotGreaterEqual", Integer.valueOf('\u2271')) // NEITHER GREATER-THAN NOR EQUAL TO
      .put("ngeq", Integer.valueOf('\u2271')) // NEITHER GREATER-THAN NOR EQUAL TO
      .put("lsim", Integer.valueOf('\u2272')) // LESS-THAN OR EQUIVALENT TO
      .put("LessTilde", Integer.valueOf('\u2272')) // LESS-THAN OR EQUIVALENT TO
      .put("lesssim", Integer.valueOf('\u2272')) // LESS-THAN OR EQUIVALENT TO
      .put("gsim", Integer.valueOf('\u2273')) // GREATER-THAN OR EQUIVALENT TO
      .put("gtrsim", Integer.valueOf('\u2273')) // GREATER-THAN OR EQUIVALENT TO
      .put("GreaterTilde", Integer.valueOf('\u2273')) // GREATER-THAN OR EQUIVALENT TO
      .put("nlsim", Integer.valueOf('\u2274')) // NEITHER LESS-THAN NOR EQUIVALENT TO
      .put("NotLessTilde", Integer.valueOf('\u2274')) // NEITHER LESS-THAN NOR EQUIVALENT TO
      .put("ngsim", Integer.valueOf('\u2275')) // NEITHER GREATER-THAN NOR EQUIVALENT TO
      .put("NotGreaterTilde", Integer.valueOf('\u2275')) // NEITHER GREATER-THAN NOR EQUIVALENT TO
      .put("lg", Integer.valueOf('\u2276')) // LESS-THAN OR GREATER-THAN
      .put("lessgtr", Integer.valueOf('\u2276')) // LESS-THAN OR GREATER-THAN
      .put("LessGreater", Integer.valueOf('\u2276')) // LESS-THAN OR GREATER-THAN
      .put("gl", Integer.valueOf('\u2277')) // GREATER-THAN OR LESS-THAN
      .put("gtrless", Integer.valueOf('\u2277')) // GREATER-THAN OR LESS-THAN
      .put("GreaterLess", Integer.valueOf('\u2277')) // GREATER-THAN OR LESS-THAN
      .put("ntlg", Integer.valueOf('\u2278')) // NEITHER LESS-THAN NOR GREATER-THAN
      .put("NotLessGreater", Integer.valueOf('\u2278')) // NEITHER LESS-THAN NOR GREATER-THAN
      .put("ntgl", Integer.valueOf('\u2279')) // NEITHER GREATER-THAN NOR LESS-THAN
      .put("NotGreaterLess", Integer.valueOf('\u2279')) // NEITHER GREATER-THAN NOR LESS-THAN
      .put("pr", Integer.valueOf('\u227a')) // PRECEDES
      .put("Precedes", Integer.valueOf('\u227a')) // PRECEDES
      .put("prec", Integer.valueOf('\u227a')) // PRECEDES
      .put("sc", Integer.valueOf('\u227b')) // SUCCEEDS
      .put("Succeeds", Integer.valueOf('\u227b')) // SUCCEEDS
      .put("succ", Integer.valueOf('\u227b')) // SUCCEEDS
      .put("prcue", Integer.valueOf('\u227c')) // PRECEDES OR EQUAL TO
      .put("PrecedesSlantEqual", Integer.valueOf('\u227c')) // PRECEDES OR EQUAL TO
      .put("preccurlyeq", Integer.valueOf('\u227c')) // PRECEDES OR EQUAL TO
      .put("sccue", Integer.valueOf('\u227d')) // SUCCEEDS OR EQUAL TO
      .put("SucceedsSlantEqual", Integer.valueOf('\u227d')) // SUCCEEDS OR EQUAL TO
      .put("succcurlyeq", Integer.valueOf('\u227d')) // SUCCEEDS OR EQUAL TO
      .put("prsim", Integer.valueOf('\u227e')) // PRECEDES OR EQUIVALENT TO
      .put("precsim", Integer.valueOf('\u227e')) // PRECEDES OR EQUIVALENT TO
      .put("PrecedesTilde", Integer.valueOf('\u227e')) // PRECEDES OR EQUIVALENT TO
      .put("scsim", Integer.valueOf('\u227f')) // SUCCEEDS OR EQUIVALENT TO
      .put("succsim", Integer.valueOf('\u227f')) // SUCCEEDS OR EQUIVALENT TO
      .put("SucceedsTilde", Integer.valueOf('\u227f')) // SUCCEEDS OR EQUIVALENT TO
      .put("npr", Integer.valueOf('\u2280')) // DOES NOT PRECEDE
      .put("nprec", Integer.valueOf('\u2280')) // DOES NOT PRECEDE
      .put("NotPrecedes", Integer.valueOf('\u2280')) // DOES NOT PRECEDE
      .put("nsc", Integer.valueOf('\u2281')) // DOES NOT SUCCEED
      .put("nsucc", Integer.valueOf('\u2281')) // DOES NOT SUCCEED
      .put("NotSucceeds", Integer.valueOf('\u2281')) // DOES NOT SUCCEED
      .put("sub", Integer.valueOf('\u2282')) // SUBSET OF
      .put("subset", Integer.valueOf('\u2282')) // SUBSET OF
      .put("sup", Integer.valueOf('\u2283')) // SUPERSET OF
      .put("supset", Integer.valueOf('\u2283')) // SUPERSET OF
      .put("Superset", Integer.valueOf('\u2283')) // SUPERSET OF
      .put("nsub", Integer.valueOf('\u2284')) // NOT A SUBSET OF
      .put("nsup", Integer.valueOf('\u2285')) // NOT A SUPERSET OF
      .put("sube", Integer.valueOf('\u2286')) // SUBSET OF OR EQUAL TO
      .put("SubsetEqual", Integer.valueOf('\u2286')) // SUBSET OF OR EQUAL TO
      .put("subseteq", Integer.valueOf('\u2286')) // SUBSET OF OR EQUAL TO
      .put("supe", Integer.valueOf('\u2287')) // SUPERSET OF OR EQUAL TO
      .put("supseteq", Integer.valueOf('\u2287')) // SUPERSET OF OR EQUAL TO
      .put("SupersetEqual", Integer.valueOf('\u2287')) // SUPERSET OF OR EQUAL TO
      .put("nsube", Integer.valueOf('\u2288')) // NEITHER A SUBSET OF NOR EQUAL TO
      .put("nsubseteq", Integer.valueOf('\u2288')) // NEITHER A SUBSET OF NOR EQUAL TO
      .put("NotSubsetEqual", Integer.valueOf('\u2288')) // NEITHER A SUBSET OF NOR EQUAL TO
      .put("nsupe", Integer.valueOf('\u2289')) // NEITHER A SUPERSET OF NOR EQUAL TO
      .put("nsupseteq", Integer.valueOf('\u2289')) // NEITHER A SUPERSET OF NOR EQUAL TO
      .put("NotSupersetEqual", Integer.valueOf('\u2289')) // NEITHER A SUPERSET OF NOR EQUAL TO
      .put("subne", Integer.valueOf('\u228a')) // SUBSET OF WITH NOT EQUAL TO
      .put("subsetneq", Integer.valueOf('\u228a')) // SUBSET OF WITH NOT EQUAL TO
      .put("supne", Integer.valueOf('\u228b')) // SUPERSET OF WITH NOT EQUAL TO
      .put("supsetneq", Integer.valueOf('\u228b')) // SUPERSET OF WITH NOT EQUAL TO
      .put("cupdot", Integer.valueOf('\u228d')) // MULTISET MULTIPLICATION
      .put("uplus", Integer.valueOf('\u228e')) // MULTISET UNION
      .put("UnionPlus", Integer.valueOf('\u228e')) // MULTISET UNION
      .put("sqsub", Integer.valueOf('\u228f')) // SQUARE IMAGE OF
      .put("SquareSubset", Integer.valueOf('\u228f')) // SQUARE IMAGE OF
      .put("sqsubset", Integer.valueOf('\u228f')) // SQUARE IMAGE OF
      .put("sqsup", Integer.valueOf('\u2290')) // SQUARE ORIGINAL OF
      .put("SquareSuperset", Integer.valueOf('\u2290')) // SQUARE ORIGINAL OF
      .put("sqsupset", Integer.valueOf('\u2290')) // SQUARE ORIGINAL OF
      .put("sqsube", Integer.valueOf('\u2291')) // SQUARE IMAGE OF OR EQUAL TO
      .put("SquareSubsetEqual", Integer.valueOf('\u2291')) // SQUARE IMAGE OF OR EQUAL TO
      .put("sqsubseteq", Integer.valueOf('\u2291')) // SQUARE IMAGE OF OR EQUAL TO
      .put("sqsupe", Integer.valueOf('\u2292')) // SQUARE ORIGINAL OF OR EQUAL TO
      .put("SquareSupersetEqual", Integer.valueOf('\u2292')) // SQUARE ORIGINAL OF OR EQUAL TO
      .put("sqsupseteq", Integer.valueOf('\u2292')) // SQUARE ORIGINAL OF OR EQUAL TO
      .put("sqcap", Integer.valueOf('\u2293')) // SQUARE CAP
      .put("SquareIntersection", Integer.valueOf('\u2293')) // SQUARE CAP
      .put("sqcup", Integer.valueOf('\u2294')) // SQUARE CUP
      .put("SquareUnion", Integer.valueOf('\u2294')) // SQUARE CUP
      .put("oplus", Integer.valueOf('\u2295')) // CIRCLED PLUS
      .put("CirclePlus", Integer.valueOf('\u2295')) // CIRCLED PLUS
      .put("ominus", Integer.valueOf('\u2296')) // CIRCLED MINUS
      .put("CircleMinus", Integer.valueOf('\u2296')) // CIRCLED MINUS
      .put("otimes", Integer.valueOf('\u2297')) // CIRCLED TIMES
      .put("CircleTimes", Integer.valueOf('\u2297')) // CIRCLED TIMES
      .put("osol", Integer.valueOf('\u2298')) // CIRCLED DIVISION SLASH
      .put("odot", Integer.valueOf('\u2299')) // CIRCLED DOT OPERATOR
      .put("CircleDot", Integer.valueOf('\u2299')) // CIRCLED DOT OPERATOR
      .put("ocir", Integer.valueOf('\u229a')) // CIRCLED RING OPERATOR
      .put("circledcirc", Integer.valueOf('\u229a')) // CIRCLED RING OPERATOR
      .put("oast", Integer.valueOf('\u229b')) // CIRCLED ASTERISK OPERATOR
      .put("circledast", Integer.valueOf('\u229b')) // CIRCLED ASTERISK OPERATOR
      .put("odash", Integer.valueOf('\u229d')) // CIRCLED DASH
      .put("circleddash", Integer.valueOf('\u229d')) // CIRCLED DASH
      .put("plusb", Integer.valueOf('\u229e')) // SQUARED PLUS
      .put("boxplus", Integer.valueOf('\u229e')) // SQUARED PLUS
      .put("minusb", Integer.valueOf('\u229f')) // SQUARED MINUS
      .put("boxminus", Integer.valueOf('\u229f')) // SQUARED MINUS
      .put("timesb", Integer.valueOf('\u22a0')) // SQUARED TIMES
      .put("boxtimes", Integer.valueOf('\u22a0')) // SQUARED TIMES
      .put("sdotb", Integer.valueOf('\u22a1')) // SQUARED DOT OPERATOR
      .put("dotsquare", Integer.valueOf('\u22a1')) // SQUARED DOT OPERATOR
      .put("vdash", Integer.valueOf('\u22a2')) // RIGHT TACK
      .put("RightTee", Integer.valueOf('\u22a2')) // RIGHT TACK
      .put("dashv", Integer.valueOf('\u22a3')) // LEFT TACK
      .put("LeftTee", Integer.valueOf('\u22a3')) // LEFT TACK
      .put("top", Integer.valueOf('\u22a4')) // DOWN TACK
      .put("DownTee", Integer.valueOf('\u22a4')) // DOWN TACK
      .put("bottom", Integer.valueOf('\u22a5')) // UP TACK
      .put("bot", Integer.valueOf('\u22a5')) // UP TACK
      .put("perp", Integer.valueOf('\u22a5')) // UP TACK
      .put("UpTee", Integer.valueOf('\u22a5')) // UP TACK
      .put("models", Integer.valueOf('\u22a7')) // MODELS
      .put("vDash", Integer.valueOf('\u22a8')) // TRUE
      .put("DoubleRightTee", Integer.valueOf('\u22a8')) // TRUE
      .put("Vdash", Integer.valueOf('\u22a9')) // FORCES
      .put("Vvdash", Integer.valueOf('\u22aa')) // TRIPLE VERTICAL BAR RIGHT TURNSTILE
      .put("VDash", Integer.valueOf('\u22ab')) // DOUBLE VERTICAL BAR DOUBLE RIGHT TURNSTILE
      .put("nvdash", Integer.valueOf('\u22ac')) // DOES NOT PROVE
      .put("nvDash", Integer.valueOf('\u22ad')) // NOT TRUE
      .put("nVdash", Integer.valueOf('\u22ae')) // DOES NOT FORCE
      .put("nVDash", Integer.valueOf('\u22af')) // NEGATED DOUBLE VERTICAL BAR DOUBLE RIGHT TURNSTILE
      .put("prurel", Integer.valueOf('\u22b0')) // PRECEDES UNDER RELATION
      .put("vltri", Integer.valueOf('\u22b2')) // NORMAL SUBGROUP OF
      .put("vartriangleleft", Integer.valueOf('\u22b2')) // NORMAL SUBGROUP OF
      .put("LeftTriangle", Integer.valueOf('\u22b2')) // NORMAL SUBGROUP OF
      .put("vrtri", Integer.valueOf('\u22b3')) // CONTAINS AS NORMAL SUBGROUP
      .put("vartriangleright", Integer.valueOf('\u22b3')) // CONTAINS AS NORMAL SUBGROUP
      .put("RightTriangle", Integer.valueOf('\u22b3')) // CONTAINS AS NORMAL SUBGROUP
      .put("ltrie", Integer.valueOf('\u22b4')) // NORMAL SUBGROUP OF OR EQUAL TO
      .put("trianglelefteq", Integer.valueOf('\u22b4')) // NORMAL SUBGROUP OF OR EQUAL TO
      .put("LeftTriangleEqual", Integer.valueOf('\u22b4')) // NORMAL SUBGROUP OF OR EQUAL TO
      .put("rtrie", Integer.valueOf('\u22b5')) // CONTAINS AS NORMAL SUBGROUP OR EQUAL TO
      .put("trianglerighteq", Integer.valueOf('\u22b5')) // CONTAINS AS NORMAL SUBGROUP OR EQUAL TO
      .put("RightTriangleEqual", Integer.valueOf('\u22b5')) // CONTAINS AS NORMAL SUBGROUP OR EQUAL TO
      .put("origof", Integer.valueOf('\u22b6')) // ORIGINAL OF
      .put("imof", Integer.valueOf('\u22b7')) // IMAGE OF
      .put("mumap", Integer.valueOf('\u22b8')) // MULTIMAP
      .put("multimap", Integer.valueOf('\u22b8')) // MULTIMAP
      .put("hercon", Integer.valueOf('\u22b9')) // HERMITIAN CONJUGATE MATRIX
      .put("intcal", Integer.valueOf('\u22ba')) // INTERCALATE
      .put("intercal", Integer.valueOf('\u22ba')) // INTERCALATE
      .put("veebar", Integer.valueOf('\u22bb')) // XOR
      .put("barvee", Integer.valueOf('\u22bd')) // NOR
      .put("angrtvb", Integer.valueOf('\u22be')) // RIGHT ANGLE WITH ARC
      .put("lrtri", Integer.valueOf('\u22bf')) // RIGHT TRIANGLE
      .put("xwedge", Integer.valueOf('\u22c0')) // N-ARY LOGICAL AND
      .put("Wedge", Integer.valueOf('\u22c0')) // N-ARY LOGICAL AND
      .put("bigwedge", Integer.valueOf('\u22c0')) // N-ARY LOGICAL AND
      .put("xvee", Integer.valueOf('\u22c1')) // N-ARY LOGICAL OR
      .put("Vee", Integer.valueOf('\u22c1')) // N-ARY LOGICAL OR
      .put("bigvee", Integer.valueOf('\u22c1')) // N-ARY LOGICAL OR
      .put("xcap", Integer.valueOf('\u22c2')) // N-ARY INTERSECTION
      .put("Intersection", Integer.valueOf('\u22c2')) // N-ARY INTERSECTION
      .put("bigcap", Integer.valueOf('\u22c2')) // N-ARY INTERSECTION
      .put("xcup", Integer.valueOf('\u22c3')) // N-ARY UNION
      .put("Union", Integer.valueOf('\u22c3')) // N-ARY UNION
      .put("bigcup", Integer.valueOf('\u22c3')) // N-ARY UNION
      .put("diam", Integer.valueOf('\u22c4')) // DIAMOND OPERATOR
      .put("diamond", Integer.valueOf('\u22c4')) // DIAMOND OPERATOR
      .put("Diamond", Integer.valueOf('\u22c4')) // DIAMOND OPERATOR
      .put("sdot", Integer.valueOf('\u22c5')) // DOT OPERATOR
      .put("sstarf", Integer.valueOf('\u22c6')) // STAR OPERATOR
      .put("Star", Integer.valueOf('\u22c6')) // STAR OPERATOR
      .put("divonx", Integer.valueOf('\u22c7')) // DIVISION TIMES
      .put("divideontimes", Integer.valueOf('\u22c7')) // DIVISION TIMES
      .put("bowtie", Integer.valueOf('\u22c8')) // BOWTIE
      .put("ltimes", Integer.valueOf('\u22c9')) // LEFT NORMAL FACTOR SEMIDIRECT PRODUCT
      .put("rtimes", Integer.valueOf('\u22ca')) // RIGHT NORMAL FACTOR SEMIDIRECT PRODUCT
      .put("lthree", Integer.valueOf('\u22cb')) // LEFT SEMIDIRECT PRODUCT
      .put("leftthreetimes", Integer.valueOf('\u22cb')) // LEFT SEMIDIRECT PRODUCT
      .put("rthree", Integer.valueOf('\u22cc')) // RIGHT SEMIDIRECT PRODUCT
      .put("rightthreetimes", Integer.valueOf('\u22cc')) // RIGHT SEMIDIRECT PRODUCT
      .put("bsime", Integer.valueOf('\u22cd')) // REVERSED TILDE EQUALS
      .put("backsimeq", Integer.valueOf('\u22cd')) // REVERSED TILDE EQUALS
      .put("cuvee", Integer.valueOf('\u22ce')) // CURLY LOGICAL OR
      .put("curlyvee", Integer.valueOf('\u22ce')) // CURLY LOGICAL OR
      .put("cuwed", Integer.valueOf('\u22cf')) // CURLY LOGICAL AND
      .put("curlywedge", Integer.valueOf('\u22cf')) // CURLY LOGICAL AND
      .put("Sub", Integer.valueOf('\u22d0')) // DOUBLE SUBSET
      .put("Subset", Integer.valueOf('\u22d0')) // DOUBLE SUBSET
      .put("Sup", Integer.valueOf('\u22d1')) // DOUBLE SUPERSET
      .put("Supset", Integer.valueOf('\u22d1')) // DOUBLE SUPERSET
      .put("Cap", Integer.valueOf('\u22d2')) // DOUBLE INTERSECTION
      .put("Cup", Integer.valueOf('\u22d3')) // DOUBLE UNION
      .put("fork", Integer.valueOf('\u22d4')) // PITCHFORK
      .put("pitchfork", Integer.valueOf('\u22d4')) // PITCHFORK
      .put("epar", Integer.valueOf('\u22d5')) // EQUAL AND PARALLEL TO
      .put("ltdot", Integer.valueOf('\u22d6')) // LESS-THAN WITH DOT
      .put("lessdot", Integer.valueOf('\u22d6')) // LESS-THAN WITH DOT
      .put("gtdot", Integer.valueOf('\u22d7')) // GREATER-THAN WITH DOT
      .put("gtrdot", Integer.valueOf('\u22d7')) // GREATER-THAN WITH DOT
      .put("Ll", Integer.valueOf('\u22d8')) // VERY MUCH LESS-THAN
      .put("Gg", Integer.valueOf('\u22d9')) // VERY MUCH GREATER-THAN
      .put("ggg", Integer.valueOf('\u22d9')) // VERY MUCH GREATER-THAN
      .put("leg", Integer.valueOf('\u22da')) // LESS-THAN EQUAL TO OR GREATER-THAN
      .put("LessEqualGreater", Integer.valueOf('\u22da')) // LESS-THAN EQUAL TO OR GREATER-THAN
      .put("lesseqgtr", Integer.valueOf('\u22da')) // LESS-THAN EQUAL TO OR GREATER-THAN
      .put("gel", Integer.valueOf('\u22db')) // GREATER-THAN EQUAL TO OR LESS-THAN
      .put("gtreqless", Integer.valueOf('\u22db')) // GREATER-THAN EQUAL TO OR LESS-THAN
      .put("GreaterEqualLess", Integer.valueOf('\u22db')) // GREATER-THAN EQUAL TO OR LESS-THAN
      .put("cuepr", Integer.valueOf('\u22de')) // EQUAL TO OR PRECEDES
      .put("curlyeqprec", Integer.valueOf('\u22de')) // EQUAL TO OR PRECEDES
      .put("cuesc", Integer.valueOf('\u22df')) // EQUAL TO OR SUCCEEDS
      .put("curlyeqsucc", Integer.valueOf('\u22df')) // EQUAL TO OR SUCCEEDS
      .put("nprcue", Integer.valueOf('\u22e0')) // DOES NOT PRECEDE OR EQUAL
      .put("NotPrecedesSlantEqual", Integer.valueOf('\u22e0')) // DOES NOT PRECEDE OR EQUAL
      .put("nsccue", Integer.valueOf('\u22e1')) // DOES NOT SUCCEED OR EQUAL
      .put("NotSucceedsSlantEqual", Integer.valueOf('\u22e1')) // DOES NOT SUCCEED OR EQUAL
      .put("nsqsube", Integer.valueOf('\u22e2')) // NOT SQUARE IMAGE OF OR EQUAL TO
      .put("NotSquareSubsetEqual", Integer.valueOf('\u22e2')) // NOT SQUARE IMAGE OF OR EQUAL TO
      .put("nsqsupe", Integer.valueOf('\u22e3')) // NOT SQUARE ORIGINAL OF OR EQUAL TO
      .put("NotSquareSupersetEqual", Integer.valueOf('\u22e3')) // NOT SQUARE ORIGINAL OF OR EQUAL TO
      .put("lnsim", Integer.valueOf('\u22e6')) // LESS-THAN BUT NOT EQUIVALENT TO
      .put("gnsim", Integer.valueOf('\u22e7')) // GREATER-THAN BUT NOT EQUIVALENT TO
      .put("prnsim", Integer.valueOf('\u22e8')) // PRECEDES BUT NOT EQUIVALENT TO
      .put("precnsim", Integer.valueOf('\u22e8')) // PRECEDES BUT NOT EQUIVALENT TO
      .put("scnsim", Integer.valueOf('\u22e9')) // SUCCEEDS BUT NOT EQUIVALENT TO
      .put("succnsim", Integer.valueOf('\u22e9')) // SUCCEEDS BUT NOT EQUIVALENT TO
      .put("nltri", Integer.valueOf('\u22ea')) // NOT NORMAL SUBGROUP OF
      .put("ntriangleleft", Integer.valueOf('\u22ea')) // NOT NORMAL SUBGROUP OF
      .put("NotLeftTriangle", Integer.valueOf('\u22ea')) // NOT NORMAL SUBGROUP OF
      .put("nrtri", Integer.valueOf('\u22eb')) // DOES NOT CONTAIN AS NORMAL SUBGROUP
      .put("ntriangleright", Integer.valueOf('\u22eb')) // DOES NOT CONTAIN AS NORMAL SUBGROUP
      .put("NotRightTriangle", Integer.valueOf('\u22eb')) // DOES NOT CONTAIN AS NORMAL SUBGROUP
      .put("nltrie", Integer.valueOf('\u22ec')) // NOT NORMAL SUBGROUP OF OR EQUAL TO
      .put("ntrianglelefteq", Integer.valueOf('\u22ec')) // NOT NORMAL SUBGROUP OF OR EQUAL TO
      .put("NotLeftTriangleEqual", Integer.valueOf('\u22ec')) // NOT NORMAL SUBGROUP OF OR EQUAL TO
      .put("nrtrie", Integer.valueOf('\u22ed')) // DOES NOT CONTAIN AS NORMAL SUBGROUP OR EQUAL
      .put("ntrianglerighteq", Integer.valueOf('\u22ed')) // DOES NOT CONTAIN AS NORMAL SUBGROUP OR EQUAL
      .put("NotRightTriangleEqual", Integer.valueOf('\u22ed')) // DOES NOT CONTAIN AS NORMAL SUBGROUP OR EQUAL
      .put("vellip", Integer.valueOf('\u22ee')) // VERTICAL ELLIPSIS
      .put("ctdot", Integer.valueOf('\u22ef')) // MIDLINE HORIZONTAL ELLIPSIS
      .put("utdot", Integer.valueOf('\u22f0')) // UP RIGHT DIAGONAL ELLIPSIS
      .put("dtdot", Integer.valueOf('\u22f1')) // DOWN RIGHT DIAGONAL ELLIPSIS
      .put("disin", Integer.valueOf('\u22f2')) // ELEMENT OF WITH LONG HORIZONTAL STROKE
      .put("isinsv", Integer.valueOf('\u22f3')) // ELEMENT OF WITH VERTICAL BAR AT END OF HORIZONTAL STROKE
      .put("isins", Integer.valueOf('\u22f4')) // SMALL ELEMENT OF WITH VERTICAL BAR AT END OF HORIZONTAL STROKE
      .put("isindot", Integer.valueOf('\u22f5')) // ELEMENT OF WITH DOT ABOVE
      .put("notinvc", Integer.valueOf('\u22f6')) // ELEMENT OF WITH OVERBAR
      .put("notinvb", Integer.valueOf('\u22f7')) // SMALL ELEMENT OF WITH OVERBAR
      .put("isinE", Integer.valueOf('\u22f9')) // ELEMENT OF WITH TWO HORIZONTAL STROKES
      .put("nisd", Integer.valueOf('\u22fa')) // CONTAINS WITH LONG HORIZONTAL STROKE
      .put("xnis", Integer.valueOf('\u22fb')) // CONTAINS WITH VERTICAL BAR AT END OF HORIZONTAL STROKE
      .put("nis", Integer.valueOf('\u22fc')) // SMALL CONTAINS WITH VERTICAL BAR AT END OF HORIZONTAL STROKE
      .put("notnivc", Integer.valueOf('\u22fd')) // CONTAINS WITH OVERBAR
      .put("notnivb", Integer.valueOf('\u22fe')) // SMALL CONTAINS WITH OVERBAR

    // Miscellaneous Technical
      .put("barwed", Integer.valueOf('\u2305')) // PROJECTIVE
      .put("barwedge", Integer.valueOf('\u2305')) // PROJECTIVE
      .put("Barwed", Integer.valueOf('\u2306')) // PERSPECTIVE
      .put("doublebarwedge", Integer.valueOf('\u2306')) // PERSPECTIVE
      .put("lceil", Integer.valueOf('\u2308')) // LEFT CEILING
      .put("LeftCeiling", Integer.valueOf('\u2308')) // LEFT CEILING
      .put("rceil", Integer.valueOf('\u2309')) // RIGHT CEILING
      .put("RightCeiling", Integer.valueOf('\u2309')) // RIGHT CEILING
      .put("lfloor", Integer.valueOf('\u230a')) // LEFT FLOOR
      .put("LeftFloor", Integer.valueOf('\u230a')) // LEFT FLOOR
      .put("rfloor", Integer.valueOf('\u230b')) // RIGHT FLOOR
      .put("RightFloor", Integer.valueOf('\u230b')) // RIGHT FLOOR
      .put("drcrop", Integer.valueOf('\u230c')) // BOTTOM RIGHT CROP
      .put("dlcrop", Integer.valueOf('\u230d')) // BOTTOM LEFT CROP
      .put("urcrop", Integer.valueOf('\u230e')) // TOP RIGHT CROP
      .put("ulcrop", Integer.valueOf('\u230f')) // TOP LEFT CROP
      .put("bnot", Integer.valueOf('\u2310')) // REVERSED NOT SIGN
      .put("profline", Integer.valueOf('\u2312')) // ARC
      .put("profsurf", Integer.valueOf('\u2313')) // SEGMENT
      .put("telrec", Integer.valueOf('\u2315')) // TELEPHONE RECORDER
      .put("target", Integer.valueOf('\u2316')) // POSITION INDICATOR
      .put("ulcorn", Integer.valueOf('\u231c')) // TOP LEFT CORNER
      .put("ulcorner", Integer.valueOf('\u231c')) // TOP LEFT CORNER
      .put("urcorn", Integer.valueOf('\u231d')) // TOP RIGHT CORNER
      .put("urcorner", Integer.valueOf('\u231d')) // TOP RIGHT CORNER
      .put("dlcorn", Integer.valueOf('\u231e')) // BOTTOM LEFT CORNER
      .put("llcorner", Integer.valueOf('\u231e')) // BOTTOM LEFT CORNER
      .put("drcorn", Integer.valueOf('\u231f')) // BOTTOM RIGHT CORNER
      .put("lrcorner", Integer.valueOf('\u231f')) // BOTTOM RIGHT CORNER
      .put("frown", Integer.valueOf('\u2322')) // FROWN
      .put("sfrown", Integer.valueOf('\u2322')) // FROWN
      .put("smile", Integer.valueOf('\u2323')) // SMILE
      .put("ssmile", Integer.valueOf('\u2323')) // SMILE
      .put("cylcty", Integer.valueOf('\u232d')) // CYLINDRICITY
      .put("profalar", Integer.valueOf('\u232e')) // ALL AROUND-PROFILE
      .put("topbot", Integer.valueOf('\u2336')) // APL FUNCTIONAL SYMBOL I-BEAM
      .put("ovbar", Integer.valueOf('\u233d')) // APL FUNCTIONAL SYMBOL CIRCLE STILE
      .put("solbar", Integer.valueOf('\u233f')) // APL FUNCTIONAL SYMBOL SLASH BAR
      .put("angzarr", Integer.valueOf('\u237c')) // RIGHT ANGLE WITH DOWNWARDS ZIGZAG ARROW
      .put("lmoust", Integer.valueOf('\u23b0')) // UPPER LEFT OR LOWER RIGHT CURLY BRACKET SECTION
      .put("lmoustache", Integer.valueOf('\u23b0')) // UPPER LEFT OR LOWER RIGHT CURLY BRACKET SECTION
      .put("rmoust", Integer.valueOf('\u23b1')) // UPPER RIGHT OR LOWER LEFT CURLY BRACKET SECTION
      .put("rmoustache", Integer.valueOf('\u23b1')) // UPPER RIGHT OR LOWER LEFT CURLY BRACKET SECTION
      .put("tbrk", Integer.valueOf('\u23b4')) // TOP SQUARE BRACKET
      .put("OverBracket", Integer.valueOf('\u23b4')) // TOP SQUARE BRACKET
      .put("bbrk", Integer.valueOf('\u23b5')) // BOTTOM SQUARE BRACKET
      .put("UnderBracket", Integer.valueOf('\u23b5')) // BOTTOM SQUARE BRACKET
      .put("bbrktbrk", Integer.valueOf('\u23b6')) // BOTTOM SQUARE BRACKET OVER TOP SQUARE BRACKET
      .put("OverParenthesis", Integer.valueOf('\u23dc')) // TOP PARENTHESIS
      .put("UnderParenthesis", Integer.valueOf('\u23dd')) // BOTTOM PARENTHESIS
      .put("OverBrace", Integer.valueOf('\u23de')) // TOP CURLY BRACKET
      .put("UnderBrace", Integer.valueOf('\u23df')) // BOTTOM CURLY BRACKET
      .put("trpezium", Integer.valueOf('\u23e2')) // WHITE TRAPEZIUM
      .put("elinters", Integer.valueOf('\u23e7')) // ELECTRICAL INTERSECTION

    // Control Pictures
      .put("blank", Integer.valueOf('\u2423')) // OPEN BOX

    // Enclosed Alphanumerics
      .put("oS", Integer.valueOf('\u24c8')) // CIRCLED LATIN CAPITAL LETTER S
      .put("circledS", Integer.valueOf('\u24c8')) // CIRCLED LATIN CAPITAL LETTER S

    // Box Drawing
      .put("boxh", Integer.valueOf('\u2500')) // BOX DRAWINGS LIGHT HORIZONTAL
      .put("HorizontalLine", Integer.valueOf('\u2500')) // BOX DRAWINGS LIGHT HORIZONTAL
      .put("boxv", Integer.valueOf('\u2502')) // BOX DRAWINGS LIGHT VERTICAL
      .put("boxdr", Integer.valueOf('\u250c')) // BOX DRAWINGS LIGHT DOWN AND RIGHT
      .put("boxdl", Integer.valueOf('\u2510')) // BOX DRAWINGS LIGHT DOWN AND LEFT
      .put("boxur", Integer.valueOf('\u2514')) // BOX DRAWINGS LIGHT UP AND RIGHT
      .put("boxul", Integer.valueOf('\u2518')) // BOX DRAWINGS LIGHT UP AND LEFT
      .put("boxvr", Integer.valueOf('\u251c')) // BOX DRAWINGS LIGHT VERTICAL AND RIGHT
      .put("boxvl", Integer.valueOf('\u2524')) // BOX DRAWINGS LIGHT VERTICAL AND LEFT
      .put("boxhd", Integer.valueOf('\u252c')) // BOX DRAWINGS LIGHT DOWN AND HORIZONTAL
      .put("boxhu", Integer.valueOf('\u2534')) // BOX DRAWINGS LIGHT UP AND HORIZONTAL
      .put("boxvh", Integer.valueOf('\u253c')) // BOX DRAWINGS LIGHT VERTICAL AND HORIZONTAL
      .put("boxH", Integer.valueOf('\u2550')) // BOX DRAWINGS DOUBLE HORIZONTAL
      .put("boxV", Integer.valueOf('\u2551')) // BOX DRAWINGS DOUBLE VERTICAL
      .put("boxdR", Integer.valueOf('\u2552')) // BOX DRAWINGS DOWN SINGLE AND RIGHT DOUBLE
      .put("boxDr", Integer.valueOf('\u2553')) // BOX DRAWINGS DOWN DOUBLE AND RIGHT SINGLE
      .put("boxDR", Integer.valueOf('\u2554')) // BOX DRAWINGS DOUBLE DOWN AND RIGHT
      .put("boxdL", Integer.valueOf('\u2555')) // BOX DRAWINGS DOWN SINGLE AND LEFT DOUBLE
      .put("boxDl", Integer.valueOf('\u2556')) // BOX DRAWINGS DOWN DOUBLE AND LEFT SINGLE
      .put("boxDL", Integer.valueOf('\u2557')) // BOX DRAWINGS DOUBLE DOWN AND LEFT
      .put("boxuR", Integer.valueOf('\u2558')) // BOX DRAWINGS UP SINGLE AND RIGHT DOUBLE
      .put("boxUr", Integer.valueOf('\u2559')) // BOX DRAWINGS UP DOUBLE AND RIGHT SINGLE
      .put("boxUR", Integer.valueOf('\u255a')) // BOX DRAWINGS DOUBLE UP AND RIGHT
      .put("boxuL", Integer.valueOf('\u255b')) // BOX DRAWINGS UP SINGLE AND LEFT DOUBLE
      .put("boxUl", Integer.valueOf('\u255c')) // BOX DRAWINGS UP DOUBLE AND LEFT SINGLE
      .put("boxUL", Integer.valueOf('\u255d')) // BOX DRAWINGS DOUBLE UP AND LEFT
      .put("boxvR", Integer.valueOf('\u255e')) // BOX DRAWINGS VERTICAL SINGLE AND RIGHT DOUBLE
      .put("boxVr", Integer.valueOf('\u255f')) // BOX DRAWINGS VERTICAL DOUBLE AND RIGHT SINGLE
      .put("boxVR", Integer.valueOf('\u2560')) // BOX DRAWINGS DOUBLE VERTICAL AND RIGHT
      .put("boxvL", Integer.valueOf('\u2561')) // BOX DRAWINGS VERTICAL SINGLE AND LEFT DOUBLE
      .put("boxVl", Integer.valueOf('\u2562')) // BOX DRAWINGS VERTICAL DOUBLE AND LEFT SINGLE
      .put("boxVL", Integer.valueOf('\u2563')) // BOX DRAWINGS DOUBLE VERTICAL AND LEFT
      .put("boxHd", Integer.valueOf('\u2564')) // BOX DRAWINGS DOWN SINGLE AND HORIZONTAL DOUBLE
      .put("boxhD", Integer.valueOf('\u2565')) // BOX DRAWINGS DOWN DOUBLE AND HORIZONTAL SINGLE
      .put("boxHD", Integer.valueOf('\u2566')) // BOX DRAWINGS DOUBLE DOWN AND HORIZONTAL
      .put("boxHu", Integer.valueOf('\u2567')) // BOX DRAWINGS UP SINGLE AND HORIZONTAL DOUBLE
      .put("boxhU", Integer.valueOf('\u2568')) // BOX DRAWINGS UP DOUBLE AND HORIZONTAL SINGLE
      .put("boxHU", Integer.valueOf('\u2569')) // BOX DRAWINGS DOUBLE UP AND HORIZONTAL
      .put("boxvH", Integer.valueOf('\u256a')) // BOX DRAWINGS VERTICAL SINGLE AND HORIZONTAL DOUBLE
      .put("boxVh", Integer.valueOf('\u256b')) // BOX DRAWINGS VERTICAL DOUBLE AND HORIZONTAL SINGLE
      .put("boxVH", Integer.valueOf('\u256c')) // BOX DRAWINGS DOUBLE VERTICAL AND HORIZONTAL

    // Block Elements
      .put("uhblk", Integer.valueOf('\u2580')) // UPPER HALF BLOCK
      .put("lhblk", Integer.valueOf('\u2584')) // LOWER HALF BLOCK
      .put("block", Integer.valueOf('\u2588')) // FULL BLOCK
      .put("blk14", Integer.valueOf('\u2591')) // LIGHT SHADE
      .put("blk12", Integer.valueOf('\u2592')) // MEDIUM SHADE
      .put("blk34", Integer.valueOf('\u2593')) // DARK SHADE

    // Geometric Shapes
      .put("squ", Integer.valueOf('\u25a1')) // WHITE SQUARE
      .put("square", Integer.valueOf('\u25a1')) // WHITE SQUARE
      .put("Square", Integer.valueOf('\u25a1')) // WHITE SQUARE
      .put("squf", Integer.valueOf('\u25aa')) // BLACK SMALL SQUARE
      .put("squarf", Integer.valueOf('\u25aa')) // BLACK SMALL SQUARE
      .put("blacksquare", Integer.valueOf('\u25aa')) // BLACK SMALL SQUARE
      .put("FilledVerySmallSquare", Integer.valueOf('\u25aa')) // BLACK SMALL SQUARE
      .put("EmptyVerySmallSquare", Integer.valueOf('\u25ab')) // WHITE SMALL SQUARE
      .put("rect", Integer.valueOf('\u25ad')) // WHITE RECTANGLE
      .put("marker", Integer.valueOf('\u25ae')) // BLACK VERTICAL RECTANGLE
      .put("fltns", Integer.valueOf('\u25b1')) // WHITE PARALLELOGRAM
      .put("xutri", Integer.valueOf('\u25b3')) // WHITE UP-POINTING TRIANGLE
      .put("bigtriangleup", Integer.valueOf('\u25b3')) // WHITE UP-POINTING TRIANGLE
      .put("utrif", Integer.valueOf('\u25b4')) // BLACK UP-POINTING SMALL TRIANGLE
      .put("blacktriangle", Integer.valueOf('\u25b4')) // BLACK UP-POINTING SMALL TRIANGLE
      .put("utri", Integer.valueOf('\u25b5')) // WHITE UP-POINTING SMALL TRIANGLE
      .put("triangle", Integer.valueOf('\u25b5')) // WHITE UP-POINTING SMALL TRIANGLE
      .put("rtrif", Integer.valueOf('\u25b8')) // BLACK RIGHT-POINTING SMALL TRIANGLE
      .put("blacktriangleright", Integer.valueOf('\u25b8')) // BLACK RIGHT-POINTING SMALL TRIANGLE
      .put("rtri", Integer.valueOf('\u25b9')) // WHITE RIGHT-POINTING SMALL TRIANGLE
      .put("triangleright", Integer.valueOf('\u25b9')) // WHITE RIGHT-POINTING SMALL TRIANGLE
      .put("xdtri", Integer.valueOf('\u25bd')) // WHITE DOWN-POINTING TRIANGLE
      .put("bigtriangledown", Integer.valueOf('\u25bd')) // WHITE DOWN-POINTING TRIANGLE
      .put("dtrif", Integer.valueOf('\u25be')) // BLACK DOWN-POINTING SMALL TRIANGLE
      .put("blacktriangledown", Integer.valueOf('\u25be')) // BLACK DOWN-POINTING SMALL TRIANGLE
      .put("dtri", Integer.valueOf('\u25bf')) // WHITE DOWN-POINTING SMALL TRIANGLE
      .put("triangledown", Integer.valueOf('\u25bf')) // WHITE DOWN-POINTING SMALL TRIANGLE
      .put("ltrif", Integer.valueOf('\u25c2')) // BLACK LEFT-POINTING SMALL TRIANGLE
      .put("blacktriangleleft", Integer.valueOf('\u25c2')) // BLACK LEFT-POINTING SMALL TRIANGLE
      .put("ltri", Integer.valueOf('\u25c3')) // WHITE LEFT-POINTING SMALL TRIANGLE
      .put("triangleleft", Integer.valueOf('\u25c3')) // WHITE LEFT-POINTING SMALL TRIANGLE
      .put("loz", Integer.valueOf('\u25ca')) // LOZENGE
      .put("lozenge", Integer.valueOf('\u25ca')) // LOZENGE
      .put("cir", Integer.valueOf('\u25cb')) // WHITE CIRCLE
      .put("tridot", Integer.valueOf('\u25ec')) // WHITE UP-POINTING TRIANGLE WITH DOT
      .put("xcirc", Integer.valueOf('\u25ef')) // LARGE CIRCLE
      .put("bigcirc", Integer.valueOf('\u25ef')) // LARGE CIRCLE
      .put("ultri", Integer.valueOf('\u25f8')) // UPPER LEFT TRIANGLE
      .put("urtri", Integer.valueOf('\u25f9')) // UPPER RIGHT TRIANGLE
      .put("lltri", Integer.valueOf('\u25fa')) // LOWER LEFT TRIANGLE
      .put("EmptySmallSquare", Integer.valueOf('\u25fb')) // WHITE MEDIUM SQUARE
      .put("FilledSmallSquare", Integer.valueOf('\u25fc')) // BLACK MEDIUM SQUARE

    // Miscellaneous Symbols
      .put("starf", Integer.valueOf('\u2605')) // BLACK STAR
      .put("bigstar", Integer.valueOf('\u2605')) // BLACK STAR
      .put("star", Integer.valueOf('\u2606')) // WHITE STAR
      .put("phone", Integer.valueOf('\u260e')) // BLACK TELEPHONE
      .put("female", Integer.valueOf('\u2640')) // FEMALE SIGN
      .put("male", Integer.valueOf('\u2642')) // MALE SIGN
      .put("spades", Integer.valueOf('\u2660')) // BLACK SPADE SUIT
      .put("spadesuit", Integer.valueOf('\u2660')) // BLACK SPADE SUIT
      .put("clubs", Integer.valueOf('\u2663')) // BLACK CLUB SUIT
      .put("clubsuit", Integer.valueOf('\u2663')) // BLACK CLUB SUIT
      .put("hearts", Integer.valueOf('\u2665')) // BLACK HEART SUIT
      .put("heartsuit", Integer.valueOf('\u2665')) // BLACK HEART SUIT
      .put("diams", Integer.valueOf('\u2666')) // BLACK DIAMOND SUIT
      .put("diamondsuit", Integer.valueOf('\u2666')) // BLACK DIAMOND SUIT
      .put("sung", Integer.valueOf('\u266a')) // EIGHTH NOTE
      .put("flat", Integer.valueOf('\u266d')) // MUSIC FLAT SIGN
      .put("natur", Integer.valueOf('\u266e')) // MUSIC NATURAL SIGN
      .put("natural", Integer.valueOf('\u266e')) // MUSIC NATURAL SIGN
      .put("sharp", Integer.valueOf('\u266f')) // MUSIC SHARP SIGN

    // Dingbats
      .put("check", Integer.valueOf('\u2713')) // CHECK MARK
      .put("checkmark", Integer.valueOf('\u2713')) // CHECK MARK
      .put("cross", Integer.valueOf('\u2717')) // BALLOT X
      .put("malt", Integer.valueOf('\u2720')) // MALTESE CROSS
      .put("maltese", Integer.valueOf('\u2720')) // MALTESE CROSS
      .put("sext", Integer.valueOf('\u2736')) // SIX POINTED BLACK STAR
      .put("VerticalSeparator", Integer.valueOf('\u2758')) // LIGHT VERTICAL BAR
      .put("lbbrk", Integer.valueOf('\u2772')) // LIGHT LEFT TORTOISE SHELL BRACKET ORNAMENT
      .put("rbbrk", Integer.valueOf('\u2773')) // LIGHT RIGHT TORTOISE SHELL BRACKET ORNAMENT

    // Miscellaneous Mathematical Symbols-A
      .put("lobrk", Integer.valueOf('\u27e6')) // MATHEMATICAL LEFT WHITE SQUARE BRACKET
      .put("LeftDoubleBracket", Integer.valueOf('\u27e6')) // MATHEMATICAL LEFT WHITE SQUARE BRACKET
      .put("robrk", Integer.valueOf('\u27e7')) // MATHEMATICAL RIGHT WHITE SQUARE BRACKET
      .put("RightDoubleBracket", Integer.valueOf('\u27e7')) // MATHEMATICAL RIGHT WHITE SQUARE BRACKET
      .put("lang", Integer.valueOf('\u27e8')) // MATHEMATICAL LEFT ANGLE BRACKET
      .put("LeftAngleBracket", Integer.valueOf('\u27e8')) // MATHEMATICAL LEFT ANGLE BRACKET
      .put("langle", Integer.valueOf('\u27e8')) // MATHEMATICAL LEFT ANGLE BRACKET
      .put("rang", Integer.valueOf('\u27e9')) // MATHEMATICAL RIGHT ANGLE BRACKET
      .put("RightAngleBracket", Integer.valueOf('\u27e9')) // MATHEMATICAL RIGHT ANGLE BRACKET
      .put("rangle", Integer.valueOf('\u27e9')) // MATHEMATICAL RIGHT ANGLE BRACKET
      .put("Lang", Integer.valueOf('\u27ea')) // MATHEMATICAL LEFT DOUBLE ANGLE BRACKET
      .put("Rang", Integer.valueOf('\u27eb')) // MATHEMATICAL RIGHT DOUBLE ANGLE BRACKET
      .put("loang", Integer.valueOf('\u27ec')) // MATHEMATICAL LEFT WHITE TORTOISE SHELL BRACKET
      .put("roang", Integer.valueOf('\u27ed')) // MATHEMATICAL RIGHT WHITE TORTOISE SHELL BRACKET

    // Supplemental Arrows-A
      .put("xlarr", Integer.valueOf('\u27f5')) // LONG LEFTWARDS ARROW
      .put("longleftarrow", Integer.valueOf('\u27f5')) // LONG LEFTWARDS ARROW
      .put("LongLeftArrow", Integer.valueOf('\u27f5')) // LONG LEFTWARDS ARROW
      .put("xrarr", Integer.valueOf('\u27f6')) // LONG RIGHTWARDS ARROW
      .put("longrightarrow", Integer.valueOf('\u27f6')) // LONG RIGHTWARDS ARROW
      .put("LongRightArrow", Integer.valueOf('\u27f6')) // LONG RIGHTWARDS ARROW
      .put("xharr", Integer.valueOf('\u27f7')) // LONG LEFT RIGHT ARROW
      .put("longleftrightarrow", Integer.valueOf('\u27f7')) // LONG LEFT RIGHT ARROW
      .put("LongLeftRightArrow", Integer.valueOf('\u27f7')) // LONG LEFT RIGHT ARROW
      .put("xlArr", Integer.valueOf('\u27f8')) // LONG LEFTWARDS DOUBLE ARROW
      .put("Longleftarrow", Integer.valueOf('\u27f8')) // LONG LEFTWARDS DOUBLE ARROW
      .put("DoubleLongLeftArrow", Integer.valueOf('\u27f8')) // LONG LEFTWARDS DOUBLE ARROW
      .put("xrArr", Integer.valueOf('\u27f9')) // LONG RIGHTWARDS DOUBLE ARROW
      .put("Longrightarrow", Integer.valueOf('\u27f9')) // LONG RIGHTWARDS DOUBLE ARROW
      .put("DoubleLongRightArrow", Integer.valueOf('\u27f9')) // LONG RIGHTWARDS DOUBLE ARROW
      .put("xhArr", Integer.valueOf('\u27fa')) // LONG LEFT RIGHT DOUBLE ARROW
      .put("Longleftrightarrow", Integer.valueOf('\u27fa')) // LONG LEFT RIGHT DOUBLE ARROW
      .put("DoubleLongLeftRightArrow", Integer.valueOf('\u27fa')) // LONG LEFT RIGHT DOUBLE ARROW
      .put("xmap", Integer.valueOf('\u27fc')) // LONG RIGHTWARDS ARROW FROM BAR
      .put("longmapsto", Integer.valueOf('\u27fc')) // LONG RIGHTWARDS ARROW FROM BAR
      .put("dzigrarr", Integer.valueOf('\u27ff')) // LONG RIGHTWARDS SQUIGGLE ARROW

    // Supplemental Arrows-B
      .put("nvlArr", Integer.valueOf('\u2902')) // LEFTWARDS DOUBLE ARROW WITH VERTICAL STROKE
      .put("nvrArr", Integer.valueOf('\u2903')) // RIGHTWARDS DOUBLE ARROW WITH VERTICAL STROKE
      .put("nvHarr", Integer.valueOf('\u2904')) // LEFT RIGHT DOUBLE ARROW WITH VERTICAL STROKE
      .put("Map", Integer.valueOf('\u2905')) // RIGHTWARDS TWO-HEADED ARROW FROM BAR
      .put("lbarr", Integer.valueOf('\u290c')) // LEFTWARDS DOUBLE DASH ARROW
      .put("rbarr", Integer.valueOf('\u290d')) // RIGHTWARDS DOUBLE DASH ARROW
      .put("bkarow", Integer.valueOf('\u290d')) // RIGHTWARDS DOUBLE DASH ARROW
      .put("lBarr", Integer.valueOf('\u290e')) // LEFTWARDS TRIPLE DASH ARROW
      .put("rBarr", Integer.valueOf('\u290f')) // RIGHTWARDS TRIPLE DASH ARROW
      .put("dbkarow", Integer.valueOf('\u290f')) // RIGHTWARDS TRIPLE DASH ARROW
      .put("RBarr", Integer.valueOf('\u2910')) // RIGHTWARDS TWO-HEADED TRIPLE DASH ARROW
      .put("drbkarow", Integer.valueOf('\u2910')) // RIGHTWARDS TWO-HEADED TRIPLE DASH ARROW
      .put("DDotrahd", Integer.valueOf('\u2911')) // RIGHTWARDS ARROW WITH DOTTED STEM
      .put("UpArrowBar", Integer.valueOf('\u2912')) // UPWARDS ARROW TO BAR
      .put("DownArrowBar", Integer.valueOf('\u2913')) // DOWNWARDS ARROW TO BAR
      .put("Rarrtl", Integer.valueOf('\u2916')) // RIGHTWARDS TWO-HEADED ARROW WITH TAIL
      .put("latail", Integer.valueOf('\u2919')) // LEFTWARDS ARROW-TAIL
      .put("ratail", Integer.valueOf('\u291a')) // RIGHTWARDS ARROW-TAIL
      .put("lAtail", Integer.valueOf('\u291b')) // LEFTWARDS DOUBLE ARROW-TAIL
      .put("rAtail", Integer.valueOf('\u291c')) // RIGHTWARDS DOUBLE ARROW-TAIL
      .put("larrfs", Integer.valueOf('\u291d')) // LEFTWARDS ARROW TO BLACK DIAMOND
      .put("rarrfs", Integer.valueOf('\u291e')) // RIGHTWARDS ARROW TO BLACK DIAMOND
      .put("larrbfs", Integer.valueOf('\u291f')) // LEFTWARDS ARROW FROM BAR TO BLACK DIAMOND
      .put("rarrbfs", Integer.valueOf('\u2920')) // RIGHTWARDS ARROW FROM BAR TO BLACK DIAMOND
      .put("nwarhk", Integer.valueOf('\u2923')) // NORTH WEST ARROW WITH HOOK
      .put("nearhk", Integer.valueOf('\u2924')) // NORTH EAST ARROW WITH HOOK
      .put("searhk", Integer.valueOf('\u2925')) // SOUTH EAST ARROW WITH HOOK
      .put("hksearow", Integer.valueOf('\u2925')) // SOUTH EAST ARROW WITH HOOK
      .put("swarhk", Integer.valueOf('\u2926')) // SOUTH WEST ARROW WITH HOOK
      .put("hkswarow", Integer.valueOf('\u2926')) // SOUTH WEST ARROW WITH HOOK
      .put("nwnear", Integer.valueOf('\u2927')) // NORTH WEST ARROW AND NORTH EAST ARROW
      .put("nesear", Integer.valueOf('\u2928')) // NORTH EAST ARROW AND SOUTH EAST ARROW
      .put("toea", Integer.valueOf('\u2928')) // NORTH EAST ARROW AND SOUTH EAST ARROW
      .put("seswar", Integer.valueOf('\u2929')) // SOUTH EAST ARROW AND SOUTH WEST ARROW
      .put("tosa", Integer.valueOf('\u2929')) // SOUTH EAST ARROW AND SOUTH WEST ARROW
      .put("swnwar", Integer.valueOf('\u292a')) // SOUTH WEST ARROW AND NORTH WEST ARROW
      .put("rarrc", Integer.valueOf('\u2933')) // WAVE ARROW POINTING DIRECTLY RIGHT
      .put("cudarrr", Integer.valueOf('\u2935')) // ARROW POINTING RIGHTWARDS THEN CURVING DOWNWARDS
      .put("ldca", Integer.valueOf('\u2936')) // ARROW POINTING DOWNWARDS THEN CURVING LEFTWARDS
      .put("rdca", Integer.valueOf('\u2937')) // ARROW POINTING DOWNWARDS THEN CURVING RIGHTWARDS
      .put("cudarrl", Integer.valueOf('\u2938')) // RIGHT-SIDE ARC CLOCKWISE ARROW
      .put("larrpl", Integer.valueOf('\u2939')) // LEFT-SIDE ARC ANTICLOCKWISE ARROW
      .put("curarrm", Integer.valueOf('\u293c')) // TOP ARC CLOCKWISE ARROW WITH MINUS
      .put("cularrp", Integer.valueOf('\u293d')) // TOP ARC ANTICLOCKWISE ARROW WITH PLUS
      .put("rarrpl", Integer.valueOf('\u2945')) // RIGHTWARDS ARROW WITH PLUS BELOW
      .put("harrcir", Integer.valueOf('\u2948')) // LEFT RIGHT ARROW THROUGH SMALL CIRCLE
      .put("Uarrocir", Integer.valueOf('\u2949')) // UPWARDS TWO-HEADED ARROW FROM SMALL CIRCLE
      .put("lurdshar", Integer.valueOf('\u294a')) // LEFT BARB UP RIGHT BARB DOWN HARPOON
      .put("ldrushar", Integer.valueOf('\u294b')) // LEFT BARB DOWN RIGHT BARB UP HARPOON
      .put("LeftRightVector", Integer.valueOf('\u294e')) // LEFT BARB UP RIGHT BARB UP HARPOON
      .put("RightUpDownVector", Integer.valueOf('\u294f')) // UP BARB RIGHT DOWN BARB RIGHT HARPOON
      .put("DownLeftRightVector", Integer.valueOf('\u2950')) // LEFT BARB DOWN RIGHT BARB DOWN HARPOON
      .put("LeftUpDownVector", Integer.valueOf('\u2951')) // UP BARB LEFT DOWN BARB LEFT HARPOON
      .put("LeftVectorBar", Integer.valueOf('\u2952')) // LEFTWARDS HARPOON WITH BARB UP TO BAR
      .put("RightVectorBar", Integer.valueOf('\u2953')) // RIGHTWARDS HARPOON WITH BARB UP TO BAR
      .put("RightUpVectorBar", Integer.valueOf('\u2954')) // UPWARDS HARPOON WITH BARB RIGHT TO BAR
      .put("RightDownVectorBar", Integer.valueOf('\u2955')) // DOWNWARDS HARPOON WITH BARB RIGHT TO BAR
      .put("DownLeftVectorBar", Integer.valueOf('\u2956')) // LEFTWARDS HARPOON WITH BARB DOWN TO BAR
      .put("DownRightVectorBar", Integer.valueOf('\u2957')) // RIGHTWARDS HARPOON WITH BARB DOWN TO BAR
      .put("LeftUpVectorBar", Integer.valueOf('\u2958')) // UPWARDS HARPOON WITH BARB LEFT TO BAR
      .put("LeftDownVectorBar", Integer.valueOf('\u2959')) // DOWNWARDS HARPOON WITH BARB LEFT TO BAR
      .put("LeftTeeVector", Integer.valueOf('\u295a')) // LEFTWARDS HARPOON WITH BARB UP FROM BAR
      .put("RightTeeVector", Integer.valueOf('\u295b')) // RIGHTWARDS HARPOON WITH BARB UP FROM BAR
      .put("RightUpTeeVector", Integer.valueOf('\u295c')) // UPWARDS HARPOON WITH BARB RIGHT FROM BAR
      .put("RightDownTeeVector", Integer.valueOf('\u295d')) // DOWNWARDS HARPOON WITH BARB RIGHT FROM BAR
      .put("DownLeftTeeVector", Integer.valueOf('\u295e')) // LEFTWARDS HARPOON WITH BARB DOWN FROM BAR
      .put("DownRightTeeVector", Integer.valueOf('\u295f')) // RIGHTWARDS HARPOON WITH BARB DOWN FROM BAR
      .put("LeftUpTeeVector", Integer.valueOf('\u2960')) // UPWARDS HARPOON WITH BARB LEFT FROM BAR
      .put("LeftDownTeeVector", Integer.valueOf('\u2961')) // DOWNWARDS HARPOON WITH BARB LEFT FROM BAR
      .put("lHar", Integer.valueOf('\u2962')) // LEFTWARDS HARPOON WITH BARB UP ABOVE LEFTWARDS HARPOON WITH BARB DOWN
      .put("uHar", Integer.valueOf('\u2963')) // UPWARDS HARPOON WITH BARB LEFT BESIDE UPWARDS HARPOON WITH BARB RIGHT
      .put("rHar", Integer.valueOf('\u2964')) // RIGHTWARDS HARPOON WITH BARB UP ABOVE RIGHTWARDS HARPOON WITH BARB DOWN
      .put("dHar", Integer.valueOf('\u2965')) // DOWNWARDS HARPOON WITH BARB LEFT BESIDE DOWNWARDS HARPOON WITH BARB RIGHT
      .put("luruhar", Integer.valueOf('\u2966')) // LEFTWARDS HARPOON WITH BARB UP ABOVE RIGHTWARDS HARPOON WITH BARB UP
      .put("ldrdhar", Integer.valueOf('\u2967')) // LEFTWARDS HARPOON WITH BARB DOWN ABOVE RIGHTWARDS HARPOON WITH BARB DOWN
      .put("ruluhar", Integer.valueOf('\u2968')) // RIGHTWARDS HARPOON WITH BARB UP ABOVE LEFTWARDS HARPOON WITH BARB UP
      .put("rdldhar", Integer.valueOf('\u2969')) // RIGHTWARDS HARPOON WITH BARB DOWN ABOVE LEFTWARDS HARPOON WITH BARB DOWN
      .put("lharul", Integer.valueOf('\u296a')) // LEFTWARDS HARPOON WITH BARB UP ABOVE LONG DASH
      .put("llhard", Integer.valueOf('\u296b')) // LEFTWARDS HARPOON WITH BARB DOWN BELOW LONG DASH
      .put("rharul", Integer.valueOf('\u296c')) // RIGHTWARDS HARPOON WITH BARB UP ABOVE LONG DASH
      .put("lrhard", Integer.valueOf('\u296d')) // RIGHTWARDS HARPOON WITH BARB DOWN BELOW LONG DASH
      .put("udhar", Integer.valueOf('\u296e')) // UPWARDS HARPOON WITH BARB LEFT BESIDE DOWNWARDS HARPOON WITH BARB RIGHT
      .put("UpEquilibrium", Integer.valueOf('\u296e')) // UPWARDS HARPOON WITH BARB LEFT BESIDE DOWNWARDS HARPOON WITH BARB RIGHT
      .put("duhar", Integer.valueOf('\u296f')) // DOWNWARDS HARPOON WITH BARB LEFT BESIDE UPWARDS HARPOON WITH BARB RIGHT
      .put("ReverseUpEquilibrium", Integer.valueOf('\u296f')) // DOWNWARDS HARPOON WITH BARB LEFT BESIDE UPWARDS HARPOON WITH BARB RIGHT
      .put("RoundImplies", Integer.valueOf('\u2970')) // RIGHT DOUBLE ARROW WITH ROUNDED HEAD
      .put("erarr", Integer.valueOf('\u2971')) // EQUALS SIGN ABOVE RIGHTWARDS ARROW
      .put("simrarr", Integer.valueOf('\u2972')) // TILDE OPERATOR ABOVE RIGHTWARDS ARROW
      .put("larrsim", Integer.valueOf('\u2973')) // LEFTWARDS ARROW ABOVE TILDE OPERATOR
      .put("rarrsim", Integer.valueOf('\u2974')) // RIGHTWARDS ARROW ABOVE TILDE OPERATOR
      .put("rarrap", Integer.valueOf('\u2975')) // RIGHTWARDS ARROW ABOVE ALMOST EQUAL TO
      .put("ltlarr", Integer.valueOf('\u2976')) // LESS-THAN ABOVE LEFTWARDS ARROW
      .put("gtrarr", Integer.valueOf('\u2978')) // GREATER-THAN ABOVE RIGHTWARDS ARROW
      .put("subrarr", Integer.valueOf('\u2979')) // SUBSET ABOVE RIGHTWARDS ARROW
      .put("suplarr", Integer.valueOf('\u297b')) // SUPERSET ABOVE LEFTWARDS ARROW
      .put("lfisht", Integer.valueOf('\u297c')) // LEFT FISH TAIL
      .put("rfisht", Integer.valueOf('\u297d')) // RIGHT FISH TAIL
      .put("ufisht", Integer.valueOf('\u297e')) // UP FISH TAIL
      .put("dfisht", Integer.valueOf('\u297f')) // DOWN FISH TAIL

    // Miscellaneous Mathematical Symbols-B
      .put("lopar", Integer.valueOf('\u2985')) // LEFT WHITE PARENTHESIS
      .put("ropar", Integer.valueOf('\u2986')) // RIGHT WHITE PARENTHESIS
      .put("lbrke", Integer.valueOf('\u298b')) // LEFT SQUARE BRACKET WITH UNDERBAR
      .put("rbrke", Integer.valueOf('\u298c')) // RIGHT SQUARE BRACKET WITH UNDERBAR
      .put("lbrkslu", Integer.valueOf('\u298d')) // LEFT SQUARE BRACKET WITH TICK IN TOP CORNER
      .put("rbrksld", Integer.valueOf('\u298e')) // RIGHT SQUARE BRACKET WITH TICK IN BOTTOM CORNER
      .put("lbrksld", Integer.valueOf('\u298f')) // LEFT SQUARE BRACKET WITH TICK IN BOTTOM CORNER
      .put("rbrkslu", Integer.valueOf('\u2990')) // RIGHT SQUARE BRACKET WITH TICK IN TOP CORNER
      .put("langd", Integer.valueOf('\u2991')) // LEFT ANGLE BRACKET WITH DOT
      .put("rangd", Integer.valueOf('\u2992')) // RIGHT ANGLE BRACKET WITH DOT
      .put("lparlt", Integer.valueOf('\u2993')) // LEFT ARC LESS-THAN BRACKET
      .put("rpargt", Integer.valueOf('\u2994')) // RIGHT ARC GREATER-THAN BRACKET
      .put("gtlPar", Integer.valueOf('\u2995')) // DOUBLE LEFT ARC GREATER-THAN BRACKET
      .put("ltrPar", Integer.valueOf('\u2996')) // DOUBLE RIGHT ARC LESS-THAN BRACKET
      .put("vzigzag", Integer.valueOf('\u299a')) // VERTICAL ZIGZAG LINE
      .put("vangrt", Integer.valueOf('\u299c')) // RIGHT ANGLE VARIANT WITH SQUARE
      .put("angrtvbd", Integer.valueOf('\u299d')) // MEASURED RIGHT ANGLE WITH DOT
      .put("ange", Integer.valueOf('\u29a4')) // ANGLE WITH UNDERBAR
      .put("range", Integer.valueOf('\u29a5')) // REVERSED ANGLE WITH UNDERBAR
      .put("dwangle", Integer.valueOf('\u29a6')) // OBLIQUE ANGLE OPENING UP
      .put("uwangle", Integer.valueOf('\u29a7')) // OBLIQUE ANGLE OPENING DOWN
      .put("angmsdaa", Integer.valueOf('\u29a8')) // MEASURED ANGLE WITH OPEN ARM ENDING IN ARROW POINTING UP AND RIGHT
      .put("angmsdab", Integer.valueOf('\u29a9')) // MEASURED ANGLE WITH OPEN ARM ENDING IN ARROW POINTING UP AND LEFT
      .put("angmsdac", Integer.valueOf('\u29aa')) // MEASURED ANGLE WITH OPEN ARM ENDING IN ARROW POINTING DOWN AND RIGHT
      .put("angmsdad", Integer.valueOf('\u29ab')) // MEASURED ANGLE WITH OPEN ARM ENDING IN ARROW POINTING DOWN AND LEFT
      .put("angmsdae", Integer.valueOf('\u29ac')) // MEASURED ANGLE WITH OPEN ARM ENDING IN ARROW POINTING RIGHT AND UP
      .put("angmsdaf", Integer.valueOf('\u29ad')) // MEASURED ANGLE WITH OPEN ARM ENDING IN ARROW POINTING LEFT AND UP
      .put("angmsdag", Integer.valueOf('\u29ae')) // MEASURED ANGLE WITH OPEN ARM ENDING IN ARROW POINTING RIGHT AND DOWN
      .put("angmsdah", Integer.valueOf('\u29af')) // MEASURED ANGLE WITH OPEN ARM ENDING IN ARROW POINTING LEFT AND DOWN
      .put("bemptyv", Integer.valueOf('\u29b0')) // REVERSED EMPTY SET
      .put("demptyv", Integer.valueOf('\u29b1')) // EMPTY SET WITH OVERBAR
      .put("cemptyv", Integer.valueOf('\u29b2')) // EMPTY SET WITH SMALL CIRCLE ABOVE
      .put("raemptyv", Integer.valueOf('\u29b3')) // EMPTY SET WITH RIGHT ARROW ABOVE
      .put("laemptyv", Integer.valueOf('\u29b4')) // EMPTY SET WITH LEFT ARROW ABOVE
      .put("ohbar", Integer.valueOf('\u29b5')) // CIRCLE WITH HORIZONTAL BAR
      .put("omid", Integer.valueOf('\u29b6')) // CIRCLED VERTICAL BAR
      .put("opar", Integer.valueOf('\u29b7')) // CIRCLED PARALLEL
      .put("operp", Integer.valueOf('\u29b9')) // CIRCLED PERPENDICULAR
      .put("olcross", Integer.valueOf('\u29bb')) // CIRCLE WITH SUPERIMPOSED X
      .put("odsold", Integer.valueOf('\u29bc')) // CIRCLED ANTICLOCKWISE-ROTATED DIVISION SIGN
      .put("olcir", Integer.valueOf('\u29be')) // CIRCLED WHITE BULLET
      .put("ofcir", Integer.valueOf('\u29bf')) // CIRCLED BULLET
      .put("olt", Integer.valueOf('\u29c0')) // CIRCLED LESS-THAN
      .put("ogt", Integer.valueOf('\u29c1')) // CIRCLED GREATER-THAN
      .put("cirscir", Integer.valueOf('\u29c2')) // CIRCLE WITH SMALL CIRCLE TO THE RIGHT
      .put("cirE", Integer.valueOf('\u29c3')) // CIRCLE WITH TWO HORIZONTAL STROKES TO THE RIGHT
      .put("solb", Integer.valueOf('\u29c4')) // SQUARED RISING DIAGONAL SLASH
      .put("bsolb", Integer.valueOf('\u29c5')) // SQUARED FALLING DIAGONAL SLASH
      .put("boxbox", Integer.valueOf('\u29c9')) // TWO JOINED SQUARES
      .put("trisb", Integer.valueOf('\u29cd')) // TRIANGLE WITH SERIFS AT BOTTOM
      .put("rtriltri", Integer.valueOf('\u29ce')) // RIGHT TRIANGLE ABOVE LEFT TRIANGLE
      .put("LeftTriangleBar", Integer.valueOf('\u29cf')) // LEFT TRIANGLE BESIDE VERTICAL BAR
      .put("RightTriangleBar", Integer.valueOf('\u29d0')) // VERTICAL BAR BESIDE RIGHT TRIANGLE
      .put("race", Integer.valueOf('\u29da')) // LEFT DOUBLE WIGGLY FENCE
      .put("iinfin", Integer.valueOf('\u29dc')) // INCOMPLETE INFINITY
      .put("infintie", Integer.valueOf('\u29dd')) // TIE OVER INFINITY
      .put("nvinfin", Integer.valueOf('\u29de')) // INFINITY NEGATED WITH VERTICAL BAR
      .put("eparsl", Integer.valueOf('\u29e3')) // EQUALS SIGN AND SLANTED PARALLEL
      .put("smeparsl", Integer.valueOf('\u29e4')) // EQUALS SIGN AND SLANTED PARALLEL WITH TILDE ABOVE
      .put("eqvparsl", Integer.valueOf('\u29e5')) // IDENTICAL TO AND SLANTED PARALLEL
      .put("lozf", Integer.valueOf('\u29eb')) // BLACK LOZENGE
      .put("blacklozenge", Integer.valueOf('\u29eb')) // BLACK LOZENGE
      .put("RuleDelayed", Integer.valueOf('\u29f4')) // RULE-DELAYED
      .put("dsol", Integer.valueOf('\u29f6')) // SOLIDUS WITH OVERBAR

    // Supplemental Mathematical Operators
      .put("xodot", Integer.valueOf('\u2a00')) // N-ARY CIRCLED DOT OPERATOR
      .put("bigodot", Integer.valueOf('\u2a00')) // N-ARY CIRCLED DOT OPERATOR
      .put("xoplus", Integer.valueOf('\u2a01')) // N-ARY CIRCLED PLUS OPERATOR
      .put("bigoplus", Integer.valueOf('\u2a01')) // N-ARY CIRCLED PLUS OPERATOR
      .put("xotime", Integer.valueOf('\u2a02')) // N-ARY CIRCLED TIMES OPERATOR
      .put("bigotimes", Integer.valueOf('\u2a02')) // N-ARY CIRCLED TIMES OPERATOR
      .put("xuplus", Integer.valueOf('\u2a04')) // N-ARY UNION OPERATOR WITH PLUS
      .put("biguplus", Integer.valueOf('\u2a04')) // N-ARY UNION OPERATOR WITH PLUS
      .put("xsqcup", Integer.valueOf('\u2a06')) // N-ARY SQUARE UNION OPERATOR
      .put("bigsqcup", Integer.valueOf('\u2a06')) // N-ARY SQUARE UNION OPERATOR
      .put("qint", Integer.valueOf('\u2a0c')) // QUADRUPLE INTEGRAL OPERATOR
      .put("iiiint", Integer.valueOf('\u2a0c')) // QUADRUPLE INTEGRAL OPERATOR
      .put("fpartint", Integer.valueOf('\u2a0d')) // FINITE PART INTEGRAL
      .put("cirfnint", Integer.valueOf('\u2a10')) // CIRCULATION FUNCTION
      .put("awint", Integer.valueOf('\u2a11')) // ANTICLOCKWISE INTEGRATION
      .put("rppolint", Integer.valueOf('\u2a12')) // LINE INTEGRATION WITH RECTANGULAR PATH AROUND POLE
      .put("scpolint", Integer.valueOf('\u2a13')) // LINE INTEGRATION WITH SEMICIRCULAR PATH AROUND POLE
      .put("npolint", Integer.valueOf('\u2a14')) // LINE INTEGRATION NOT INCLUDING THE POLE
      .put("pointint", Integer.valueOf('\u2a15')) // INTEGRAL AROUND A POINT OPERATOR
      .put("quatint", Integer.valueOf('\u2a16')) // QUATERNION INTEGRAL OPERATOR
      .put("intlarhk", Integer.valueOf('\u2a17')) // INTEGRAL WITH LEFTWARDS ARROW WITH HOOK
      .put("pluscir", Integer.valueOf('\u2a22')) // PLUS SIGN WITH SMALL CIRCLE ABOVE
      .put("plusacir", Integer.valueOf('\u2a23')) // PLUS SIGN WITH CIRCUMFLEX ACCENT ABOVE
      .put("simplus", Integer.valueOf('\u2a24')) // PLUS SIGN WITH TILDE ABOVE
      .put("plusdu", Integer.valueOf('\u2a25')) // PLUS SIGN WITH DOT BELOW
      .put("plussim", Integer.valueOf('\u2a26')) // PLUS SIGN WITH TILDE BELOW
      .put("plustwo", Integer.valueOf('\u2a27')) // PLUS SIGN WITH SUBSCRIPT TWO
      .put("mcomma", Integer.valueOf('\u2a29')) // MINUS SIGN WITH COMMA ABOVE
      .put("minusdu", Integer.valueOf('\u2a2a')) // MINUS SIGN WITH DOT BELOW
      .put("loplus", Integer.valueOf('\u2a2d')) // PLUS SIGN IN LEFT HALF CIRCLE
      .put("roplus", Integer.valueOf('\u2a2e')) // PLUS SIGN IN RIGHT HALF CIRCLE
      .put("Cross", Integer.valueOf('\u2a2f')) // VECTOR OR CROSS PRODUCT
      .put("timesd", Integer.valueOf('\u2a30')) // MULTIPLICATION SIGN WITH DOT ABOVE
      .put("timesbar", Integer.valueOf('\u2a31')) // MULTIPLICATION SIGN WITH UNDERBAR
      .put("smashp", Integer.valueOf('\u2a33')) // SMASH PRODUCT
      .put("lotimes", Integer.valueOf('\u2a34')) // MULTIPLICATION SIGN IN LEFT HALF CIRCLE
      .put("rotimes", Integer.valueOf('\u2a35')) // MULTIPLICATION SIGN IN RIGHT HALF CIRCLE
      .put("otimesas", Integer.valueOf('\u2a36')) // CIRCLED MULTIPLICATION SIGN WITH CIRCUMFLEX ACCENT
      .put("Otimes", Integer.valueOf('\u2a37')) // MULTIPLICATION SIGN IN DOUBLE CIRCLE
      .put("odiv", Integer.valueOf('\u2a38')) // CIRCLED DIVISION SIGN
      .put("triplus", Integer.valueOf('\u2a39')) // PLUS SIGN IN TRIANGLE
      .put("triminus", Integer.valueOf('\u2a3a')) // MINUS SIGN IN TRIANGLE
      .put("tritime", Integer.valueOf('\u2a3b')) // MULTIPLICATION SIGN IN TRIANGLE
      .put("iprod", Integer.valueOf('\u2a3c')) // INTERIOR PRODUCT
      .put("intprod", Integer.valueOf('\u2a3c')) // INTERIOR PRODUCT
      .put("amalg", Integer.valueOf('\u2a3f')) // AMALGAMATION OR COPRODUCT
      .put("capdot", Integer.valueOf('\u2a40')) // INTERSECTION WITH DOT
      .put("ncup", Integer.valueOf('\u2a42')) // UNION WITH OVERBAR
      .put("ncap", Integer.valueOf('\u2a43')) // INTERSECTION WITH OVERBAR
      .put("capand", Integer.valueOf('\u2a44')) // INTERSECTION WITH LOGICAL AND
      .put("cupor", Integer.valueOf('\u2a45')) // UNION WITH LOGICAL OR
      .put("cupcap", Integer.valueOf('\u2a46')) // UNION ABOVE INTERSECTION
      .put("capcup", Integer.valueOf('\u2a47')) // INTERSECTION ABOVE UNION
      .put("cupbrcap", Integer.valueOf('\u2a48')) // UNION ABOVE BAR ABOVE INTERSECTION
      .put("capbrcup", Integer.valueOf('\u2a49')) // INTERSECTION ABOVE BAR ABOVE UNION
      .put("cupcup", Integer.valueOf('\u2a4a')) // UNION BESIDE AND JOINED WITH UNION
      .put("capcap", Integer.valueOf('\u2a4b')) // INTERSECTION BESIDE AND JOINED WITH INTERSECTION
      .put("ccups", Integer.valueOf('\u2a4c')) // CLOSED UNION WITH SERIFS
      .put("ccaps", Integer.valueOf('\u2a4d')) // CLOSED INTERSECTION WITH SERIFS
      .put("ccupssm", Integer.valueOf('\u2a50')) // CLOSED UNION WITH SERIFS AND SMASH PRODUCT
      .put("And", Integer.valueOf('\u2a53')) // DOUBLE LOGICAL AND
      .put("Or", Integer.valueOf('\u2a54')) // DOUBLE LOGICAL OR
      .put("andand", Integer.valueOf('\u2a55')) // TWO INTERSECTING LOGICAL AND
      .put("oror", Integer.valueOf('\u2a56')) // TWO INTERSECTING LOGICAL OR
      .put("orslope", Integer.valueOf('\u2a57')) // SLOPING LARGE OR
      .put("andslope", Integer.valueOf('\u2a58')) // SLOPING LARGE AND
      .put("andv", Integer.valueOf('\u2a5a')) // LOGICAL AND WITH MIDDLE STEM
      .put("orv", Integer.valueOf('\u2a5b')) // LOGICAL OR WITH MIDDLE STEM
      .put("andd", Integer.valueOf('\u2a5c')) // LOGICAL AND WITH HORIZONTAL DASH
      .put("ord", Integer.valueOf('\u2a5d')) // LOGICAL OR WITH HORIZONTAL DASH
      .put("wedbar", Integer.valueOf('\u2a5f')) // LOGICAL AND WITH UNDERBAR
      .put("sdote", Integer.valueOf('\u2a66')) // EQUALS SIGN WITH DOT BELOW
      .put("simdot", Integer.valueOf('\u2a6a')) // TILDE OPERATOR WITH DOT ABOVE
      .put("congdot", Integer.valueOf('\u2a6d')) // CONGRUENT WITH DOT ABOVE
      .put("easter", Integer.valueOf('\u2a6e')) // EQUALS WITH ASTERISK
      .put("apacir", Integer.valueOf('\u2a6f')) // ALMOST EQUAL TO WITH CIRCUMFLEX ACCENT
      .put("apE", Integer.valueOf('\u2a70')) // APPROXIMATELY EQUAL OR EQUAL TO
      .put("eplus", Integer.valueOf('\u2a71')) // EQUALS SIGN ABOVE PLUS SIGN
      .put("pluse", Integer.valueOf('\u2a72')) // PLUS SIGN ABOVE EQUALS SIGN
      .put("Esim", Integer.valueOf('\u2a73')) // EQUALS SIGN ABOVE TILDE OPERATOR
      .put("Colone", Integer.valueOf('\u2a74')) // DOUBLE COLON EQUAL
      .put("Equal", Integer.valueOf('\u2a75')) // TWO CONSECUTIVE EQUALS SIGNS
      .put("eDDot", Integer.valueOf('\u2a77')) // EQUALS SIGN WITH TWO DOTS ABOVE AND TWO DOTS BELOW
      .put("ddotseq", Integer.valueOf('\u2a77')) // EQUALS SIGN WITH TWO DOTS ABOVE AND TWO DOTS BELOW
      .put("equivDD", Integer.valueOf('\u2a78')) // EQUIVALENT WITH FOUR DOTS ABOVE
      .put("ltcir", Integer.valueOf('\u2a79')) // LESS-THAN WITH CIRCLE INSIDE
      .put("gtcir", Integer.valueOf('\u2a7a')) // GREATER-THAN WITH CIRCLE INSIDE
      .put("ltquest", Integer.valueOf('\u2a7b')) // LESS-THAN WITH QUESTION MARK ABOVE
      .put("gtquest", Integer.valueOf('\u2a7c')) // GREATER-THAN WITH QUESTION MARK ABOVE
      .put("les", Integer.valueOf('\u2a7d')) // LESS-THAN OR SLANTED EQUAL TO
      .put("LessSlantEqual", Integer.valueOf('\u2a7d')) // LESS-THAN OR SLANTED EQUAL TO
      .put("leqslant", Integer.valueOf('\u2a7d')) // LESS-THAN OR SLANTED EQUAL TO
      .put("ges", Integer.valueOf('\u2a7e')) // GREATER-THAN OR SLANTED EQUAL TO
      .put("GreaterSlantEqual", Integer.valueOf('\u2a7e')) // GREATER-THAN OR SLANTED EQUAL TO
      .put("geqslant", Integer.valueOf('\u2a7e')) // GREATER-THAN OR SLANTED EQUAL TO
      .put("lesdot", Integer.valueOf('\u2a7f')) // LESS-THAN OR SLANTED EQUAL TO WITH DOT INSIDE
      .put("gesdot", Integer.valueOf('\u2a80')) // GREATER-THAN OR SLANTED EQUAL TO WITH DOT INSIDE
      .put("lesdoto", Integer.valueOf('\u2a81')) // LESS-THAN OR SLANTED EQUAL TO WITH DOT ABOVE
      .put("gesdoto", Integer.valueOf('\u2a82')) // GREATER-THAN OR SLANTED EQUAL TO WITH DOT ABOVE
      .put("lesdotor", Integer.valueOf('\u2a83')) // LESS-THAN OR SLANTED EQUAL TO WITH DOT ABOVE RIGHT
      .put("gesdotol", Integer.valueOf('\u2a84')) // GREATER-THAN OR SLANTED EQUAL TO WITH DOT ABOVE LEFT
      .put("lap", Integer.valueOf('\u2a85')) // LESS-THAN OR APPROXIMATE
      .put("lessapprox", Integer.valueOf('\u2a85')) // LESS-THAN OR APPROXIMATE
      .put("gap", Integer.valueOf('\u2a86')) // GREATER-THAN OR APPROXIMATE
      .put("gtrapprox", Integer.valueOf('\u2a86')) // GREATER-THAN OR APPROXIMATE
      .put("lne", Integer.valueOf('\u2a87')) // LESS-THAN AND SINGLE-LINE NOT EQUAL TO
      .put("lneq", Integer.valueOf('\u2a87')) // LESS-THAN AND SINGLE-LINE NOT EQUAL TO
      .put("gne", Integer.valueOf('\u2a88')) // GREATER-THAN AND SINGLE-LINE NOT EQUAL TO
      .put("gneq", Integer.valueOf('\u2a88')) // GREATER-THAN AND SINGLE-LINE NOT EQUAL TO
      .put("lnap", Integer.valueOf('\u2a89')) // LESS-THAN AND NOT APPROXIMATE
      .put("lnapprox", Integer.valueOf('\u2a89')) // LESS-THAN AND NOT APPROXIMATE
      .put("gnap", Integer.valueOf('\u2a8a')) // GREATER-THAN AND NOT APPROXIMATE
      .put("gnapprox", Integer.valueOf('\u2a8a')) // GREATER-THAN AND NOT APPROXIMATE
      .put("lEg", Integer.valueOf('\u2a8b')) // LESS-THAN ABOVE DOUBLE-LINE EQUAL ABOVE GREATER-THAN
      .put("lesseqqgtr", Integer.valueOf('\u2a8b')) // LESS-THAN ABOVE DOUBLE-LINE EQUAL ABOVE GREATER-THAN
      .put("gEl", Integer.valueOf('\u2a8c')) // GREATER-THAN ABOVE DOUBLE-LINE EQUAL ABOVE LESS-THAN
      .put("gtreqqless", Integer.valueOf('\u2a8c')) // GREATER-THAN ABOVE DOUBLE-LINE EQUAL ABOVE LESS-THAN
      .put("lsime", Integer.valueOf('\u2a8d')) // LESS-THAN ABOVE SIMILAR OR EQUAL
      .put("gsime", Integer.valueOf('\u2a8e')) // GREATER-THAN ABOVE SIMILAR OR EQUAL
      .put("lsimg", Integer.valueOf('\u2a8f')) // LESS-THAN ABOVE SIMILAR ABOVE GREATER-THAN
      .put("gsiml", Integer.valueOf('\u2a90')) // GREATER-THAN ABOVE SIMILAR ABOVE LESS-THAN
      .put("lgE", Integer.valueOf('\u2a91')) // LESS-THAN ABOVE GREATER-THAN ABOVE DOUBLE-LINE EQUAL
      .put("glE", Integer.valueOf('\u2a92')) // GREATER-THAN ABOVE LESS-THAN ABOVE DOUBLE-LINE EQUAL
      .put("lesges", Integer.valueOf('\u2a93')) // LESS-THAN ABOVE SLANTED EQUAL ABOVE GREATER-THAN ABOVE SLANTED EQUAL
      .put("gesles", Integer.valueOf('\u2a94')) // GREATER-THAN ABOVE SLANTED EQUAL ABOVE LESS-THAN ABOVE SLANTED EQUAL
      .put("els", Integer.valueOf('\u2a95')) // SLANTED EQUAL TO OR LESS-THAN
      .put("eqslantless", Integer.valueOf('\u2a95')) // SLANTED EQUAL TO OR LESS-THAN
      .put("egs", Integer.valueOf('\u2a96')) // SLANTED EQUAL TO OR GREATER-THAN
      .put("eqslantgtr", Integer.valueOf('\u2a96')) // SLANTED EQUAL TO OR GREATER-THAN
      .put("elsdot", Integer.valueOf('\u2a97')) // SLANTED EQUAL TO OR LESS-THAN WITH DOT INSIDE
      .put("egsdot", Integer.valueOf('\u2a98')) // SLANTED EQUAL TO OR GREATER-THAN WITH DOT INSIDE
      .put("el", Integer.valueOf('\u2a99')) // DOUBLE-LINE EQUAL TO OR LESS-THAN
      .put("eg", Integer.valueOf('\u2a9a')) // DOUBLE-LINE EQUAL TO OR GREATER-THAN
      .put("siml", Integer.valueOf('\u2a9d')) // SIMILAR OR LESS-THAN
      .put("simg", Integer.valueOf('\u2a9e')) // SIMILAR OR GREATER-THAN
      .put("simlE", Integer.valueOf('\u2a9f')) // SIMILAR ABOVE LESS-THAN ABOVE EQUALS SIGN
      .put("simgE", Integer.valueOf('\u2aa0')) // SIMILAR ABOVE GREATER-THAN ABOVE EQUALS SIGN
      .put("LessLess", Integer.valueOf('\u2aa1')) // DOUBLE NESTED LESS-THAN
      .put("GreaterGreater", Integer.valueOf('\u2aa2')) // DOUBLE NESTED GREATER-THAN
      .put("glj", Integer.valueOf('\u2aa4')) // GREATER-THAN OVERLAPPING LESS-THAN
      .put("gla", Integer.valueOf('\u2aa5')) // GREATER-THAN BESIDE LESS-THAN
      .put("ltcc", Integer.valueOf('\u2aa6')) // LESS-THAN CLOSED BY CURVE
      .put("gtcc", Integer.valueOf('\u2aa7')) // GREATER-THAN CLOSED BY CURVE
      .put("lescc", Integer.valueOf('\u2aa8')) // LESS-THAN CLOSED BY CURVE ABOVE SLANTED EQUAL
      .put("gescc", Integer.valueOf('\u2aa9')) // GREATER-THAN CLOSED BY CURVE ABOVE SLANTED EQUAL
      .put("smt", Integer.valueOf('\u2aaa')) // SMALLER THAN
      .put("lat", Integer.valueOf('\u2aab')) // LARGER THAN
      .put("smte", Integer.valueOf('\u2aac')) // SMALLER THAN OR EQUAL TO
      .put("late", Integer.valueOf('\u2aad')) // LARGER THAN OR EQUAL TO
      .put("bumpE", Integer.valueOf('\u2aae')) // EQUALS SIGN WITH BUMPY ABOVE
      .put("pre", Integer.valueOf('\u2aaf')) // PRECEDES ABOVE SINGLE-LINE EQUALS SIGN
      .put("preceq", Integer.valueOf('\u2aaf')) // PRECEDES ABOVE SINGLE-LINE EQUALS SIGN
      .put("PrecedesEqual", Integer.valueOf('\u2aaf')) // PRECEDES ABOVE SINGLE-LINE EQUALS SIGN
      .put("sce", Integer.valueOf('\u2ab0')) // SUCCEEDS ABOVE SINGLE-LINE EQUALS SIGN
      .put("succeq", Integer.valueOf('\u2ab0')) // SUCCEEDS ABOVE SINGLE-LINE EQUALS SIGN
      .put("SucceedsEqual", Integer.valueOf('\u2ab0')) // SUCCEEDS ABOVE SINGLE-LINE EQUALS SIGN
      .put("prE", Integer.valueOf('\u2ab3')) // PRECEDES ABOVE EQUALS SIGN
      .put("scE", Integer.valueOf('\u2ab4')) // SUCCEEDS ABOVE EQUALS SIGN
      .put("prnE", Integer.valueOf('\u2ab5')) // PRECEDES ABOVE NOT EQUAL TO
      .put("precneqq", Integer.valueOf('\u2ab5')) // PRECEDES ABOVE NOT EQUAL TO
      .put("scnE", Integer.valueOf('\u2ab6')) // SUCCEEDS ABOVE NOT EQUAL TO
      .put("succneqq", Integer.valueOf('\u2ab6')) // SUCCEEDS ABOVE NOT EQUAL TO
      .put("prap", Integer.valueOf('\u2ab7')) // PRECEDES ABOVE ALMOST EQUAL TO
      .put("precapprox", Integer.valueOf('\u2ab7')) // PRECEDES ABOVE ALMOST EQUAL TO
      .put("scap", Integer.valueOf('\u2ab8')) // SUCCEEDS ABOVE ALMOST EQUAL TO
      .put("succapprox", Integer.valueOf('\u2ab8')) // SUCCEEDS ABOVE ALMOST EQUAL TO
      .put("prnap", Integer.valueOf('\u2ab9')) // PRECEDES ABOVE NOT ALMOST EQUAL TO
      .put("precnapprox", Integer.valueOf('\u2ab9')) // PRECEDES ABOVE NOT ALMOST EQUAL TO
      .put("scnap", Integer.valueOf('\u2aba')) // SUCCEEDS ABOVE NOT ALMOST EQUAL TO
      .put("succnapprox", Integer.valueOf('\u2aba')) // SUCCEEDS ABOVE NOT ALMOST EQUAL TO
      .put("Pr", Integer.valueOf('\u2abb')) // DOUBLE PRECEDES
      .put("Sc", Integer.valueOf('\u2abc')) // DOUBLE SUCCEEDS
      .put("subdot", Integer.valueOf('\u2abd')) // SUBSET WITH DOT
      .put("supdot", Integer.valueOf('\u2abe')) // SUPERSET WITH DOT
      .put("subplus", Integer.valueOf('\u2abf')) // SUBSET WITH PLUS SIGN BELOW
      .put("supplus", Integer.valueOf('\u2ac0')) // SUPERSET WITH PLUS SIGN BELOW
      .put("submult", Integer.valueOf('\u2ac1')) // SUBSET WITH MULTIPLICATION SIGN BELOW
      .put("supmult", Integer.valueOf('\u2ac2')) // SUPERSET WITH MULTIPLICATION SIGN BELOW
      .put("subedot", Integer.valueOf('\u2ac3')) // SUBSET OF OR EQUAL TO WITH DOT ABOVE
      .put("supedot", Integer.valueOf('\u2ac4')) // SUPERSET OF OR EQUAL TO WITH DOT ABOVE
      .put("subE", Integer.valueOf('\u2ac5')) // SUBSET OF ABOVE EQUALS SIGN
      .put("subseteqq", Integer.valueOf('\u2ac5')) // SUBSET OF ABOVE EQUALS SIGN
      .put("supE", Integer.valueOf('\u2ac6')) // SUPERSET OF ABOVE EQUALS SIGN
      .put("supseteqq", Integer.valueOf('\u2ac6')) // SUPERSET OF ABOVE EQUALS SIGN
      .put("subsim", Integer.valueOf('\u2ac7')) // SUBSET OF ABOVE TILDE OPERATOR
      .put("supsim", Integer.valueOf('\u2ac8')) // SUPERSET OF ABOVE TILDE OPERATOR
      .put("subnE", Integer.valueOf('\u2acb')) // SUBSET OF ABOVE NOT EQUAL TO
      .put("subsetneqq", Integer.valueOf('\u2acb')) // SUBSET OF ABOVE NOT EQUAL TO
      .put("supnE", Integer.valueOf('\u2acc')) // SUPERSET OF ABOVE NOT EQUAL TO
      .put("supsetneqq", Integer.valueOf('\u2acc')) // SUPERSET OF ABOVE NOT EQUAL TO
      .put("csub", Integer.valueOf('\u2acf')) // CLOSED SUBSET
      .put("csup", Integer.valueOf('\u2ad0')) // CLOSED SUPERSET
      .put("csube", Integer.valueOf('\u2ad1')) // CLOSED SUBSET OR EQUAL TO
      .put("csupe", Integer.valueOf('\u2ad2')) // CLOSED SUPERSET OR EQUAL TO
      .put("subsup", Integer.valueOf('\u2ad3')) // SUBSET ABOVE SUPERSET
      .put("supsub", Integer.valueOf('\u2ad4')) // SUPERSET ABOVE SUBSET
      .put("subsub", Integer.valueOf('\u2ad5')) // SUBSET ABOVE SUBSET
      .put("supsup", Integer.valueOf('\u2ad6')) // SUPERSET ABOVE SUPERSET
      .put("suphsub", Integer.valueOf('\u2ad7')) // SUPERSET BESIDE SUBSET
      .put("supdsub", Integer.valueOf('\u2ad8')) // SUPERSET BESIDE AND JOINED BY DASH WITH SUBSET
      .put("forkv", Integer.valueOf('\u2ad9')) // ELEMENT OF OPENING DOWNWARDS
      .put("topfork", Integer.valueOf('\u2ada')) // PITCHFORK WITH TEE TOP
      .put("mlcp", Integer.valueOf('\u2adb')) // TRANSVERSAL INTERSECTION
      .put("Dashv", Integer.valueOf('\u2ae4')) // VERTICAL BAR DOUBLE LEFT TURNSTILE
      .put("DoubleLeftTee", Integer.valueOf('\u2ae4')) // VERTICAL BAR DOUBLE LEFT TURNSTILE
      .put("Vdashl", Integer.valueOf('\u2ae6')) // LONG DASH FROM LEFT MEMBER OF DOUBLE VERTICAL
      .put("Barv", Integer.valueOf('\u2ae7')) // SHORT DOWN TACK WITH OVERBAR
      .put("vBar", Integer.valueOf('\u2ae8')) // SHORT UP TACK WITH UNDERBAR
      .put("vBarv", Integer.valueOf('\u2ae9')) // SHORT UP TACK ABOVE SHORT DOWN TACK
      .put("Vbar", Integer.valueOf('\u2aeb')) // DOUBLE UP TACK
      .put("Not", Integer.valueOf('\u2aec')) // DOUBLE STROKE NOT SIGN
      .put("bNot", Integer.valueOf('\u2aed')) // REVERSED DOUBLE STROKE NOT SIGN
      .put("rnmid", Integer.valueOf('\u2aee')) // DOES NOT DIVIDE WITH REVERSED NEGATION SLASH
      .put("cirmid", Integer.valueOf('\u2aef')) // VERTICAL LINE WITH CIRCLE ABOVE
      .put("midcir", Integer.valueOf('\u2af0')) // VERTICAL LINE WITH CIRCLE BELOW
      .put("topcir", Integer.valueOf('\u2af1')) // DOWN TACK WITH CIRCLE BELOW
      .put("nhpar", Integer.valueOf('\u2af2')) // PARALLEL WITH HORIZONTAL STROKE
      .put("parsim", Integer.valueOf('\u2af3')) // PARALLEL WITH TILDE OPERATOR
      .put("parsl", Integer.valueOf('\u2afd')) // DOUBLE SOLIDUS OPERATOR

    // Alphabetic Presentation Forms
      .put("fflig", Integer.valueOf('\ufb00')) // LATIN SMALL LIGATURE FF
      .put("filig", Integer.valueOf('\ufb01')) // LATIN SMALL LIGATURE FI
      .put("fllig", Integer.valueOf('\ufb02')) // LATIN SMALL LIGATURE FL
      .put("ffilig", Integer.valueOf('\ufb03')) // LATIN SMALL LIGATURE FFI
      .put("ffllig", Integer.valueOf('\ufb04')) // LATIN SMALL LIGATURE FFL

    // Mathematical Alphanumeric Symbols
      .put("Ascr", Character.toCodePoint('\ud835', '\udc9c')) // MATHEMATICAL SCRIPT CAPITAL A
      .put("Cscr", Character.toCodePoint('\ud835', '\udc9e')) // MATHEMATICAL SCRIPT CAPITAL C
      .put("Dscr", Character.toCodePoint('\ud835', '\udc9f')) // MATHEMATICAL SCRIPT CAPITAL D
      .put("Gscr", Character.toCodePoint('\ud835', '\udca2')) // MATHEMATICAL SCRIPT CAPITAL G
      .put("Jscr", Character.toCodePoint('\ud835', '\udca5')) // MATHEMATICAL SCRIPT CAPITAL J
      .put("Kscr", Character.toCodePoint('\ud835', '\udca6')) // MATHEMATICAL SCRIPT CAPITAL K
      .put("Nscr", Character.toCodePoint('\ud835', '\udca9')) // MATHEMATICAL SCRIPT CAPITAL N
      .put("Oscr", Character.toCodePoint('\ud835', '\udcaa')) // MATHEMATICAL SCRIPT CAPITAL O
      .put("Pscr", Character.toCodePoint('\ud835', '\udcab')) // MATHEMATICAL SCRIPT CAPITAL P
      .put("Qscr", Character.toCodePoint('\ud835', '\udcac')) // MATHEMATICAL SCRIPT CAPITAL Q
      .put("Sscr", Character.toCodePoint('\ud835', '\udcae')) // MATHEMATICAL SCRIPT CAPITAL S
      .put("Tscr", Character.toCodePoint('\ud835', '\udcaf')) // MATHEMATICAL SCRIPT CAPITAL T
      .put("Uscr", Character.toCodePoint('\ud835', '\udcb0')) // MATHEMATICAL SCRIPT CAPITAL U
      .put("Vscr", Character.toCodePoint('\ud835', '\udcb1')) // MATHEMATICAL SCRIPT CAPITAL V
      .put("Wscr", Character.toCodePoint('\ud835', '\udcb2')) // MATHEMATICAL SCRIPT CAPITAL W
      .put("Xscr", Character.toCodePoint('\ud835', '\udcb3')) // MATHEMATICAL SCRIPT CAPITAL X
      .put("Yscr", Character.toCodePoint('\ud835', '\udcb4')) // MATHEMATICAL SCRIPT CAPITAL Y
      .put("Zscr", Character.toCodePoint('\ud835', '\udcb5')) // MATHEMATICAL SCRIPT CAPITAL Z
      .put("ascr", Character.toCodePoint('\ud835', '\udcb6')) // MATHEMATICAL SCRIPT SMALL A
      .put("bscr", Character.toCodePoint('\ud835', '\udcb7')) // MATHEMATICAL SCRIPT SMALL B
      .put("cscr", Character.toCodePoint('\ud835', '\udcb8')) // MATHEMATICAL SCRIPT SMALL C
      .put("dscr", Character.toCodePoint('\ud835', '\udcb9')) // MATHEMATICAL SCRIPT SMALL D
      .put("fscr", Character.toCodePoint('\ud835', '\udcbb')) // MATHEMATICAL SCRIPT SMALL F
      .put("hscr", Character.toCodePoint('\ud835', '\udcbd')) // MATHEMATICAL SCRIPT SMALL H
      .put("iscr", Character.toCodePoint('\ud835', '\udcbe')) // MATHEMATICAL SCRIPT SMALL I
      .put("jscr", Character.toCodePoint('\ud835', '\udcbf')) // MATHEMATICAL SCRIPT SMALL J
      .put("kscr", Character.toCodePoint('\ud835', '\udcc0')) // MATHEMATICAL SCRIPT SMALL K
      .put("lscr", Character.toCodePoint('\ud835', '\udcc1')) // MATHEMATICAL SCRIPT SMALL L
      .put("mscr", Character.toCodePoint('\ud835', '\udcc2')) // MATHEMATICAL SCRIPT SMALL M
      .put("nscr", Character.toCodePoint('\ud835', '\udcc3')) // MATHEMATICAL SCRIPT SMALL N
      .put("pscr", Character.toCodePoint('\ud835', '\udcc5')) // MATHEMATICAL SCRIPT SMALL P
      .put("qscr", Character.toCodePoint('\ud835', '\udcc6')) // MATHEMATICAL SCRIPT SMALL Q
      .put("rscr", Character.toCodePoint('\ud835', '\udcc7')) // MATHEMATICAL SCRIPT SMALL R
      .put("sscr", Character.toCodePoint('\ud835', '\udcc8')) // MATHEMATICAL SCRIPT SMALL S
      .put("tscr", Character.toCodePoint('\ud835', '\udcc9')) // MATHEMATICAL SCRIPT SMALL T
      .put("uscr", Character.toCodePoint('\ud835', '\udcca')) // MATHEMATICAL SCRIPT SMALL U
      .put("vscr", Character.toCodePoint('\ud835', '\udccb')) // MATHEMATICAL SCRIPT SMALL V
      .put("wscr", Character.toCodePoint('\ud835', '\udccc')) // MATHEMATICAL SCRIPT SMALL W
      .put("xscr", Character.toCodePoint('\ud835', '\udccd')) // MATHEMATICAL SCRIPT SMALL X
      .put("yscr", Character.toCodePoint('\ud835', '\udcce')) // MATHEMATICAL SCRIPT SMALL Y
      .put("zscr", Character.toCodePoint('\ud835', '\udccf')) // MATHEMATICAL SCRIPT SMALL Z
      .put("Afr", Character.toCodePoint('\ud835', '\udd04')) // MATHEMATICAL FRAKTUR CAPITAL A
      .put("Bfr", Character.toCodePoint('\ud835', '\udd05')) // MATHEMATICAL FRAKTUR CAPITAL B
      .put("Dfr", Character.toCodePoint('\ud835', '\udd07')) // MATHEMATICAL FRAKTUR CAPITAL D
      .put("Efr", Character.toCodePoint('\ud835', '\udd08')) // MATHEMATICAL FRAKTUR CAPITAL E
      .put("Ffr", Character.toCodePoint('\ud835', '\udd09')) // MATHEMATICAL FRAKTUR CAPITAL F
      .put("Gfr", Character.toCodePoint('\ud835', '\udd0a')) // MATHEMATICAL FRAKTUR CAPITAL G
      .put("Jfr", Character.toCodePoint('\ud835', '\udd0d')) // MATHEMATICAL FRAKTUR CAPITAL J
      .put("Kfr", Character.toCodePoint('\ud835', '\udd0e')) // MATHEMATICAL FRAKTUR CAPITAL K
      .put("Lfr", Character.toCodePoint('\ud835', '\udd0f')) // MATHEMATICAL FRAKTUR CAPITAL L
      .put("Mfr", Character.toCodePoint('\ud835', '\udd10')) // MATHEMATICAL FRAKTUR CAPITAL M
      .put("Nfr", Character.toCodePoint('\ud835', '\udd11')) // MATHEMATICAL FRAKTUR CAPITAL N
      .put("Ofr", Character.toCodePoint('\ud835', '\udd12')) // MATHEMATICAL FRAKTUR CAPITAL O
      .put("Pfr", Character.toCodePoint('\ud835', '\udd13')) // MATHEMATICAL FRAKTUR CAPITAL P
      .put("Qfr", Character.toCodePoint('\ud835', '\udd14')) // MATHEMATICAL FRAKTUR CAPITAL Q
      .put("Sfr", Character.toCodePoint('\ud835', '\udd16')) // MATHEMATICAL FRAKTUR CAPITAL S
      .put("Tfr", Character.toCodePoint('\ud835', '\udd17')) // MATHEMATICAL FRAKTUR CAPITAL T
      .put("Ufr", Character.toCodePoint('\ud835', '\udd18')) // MATHEMATICAL FRAKTUR CAPITAL U
      .put("Vfr", Character.toCodePoint('\ud835', '\udd19')) // MATHEMATICAL FRAKTUR CAPITAL V
      .put("Wfr", Character.toCodePoint('\ud835', '\udd1a')) // MATHEMATICAL FRAKTUR CAPITAL W
      .put("Xfr", Character.toCodePoint('\ud835', '\udd1b')) // MATHEMATICAL FRAKTUR CAPITAL X
      .put("Yfr", Character.toCodePoint('\ud835', '\udd1c')) // MATHEMATICAL FRAKTUR CAPITAL Y
      .put("afr", Character.toCodePoint('\ud835', '\udd1e')) // MATHEMATICAL FRAKTUR SMALL A
      .put("bfr", Character.toCodePoint('\ud835', '\udd1f')) // MATHEMATICAL FRAKTUR SMALL B
      .put("cfr", Character.toCodePoint('\ud835', '\udd20')) // MATHEMATICAL FRAKTUR SMALL C
      .put("dfr", Character.toCodePoint('\ud835', '\udd21')) // MATHEMATICAL FRAKTUR SMALL D
      .put("efr", Character.toCodePoint('\ud835', '\udd22')) // MATHEMATICAL FRAKTUR SMALL E
      .put("ffr", Character.toCodePoint('\ud835', '\udd23')) // MATHEMATICAL FRAKTUR SMALL F
      .put("gfr", Character.toCodePoint('\ud835', '\udd24')) // MATHEMATICAL FRAKTUR SMALL G
      .put("hfr", Character.toCodePoint('\ud835', '\udd25')) // MATHEMATICAL FRAKTUR SMALL H
      .put("ifr", Character.toCodePoint('\ud835', '\udd26')) // MATHEMATICAL FRAKTUR SMALL I
      .put("jfr", Character.toCodePoint('\ud835', '\udd27')) // MATHEMATICAL FRAKTUR SMALL J
      .put("kfr", Character.toCodePoint('\ud835', '\udd28')) // MATHEMATICAL FRAKTUR SMALL K
      .put("lfr", Character.toCodePoint('\ud835', '\udd29')) // MATHEMATICAL FRAKTUR SMALL L
      .put("mfr", Character.toCodePoint('\ud835', '\udd2a')) // MATHEMATICAL FRAKTUR SMALL M
      .put("nfr", Character.toCodePoint('\ud835', '\udd2b')) // MATHEMATICAL FRAKTUR SMALL N
      .put("ofr", Character.toCodePoint('\ud835', '\udd2c')) // MATHEMATICAL FRAKTUR SMALL O
      .put("pfr", Character.toCodePoint('\ud835', '\udd2d')) // MATHEMATICAL FRAKTUR SMALL P
      .put("qfr", Character.toCodePoint('\ud835', '\udd2e')) // MATHEMATICAL FRAKTUR SMALL Q
      .put("rfr", Character.toCodePoint('\ud835', '\udd2f')) // MATHEMATICAL FRAKTUR SMALL R
      .put("sfr", Character.toCodePoint('\ud835', '\udd30')) // MATHEMATICAL FRAKTUR SMALL S
      .put("tfr", Character.toCodePoint('\ud835', '\udd31')) // MATHEMATICAL FRAKTUR SMALL T
      .put("ufr", Character.toCodePoint('\ud835', '\udd32')) // MATHEMATICAL FRAKTUR SMALL U
      .put("vfr", Character.toCodePoint('\ud835', '\udd33')) // MATHEMATICAL FRAKTUR SMALL V
      .put("wfr", Character.toCodePoint('\ud835', '\udd34')) // MATHEMATICAL FRAKTUR SMALL W
      .put("xfr", Character.toCodePoint('\ud835', '\udd35')) // MATHEMATICAL FRAKTUR SMALL X
      .put("yfr", Character.toCodePoint('\ud835', '\udd36')) // MATHEMATICAL FRAKTUR SMALL Y
      .put("zfr", Character.toCodePoint('\ud835', '\udd37')) // MATHEMATICAL FRAKTUR SMALL Z
      .put("Aopf", Character.toCodePoint('\ud835', '\udd38')) // MATHEMATICAL DOUBLE-STRUCK CAPITAL A
      .put("Bopf", Character.toCodePoint('\ud835', '\udd39')) // MATHEMATICAL DOUBLE-STRUCK CAPITAL B
      .put("Dopf", Character.toCodePoint('\ud835', '\udd3b')) // MATHEMATICAL DOUBLE-STRUCK CAPITAL D
      .put("Eopf", Character.toCodePoint('\ud835', '\udd3c')) // MATHEMATICAL DOUBLE-STRUCK CAPITAL E
      .put("Fopf", Character.toCodePoint('\ud835', '\udd3d')) // MATHEMATICAL DOUBLE-STRUCK CAPITAL F
      .put("Gopf", Character.toCodePoint('\ud835', '\udd3e')) // MATHEMATICAL DOUBLE-STRUCK CAPITAL G
      .put("Iopf", Character.toCodePoint('\ud835', '\udd40')) // MATHEMATICAL DOUBLE-STRUCK CAPITAL I
      .put("Jopf", Character.toCodePoint('\ud835', '\udd41')) // MATHEMATICAL DOUBLE-STRUCK CAPITAL J
      .put("Kopf", Character.toCodePoint('\ud835', '\udd42')) // MATHEMATICAL DOUBLE-STRUCK CAPITAL K
      .put("Lopf", Character.toCodePoint('\ud835', '\udd43')) // MATHEMATICAL DOUBLE-STRUCK CAPITAL L
      .put("Mopf", Character.toCodePoint('\ud835', '\udd44')) // MATHEMATICAL DOUBLE-STRUCK CAPITAL M
      .put("Oopf", Character.toCodePoint('\ud835', '\udd46')) // MATHEMATICAL DOUBLE-STRUCK CAPITAL O
      .put("Sopf", Character.toCodePoint('\ud835', '\udd4a')) // MATHEMATICAL DOUBLE-STRUCK CAPITAL S
      .put("Topf", Character.toCodePoint('\ud835', '\udd4b')) // MATHEMATICAL DOUBLE-STRUCK CAPITAL T
      .put("Uopf", Character.toCodePoint('\ud835', '\udd4c')) // MATHEMATICAL DOUBLE-STRUCK CAPITAL U
      .put("Vopf", Character.toCodePoint('\ud835', '\udd4d')) // MATHEMATICAL DOUBLE-STRUCK CAPITAL V
      .put("Wopf", Character.toCodePoint('\ud835', '\udd4e')) // MATHEMATICAL DOUBLE-STRUCK CAPITAL W
      .put("Xopf", Character.toCodePoint('\ud835', '\udd4f')) // MATHEMATICAL DOUBLE-STRUCK CAPITAL X
      .put("Yopf", Character.toCodePoint('\ud835', '\udd50')) // MATHEMATICAL DOUBLE-STRUCK CAPITAL Y
      .put("aopf", Character.toCodePoint('\ud835', '\udd52')) // MATHEMATICAL DOUBLE-STRUCK SMALL A
      .put("bopf", Character.toCodePoint('\ud835', '\udd53')) // MATHEMATICAL DOUBLE-STRUCK SMALL B
      .put("copf", Character.toCodePoint('\ud835', '\udd54')) // MATHEMATICAL DOUBLE-STRUCK SMALL C
      .put("dopf", Character.toCodePoint('\ud835', '\udd55')) // MATHEMATICAL DOUBLE-STRUCK SMALL D
      .put("eopf", Character.toCodePoint('\ud835', '\udd56')) // MATHEMATICAL DOUBLE-STRUCK SMALL E
      .put("fopf", Character.toCodePoint('\ud835', '\udd57')) // MATHEMATICAL DOUBLE-STRUCK SMALL F
      .put("gopf", Character.toCodePoint('\ud835', '\udd58')) // MATHEMATICAL DOUBLE-STRUCK SMALL G
      .put("hopf", Character.toCodePoint('\ud835', '\udd59')) // MATHEMATICAL DOUBLE-STRUCK SMALL H
      .put("iopf", Character.toCodePoint('\ud835', '\udd5a')) // MATHEMATICAL DOUBLE-STRUCK SMALL I
      .put("jopf", Character.toCodePoint('\ud835', '\udd5b')) // MATHEMATICAL DOUBLE-STRUCK SMALL J
      .put("kopf", Character.toCodePoint('\ud835', '\udd5c')) // MATHEMATICAL DOUBLE-STRUCK SMALL K
      .put("lopf", Character.toCodePoint('\ud835', '\udd5d')) // MATHEMATICAL DOUBLE-STRUCK SMALL L
      .put("mopf", Character.toCodePoint('\ud835', '\udd5e')) // MATHEMATICAL DOUBLE-STRUCK SMALL M
      .put("nopf", Character.toCodePoint('\ud835', '\udd5f')) // MATHEMATICAL DOUBLE-STRUCK SMALL N
      .put("oopf", Character.toCodePoint('\ud835', '\udd60')) // MATHEMATICAL DOUBLE-STRUCK SMALL O
      .put("popf", Character.toCodePoint('\ud835', '\udd61')) // MATHEMATICAL DOUBLE-STRUCK SMALL P
      .put("qopf", Character.toCodePoint('\ud835', '\udd62')) // MATHEMATICAL DOUBLE-STRUCK SMALL Q
      .put("ropf", Character.toCodePoint('\ud835', '\udd63')) // MATHEMATICAL DOUBLE-STRUCK SMALL R
      .put("sopf", Character.toCodePoint('\ud835', '\udd64')) // MATHEMATICAL DOUBLE-STRUCK SMALL S
      .put("topf", Character.toCodePoint('\ud835', '\udd65')) // MATHEMATICAL DOUBLE-STRUCK SMALL T
      .put("uopf", Character.toCodePoint('\ud835', '\udd66')) // MATHEMATICAL DOUBLE-STRUCK SMALL U
      .put("vopf", Character.toCodePoint('\ud835', '\udd67')) // MATHEMATICAL DOUBLE-STRUCK SMALL V
      .put("wopf", Character.toCodePoint('\ud835', '\udd68')) // MATHEMATICAL DOUBLE-STRUCK SMALL W
      .put("xopf", Character.toCodePoint('\ud835', '\udd69')) // MATHEMATICAL DOUBLE-STRUCK SMALL X
      .put("yopf", Character.toCodePoint('\ud835', '\udd6a')) // MATHEMATICAL DOUBLE-STRUCK SMALL Y
      .put("zopf", Character.toCodePoint('\ud835', '\udd6b')) // MATHEMATICAL DOUBLE-STRUCK SMALL Z

      .build());

  private HtmlEntities() { /* uninstantiable */ }
}
