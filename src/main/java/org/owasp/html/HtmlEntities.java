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
class HtmlEntities {

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

    int entityLimit = Math.min(limit, offset + 10);
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
      .put("quot", Integer.valueOf('"'))
      .put("amp", Integer.valueOf('&'))
      .put("lt", Integer.valueOf('<'))
      .put("gt", Integer.valueOf('>'))

    // XML 1.0
      .put("apos", Integer.valueOf('\''))

    // HTML4 entities
      .put("nbsp", Integer.valueOf('\u00a0'))
      .put("iexcl", Integer.valueOf('\u00a1'))
      .put("cent", Integer.valueOf('\u00a2'))
      .put("pound", Integer.valueOf('\u00a3'))
      .put("curren", Integer.valueOf('\u00a4'))
      .put("yen", Integer.valueOf('\u00a5'))
      .put("brvbar", Integer.valueOf('\u00a6'))
      .put("sect", Integer.valueOf('\u00a7'))
      .put("uml", Integer.valueOf('\u00a8'))
      .put("copy", Integer.valueOf('\u00a9'))
      .put("ordf", Integer.valueOf('\u00aa'))
      .put("laquo", Integer.valueOf('\u00ab'))
      .put("not", Integer.valueOf('\u00ac'))
      .put("shy", Integer.valueOf('\u00ad'))
      .put("reg", Integer.valueOf('\u00ae'))
      .put("macr", Integer.valueOf('\u00af'))
      .put("deg", Integer.valueOf('\u00b0'))
      .put("plusmn", Integer.valueOf('\u00b1'))
      .put("sup2", Integer.valueOf('\u00b2'))
      .put("sup3", Integer.valueOf('\u00b3'))
      .put("acute", Integer.valueOf('\u00b4'))
      .put("micro", Integer.valueOf('\u00b5'))
      .put("para", Integer.valueOf('\u00b6'))
      .put("middot", Integer.valueOf('\u00b7'))
      .put("cedil", Integer.valueOf('\u00b8'))
      .put("sup1", Integer.valueOf('\u00b9'))
      .put("ordm", Integer.valueOf('\u00ba'))
      .put("raquo", Integer.valueOf('\u00bb'))
      .put("frac14", Integer.valueOf('\u00bc'))
      .put("frac12", Integer.valueOf('\u00bd'))
      .put("frac34", Integer.valueOf('\u00be'))
      .put("iquest", Integer.valueOf('\u00bf'))
      .put("Agrave", Integer.valueOf('\u00c0'))
      .put("Aacute", Integer.valueOf('\u00c1'))
      .put("Acirc", Integer.valueOf('\u00c2'))
      .put("Atilde", Integer.valueOf('\u00c3'))
      .put("Auml", Integer.valueOf('\u00c4'))
      .put("Aring", Integer.valueOf('\u00c5'))
      .put("AElig", Integer.valueOf('\u00c6'))
      .put("Ccedil", Integer.valueOf('\u00c7'))
      .put("Egrave", Integer.valueOf('\u00c8'))
      .put("Eacute", Integer.valueOf('\u00c9'))
      .put("Ecirc", Integer.valueOf('\u00ca'))
      .put("Euml", Integer.valueOf('\u00cb'))
      .put("Igrave", Integer.valueOf('\u00cc'))
      .put("Iacute", Integer.valueOf('\u00cd'))
      .put("Icirc", Integer.valueOf('\u00ce'))
      .put("Iuml", Integer.valueOf('\u00cf'))
      .put("ETH", Integer.valueOf('\u00d0'))
      .put("Ntilde", Integer.valueOf('\u00d1'))
      .put("Ograve", Integer.valueOf('\u00d2'))
      .put("Oacute", Integer.valueOf('\u00d3'))
      .put("Ocirc", Integer.valueOf('\u00d4'))
      .put("Otilde", Integer.valueOf('\u00d5'))
      .put("Ouml", Integer.valueOf('\u00d6'))
      .put("times", Integer.valueOf('\u00d7'))
      .put("Oslash", Integer.valueOf('\u00d8'))
      .put("Ugrave", Integer.valueOf('\u00d9'))
      .put("Uacute", Integer.valueOf('\u00da'))
      .put("Ucirc", Integer.valueOf('\u00db'))
      .put("Uuml", Integer.valueOf('\u00dc'))
      .put("Yacute", Integer.valueOf('\u00dd'))
      .put("THORN", Integer.valueOf('\u00de'))
      .put("szlig", Integer.valueOf('\u00df'))
      .put("agrave", Integer.valueOf('\u00e0'))
      .put("aacute", Integer.valueOf('\u00e1'))
      .put("acirc", Integer.valueOf('\u00e2'))
      .put("atilde", Integer.valueOf('\u00e3'))
      .put("auml", Integer.valueOf('\u00e4'))
      .put("aring", Integer.valueOf('\u00e5'))
      .put("aelig", Integer.valueOf('\u00e6'))
      .put("ccedil", Integer.valueOf('\u00e7'))
      .put("egrave", Integer.valueOf('\u00e8'))
      .put("eacute", Integer.valueOf('\u00e9'))
      .put("ecirc", Integer.valueOf('\u00ea'))
      .put("euml", Integer.valueOf('\u00eb'))
      .put("igrave", Integer.valueOf('\u00ec'))
      .put("iacute", Integer.valueOf('\u00ed'))
      .put("icirc", Integer.valueOf('\u00ee'))
      .put("iuml", Integer.valueOf('\u00ef'))
      .put("eth", Integer.valueOf('\u00f0'))
      .put("ntilde", Integer.valueOf('\u00f1'))
      .put("ograve", Integer.valueOf('\u00f2'))
      .put("oacute", Integer.valueOf('\u00f3'))
      .put("ocirc", Integer.valueOf('\u00f4'))
      .put("otilde", Integer.valueOf('\u00f5'))
      .put("ouml", Integer.valueOf('\u00f6'))
      .put("divide", Integer.valueOf('\u00f7'))
      .put("oslash", Integer.valueOf('\u00f8'))
      .put("ugrave", Integer.valueOf('\u00f9'))
      .put("uacute", Integer.valueOf('\u00fa'))
      .put("ucirc", Integer.valueOf('\u00fb'))
      .put("uuml", Integer.valueOf('\u00fc'))
      .put("yacute", Integer.valueOf('\u00fd'))
      .put("thorn", Integer.valueOf('\u00fe'))
      .put("yuml", Integer.valueOf('\u00ff'))

    // Latin Extended-B
      .put("fnof", Integer.valueOf('\u0192'))

    // Greek
      .put("Alpha", Integer.valueOf('\u0391'))
      .put("Beta", Integer.valueOf('\u0392'))
      .put("Gamma", Integer.valueOf('\u0393'))
      .put("Delta", Integer.valueOf('\u0394'))
      .put("Epsilon", Integer.valueOf('\u0395'))
      .put("Zeta", Integer.valueOf('\u0396'))
      .put("Eta", Integer.valueOf('\u0397'))
      .put("Theta", Integer.valueOf('\u0398'))
      .put("Iota", Integer.valueOf('\u0399'))
      .put("Kappa", Integer.valueOf('\u039a'))
      .put("Lambda", Integer.valueOf('\u039b'))
      .put("Mu", Integer.valueOf('\u039c'))
      .put("Nu", Integer.valueOf('\u039d'))
      .put("Xi", Integer.valueOf('\u039e'))
      .put("Omicron", Integer.valueOf('\u039f'))
      .put("Pi", Integer.valueOf('\u03a0'))
      .put("Rho", Integer.valueOf('\u03a1'))
      .put("Sigma", Integer.valueOf('\u03a3'))
      .put("Tau", Integer.valueOf('\u03a4'))
      .put("Upsilon", Integer.valueOf('\u03a5'))
      .put("Phi", Integer.valueOf('\u03a6'))
      .put("Chi", Integer.valueOf('\u03a7'))
      .put("Psi", Integer.valueOf('\u03a8'))
      .put("Omega", Integer.valueOf('\u03a9'))

      .put("alpha", Integer.valueOf('\u03b1'))
      .put("beta", Integer.valueOf('\u03b2'))
      .put("gamma", Integer.valueOf('\u03b3'))
      .put("delta", Integer.valueOf('\u03b4'))
      .put("epsilon", Integer.valueOf('\u03b5'))
      .put("zeta", Integer.valueOf('\u03b6'))
      .put("eta", Integer.valueOf('\u03b7'))
      .put("theta", Integer.valueOf('\u03b8'))
      .put("iota", Integer.valueOf('\u03b9'))
      .put("kappa", Integer.valueOf('\u03ba'))
      .put("lambda", Integer.valueOf('\u03bb'))
      .put("mu", Integer.valueOf('\u03bc'))
      .put("nu", Integer.valueOf('\u03bd'))
      .put("xi", Integer.valueOf('\u03be'))
      .put("omicron", Integer.valueOf('\u03bf'))
      .put("pi", Integer.valueOf('\u03c0'))
      .put("rho", Integer.valueOf('\u03c1'))
      .put("sigmaf", Integer.valueOf('\u03c2'))
      .put("sigma", Integer.valueOf('\u03c3'))
      .put("tau", Integer.valueOf('\u03c4'))
      .put("upsilon", Integer.valueOf('\u03c5'))
      .put("phi", Integer.valueOf('\u03c6'))
      .put("chi", Integer.valueOf('\u03c7'))
      .put("psi", Integer.valueOf('\u03c8'))
      .put("omega", Integer.valueOf('\u03c9'))
      .put("thetasym", Integer.valueOf('\u03d1'))
      .put("upsih", Integer.valueOf('\u03d2'))
      .put("piv", Integer.valueOf('\u03d6'))

    // General Punctuation
      .put("bull", Integer.valueOf('\u2022'))
      .put("hellip", Integer.valueOf('\u2026'))
      .put("prime", Integer.valueOf('\u2032'))
      .put("Prime", Integer.valueOf('\u2033'))
      .put("oline", Integer.valueOf('\u203e'))
      .put("frasl", Integer.valueOf('\u2044'))

    // Letterlike Symbols
      .put("weierp", Integer.valueOf('\u2118'))
      .put("image", Integer.valueOf('\u2111'))
      .put("real", Integer.valueOf('\u211c'))
      .put("trade", Integer.valueOf('\u2122'))
      .put("alefsym", Integer.valueOf('\u2135'))

    // Arrows
      .put("larr", Integer.valueOf('\u2190'))
      .put("uarr", Integer.valueOf('\u2191'))
      .put("rarr", Integer.valueOf('\u2192'))
      .put("darr", Integer.valueOf('\u2193'))
      .put("harr", Integer.valueOf('\u2194'))
      .put("crarr", Integer.valueOf('\u21b5'))
      .put("lArr", Integer.valueOf('\u21d0'))
      .put("uArr", Integer.valueOf('\u21d1'))
      .put("rArr", Integer.valueOf('\u21d2'))
      .put("dArr", Integer.valueOf('\u21d3'))
      .put("hArr", Integer.valueOf('\u21d4'))

    // Mathematical Operators
      .put("forall", Integer.valueOf('\u2200'))
      .put("part", Integer.valueOf('\u2202'))
      .put("exist", Integer.valueOf('\u2203'))
      .put("empty", Integer.valueOf('\u2205'))
      .put("nabla", Integer.valueOf('\u2207'))
      .put("isin", Integer.valueOf('\u2208'))
      .put("notin", Integer.valueOf('\u2209'))
      .put("ni", Integer.valueOf('\u220b'))
      .put("prod", Integer.valueOf('\u220f'))
      .put("sum", Integer.valueOf('\u2211'))
      .put("minus", Integer.valueOf('\u2212'))
      .put("lowast", Integer.valueOf('\u2217'))
      .put("radic", Integer.valueOf('\u221a'))
      .put("prop", Integer.valueOf('\u221d'))
      .put("infin", Integer.valueOf('\u221e'))
      .put("ang", Integer.valueOf('\u2220'))
      .put("and", Integer.valueOf('\u2227'))
      .put("or", Integer.valueOf('\u2228'))
      .put("cap", Integer.valueOf('\u2229'))
      .put("cup", Integer.valueOf('\u222a'))
      .put("int", Integer.valueOf('\u222b'))
      .put("there4", Integer.valueOf('\u2234'))
      .put("sim", Integer.valueOf('\u223c'))
      .put("cong", Integer.valueOf('\u2245'))
      .put("asymp", Integer.valueOf('\u2248'))
      .put("ne", Integer.valueOf('\u2260'))
      .put("equiv", Integer.valueOf('\u2261'))
      .put("le", Integer.valueOf('\u2264'))
      .put("ge", Integer.valueOf('\u2265'))
      .put("sub", Integer.valueOf('\u2282'))
      .put("sup", Integer.valueOf('\u2283'))
      .put("nsub", Integer.valueOf('\u2284'))
      .put("sube", Integer.valueOf('\u2286'))
      .put("supe", Integer.valueOf('\u2287'))
      .put("oplus", Integer.valueOf('\u2295'))
      .put("otimes", Integer.valueOf('\u2297'))
      .put("perp", Integer.valueOf('\u22a5'))
      .put("sdot", Integer.valueOf('\u22c5'))

    // Miscellaneous Technical
      .put("lceil", Integer.valueOf('\u2308'))
      .put("rceil", Integer.valueOf('\u2309'))
      .put("lfloor", Integer.valueOf('\u230a'))
      .put("rfloor", Integer.valueOf('\u230b'))
      .put("lang", Integer.valueOf('\u2329'))
      .put("rang", Integer.valueOf('\u232a'))

    // Geometric Shapes
      .put("loz", Integer.valueOf('\u25ca'))

    // Miscellaneous Symbols
      .put("spades", Integer.valueOf('\u2660'))
      .put("clubs", Integer.valueOf('\u2663'))
      .put("hearts", Integer.valueOf('\u2665'))
      .put("diams", Integer.valueOf('\u2666'))

    // Latin Extended-A
      .put("OElig", Integer.valueOf('\u0152'))
      .put("oelig", Integer.valueOf('\u0153'))
      .put("Scaron", Integer.valueOf('\u0160'))
      .put("scaron", Integer.valueOf('\u0161'))
      .put("Yuml", Integer.valueOf('\u0178'))

    // Spacing Modifier Letters
      .put("circ", Integer.valueOf('\u02c6'))
      .put("tilde", Integer.valueOf('\u02dc'))

    // General Punctuation
      .put("ensp", Integer.valueOf('\u2002'))
      .put("emsp", Integer.valueOf('\u2003'))
      .put("thinsp", Integer.valueOf('\u2009'))
      .put("zwnj", Integer.valueOf('\u200c'))
      .put("zwj", Integer.valueOf('\u200d'))
      .put("lrm", Integer.valueOf('\u200e'))
      .put("rlm", Integer.valueOf('\u200f'))
      .put("ndash", Integer.valueOf('\u2013'))
      .put("mdash", Integer.valueOf('\u2014'))
      .put("lsquo", Integer.valueOf('\u2018'))
      .put("rsquo", Integer.valueOf('\u2019'))
      .put("sbquo", Integer.valueOf('\u201a'))
      .put("ldquo", Integer.valueOf('\u201c'))
      .put("rdquo", Integer.valueOf('\u201d'))
      .put("bdquo", Integer.valueOf('\u201e'))
      .put("dagger", Integer.valueOf('\u2020'))
      .put("Dagger", Integer.valueOf('\u2021'))
      .put("permil", Integer.valueOf('\u2030'))
      .put("lsaquo", Integer.valueOf('\u2039'))
      .put("rsaquo", Integer.valueOf('\u203a'))
      .put("euro", Integer.valueOf('\u20ac'))
      .build());

  private HtmlEntities() { /* uninstantiable */ }
}
