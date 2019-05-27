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

import static java.lang.Character.MIN_HIGH_SURROGATE;
import static java.lang.Character.MIN_LOW_SURROGATE;
import static java.lang.Character.MIN_SUPPLEMENTARY_CODE_POINT;

import java.util.Map;

import com.google.common.collect.ImmutableMap;

/**
 * Utilities for decoding HTML entities, e.g., {@code &amp;}.
 */
final class HtmlEntities {

  /**
   * A trie that maps entity names to code-units. Values are one or two 16-bit
   * code-units packed into 32 bits.
   * The first 16 bits are the first code-unit. The second 16 bits are either
   * the second code-unit or 0x0000 if there is only one code-unit.
   */
  public static final Trie ENTITY_TRIE;

  private static final int LONGEST_ENTITY_NAME;

  static {
    final ImmutableMap.Builder<String, Integer> builder = ImmutableMap.builder();

    // Source data: https://dev.w3.org/html5/html-author/charref

    // C0 Controls and Basic Latin
    builder.put("Tab", Integer.valueOf('\u0009') << 16); // CHARACTER TABULATION
    builder.put("NewLine", Integer.valueOf('\n') << 16); // LINE FEED (LF)
    builder.put("excl", Integer.valueOf('\u0021') << 16); // EXCLAMATION MARK
    builder.put("quot", Integer.valueOf('\u0022') << 16); // QUOTATION MARK
    builder.put("QUOT", Integer.valueOf('\u0022') << 16); // QUOTATION MARK
    builder.put("num", Integer.valueOf('\u0023') << 16); // NUMBER SIGN
    builder.put("dollar", Integer.valueOf('\u0024') << 16); // DOLLAR SIGN
    builder.put("percnt", Integer.valueOf('\u0025') << 16); // PERCENT SIGN
    builder.put("amp", Integer.valueOf('\u0026') << 16); // AMPERSAND
    builder.put("AMP", Integer.valueOf('\u0026') << 16); // AMPERSAND
    builder.put("apos", Integer.valueOf('\'') << 16); // APOSTROPHE
    builder.put("lpar", Integer.valueOf('\u0028') << 16); // LEFT PARENTHESIS
    builder.put("rpar", Integer.valueOf('\u0029') << 16); // RIGHT PARENTHESIS
    builder.put("ast", Integer.valueOf('\u002a') << 16); // ASTERISK
    builder.put("midast", Integer.valueOf('\u002a') << 16); // ASTERISK
    builder.put("plus", Integer.valueOf('\u002b') << 16); // PLUS SIGN
    builder.put("comma", Integer.valueOf('\u002c') << 16); // COMMA
    builder.put("period", Integer.valueOf('\u002e') << 16); // FULL STOP
    builder.put("sol", Integer.valueOf('\u002f') << 16); // SOLIDUS
    builder.put("colon", Integer.valueOf('\u003a') << 16); // COLON
    builder.put("semi", Integer.valueOf('\u003b') << 16); // SEMICOLON
    builder.put("lt", Integer.valueOf('\u003c') << 16); // LESS-THAN SIGN
    builder.put("LT", Integer.valueOf('\u003c') << 16); // LESS-THAN SIGN
    builder.put("equals", Integer.valueOf('\u003d') << 16); // EQUALS SIGN
    builder.put("gt", Integer.valueOf('\u003e') << 16); // GREATER-THAN SIGN
    builder.put("GT", Integer.valueOf('\u003e') << 16); // GREATER-THAN SIGN
    builder.put("quest", Integer.valueOf('\u003f') << 16); // QUESTION MARK
    builder.put("commat", Integer.valueOf('\u0040') << 16); // COMMERCIAL AT
    builder.put("lsqb", Integer.valueOf('\u005b') << 16); // LEFT SQUARE BRACKET
    builder.put("lbrack", Integer.valueOf('\u005b') << 16); // LEFT SQUARE BRACKET
    builder.put("bsol", Integer.valueOf('\\') << 16); // REVERSE SOLIDUS
    builder.put("rsqb", Integer.valueOf('\u005d') << 16); // RIGHT SQUARE BRACKET
    builder.put("rbrack", Integer.valueOf('\u005d') << 16); // RIGHT SQUARE BRACKET
    builder.put("Hat", Integer.valueOf('\u005e') << 16); // CIRCUMFLEX ACCENT
    builder.put("lowbar", Integer.valueOf('\u005f') << 16); // LOW LINE
    builder.put("grave", Integer.valueOf('\u0060') << 16); // GRAVE ACCENT
    builder.put("DiacriticalGrave", Integer.valueOf('\u0060') << 16); // GRAVE ACCENT
    builder.put("lcub", Integer.valueOf('\u007b') << 16); // LEFT CURLY BRACKET
    builder.put("lbrace", Integer.valueOf('\u007b') << 16); // LEFT CURLY BRACKET
    builder.put("verbar", Integer.valueOf('\u007c') << 16); // VERTICAL LINE
    builder.put("vert", Integer.valueOf('\u007c') << 16); // VERTICAL LINE
    builder.put("VerticalLine", Integer.valueOf('\u007c') << 16); // VERTICAL LINE
    builder.put("rcub", Integer.valueOf('\u007d') << 16); // RIGHT CURLY BRACKET
    builder.put("rbrace", Integer.valueOf('\u007d') << 16); // RIGHT CURLY BRACKET

    // C1 Controls and Latin-1 Supplement
    builder.put("nbsp", Integer.valueOf('\u00a0') << 16); // NO-BREAK SPACE
    builder.put("NonBreakingSpace", Integer.valueOf('\u00a0') << 16); // NO-BREAK SPACE
    builder.put("iexcl", Integer.valueOf('\u00a1') << 16); // INVERTED EXCLAMATION MARK
    builder.put("cent", Integer.valueOf('\u00a2') << 16); // CENT SIGN
    builder.put("pound", Integer.valueOf('\u00a3') << 16); // POUND SIGN
    builder.put("curren", Integer.valueOf('\u00a4') << 16); // CURRENCY SIGN
    builder.put("yen", Integer.valueOf('\u00a5') << 16); // YEN SIGN
    builder.put("brvbar", Integer.valueOf('\u00a6') << 16); // BROKEN BAR
    builder.put("sect", Integer.valueOf('\u00a7') << 16); // SECTION SIGN
    builder.put("Dot", Integer.valueOf('\u00a8') << 16); // DIAERESIS
    builder.put("die", Integer.valueOf('\u00a8') << 16); // DIAERESIS
    builder.put("DoubleDot", Integer.valueOf('\u00a8') << 16); // DIAERESIS
    builder.put("uml", Integer.valueOf('\u00a8') << 16); // DIAERESIS
    builder.put("copy", Integer.valueOf('\u00a9') << 16); // COPYRIGHT SIGN
    builder.put("COPY", Integer.valueOf('\u00a9') << 16); // COPYRIGHT SIGN
    builder.put("ordf", Integer.valueOf('\u00aa') << 16); // FEMININE ORDINAL INDICATOR
    builder.put("laquo", Integer.valueOf('\u00ab') << 16); // LEFT-POINTING DOUBLE ANGLE QUOTATION MARK
    builder.put("not", Integer.valueOf('\u00ac') << 16); // NOT SIGN
    builder.put("shy", Integer.valueOf('\u00ad') << 16); // SOFT HYPHEN
    builder.put("reg", Integer.valueOf('\u00ae') << 16); // REGISTERED SIGN
    builder.put("circledR", Integer.valueOf('\u00ae') << 16); // REGISTERED SIGN
    builder.put("REG", Integer.valueOf('\u00ae') << 16); // REGISTERED SIGN
    builder.put("macr", Integer.valueOf('\u00af') << 16); // MACRON
    builder.put("OverBar", Integer.valueOf('\u00af') << 16); // MACRON
    builder.put("strns", Integer.valueOf('\u00af') << 16); // MACRON
    builder.put("deg", Integer.valueOf('\u00b0') << 16); // DEGREE SIGN
    builder.put("plusmn", Integer.valueOf('\u00b1') << 16); // PLUS-MINUS SIGN
    builder.put("pm", Integer.valueOf('\u00b1') << 16); // PLUS-MINUS SIGN
    builder.put("PlusMinus", Integer.valueOf('\u00b1') << 16); // PLUS-MINUS SIGN
    builder.put("sup2", Integer.valueOf('\u00b2') << 16); // SUPERSCRIPT TWO
    builder.put("sup3", Integer.valueOf('\u00b3') << 16); // SUPERSCRIPT THREE
    builder.put("acute", Integer.valueOf('\u00b4') << 16); // ACUTE ACCENT
    builder.put("DiacriticalAcute", Integer.valueOf('\u00b4') << 16); // ACUTE ACCENT
    builder.put("micro", Integer.valueOf('\u00b5') << 16); // MICRO SIGN
    builder.put("para", Integer.valueOf('\u00b6') << 16); // PILCROW SIGN
    builder.put("middot", Integer.valueOf('\u00b7') << 16); // MIDDLE DOT
    builder.put("centerdot", Integer.valueOf('\u00b7') << 16); // MIDDLE DOT
    builder.put("CenterDot", Integer.valueOf('\u00b7') << 16); // MIDDLE DOT
    builder.put("cedil", Integer.valueOf('\u00b8') << 16); // CEDILLA
    builder.put("Cedilla", Integer.valueOf('\u00b8') << 16); // CEDILLA
    builder.put("sup1", Integer.valueOf('\u00b9') << 16); // SUPERSCRIPT ONE
    builder.put("ordm", Integer.valueOf('\u00ba') << 16); // MASCULINE ORDINAL INDICATOR
    builder.put("raquo", Integer.valueOf('\u00bb') << 16); // RIGHT-POINTING DOUBLE ANGLE QUOTATION MARK
    builder.put("frac14", Integer.valueOf('\u00bc') << 16); // VULGAR FRACTION ONE QUARTER
    builder.put("frac12", Integer.valueOf('\u00bd') << 16); // VULGAR FRACTION ONE HALF
    builder.put("half", Integer.valueOf('\u00bd') << 16); // VULGAR FRACTION ONE HALF
    builder.put("frac34", Integer.valueOf('\u00be') << 16); // VULGAR FRACTION THREE QUARTERS
    builder.put("iquest", Integer.valueOf('\u00bf') << 16); // INVERTED QUESTION MARK
    builder.put("Agrave", Integer.valueOf('\u00c0') << 16); // LATIN CAPITAL LETTER A WITH GRAVE
    builder.put("Aacute", Integer.valueOf('\u00c1') << 16); // LATIN CAPITAL LETTER A WITH ACUTE
    builder.put("Acirc", Integer.valueOf('\u00c2') << 16); // LATIN CAPITAL LETTER A WITH CIRCUMFLEX
    builder.put("Atilde", Integer.valueOf('\u00c3') << 16); // LATIN CAPITAL LETTER A WITH TILDE
    builder.put("Auml", Integer.valueOf('\u00c4') << 16); // LATIN CAPITAL LETTER A WITH DIAERESIS
    builder.put("Aring", Integer.valueOf('\u00c5') << 16); // LATIN CAPITAL LETTER A WITH RING ABOVE
    builder.put("AElig", Integer.valueOf('\u00c6') << 16); // LATIN CAPITAL LETTER AE
    builder.put("Ccedil", Integer.valueOf('\u00c7') << 16); // LATIN CAPITAL LETTER C WITH CEDILLA
    builder.put("Egrave", Integer.valueOf('\u00c8') << 16); // LATIN CAPITAL LETTER E WITH GRAVE
    builder.put("Eacute", Integer.valueOf('\u00c9') << 16); // LATIN CAPITAL LETTER E WITH ACUTE
    builder.put("Ecirc", Integer.valueOf('\u00ca') << 16); // LATIN CAPITAL LETTER E WITH CIRCUMFLEX
    builder.put("Euml", Integer.valueOf('\u00cb') << 16); // LATIN CAPITAL LETTER E WITH DIAERESIS
    builder.put("Igrave", Integer.valueOf('\u00cc') << 16); // LATIN CAPITAL LETTER I WITH GRAVE
    builder.put("Iacute", Integer.valueOf('\u00cd') << 16); // LATIN CAPITAL LETTER I WITH ACUTE
    builder.put("Icirc", Integer.valueOf('\u00ce') << 16); // LATIN CAPITAL LETTER I WITH CIRCUMFLEX
    builder.put("Iuml", Integer.valueOf('\u00cf') << 16); // LATIN CAPITAL LETTER I WITH DIAERESIS
    builder.put("ETH", Integer.valueOf('\u00d0') << 16); // LATIN CAPITAL LETTER ETH
    builder.put("Ntilde", Integer.valueOf('\u00d1') << 16); // LATIN CAPITAL LETTER N WITH TILDE
    builder.put("Ograve", Integer.valueOf('\u00d2') << 16); // LATIN CAPITAL LETTER O WITH GRAVE
    builder.put("Oacute", Integer.valueOf('\u00d3') << 16); // LATIN CAPITAL LETTER O WITH ACUTE
    builder.put("Ocirc", Integer.valueOf('\u00d4') << 16); // LATIN CAPITAL LETTER O WITH CIRCUMFLEX
    builder.put("Otilde", Integer.valueOf('\u00d5') << 16); // LATIN CAPITAL LETTER O WITH TILDE
    builder.put("Ouml", Integer.valueOf('\u00d6') << 16); // LATIN CAPITAL LETTER O WITH DIAERESIS
    builder.put("times", Integer.valueOf('\u00d7') << 16); // MULTIPLICATION SIGN
    builder.put("Oslash", Integer.valueOf('\u00d8') << 16); // LATIN CAPITAL LETTER O WITH STROKE
    builder.put("Ugrave", Integer.valueOf('\u00d9') << 16); // LATIN CAPITAL LETTER U WITH GRAVE
    builder.put("Uacute", Integer.valueOf('\u00da') << 16); // LATIN CAPITAL LETTER U WITH ACUTE
    builder.put("Ucirc", Integer.valueOf('\u00db') << 16); // LATIN CAPITAL LETTER U WITH CIRCUMFLEX
    builder.put("Uuml", Integer.valueOf('\u00dc') << 16); // LATIN CAPITAL LETTER U WITH DIAERESIS
    builder.put("Yacute", Integer.valueOf('\u00dd') << 16); // LATIN CAPITAL LETTER Y WITH ACUTE
    builder.put("THORN", Integer.valueOf('\u00de') << 16); // LATIN CAPITAL LETTER THORN
    builder.put("szlig", Integer.valueOf('\u00df') << 16); // LATIN SMALL LETTER SHARP S
    builder.put("agrave", Integer.valueOf('\u00e0') << 16); // LATIN SMALL LETTER A WITH GRAVE
    builder.put("aacute", Integer.valueOf('\u00e1') << 16); // LATIN SMALL LETTER A WITH ACUTE
    builder.put("acirc", Integer.valueOf('\u00e2') << 16); // LATIN SMALL LETTER A WITH CIRCUMFLEX
    builder.put("atilde", Integer.valueOf('\u00e3') << 16); // LATIN SMALL LETTER A WITH TILDE
    builder.put("auml", Integer.valueOf('\u00e4') << 16); // LATIN SMALL LETTER A WITH DIAERESIS
    builder.put("aring", Integer.valueOf('\u00e5') << 16); // LATIN SMALL LETTER A WITH RING ABOVE
    builder.put("aelig", Integer.valueOf('\u00e6') << 16); // LATIN SMALL LETTER AE
    builder.put("ccedil", Integer.valueOf('\u00e7') << 16); // LATIN SMALL LETTER C WITH CEDILLA
    builder.put("egrave", Integer.valueOf('\u00e8') << 16); // LATIN SMALL LETTER E WITH GRAVE
    builder.put("eacute", Integer.valueOf('\u00e9') << 16); // LATIN SMALL LETTER E WITH ACUTE
    builder.put("ecirc", Integer.valueOf('\u00ea') << 16); // LATIN SMALL LETTER E WITH CIRCUMFLEX
    builder.put("euml", Integer.valueOf('\u00eb') << 16); // LATIN SMALL LETTER E WITH DIAERESIS
    builder.put("igrave", Integer.valueOf('\u00ec') << 16); // LATIN SMALL LETTER I WITH GRAVE
    builder.put("iacute", Integer.valueOf('\u00ed') << 16); // LATIN SMALL LETTER I WITH ACUTE
    builder.put("icirc", Integer.valueOf('\u00ee') << 16); // LATIN SMALL LETTER I WITH CIRCUMFLEX
    builder.put("iuml", Integer.valueOf('\u00ef') << 16); // LATIN SMALL LETTER I WITH DIAERESIS
    builder.put("eth", Integer.valueOf('\u00f0') << 16); // LATIN SMALL LETTER ETH
    builder.put("ntilde", Integer.valueOf('\u00f1') << 16); // LATIN SMALL LETTER N WITH TILDE
    builder.put("ograve", Integer.valueOf('\u00f2') << 16); // LATIN SMALL LETTER O WITH GRAVE
    builder.put("oacute", Integer.valueOf('\u00f3') << 16); // LATIN SMALL LETTER O WITH ACUTE
    builder.put("ocirc", Integer.valueOf('\u00f4') << 16); // LATIN SMALL LETTER O WITH CIRCUMFLEX
    builder.put("otilde", Integer.valueOf('\u00f5') << 16); // LATIN SMALL LETTER O WITH TILDE
    builder.put("ouml", Integer.valueOf('\u00f6') << 16); // LATIN SMALL LETTER O WITH DIAERESIS
    builder.put("divide", Integer.valueOf('\u00f7') << 16); // DIVISION SIGN
    builder.put("div", Integer.valueOf('\u00f7') << 16); // DIVISION SIGN
    builder.put("oslash", Integer.valueOf('\u00f8') << 16); // LATIN SMALL LETTER O WITH STROKE
    builder.put("ugrave", Integer.valueOf('\u00f9') << 16); // LATIN SMALL LETTER U WITH GRAVE
    builder.put("uacute", Integer.valueOf('\u00fa') << 16); // LATIN SMALL LETTER U WITH ACUTE
    builder.put("ucirc", Integer.valueOf('\u00fb') << 16); // LATIN SMALL LETTER U WITH CIRCUMFLEX
    builder.put("uuml", Integer.valueOf('\u00fc') << 16); // LATIN SMALL LETTER U WITH DIAERESIS
    builder.put("yacute", Integer.valueOf('\u00fd') << 16); // LATIN SMALL LETTER Y WITH ACUTE
    builder.put("thorn", Integer.valueOf('\u00fe') << 16); // LATIN SMALL LETTER THORN
    builder.put("yuml", Integer.valueOf('\u00ff') << 16); // LATIN SMALL LETTER Y WITH DIAERESIS

    // Latin Extended-A
    builder.put("Amacr", Integer.valueOf('\u0100') << 16); // LATIN CAPITAL LETTER A WITH MACRON
    builder.put("amacr", Integer.valueOf('\u0101') << 16); // LATIN SMALL LETTER A WITH MACRON
    builder.put("Abreve", Integer.valueOf('\u0102') << 16); // LATIN CAPITAL LETTER A WITH BREVE
    builder.put("abreve", Integer.valueOf('\u0103') << 16); // LATIN SMALL LETTER A WITH BREVE
    builder.put("Aogon", Integer.valueOf('\u0104') << 16); // LATIN CAPITAL LETTER A WITH OGONEK
    builder.put("aogon", Integer.valueOf('\u0105') << 16); // LATIN SMALL LETTER A WITH OGONEK
    builder.put("Cacute", Integer.valueOf('\u0106') << 16); // LATIN CAPITAL LETTER C WITH ACUTE
    builder.put("cacute", Integer.valueOf('\u0107') << 16); // LATIN SMALL LETTER C WITH ACUTE
    builder.put("Ccirc", Integer.valueOf('\u0108') << 16); // LATIN CAPITAL LETTER C WITH CIRCUMFLEX
    builder.put("ccirc", Integer.valueOf('\u0109') << 16); // LATIN SMALL LETTER C WITH CIRCUMFLEX
    builder.put("Cdot", Integer.valueOf('\u010a') << 16); // LATIN CAPITAL LETTER C WITH DOT ABOVE
    builder.put("cdot", Integer.valueOf('\u010b') << 16); // LATIN SMALL LETTER C WITH DOT ABOVE
    builder.put("Ccaron", Integer.valueOf('\u010c') << 16); // LATIN CAPITAL LETTER C WITH CARON
    builder.put("ccaron", Integer.valueOf('\u010d') << 16); // LATIN SMALL LETTER C WITH CARON
    builder.put("Dcaron", Integer.valueOf('\u010e') << 16); // LATIN CAPITAL LETTER D WITH CARON
    builder.put("dcaron", Integer.valueOf('\u010f') << 16); // LATIN SMALL LETTER D WITH CARON
    builder.put("Dstrok", Integer.valueOf('\u0110') << 16); // LATIN CAPITAL LETTER D WITH STROKE
    builder.put("dstrok", Integer.valueOf('\u0111') << 16); // LATIN SMALL LETTER D WITH STROKE
    builder.put("Emacr", Integer.valueOf('\u0112') << 16); // LATIN CAPITAL LETTER E WITH MACRON
    builder.put("emacr", Integer.valueOf('\u0113') << 16); // LATIN SMALL LETTER E WITH MACRON
    builder.put("Edot", Integer.valueOf('\u0116') << 16); // LATIN CAPITAL LETTER E WITH DOT ABOVE
    builder.put("edot", Integer.valueOf('\u0117') << 16); // LATIN SMALL LETTER E WITH DOT ABOVE
    builder.put("Eogon", Integer.valueOf('\u0118') << 16); // LATIN CAPITAL LETTER E WITH OGONEK
    builder.put("eogon", Integer.valueOf('\u0119') << 16); // LATIN SMALL LETTER E WITH OGONEK
    builder.put("Ecaron", Integer.valueOf('\u011a') << 16); // LATIN CAPITAL LETTER E WITH CARON
    builder.put("ecaron", Integer.valueOf('\u011b') << 16); // LATIN SMALL LETTER E WITH CARON
    builder.put("Gcirc", Integer.valueOf('\u011c') << 16); // LATIN CAPITAL LETTER G WITH CIRCUMFLEX
    builder.put("gcirc", Integer.valueOf('\u011d') << 16); // LATIN SMALL LETTER G WITH CIRCUMFLEX
    builder.put("Gbreve", Integer.valueOf('\u011e') << 16); // LATIN CAPITAL LETTER G WITH BREVE
    builder.put("gbreve", Integer.valueOf('\u011f') << 16); // LATIN SMALL LETTER G WITH BREVE
    builder.put("Gdot", Integer.valueOf('\u0120') << 16); // LATIN CAPITAL LETTER G WITH DOT ABOVE
    builder.put("gdot", Integer.valueOf('\u0121') << 16); // LATIN SMALL LETTER G WITH DOT ABOVE
    builder.put("Gcedil", Integer.valueOf('\u0122') << 16); // LATIN CAPITAL LETTER G WITH CEDILLA
    builder.put("Hcirc", Integer.valueOf('\u0124') << 16); // LATIN CAPITAL LETTER H WITH CIRCUMFLEX
    builder.put("hcirc", Integer.valueOf('\u0125') << 16); // LATIN SMALL LETTER H WITH CIRCUMFLEX
    builder.put("Hstrok", Integer.valueOf('\u0126') << 16); // LATIN CAPITAL LETTER H WITH STROKE
    builder.put("hstrok", Integer.valueOf('\u0127') << 16); // LATIN SMALL LETTER H WITH STROKE
    builder.put("Itilde", Integer.valueOf('\u0128') << 16); // LATIN CAPITAL LETTER I WITH TILDE
    builder.put("itilde", Integer.valueOf('\u0129') << 16); // LATIN SMALL LETTER I WITH TILDE
    builder.put("Imacr", Integer.valueOf('\u012a') << 16); // LATIN CAPITAL LETTER I WITH MACRON
    builder.put("imacr", Integer.valueOf('\u012b') << 16); // LATIN SMALL LETTER I WITH MACRON
    builder.put("Iogon", Integer.valueOf('\u012e') << 16); // LATIN CAPITAL LETTER I WITH OGONEK
    builder.put("iogon", Integer.valueOf('\u012f') << 16); // LATIN SMALL LETTER I WITH OGONEK
    builder.put("Idot", Integer.valueOf('\u0130') << 16); // LATIN CAPITAL LETTER I WITH DOT ABOVE
    builder.put("imath", Integer.valueOf('\u0131') << 16); // LATIN SMALL LETTER DOTLESS I
    builder.put("inodot", Integer.valueOf('\u0131') << 16); // LATIN SMALL LETTER DOTLESS I
    builder.put("IJlig", Integer.valueOf('\u0132') << 16); // LATIN CAPITAL LIGATURE IJ
    builder.put("ijlig", Integer.valueOf('\u0133') << 16); // LATIN SMALL LIGATURE IJ
    builder.put("Jcirc", Integer.valueOf('\u0134') << 16); // LATIN CAPITAL LETTER J WITH CIRCUMFLEX
    builder.put("jcirc", Integer.valueOf('\u0135') << 16); // LATIN SMALL LETTER J WITH CIRCUMFLEX
    builder.put("Kcedil", Integer.valueOf('\u0136') << 16); // LATIN CAPITAL LETTER K WITH CEDILLA
    builder.put("kcedil", Integer.valueOf('\u0137') << 16); // LATIN SMALL LETTER K WITH CEDILLA
    builder.put("kgreen", Integer.valueOf('\u0138') << 16); // LATIN SMALL LETTER KRA
    builder.put("Lacute", Integer.valueOf('\u0139') << 16); // LATIN CAPITAL LETTER L WITH ACUTE
    builder.put("lacute", Integer.valueOf('\u013a') << 16); // LATIN SMALL LETTER L WITH ACUTE
    builder.put("Lcedil", Integer.valueOf('\u013b') << 16); // LATIN CAPITAL LETTER L WITH CEDILLA
    builder.put("lcedil", Integer.valueOf('\u013c') << 16); // LATIN SMALL LETTER L WITH CEDILLA
    builder.put("Lcaron", Integer.valueOf('\u013d') << 16); // LATIN CAPITAL LETTER L WITH CARON
    builder.put("lcaron", Integer.valueOf('\u013e') << 16); // LATIN SMALL LETTER L WITH CARON
    builder.put("Lmidot", Integer.valueOf('\u013f') << 16); // LATIN CAPITAL LETTER L WITH MIDDLE DOT
    builder.put("lmidot", Integer.valueOf('\u0140') << 16); // LATIN SMALL LETTER L WITH MIDDLE DOT
    builder.put("Lstrok", Integer.valueOf('\u0141') << 16); // LATIN CAPITAL LETTER L WITH STROKE
    builder.put("lstrok", Integer.valueOf('\u0142') << 16); // LATIN SMALL LETTER L WITH STROKE
    builder.put("Nacute", Integer.valueOf('\u0143') << 16); // LATIN CAPITAL LETTER N WITH ACUTE
    builder.put("nacute", Integer.valueOf('\u0144') << 16); // LATIN SMALL LETTER N WITH ACUTE
    builder.put("Ncedil", Integer.valueOf('\u0145') << 16); // LATIN CAPITAL LETTER N WITH CEDILLA
    builder.put("ncedil", Integer.valueOf('\u0146') << 16); // LATIN SMALL LETTER N WITH CEDILLA
    builder.put("Ncaron", Integer.valueOf('\u0147') << 16); // LATIN CAPITAL LETTER N WITH CARON
    builder.put("ncaron", Integer.valueOf('\u0148') << 16); // LATIN SMALL LETTER N WITH CARON
    builder.put("napos", Integer.valueOf('\u0149') << 16); // LATIN SMALL LETTER N PRECEDED BY APOSTROPHE
    builder.put("ENG", Integer.valueOf('\u014a') << 16); // LATIN CAPITAL LETTER ENG
    builder.put("eng", Integer.valueOf('\u014b') << 16); // LATIN SMALL LETTER ENG
    builder.put("Omacr", Integer.valueOf('\u014c') << 16); // LATIN CAPITAL LETTER O WITH MACRON
    builder.put("omacr", Integer.valueOf('\u014d') << 16); // LATIN SMALL LETTER O WITH MACRON
    builder.put("Odblac", Integer.valueOf('\u0150') << 16); // LATIN CAPITAL LETTER O WITH DOUBLE ACUTE
    builder.put("odblac", Integer.valueOf('\u0151') << 16); // LATIN SMALL LETTER O WITH DOUBLE ACUTE
    builder.put("OElig", Integer.valueOf('\u0152') << 16); // LATIN CAPITAL LIGATURE OE
    builder.put("oelig", Integer.valueOf('\u0153') << 16); // LATIN SMALL LIGATURE OE
    builder.put("Racute", Integer.valueOf('\u0154') << 16); // LATIN CAPITAL LETTER R WITH ACUTE
    builder.put("racute", Integer.valueOf('\u0155') << 16); // LATIN SMALL LETTER R WITH ACUTE
    builder.put("Rcedil", Integer.valueOf('\u0156') << 16); // LATIN CAPITAL LETTER R WITH CEDILLA
    builder.put("rcedil", Integer.valueOf('\u0157') << 16); // LATIN SMALL LETTER R WITH CEDILLA
    builder.put("Rcaron", Integer.valueOf('\u0158') << 16); // LATIN CAPITAL LETTER R WITH CARON
    builder.put("rcaron", Integer.valueOf('\u0159') << 16); // LATIN SMALL LETTER R WITH CARON
    builder.put("Sacute", Integer.valueOf('\u015a') << 16); // LATIN CAPITAL LETTER S WITH ACUTE
    builder.put("sacute", Integer.valueOf('\u015b') << 16); // LATIN SMALL LETTER S WITH ACUTE
    builder.put("Scirc", Integer.valueOf('\u015c') << 16); // LATIN CAPITAL LETTER S WITH CIRCUMFLEX
    builder.put("scirc", Integer.valueOf('\u015d') << 16); // LATIN SMALL LETTER S WITH CIRCUMFLEX
    builder.put("Scedil", Integer.valueOf('\u015e') << 16); // LATIN CAPITAL LETTER S WITH CEDILLA
    builder.put("scedil", Integer.valueOf('\u015f') << 16); // LATIN SMALL LETTER S WITH CEDILLA
    builder.put("Scaron", Integer.valueOf('\u0160') << 16); // LATIN CAPITAL LETTER S WITH CARON
    builder.put("scaron", Integer.valueOf('\u0161') << 16); // LATIN SMALL LETTER S WITH CARON
    builder.put("Tcedil", Integer.valueOf('\u0162') << 16); // LATIN CAPITAL LETTER T WITH CEDILLA
    builder.put("tcedil", Integer.valueOf('\u0163') << 16); // LATIN SMALL LETTER T WITH CEDILLA
    builder.put("Tcaron", Integer.valueOf('\u0164') << 16); // LATIN CAPITAL LETTER T WITH CARON
    builder.put("tcaron", Integer.valueOf('\u0165') << 16); // LATIN SMALL LETTER T WITH CARON
    builder.put("Tstrok", Integer.valueOf('\u0166') << 16); // LATIN CAPITAL LETTER T WITH STROKE
    builder.put("tstrok", Integer.valueOf('\u0167') << 16); // LATIN SMALL LETTER T WITH STROKE
    builder.put("Utilde", Integer.valueOf('\u0168') << 16); // LATIN CAPITAL LETTER U WITH TILDE
    builder.put("utilde", Integer.valueOf('\u0169') << 16); // LATIN SMALL LETTER U WITH TILDE
    builder.put("Umacr", Integer.valueOf('\u016a') << 16); // LATIN CAPITAL LETTER U WITH MACRON
    builder.put("umacr", Integer.valueOf('\u016b') << 16); // LATIN SMALL LETTER U WITH MACRON
    builder.put("Ubreve", Integer.valueOf('\u016c') << 16); // LATIN CAPITAL LETTER U WITH BREVE
    builder.put("ubreve", Integer.valueOf('\u016d') << 16); // LATIN SMALL LETTER U WITH BREVE
    builder.put("Uring", Integer.valueOf('\u016e') << 16); // LATIN CAPITAL LETTER U WITH RING ABOVE
    builder.put("uring", Integer.valueOf('\u016f') << 16); // LATIN SMALL LETTER U WITH RING ABOVE
    builder.put("Udblac", Integer.valueOf('\u0170') << 16); // LATIN CAPITAL LETTER U WITH DOUBLE ACUTE
    builder.put("udblac", Integer.valueOf('\u0171') << 16); // LATIN SMALL LETTER U WITH DOUBLE ACUTE
    builder.put("Uogon", Integer.valueOf('\u0172') << 16); // LATIN CAPITAL LETTER U WITH OGONEK
    builder.put("uogon", Integer.valueOf('\u0173') << 16); // LATIN SMALL LETTER U WITH OGONEK
    builder.put("Wcirc", Integer.valueOf('\u0174') << 16); // LATIN CAPITAL LETTER W WITH CIRCUMFLEX
    builder.put("wcirc", Integer.valueOf('\u0175') << 16); // LATIN SMALL LETTER W WITH CIRCUMFLEX
    builder.put("Ycirc", Integer.valueOf('\u0176') << 16); // LATIN CAPITAL LETTER Y WITH CIRCUMFLEX
    builder.put("ycirc", Integer.valueOf('\u0177') << 16); // LATIN SMALL LETTER Y WITH CIRCUMFLEX
    builder.put("Yuml", Integer.valueOf('\u0178') << 16); // LATIN CAPITAL LETTER Y WITH DIAERESIS
    builder.put("Zacute", Integer.valueOf('\u0179') << 16); // LATIN CAPITAL LETTER Z WITH ACUTE
    builder.put("zacute", Integer.valueOf('\u017a') << 16); // LATIN SMALL LETTER Z WITH ACUTE
    builder.put("Zdot", Integer.valueOf('\u017b') << 16); // LATIN CAPITAL LETTER Z WITH DOT ABOVE
    builder.put("zdot", Integer.valueOf('\u017c') << 16); // LATIN SMALL LETTER Z WITH DOT ABOVE
    builder.put("Zcaron", Integer.valueOf('\u017d') << 16); // LATIN CAPITAL LETTER Z WITH CARON
    builder.put("zcaron", Integer.valueOf('\u017e') << 16); // LATIN SMALL LETTER Z WITH CARON

    // Latin Extended-B
    builder.put("fnof", Integer.valueOf('\u0192') << 16); // LATIN SMALL LETTER F WITH HOOK
    builder.put("imped", Integer.valueOf('\u01b5') << 16); // LATIN CAPITAL LETTER Z WITH STROKE
    builder.put("gacute", Integer.valueOf('\u01f5') << 16); // LATIN SMALL LETTER G WITH ACUTE
    builder.put("jmath", Integer.valueOf('\u0237') << 16); // LATIN SMALL LETTER DOTLESS J

    // Spacing Modifier Letters
    builder.put("circ", Integer.valueOf('\u02c6') << 16); // MODIFIER LETTER CIRCUMFLEX ACCENT
    builder.put("caron", Integer.valueOf('\u02c7') << 16); // CARON
    builder.put("Hacek", Integer.valueOf('\u02c7') << 16); // CARON
    builder.put("breve", Integer.valueOf('\u02d8') << 16); // BREVE
    builder.put("Breve", Integer.valueOf('\u02d8') << 16); // BREVE
    builder.put("dot", Integer.valueOf('\u02d9') << 16); // DOT ABOVE
    builder.put("DiacriticalDot", Integer.valueOf('\u02d9') << 16); // DOT ABOVE
    builder.put("ring", Integer.valueOf('\u02da') << 16); // RING ABOVE
    builder.put("ogon", Integer.valueOf('\u02db') << 16); // OGONEK
    builder.put("tilde", Integer.valueOf('\u02dc') << 16); // SMALL TILDE
    builder.put("DiacriticalTilde", Integer.valueOf('\u02dc') << 16); // SMALL TILDE
    builder.put("dblac", Integer.valueOf('\u02dd') << 16); // DOUBLE ACUTE ACCENT
    builder.put("DiacriticalDoubleAcute", Integer.valueOf('\u02dd') << 16); // DOUBLE ACUTE ACCENT

    // Combining Diacritical Marks
    builder.put("DownBreve", Integer.valueOf('\u0311') << 16); // COMBINING INVERTED BREVE
    builder.put("UnderBar", Integer.valueOf('\u0332') << 16); // COMBINING LOW LINE

    // Greek and Coptic
    builder.put("Alpha", Integer.valueOf('\u0391') << 16); // GREEK CAPITAL LETTER ALPHA
    builder.put("Beta", Integer.valueOf('\u0392') << 16); // GREEK CAPITAL LETTER BETA
    builder.put("Gamma", Integer.valueOf('\u0393') << 16); // GREEK CAPITAL LETTER GAMMA
    builder.put("Delta", Integer.valueOf('\u0394') << 16); // GREEK CAPITAL LETTER DELTA
    builder.put("Epsilon", Integer.valueOf('\u0395') << 16); // GREEK CAPITAL LETTER EPSILON
    builder.put("Zeta", Integer.valueOf('\u0396') << 16); // GREEK CAPITAL LETTER ZETA
    builder.put("Eta", Integer.valueOf('\u0397') << 16); // GREEK CAPITAL LETTER ETA
    builder.put("Theta", Integer.valueOf('\u0398') << 16); // GREEK CAPITAL LETTER THETA
    builder.put("Iota", Integer.valueOf('\u0399') << 16); // GREEK CAPITAL LETTER IOTA
    builder.put("Kappa", Integer.valueOf('\u039a') << 16); // GREEK CAPITAL LETTER KAPPA
    builder.put("Lambda", Integer.valueOf('\u039b') << 16); // GREEK CAPITAL LETTER LAMDA
    builder.put("Mu", Integer.valueOf('\u039c') << 16); // GREEK CAPITAL LETTER MU
    builder.put("Nu", Integer.valueOf('\u039d') << 16); // GREEK CAPITAL LETTER NU
    builder.put("Xi", Integer.valueOf('\u039e') << 16); // GREEK CAPITAL LETTER XI
    builder.put("Omicron", Integer.valueOf('\u039f') << 16); // GREEK CAPITAL LETTER OMICRON
    builder.put("Pi", Integer.valueOf('\u03a0') << 16); // GREEK CAPITAL LETTER PI
    builder.put("Rho", Integer.valueOf('\u03a1') << 16); // GREEK CAPITAL LETTER RHO
    builder.put("Sigma", Integer.valueOf('\u03a3') << 16); // GREEK CAPITAL LETTER SIGMA
    builder.put("Tau", Integer.valueOf('\u03a4') << 16); // GREEK CAPITAL LETTER TAU
    builder.put("Upsilon", Integer.valueOf('\u03a5') << 16); // GREEK CAPITAL LETTER UPSILON
    builder.put("Phi", Integer.valueOf('\u03a6') << 16); // GREEK CAPITAL LETTER PHI
    builder.put("Chi", Integer.valueOf('\u03a7') << 16); // GREEK CAPITAL LETTER CHI
    builder.put("Psi", Integer.valueOf('\u03a8') << 16); // GREEK CAPITAL LETTER PSI
    builder.put("Omega", Integer.valueOf('\u03a9') << 16); // GREEK CAPITAL LETTER OMEGA
    builder.put("alpha", Integer.valueOf('\u03b1') << 16); // GREEK SMALL LETTER ALPHA
    builder.put("beta", Integer.valueOf('\u03b2') << 16); // GREEK SMALL LETTER BETA
    builder.put("gamma", Integer.valueOf('\u03b3') << 16); // GREEK SMALL LETTER GAMMA
    builder.put("delta", Integer.valueOf('\u03b4') << 16); // GREEK SMALL LETTER DELTA
    builder.put("epsiv", Integer.valueOf('\u03b5') << 16); // GREEK SMALL LETTER EPSILON
    builder.put("varepsilon", Integer.valueOf('\u03b5') << 16); // GREEK SMALL LETTER EPSILON
    builder.put("epsilon", Integer.valueOf('\u03b5') << 16); // GREEK SMALL LETTER EPSILON
    builder.put("zeta", Integer.valueOf('\u03b6') << 16); // GREEK SMALL LETTER ZETA
    builder.put("eta", Integer.valueOf('\u03b7') << 16); // GREEK SMALL LETTER ETA
    builder.put("theta", Integer.valueOf('\u03b8') << 16); // GREEK SMALL LETTER THETA
    builder.put("iota", Integer.valueOf('\u03b9') << 16); // GREEK SMALL LETTER IOTA
    builder.put("kappa", Integer.valueOf('\u03ba') << 16); // GREEK SMALL LETTER KAPPA
    builder.put("lambda", Integer.valueOf('\u03bb') << 16); // GREEK SMALL LETTER LAMDA
    builder.put("mu", Integer.valueOf('\u03bc') << 16); // GREEK SMALL LETTER MU
    builder.put("nu", Integer.valueOf('\u03bd') << 16); // GREEK SMALL LETTER NU
    builder.put("xi", Integer.valueOf('\u03be') << 16); // GREEK SMALL LETTER XI
    builder.put("omicron", Integer.valueOf('\u03bf') << 16); // GREEK SMALL LETTER OMICRON
    builder.put("pi", Integer.valueOf('\u03c0') << 16); // GREEK SMALL LETTER PI
    builder.put("rho", Integer.valueOf('\u03c1') << 16); // GREEK SMALL LETTER RHO
    builder.put("sigmav", Integer.valueOf('\u03c2') << 16); // GREEK SMALL LETTER FINAL SIGMA
    builder.put("varsigma", Integer.valueOf('\u03c2') << 16); // GREEK SMALL LETTER FINAL SIGMA
    builder.put("sigmaf", Integer.valueOf('\u03c2') << 16); // GREEK SMALL LETTER FINAL SIGMA
    builder.put("sigma", Integer.valueOf('\u03c3') << 16); // GREEK SMALL LETTER SIGMA
    builder.put("tau", Integer.valueOf('\u03c4') << 16); // GREEK SMALL LETTER TAU
    builder.put("upsi", Integer.valueOf('\u03c5') << 16); // GREEK SMALL LETTER UPSILON
    builder.put("upsilon", Integer.valueOf('\u03c5') << 16); // GREEK SMALL LETTER UPSILON
    builder.put("phi", Integer.valueOf('\u03c6') << 16); // GREEK SMALL LETTER PHI
    builder.put("phiv", Integer.valueOf('\u03c6') << 16); // GREEK SMALL LETTER PHI
    builder.put("varphi", Integer.valueOf('\u03c6') << 16); // GREEK SMALL LETTER PHI
    builder.put("chi", Integer.valueOf('\u03c7') << 16); // GREEK SMALL LETTER CHI
    builder.put("psi", Integer.valueOf('\u03c8') << 16); // GREEK SMALL LETTER PSI
    builder.put("omega", Integer.valueOf('\u03c9') << 16); // GREEK SMALL LETTER OMEGA
    builder.put("thetav", Integer.valueOf('\u03d1') << 16); // GREEK THETA SYMBOL
    builder.put("vartheta", Integer.valueOf('\u03d1') << 16); // GREEK THETA SYMBOL
    builder.put("thetasym", Integer.valueOf('\u03d1') << 16); // GREEK THETA SYMBOL
    builder.put("Upsi", Integer.valueOf('\u03d2') << 16); // GREEK UPSILON WITH HOOK SYMBOL
    builder.put("upsih", Integer.valueOf('\u03d2') << 16); // GREEK UPSILON WITH HOOK SYMBOL
    builder.put("straightphi", Integer.valueOf('\u03d5') << 16); // GREEK PHI SYMBOL
    builder.put("piv", Integer.valueOf('\u03d6') << 16); // GREEK PI SYMBOL
    builder.put("varpi", Integer.valueOf('\u03d6') << 16); // GREEK PI SYMBOL
    builder.put("Gammad", Integer.valueOf('\u03dc') << 16); // GREEK LETTER DIGAMMA
    builder.put("gammad", Integer.valueOf('\u03dd') << 16); // GREEK SMALL LETTER DIGAMMA
    builder.put("digamma", Integer.valueOf('\u03dd') << 16); // GREEK SMALL LETTER DIGAMMA
    builder.put("kappav", Integer.valueOf('\u03f0') << 16); // GREEK KAPPA SYMBOL
    builder.put("varkappa", Integer.valueOf('\u03f0') << 16); // GREEK KAPPA SYMBOL
    builder.put("rhov", Integer.valueOf('\u03f1') << 16); // GREEK RHO SYMBOL
    builder.put("varrho", Integer.valueOf('\u03f1') << 16); // GREEK RHO SYMBOL
    builder.put("epsi", Integer.valueOf('\u03f5') << 16); // GREEK LUNATE EPSILON SYMBOL
    builder.put("straightepsilon", Integer.valueOf('\u03f5') << 16); // GREEK LUNATE EPSILON SYMBOL
    builder.put("bepsi", Integer.valueOf('\u03f6') << 16); // GREEK REVERSED LUNATE EPSILON SYMBOL
    builder.put("backepsilon", Integer.valueOf('\u03f6') << 16); // GREEK REVERSED LUNATE EPSILON SYMBOL

    // Cyrillic
    builder.put("IOcy", Integer.valueOf('\u0401') << 16); // CYRILLIC CAPITAL LETTER IO
    builder.put("DJcy", Integer.valueOf('\u0402') << 16); // CYRILLIC CAPITAL LETTER DJE
    builder.put("GJcy", Integer.valueOf('\u0403') << 16); // CYRILLIC CAPITAL LETTER GJE
    builder.put("Jukcy", Integer.valueOf('\u0404') << 16); // CYRILLIC CAPITAL LETTER UKRAINIAN IE
    builder.put("DScy", Integer.valueOf('\u0405') << 16); // CYRILLIC CAPITAL LETTER DZE
    builder.put("Iukcy", Integer.valueOf('\u0406') << 16); // CYRILLIC CAPITAL LETTER BYELORUSSIAN-UKRAINIAN I
    builder.put("YIcy", Integer.valueOf('\u0407') << 16); // CYRILLIC CAPITAL LETTER YI
    builder.put("Jsercy", Integer.valueOf('\u0408') << 16); // CYRILLIC CAPITAL LETTER JE
    builder.put("LJcy", Integer.valueOf('\u0409') << 16); // CYRILLIC CAPITAL LETTER LJE
    builder.put("NJcy", Integer.valueOf('\u040a') << 16); // CYRILLIC CAPITAL LETTER NJE
    builder.put("TSHcy", Integer.valueOf('\u040b') << 16); // CYRILLIC CAPITAL LETTER TSHE
    builder.put("KJcy", Integer.valueOf('\u040c') << 16); // CYRILLIC CAPITAL LETTER KJE
    builder.put("Ubrcy", Integer.valueOf('\u040e') << 16); // CYRILLIC CAPITAL LETTER SHORT U
    builder.put("DZcy", Integer.valueOf('\u040f') << 16); // CYRILLIC CAPITAL LETTER DZHE
    builder.put("Acy", Integer.valueOf('\u0410') << 16); // CYRILLIC CAPITAL LETTER A
    builder.put("Bcy", Integer.valueOf('\u0411') << 16); // CYRILLIC CAPITAL LETTER BE
    builder.put("Vcy", Integer.valueOf('\u0412') << 16); // CYRILLIC CAPITAL LETTER VE
    builder.put("Gcy", Integer.valueOf('\u0413') << 16); // CYRILLIC CAPITAL LETTER GHE
    builder.put("Dcy", Integer.valueOf('\u0414') << 16); // CYRILLIC CAPITAL LETTER DE
    builder.put("IEcy", Integer.valueOf('\u0415') << 16); // CYRILLIC CAPITAL LETTER IE
    builder.put("ZHcy", Integer.valueOf('\u0416') << 16); // CYRILLIC CAPITAL LETTER ZHE
    builder.put("Zcy", Integer.valueOf('\u0417') << 16); // CYRILLIC CAPITAL LETTER ZE
    builder.put("Icy", Integer.valueOf('\u0418') << 16); // CYRILLIC CAPITAL LETTER I
    builder.put("Jcy", Integer.valueOf('\u0419') << 16); // CYRILLIC CAPITAL LETTER SHORT I
    builder.put("Kcy", Integer.valueOf('\u041a') << 16); // CYRILLIC CAPITAL LETTER KA
    builder.put("Lcy", Integer.valueOf('\u041b') << 16); // CYRILLIC CAPITAL LETTER EL
    builder.put("Mcy", Integer.valueOf('\u041c') << 16); // CYRILLIC CAPITAL LETTER EM
    builder.put("Ncy", Integer.valueOf('\u041d') << 16); // CYRILLIC CAPITAL LETTER EN
    builder.put("Ocy", Integer.valueOf('\u041e') << 16); // CYRILLIC CAPITAL LETTER O
    builder.put("Pcy", Integer.valueOf('\u041f') << 16); // CYRILLIC CAPITAL LETTER PE
    builder.put("Rcy", Integer.valueOf('\u0420') << 16); // CYRILLIC CAPITAL LETTER ER
    builder.put("Scy", Integer.valueOf('\u0421') << 16); // CYRILLIC CAPITAL LETTER ES
    builder.put("Tcy", Integer.valueOf('\u0422') << 16); // CYRILLIC CAPITAL LETTER TE
    builder.put("Ucy", Integer.valueOf('\u0423') << 16); // CYRILLIC CAPITAL LETTER U
    builder.put("Fcy", Integer.valueOf('\u0424') << 16); // CYRILLIC CAPITAL LETTER EF
    builder.put("KHcy", Integer.valueOf('\u0425') << 16); // CYRILLIC CAPITAL LETTER HA
    builder.put("TScy", Integer.valueOf('\u0426') << 16); // CYRILLIC CAPITAL LETTER TSE
    builder.put("CHcy", Integer.valueOf('\u0427') << 16); // CYRILLIC CAPITAL LETTER CHE
    builder.put("SHcy", Integer.valueOf('\u0428') << 16); // CYRILLIC CAPITAL LETTER SHA
    builder.put("SHCHcy", Integer.valueOf('\u0429') << 16); // CYRILLIC CAPITAL LETTER SHCHA
    builder.put("HARDcy", Integer.valueOf('\u042a') << 16); // CYRILLIC CAPITAL LETTER HARD SIGN
    builder.put("Ycy", Integer.valueOf('\u042b') << 16); // CYRILLIC CAPITAL LETTER YERU
    builder.put("SOFTcy", Integer.valueOf('\u042c') << 16); // CYRILLIC CAPITAL LETTER SOFT SIGN
    builder.put("Ecy", Integer.valueOf('\u042d') << 16); // CYRILLIC CAPITAL LETTER E
    builder.put("YUcy", Integer.valueOf('\u042e') << 16); // CYRILLIC CAPITAL LETTER YU
    builder.put("YAcy", Integer.valueOf('\u042f') << 16); // CYRILLIC CAPITAL LETTER YA
    builder.put("acy", Integer.valueOf('\u0430') << 16); // CYRILLIC SMALL LETTER A
    builder.put("bcy", Integer.valueOf('\u0431') << 16); // CYRILLIC SMALL LETTER BE
    builder.put("vcy", Integer.valueOf('\u0432') << 16); // CYRILLIC SMALL LETTER VE
    builder.put("gcy", Integer.valueOf('\u0433') << 16); // CYRILLIC SMALL LETTER GHE
    builder.put("dcy", Integer.valueOf('\u0434') << 16); // CYRILLIC SMALL LETTER DE
    builder.put("iecy", Integer.valueOf('\u0435') << 16); // CYRILLIC SMALL LETTER IE
    builder.put("zhcy", Integer.valueOf('\u0436') << 16); // CYRILLIC SMALL LETTER ZHE
    builder.put("zcy", Integer.valueOf('\u0437') << 16); // CYRILLIC SMALL LETTER ZE
    builder.put("icy", Integer.valueOf('\u0438') << 16); // CYRILLIC SMALL LETTER I
    builder.put("jcy", Integer.valueOf('\u0439') << 16); // CYRILLIC SMALL LETTER SHORT I
    builder.put("kcy", Integer.valueOf('\u043a') << 16); // CYRILLIC SMALL LETTER KA
    builder.put("lcy", Integer.valueOf('\u043b') << 16); // CYRILLIC SMALL LETTER EL
    builder.put("mcy", Integer.valueOf('\u043c') << 16); // CYRILLIC SMALL LETTER EM
    builder.put("ncy", Integer.valueOf('\u043d') << 16); // CYRILLIC SMALL LETTER EN
    builder.put("ocy", Integer.valueOf('\u043e') << 16); // CYRILLIC SMALL LETTER O
    builder.put("pcy", Integer.valueOf('\u043f') << 16); // CYRILLIC SMALL LETTER PE
    builder.put("rcy", Integer.valueOf('\u0440') << 16); // CYRILLIC SMALL LETTER ER
    builder.put("scy", Integer.valueOf('\u0441') << 16); // CYRILLIC SMALL LETTER ES
    builder.put("tcy", Integer.valueOf('\u0442') << 16); // CYRILLIC SMALL LETTER TE
    builder.put("ucy", Integer.valueOf('\u0443') << 16); // CYRILLIC SMALL LETTER U
    builder.put("fcy", Integer.valueOf('\u0444') << 16); // CYRILLIC SMALL LETTER EF
    builder.put("khcy", Integer.valueOf('\u0445') << 16); // CYRILLIC SMALL LETTER HA
    builder.put("tscy", Integer.valueOf('\u0446') << 16); // CYRILLIC SMALL LETTER TSE
    builder.put("chcy", Integer.valueOf('\u0447') << 16); // CYRILLIC SMALL LETTER CHE
    builder.put("shcy", Integer.valueOf('\u0448') << 16); // CYRILLIC SMALL LETTER SHA
    builder.put("shchcy", Integer.valueOf('\u0449') << 16); // CYRILLIC SMALL LETTER SHCHA
    builder.put("hardcy", Integer.valueOf('\u044a') << 16); // CYRILLIC SMALL LETTER HARD SIGN
    builder.put("ycy", Integer.valueOf('\u044b') << 16); // CYRILLIC SMALL LETTER YERU
    builder.put("softcy", Integer.valueOf('\u044c') << 16); // CYRILLIC SMALL LETTER SOFT SIGN
    builder.put("ecy", Integer.valueOf('\u044d') << 16); // CYRILLIC SMALL LETTER E
    builder.put("yucy", Integer.valueOf('\u044e') << 16); // CYRILLIC SMALL LETTER YU
    builder.put("yacy", Integer.valueOf('\u044f') << 16); // CYRILLIC SMALL LETTER YA
    builder.put("iocy", Integer.valueOf('\u0451') << 16); // CYRILLIC SMALL LETTER IO
    builder.put("djcy", Integer.valueOf('\u0452') << 16); // CYRILLIC SMALL LETTER DJE
    builder.put("gjcy", Integer.valueOf('\u0453') << 16); // CYRILLIC SMALL LETTER GJE
    builder.put("jukcy", Integer.valueOf('\u0454') << 16); // CYRILLIC SMALL LETTER UKRAINIAN IE
    builder.put("dscy", Integer.valueOf('\u0455') << 16); // CYRILLIC SMALL LETTER DZE
    builder.put("iukcy", Integer.valueOf('\u0456') << 16); // CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I
    builder.put("yicy", Integer.valueOf('\u0457') << 16); // CYRILLIC SMALL LETTER YI
    builder.put("jsercy", Integer.valueOf('\u0458') << 16); // CYRILLIC SMALL LETTER JE
    builder.put("ljcy", Integer.valueOf('\u0459') << 16); // CYRILLIC SMALL LETTER LJE
    builder.put("njcy", Integer.valueOf('\u045a') << 16); // CYRILLIC SMALL LETTER NJE
    builder.put("tshcy", Integer.valueOf('\u045b') << 16); // CYRILLIC SMALL LETTER TSHE
    builder.put("kjcy", Integer.valueOf('\u045c') << 16); // CYRILLIC SMALL LETTER KJE
    builder.put("ubrcy", Integer.valueOf('\u045e') << 16); // CYRILLIC SMALL LETTER SHORT U
    builder.put("dzcy", Integer.valueOf('\u045f') << 16); // CYRILLIC SMALL LETTER DZHE

    // General Punctuation
    builder.put("ensp", Integer.valueOf('\u2002') << 16); // EN SPACE
    builder.put("emsp", Integer.valueOf('\u2003') << 16); // EM SPACE
    builder.put("emsp13", Integer.valueOf('\u2004') << 16); // THREE-PER-EM SPACE
    builder.put("emsp14", Integer.valueOf('\u2005') << 16); // FOUR-PER-EM SPACE
    builder.put("numsp", Integer.valueOf('\u2007') << 16); // FIGURE SPACE
    builder.put("puncsp", Integer.valueOf('\u2008') << 16); // PUNCTUATION SPACE
    builder.put("thinsp", Integer.valueOf('\u2009') << 16); // THIN SPACE
    builder.put("ThinSpace", Integer.valueOf('\u2009') << 16); // THIN SPACE
    builder.put("hairsp", Integer.valueOf('\u200a') << 16); // HAIR SPACE
    builder.put("VeryThinSpace", Integer.valueOf('\u200a') << 16); // HAIR SPACE
    builder.put("ZeroWidthSpace", Integer.valueOf('\u200b') << 16); // ZERO WIDTH SPACE
    builder.put("NegativeVeryThinSpace", Integer.valueOf('\u200b') << 16); // ZERO WIDTH SPACE
    builder.put("NegativeThinSpace", Integer.valueOf('\u200b') << 16); // ZERO WIDTH SPACE
    builder.put("NegativeMediumSpace", Integer.valueOf('\u200b') << 16); // ZERO WIDTH SPACE
    builder.put("NegativeThickSpace", Integer.valueOf('\u200b') << 16); // ZERO WIDTH SPACE
    builder.put("zwnj", Integer.valueOf('\u200c') << 16); // ZERO WIDTH NON-JOINER
    builder.put("zwj", Integer.valueOf('\u200d') << 16); // ZERO WIDTH JOINER
    builder.put("lrm", Integer.valueOf('\u200e') << 16); // LEFT-TO-RIGHT MARK
    builder.put("rlm", Integer.valueOf('\u200f') << 16); // RIGHT-TO-LEFT MARK
    builder.put("hyphen", Integer.valueOf('\u2010') << 16); // HYPHEN
    builder.put("dash", Integer.valueOf('\u2010') << 16); // HYPHEN
    builder.put("ndash", Integer.valueOf('\u2013') << 16); // EN DASH
    builder.put("mdash", Integer.valueOf('\u2014') << 16); // EM DASH
    builder.put("horbar", Integer.valueOf('\u2015') << 16); // HORIZONTAL BAR
    builder.put("Verbar", Integer.valueOf('\u2016') << 16); // DOUBLE VERTICAL LINE
    builder.put("Vert", Integer.valueOf('\u2016') << 16); // DOUBLE VERTICAL LINE
    builder.put("lsquo", Integer.valueOf('\u2018') << 16); // LEFT SINGLE QUOTATION MARK
    builder.put("OpenCurlyQuote", Integer.valueOf('\u2018') << 16); // LEFT SINGLE QUOTATION MARK
    builder.put("rsquo", Integer.valueOf('\u2019') << 16); // RIGHT SINGLE QUOTATION MARK
    builder.put("rsquor", Integer.valueOf('\u2019') << 16); // RIGHT SINGLE QUOTATION MARK
    builder.put("CloseCurlyQuote", Integer.valueOf('\u2019') << 16); // RIGHT SINGLE QUOTATION MARK
    builder.put("lsquor", Integer.valueOf('\u201a') << 16); // SINGLE LOW-9 QUOTATION MARK
    builder.put("sbquo", Integer.valueOf('\u201a') << 16); // SINGLE LOW-9 QUOTATION MARK
    builder.put("ldquo", Integer.valueOf('\u201c') << 16); // LEFT DOUBLE QUOTATION MARK
    builder.put("OpenCurlyDoubleQuote", Integer.valueOf('\u201c') << 16); // LEFT DOUBLE QUOTATION MARK
    builder.put("rdquo", Integer.valueOf('\u201d') << 16); // RIGHT DOUBLE QUOTATION MARK
    builder.put("rdquor", Integer.valueOf('\u201d') << 16); // RIGHT DOUBLE QUOTATION MARK
    builder.put("CloseCurlyDoubleQuote", Integer.valueOf('\u201d') << 16); // RIGHT DOUBLE QUOTATION MARK
    builder.put("ldquor", Integer.valueOf('\u201e') << 16); // DOUBLE LOW-9 QUOTATION MARK
    builder.put("bdquo", Integer.valueOf('\u201e') << 16); // DOUBLE LOW-9 QUOTATION MARK
    builder.put("dagger", Integer.valueOf('\u2020') << 16); // DAGGER
    builder.put("Dagger", Integer.valueOf('\u2021') << 16); // DOUBLE DAGGER
    builder.put("ddagger", Integer.valueOf('\u2021') << 16); // DOUBLE DAGGER
    builder.put("bull", Integer.valueOf('\u2022') << 16); // BULLET
    builder.put("bullet", Integer.valueOf('\u2022') << 16); // BULLET
    builder.put("nldr", Integer.valueOf('\u2025') << 16); // TWO DOT LEADER
    builder.put("hellip", Integer.valueOf('\u2026') << 16); // HORIZONTAL ELLIPSIS
    builder.put("mldr", Integer.valueOf('\u2026') << 16); // HORIZONTAL ELLIPSIS
    builder.put("permil", Integer.valueOf('\u2030') << 16); // PER MILLE SIGN
    builder.put("pertenk", Integer.valueOf('\u2031') << 16); // PER TEN THOUSAND SIGN
    builder.put("prime", Integer.valueOf('\u2032') << 16); // PRIME
    builder.put("Prime", Integer.valueOf('\u2033') << 16); // DOUBLE PRIME
    builder.put("tprime", Integer.valueOf('\u2034') << 16); // TRIPLE PRIME
    builder.put("bprime", Integer.valueOf('\u2035') << 16); // REVERSED PRIME
    builder.put("backprime", Integer.valueOf('\u2035') << 16); // REVERSED PRIME
    builder.put("lsaquo", Integer.valueOf('\u2039') << 16); // SINGLE LEFT-POINTING ANGLE QUOTATION MARK
    builder.put("rsaquo", Integer.valueOf('\u203a') << 16); // SINGLE RIGHT-POINTING ANGLE QUOTATION MARK
    builder.put("oline", Integer.valueOf('\u203e') << 16); // OVERLINE
    builder.put("caret", Integer.valueOf('\u2041') << 16); // CARET INSERTION POINT
    builder.put("hybull", Integer.valueOf('\u2043') << 16); // HYPHEN BULLET
    builder.put("frasl", Integer.valueOf('\u2044') << 16); // FRACTION SLASH
    builder.put("bsemi", Integer.valueOf('\u204f') << 16); // REVERSED SEMICOLON
    builder.put("qprime", Integer.valueOf('\u2057') << 16); // QUADRUPLE PRIME
    builder.put("MediumSpace", Integer.valueOf('\u205f') << 16); // MEDIUM MATHEMATICAL SPACE
    builder.put("NoBreak", Integer.valueOf('\u2060') << 16); // WORD JOINER
    builder.put("ApplyFunction", Integer.valueOf('\u2061') << 16); // FUNCTION APPLICATION
    builder.put("af", Integer.valueOf('\u2061') << 16); // FUNCTION APPLICATION
    builder.put("InvisibleTimes", Integer.valueOf('\u2062') << 16); // INVISIBLE TIMES
    builder.put("it", Integer.valueOf('\u2062') << 16); // INVISIBLE TIMES
    builder.put("InvisibleComma", Integer.valueOf('\u2063') << 16); // INVISIBLE SEPARATOR
    builder.put("ic", Integer.valueOf('\u2063') << 16); // INVISIBLE SEPARATOR

    // Currency Symbols
    builder.put("euro", Integer.valueOf('\u20ac') << 16); // EURO SIGN

    // Combining Diacritical Marks for Symbols
    builder.put("tdot", Integer.valueOf('\u20db') << 16); // COMBINING THREE DOTS ABOVE
    builder.put("TripleDot", Integer.valueOf('\u20db') << 16); // COMBINING THREE DOTS ABOVE
    builder.put("DotDot", Integer.valueOf('\u20dc') << 16); // COMBINING FOUR DOTS ABOVE

    // Letterlike Symbols
    builder.put("Copf", Integer.valueOf('\u2102') << 16); // DOUBLE-STRUCK CAPITAL C
    builder.put("complexes", Integer.valueOf('\u2102') << 16); // DOUBLE-STRUCK CAPITAL C
    builder.put("incare", Integer.valueOf('\u2105') << 16); // CARE OF
    builder.put("gscr", Integer.valueOf('\u210a') << 16); // SCRIPT SMALL G
    builder.put("hamilt", Integer.valueOf('\u210b') << 16); // SCRIPT CAPITAL H
    builder.put("HilbertSpace", Integer.valueOf('\u210b') << 16); // SCRIPT CAPITAL H
    builder.put("Hscr", Integer.valueOf('\u210b') << 16); // SCRIPT CAPITAL H
    builder.put("Hfr", Integer.valueOf('\u210c') << 16); // BLACK-LETTER CAPITAL H
    builder.put("Poincareplane", Integer.valueOf('\u210c') << 16); // BLACK-LETTER CAPITAL H
    builder.put("quaternions", Integer.valueOf('\u210d') << 16); // DOUBLE-STRUCK CAPITAL H
    builder.put("Hopf", Integer.valueOf('\u210d') << 16); // DOUBLE-STRUCK CAPITAL H
    builder.put("planckh", Integer.valueOf('\u210e') << 16); // PLANCK CONSTANT
    builder.put("planck", Integer.valueOf('\u210f') << 16); // PLANCK CONSTANT OVER TWO PI
    builder.put("hbar", Integer.valueOf('\u210f') << 16); // PLANCK CONSTANT OVER TWO PI
    builder.put("plankv", Integer.valueOf('\u210f') << 16); // PLANCK CONSTANT OVER TWO PI
    builder.put("hslash", Integer.valueOf('\u210f') << 16); // PLANCK CONSTANT OVER TWO PI
    builder.put("Iscr", Integer.valueOf('\u2110') << 16); // SCRIPT CAPITAL I
    builder.put("imagline", Integer.valueOf('\u2110') << 16); // SCRIPT CAPITAL I
    builder.put("image", Integer.valueOf('\u2111') << 16); // BLACK-LETTER CAPITAL I
    builder.put("Im", Integer.valueOf('\u2111') << 16); // BLACK-LETTER CAPITAL I
    builder.put("imagpart", Integer.valueOf('\u2111') << 16); // BLACK-LETTER CAPITAL I
    builder.put("Ifr", Integer.valueOf('\u2111') << 16); // BLACK-LETTER CAPITAL I
    builder.put("Lscr", Integer.valueOf('\u2112') << 16); // SCRIPT CAPITAL L
    builder.put("lagran", Integer.valueOf('\u2112') << 16); // SCRIPT CAPITAL L
    builder.put("Laplacetrf", Integer.valueOf('\u2112') << 16); // SCRIPT CAPITAL L
    builder.put("ell", Integer.valueOf('\u2113') << 16); // SCRIPT SMALL L
    builder.put("Nopf", Integer.valueOf('\u2115') << 16); // DOUBLE-STRUCK CAPITAL N
    builder.put("naturals", Integer.valueOf('\u2115') << 16); // DOUBLE-STRUCK CAPITAL N
    builder.put("numero", Integer.valueOf('\u2116') << 16); // NUMERO SIGN
    builder.put("copysr", Integer.valueOf('\u2117') << 16); // SOUND RECORDING COPYRIGHT
    builder.put("weierp", Integer.valueOf('\u2118') << 16); // SCRIPT CAPITAL P
    builder.put("wp", Integer.valueOf('\u2118') << 16); // SCRIPT CAPITAL P
    builder.put("Popf", Integer.valueOf('\u2119') << 16); // DOUBLE-STRUCK CAPITAL P
    builder.put("primes", Integer.valueOf('\u2119') << 16); // DOUBLE-STRUCK CAPITAL P
    builder.put("rationals", Integer.valueOf('\u211a') << 16); // DOUBLE-STRUCK CAPITAL Q
    builder.put("Qopf", Integer.valueOf('\u211a') << 16); // DOUBLE-STRUCK CAPITAL Q
    builder.put("Rscr", Integer.valueOf('\u211b') << 16); // SCRIPT CAPITAL R
    builder.put("realine", Integer.valueOf('\u211b') << 16); // SCRIPT CAPITAL R
    builder.put("real", Integer.valueOf('\u211c') << 16); // BLACK-LETTER CAPITAL R
    builder.put("Re", Integer.valueOf('\u211c') << 16); // BLACK-LETTER CAPITAL R
    builder.put("realpart", Integer.valueOf('\u211c') << 16); // BLACK-LETTER CAPITAL R
    builder.put("Rfr", Integer.valueOf('\u211c') << 16); // BLACK-LETTER CAPITAL R
    builder.put("reals", Integer.valueOf('\u211d') << 16); // DOUBLE-STRUCK CAPITAL R
    builder.put("Ropf", Integer.valueOf('\u211d') << 16); // DOUBLE-STRUCK CAPITAL R
    builder.put("rx", Integer.valueOf('\u211e') << 16); // PRESCRIPTION TAKE
    builder.put("trade", Integer.valueOf('\u2122') << 16); // TRADE MARK SIGN
    builder.put("TRADE", Integer.valueOf('\u2122') << 16); // TRADE MARK SIGN
    builder.put("integers", Integer.valueOf('\u2124') << 16); // DOUBLE-STRUCK CAPITAL Z
    builder.put("Zopf", Integer.valueOf('\u2124') << 16); // DOUBLE-STRUCK CAPITAL Z
    builder.put("ohm", Integer.valueOf('\u2126') << 16); // OHM SIGN
    builder.put("mho", Integer.valueOf('\u2127') << 16); // INVERTED OHM SIGN
    builder.put("Zfr", Integer.valueOf('\u2128') << 16); // BLACK-LETTER CAPITAL Z
    builder.put("zeetrf", Integer.valueOf('\u2128') << 16); // BLACK-LETTER CAPITAL Z
    builder.put("iiota", Integer.valueOf('\u2129') << 16); // TURNED GREEK SMALL LETTER IOTA
    builder.put("angst", Integer.valueOf('\u212b') << 16); // ANGSTROM SIGN
    builder.put("bernou", Integer.valueOf('\u212c') << 16); // SCRIPT CAPITAL B
    builder.put("Bernoullis", Integer.valueOf('\u212c') << 16); // SCRIPT CAPITAL B
    builder.put("Bscr", Integer.valueOf('\u212c') << 16); // SCRIPT CAPITAL B
    builder.put("Cfr", Integer.valueOf('\u212d') << 16); // BLACK-LETTER CAPITAL C
    builder.put("Cayleys", Integer.valueOf('\u212d') << 16); // BLACK-LETTER CAPITAL C
    builder.put("escr", Integer.valueOf('\u212f') << 16); // SCRIPT SMALL E
    builder.put("Escr", Integer.valueOf('\u2130') << 16); // SCRIPT CAPITAL E
    builder.put("expectation", Integer.valueOf('\u2130') << 16); // SCRIPT CAPITAL E
    builder.put("Fscr", Integer.valueOf('\u2131') << 16); // SCRIPT CAPITAL F
    builder.put("Fouriertrf", Integer.valueOf('\u2131') << 16); // SCRIPT CAPITAL F
    builder.put("phmmat", Integer.valueOf('\u2133') << 16); // SCRIPT CAPITAL M
    builder.put("Mellintrf", Integer.valueOf('\u2133') << 16); // SCRIPT CAPITAL M
    builder.put("Mscr", Integer.valueOf('\u2133') << 16); // SCRIPT CAPITAL M
    builder.put("order", Integer.valueOf('\u2134') << 16); // SCRIPT SMALL O
    builder.put("orderof", Integer.valueOf('\u2134') << 16); // SCRIPT SMALL O
    builder.put("oscr", Integer.valueOf('\u2134') << 16); // SCRIPT SMALL O
    builder.put("alefsym", Integer.valueOf('\u2135') << 16); // ALEF SYMBOL
    builder.put("aleph", Integer.valueOf('\u2135') << 16); // ALEF SYMBOL
    builder.put("beth", Integer.valueOf('\u2136') << 16); // BET SYMBOL
    builder.put("gimel", Integer.valueOf('\u2137') << 16); // GIMEL SYMBOL
    builder.put("daleth", Integer.valueOf('\u2138') << 16); // DALET SYMBOL
    builder.put("CapitalDifferentialD", Integer.valueOf('\u2145') << 16); // DOUBLE-STRUCK ITALIC CAPITAL D
    builder.put("DD", Integer.valueOf('\u2145') << 16); // DOUBLE-STRUCK ITALIC CAPITAL D
    builder.put("DifferentialD", Integer.valueOf('\u2146') << 16); // DOUBLE-STRUCK ITALIC SMALL D
    builder.put("dd", Integer.valueOf('\u2146') << 16); // DOUBLE-STRUCK ITALIC SMALL D
    builder.put("ExponentialE", Integer.valueOf('\u2147') << 16); // DOUBLE-STRUCK ITALIC SMALL E
    builder.put("exponentiale", Integer.valueOf('\u2147') << 16); // DOUBLE-STRUCK ITALIC SMALL E
    builder.put("ee", Integer.valueOf('\u2147') << 16); // DOUBLE-STRUCK ITALIC SMALL E
    builder.put("ImaginaryI", Integer.valueOf('\u2148') << 16); // DOUBLE-STRUCK ITALIC SMALL I
    builder.put("ii", Integer.valueOf('\u2148') << 16); // DOUBLE-STRUCK ITALIC SMALL I

    // Number Forms
    builder.put("frac13", Integer.valueOf('\u2153') << 16); // VULGAR FRACTION ONE THIRD
    builder.put("frac23", Integer.valueOf('\u2154') << 16); // VULGAR FRACTION TWO THIRDS
    builder.put("frac15", Integer.valueOf('\u2155') << 16); // VULGAR FRACTION ONE FIFTH
    builder.put("frac25", Integer.valueOf('\u2156') << 16); // VULGAR FRACTION TWO FIFTHS
    builder.put("frac35", Integer.valueOf('\u2157') << 16); // VULGAR FRACTION THREE FIFTHS
    builder.put("frac45", Integer.valueOf('\u2158') << 16); // VULGAR FRACTION FOUR FIFTHS
    builder.put("frac16", Integer.valueOf('\u2159') << 16); // VULGAR FRACTION ONE SIXTH
    builder.put("frac56", Integer.valueOf('\u215a') << 16); // VULGAR FRACTION FIVE SIXTHS
    builder.put("frac18", Integer.valueOf('\u215b') << 16); // VULGAR FRACTION ONE EIGHTH
    builder.put("frac38", Integer.valueOf('\u215c') << 16); // VULGAR FRACTION THREE EIGHTHS
    builder.put("frac58", Integer.valueOf('\u215d') << 16); // VULGAR FRACTION FIVE EIGHTHS
    builder.put("frac78", Integer.valueOf('\u215e') << 16); // VULGAR FRACTION SEVEN EIGHTHS

    // Arrows
    builder.put("larr", Integer.valueOf('\u2190') << 16); // LEFTWARDS ARROW
    builder.put("leftarrow", Integer.valueOf('\u2190') << 16); // LEFTWARDS ARROW
    builder.put("LeftArrow", Integer.valueOf('\u2190') << 16); // LEFTWARDS ARROW
    builder.put("slarr", Integer.valueOf('\u2190') << 16); // LEFTWARDS ARROW
    builder.put("ShortLeftArrow", Integer.valueOf('\u2190') << 16); // LEFTWARDS ARROW
    builder.put("uarr", Integer.valueOf('\u2191') << 16); // UPWARDS ARROW
    builder.put("uparrow", Integer.valueOf('\u2191') << 16); // UPWARDS ARROW
    builder.put("UpArrow", Integer.valueOf('\u2191') << 16); // UPWARDS ARROW
    builder.put("ShortUpArrow", Integer.valueOf('\u2191') << 16); // UPWARDS ARROW
    builder.put("rarr", Integer.valueOf('\u2192') << 16); // RIGHTWARDS ARROW
    builder.put("rightarrow", Integer.valueOf('\u2192') << 16); // RIGHTWARDS ARROW
    builder.put("RightArrow", Integer.valueOf('\u2192') << 16); // RIGHTWARDS ARROW
    builder.put("srarr", Integer.valueOf('\u2192') << 16); // RIGHTWARDS ARROW
    builder.put("ShortRightArrow", Integer.valueOf('\u2192') << 16); // RIGHTWARDS ARROW
    builder.put("darr", Integer.valueOf('\u2193') << 16); // DOWNWARDS ARROW
    builder.put("downarrow", Integer.valueOf('\u2193') << 16); // DOWNWARDS ARROW
    builder.put("DownArrow", Integer.valueOf('\u2193') << 16); // DOWNWARDS ARROW
    builder.put("ShortDownArrow", Integer.valueOf('\u2193') << 16); // DOWNWARDS ARROW
    builder.put("harr", Integer.valueOf('\u2194') << 16); // LEFT RIGHT ARROW
    builder.put("leftrightarrow", Integer.valueOf('\u2194') << 16); // LEFT RIGHT ARROW
    builder.put("LeftRightArrow", Integer.valueOf('\u2194') << 16); // LEFT RIGHT ARROW
    builder.put("varr", Integer.valueOf('\u2195') << 16); // UP DOWN ARROW
    builder.put("updownarrow", Integer.valueOf('\u2195') << 16); // UP DOWN ARROW
    builder.put("UpDownArrow", Integer.valueOf('\u2195') << 16); // UP DOWN ARROW
    builder.put("nwarr", Integer.valueOf('\u2196') << 16); // NORTH WEST ARROW
    builder.put("UpperLeftArrow", Integer.valueOf('\u2196') << 16); // NORTH WEST ARROW
    builder.put("nwarrow", Integer.valueOf('\u2196') << 16); // NORTH WEST ARROW
    builder.put("nearr", Integer.valueOf('\u2197') << 16); // NORTH EAST ARROW
    builder.put("UpperRightArrow", Integer.valueOf('\u2197') << 16); // NORTH EAST ARROW
    builder.put("nearrow", Integer.valueOf('\u2197') << 16); // NORTH EAST ARROW
    builder.put("searr", Integer.valueOf('\u2198') << 16); // SOUTH EAST ARROW
    builder.put("searrow", Integer.valueOf('\u2198') << 16); // SOUTH EAST ARROW
    builder.put("LowerRightArrow", Integer.valueOf('\u2198') << 16); // SOUTH EAST ARROW
    builder.put("swarr", Integer.valueOf('\u2199') << 16); // SOUTH WEST ARROW
    builder.put("swarrow", Integer.valueOf('\u2199') << 16); // SOUTH WEST ARROW
    builder.put("LowerLeftArrow", Integer.valueOf('\u2199') << 16); // SOUTH WEST ARROW
    builder.put("nlarr", Integer.valueOf('\u219a') << 16); // LEFTWARDS ARROW WITH STROKE
    builder.put("nleftarrow", Integer.valueOf('\u219a') << 16); // LEFTWARDS ARROW WITH STROKE
    builder.put("nrarr", Integer.valueOf('\u219b') << 16); // RIGHTWARDS ARROW WITH STROKE
    builder.put("nrightarrow", Integer.valueOf('\u219b') << 16); // RIGHTWARDS ARROW WITH STROKE
    builder.put("rarrw", Integer.valueOf('\u219d') << 16); // RIGHTWARDS WAVE ARROW
    builder.put("rightsquigarrow", Integer.valueOf('\u219d') << 16); // RIGHTWARDS WAVE ARROW
    builder.put("Larr", Integer.valueOf('\u219e') << 16); // LEFTWARDS TWO HEADED ARROW
    builder.put("twoheadleftarrow", Integer.valueOf('\u219e') << 16); // LEFTWARDS TWO HEADED ARROW
    builder.put("Uarr", Integer.valueOf('\u219f') << 16); // UPWARDS TWO HEADED ARROW
    builder.put("Rarr", Integer.valueOf('\u21a0') << 16); // RIGHTWARDS TWO HEADED ARROW
    builder.put("twoheadrightarrow", Integer.valueOf('\u21a0') << 16); // RIGHTWARDS TWO HEADED ARROW
    builder.put("Darr", Integer.valueOf('\u21a1') << 16); // DOWNWARDS TWO HEADED ARROW
    builder.put("larrtl", Integer.valueOf('\u21a2') << 16); // LEFTWARDS ARROW WITH TAIL
    builder.put("leftarrowtail", Integer.valueOf('\u21a2') << 16); // LEFTWARDS ARROW WITH TAIL
    builder.put("rarrtl", Integer.valueOf('\u21a3') << 16); // RIGHTWARDS ARROW WITH TAIL
    builder.put("rightarrowtail", Integer.valueOf('\u21a3') << 16); // RIGHTWARDS ARROW WITH TAIL
    builder.put("LeftTeeArrow", Integer.valueOf('\u21a4') << 16); // LEFTWARDS ARROW FROM BAR
    builder.put("mapstoleft", Integer.valueOf('\u21a4') << 16); // LEFTWARDS ARROW FROM BAR
    builder.put("UpTeeArrow", Integer.valueOf('\u21a5') << 16); // UPWARDS ARROW FROM BAR
    builder.put("mapstoup", Integer.valueOf('\u21a5') << 16); // UPWARDS ARROW FROM BAR
    builder.put("map", Integer.valueOf('\u21a6') << 16); // RIGHTWARDS ARROW FROM BAR
    builder.put("RightTeeArrow", Integer.valueOf('\u21a6') << 16); // RIGHTWARDS ARROW FROM BAR
    builder.put("mapsto", Integer.valueOf('\u21a6') << 16); // RIGHTWARDS ARROW FROM BAR
    builder.put("DownTeeArrow", Integer.valueOf('\u21a7') << 16); // DOWNWARDS ARROW FROM BAR
    builder.put("mapstodown", Integer.valueOf('\u21a7') << 16); // DOWNWARDS ARROW FROM BAR
    builder.put("larrhk", Integer.valueOf('\u21a9') << 16); // LEFTWARDS ARROW WITH HOOK
    builder.put("hookleftarrow", Integer.valueOf('\u21a9') << 16); // LEFTWARDS ARROW WITH HOOK
    builder.put("rarrhk", Integer.valueOf('\u21aa') << 16); // RIGHTWARDS ARROW WITH HOOK
    builder.put("hookrightarrow", Integer.valueOf('\u21aa') << 16); // RIGHTWARDS ARROW WITH HOOK
    builder.put("larrlp", Integer.valueOf('\u21ab') << 16); // LEFTWARDS ARROW WITH LOOP
    builder.put("looparrowleft", Integer.valueOf('\u21ab') << 16); // LEFTWARDS ARROW WITH LOOP
    builder.put("rarrlp", Integer.valueOf('\u21ac') << 16); // RIGHTWARDS ARROW WITH LOOP
    builder.put("looparrowright", Integer.valueOf('\u21ac') << 16); // RIGHTWARDS ARROW WITH LOOP
    builder.put("harrw", Integer.valueOf('\u21ad') << 16); // LEFT RIGHT WAVE ARROW
    builder.put("leftrightsquigarrow", Integer.valueOf('\u21ad') << 16); // LEFT RIGHT WAVE ARROW
    builder.put("nharr", Integer.valueOf('\u21ae') << 16); // LEFT RIGHT ARROW WITH STROKE
    builder.put("nleftrightarrow", Integer.valueOf('\u21ae') << 16); // LEFT RIGHT ARROW WITH STROKE
    builder.put("lsh", Integer.valueOf('\u21b0') << 16); // UPWARDS ARROW WITH TIP LEFTWARDS
    builder.put("Lsh", Integer.valueOf('\u21b0') << 16); // UPWARDS ARROW WITH TIP LEFTWARDS
    builder.put("rsh", Integer.valueOf('\u21b1') << 16); // UPWARDS ARROW WITH TIP RIGHTWARDS
    builder.put("Rsh", Integer.valueOf('\u21b1') << 16); // UPWARDS ARROW WITH TIP RIGHTWARDS
    builder.put("ldsh", Integer.valueOf('\u21b2') << 16); // DOWNWARDS ARROW WITH TIP LEFTWARDS
    builder.put("rdsh", Integer.valueOf('\u21b3') << 16); // DOWNWARDS ARROW WITH TIP RIGHTWARDS
    builder.put("crarr", Integer.valueOf('\u21b5') << 16); // DOWNWARDS ARROW WITH CORNER LEFTWARDS
    builder.put("cularr", Integer.valueOf('\u21b6') << 16); // ANTICLOCKWISE TOP SEMICIRCLE ARROW
    builder.put("curvearrowleft", Integer.valueOf('\u21b6') << 16); // ANTICLOCKWISE TOP SEMICIRCLE ARROW
    builder.put("curarr", Integer.valueOf('\u21b7') << 16); // CLOCKWISE TOP SEMICIRCLE ARROW
    builder.put("curvearrowright", Integer.valueOf('\u21b7') << 16); // CLOCKWISE TOP SEMICIRCLE ARROW
    builder.put("olarr", Integer.valueOf('\u21ba') << 16); // ANTICLOCKWISE OPEN CIRCLE ARROW
    builder.put("circlearrowleft", Integer.valueOf('\u21ba') << 16); // ANTICLOCKWISE OPEN CIRCLE ARROW
    builder.put("orarr", Integer.valueOf('\u21bb') << 16); // CLOCKWISE OPEN CIRCLE ARROW
    builder.put("circlearrowright", Integer.valueOf('\u21bb') << 16); // CLOCKWISE OPEN CIRCLE ARROW
    builder.put("lharu", Integer.valueOf('\u21bc') << 16); // LEFTWARDS HARPOON WITH BARB UPWARDS
    builder.put("LeftVector", Integer.valueOf('\u21bc') << 16); // LEFTWARDS HARPOON WITH BARB UPWARDS
    builder.put("leftharpoonup", Integer.valueOf('\u21bc') << 16); // LEFTWARDS HARPOON WITH BARB UPWARDS
    builder.put("lhard", Integer.valueOf('\u21bd') << 16); // LEFTWARDS HARPOON WITH BARB DOWNWARDS
    builder.put("leftharpoondown", Integer.valueOf('\u21bd') << 16); // LEFTWARDS HARPOON WITH BARB DOWNWARDS
    builder.put("DownLeftVector", Integer.valueOf('\u21bd') << 16); // LEFTWARDS HARPOON WITH BARB DOWNWARDS
    builder.put("uharr", Integer.valueOf('\u21be') << 16); // UPWARDS HARPOON WITH BARB RIGHTWARDS
    builder.put("upharpoonright", Integer.valueOf('\u21be') << 16); // UPWARDS HARPOON WITH BARB RIGHTWARDS
    builder.put("RightUpVector", Integer.valueOf('\u21be') << 16); // UPWARDS HARPOON WITH BARB RIGHTWARDS
    builder.put("uharl", Integer.valueOf('\u21bf') << 16); // UPWARDS HARPOON WITH BARB LEFTWARDS
    builder.put("upharpoonleft", Integer.valueOf('\u21bf') << 16); // UPWARDS HARPOON WITH BARB LEFTWARDS
    builder.put("LeftUpVector", Integer.valueOf('\u21bf') << 16); // UPWARDS HARPOON WITH BARB LEFTWARDS
    builder.put("rharu", Integer.valueOf('\u21c0') << 16); // RIGHTWARDS HARPOON WITH BARB UPWARDS
    builder.put("RightVector", Integer.valueOf('\u21c0') << 16); // RIGHTWARDS HARPOON WITH BARB UPWARDS
    builder.put("rightharpoonup", Integer.valueOf('\u21c0') << 16); // RIGHTWARDS HARPOON WITH BARB UPWARDS
    builder.put("rhard", Integer.valueOf('\u21c1') << 16); // RIGHTWARDS HARPOON WITH BARB DOWNWARDS
    builder.put("rightharpoondown", Integer.valueOf('\u21c1') << 16); // RIGHTWARDS HARPOON WITH BARB DOWNWARDS
    builder.put("DownRightVector", Integer.valueOf('\u21c1') << 16); // RIGHTWARDS HARPOON WITH BARB DOWNWARDS
    builder.put("dharr", Integer.valueOf('\u21c2') << 16); // DOWNWARDS HARPOON WITH BARB RIGHTWARDS
    builder.put("RightDownVector", Integer.valueOf('\u21c2') << 16); // DOWNWARDS HARPOON WITH BARB RIGHTWARDS
    builder.put("downharpoonright", Integer.valueOf('\u21c2') << 16); // DOWNWARDS HARPOON WITH BARB RIGHTWARDS
    builder.put("dharl", Integer.valueOf('\u21c3') << 16); // DOWNWARDS HARPOON WITH BARB LEFTWARDS
    builder.put("LeftDownVector", Integer.valueOf('\u21c3') << 16); // DOWNWARDS HARPOON WITH BARB LEFTWARDS
    builder.put("downharpoonleft", Integer.valueOf('\u21c3') << 16); // DOWNWARDS HARPOON WITH BARB LEFTWARDS
    builder.put("rlarr", Integer.valueOf('\u21c4') << 16); // RIGHTWARDS ARROW OVER LEFTWARDS ARROW
    builder.put("rightleftarrows", Integer.valueOf('\u21c4') << 16); // RIGHTWARDS ARROW OVER LEFTWARDS ARROW
    builder.put("RightArrowLeftArrow", Integer.valueOf('\u21c4') << 16); // RIGHTWARDS ARROW OVER LEFTWARDS ARROW
    builder.put("udarr", Integer.valueOf('\u21c5') << 16); // UPWARDS ARROW LEFTWARDS OF DOWNWARDS ARROW
    builder.put("UpArrowDownArrow", Integer.valueOf('\u21c5') << 16); // UPWARDS ARROW LEFTWARDS OF DOWNWARDS ARROW
    builder.put("lrarr", Integer.valueOf('\u21c6') << 16); // LEFTWARDS ARROW OVER RIGHTWARDS ARROW
    builder.put("leftrightarrows", Integer.valueOf('\u21c6') << 16); // LEFTWARDS ARROW OVER RIGHTWARDS ARROW
    builder.put("LeftArrowRightArrow", Integer.valueOf('\u21c6') << 16); // LEFTWARDS ARROW OVER RIGHTWARDS ARROW
    builder.put("llarr", Integer.valueOf('\u21c7') << 16); // LEFTWARDS PAIRED ARROWS
    builder.put("leftleftarrows", Integer.valueOf('\u21c7') << 16); // LEFTWARDS PAIRED ARROWS
    builder.put("uuarr", Integer.valueOf('\u21c8') << 16); // UPWARDS PAIRED ARROWS
    builder.put("upuparrows", Integer.valueOf('\u21c8') << 16); // UPWARDS PAIRED ARROWS
    builder.put("rrarr", Integer.valueOf('\u21c9') << 16); // RIGHTWARDS PAIRED ARROWS
    builder.put("rightrightarrows", Integer.valueOf('\u21c9') << 16); // RIGHTWARDS PAIRED ARROWS
    builder.put("ddarr", Integer.valueOf('\u21ca') << 16); // DOWNWARDS PAIRED ARROWS
    builder.put("downdownarrows", Integer.valueOf('\u21ca') << 16); // DOWNWARDS PAIRED ARROWS
    builder.put("lrhar", Integer.valueOf('\u21cb') << 16); // LEFTWARDS HARPOON OVER RIGHTWARDS HARPOON
    builder.put("ReverseEquilibrium", Integer.valueOf('\u21cb') << 16); // LEFTWARDS HARPOON OVER RIGHTWARDS HARPOON
    builder.put("leftrightharpoons", Integer.valueOf('\u21cb') << 16); // LEFTWARDS HARPOON OVER RIGHTWARDS HARPOON
    builder.put("rlhar", Integer.valueOf('\u21cc') << 16); // RIGHTWARDS HARPOON OVER LEFTWARDS HARPOON
    builder.put("rightleftharpoons", Integer.valueOf('\u21cc') << 16); // RIGHTWARDS HARPOON OVER LEFTWARDS HARPOON
    builder.put("Equilibrium", Integer.valueOf('\u21cc') << 16); // RIGHTWARDS HARPOON OVER LEFTWARDS HARPOON
    builder.put("nlArr", Integer.valueOf('\u21cd') << 16); // LEFTWARDS DOUBLE ARROW WITH STROKE
    builder.put("nLeftarrow", Integer.valueOf('\u21cd') << 16); // LEFTWARDS DOUBLE ARROW WITH STROKE
    builder.put("nhArr", Integer.valueOf('\u21ce') << 16); // LEFT RIGHT DOUBLE ARROW WITH STROKE
    builder.put("nLeftrightarrow", Integer.valueOf('\u21ce') << 16); // LEFT RIGHT DOUBLE ARROW WITH STROKE
    builder.put("nrArr", Integer.valueOf('\u21cf') << 16); // RIGHTWARDS DOUBLE ARROW WITH STROKE
    builder.put("nRightarrow", Integer.valueOf('\u21cf') << 16); // RIGHTWARDS DOUBLE ARROW WITH STROKE
    builder.put("lArr", Integer.valueOf('\u21d0') << 16); // LEFTWARDS DOUBLE ARROW
    builder.put("Leftarrow", Integer.valueOf('\u21d0') << 16); // LEFTWARDS DOUBLE ARROW
    builder.put("DoubleLeftArrow", Integer.valueOf('\u21d0') << 16); // LEFTWARDS DOUBLE ARROW
    builder.put("uArr", Integer.valueOf('\u21d1') << 16); // UPWARDS DOUBLE ARROW
    builder.put("Uparrow", Integer.valueOf('\u21d1') << 16); // UPWARDS DOUBLE ARROW
    builder.put("DoubleUpArrow", Integer.valueOf('\u21d1') << 16); // UPWARDS DOUBLE ARROW
    builder.put("rArr", Integer.valueOf('\u21d2') << 16); // RIGHTWARDS DOUBLE ARROW
    builder.put("Rightarrow", Integer.valueOf('\u21d2') << 16); // RIGHTWARDS DOUBLE ARROW
    builder.put("Implies", Integer.valueOf('\u21d2') << 16); // RIGHTWARDS DOUBLE ARROW
    builder.put("DoubleRightArrow", Integer.valueOf('\u21d2') << 16); // RIGHTWARDS DOUBLE ARROW
    builder.put("dArr", Integer.valueOf('\u21d3') << 16); // DOWNWARDS DOUBLE ARROW
    builder.put("Downarrow", Integer.valueOf('\u21d3') << 16); // DOWNWARDS DOUBLE ARROW
    builder.put("DoubleDownArrow", Integer.valueOf('\u21d3') << 16); // DOWNWARDS DOUBLE ARROW
    builder.put("hArr", Integer.valueOf('\u21d4') << 16); // LEFT RIGHT DOUBLE ARROW
    builder.put("Leftrightarrow", Integer.valueOf('\u21d4') << 16); // LEFT RIGHT DOUBLE ARROW
    builder.put("DoubleLeftRightArrow", Integer.valueOf('\u21d4') << 16); // LEFT RIGHT DOUBLE ARROW
    builder.put("iff", Integer.valueOf('\u21d4') << 16); // LEFT RIGHT DOUBLE ARROW
    builder.put("vArr", Integer.valueOf('\u21d5') << 16); // UP DOWN DOUBLE ARROW
    builder.put("Updownarrow", Integer.valueOf('\u21d5') << 16); // UP DOWN DOUBLE ARROW
    builder.put("DoubleUpDownArrow", Integer.valueOf('\u21d5') << 16); // UP DOWN DOUBLE ARROW
    builder.put("nwArr", Integer.valueOf('\u21d6') << 16); // NORTH WEST DOUBLE ARROW
    builder.put("neArr", Integer.valueOf('\u21d7') << 16); // NORTH EAST DOUBLE ARROW
    builder.put("seArr", Integer.valueOf('\u21d8') << 16); // SOUTH EAST DOUBLE ARROW
    builder.put("swArr", Integer.valueOf('\u21d9') << 16); // SOUTH WEST DOUBLE ARROW
    builder.put("lAarr", Integer.valueOf('\u21da') << 16); // LEFTWARDS TRIPLE ARROW
    builder.put("Lleftarrow", Integer.valueOf('\u21da') << 16); // LEFTWARDS TRIPLE ARROW
    builder.put("rAarr", Integer.valueOf('\u21db') << 16); // RIGHTWARDS TRIPLE ARROW
    builder.put("Rrightarrow", Integer.valueOf('\u21db') << 16); // RIGHTWARDS TRIPLE ARROW
    builder.put("zigrarr", Integer.valueOf('\u21dd') << 16); // RIGHTWARDS SQUIGGLE ARROW
    builder.put("larrb", Integer.valueOf('\u21e4') << 16); // LEFTWARDS ARROW TO BAR
    builder.put("LeftArrowBar", Integer.valueOf('\u21e4') << 16); // LEFTWARDS ARROW TO BAR
    builder.put("rarrb", Integer.valueOf('\u21e5') << 16); // RIGHTWARDS ARROW TO BAR
    builder.put("RightArrowBar", Integer.valueOf('\u21e5') << 16); // RIGHTWARDS ARROW TO BAR
    builder.put("duarr", Integer.valueOf('\u21f5') << 16); // DOWNWARDS ARROW LEFTWARDS OF UPWARDS ARROW
    builder.put("DownArrowUpArrow", Integer.valueOf('\u21f5') << 16); // DOWNWARDS ARROW LEFTWARDS OF UPWARDS ARROW
    builder.put("loarr", Integer.valueOf('\u21fd') << 16); // LEFTWARDS OPEN-HEADED ARROW
    builder.put("roarr", Integer.valueOf('\u21fe') << 16); // RIGHTWARDS OPEN-HEADED ARROW
    builder.put("hoarr", Integer.valueOf('\u21ff') << 16); // LEFT RIGHT OPEN-HEADED ARROW

    // Mathematical Operators
    builder.put("forall", Integer.valueOf('\u2200') << 16); // FOR ALL
    builder.put("ForAll", Integer.valueOf('\u2200') << 16); // FOR ALL
    builder.put("comp", Integer.valueOf('\u2201') << 16); // COMPLEMENT
    builder.put("complement", Integer.valueOf('\u2201') << 16); // COMPLEMENT
    builder.put("part", Integer.valueOf('\u2202') << 16); // PARTIAL DIFFERENTIAL
    builder.put("PartialD", Integer.valueOf('\u2202') << 16); // PARTIAL DIFFERENTIAL
    builder.put("exist", Integer.valueOf('\u2203') << 16); // THERE EXISTS
    builder.put("Exists", Integer.valueOf('\u2203') << 16); // THERE EXISTS
    builder.put("nexist", Integer.valueOf('\u2204') << 16); // THERE DOES NOT EXIST
    builder.put("NotExists", Integer.valueOf('\u2204') << 16); // THERE DOES NOT EXIST
    builder.put("nexists", Integer.valueOf('\u2204') << 16); // THERE DOES NOT EXIST
    builder.put("empty", Integer.valueOf('\u2205') << 16); // EMPTY SET
    builder.put("emptyset", Integer.valueOf('\u2205') << 16); // EMPTY SET
    builder.put("emptyv", Integer.valueOf('\u2205') << 16); // EMPTY SET
    builder.put("varnothing", Integer.valueOf('\u2205') << 16); // EMPTY SET
    builder.put("nabla", Integer.valueOf('\u2207') << 16); // NABLA
    builder.put("Del", Integer.valueOf('\u2207') << 16); // NABLA
    builder.put("isin", Integer.valueOf('\u2208') << 16); // ELEMENT OF
    builder.put("isinv", Integer.valueOf('\u2208') << 16); // ELEMENT OF
    builder.put("Element", Integer.valueOf('\u2208') << 16); // ELEMENT OF
    builder.put("in", Integer.valueOf('\u2208') << 16); // ELEMENT OF
    builder.put("notin", Integer.valueOf('\u2209') << 16); // NOT AN ELEMENT OF
    builder.put("NotElement", Integer.valueOf('\u2209') << 16); // NOT AN ELEMENT OF
    builder.put("notinva", Integer.valueOf('\u2209') << 16); // NOT AN ELEMENT OF
    builder.put("niv", Integer.valueOf('\u220b') << 16); // CONTAINS AS MEMBER
    builder.put("ReverseElement", Integer.valueOf('\u220b') << 16); // CONTAINS AS MEMBER
    builder.put("ni", Integer.valueOf('\u220b') << 16); // CONTAINS AS MEMBER
    builder.put("SuchThat", Integer.valueOf('\u220b') << 16); // CONTAINS AS MEMBER
    builder.put("notni", Integer.valueOf('\u220c') << 16); // DOES NOT CONTAIN AS MEMBER
    builder.put("notniva", Integer.valueOf('\u220c') << 16); // DOES NOT CONTAIN AS MEMBER
    builder.put("NotReverseElement", Integer.valueOf('\u220c') << 16); // DOES NOT CONTAIN AS MEMBER
    builder.put("prod", Integer.valueOf('\u220f') << 16); // N-ARY PRODUCT
    builder.put("Product", Integer.valueOf('\u220f') << 16); // N-ARY PRODUCT
    builder.put("coprod", Integer.valueOf('\u2210') << 16); // N-ARY COPRODUCT
    builder.put("Coproduct", Integer.valueOf('\u2210') << 16); // N-ARY COPRODUCT
    builder.put("sum", Integer.valueOf('\u2211') << 16); // N-ARY SUMMATION
    builder.put("Sum", Integer.valueOf('\u2211') << 16); // N-ARY SUMMATION
    builder.put("minus", Integer.valueOf('\u2212') << 16); // MINUS SIGN
    builder.put("mnplus", Integer.valueOf('\u2213') << 16); // MINUS-OR-PLUS SIGN
    builder.put("mp", Integer.valueOf('\u2213') << 16); // MINUS-OR-PLUS SIGN
    builder.put("MinusPlus", Integer.valueOf('\u2213') << 16); // MINUS-OR-PLUS SIGN
    builder.put("plusdo", Integer.valueOf('\u2214') << 16); // DOT PLUS
    builder.put("dotplus", Integer.valueOf('\u2214') << 16); // DOT PLUS
    builder.put("setmn", Integer.valueOf('\u2216') << 16); // SET MINUS
    builder.put("setminus", Integer.valueOf('\u2216') << 16); // SET MINUS
    builder.put("Backslash", Integer.valueOf('\u2216') << 16); // SET MINUS
    builder.put("ssetmn", Integer.valueOf('\u2216') << 16); // SET MINUS
    builder.put("smallsetminus", Integer.valueOf('\u2216') << 16); // SET MINUS
    builder.put("lowast", Integer.valueOf('\u2217') << 16); // ASTERISK OPERATOR
    builder.put("compfn", Integer.valueOf('\u2218') << 16); // RING OPERATOR
    builder.put("SmallCircle", Integer.valueOf('\u2218') << 16); // RING OPERATOR
    builder.put("radic", Integer.valueOf('\u221a') << 16); // SQUARE ROOT
    builder.put("Sqrt", Integer.valueOf('\u221a') << 16); // SQUARE ROOT
    builder.put("prop", Integer.valueOf('\u221d') << 16); // PROPORTIONAL TO
    builder.put("propto", Integer.valueOf('\u221d') << 16); // PROPORTIONAL TO
    builder.put("Proportional", Integer.valueOf('\u221d') << 16); // PROPORTIONAL TO
    builder.put("vprop", Integer.valueOf('\u221d') << 16); // PROPORTIONAL TO
    builder.put("varpropto", Integer.valueOf('\u221d') << 16); // PROPORTIONAL TO
    builder.put("infin", Integer.valueOf('\u221e') << 16); // INFINITY
    builder.put("angrt", Integer.valueOf('\u221f') << 16); // RIGHT ANGLE
    builder.put("ang", Integer.valueOf('\u2220') << 16); // ANGLE
    builder.put("angle", Integer.valueOf('\u2220') << 16); // ANGLE
    builder.put("angmsd", Integer.valueOf('\u2221') << 16); // MEASURED ANGLE
    builder.put("measuredangle", Integer.valueOf('\u2221') << 16); // MEASURED ANGLE
    builder.put("angsph", Integer.valueOf('\u2222') << 16); // SPHERICAL ANGLE
    builder.put("mid", Integer.valueOf('\u2223') << 16); // DIVIDES
    builder.put("VerticalBar", Integer.valueOf('\u2223') << 16); // DIVIDES
    builder.put("smid", Integer.valueOf('\u2223') << 16); // DIVIDES
    builder.put("shortmid", Integer.valueOf('\u2223') << 16); // DIVIDES
    builder.put("nmid", Integer.valueOf('\u2224') << 16); // DOES NOT DIVIDE
    builder.put("NotVerticalBar", Integer.valueOf('\u2224') << 16); // DOES NOT DIVIDE
    builder.put("nsmid", Integer.valueOf('\u2224') << 16); // DOES NOT DIVIDE
    builder.put("nshortmid", Integer.valueOf('\u2224') << 16); // DOES NOT DIVIDE
    builder.put("par", Integer.valueOf('\u2225') << 16); // PARALLEL TO
    builder.put("parallel", Integer.valueOf('\u2225') << 16); // PARALLEL TO
    builder.put("DoubleVerticalBar", Integer.valueOf('\u2225') << 16); // PARALLEL TO
    builder.put("spar", Integer.valueOf('\u2225') << 16); // PARALLEL TO
    builder.put("shortparallel", Integer.valueOf('\u2225') << 16); // PARALLEL TO
    builder.put("npar", Integer.valueOf('\u2226') << 16); // NOT PARALLEL TO
    builder.put("nparallel", Integer.valueOf('\u2226') << 16); // NOT PARALLEL TO
    builder.put("NotDoubleVerticalBar", Integer.valueOf('\u2226') << 16); // NOT PARALLEL TO
    builder.put("nspar", Integer.valueOf('\u2226') << 16); // NOT PARALLEL TO
    builder.put("nshortparallel", Integer.valueOf('\u2226') << 16); // NOT PARALLEL TO
    builder.put("and", Integer.valueOf('\u2227') << 16); // LOGICAL AND
    builder.put("wedge", Integer.valueOf('\u2227') << 16); // LOGICAL AND
    builder.put("or", Integer.valueOf('\u2228') << 16); // LOGICAL OR
    builder.put("vee", Integer.valueOf('\u2228') << 16); // LOGICAL OR
    builder.put("cap", Integer.valueOf('\u2229') << 16); // INTERSECTION
    builder.put("cup", Integer.valueOf('\u222a') << 16); // UNION
    builder.put("int", Integer.valueOf('\u222b') << 16); // INTEGRAL
    builder.put("Integral", Integer.valueOf('\u222b') << 16); // INTEGRAL
    builder.put("Int", Integer.valueOf('\u222c') << 16); // DOUBLE INTEGRAL
    builder.put("tint", Integer.valueOf('\u222d') << 16); // TRIPLE INTEGRAL
    builder.put("iiint", Integer.valueOf('\u222d') << 16); // TRIPLE INTEGRAL
    builder.put("conint", Integer.valueOf('\u222e') << 16); // CONTOUR INTEGRAL
    builder.put("oint", Integer.valueOf('\u222e') << 16); // CONTOUR INTEGRAL
    builder.put("ContourIntegral", Integer.valueOf('\u222e') << 16); // CONTOUR INTEGRAL
    builder.put("Conint", Integer.valueOf('\u222f') << 16); // SURFACE INTEGRAL
    builder.put("DoubleContourIntegral", Integer.valueOf('\u222f') << 16); // SURFACE INTEGRAL
    builder.put("Cconint", Integer.valueOf('\u2230') << 16); // VOLUME INTEGRAL
    builder.put("cwint", Integer.valueOf('\u2231') << 16); // CLOCKWISE INTEGRAL
    builder.put("cwconint", Integer.valueOf('\u2232') << 16); // CLOCKWISE CONTOUR INTEGRAL
    builder.put("ClockwiseContourIntegral", Integer.valueOf('\u2232') << 16); // CLOCKWISE CONTOUR INTEGRAL
    builder.put("awconint", Integer.valueOf('\u2233') << 16); // ANTICLOCKWISE CONTOUR INTEGRAL
    builder.put("CounterClockwiseContourIntegral", Integer.valueOf('\u2233') << 16); // ANTICLOCKWISE CONTOUR INTEGRAL
    builder.put("there4", Integer.valueOf('\u2234') << 16); // THEREFORE
    builder.put("therefore", Integer.valueOf('\u2234') << 16); // THEREFORE
    builder.put("Therefore", Integer.valueOf('\u2234') << 16); // THEREFORE
    builder.put("becaus", Integer.valueOf('\u2235') << 16); // BECAUSE
    builder.put("because", Integer.valueOf('\u2235') << 16); // BECAUSE
    builder.put("Because", Integer.valueOf('\u2235') << 16); // BECAUSE
    builder.put("ratio", Integer.valueOf('\u2236') << 16); // RATIO
    builder.put("Colon", Integer.valueOf('\u2237') << 16); // PROPORTION
    builder.put("Proportion", Integer.valueOf('\u2237') << 16); // PROPORTION
    builder.put("minusd", Integer.valueOf('\u2238') << 16); // DOT MINUS
    builder.put("dotminus", Integer.valueOf('\u2238') << 16); // DOT MINUS
    builder.put("mDDot", Integer.valueOf('\u223a') << 16); // GEOMETRIC PROPORTION
    builder.put("homtht", Integer.valueOf('\u223b') << 16); // HOMOTHETIC
    builder.put("sim", Integer.valueOf('\u223c') << 16); // TILDE OPERATOR
    builder.put("Tilde", Integer.valueOf('\u223c') << 16); // TILDE OPERATOR
    builder.put("thksim", Integer.valueOf('\u223c') << 16); // TILDE OPERATOR
    builder.put("thicksim", Integer.valueOf('\u223c') << 16); // TILDE OPERATOR
    builder.put("bsim", Integer.valueOf('\u223d') << 16); // REVERSED TILDE
    builder.put("backsim", Integer.valueOf('\u223d') << 16); // REVERSED TILDE
    builder.put("ac", Integer.valueOf('\u223e') << 16); // INVERTED LAZY S
    builder.put("mstpos", Integer.valueOf('\u223e') << 16); // INVERTED LAZY S
    builder.put("acd", Integer.valueOf('\u223f') << 16); // SINE WAVE
    builder.put("wreath", Integer.valueOf('\u2240') << 16); // WREATH PRODUCT
    builder.put("VerticalTilde", Integer.valueOf('\u2240') << 16); // WREATH PRODUCT
    builder.put("wr", Integer.valueOf('\u2240') << 16); // WREATH PRODUCT
    builder.put("nsim", Integer.valueOf('\u2241') << 16); // NOT TILDE
    builder.put("NotTilde", Integer.valueOf('\u2241') << 16); // NOT TILDE
    builder.put("esim", Integer.valueOf('\u2242') << 16); // MINUS TILDE
    builder.put("EqualTilde", Integer.valueOf('\u2242') << 16); // MINUS TILDE
    builder.put("eqsim", Integer.valueOf('\u2242') << 16); // MINUS TILDE
    builder.put("sime", Integer.valueOf('\u2243') << 16); // ASYMPTOTICALLY EQUAL TO
    builder.put("TildeEqual", Integer.valueOf('\u2243') << 16); // ASYMPTOTICALLY EQUAL TO
    builder.put("simeq", Integer.valueOf('\u2243') << 16); // ASYMPTOTICALLY EQUAL TO
    builder.put("nsime", Integer.valueOf('\u2244') << 16); // NOT ASYMPTOTICALLY EQUAL TO
    builder.put("nsimeq", Integer.valueOf('\u2244') << 16); // NOT ASYMPTOTICALLY EQUAL TO
    builder.put("NotTildeEqual", Integer.valueOf('\u2244') << 16); // NOT ASYMPTOTICALLY EQUAL TO
    builder.put("cong", Integer.valueOf('\u2245') << 16); // APPROXIMATELY EQUAL TO
    builder.put("TildeFullEqual", Integer.valueOf('\u2245') << 16); // APPROXIMATELY EQUAL TO
    builder.put("simne", Integer.valueOf('\u2246') << 16); // APPROXIMATELY BUT NOT ACTUALLY EQUAL TO
    builder.put("ncong", Integer.valueOf('\u2247') << 16); // NEITHER APPROXIMATELY NOR ACTUALLY EQUAL TO
    builder.put("NotTildeFullEqual", Integer.valueOf('\u2247') << 16); // NEITHER APPROXIMATELY NOR ACTUALLY EQUAL TO
    builder.put("asymp", Integer.valueOf('\u2248') << 16); // ALMOST EQUAL TO
    builder.put("ap", Integer.valueOf('\u2248') << 16); // ALMOST EQUAL TO
    builder.put("TildeTilde", Integer.valueOf('\u2248') << 16); // ALMOST EQUAL TO
    builder.put("approx", Integer.valueOf('\u2248') << 16); // ALMOST EQUAL TO
    builder.put("thkap", Integer.valueOf('\u2248') << 16); // ALMOST EQUAL TO
    builder.put("thickapprox", Integer.valueOf('\u2248') << 16); // ALMOST EQUAL TO
    builder.put("nap", Integer.valueOf('\u2249') << 16); // NOT ALMOST EQUAL TO
    builder.put("NotTildeTilde", Integer.valueOf('\u2249') << 16); // NOT ALMOST EQUAL TO
    builder.put("napprox", Integer.valueOf('\u2249') << 16); // NOT ALMOST EQUAL TO
    builder.put("ape", Integer.valueOf('\u224a') << 16); // ALMOST EQUAL OR EQUAL TO
    builder.put("approxeq", Integer.valueOf('\u224a') << 16); // ALMOST EQUAL OR EQUAL TO
    builder.put("apid", Integer.valueOf('\u224b') << 16); // TRIPLE TILDE
    builder.put("bcong", Integer.valueOf('\u224c') << 16); // ALL EQUAL TO
    builder.put("backcong", Integer.valueOf('\u224c') << 16); // ALL EQUAL TO
    builder.put("asympeq", Integer.valueOf('\u224d') << 16); // EQUIVALENT TO
    builder.put("CupCap", Integer.valueOf('\u224d') << 16); // EQUIVALENT TO
    builder.put("bump", Integer.valueOf('\u224e') << 16); // GEOMETRICALLY EQUIVALENT TO
    builder.put("HumpDownHump", Integer.valueOf('\u224e') << 16); // GEOMETRICALLY EQUIVALENT TO
    builder.put("Bumpeq", Integer.valueOf('\u224e') << 16); // GEOMETRICALLY EQUIVALENT TO
    builder.put("bumpe", Integer.valueOf('\u224f') << 16); // DIFFERENCE BETWEEN
    builder.put("HumpEqual", Integer.valueOf('\u224f') << 16); // DIFFERENCE BETWEEN
    builder.put("bumpeq", Integer.valueOf('\u224f') << 16); // DIFFERENCE BETWEEN
    builder.put("esdot", Integer.valueOf('\u2250') << 16); // APPROACHES THE LIMIT
    builder.put("DotEqual", Integer.valueOf('\u2250') << 16); // APPROACHES THE LIMIT
    builder.put("doteq", Integer.valueOf('\u2250') << 16); // APPROACHES THE LIMIT
    builder.put("eDot", Integer.valueOf('\u2251') << 16); // GEOMETRICALLY EQUAL TO
    builder.put("doteqdot", Integer.valueOf('\u2251') << 16); // GEOMETRICALLY EQUAL TO
    builder.put("efDot", Integer.valueOf('\u2252') << 16); // APPROXIMATELY EQUAL TO OR THE IMAGE OF
    builder.put("fallingdotseq", Integer.valueOf('\u2252') << 16); // APPROXIMATELY EQUAL TO OR THE IMAGE OF
    builder.put("erDot", Integer.valueOf('\u2253') << 16); // IMAGE OF OR APPROXIMATELY EQUAL TO
    builder.put("risingdotseq", Integer.valueOf('\u2253') << 16); // IMAGE OF OR APPROXIMATELY EQUAL TO
    builder.put("colone", Integer.valueOf('\u2254') << 16); // COLON EQUALS
    builder.put("coloneq", Integer.valueOf('\u2254') << 16); // COLON EQUALS
    builder.put("Assign", Integer.valueOf('\u2254') << 16); // COLON EQUALS
    builder.put("ecolon", Integer.valueOf('\u2255') << 16); // EQUALS COLON
    builder.put("eqcolon", Integer.valueOf('\u2255') << 16); // EQUALS COLON
    builder.put("ecir", Integer.valueOf('\u2256') << 16); // RING IN EQUAL TO
    builder.put("eqcirc", Integer.valueOf('\u2256') << 16); // RING IN EQUAL TO
    builder.put("cire", Integer.valueOf('\u2257') << 16); // RING EQUAL TO
    builder.put("circeq", Integer.valueOf('\u2257') << 16); // RING EQUAL TO
    builder.put("wedgeq", Integer.valueOf('\u2259') << 16); // ESTIMATES
    builder.put("veeeq", Integer.valueOf('\u225a') << 16); // EQUIANGULAR TO
    builder.put("trie", Integer.valueOf('\u225c') << 16); // DELTA EQUAL TO
    builder.put("triangleq", Integer.valueOf('\u225c') << 16); // DELTA EQUAL TO
    builder.put("equest", Integer.valueOf('\u225f') << 16); // QUESTIONED EQUAL TO
    builder.put("questeq", Integer.valueOf('\u225f') << 16); // QUESTIONED EQUAL TO
    builder.put("ne", Integer.valueOf('\u2260') << 16); // NOT EQUAL TO
    builder.put("NotEqual", Integer.valueOf('\u2260') << 16); // NOT EQUAL TO
    builder.put("equiv", Integer.valueOf('\u2261') << 16); // IDENTICAL TO
    builder.put("Congruent", Integer.valueOf('\u2261') << 16); // IDENTICAL TO
    builder.put("nequiv", Integer.valueOf('\u2262') << 16); // NOT IDENTICAL TO
    builder.put("NotCongruent", Integer.valueOf('\u2262') << 16); // NOT IDENTICAL TO
    builder.put("le", Integer.valueOf('\u2264') << 16); // LESS-THAN OR EQUAL TO
    builder.put("leq", Integer.valueOf('\u2264') << 16); // LESS-THAN OR EQUAL TO
    builder.put("ge", Integer.valueOf('\u2265') << 16); // GREATER-THAN OR EQUAL TO
    builder.put("GreaterEqual", Integer.valueOf('\u2265') << 16); // GREATER-THAN OR EQUAL TO
    builder.put("geq", Integer.valueOf('\u2265') << 16); // GREATER-THAN OR EQUAL TO
    builder.put("lE", Integer.valueOf('\u2266') << 16); // LESS-THAN OVER EQUAL TO
    builder.put("LessFullEqual", Integer.valueOf('\u2266') << 16); // LESS-THAN OVER EQUAL TO
    builder.put("leqq", Integer.valueOf('\u2266') << 16); // LESS-THAN OVER EQUAL TO
    builder.put("gE", Integer.valueOf('\u2267') << 16); // GREATER-THAN OVER EQUAL TO
    builder.put("GreaterFullEqual", Integer.valueOf('\u2267') << 16); // GREATER-THAN OVER EQUAL TO
    builder.put("geqq", Integer.valueOf('\u2267') << 16); // GREATER-THAN OVER EQUAL TO
    builder.put("lnE", Integer.valueOf('\u2268') << 16); // LESS-THAN BUT NOT EQUAL TO
    builder.put("lneqq", Integer.valueOf('\u2268') << 16); // LESS-THAN BUT NOT EQUAL TO
    builder.put("gnE", Integer.valueOf('\u2269') << 16); // GREATER-THAN BUT NOT EQUAL TO
    builder.put("gneqq", Integer.valueOf('\u2269') << 16); // GREATER-THAN BUT NOT EQUAL TO
    builder.put("Lt", Integer.valueOf('\u226a') << 16); // MUCH LESS-THAN
    builder.put("NestedLessLess", Integer.valueOf('\u226a') << 16); // MUCH LESS-THAN
    builder.put("ll", Integer.valueOf('\u226a') << 16); // MUCH LESS-THAN
    builder.put("Gt", Integer.valueOf('\u226b') << 16); // MUCH GREATER-THAN
    builder.put("NestedGreaterGreater", Integer.valueOf('\u226b') << 16); // MUCH GREATER-THAN
    builder.put("gg", Integer.valueOf('\u226b') << 16); // MUCH GREATER-THAN
    builder.put("twixt", Integer.valueOf('\u226c') << 16); // BETWEEN
    builder.put("between", Integer.valueOf('\u226c') << 16); // BETWEEN
    builder.put("NotCupCap", Integer.valueOf('\u226d') << 16); // NOT EQUIVALENT TO
    builder.put("nlt", Integer.valueOf('\u226e') << 16); // NOT LESS-THAN
    builder.put("NotLess", Integer.valueOf('\u226e') << 16); // NOT LESS-THAN
    builder.put("nless", Integer.valueOf('\u226e') << 16); // NOT LESS-THAN
    builder.put("ngt", Integer.valueOf('\u226f') << 16); // NOT GREATER-THAN
    builder.put("NotGreater", Integer.valueOf('\u226f') << 16); // NOT GREATER-THAN
    builder.put("ngtr", Integer.valueOf('\u226f') << 16); // NOT GREATER-THAN
    builder.put("nle", Integer.valueOf('\u2270') << 16); // NEITHER LESS-THAN NOR EQUAL TO
    builder.put("NotLessEqual", Integer.valueOf('\u2270') << 16); // NEITHER LESS-THAN NOR EQUAL TO
    builder.put("nleq", Integer.valueOf('\u2270') << 16); // NEITHER LESS-THAN NOR EQUAL TO
    builder.put("nge", Integer.valueOf('\u2271') << 16); // NEITHER GREATER-THAN NOR EQUAL TO
    builder.put("NotGreaterEqual", Integer.valueOf('\u2271') << 16); // NEITHER GREATER-THAN NOR EQUAL TO
    builder.put("ngeq", Integer.valueOf('\u2271') << 16); // NEITHER GREATER-THAN NOR EQUAL TO
    builder.put("lsim", Integer.valueOf('\u2272') << 16); // LESS-THAN OR EQUIVALENT TO
    builder.put("LessTilde", Integer.valueOf('\u2272') << 16); // LESS-THAN OR EQUIVALENT TO
    builder.put("lesssim", Integer.valueOf('\u2272') << 16); // LESS-THAN OR EQUIVALENT TO
    builder.put("gsim", Integer.valueOf('\u2273') << 16); // GREATER-THAN OR EQUIVALENT TO
    builder.put("gtrsim", Integer.valueOf('\u2273') << 16); // GREATER-THAN OR EQUIVALENT TO
    builder.put("GreaterTilde", Integer.valueOf('\u2273') << 16); // GREATER-THAN OR EQUIVALENT TO
    builder.put("nlsim", Integer.valueOf('\u2274') << 16); // NEITHER LESS-THAN NOR EQUIVALENT TO
    builder.put("NotLessTilde", Integer.valueOf('\u2274') << 16); // NEITHER LESS-THAN NOR EQUIVALENT TO
    builder.put("ngsim", Integer.valueOf('\u2275') << 16); // NEITHER GREATER-THAN NOR EQUIVALENT TO
    builder.put("NotGreaterTilde", Integer.valueOf('\u2275') << 16); // NEITHER GREATER-THAN NOR EQUIVALENT TO
    builder.put("lg", Integer.valueOf('\u2276') << 16); // LESS-THAN OR GREATER-THAN
    builder.put("lessgtr", Integer.valueOf('\u2276') << 16); // LESS-THAN OR GREATER-THAN
    builder.put("LessGreater", Integer.valueOf('\u2276') << 16); // LESS-THAN OR GREATER-THAN
    builder.put("gl", Integer.valueOf('\u2277') << 16); // GREATER-THAN OR LESS-THAN
    builder.put("gtrless", Integer.valueOf('\u2277') << 16); // GREATER-THAN OR LESS-THAN
    builder.put("GreaterLess", Integer.valueOf('\u2277') << 16); // GREATER-THAN OR LESS-THAN
    builder.put("ntlg", Integer.valueOf('\u2278') << 16); // NEITHER LESS-THAN NOR GREATER-THAN
    builder.put("NotLessGreater", Integer.valueOf('\u2278') << 16); // NEITHER LESS-THAN NOR GREATER-THAN
    builder.put("ntgl", Integer.valueOf('\u2279') << 16); // NEITHER GREATER-THAN NOR LESS-THAN
    builder.put("NotGreaterLess", Integer.valueOf('\u2279') << 16); // NEITHER GREATER-THAN NOR LESS-THAN
    builder.put("pr", Integer.valueOf('\u227a') << 16); // PRECEDES
    builder.put("Precedes", Integer.valueOf('\u227a') << 16); // PRECEDES
    builder.put("prec", Integer.valueOf('\u227a') << 16); // PRECEDES
    builder.put("sc", Integer.valueOf('\u227b') << 16); // SUCCEEDS
    builder.put("Succeeds", Integer.valueOf('\u227b') << 16); // SUCCEEDS
    builder.put("succ", Integer.valueOf('\u227b') << 16); // SUCCEEDS
    builder.put("prcue", Integer.valueOf('\u227c') << 16); // PRECEDES OR EQUAL TO
    builder.put("PrecedesSlantEqual", Integer.valueOf('\u227c') << 16); // PRECEDES OR EQUAL TO
    builder.put("preccurlyeq", Integer.valueOf('\u227c') << 16); // PRECEDES OR EQUAL TO
    builder.put("sccue", Integer.valueOf('\u227d') << 16); // SUCCEEDS OR EQUAL TO
    builder.put("SucceedsSlantEqual", Integer.valueOf('\u227d') << 16); // SUCCEEDS OR EQUAL TO
    builder.put("succcurlyeq", Integer.valueOf('\u227d') << 16); // SUCCEEDS OR EQUAL TO
    builder.put("prsim", Integer.valueOf('\u227e') << 16); // PRECEDES OR EQUIVALENT TO
    builder.put("precsim", Integer.valueOf('\u227e') << 16); // PRECEDES OR EQUIVALENT TO
    builder.put("PrecedesTilde", Integer.valueOf('\u227e') << 16); // PRECEDES OR EQUIVALENT TO
    builder.put("scsim", Integer.valueOf('\u227f') << 16); // SUCCEEDS OR EQUIVALENT TO
    builder.put("succsim", Integer.valueOf('\u227f') << 16); // SUCCEEDS OR EQUIVALENT TO
    builder.put("SucceedsTilde", Integer.valueOf('\u227f') << 16); // SUCCEEDS OR EQUIVALENT TO
    builder.put("npr", Integer.valueOf('\u2280') << 16); // DOES NOT PRECEDE
    builder.put("nprec", Integer.valueOf('\u2280') << 16); // DOES NOT PRECEDE
    builder.put("NotPrecedes", Integer.valueOf('\u2280') << 16); // DOES NOT PRECEDE
    builder.put("nsc", Integer.valueOf('\u2281') << 16); // DOES NOT SUCCEED
    builder.put("nsucc", Integer.valueOf('\u2281') << 16); // DOES NOT SUCCEED
    builder.put("NotSucceeds", Integer.valueOf('\u2281') << 16); // DOES NOT SUCCEED
    builder.put("sub", Integer.valueOf('\u2282') << 16); // SUBSET OF
    builder.put("subset", Integer.valueOf('\u2282') << 16); // SUBSET OF
    builder.put("sup", Integer.valueOf('\u2283') << 16); // SUPERSET OF
    builder.put("supset", Integer.valueOf('\u2283') << 16); // SUPERSET OF
    builder.put("Superset", Integer.valueOf('\u2283') << 16); // SUPERSET OF
    builder.put("nsub", Integer.valueOf('\u2284') << 16); // NOT A SUBSET OF
    builder.put("nsup", Integer.valueOf('\u2285') << 16); // NOT A SUPERSET OF
    builder.put("sube", Integer.valueOf('\u2286') << 16); // SUBSET OF OR EQUAL TO
    builder.put("SubsetEqual", Integer.valueOf('\u2286') << 16); // SUBSET OF OR EQUAL TO
    builder.put("subseteq", Integer.valueOf('\u2286') << 16); // SUBSET OF OR EQUAL TO
    builder.put("supe", Integer.valueOf('\u2287') << 16); // SUPERSET OF OR EQUAL TO
    builder.put("supseteq", Integer.valueOf('\u2287') << 16); // SUPERSET OF OR EQUAL TO
    builder.put("SupersetEqual", Integer.valueOf('\u2287') << 16); // SUPERSET OF OR EQUAL TO
    builder.put("nsube", Integer.valueOf('\u2288') << 16); // NEITHER A SUBSET OF NOR EQUAL TO
    builder.put("nsubseteq", Integer.valueOf('\u2288') << 16); // NEITHER A SUBSET OF NOR EQUAL TO
    builder.put("NotSubsetEqual", Integer.valueOf('\u2288') << 16); // NEITHER A SUBSET OF NOR EQUAL TO
    builder.put("nsupe", Integer.valueOf('\u2289') << 16); // NEITHER A SUPERSET OF NOR EQUAL TO
    builder.put("nsupseteq", Integer.valueOf('\u2289') << 16); // NEITHER A SUPERSET OF NOR EQUAL TO
    builder.put("NotSupersetEqual", Integer.valueOf('\u2289') << 16); // NEITHER A SUPERSET OF NOR EQUAL TO
    builder.put("subne", Integer.valueOf('\u228a') << 16); // SUBSET OF WITH NOT EQUAL TO
    builder.put("subsetneq", Integer.valueOf('\u228a') << 16); // SUBSET OF WITH NOT EQUAL TO
    builder.put("supne", Integer.valueOf('\u228b') << 16); // SUPERSET OF WITH NOT EQUAL TO
    builder.put("supsetneq", Integer.valueOf('\u228b') << 16); // SUPERSET OF WITH NOT EQUAL TO
    builder.put("cupdot", Integer.valueOf('\u228d') << 16); // MULTISET MULTIPLICATION
    builder.put("uplus", Integer.valueOf('\u228e') << 16); // MULTISET UNION
    builder.put("UnionPlus", Integer.valueOf('\u228e') << 16); // MULTISET UNION
    builder.put("sqsub", Integer.valueOf('\u228f') << 16); // SQUARE IMAGE OF
    builder.put("SquareSubset", Integer.valueOf('\u228f') << 16); // SQUARE IMAGE OF
    builder.put("sqsubset", Integer.valueOf('\u228f') << 16); // SQUARE IMAGE OF
    builder.put("sqsup", Integer.valueOf('\u2290') << 16); // SQUARE ORIGINAL OF
    builder.put("SquareSuperset", Integer.valueOf('\u2290') << 16); // SQUARE ORIGINAL OF
    builder.put("sqsupset", Integer.valueOf('\u2290') << 16); // SQUARE ORIGINAL OF
    builder.put("sqsube", Integer.valueOf('\u2291') << 16); // SQUARE IMAGE OF OR EQUAL TO
    builder.put("SquareSubsetEqual", Integer.valueOf('\u2291') << 16); // SQUARE IMAGE OF OR EQUAL TO
    builder.put("sqsubseteq", Integer.valueOf('\u2291') << 16); // SQUARE IMAGE OF OR EQUAL TO
    builder.put("sqsupe", Integer.valueOf('\u2292') << 16); // SQUARE ORIGINAL OF OR EQUAL TO
    builder.put("SquareSupersetEqual", Integer.valueOf('\u2292') << 16); // SQUARE ORIGINAL OF OR EQUAL TO
    builder.put("sqsupseteq", Integer.valueOf('\u2292') << 16); // SQUARE ORIGINAL OF OR EQUAL TO
    builder.put("sqcap", Integer.valueOf('\u2293') << 16); // SQUARE CAP
    builder.put("SquareIntersection", Integer.valueOf('\u2293') << 16); // SQUARE CAP
    builder.put("sqcup", Integer.valueOf('\u2294') << 16); // SQUARE CUP
    builder.put("SquareUnion", Integer.valueOf('\u2294') << 16); // SQUARE CUP
    builder.put("oplus", Integer.valueOf('\u2295') << 16); // CIRCLED PLUS
    builder.put("CirclePlus", Integer.valueOf('\u2295') << 16); // CIRCLED PLUS
    builder.put("ominus", Integer.valueOf('\u2296') << 16); // CIRCLED MINUS
    builder.put("CircleMinus", Integer.valueOf('\u2296') << 16); // CIRCLED MINUS
    builder.put("otimes", Integer.valueOf('\u2297') << 16); // CIRCLED TIMES
    builder.put("CircleTimes", Integer.valueOf('\u2297') << 16); // CIRCLED TIMES
    builder.put("osol", Integer.valueOf('\u2298') << 16); // CIRCLED DIVISION SLASH
    builder.put("odot", Integer.valueOf('\u2299') << 16); // CIRCLED DOT OPERATOR
    builder.put("CircleDot", Integer.valueOf('\u2299') << 16); // CIRCLED DOT OPERATOR
    builder.put("ocir", Integer.valueOf('\u229a') << 16); // CIRCLED RING OPERATOR
    builder.put("circledcirc", Integer.valueOf('\u229a') << 16); // CIRCLED RING OPERATOR
    builder.put("oast", Integer.valueOf('\u229b') << 16); // CIRCLED ASTERISK OPERATOR
    builder.put("circledast", Integer.valueOf('\u229b') << 16); // CIRCLED ASTERISK OPERATOR
    builder.put("odash", Integer.valueOf('\u229d') << 16); // CIRCLED DASH
    builder.put("circleddash", Integer.valueOf('\u229d') << 16); // CIRCLED DASH
    builder.put("plusb", Integer.valueOf('\u229e') << 16); // SQUARED PLUS
    builder.put("boxplus", Integer.valueOf('\u229e') << 16); // SQUARED PLUS
    builder.put("minusb", Integer.valueOf('\u229f') << 16); // SQUARED MINUS
    builder.put("boxminus", Integer.valueOf('\u229f') << 16); // SQUARED MINUS
    builder.put("timesb", Integer.valueOf('\u22a0') << 16); // SQUARED TIMES
    builder.put("boxtimes", Integer.valueOf('\u22a0') << 16); // SQUARED TIMES
    builder.put("sdotb", Integer.valueOf('\u22a1') << 16); // SQUARED DOT OPERATOR
    builder.put("dotsquare", Integer.valueOf('\u22a1') << 16); // SQUARED DOT OPERATOR
    builder.put("vdash", Integer.valueOf('\u22a2') << 16); // RIGHT TACK
    builder.put("RightTee", Integer.valueOf('\u22a2') << 16); // RIGHT TACK
    builder.put("dashv", Integer.valueOf('\u22a3') << 16); // LEFT TACK
    builder.put("LeftTee", Integer.valueOf('\u22a3') << 16); // LEFT TACK
    builder.put("top", Integer.valueOf('\u22a4') << 16); // DOWN TACK
    builder.put("DownTee", Integer.valueOf('\u22a4') << 16); // DOWN TACK
    builder.put("bottom", Integer.valueOf('\u22a5') << 16); // UP TACK
    builder.put("bot", Integer.valueOf('\u22a5') << 16); // UP TACK
    builder.put("perp", Integer.valueOf('\u22a5') << 16); // UP TACK
    builder.put("UpTee", Integer.valueOf('\u22a5') << 16); // UP TACK
    builder.put("models", Integer.valueOf('\u22a7') << 16); // MODELS
    builder.put("vDash", Integer.valueOf('\u22a8') << 16); // TRUE
    builder.put("DoubleRightTee", Integer.valueOf('\u22a8') << 16); // TRUE
    builder.put("Vdash", Integer.valueOf('\u22a9') << 16); // FORCES
    builder.put("Vvdash", Integer.valueOf('\u22aa') << 16); // TRIPLE VERTICAL BAR RIGHT TURNSTILE
    builder.put("VDash", Integer.valueOf('\u22ab') << 16); // DOUBLE VERTICAL BAR DOUBLE RIGHT TURNSTILE
    builder.put("nvdash", Integer.valueOf('\u22ac') << 16); // DOES NOT PROVE
    builder.put("nvDash", Integer.valueOf('\u22ad') << 16); // NOT TRUE
    builder.put("nVdash", Integer.valueOf('\u22ae') << 16); // DOES NOT FORCE
    builder.put("nVDash", Integer.valueOf('\u22af') << 16); // NEGATED DOUBLE VERTICAL BAR DOUBLE RIGHT TURNSTILE
    builder.put("prurel", Integer.valueOf('\u22b0') << 16); // PRECEDES UNDER RELATION
    builder.put("vltri", Integer.valueOf('\u22b2') << 16); // NORMAL SUBGROUP OF
    builder.put("vartriangleleft", Integer.valueOf('\u22b2') << 16); // NORMAL SUBGROUP OF
    builder.put("LeftTriangle", Integer.valueOf('\u22b2') << 16); // NORMAL SUBGROUP OF
    builder.put("vrtri", Integer.valueOf('\u22b3') << 16); // CONTAINS AS NORMAL SUBGROUP
    builder.put("vartriangleright", Integer.valueOf('\u22b3') << 16); // CONTAINS AS NORMAL SUBGROUP
    builder.put("RightTriangle", Integer.valueOf('\u22b3') << 16); // CONTAINS AS NORMAL SUBGROUP
    builder.put("ltrie", Integer.valueOf('\u22b4') << 16); // NORMAL SUBGROUP OF OR EQUAL TO
    builder.put("trianglelefteq", Integer.valueOf('\u22b4') << 16); // NORMAL SUBGROUP OF OR EQUAL TO
    builder.put("LeftTriangleEqual", Integer.valueOf('\u22b4') << 16); // NORMAL SUBGROUP OF OR EQUAL TO
    builder.put("rtrie", Integer.valueOf('\u22b5') << 16); // CONTAINS AS NORMAL SUBGROUP OR EQUAL TO
    builder.put("trianglerighteq", Integer.valueOf('\u22b5') << 16); // CONTAINS AS NORMAL SUBGROUP OR EQUAL TO
    builder.put("RightTriangleEqual", Integer.valueOf('\u22b5') << 16); // CONTAINS AS NORMAL SUBGROUP OR EQUAL TO
    builder.put("origof", Integer.valueOf('\u22b6') << 16); // ORIGINAL OF
    builder.put("imof", Integer.valueOf('\u22b7') << 16); // IMAGE OF
    builder.put("mumap", Integer.valueOf('\u22b8') << 16); // MULTIMAP
    builder.put("multimap", Integer.valueOf('\u22b8') << 16); // MULTIMAP
    builder.put("hercon", Integer.valueOf('\u22b9') << 16); // HERMITIAN CONJUGATE MATRIX
    builder.put("intcal", Integer.valueOf('\u22ba') << 16); // INTERCALATE
    builder.put("intercal", Integer.valueOf('\u22ba') << 16); // INTERCALATE
    builder.put("veebar", Integer.valueOf('\u22bb') << 16); // XOR
    builder.put("barvee", Integer.valueOf('\u22bd') << 16); // NOR
    builder.put("angrtvb", Integer.valueOf('\u22be') << 16); // RIGHT ANGLE WITH ARC
    builder.put("lrtri", Integer.valueOf('\u22bf') << 16); // RIGHT TRIANGLE
    builder.put("xwedge", Integer.valueOf('\u22c0') << 16); // N-ARY LOGICAL AND
    builder.put("Wedge", Integer.valueOf('\u22c0') << 16); // N-ARY LOGICAL AND
    builder.put("bigwedge", Integer.valueOf('\u22c0') << 16); // N-ARY LOGICAL AND
    builder.put("xvee", Integer.valueOf('\u22c1') << 16); // N-ARY LOGICAL OR
    builder.put("Vee", Integer.valueOf('\u22c1') << 16); // N-ARY LOGICAL OR
    builder.put("bigvee", Integer.valueOf('\u22c1') << 16); // N-ARY LOGICAL OR
    builder.put("xcap", Integer.valueOf('\u22c2') << 16); // N-ARY INTERSECTION
    builder.put("Intersection", Integer.valueOf('\u22c2') << 16); // N-ARY INTERSECTION
    builder.put("bigcap", Integer.valueOf('\u22c2') << 16); // N-ARY INTERSECTION
    builder.put("xcup", Integer.valueOf('\u22c3') << 16); // N-ARY UNION
    builder.put("Union", Integer.valueOf('\u22c3') << 16); // N-ARY UNION
    builder.put("bigcup", Integer.valueOf('\u22c3') << 16); // N-ARY UNION
    builder.put("diam", Integer.valueOf('\u22c4') << 16); // DIAMOND OPERATOR
    builder.put("diamond", Integer.valueOf('\u22c4') << 16); // DIAMOND OPERATOR
    builder.put("Diamond", Integer.valueOf('\u22c4') << 16); // DIAMOND OPERATOR
    builder.put("sdot", Integer.valueOf('\u22c5') << 16); // DOT OPERATOR
    builder.put("sstarf", Integer.valueOf('\u22c6') << 16); // STAR OPERATOR
    builder.put("Star", Integer.valueOf('\u22c6') << 16); // STAR OPERATOR
    builder.put("divonx", Integer.valueOf('\u22c7') << 16); // DIVISION TIMES
    builder.put("divideontimes", Integer.valueOf('\u22c7') << 16); // DIVISION TIMES
    builder.put("bowtie", Integer.valueOf('\u22c8') << 16); // BOWTIE
    builder.put("ltimes", Integer.valueOf('\u22c9') << 16); // LEFT NORMAL FACTOR SEMIDIRECT PRODUCT
    builder.put("rtimes", Integer.valueOf('\u22ca') << 16); // RIGHT NORMAL FACTOR SEMIDIRECT PRODUCT
    builder.put("lthree", Integer.valueOf('\u22cb') << 16); // LEFT SEMIDIRECT PRODUCT
    builder.put("leftthreetimes", Integer.valueOf('\u22cb') << 16); // LEFT SEMIDIRECT PRODUCT
    builder.put("rthree", Integer.valueOf('\u22cc') << 16); // RIGHT SEMIDIRECT PRODUCT
    builder.put("rightthreetimes", Integer.valueOf('\u22cc') << 16); // RIGHT SEMIDIRECT PRODUCT
    builder.put("bsime", Integer.valueOf('\u22cd') << 16); // REVERSED TILDE EQUALS
    builder.put("backsimeq", Integer.valueOf('\u22cd') << 16); // REVERSED TILDE EQUALS
    builder.put("cuvee", Integer.valueOf('\u22ce') << 16); // CURLY LOGICAL OR
    builder.put("curlyvee", Integer.valueOf('\u22ce') << 16); // CURLY LOGICAL OR
    builder.put("cuwed", Integer.valueOf('\u22cf') << 16); // CURLY LOGICAL AND
    builder.put("curlywedge", Integer.valueOf('\u22cf') << 16); // CURLY LOGICAL AND
    builder.put("Sub", Integer.valueOf('\u22d0') << 16); // DOUBLE SUBSET
    builder.put("Subset", Integer.valueOf('\u22d0') << 16); // DOUBLE SUBSET
    builder.put("Sup", Integer.valueOf('\u22d1') << 16); // DOUBLE SUPERSET
    builder.put("Supset", Integer.valueOf('\u22d1') << 16); // DOUBLE SUPERSET
    builder.put("Cap", Integer.valueOf('\u22d2') << 16); // DOUBLE INTERSECTION
    builder.put("Cup", Integer.valueOf('\u22d3') << 16); // DOUBLE UNION
    builder.put("fork", Integer.valueOf('\u22d4') << 16); // PITCHFORK
    builder.put("pitchfork", Integer.valueOf('\u22d4') << 16); // PITCHFORK
    builder.put("epar", Integer.valueOf('\u22d5') << 16); // EQUAL AND PARALLEL TO
    builder.put("ltdot", Integer.valueOf('\u22d6') << 16); // LESS-THAN WITH DOT
    builder.put("lessdot", Integer.valueOf('\u22d6') << 16); // LESS-THAN WITH DOT
    builder.put("gtdot", Integer.valueOf('\u22d7') << 16); // GREATER-THAN WITH DOT
    builder.put("gtrdot", Integer.valueOf('\u22d7') << 16); // GREATER-THAN WITH DOT
    builder.put("Ll", Integer.valueOf('\u22d8') << 16); // VERY MUCH LESS-THAN
    builder.put("Gg", Integer.valueOf('\u22d9') << 16); // VERY MUCH GREATER-THAN
    builder.put("ggg", Integer.valueOf('\u22d9') << 16); // VERY MUCH GREATER-THAN
    builder.put("leg", Integer.valueOf('\u22da') << 16); // LESS-THAN EQUAL TO OR GREATER-THAN
    builder.put("LessEqualGreater", Integer.valueOf('\u22da') << 16); // LESS-THAN EQUAL TO OR GREATER-THAN
    builder.put("lesseqgtr", Integer.valueOf('\u22da') << 16); // LESS-THAN EQUAL TO OR GREATER-THAN
    builder.put("gel", Integer.valueOf('\u22db') << 16); // GREATER-THAN EQUAL TO OR LESS-THAN
    builder.put("gtreqless", Integer.valueOf('\u22db') << 16); // GREATER-THAN EQUAL TO OR LESS-THAN
    builder.put("GreaterEqualLess", Integer.valueOf('\u22db') << 16); // GREATER-THAN EQUAL TO OR LESS-THAN
    builder.put("cuepr", Integer.valueOf('\u22de') << 16); // EQUAL TO OR PRECEDES
    builder.put("curlyeqprec", Integer.valueOf('\u22de') << 16); // EQUAL TO OR PRECEDES
    builder.put("cuesc", Integer.valueOf('\u22df') << 16); // EQUAL TO OR SUCCEEDS
    builder.put("curlyeqsucc", Integer.valueOf('\u22df') << 16); // EQUAL TO OR SUCCEEDS
    builder.put("nprcue", Integer.valueOf('\u22e0') << 16); // DOES NOT PRECEDE OR EQUAL
    builder.put("NotPrecedesSlantEqual", Integer.valueOf('\u22e0') << 16); // DOES NOT PRECEDE OR EQUAL
    builder.put("nsccue", Integer.valueOf('\u22e1') << 16); // DOES NOT SUCCEED OR EQUAL
    builder.put("NotSucceedsSlantEqual", Integer.valueOf('\u22e1') << 16); // DOES NOT SUCCEED OR EQUAL
    builder.put("nsqsube", Integer.valueOf('\u22e2') << 16); // NOT SQUARE IMAGE OF OR EQUAL TO
    builder.put("NotSquareSubsetEqual", Integer.valueOf('\u22e2') << 16); // NOT SQUARE IMAGE OF OR EQUAL TO
    builder.put("nsqsupe", Integer.valueOf('\u22e3') << 16); // NOT SQUARE ORIGINAL OF OR EQUAL TO
    builder.put("NotSquareSupersetEqual", Integer.valueOf('\u22e3') << 16); // NOT SQUARE ORIGINAL OF OR EQUAL TO
    builder.put("lnsim", Integer.valueOf('\u22e6') << 16); // LESS-THAN BUT NOT EQUIVALENT TO
    builder.put("gnsim", Integer.valueOf('\u22e7') << 16); // GREATER-THAN BUT NOT EQUIVALENT TO
    builder.put("prnsim", Integer.valueOf('\u22e8') << 16); // PRECEDES BUT NOT EQUIVALENT TO
    builder.put("precnsim", Integer.valueOf('\u22e8') << 16); // PRECEDES BUT NOT EQUIVALENT TO
    builder.put("scnsim", Integer.valueOf('\u22e9') << 16); // SUCCEEDS BUT NOT EQUIVALENT TO
    builder.put("succnsim", Integer.valueOf('\u22e9') << 16); // SUCCEEDS BUT NOT EQUIVALENT TO
    builder.put("nltri", Integer.valueOf('\u22ea') << 16); // NOT NORMAL SUBGROUP OF
    builder.put("ntriangleleft", Integer.valueOf('\u22ea') << 16); // NOT NORMAL SUBGROUP OF
    builder.put("NotLeftTriangle", Integer.valueOf('\u22ea') << 16); // NOT NORMAL SUBGROUP OF
    builder.put("nrtri", Integer.valueOf('\u22eb') << 16); // DOES NOT CONTAIN AS NORMAL SUBGROUP
    builder.put("ntriangleright", Integer.valueOf('\u22eb') << 16); // DOES NOT CONTAIN AS NORMAL SUBGROUP
    builder.put("NotRightTriangle", Integer.valueOf('\u22eb') << 16); // DOES NOT CONTAIN AS NORMAL SUBGROUP
    builder.put("nltrie", Integer.valueOf('\u22ec') << 16); // NOT NORMAL SUBGROUP OF OR EQUAL TO
    builder.put("ntrianglelefteq", Integer.valueOf('\u22ec') << 16); // NOT NORMAL SUBGROUP OF OR EQUAL TO
    builder.put("NotLeftTriangleEqual", Integer.valueOf('\u22ec') << 16); // NOT NORMAL SUBGROUP OF OR EQUAL TO
    builder.put("nrtrie", Integer.valueOf('\u22ed') << 16); // DOES NOT CONTAIN AS NORMAL SUBGROUP OR EQUAL
    builder.put("ntrianglerighteq", Integer.valueOf('\u22ed') << 16); // DOES NOT CONTAIN AS NORMAL SUBGROUP OR EQUAL
    builder.put("NotRightTriangleEqual", Integer.valueOf('\u22ed') << 16); // DOES NOT CONTAIN AS NORMAL SUBGROUP OR EQUAL
    builder.put("vellip", Integer.valueOf('\u22ee') << 16); // VERTICAL ELLIPSIS
    builder.put("ctdot", Integer.valueOf('\u22ef') << 16); // MIDLINE HORIZONTAL ELLIPSIS
    builder.put("utdot", Integer.valueOf('\u22f0') << 16); // UP RIGHT DIAGONAL ELLIPSIS
    builder.put("dtdot", Integer.valueOf('\u22f1') << 16); // DOWN RIGHT DIAGONAL ELLIPSIS
    builder.put("disin", Integer.valueOf('\u22f2') << 16); // ELEMENT OF WITH LONG HORIZONTAL STROKE
    builder.put("isinsv", Integer.valueOf('\u22f3') << 16); // ELEMENT OF WITH VERTICAL BAR AT END OF HORIZONTAL STROKE
    builder.put("isins", Integer.valueOf('\u22f4') << 16); // SMALL ELEMENT OF WITH VERTICAL BAR AT END OF HORIZONTAL STROKE
    builder.put("isindot", Integer.valueOf('\u22f5') << 16); // ELEMENT OF WITH DOT ABOVE
    builder.put("notinvc", Integer.valueOf('\u22f6') << 16); // ELEMENT OF WITH OVERBAR
    builder.put("notinvb", Integer.valueOf('\u22f7') << 16); // SMALL ELEMENT OF WITH OVERBAR
    builder.put("isinE", Integer.valueOf('\u22f9') << 16); // ELEMENT OF WITH TWO HORIZONTAL STROKES
    builder.put("nisd", Integer.valueOf('\u22fa') << 16); // CONTAINS WITH LONG HORIZONTAL STROKE
    builder.put("xnis", Integer.valueOf('\u22fb') << 16); // CONTAINS WITH VERTICAL BAR AT END OF HORIZONTAL STROKE
    builder.put("nis", Integer.valueOf('\u22fc') << 16); // SMALL CONTAINS WITH VERTICAL BAR AT END OF HORIZONTAL STROKE
    builder.put("notnivc", Integer.valueOf('\u22fd') << 16); // CONTAINS WITH OVERBAR
    builder.put("notnivb", Integer.valueOf('\u22fe') << 16); // SMALL CONTAINS WITH OVERBAR

    // Miscellaneous Technical
    builder.put("barwed", Integer.valueOf('\u2305') << 16); // PROJECTIVE
    builder.put("barwedge", Integer.valueOf('\u2305') << 16); // PROJECTIVE
    builder.put("Barwed", Integer.valueOf('\u2306') << 16); // PERSPECTIVE
    builder.put("doublebarwedge", Integer.valueOf('\u2306') << 16); // PERSPECTIVE
    builder.put("lceil", Integer.valueOf('\u2308') << 16); // LEFT CEILING
    builder.put("LeftCeiling", Integer.valueOf('\u2308') << 16); // LEFT CEILING
    builder.put("rceil", Integer.valueOf('\u2309') << 16); // RIGHT CEILING
    builder.put("RightCeiling", Integer.valueOf('\u2309') << 16); // RIGHT CEILING
    builder.put("lfloor", Integer.valueOf('\u230a') << 16); // LEFT FLOOR
    builder.put("LeftFloor", Integer.valueOf('\u230a') << 16); // LEFT FLOOR
    builder.put("rfloor", Integer.valueOf('\u230b') << 16); // RIGHT FLOOR
    builder.put("RightFloor", Integer.valueOf('\u230b') << 16); // RIGHT FLOOR
    builder.put("drcrop", Integer.valueOf('\u230c') << 16); // BOTTOM RIGHT CROP
    builder.put("dlcrop", Integer.valueOf('\u230d') << 16); // BOTTOM LEFT CROP
    builder.put("urcrop", Integer.valueOf('\u230e') << 16); // TOP RIGHT CROP
    builder.put("ulcrop", Integer.valueOf('\u230f') << 16); // TOP LEFT CROP
    builder.put("bnot", Integer.valueOf('\u2310') << 16); // REVERSED NOT SIGN
    builder.put("profline", Integer.valueOf('\u2312') << 16); // ARC
    builder.put("profsurf", Integer.valueOf('\u2313') << 16); // SEGMENT
    builder.put("telrec", Integer.valueOf('\u2315') << 16); // TELEPHONE RECORDER
    builder.put("target", Integer.valueOf('\u2316') << 16); // POSITION INDICATOR
    builder.put("ulcorn", Integer.valueOf('\u231c') << 16); // TOP LEFT CORNER
    builder.put("ulcorner", Integer.valueOf('\u231c') << 16); // TOP LEFT CORNER
    builder.put("urcorn", Integer.valueOf('\u231d') << 16); // TOP RIGHT CORNER
    builder.put("urcorner", Integer.valueOf('\u231d') << 16); // TOP RIGHT CORNER
    builder.put("dlcorn", Integer.valueOf('\u231e') << 16); // BOTTOM LEFT CORNER
    builder.put("llcorner", Integer.valueOf('\u231e') << 16); // BOTTOM LEFT CORNER
    builder.put("drcorn", Integer.valueOf('\u231f') << 16); // BOTTOM RIGHT CORNER
    builder.put("lrcorner", Integer.valueOf('\u231f') << 16); // BOTTOM RIGHT CORNER
    builder.put("frown", Integer.valueOf('\u2322') << 16); // FROWN
    builder.put("sfrown", Integer.valueOf('\u2322') << 16); // FROWN
    builder.put("smile", Integer.valueOf('\u2323') << 16); // SMILE
    builder.put("ssmile", Integer.valueOf('\u2323') << 16); // SMILE
    builder.put("cylcty", Integer.valueOf('\u232d') << 16); // CYLINDRICITY
    builder.put("profalar", Integer.valueOf('\u232e') << 16); // ALL AROUND-PROFILE
    builder.put("topbot", Integer.valueOf('\u2336') << 16); // APL FUNCTIONAL SYMBOL I-BEAM
    builder.put("ovbar", Integer.valueOf('\u233d') << 16); // APL FUNCTIONAL SYMBOL CIRCLE STILE
    builder.put("solbar", Integer.valueOf('\u233f') << 16); // APL FUNCTIONAL SYMBOL SLASH BAR
    builder.put("angzarr", Integer.valueOf('\u237c') << 16); // RIGHT ANGLE WITH DOWNWARDS ZIGZAG ARROW
    builder.put("lmoust", Integer.valueOf('\u23b0') << 16); // UPPER LEFT OR LOWER RIGHT CURLY BRACKET SECTION
    builder.put("lmoustache", Integer.valueOf('\u23b0') << 16); // UPPER LEFT OR LOWER RIGHT CURLY BRACKET SECTION
    builder.put("rmoust", Integer.valueOf('\u23b1') << 16); // UPPER RIGHT OR LOWER LEFT CURLY BRACKET SECTION
    builder.put("rmoustache", Integer.valueOf('\u23b1') << 16); // UPPER RIGHT OR LOWER LEFT CURLY BRACKET SECTION
    builder.put("tbrk", Integer.valueOf('\u23b4') << 16); // TOP SQUARE BRACKET
    builder.put("OverBracket", Integer.valueOf('\u23b4') << 16); // TOP SQUARE BRACKET
    builder.put("bbrk", Integer.valueOf('\u23b5') << 16); // BOTTOM SQUARE BRACKET
    builder.put("UnderBracket", Integer.valueOf('\u23b5') << 16); // BOTTOM SQUARE BRACKET
    builder.put("bbrktbrk", Integer.valueOf('\u23b6') << 16); // BOTTOM SQUARE BRACKET OVER TOP SQUARE BRACKET
    builder.put("OverParenthesis", Integer.valueOf('\u23dc') << 16); // TOP PARENTHESIS
    builder.put("UnderParenthesis", Integer.valueOf('\u23dd') << 16); // BOTTOM PARENTHESIS
    builder.put("OverBrace", Integer.valueOf('\u23de') << 16); // TOP CURLY BRACKET
    builder.put("UnderBrace", Integer.valueOf('\u23df') << 16); // BOTTOM CURLY BRACKET
    builder.put("trpezium", Integer.valueOf('\u23e2') << 16); // WHITE TRAPEZIUM
    builder.put("elinters", Integer.valueOf('\u23e7') << 16); // ELECTRICAL INTERSECTION

    // Control Pictures
    builder.put("blank", Integer.valueOf('\u2423') << 16); // OPEN BOX

    // Enclosed Alphanumerics
    builder.put("oS", Integer.valueOf('\u24c8') << 16); // CIRCLED LATIN CAPITAL LETTER S
    builder.put("circledS", Integer.valueOf('\u24c8') << 16); // CIRCLED LATIN CAPITAL LETTER S

    // Box Drawing
    builder.put("boxh", Integer.valueOf('\u2500') << 16); // BOX DRAWINGS LIGHT HORIZONTAL
    builder.put("HorizontalLine", Integer.valueOf('\u2500') << 16); // BOX DRAWINGS LIGHT HORIZONTAL
    builder.put("boxv", Integer.valueOf('\u2502') << 16); // BOX DRAWINGS LIGHT VERTICAL
    builder.put("boxdr", Integer.valueOf('\u250c') << 16); // BOX DRAWINGS LIGHT DOWN AND RIGHT
    builder.put("boxdl", Integer.valueOf('\u2510') << 16); // BOX DRAWINGS LIGHT DOWN AND LEFT
    builder.put("boxur", Integer.valueOf('\u2514') << 16); // BOX DRAWINGS LIGHT UP AND RIGHT
    builder.put("boxul", Integer.valueOf('\u2518') << 16); // BOX DRAWINGS LIGHT UP AND LEFT
    builder.put("boxvr", Integer.valueOf('\u251c') << 16); // BOX DRAWINGS LIGHT VERTICAL AND RIGHT
    builder.put("boxvl", Integer.valueOf('\u2524') << 16); // BOX DRAWINGS LIGHT VERTICAL AND LEFT
    builder.put("boxhd", Integer.valueOf('\u252c') << 16); // BOX DRAWINGS LIGHT DOWN AND HORIZONTAL
    builder.put("boxhu", Integer.valueOf('\u2534') << 16); // BOX DRAWINGS LIGHT UP AND HORIZONTAL
    builder.put("boxvh", Integer.valueOf('\u253c') << 16); // BOX DRAWINGS LIGHT VERTICAL AND HORIZONTAL
    builder.put("boxH", Integer.valueOf('\u2550') << 16); // BOX DRAWINGS DOUBLE HORIZONTAL
    builder.put("boxV", Integer.valueOf('\u2551') << 16); // BOX DRAWINGS DOUBLE VERTICAL
    builder.put("boxdR", Integer.valueOf('\u2552') << 16); // BOX DRAWINGS DOWN SINGLE AND RIGHT DOUBLE
    builder.put("boxDr", Integer.valueOf('\u2553') << 16); // BOX DRAWINGS DOWN DOUBLE AND RIGHT SINGLE
    builder.put("boxDR", Integer.valueOf('\u2554') << 16); // BOX DRAWINGS DOUBLE DOWN AND RIGHT
    builder.put("boxdL", Integer.valueOf('\u2555') << 16); // BOX DRAWINGS DOWN SINGLE AND LEFT DOUBLE
    builder.put("boxDl", Integer.valueOf('\u2556') << 16); // BOX DRAWINGS DOWN DOUBLE AND LEFT SINGLE
    builder.put("boxDL", Integer.valueOf('\u2557') << 16); // BOX DRAWINGS DOUBLE DOWN AND LEFT
    builder.put("boxuR", Integer.valueOf('\u2558') << 16); // BOX DRAWINGS UP SINGLE AND RIGHT DOUBLE
    builder.put("boxUr", Integer.valueOf('\u2559') << 16); // BOX DRAWINGS UP DOUBLE AND RIGHT SINGLE
    builder.put("boxUR", Integer.valueOf('\u255a') << 16); // BOX DRAWINGS DOUBLE UP AND RIGHT
    builder.put("boxuL", Integer.valueOf('\u255b') << 16); // BOX DRAWINGS UP SINGLE AND LEFT DOUBLE
    builder.put("boxUl", Integer.valueOf('\u255c') << 16); // BOX DRAWINGS UP DOUBLE AND LEFT SINGLE
    builder.put("boxUL", Integer.valueOf('\u255d') << 16); // BOX DRAWINGS DOUBLE UP AND LEFT
    builder.put("boxvR", Integer.valueOf('\u255e') << 16); // BOX DRAWINGS VERTICAL SINGLE AND RIGHT DOUBLE
    builder.put("boxVr", Integer.valueOf('\u255f') << 16); // BOX DRAWINGS VERTICAL DOUBLE AND RIGHT SINGLE
    builder.put("boxVR", Integer.valueOf('\u2560') << 16); // BOX DRAWINGS DOUBLE VERTICAL AND RIGHT
    builder.put("boxvL", Integer.valueOf('\u2561') << 16); // BOX DRAWINGS VERTICAL SINGLE AND LEFT DOUBLE
    builder.put("boxVl", Integer.valueOf('\u2562') << 16); // BOX DRAWINGS VERTICAL DOUBLE AND LEFT SINGLE
    builder.put("boxVL", Integer.valueOf('\u2563') << 16); // BOX DRAWINGS DOUBLE VERTICAL AND LEFT
    builder.put("boxHd", Integer.valueOf('\u2564') << 16); // BOX DRAWINGS DOWN SINGLE AND HORIZONTAL DOUBLE
    builder.put("boxhD", Integer.valueOf('\u2565') << 16); // BOX DRAWINGS DOWN DOUBLE AND HORIZONTAL SINGLE
    builder.put("boxHD", Integer.valueOf('\u2566') << 16); // BOX DRAWINGS DOUBLE DOWN AND HORIZONTAL
    builder.put("boxHu", Integer.valueOf('\u2567') << 16); // BOX DRAWINGS UP SINGLE AND HORIZONTAL DOUBLE
    builder.put("boxhU", Integer.valueOf('\u2568') << 16); // BOX DRAWINGS UP DOUBLE AND HORIZONTAL SINGLE
    builder.put("boxHU", Integer.valueOf('\u2569') << 16); // BOX DRAWINGS DOUBLE UP AND HORIZONTAL
    builder.put("boxvH", Integer.valueOf('\u256a') << 16); // BOX DRAWINGS VERTICAL SINGLE AND HORIZONTAL DOUBLE
    builder.put("boxVh", Integer.valueOf('\u256b') << 16); // BOX DRAWINGS VERTICAL DOUBLE AND HORIZONTAL SINGLE
    builder.put("boxVH", Integer.valueOf('\u256c') << 16); // BOX DRAWINGS DOUBLE VERTICAL AND HORIZONTAL

    // Block Elements
    builder.put("uhblk", Integer.valueOf('\u2580') << 16); // UPPER HALF BLOCK
    builder.put("lhblk", Integer.valueOf('\u2584') << 16); // LOWER HALF BLOCK
    builder.put("block", Integer.valueOf('\u2588') << 16); // FULL BLOCK
    builder.put("blk14", Integer.valueOf('\u2591') << 16); // LIGHT SHADE
    builder.put("blk12", Integer.valueOf('\u2592') << 16); // MEDIUM SHADE
    builder.put("blk34", Integer.valueOf('\u2593') << 16); // DARK SHADE

    // Geometric Shapes
    builder.put("squ", Integer.valueOf('\u25a1') << 16); // WHITE SQUARE
    builder.put("square", Integer.valueOf('\u25a1') << 16); // WHITE SQUARE
    builder.put("Square", Integer.valueOf('\u25a1') << 16); // WHITE SQUARE
    builder.put("squf", Integer.valueOf('\u25aa') << 16); // BLACK SMALL SQUARE
    builder.put("squarf", Integer.valueOf('\u25aa') << 16); // BLACK SMALL SQUARE
    builder.put("blacksquare", Integer.valueOf('\u25aa') << 16); // BLACK SMALL SQUARE
    builder.put("FilledVerySmallSquare", Integer.valueOf('\u25aa') << 16); // BLACK SMALL SQUARE
    builder.put("EmptyVerySmallSquare", Integer.valueOf('\u25ab') << 16); // WHITE SMALL SQUARE
    builder.put("rect", Integer.valueOf('\u25ad') << 16); // WHITE RECTANGLE
    builder.put("marker", Integer.valueOf('\u25ae') << 16); // BLACK VERTICAL RECTANGLE
    builder.put("fltns", Integer.valueOf('\u25b1') << 16); // WHITE PARALLELOGRAM
    builder.put("xutri", Integer.valueOf('\u25b3') << 16); // WHITE UP-POINTING TRIANGLE
    builder.put("bigtriangleup", Integer.valueOf('\u25b3') << 16); // WHITE UP-POINTING TRIANGLE
    builder.put("utrif", Integer.valueOf('\u25b4') << 16); // BLACK UP-POINTING SMALL TRIANGLE
    builder.put("blacktriangle", Integer.valueOf('\u25b4') << 16); // BLACK UP-POINTING SMALL TRIANGLE
    builder.put("utri", Integer.valueOf('\u25b5') << 16); // WHITE UP-POINTING SMALL TRIANGLE
    builder.put("triangle", Integer.valueOf('\u25b5') << 16); // WHITE UP-POINTING SMALL TRIANGLE
    builder.put("rtrif", Integer.valueOf('\u25b8') << 16); // BLACK RIGHT-POINTING SMALL TRIANGLE
    builder.put("blacktriangleright", Integer.valueOf('\u25b8') << 16); // BLACK RIGHT-POINTING SMALL TRIANGLE
    builder.put("rtri", Integer.valueOf('\u25b9') << 16); // WHITE RIGHT-POINTING SMALL TRIANGLE
    builder.put("triangleright", Integer.valueOf('\u25b9') << 16); // WHITE RIGHT-POINTING SMALL TRIANGLE
    builder.put("xdtri", Integer.valueOf('\u25bd') << 16); // WHITE DOWN-POINTING TRIANGLE
    builder.put("bigtriangledown", Integer.valueOf('\u25bd') << 16); // WHITE DOWN-POINTING TRIANGLE
    builder.put("dtrif", Integer.valueOf('\u25be') << 16); // BLACK DOWN-POINTING SMALL TRIANGLE
    builder.put("blacktriangledown", Integer.valueOf('\u25be') << 16); // BLACK DOWN-POINTING SMALL TRIANGLE
    builder.put("dtri", Integer.valueOf('\u25bf') << 16); // WHITE DOWN-POINTING SMALL TRIANGLE
    builder.put("triangledown", Integer.valueOf('\u25bf') << 16); // WHITE DOWN-POINTING SMALL TRIANGLE
    builder.put("ltrif", Integer.valueOf('\u25c2') << 16); // BLACK LEFT-POINTING SMALL TRIANGLE
    builder.put("blacktriangleleft", Integer.valueOf('\u25c2') << 16); // BLACK LEFT-POINTING SMALL TRIANGLE
    builder.put("ltri", Integer.valueOf('\u25c3') << 16); // WHITE LEFT-POINTING SMALL TRIANGLE
    builder.put("triangleleft", Integer.valueOf('\u25c3') << 16); // WHITE LEFT-POINTING SMALL TRIANGLE
    builder.put("loz", Integer.valueOf('\u25ca') << 16); // LOZENGE
    builder.put("lozenge", Integer.valueOf('\u25ca') << 16); // LOZENGE
    builder.put("cir", Integer.valueOf('\u25cb') << 16); // WHITE CIRCLE
    builder.put("tridot", Integer.valueOf('\u25ec') << 16); // WHITE UP-POINTING TRIANGLE WITH DOT
    builder.put("xcirc", Integer.valueOf('\u25ef') << 16); // LARGE CIRCLE
    builder.put("bigcirc", Integer.valueOf('\u25ef') << 16); // LARGE CIRCLE
    builder.put("ultri", Integer.valueOf('\u25f8') << 16); // UPPER LEFT TRIANGLE
    builder.put("urtri", Integer.valueOf('\u25f9') << 16); // UPPER RIGHT TRIANGLE
    builder.put("lltri", Integer.valueOf('\u25fa') << 16); // LOWER LEFT TRIANGLE
    builder.put("EmptySmallSquare", Integer.valueOf('\u25fb') << 16); // WHITE MEDIUM SQUARE
    builder.put("FilledSmallSquare", Integer.valueOf('\u25fc') << 16); // BLACK MEDIUM SQUARE

    // Miscellaneous Symbols
    builder.put("starf", Integer.valueOf('\u2605') << 16); // BLACK STAR
    builder.put("bigstar", Integer.valueOf('\u2605') << 16); // BLACK STAR
    builder.put("star", Integer.valueOf('\u2606') << 16); // WHITE STAR
    builder.put("phone", Integer.valueOf('\u260e') << 16); // BLACK TELEPHONE
    builder.put("female", Integer.valueOf('\u2640') << 16); // FEMALE SIGN
    builder.put("male", Integer.valueOf('\u2642') << 16); // MALE SIGN
    builder.put("spades", Integer.valueOf('\u2660') << 16); // BLACK SPADE SUIT
    builder.put("spadesuit", Integer.valueOf('\u2660') << 16); // BLACK SPADE SUIT
    builder.put("clubs", Integer.valueOf('\u2663') << 16); // BLACK CLUB SUIT
    builder.put("clubsuit", Integer.valueOf('\u2663') << 16); // BLACK CLUB SUIT
    builder.put("hearts", Integer.valueOf('\u2665') << 16); // BLACK HEART SUIT
    builder.put("heartsuit", Integer.valueOf('\u2665') << 16); // BLACK HEART SUIT
    builder.put("diams", Integer.valueOf('\u2666') << 16); // BLACK DIAMOND SUIT
    builder.put("diamondsuit", Integer.valueOf('\u2666') << 16); // BLACK DIAMOND SUIT
    builder.put("sung", Integer.valueOf('\u266a') << 16); // EIGHTH NOTE
    builder.put("flat", Integer.valueOf('\u266d') << 16); // MUSIC FLAT SIGN
    builder.put("natur", Integer.valueOf('\u266e') << 16); // MUSIC NATURAL SIGN
    builder.put("natural", Integer.valueOf('\u266e') << 16); // MUSIC NATURAL SIGN
    builder.put("sharp", Integer.valueOf('\u266f') << 16); // MUSIC SHARP SIGN

    // Dingbats
    builder.put("check", Integer.valueOf('\u2713') << 16); // CHECK MARK
    builder.put("checkmark", Integer.valueOf('\u2713') << 16); // CHECK MARK
    builder.put("cross", Integer.valueOf('\u2717') << 16); // BALLOT X
    builder.put("malt", Integer.valueOf('\u2720') << 16); // MALTESE CROSS
    builder.put("maltese", Integer.valueOf('\u2720') << 16); // MALTESE CROSS
    builder.put("sext", Integer.valueOf('\u2736') << 16); // SIX POINTED BLACK STAR
    builder.put("VerticalSeparator", Integer.valueOf('\u2758') << 16); // LIGHT VERTICAL BAR
    builder.put("lbbrk", Integer.valueOf('\u2772') << 16); // LIGHT LEFT TORTOISE SHELL BRACKET ORNAMENT
    builder.put("rbbrk", Integer.valueOf('\u2773') << 16); // LIGHT RIGHT TORTOISE SHELL BRACKET ORNAMENT

    // Miscellaneous Mathematical Symbols-A
    builder.put("lobrk", Integer.valueOf('\u27e6') << 16); // MATHEMATICAL LEFT WHITE SQUARE BRACKET
    builder.put("LeftDoubleBracket", Integer.valueOf('\u27e6') << 16); // MATHEMATICAL LEFT WHITE SQUARE BRACKET
    builder.put("robrk", Integer.valueOf('\u27e7') << 16); // MATHEMATICAL RIGHT WHITE SQUARE BRACKET
    builder.put("RightDoubleBracket", Integer.valueOf('\u27e7') << 16); // MATHEMATICAL RIGHT WHITE SQUARE BRACKET
    builder.put("lang", Integer.valueOf('\u27e8') << 16); // MATHEMATICAL LEFT ANGLE BRACKET
    builder.put("LeftAngleBracket", Integer.valueOf('\u27e8') << 16); // MATHEMATICAL LEFT ANGLE BRACKET
    builder.put("langle", Integer.valueOf('\u27e8') << 16); // MATHEMATICAL LEFT ANGLE BRACKET
    builder.put("rang", Integer.valueOf('\u27e9') << 16); // MATHEMATICAL RIGHT ANGLE BRACKET
    builder.put("RightAngleBracket", Integer.valueOf('\u27e9') << 16); // MATHEMATICAL RIGHT ANGLE BRACKET
    builder.put("rangle", Integer.valueOf('\u27e9') << 16); // MATHEMATICAL RIGHT ANGLE BRACKET
    builder.put("Lang", Integer.valueOf('\u27ea') << 16); // MATHEMATICAL LEFT DOUBLE ANGLE BRACKET
    builder.put("Rang", Integer.valueOf('\u27eb') << 16); // MATHEMATICAL RIGHT DOUBLE ANGLE BRACKET
    builder.put("loang", Integer.valueOf('\u27ec') << 16); // MATHEMATICAL LEFT WHITE TORTOISE SHELL BRACKET
    builder.put("roang", Integer.valueOf('\u27ed') << 16); // MATHEMATICAL RIGHT WHITE TORTOISE SHELL BRACKET

    // Supplemental Arrows-A
    builder.put("xlarr", Integer.valueOf('\u27f5') << 16); // LONG LEFTWARDS ARROW
    builder.put("longleftarrow", Integer.valueOf('\u27f5') << 16); // LONG LEFTWARDS ARROW
    builder.put("LongLeftArrow", Integer.valueOf('\u27f5') << 16); // LONG LEFTWARDS ARROW
    builder.put("xrarr", Integer.valueOf('\u27f6') << 16); // LONG RIGHTWARDS ARROW
    builder.put("longrightarrow", Integer.valueOf('\u27f6') << 16); // LONG RIGHTWARDS ARROW
    builder.put("LongRightArrow", Integer.valueOf('\u27f6') << 16); // LONG RIGHTWARDS ARROW
    builder.put("xharr", Integer.valueOf('\u27f7') << 16); // LONG LEFT RIGHT ARROW
    builder.put("longleftrightarrow", Integer.valueOf('\u27f7') << 16); // LONG LEFT RIGHT ARROW
    builder.put("LongLeftRightArrow", Integer.valueOf('\u27f7') << 16); // LONG LEFT RIGHT ARROW
    builder.put("xlArr", Integer.valueOf('\u27f8') << 16); // LONG LEFTWARDS DOUBLE ARROW
    builder.put("Longleftarrow", Integer.valueOf('\u27f8') << 16); // LONG LEFTWARDS DOUBLE ARROW
    builder.put("DoubleLongLeftArrow", Integer.valueOf('\u27f8') << 16); // LONG LEFTWARDS DOUBLE ARROW
    builder.put("xrArr", Integer.valueOf('\u27f9') << 16); // LONG RIGHTWARDS DOUBLE ARROW
    builder.put("Longrightarrow", Integer.valueOf('\u27f9') << 16); // LONG RIGHTWARDS DOUBLE ARROW
    builder.put("DoubleLongRightArrow", Integer.valueOf('\u27f9') << 16); // LONG RIGHTWARDS DOUBLE ARROW
    builder.put("xhArr", Integer.valueOf('\u27fa') << 16); // LONG LEFT RIGHT DOUBLE ARROW
    builder.put("Longleftrightarrow", Integer.valueOf('\u27fa') << 16); // LONG LEFT RIGHT DOUBLE ARROW
    builder.put("DoubleLongLeftRightArrow", Integer.valueOf('\u27fa') << 16); // LONG LEFT RIGHT DOUBLE ARROW
    builder.put("xmap", Integer.valueOf('\u27fc') << 16); // LONG RIGHTWARDS ARROW FROM BAR
    builder.put("longmapsto", Integer.valueOf('\u27fc') << 16); // LONG RIGHTWARDS ARROW FROM BAR
    builder.put("dzigrarr", Integer.valueOf('\u27ff') << 16); // LONG RIGHTWARDS SQUIGGLE ARROW

    // Supplemental Arrows-B
    builder.put("nvlArr", Integer.valueOf('\u2902') << 16); // LEFTWARDS DOUBLE ARROW WITH VERTICAL STROKE
    builder.put("nvrArr", Integer.valueOf('\u2903') << 16); // RIGHTWARDS DOUBLE ARROW WITH VERTICAL STROKE
    builder.put("nvHarr", Integer.valueOf('\u2904') << 16); // LEFT RIGHT DOUBLE ARROW WITH VERTICAL STROKE
    builder.put("Map", Integer.valueOf('\u2905') << 16); // RIGHTWARDS TWO-HEADED ARROW FROM BAR
    builder.put("lbarr", Integer.valueOf('\u290c') << 16); // LEFTWARDS DOUBLE DASH ARROW
    builder.put("rbarr", Integer.valueOf('\u290d') << 16); // RIGHTWARDS DOUBLE DASH ARROW
    builder.put("bkarow", Integer.valueOf('\u290d') << 16); // RIGHTWARDS DOUBLE DASH ARROW
    builder.put("lBarr", Integer.valueOf('\u290e') << 16); // LEFTWARDS TRIPLE DASH ARROW
    builder.put("rBarr", Integer.valueOf('\u290f') << 16); // RIGHTWARDS TRIPLE DASH ARROW
    builder.put("dbkarow", Integer.valueOf('\u290f') << 16); // RIGHTWARDS TRIPLE DASH ARROW
    builder.put("RBarr", Integer.valueOf('\u2910') << 16); // RIGHTWARDS TWO-HEADED TRIPLE DASH ARROW
    builder.put("drbkarow", Integer.valueOf('\u2910') << 16); // RIGHTWARDS TWO-HEADED TRIPLE DASH ARROW
    builder.put("DDotrahd", Integer.valueOf('\u2911') << 16); // RIGHTWARDS ARROW WITH DOTTED STEM
    builder.put("UpArrowBar", Integer.valueOf('\u2912') << 16); // UPWARDS ARROW TO BAR
    builder.put("DownArrowBar", Integer.valueOf('\u2913') << 16); // DOWNWARDS ARROW TO BAR
    builder.put("Rarrtl", Integer.valueOf('\u2916') << 16); // RIGHTWARDS TWO-HEADED ARROW WITH TAIL
    builder.put("latail", Integer.valueOf('\u2919') << 16); // LEFTWARDS ARROW-TAIL
    builder.put("ratail", Integer.valueOf('\u291a') << 16); // RIGHTWARDS ARROW-TAIL
    builder.put("lAtail", Integer.valueOf('\u291b') << 16); // LEFTWARDS DOUBLE ARROW-TAIL
    builder.put("rAtail", Integer.valueOf('\u291c') << 16); // RIGHTWARDS DOUBLE ARROW-TAIL
    builder.put("larrfs", Integer.valueOf('\u291d') << 16); // LEFTWARDS ARROW TO BLACK DIAMOND
    builder.put("rarrfs", Integer.valueOf('\u291e') << 16); // RIGHTWARDS ARROW TO BLACK DIAMOND
    builder.put("larrbfs", Integer.valueOf('\u291f') << 16); // LEFTWARDS ARROW FROM BAR TO BLACK DIAMOND
    builder.put("rarrbfs", Integer.valueOf('\u2920') << 16); // RIGHTWARDS ARROW FROM BAR TO BLACK DIAMOND
    builder.put("nwarhk", Integer.valueOf('\u2923') << 16); // NORTH WEST ARROW WITH HOOK
    builder.put("nearhk", Integer.valueOf('\u2924') << 16); // NORTH EAST ARROW WITH HOOK
    builder.put("searhk", Integer.valueOf('\u2925') << 16); // SOUTH EAST ARROW WITH HOOK
    builder.put("hksearow", Integer.valueOf('\u2925') << 16); // SOUTH EAST ARROW WITH HOOK
    builder.put("swarhk", Integer.valueOf('\u2926') << 16); // SOUTH WEST ARROW WITH HOOK
    builder.put("hkswarow", Integer.valueOf('\u2926') << 16); // SOUTH WEST ARROW WITH HOOK
    builder.put("nwnear", Integer.valueOf('\u2927') << 16); // NORTH WEST ARROW AND NORTH EAST ARROW
    builder.put("nesear", Integer.valueOf('\u2928') << 16); // NORTH EAST ARROW AND SOUTH EAST ARROW
    builder.put("toea", Integer.valueOf('\u2928') << 16); // NORTH EAST ARROW AND SOUTH EAST ARROW
    builder.put("seswar", Integer.valueOf('\u2929') << 16); // SOUTH EAST ARROW AND SOUTH WEST ARROW
    builder.put("tosa", Integer.valueOf('\u2929') << 16); // SOUTH EAST ARROW AND SOUTH WEST ARROW
    builder.put("swnwar", Integer.valueOf('\u292a') << 16); // SOUTH WEST ARROW AND NORTH WEST ARROW
    builder.put("rarrc", Integer.valueOf('\u2933') << 16); // WAVE ARROW POINTING DIRECTLY RIGHT
    builder.put("cudarrr", Integer.valueOf('\u2935') << 16); // ARROW POINTING RIGHTWARDS THEN CURVING DOWNWARDS
    builder.put("ldca", Integer.valueOf('\u2936') << 16); // ARROW POINTING DOWNWARDS THEN CURVING LEFTWARDS
    builder.put("rdca", Integer.valueOf('\u2937') << 16); // ARROW POINTING DOWNWARDS THEN CURVING RIGHTWARDS
    builder.put("cudarrl", Integer.valueOf('\u2938') << 16); // RIGHT-SIDE ARC CLOCKWISE ARROW
    builder.put("larrpl", Integer.valueOf('\u2939') << 16); // LEFT-SIDE ARC ANTICLOCKWISE ARROW
    builder.put("curarrm", Integer.valueOf('\u293c') << 16); // TOP ARC CLOCKWISE ARROW WITH MINUS
    builder.put("cularrp", Integer.valueOf('\u293d') << 16); // TOP ARC ANTICLOCKWISE ARROW WITH PLUS
    builder.put("rarrpl", Integer.valueOf('\u2945') << 16); // RIGHTWARDS ARROW WITH PLUS BELOW
    builder.put("harrcir", Integer.valueOf('\u2948') << 16); // LEFT RIGHT ARROW THROUGH SMALL CIRCLE
    builder.put("Uarrocir", Integer.valueOf('\u2949') << 16); // UPWARDS TWO-HEADED ARROW FROM SMALL CIRCLE
    builder.put("lurdshar", Integer.valueOf('\u294a') << 16); // LEFT BARB UP RIGHT BARB DOWN HARPOON
    builder.put("ldrushar", Integer.valueOf('\u294b') << 16); // LEFT BARB DOWN RIGHT BARB UP HARPOON
    builder.put("LeftRightVector", Integer.valueOf('\u294e') << 16); // LEFT BARB UP RIGHT BARB UP HARPOON
    builder.put("RightUpDownVector", Integer.valueOf('\u294f') << 16); // UP BARB RIGHT DOWN BARB RIGHT HARPOON
    builder.put("DownLeftRightVector", Integer.valueOf('\u2950') << 16); // LEFT BARB DOWN RIGHT BARB DOWN HARPOON
    builder.put("LeftUpDownVector", Integer.valueOf('\u2951') << 16); // UP BARB LEFT DOWN BARB LEFT HARPOON
    builder.put("LeftVectorBar", Integer.valueOf('\u2952') << 16); // LEFTWARDS HARPOON WITH BARB UP TO BAR
    builder.put("RightVectorBar", Integer.valueOf('\u2953') << 16); // RIGHTWARDS HARPOON WITH BARB UP TO BAR
    builder.put("RightUpVectorBar", Integer.valueOf('\u2954') << 16); // UPWARDS HARPOON WITH BARB RIGHT TO BAR
    builder.put("RightDownVectorBar", Integer.valueOf('\u2955') << 16); // DOWNWARDS HARPOON WITH BARB RIGHT TO BAR
    builder.put("DownLeftVectorBar", Integer.valueOf('\u2956') << 16); // LEFTWARDS HARPOON WITH BARB DOWN TO BAR
    builder.put("DownRightVectorBar", Integer.valueOf('\u2957') << 16); // RIGHTWARDS HARPOON WITH BARB DOWN TO BAR
    builder.put("LeftUpVectorBar", Integer.valueOf('\u2958') << 16); // UPWARDS HARPOON WITH BARB LEFT TO BAR
    builder.put("LeftDownVectorBar", Integer.valueOf('\u2959') << 16); // DOWNWARDS HARPOON WITH BARB LEFT TO BAR
    builder.put("LeftTeeVector", Integer.valueOf('\u295a') << 16); // LEFTWARDS HARPOON WITH BARB UP FROM BAR
    builder.put("RightTeeVector", Integer.valueOf('\u295b') << 16); // RIGHTWARDS HARPOON WITH BARB UP FROM BAR
    builder.put("RightUpTeeVector", Integer.valueOf('\u295c') << 16); // UPWARDS HARPOON WITH BARB RIGHT FROM BAR
    builder.put("RightDownTeeVector", Integer.valueOf('\u295d') << 16); // DOWNWARDS HARPOON WITH BARB RIGHT FROM BAR
    builder.put("DownLeftTeeVector", Integer.valueOf('\u295e') << 16); // LEFTWARDS HARPOON WITH BARB DOWN FROM BAR
    builder.put("DownRightTeeVector", Integer.valueOf('\u295f') << 16); // RIGHTWARDS HARPOON WITH BARB DOWN FROM BAR
    builder.put("LeftUpTeeVector", Integer.valueOf('\u2960') << 16); // UPWARDS HARPOON WITH BARB LEFT FROM BAR
    builder.put("LeftDownTeeVector", Integer.valueOf('\u2961') << 16); // DOWNWARDS HARPOON WITH BARB LEFT FROM BAR
    builder.put("lHar", Integer.valueOf('\u2962') << 16); // LEFTWARDS HARPOON WITH BARB UP ABOVE LEFTWARDS HARPOON WITH BARB DOWN
    builder.put("uHar", Integer.valueOf('\u2963') << 16); // UPWARDS HARPOON WITH BARB LEFT BESIDE UPWARDS HARPOON WITH BARB RIGHT
    builder.put("rHar", Integer.valueOf('\u2964') << 16); // RIGHTWARDS HARPOON WITH BARB UP ABOVE RIGHTWARDS HARPOON WITH BARB DOWN
    builder.put("dHar", Integer.valueOf('\u2965') << 16); // DOWNWARDS HARPOON WITH BARB LEFT BESIDE DOWNWARDS HARPOON WITH BARB RIGHT
    builder.put("luruhar", Integer.valueOf('\u2966') << 16); // LEFTWARDS HARPOON WITH BARB UP ABOVE RIGHTWARDS HARPOON WITH BARB UP
    builder.put("ldrdhar", Integer.valueOf('\u2967') << 16); // LEFTWARDS HARPOON WITH BARB DOWN ABOVE RIGHTWARDS HARPOON WITH BARB DOWN
    builder.put("ruluhar", Integer.valueOf('\u2968') << 16); // RIGHTWARDS HARPOON WITH BARB UP ABOVE LEFTWARDS HARPOON WITH BARB UP
    builder.put("rdldhar", Integer.valueOf('\u2969') << 16); // RIGHTWARDS HARPOON WITH BARB DOWN ABOVE LEFTWARDS HARPOON WITH BARB DOWN
    builder.put("lharul", Integer.valueOf('\u296a') << 16); // LEFTWARDS HARPOON WITH BARB UP ABOVE LONG DASH
    builder.put("llhard", Integer.valueOf('\u296b') << 16); // LEFTWARDS HARPOON WITH BARB DOWN BELOW LONG DASH
    builder.put("rharul", Integer.valueOf('\u296c') << 16); // RIGHTWARDS HARPOON WITH BARB UP ABOVE LONG DASH
    builder.put("lrhard", Integer.valueOf('\u296d') << 16); // RIGHTWARDS HARPOON WITH BARB DOWN BELOW LONG DASH
    builder.put("udhar", Integer.valueOf('\u296e') << 16); // UPWARDS HARPOON WITH BARB LEFT BESIDE DOWNWARDS HARPOON WITH BARB RIGHT
    builder.put("UpEquilibrium", Integer.valueOf('\u296e') << 16); // UPWARDS HARPOON WITH BARB LEFT BESIDE DOWNWARDS HARPOON WITH BARB RIGHT
    builder.put("duhar", Integer.valueOf('\u296f') << 16); // DOWNWARDS HARPOON WITH BARB LEFT BESIDE UPWARDS HARPOON WITH BARB RIGHT
    builder.put("ReverseUpEquilibrium", Integer.valueOf('\u296f') << 16); // DOWNWARDS HARPOON WITH BARB LEFT BESIDE UPWARDS HARPOON WITH BARB RIGHT
    builder.put("RoundImplies", Integer.valueOf('\u2970') << 16); // RIGHT DOUBLE ARROW WITH ROUNDED HEAD
    builder.put("erarr", Integer.valueOf('\u2971') << 16); // EQUALS SIGN ABOVE RIGHTWARDS ARROW
    builder.put("simrarr", Integer.valueOf('\u2972') << 16); // TILDE OPERATOR ABOVE RIGHTWARDS ARROW
    builder.put("larrsim", Integer.valueOf('\u2973') << 16); // LEFTWARDS ARROW ABOVE TILDE OPERATOR
    builder.put("rarrsim", Integer.valueOf('\u2974') << 16); // RIGHTWARDS ARROW ABOVE TILDE OPERATOR
    builder.put("rarrap", Integer.valueOf('\u2975') << 16); // RIGHTWARDS ARROW ABOVE ALMOST EQUAL TO
    builder.put("ltlarr", Integer.valueOf('\u2976') << 16); // LESS-THAN ABOVE LEFTWARDS ARROW
    builder.put("gtrarr", Integer.valueOf('\u2978') << 16); // GREATER-THAN ABOVE RIGHTWARDS ARROW
    builder.put("subrarr", Integer.valueOf('\u2979') << 16); // SUBSET ABOVE RIGHTWARDS ARROW
    builder.put("suplarr", Integer.valueOf('\u297b') << 16); // SUPERSET ABOVE LEFTWARDS ARROW
    builder.put("lfisht", Integer.valueOf('\u297c') << 16); // LEFT FISH TAIL
    builder.put("rfisht", Integer.valueOf('\u297d') << 16); // RIGHT FISH TAIL
    builder.put("ufisht", Integer.valueOf('\u297e') << 16); // UP FISH TAIL
    builder.put("dfisht", Integer.valueOf('\u297f') << 16); // DOWN FISH TAIL

    // Miscellaneous Mathematical Symbols-B
    builder.put("lopar", Integer.valueOf('\u2985') << 16); // LEFT WHITE PARENTHESIS
    builder.put("ropar", Integer.valueOf('\u2986') << 16); // RIGHT WHITE PARENTHESIS
    builder.put("lbrke", Integer.valueOf('\u298b') << 16); // LEFT SQUARE BRACKET WITH UNDERBAR
    builder.put("rbrke", Integer.valueOf('\u298c') << 16); // RIGHT SQUARE BRACKET WITH UNDERBAR
    builder.put("lbrkslu", Integer.valueOf('\u298d') << 16); // LEFT SQUARE BRACKET WITH TICK IN TOP CORNER
    builder.put("rbrksld", Integer.valueOf('\u298e') << 16); // RIGHT SQUARE BRACKET WITH TICK IN BOTTOM CORNER
    builder.put("lbrksld", Integer.valueOf('\u298f') << 16); // LEFT SQUARE BRACKET WITH TICK IN BOTTOM CORNER
    builder.put("rbrkslu", Integer.valueOf('\u2990') << 16); // RIGHT SQUARE BRACKET WITH TICK IN TOP CORNER
    builder.put("langd", Integer.valueOf('\u2991') << 16); // LEFT ANGLE BRACKET WITH DOT
    builder.put("rangd", Integer.valueOf('\u2992') << 16); // RIGHT ANGLE BRACKET WITH DOT
    builder.put("lparlt", Integer.valueOf('\u2993') << 16); // LEFT ARC LESS-THAN BRACKET
    builder.put("rpargt", Integer.valueOf('\u2994') << 16); // RIGHT ARC GREATER-THAN BRACKET
    builder.put("gtlPar", Integer.valueOf('\u2995') << 16); // DOUBLE LEFT ARC GREATER-THAN BRACKET
    builder.put("ltrPar", Integer.valueOf('\u2996') << 16); // DOUBLE RIGHT ARC LESS-THAN BRACKET
    builder.put("vzigzag", Integer.valueOf('\u299a') << 16); // VERTICAL ZIGZAG LINE
    builder.put("vangrt", Integer.valueOf('\u299c') << 16); // RIGHT ANGLE VARIANT WITH SQUARE
    builder.put("angrtvbd", Integer.valueOf('\u299d') << 16); // MEASURED RIGHT ANGLE WITH DOT
    builder.put("ange", Integer.valueOf('\u29a4') << 16); // ANGLE WITH UNDERBAR
    builder.put("range", Integer.valueOf('\u29a5') << 16); // REVERSED ANGLE WITH UNDERBAR
    builder.put("dwangle", Integer.valueOf('\u29a6') << 16); // OBLIQUE ANGLE OPENING UP
    builder.put("uwangle", Integer.valueOf('\u29a7') << 16); // OBLIQUE ANGLE OPENING DOWN
    builder.put("angmsdaa", Integer.valueOf('\u29a8') << 16); // MEASURED ANGLE WITH OPEN ARM ENDING IN ARROW POINTING UP AND RIGHT
    builder.put("angmsdab", Integer.valueOf('\u29a9') << 16); // MEASURED ANGLE WITH OPEN ARM ENDING IN ARROW POINTING UP AND LEFT
    builder.put("angmsdac", Integer.valueOf('\u29aa') << 16); // MEASURED ANGLE WITH OPEN ARM ENDING IN ARROW POINTING DOWN AND RIGHT
    builder.put("angmsdad", Integer.valueOf('\u29ab') << 16); // MEASURED ANGLE WITH OPEN ARM ENDING IN ARROW POINTING DOWN AND LEFT
    builder.put("angmsdae", Integer.valueOf('\u29ac') << 16); // MEASURED ANGLE WITH OPEN ARM ENDING IN ARROW POINTING RIGHT AND UP
    builder.put("angmsdaf", Integer.valueOf('\u29ad') << 16); // MEASURED ANGLE WITH OPEN ARM ENDING IN ARROW POINTING LEFT AND UP
    builder.put("angmsdag", Integer.valueOf('\u29ae') << 16); // MEASURED ANGLE WITH OPEN ARM ENDING IN ARROW POINTING RIGHT AND DOWN
    builder.put("angmsdah", Integer.valueOf('\u29af') << 16); // MEASURED ANGLE WITH OPEN ARM ENDING IN ARROW POINTING LEFT AND DOWN
    builder.put("bemptyv", Integer.valueOf('\u29b0') << 16); // REVERSED EMPTY SET
    builder.put("demptyv", Integer.valueOf('\u29b1') << 16); // EMPTY SET WITH OVERBAR
    builder.put("cemptyv", Integer.valueOf('\u29b2') << 16); // EMPTY SET WITH SMALL CIRCLE ABOVE
    builder.put("raemptyv", Integer.valueOf('\u29b3') << 16); // EMPTY SET WITH RIGHT ARROW ABOVE
    builder.put("laemptyv", Integer.valueOf('\u29b4') << 16); // EMPTY SET WITH LEFT ARROW ABOVE
    builder.put("ohbar", Integer.valueOf('\u29b5') << 16); // CIRCLE WITH HORIZONTAL BAR
    builder.put("omid", Integer.valueOf('\u29b6') << 16); // CIRCLED VERTICAL BAR
    builder.put("opar", Integer.valueOf('\u29b7') << 16); // CIRCLED PARALLEL
    builder.put("operp", Integer.valueOf('\u29b9') << 16); // CIRCLED PERPENDICULAR
    builder.put("olcross", Integer.valueOf('\u29bb') << 16); // CIRCLE WITH SUPERIMPOSED X
    builder.put("odsold", Integer.valueOf('\u29bc') << 16); // CIRCLED ANTICLOCKWISE-ROTATED DIVISION SIGN
    builder.put("olcir", Integer.valueOf('\u29be') << 16); // CIRCLED WHITE BULLET
    builder.put("ofcir", Integer.valueOf('\u29bf') << 16); // CIRCLED BULLET
    builder.put("olt", Integer.valueOf('\u29c0') << 16); // CIRCLED LESS-THAN
    builder.put("ogt", Integer.valueOf('\u29c1') << 16); // CIRCLED GREATER-THAN
    builder.put("cirscir", Integer.valueOf('\u29c2') << 16); // CIRCLE WITH SMALL CIRCLE TO THE RIGHT
    builder.put("cirE", Integer.valueOf('\u29c3') << 16); // CIRCLE WITH TWO HORIZONTAL STROKES TO THE RIGHT
    builder.put("solb", Integer.valueOf('\u29c4') << 16); // SQUARED RISING DIAGONAL SLASH
    builder.put("bsolb", Integer.valueOf('\u29c5') << 16); // SQUARED FALLING DIAGONAL SLASH
    builder.put("boxbox", Integer.valueOf('\u29c9') << 16); // TWO JOINED SQUARES
    builder.put("trisb", Integer.valueOf('\u29cd') << 16); // TRIANGLE WITH SERIFS AT BOTTOM
    builder.put("rtriltri", Integer.valueOf('\u29ce') << 16); // RIGHT TRIANGLE ABOVE LEFT TRIANGLE
    builder.put("LeftTriangleBar", Integer.valueOf('\u29cf') << 16); // LEFT TRIANGLE BESIDE VERTICAL BAR
    builder.put("RightTriangleBar", Integer.valueOf('\u29d0') << 16); // VERTICAL BAR BESIDE RIGHT TRIANGLE
    builder.put("race", Integer.valueOf('\u29da') << 16); // LEFT DOUBLE WIGGLY FENCE
    builder.put("iinfin", Integer.valueOf('\u29dc') << 16); // INCOMPLETE INFINITY
    builder.put("infintie", Integer.valueOf('\u29dd') << 16); // TIE OVER INFINITY
    builder.put("nvinfin", Integer.valueOf('\u29de') << 16); // INFINITY NEGATED WITH VERTICAL BAR
    builder.put("eparsl", Integer.valueOf('\u29e3') << 16); // EQUALS SIGN AND SLANTED PARALLEL
    builder.put("smeparsl", Integer.valueOf('\u29e4') << 16); // EQUALS SIGN AND SLANTED PARALLEL WITH TILDE ABOVE
    builder.put("eqvparsl", Integer.valueOf('\u29e5') << 16); // IDENTICAL TO AND SLANTED PARALLEL
    builder.put("lozf", Integer.valueOf('\u29eb') << 16); // BLACK LOZENGE
    builder.put("blacklozenge", Integer.valueOf('\u29eb') << 16); // BLACK LOZENGE
    builder.put("RuleDelayed", Integer.valueOf('\u29f4') << 16); // RULE-DELAYED
    builder.put("dsol", Integer.valueOf('\u29f6') << 16); // SOLIDUS WITH OVERBAR

    // Supplemental Mathematical Operators
    builder.put("xodot", Integer.valueOf('\u2a00') << 16); // N-ARY CIRCLED DOT OPERATOR
    builder.put("bigodot", Integer.valueOf('\u2a00') << 16); // N-ARY CIRCLED DOT OPERATOR
    builder.put("xoplus", Integer.valueOf('\u2a01') << 16); // N-ARY CIRCLED PLUS OPERATOR
    builder.put("bigoplus", Integer.valueOf('\u2a01') << 16); // N-ARY CIRCLED PLUS OPERATOR
    builder.put("xotime", Integer.valueOf('\u2a02') << 16); // N-ARY CIRCLED TIMES OPERATOR
    builder.put("bigotimes", Integer.valueOf('\u2a02') << 16); // N-ARY CIRCLED TIMES OPERATOR
    builder.put("xuplus", Integer.valueOf('\u2a04') << 16); // N-ARY UNION OPERATOR WITH PLUS
    builder.put("biguplus", Integer.valueOf('\u2a04') << 16); // N-ARY UNION OPERATOR WITH PLUS
    builder.put("xsqcup", Integer.valueOf('\u2a06') << 16); // N-ARY SQUARE UNION OPERATOR
    builder.put("bigsqcup", Integer.valueOf('\u2a06') << 16); // N-ARY SQUARE UNION OPERATOR
    builder.put("qint", Integer.valueOf('\u2a0c') << 16); // QUADRUPLE INTEGRAL OPERATOR
    builder.put("iiiint", Integer.valueOf('\u2a0c') << 16); // QUADRUPLE INTEGRAL OPERATOR
    builder.put("fpartint", Integer.valueOf('\u2a0d') << 16); // FINITE PART INTEGRAL
    builder.put("cirfnint", Integer.valueOf('\u2a10') << 16); // CIRCULATION FUNCTION
    builder.put("awint", Integer.valueOf('\u2a11') << 16); // ANTICLOCKWISE INTEGRATION
    builder.put("rppolint", Integer.valueOf('\u2a12') << 16); // LINE INTEGRATION WITH RECTANGULAR PATH AROUND POLE
    builder.put("scpolint", Integer.valueOf('\u2a13') << 16); // LINE INTEGRATION WITH SEMICIRCULAR PATH AROUND POLE
    builder.put("npolint", Integer.valueOf('\u2a14') << 16); // LINE INTEGRATION NOT INCLUDING THE POLE
    builder.put("pointint", Integer.valueOf('\u2a15') << 16); // INTEGRAL AROUND A POINT OPERATOR
    builder.put("quatint", Integer.valueOf('\u2a16') << 16); // QUATERNION INTEGRAL OPERATOR
    builder.put("intlarhk", Integer.valueOf('\u2a17') << 16); // INTEGRAL WITH LEFTWARDS ARROW WITH HOOK
    builder.put("pluscir", Integer.valueOf('\u2a22') << 16); // PLUS SIGN WITH SMALL CIRCLE ABOVE
    builder.put("plusacir", Integer.valueOf('\u2a23') << 16); // PLUS SIGN WITH CIRCUMFLEX ACCENT ABOVE
    builder.put("simplus", Integer.valueOf('\u2a24') << 16); // PLUS SIGN WITH TILDE ABOVE
    builder.put("plusdu", Integer.valueOf('\u2a25') << 16); // PLUS SIGN WITH DOT BELOW
    builder.put("plussim", Integer.valueOf('\u2a26') << 16); // PLUS SIGN WITH TILDE BELOW
    builder.put("plustwo", Integer.valueOf('\u2a27') << 16); // PLUS SIGN WITH SUBSCRIPT TWO
    builder.put("mcomma", Integer.valueOf('\u2a29') << 16); // MINUS SIGN WITH COMMA ABOVE
    builder.put("minusdu", Integer.valueOf('\u2a2a') << 16); // MINUS SIGN WITH DOT BELOW
    builder.put("loplus", Integer.valueOf('\u2a2d') << 16); // PLUS SIGN IN LEFT HALF CIRCLE
    builder.put("roplus", Integer.valueOf('\u2a2e') << 16); // PLUS SIGN IN RIGHT HALF CIRCLE
    builder.put("Cross", Integer.valueOf('\u2a2f') << 16); // VECTOR OR CROSS PRODUCT
    builder.put("timesd", Integer.valueOf('\u2a30') << 16); // MULTIPLICATION SIGN WITH DOT ABOVE
    builder.put("timesbar", Integer.valueOf('\u2a31') << 16); // MULTIPLICATION SIGN WITH UNDERBAR
    builder.put("smashp", Integer.valueOf('\u2a33') << 16); // SMASH PRODUCT
    builder.put("lotimes", Integer.valueOf('\u2a34') << 16); // MULTIPLICATION SIGN IN LEFT HALF CIRCLE
    builder.put("rotimes", Integer.valueOf('\u2a35') << 16); // MULTIPLICATION SIGN IN RIGHT HALF CIRCLE
    builder.put("otimesas", Integer.valueOf('\u2a36') << 16); // CIRCLED MULTIPLICATION SIGN WITH CIRCUMFLEX ACCENT
    builder.put("Otimes", Integer.valueOf('\u2a37') << 16); // MULTIPLICATION SIGN IN DOUBLE CIRCLE
    builder.put("odiv", Integer.valueOf('\u2a38') << 16); // CIRCLED DIVISION SIGN
    builder.put("triplus", Integer.valueOf('\u2a39') << 16); // PLUS SIGN IN TRIANGLE
    builder.put("triminus", Integer.valueOf('\u2a3a') << 16); // MINUS SIGN IN TRIANGLE
    builder.put("tritime", Integer.valueOf('\u2a3b') << 16); // MULTIPLICATION SIGN IN TRIANGLE
    builder.put("iprod", Integer.valueOf('\u2a3c') << 16); // INTERIOR PRODUCT
    builder.put("intprod", Integer.valueOf('\u2a3c') << 16); // INTERIOR PRODUCT
    builder.put("amalg", Integer.valueOf('\u2a3f') << 16); // AMALGAMATION OR COPRODUCT
    builder.put("capdot", Integer.valueOf('\u2a40') << 16); // INTERSECTION WITH DOT
    builder.put("ncup", Integer.valueOf('\u2a42') << 16); // UNION WITH OVERBAR
    builder.put("ncap", Integer.valueOf('\u2a43') << 16); // INTERSECTION WITH OVERBAR
    builder.put("capand", Integer.valueOf('\u2a44') << 16); // INTERSECTION WITH LOGICAL AND
    builder.put("cupor", Integer.valueOf('\u2a45') << 16); // UNION WITH LOGICAL OR
    builder.put("cupcap", Integer.valueOf('\u2a46') << 16); // UNION ABOVE INTERSECTION
    builder.put("capcup", Integer.valueOf('\u2a47') << 16); // INTERSECTION ABOVE UNION
    builder.put("cupbrcap", Integer.valueOf('\u2a48') << 16); // UNION ABOVE BAR ABOVE INTERSECTION
    builder.put("capbrcup", Integer.valueOf('\u2a49') << 16); // INTERSECTION ABOVE BAR ABOVE UNION
    builder.put("cupcup", Integer.valueOf('\u2a4a') << 16); // UNION BESIDE AND JOINED WITH UNION
    builder.put("capcap", Integer.valueOf('\u2a4b') << 16); // INTERSECTION BESIDE AND JOINED WITH INTERSECTION
    builder.put("ccups", Integer.valueOf('\u2a4c') << 16); // CLOSED UNION WITH SERIFS
    builder.put("ccaps", Integer.valueOf('\u2a4d') << 16); // CLOSED INTERSECTION WITH SERIFS
    builder.put("ccupssm", Integer.valueOf('\u2a50') << 16); // CLOSED UNION WITH SERIFS AND SMASH PRODUCT
    builder.put("And", Integer.valueOf('\u2a53') << 16); // DOUBLE LOGICAL AND
    builder.put("Or", Integer.valueOf('\u2a54') << 16); // DOUBLE LOGICAL OR
    builder.put("andand", Integer.valueOf('\u2a55') << 16); // TWO INTERSECTING LOGICAL AND
    builder.put("oror", Integer.valueOf('\u2a56') << 16); // TWO INTERSECTING LOGICAL OR
    builder.put("orslope", Integer.valueOf('\u2a57') << 16); // SLOPING LARGE OR
    builder.put("andslope", Integer.valueOf('\u2a58') << 16); // SLOPING LARGE AND
    builder.put("andv", Integer.valueOf('\u2a5a') << 16); // LOGICAL AND WITH MIDDLE STEM
    builder.put("orv", Integer.valueOf('\u2a5b') << 16); // LOGICAL OR WITH MIDDLE STEM
    builder.put("andd", Integer.valueOf('\u2a5c') << 16); // LOGICAL AND WITH HORIZONTAL DASH
    builder.put("ord", Integer.valueOf('\u2a5d') << 16); // LOGICAL OR WITH HORIZONTAL DASH
    builder.put("wedbar", Integer.valueOf('\u2a5f') << 16); // LOGICAL AND WITH UNDERBAR
    builder.put("sdote", Integer.valueOf('\u2a66') << 16); // EQUALS SIGN WITH DOT BELOW
    builder.put("simdot", Integer.valueOf('\u2a6a') << 16); // TILDE OPERATOR WITH DOT ABOVE
    builder.put("congdot", Integer.valueOf('\u2a6d') << 16); // CONGRUENT WITH DOT ABOVE
    builder.put("easter", Integer.valueOf('\u2a6e') << 16); // EQUALS WITH ASTERISK
    builder.put("apacir", Integer.valueOf('\u2a6f') << 16); // ALMOST EQUAL TO WITH CIRCUMFLEX ACCENT
    builder.put("apE", Integer.valueOf('\u2a70') << 16); // APPROXIMATELY EQUAL OR EQUAL TO
    builder.put("eplus", Integer.valueOf('\u2a71') << 16); // EQUALS SIGN ABOVE PLUS SIGN
    builder.put("pluse", Integer.valueOf('\u2a72') << 16); // PLUS SIGN ABOVE EQUALS SIGN
    builder.put("Esim", Integer.valueOf('\u2a73') << 16); // EQUALS SIGN ABOVE TILDE OPERATOR
    builder.put("Colone", Integer.valueOf('\u2a74') << 16); // DOUBLE COLON EQUAL
    builder.put("Equal", Integer.valueOf('\u2a75') << 16); // TWO CONSECUTIVE EQUALS SIGNS
    builder.put("eDDot", Integer.valueOf('\u2a77') << 16); // EQUALS SIGN WITH TWO DOTS ABOVE AND TWO DOTS BELOW
    builder.put("ddotseq", Integer.valueOf('\u2a77') << 16); // EQUALS SIGN WITH TWO DOTS ABOVE AND TWO DOTS BELOW
    builder.put("equivDD", Integer.valueOf('\u2a78') << 16); // EQUIVALENT WITH FOUR DOTS ABOVE
    builder.put("ltcir", Integer.valueOf('\u2a79') << 16); // LESS-THAN WITH CIRCLE INSIDE
    builder.put("gtcir", Integer.valueOf('\u2a7a') << 16); // GREATER-THAN WITH CIRCLE INSIDE
    builder.put("ltquest", Integer.valueOf('\u2a7b') << 16); // LESS-THAN WITH QUESTION MARK ABOVE
    builder.put("gtquest", Integer.valueOf('\u2a7c') << 16); // GREATER-THAN WITH QUESTION MARK ABOVE
    builder.put("les", Integer.valueOf('\u2a7d') << 16); // LESS-THAN OR SLANTED EQUAL TO
    builder.put("LessSlantEqual", Integer.valueOf('\u2a7d') << 16); // LESS-THAN OR SLANTED EQUAL TO
    builder.put("leqslant", Integer.valueOf('\u2a7d') << 16); // LESS-THAN OR SLANTED EQUAL TO
    builder.put("ges", Integer.valueOf('\u2a7e') << 16); // GREATER-THAN OR SLANTED EQUAL TO
    builder.put("GreaterSlantEqual", Integer.valueOf('\u2a7e') << 16); // GREATER-THAN OR SLANTED EQUAL TO
    builder.put("geqslant", Integer.valueOf('\u2a7e') << 16); // GREATER-THAN OR SLANTED EQUAL TO
    builder.put("lesdot", Integer.valueOf('\u2a7f') << 16); // LESS-THAN OR SLANTED EQUAL TO WITH DOT INSIDE
    builder.put("gesdot", Integer.valueOf('\u2a80') << 16); // GREATER-THAN OR SLANTED EQUAL TO WITH DOT INSIDE
    builder.put("lesdoto", Integer.valueOf('\u2a81') << 16); // LESS-THAN OR SLANTED EQUAL TO WITH DOT ABOVE
    builder.put("gesdoto", Integer.valueOf('\u2a82') << 16); // GREATER-THAN OR SLANTED EQUAL TO WITH DOT ABOVE
    builder.put("lesdotor", Integer.valueOf('\u2a83') << 16); // LESS-THAN OR SLANTED EQUAL TO WITH DOT ABOVE RIGHT
    builder.put("gesdotol", Integer.valueOf('\u2a84') << 16); // GREATER-THAN OR SLANTED EQUAL TO WITH DOT ABOVE LEFT
    builder.put("lap", Integer.valueOf('\u2a85') << 16); // LESS-THAN OR APPROXIMATE
    builder.put("lessapprox", Integer.valueOf('\u2a85') << 16); // LESS-THAN OR APPROXIMATE
    builder.put("gap", Integer.valueOf('\u2a86') << 16); // GREATER-THAN OR APPROXIMATE
    builder.put("gtrapprox", Integer.valueOf('\u2a86') << 16); // GREATER-THAN OR APPROXIMATE
    builder.put("lne", Integer.valueOf('\u2a87') << 16); // LESS-THAN AND SINGLE-LINE NOT EQUAL TO
    builder.put("lneq", Integer.valueOf('\u2a87') << 16); // LESS-THAN AND SINGLE-LINE NOT EQUAL TO
    builder.put("gne", Integer.valueOf('\u2a88') << 16); // GREATER-THAN AND SINGLE-LINE NOT EQUAL TO
    builder.put("gneq", Integer.valueOf('\u2a88') << 16); // GREATER-THAN AND SINGLE-LINE NOT EQUAL TO
    builder.put("lnap", Integer.valueOf('\u2a89') << 16); // LESS-THAN AND NOT APPROXIMATE
    builder.put("lnapprox", Integer.valueOf('\u2a89') << 16); // LESS-THAN AND NOT APPROXIMATE
    builder.put("gnap", Integer.valueOf('\u2a8a') << 16); // GREATER-THAN AND NOT APPROXIMATE
    builder.put("gnapprox", Integer.valueOf('\u2a8a') << 16); // GREATER-THAN AND NOT APPROXIMATE
    builder.put("lEg", Integer.valueOf('\u2a8b') << 16); // LESS-THAN ABOVE DOUBLE-LINE EQUAL ABOVE GREATER-THAN
    builder.put("lesseqqgtr", Integer.valueOf('\u2a8b') << 16); // LESS-THAN ABOVE DOUBLE-LINE EQUAL ABOVE GREATER-THAN
    builder.put("gEl", Integer.valueOf('\u2a8c') << 16); // GREATER-THAN ABOVE DOUBLE-LINE EQUAL ABOVE LESS-THAN
    builder.put("gtreqqless", Integer.valueOf('\u2a8c') << 16); // GREATER-THAN ABOVE DOUBLE-LINE EQUAL ABOVE LESS-THAN
    builder.put("lsime", Integer.valueOf('\u2a8d') << 16); // LESS-THAN ABOVE SIMILAR OR EQUAL
    builder.put("gsime", Integer.valueOf('\u2a8e') << 16); // GREATER-THAN ABOVE SIMILAR OR EQUAL
    builder.put("lsimg", Integer.valueOf('\u2a8f') << 16); // LESS-THAN ABOVE SIMILAR ABOVE GREATER-THAN
    builder.put("gsiml", Integer.valueOf('\u2a90') << 16); // GREATER-THAN ABOVE SIMILAR ABOVE LESS-THAN
    builder.put("lgE", Integer.valueOf('\u2a91') << 16); // LESS-THAN ABOVE GREATER-THAN ABOVE DOUBLE-LINE EQUAL
    builder.put("glE", Integer.valueOf('\u2a92') << 16); // GREATER-THAN ABOVE LESS-THAN ABOVE DOUBLE-LINE EQUAL
    builder.put("lesges", Integer.valueOf('\u2a93') << 16); // LESS-THAN ABOVE SLANTED EQUAL ABOVE GREATER-THAN ABOVE SLANTED EQUAL
    builder.put("gesles", Integer.valueOf('\u2a94') << 16); // GREATER-THAN ABOVE SLANTED EQUAL ABOVE LESS-THAN ABOVE SLANTED EQUAL
    builder.put("els", Integer.valueOf('\u2a95') << 16); // SLANTED EQUAL TO OR LESS-THAN
    builder.put("eqslantless", Integer.valueOf('\u2a95') << 16); // SLANTED EQUAL TO OR LESS-THAN
    builder.put("egs", Integer.valueOf('\u2a96') << 16); // SLANTED EQUAL TO OR GREATER-THAN
    builder.put("eqslantgtr", Integer.valueOf('\u2a96') << 16); // SLANTED EQUAL TO OR GREATER-THAN
    builder.put("elsdot", Integer.valueOf('\u2a97') << 16); // SLANTED EQUAL TO OR LESS-THAN WITH DOT INSIDE
    builder.put("egsdot", Integer.valueOf('\u2a98') << 16); // SLANTED EQUAL TO OR GREATER-THAN WITH DOT INSIDE
    builder.put("el", Integer.valueOf('\u2a99') << 16); // DOUBLE-LINE EQUAL TO OR LESS-THAN
    builder.put("eg", Integer.valueOf('\u2a9a') << 16); // DOUBLE-LINE EQUAL TO OR GREATER-THAN
    builder.put("siml", Integer.valueOf('\u2a9d') << 16); // SIMILAR OR LESS-THAN
    builder.put("simg", Integer.valueOf('\u2a9e') << 16); // SIMILAR OR GREATER-THAN
    builder.put("simlE", Integer.valueOf('\u2a9f') << 16); // SIMILAR ABOVE LESS-THAN ABOVE EQUALS SIGN
    builder.put("simgE", Integer.valueOf('\u2aa0') << 16); // SIMILAR ABOVE GREATER-THAN ABOVE EQUALS SIGN
    builder.put("LessLess", Integer.valueOf('\u2aa1') << 16); // DOUBLE NESTED LESS-THAN
    builder.put("GreaterGreater", Integer.valueOf('\u2aa2') << 16); // DOUBLE NESTED GREATER-THAN
    builder.put("glj", Integer.valueOf('\u2aa4') << 16); // GREATER-THAN OVERLAPPING LESS-THAN
    builder.put("gla", Integer.valueOf('\u2aa5') << 16); // GREATER-THAN BESIDE LESS-THAN
    builder.put("ltcc", Integer.valueOf('\u2aa6') << 16); // LESS-THAN CLOSED BY CURVE
    builder.put("gtcc", Integer.valueOf('\u2aa7') << 16); // GREATER-THAN CLOSED BY CURVE
    builder.put("lescc", Integer.valueOf('\u2aa8') << 16); // LESS-THAN CLOSED BY CURVE ABOVE SLANTED EQUAL
    builder.put("gescc", Integer.valueOf('\u2aa9') << 16); // GREATER-THAN CLOSED BY CURVE ABOVE SLANTED EQUAL
    builder.put("smt", Integer.valueOf('\u2aaa') << 16); // SMALLER THAN
    builder.put("lat", Integer.valueOf('\u2aab') << 16); // LARGER THAN
    builder.put("smte", Integer.valueOf('\u2aac') << 16); // SMALLER THAN OR EQUAL TO
    builder.put("late", Integer.valueOf('\u2aad') << 16); // LARGER THAN OR EQUAL TO
    builder.put("bumpE", Integer.valueOf('\u2aae') << 16); // EQUALS SIGN WITH BUMPY ABOVE
    builder.put("pre", Integer.valueOf('\u2aaf') << 16); // PRECEDES ABOVE SINGLE-LINE EQUALS SIGN
    builder.put("preceq", Integer.valueOf('\u2aaf') << 16); // PRECEDES ABOVE SINGLE-LINE EQUALS SIGN
    builder.put("PrecedesEqual", Integer.valueOf('\u2aaf') << 16); // PRECEDES ABOVE SINGLE-LINE EQUALS SIGN
    builder.put("sce", Integer.valueOf('\u2ab0') << 16); // SUCCEEDS ABOVE SINGLE-LINE EQUALS SIGN
    builder.put("succeq", Integer.valueOf('\u2ab0') << 16); // SUCCEEDS ABOVE SINGLE-LINE EQUALS SIGN
    builder.put("SucceedsEqual", Integer.valueOf('\u2ab0') << 16); // SUCCEEDS ABOVE SINGLE-LINE EQUALS SIGN
    builder.put("prE", Integer.valueOf('\u2ab3') << 16); // PRECEDES ABOVE EQUALS SIGN
    builder.put("scE", Integer.valueOf('\u2ab4') << 16); // SUCCEEDS ABOVE EQUALS SIGN
    builder.put("prnE", Integer.valueOf('\u2ab5') << 16); // PRECEDES ABOVE NOT EQUAL TO
    builder.put("precneqq", Integer.valueOf('\u2ab5') << 16); // PRECEDES ABOVE NOT EQUAL TO
    builder.put("scnE", Integer.valueOf('\u2ab6') << 16); // SUCCEEDS ABOVE NOT EQUAL TO
    builder.put("succneqq", Integer.valueOf('\u2ab6') << 16); // SUCCEEDS ABOVE NOT EQUAL TO
    builder.put("prap", Integer.valueOf('\u2ab7') << 16); // PRECEDES ABOVE ALMOST EQUAL TO
    builder.put("precapprox", Integer.valueOf('\u2ab7') << 16); // PRECEDES ABOVE ALMOST EQUAL TO
    builder.put("scap", Integer.valueOf('\u2ab8') << 16); // SUCCEEDS ABOVE ALMOST EQUAL TO
    builder.put("succapprox", Integer.valueOf('\u2ab8') << 16); // SUCCEEDS ABOVE ALMOST EQUAL TO
    builder.put("prnap", Integer.valueOf('\u2ab9') << 16); // PRECEDES ABOVE NOT ALMOST EQUAL TO
    builder.put("precnapprox", Integer.valueOf('\u2ab9') << 16); // PRECEDES ABOVE NOT ALMOST EQUAL TO
    builder.put("scnap", Integer.valueOf('\u2aba') << 16); // SUCCEEDS ABOVE NOT ALMOST EQUAL TO
    builder.put("succnapprox", Integer.valueOf('\u2aba') << 16); // SUCCEEDS ABOVE NOT ALMOST EQUAL TO
    builder.put("Pr", Integer.valueOf('\u2abb') << 16); // DOUBLE PRECEDES
    builder.put("Sc", Integer.valueOf('\u2abc') << 16); // DOUBLE SUCCEEDS
    builder.put("subdot", Integer.valueOf('\u2abd') << 16); // SUBSET WITH DOT
    builder.put("supdot", Integer.valueOf('\u2abe') << 16); // SUPERSET WITH DOT
    builder.put("subplus", Integer.valueOf('\u2abf') << 16); // SUBSET WITH PLUS SIGN BELOW
    builder.put("supplus", Integer.valueOf('\u2ac0') << 16); // SUPERSET WITH PLUS SIGN BELOW
    builder.put("submult", Integer.valueOf('\u2ac1') << 16); // SUBSET WITH MULTIPLICATION SIGN BELOW
    builder.put("supmult", Integer.valueOf('\u2ac2') << 16); // SUPERSET WITH MULTIPLICATION SIGN BELOW
    builder.put("subedot", Integer.valueOf('\u2ac3') << 16); // SUBSET OF OR EQUAL TO WITH DOT ABOVE
    builder.put("supedot", Integer.valueOf('\u2ac4') << 16); // SUPERSET OF OR EQUAL TO WITH DOT ABOVE
    builder.put("subE", Integer.valueOf('\u2ac5') << 16); // SUBSET OF ABOVE EQUALS SIGN
    builder.put("subseteqq", Integer.valueOf('\u2ac5') << 16); // SUBSET OF ABOVE EQUALS SIGN
    builder.put("supE", Integer.valueOf('\u2ac6') << 16); // SUPERSET OF ABOVE EQUALS SIGN
    builder.put("supseteqq", Integer.valueOf('\u2ac6') << 16); // SUPERSET OF ABOVE EQUALS SIGN
    builder.put("subsim", Integer.valueOf('\u2ac7') << 16); // SUBSET OF ABOVE TILDE OPERATOR
    builder.put("supsim", Integer.valueOf('\u2ac8') << 16); // SUPERSET OF ABOVE TILDE OPERATOR
    builder.put("subnE", Integer.valueOf('\u2acb') << 16); // SUBSET OF ABOVE NOT EQUAL TO
    builder.put("subsetneqq", Integer.valueOf('\u2acb') << 16); // SUBSET OF ABOVE NOT EQUAL TO
    builder.put("supnE", Integer.valueOf('\u2acc') << 16); // SUPERSET OF ABOVE NOT EQUAL TO
    builder.put("supsetneqq", Integer.valueOf('\u2acc') << 16); // SUPERSET OF ABOVE NOT EQUAL TO
    builder.put("csub", Integer.valueOf('\u2acf') << 16); // CLOSED SUBSET
    builder.put("csup", Integer.valueOf('\u2ad0') << 16); // CLOSED SUPERSET
    builder.put("csube", Integer.valueOf('\u2ad1') << 16); // CLOSED SUBSET OR EQUAL TO
    builder.put("csupe", Integer.valueOf('\u2ad2') << 16); // CLOSED SUPERSET OR EQUAL TO
    builder.put("subsup", Integer.valueOf('\u2ad3') << 16); // SUBSET ABOVE SUPERSET
    builder.put("supsub", Integer.valueOf('\u2ad4') << 16); // SUPERSET ABOVE SUBSET
    builder.put("subsub", Integer.valueOf('\u2ad5') << 16); // SUBSET ABOVE SUBSET
    builder.put("supsup", Integer.valueOf('\u2ad6') << 16); // SUPERSET ABOVE SUPERSET
    builder.put("suphsub", Integer.valueOf('\u2ad7') << 16); // SUPERSET BESIDE SUBSET
    builder.put("supdsub", Integer.valueOf('\u2ad8') << 16); // SUPERSET BESIDE AND JOINED BY DASH WITH SUBSET
    builder.put("forkv", Integer.valueOf('\u2ad9') << 16); // ELEMENT OF OPENING DOWNWARDS
    builder.put("topfork", Integer.valueOf('\u2ada') << 16); // PITCHFORK WITH TEE TOP
    builder.put("mlcp", Integer.valueOf('\u2adb') << 16); // TRANSVERSAL INTERSECTION
    builder.put("Dashv", Integer.valueOf('\u2ae4') << 16); // VERTICAL BAR DOUBLE LEFT TURNSTILE
    builder.put("DoubleLeftTee", Integer.valueOf('\u2ae4') << 16); // VERTICAL BAR DOUBLE LEFT TURNSTILE
    builder.put("Vdashl", Integer.valueOf('\u2ae6') << 16); // LONG DASH FROM LEFT MEMBER OF DOUBLE VERTICAL
    builder.put("Barv", Integer.valueOf('\u2ae7') << 16); // SHORT DOWN TACK WITH OVERBAR
    builder.put("vBar", Integer.valueOf('\u2ae8') << 16); // SHORT UP TACK WITH UNDERBAR
    builder.put("vBarv", Integer.valueOf('\u2ae9') << 16); // SHORT UP TACK ABOVE SHORT DOWN TACK
    builder.put("Vbar", Integer.valueOf('\u2aeb') << 16); // DOUBLE UP TACK
    builder.put("Not", Integer.valueOf('\u2aec') << 16); // DOUBLE STROKE NOT SIGN
    builder.put("bNot", Integer.valueOf('\u2aed') << 16); // REVERSED DOUBLE STROKE NOT SIGN
    builder.put("rnmid", Integer.valueOf('\u2aee') << 16); // DOES NOT DIVIDE WITH REVERSED NEGATION SLASH
    builder.put("cirmid", Integer.valueOf('\u2aef') << 16); // VERTICAL LINE WITH CIRCLE ABOVE
    builder.put("midcir", Integer.valueOf('\u2af0') << 16); // VERTICAL LINE WITH CIRCLE BELOW
    builder.put("topcir", Integer.valueOf('\u2af1') << 16); // DOWN TACK WITH CIRCLE BELOW
    builder.put("nhpar", Integer.valueOf('\u2af2') << 16); // PARALLEL WITH HORIZONTAL STROKE
    builder.put("parsim", Integer.valueOf('\u2af3') << 16); // PARALLEL WITH TILDE OPERATOR
    builder.put("parsl", Integer.valueOf('\u2afd') << 16); // DOUBLE SOLIDUS OPERATOR

    // Alphabetic Presentation Forms
    builder.put("fflig", Integer.valueOf('\ufb00') << 16); // LATIN SMALL LIGATURE FF
    builder.put("filig", Integer.valueOf('\ufb01') << 16); // LATIN SMALL LIGATURE FI
    builder.put("fllig", Integer.valueOf('\ufb02') << 16); // LATIN SMALL LIGATURE FL
    builder.put("ffilig", Integer.valueOf('\ufb03') << 16); // LATIN SMALL LIGATURE FFI
    builder.put("ffllig", Integer.valueOf('\ufb04') << 16); // LATIN SMALL LIGATURE FFL

    // Mathematical Alphanumeric Symbols
    builder.put("Ascr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udc9c')); // MATHEMATICAL SCRIPT CAPITAL A
    builder.put("Cscr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udc9e')); // MATHEMATICAL SCRIPT CAPITAL C
    builder.put("Dscr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udc9f')); // MATHEMATICAL SCRIPT CAPITAL D
    builder.put("Gscr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udca2')); // MATHEMATICAL SCRIPT CAPITAL G
    builder.put("Jscr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udca5')); // MATHEMATICAL SCRIPT CAPITAL J
    builder.put("Kscr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udca6')); // MATHEMATICAL SCRIPT CAPITAL K
    builder.put("Nscr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udca9')); // MATHEMATICAL SCRIPT CAPITAL N
    builder.put("Oscr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udcaa')); // MATHEMATICAL SCRIPT CAPITAL O
    builder.put("Pscr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udcab')); // MATHEMATICAL SCRIPT CAPITAL P
    builder.put("Qscr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udcac')); // MATHEMATICAL SCRIPT CAPITAL Q
    builder.put("Sscr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udcae')); // MATHEMATICAL SCRIPT CAPITAL S
    builder.put("Tscr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udcaf')); // MATHEMATICAL SCRIPT CAPITAL T
    builder.put("Uscr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udcb0')); // MATHEMATICAL SCRIPT CAPITAL U
    builder.put("Vscr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udcb1')); // MATHEMATICAL SCRIPT CAPITAL V
    builder.put("Wscr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udcb2')); // MATHEMATICAL SCRIPT CAPITAL W
    builder.put("Xscr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udcb3')); // MATHEMATICAL SCRIPT CAPITAL X
    builder.put("Yscr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udcb4')); // MATHEMATICAL SCRIPT CAPITAL Y
    builder.put("Zscr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udcb5')); // MATHEMATICAL SCRIPT CAPITAL Z
    builder.put("ascr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udcb6')); // MATHEMATICAL SCRIPT SMALL A
    builder.put("bscr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udcb7')); // MATHEMATICAL SCRIPT SMALL B
    builder.put("cscr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udcb8')); // MATHEMATICAL SCRIPT SMALL C
    builder.put("dscr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udcb9')); // MATHEMATICAL SCRIPT SMALL D
    builder.put("fscr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udcbb')); // MATHEMATICAL SCRIPT SMALL F
    builder.put("hscr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udcbd')); // MATHEMATICAL SCRIPT SMALL H
    builder.put("iscr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udcbe')); // MATHEMATICAL SCRIPT SMALL I
    builder.put("jscr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udcbf')); // MATHEMATICAL SCRIPT SMALL J
    builder.put("kscr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udcc0')); // MATHEMATICAL SCRIPT SMALL K
    builder.put("lscr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udcc1')); // MATHEMATICAL SCRIPT SMALL L
    builder.put("mscr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udcc2')); // MATHEMATICAL SCRIPT SMALL M
    builder.put("nscr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udcc3')); // MATHEMATICAL SCRIPT SMALL N
    builder.put("pscr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udcc5')); // MATHEMATICAL SCRIPT SMALL P
    builder.put("qscr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udcc6')); // MATHEMATICAL SCRIPT SMALL Q
    builder.put("rscr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udcc7')); // MATHEMATICAL SCRIPT SMALL R
    builder.put("sscr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udcc8')); // MATHEMATICAL SCRIPT SMALL S
    builder.put("tscr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udcc9')); // MATHEMATICAL SCRIPT SMALL T
    builder.put("uscr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udcca')); // MATHEMATICAL SCRIPT SMALL U
    builder.put("vscr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udccb')); // MATHEMATICAL SCRIPT SMALL V
    builder.put("wscr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udccc')); // MATHEMATICAL SCRIPT SMALL W
    builder.put("xscr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udccd')); // MATHEMATICAL SCRIPT SMALL X
    builder.put("yscr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udcce')); // MATHEMATICAL SCRIPT SMALL Y
    builder.put("zscr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udccf')); // MATHEMATICAL SCRIPT SMALL Z
    builder.put("Afr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd04')); // MATHEMATICAL FRAKTUR CAPITAL A
    builder.put("Bfr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd05')); // MATHEMATICAL FRAKTUR CAPITAL B
    builder.put("Dfr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd07')); // MATHEMATICAL FRAKTUR CAPITAL D
    builder.put("Efr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd08')); // MATHEMATICAL FRAKTUR CAPITAL E
    builder.put("Ffr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd09')); // MATHEMATICAL FRAKTUR CAPITAL F
    builder.put("Gfr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd0a')); // MATHEMATICAL FRAKTUR CAPITAL G
    builder.put("Jfr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd0d')); // MATHEMATICAL FRAKTUR CAPITAL J
    builder.put("Kfr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd0e')); // MATHEMATICAL FRAKTUR CAPITAL K
    builder.put("Lfr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd0f')); // MATHEMATICAL FRAKTUR CAPITAL L
    builder.put("Mfr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd10')); // MATHEMATICAL FRAKTUR CAPITAL M
    builder.put("Nfr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd11')); // MATHEMATICAL FRAKTUR CAPITAL N
    builder.put("Ofr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd12')); // MATHEMATICAL FRAKTUR CAPITAL O
    builder.put("Pfr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd13')); // MATHEMATICAL FRAKTUR CAPITAL P
    builder.put("Qfr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd14')); // MATHEMATICAL FRAKTUR CAPITAL Q
    builder.put("Sfr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd16')); // MATHEMATICAL FRAKTUR CAPITAL S
    builder.put("Tfr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd17')); // MATHEMATICAL FRAKTUR CAPITAL T
    builder.put("Ufr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd18')); // MATHEMATICAL FRAKTUR CAPITAL U
    builder.put("Vfr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd19')); // MATHEMATICAL FRAKTUR CAPITAL V
    builder.put("Wfr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd1a')); // MATHEMATICAL FRAKTUR CAPITAL W
    builder.put("Xfr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd1b')); // MATHEMATICAL FRAKTUR CAPITAL X
    builder.put("Yfr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd1c')); // MATHEMATICAL FRAKTUR CAPITAL Y
    builder.put("afr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd1e')); // MATHEMATICAL FRAKTUR SMALL A
    builder.put("bfr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd1f')); // MATHEMATICAL FRAKTUR SMALL B
    builder.put("cfr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd20')); // MATHEMATICAL FRAKTUR SMALL C
    builder.put("dfr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd21')); // MATHEMATICAL FRAKTUR SMALL D
    builder.put("efr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd22')); // MATHEMATICAL FRAKTUR SMALL E
    builder.put("ffr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd23')); // MATHEMATICAL FRAKTUR SMALL F
    builder.put("gfr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd24')); // MATHEMATICAL FRAKTUR SMALL G
    builder.put("hfr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd25')); // MATHEMATICAL FRAKTUR SMALL H
    builder.put("ifr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd26')); // MATHEMATICAL FRAKTUR SMALL I
    builder.put("jfr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd27')); // MATHEMATICAL FRAKTUR SMALL J
    builder.put("kfr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd28')); // MATHEMATICAL FRAKTUR SMALL K
    builder.put("lfr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd29')); // MATHEMATICAL FRAKTUR SMALL L
    builder.put("mfr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd2a')); // MATHEMATICAL FRAKTUR SMALL M
    builder.put("nfr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd2b')); // MATHEMATICAL FRAKTUR SMALL N
    builder.put("ofr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd2c')); // MATHEMATICAL FRAKTUR SMALL O
    builder.put("pfr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd2d')); // MATHEMATICAL FRAKTUR SMALL P
    builder.put("qfr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd2e')); // MATHEMATICAL FRAKTUR SMALL Q
    builder.put("rfr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd2f')); // MATHEMATICAL FRAKTUR SMALL R
    builder.put("sfr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd30')); // MATHEMATICAL FRAKTUR SMALL S
    builder.put("tfr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd31')); // MATHEMATICAL FRAKTUR SMALL T
    builder.put("ufr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd32')); // MATHEMATICAL FRAKTUR SMALL U
    builder.put("vfr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd33')); // MATHEMATICAL FRAKTUR SMALL V
    builder.put("wfr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd34')); // MATHEMATICAL FRAKTUR SMALL W
    builder.put("xfr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd35')); // MATHEMATICAL FRAKTUR SMALL X
    builder.put("yfr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd36')); // MATHEMATICAL FRAKTUR SMALL Y
    builder.put("zfr", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd37')); // MATHEMATICAL FRAKTUR SMALL Z
    builder.put("Aopf", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd38')); // MATHEMATICAL DOUBLE-STRUCK CAPITAL A
    builder.put("Bopf", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd39')); // MATHEMATICAL DOUBLE-STRUCK CAPITAL B
    builder.put("Dopf", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd3b')); // MATHEMATICAL DOUBLE-STRUCK CAPITAL D
    builder.put("Eopf", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd3c')); // MATHEMATICAL DOUBLE-STRUCK CAPITAL E
    builder.put("Fopf", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd3d')); // MATHEMATICAL DOUBLE-STRUCK CAPITAL F
    builder.put("Gopf", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd3e')); // MATHEMATICAL DOUBLE-STRUCK CAPITAL G
    builder.put("Iopf", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd40')); // MATHEMATICAL DOUBLE-STRUCK CAPITAL I
    builder.put("Jopf", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd41')); // MATHEMATICAL DOUBLE-STRUCK CAPITAL J
    builder.put("Kopf", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd42')); // MATHEMATICAL DOUBLE-STRUCK CAPITAL K
    builder.put("Lopf", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd43')); // MATHEMATICAL DOUBLE-STRUCK CAPITAL L
    builder.put("Mopf", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd44')); // MATHEMATICAL DOUBLE-STRUCK CAPITAL M
    builder.put("Oopf", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd46')); // MATHEMATICAL DOUBLE-STRUCK CAPITAL O
    builder.put("Sopf", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd4a')); // MATHEMATICAL DOUBLE-STRUCK CAPITAL S
    builder.put("Topf", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd4b')); // MATHEMATICAL DOUBLE-STRUCK CAPITAL T
    builder.put("Uopf", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd4c')); // MATHEMATICAL DOUBLE-STRUCK CAPITAL U
    builder.put("Vopf", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd4d')); // MATHEMATICAL DOUBLE-STRUCK CAPITAL V
    builder.put("Wopf", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd4e')); // MATHEMATICAL DOUBLE-STRUCK CAPITAL W
    builder.put("Xopf", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd4f')); // MATHEMATICAL DOUBLE-STRUCK CAPITAL X
    builder.put("Yopf", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd50')); // MATHEMATICAL DOUBLE-STRUCK CAPITAL Y
    builder.put("aopf", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd52')); // MATHEMATICAL DOUBLE-STRUCK SMALL A
    builder.put("bopf", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd53')); // MATHEMATICAL DOUBLE-STRUCK SMALL B
    builder.put("copf", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd54')); // MATHEMATICAL DOUBLE-STRUCK SMALL C
    builder.put("dopf", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd55')); // MATHEMATICAL DOUBLE-STRUCK SMALL D
    builder.put("eopf", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd56')); // MATHEMATICAL DOUBLE-STRUCK SMALL E
    builder.put("fopf", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd57')); // MATHEMATICAL DOUBLE-STRUCK SMALL F
    builder.put("gopf", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd58')); // MATHEMATICAL DOUBLE-STRUCK SMALL G
    builder.put("hopf", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd59')); // MATHEMATICAL DOUBLE-STRUCK SMALL H
    builder.put("iopf", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd5a')); // MATHEMATICAL DOUBLE-STRUCK SMALL I
    builder.put("jopf", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd5b')); // MATHEMATICAL DOUBLE-STRUCK SMALL J
    builder.put("kopf", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd5c')); // MATHEMATICAL DOUBLE-STRUCK SMALL K
    builder.put("lopf", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd5d')); // MATHEMATICAL DOUBLE-STRUCK SMALL L
    builder.put("mopf", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd5e')); // MATHEMATICAL DOUBLE-STRUCK SMALL M
    builder.put("nopf", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd5f')); // MATHEMATICAL DOUBLE-STRUCK SMALL N
    builder.put("oopf", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd60')); // MATHEMATICAL DOUBLE-STRUCK SMALL O
    builder.put("popf", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd61')); // MATHEMATICAL DOUBLE-STRUCK SMALL P
    builder.put("qopf", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd62')); // MATHEMATICAL DOUBLE-STRUCK SMALL Q
    builder.put("ropf", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd63')); // MATHEMATICAL DOUBLE-STRUCK SMALL R
    builder.put("sopf", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd64')); // MATHEMATICAL DOUBLE-STRUCK SMALL S
    builder.put("topf", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd65')); // MATHEMATICAL DOUBLE-STRUCK SMALL T
    builder.put("uopf", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd66')); // MATHEMATICAL DOUBLE-STRUCK SMALL U
    builder.put("vopf", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd67')); // MATHEMATICAL DOUBLE-STRUCK SMALL V
    builder.put("wopf", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd68')); // MATHEMATICAL DOUBLE-STRUCK SMALL W
    builder.put("xopf", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd69')); // MATHEMATICAL DOUBLE-STRUCK SMALL X
    builder.put("yopf", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd6a')); // MATHEMATICAL DOUBLE-STRUCK SMALL Y
    builder.put("zopf", (Integer.valueOf('\ud835') << 16) | Integer.valueOf('\udd6b')); // MATHEMATICAL DOUBLE-STRUCK SMALL Z

    final Map<String, Integer> entityNameToCodePointMap = builder.build();

    int longestEntityName = 0;
    for (String entityName : entityNameToCodePointMap.keySet()) {
      if (entityName.length() > longestEntityName) {
        longestEntityName = entityName.length();
      }
    }

    ENTITY_TRIE = new Trie(entityNameToCodePointMap);
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
   *    code-unit(s) packed into a long.
   *    The first 32 bits are the offset. The next 16 bits are the first
   *    code-unit. The last 16 bits are either the second code-unit or 0x0000
   *    if there is only one code-unit.
   */
  public static long decodeEntityAt(String html, int offset, int limit) {
    char ch = html.charAt(offset);
    if ('&' != ch) {
      return ((offset + 1L) << 32) | (((long) ch) << 16);
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
          return ((offset + 1L) << 32) | (((long) '&') << 16);
        default:  // A possible broken entity.
          end = i;
          tail = i;
          break entityloop;
      }
    }
    if (end < 0 || offset + 2 >= end) {
      return ((offset + 1L) << 32) | (((long) '&') << 16);
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
          return ((offset + 1L) << 32) | (((long) '&') << 16);
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
        return (((long) tail) << 32) | (t.getValue() & 0xffffffffL);
      }
    }
    if (codepoint < 0) {
      return ((offset + 1L) << 32) | (((long) '&') << 16);
    }
    // Code-point is a BMP value
    if (codepoint >>> 16 == 0) {
      return (((long) tail) << 32) | (((long) codepoint) << 16);
    }
    // Code-point is supplementary
    char highSurrogate = (char) ((codepoint >>> 10)
        + (MIN_HIGH_SURROGATE - (MIN_SUPPLEMENTARY_CODE_POINT >>> 10)));
    char lowSurrogate = (char) ((codepoint & 0x3ff) + MIN_LOW_SURROGATE);
    return (((long) tail) << 32) | (((long) highSurrogate) << 16) | lowSurrogate;
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

  private HtmlEntities() { /* uninstantiable */ }
}
