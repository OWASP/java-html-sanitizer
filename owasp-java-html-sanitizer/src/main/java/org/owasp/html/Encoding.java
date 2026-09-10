// Copyright (c) 2012, Mike Samuel
// All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause
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

import java.io.IOException;
import java.util.BitSet;

import javax.annotation.Nullable;

/** Encoders and decoders for HTML. */
public final class Encoding {

  /**
   * Decodes HTML entities to produce a string containing only valid
   * Unicode scalar values.
   *
   * @param s text/html
   * @return text/plain
   * @deprecated specify whether s is in an attribute value
   */
  @Deprecated
  public static String decodeHtml(String s) {
    return decodeHtml(s, false);
  }

  /**
   * Decodes HTML entities to produce a string containing only valid
   * Unicode scalar values.
   *
   * @param s text/html
   * @param inAttribute is s in an attribute value?
   * @return text/plain
   */
  public static String decodeHtml(String s, boolean inAttribute) {
    int firstAmp = s.indexOf('&');
    int safeLimit = longestPrefixOfGoodCodeunits(s);
    if ((firstAmp & safeLimit) < 0) { return s; }

    StringBuilder sb;
    {
      int n = s.length();
      sb = new StringBuilder(n);
      int pos = 0;
      int amp = firstAmp;
      while (amp >= 0) {
        sb.append(s, pos, amp);
        int end = HtmlEntities.appendDecodedEntity(s, amp, n, inAttribute, sb);
        pos = end;
        amp = s.indexOf('&', end);
      }
      sb.append(s, pos, n);
    }

    stripBannedCodeunits(
        sb,
        firstAmp < 0
          ? safeLimit : safeLimit < 0
          ? firstAmp : Math.min(firstAmp, safeLimit));

    return sb.toString();
  }

  /**
   * Returns the portion of its input that consists of chars that are safe in
   * both XML and HTML: the XML Character production without the
   * noncharacters, DEL and the C1 controls that HTML treats as parse errors.
   * @see <a href="http://www.w3.org/TR/2008/REC-xml-20081126/#charsets">XML Ch. 2.2 - Characters</a>
   * @see <a href="https://html.spec.whatwg.org/multipage/parsing.html#preprocessing-the-input-stream">HTML 13.2.3.5 - Preprocessing the input stream</a>
   */
  @TCB
  static String stripBannedCodeunits(String s) {
    int safeLimit = longestPrefixOfGoodCodeunits(s);
    if (safeLimit < 0) { return s; }

    StringBuilder sb = new StringBuilder(s);
    stripBannedCodeunits(sb, safeLimit);
    return sb.toString();
  }

  /**
   * Leaves in the input buffer only code-units that comprise chars that are
   * safe in both XML and HTML.
   * @see #stripBannedCodeunits(String)
   */
  @TCB
  static void stripBannedCodeunits(StringBuilder sb) {
    stripBannedCodeunits(sb, 0);
  }

  @TCB
  private static void stripBannedCodeunits(StringBuilder sb, int start) {
    int k = start;
    for (int i = start, n = sb.length(); i < n; ++i) {
      char ch = sb.charAt(i);
      if (ch < 0x20) {
        if (IS_BANNED_ASCII[ch]) {
          continue;
        }
      } else if (0x7f <= ch && ch <= 0x9f) {
        // DEL and the C1 controls.  encodeHtmlOnto elides them, so they are
        // stripped here too: policies must judge the text that will be
        // emitted, not text that a later elision would join up differently.
        continue;
      } else if (0xd800 <= ch) {
        if (ch <= 0xdfff) {
          if (i+1 < n) {
            char next = sb.charAt(i+1);
            if (Character.isSurrogatePair(ch, next)) {
              // The last two code points of each plane are noncharacters.
              if (!isNoncharacter(Character.toCodePoint(ch, next))) {
                sb.setCharAt(k++, ch);
                sb.setCharAt(k++, next);
              }
              ++i;
            }
          }
          continue;
        } else if (isNoncharacter(ch)) {
          continue;
        }
      }
      sb.setCharAt(k++, ch);
    }
    sb.setLength(k);
  }

  /**
   * The number of code-units at the front of s that form code-points that
   * {@link #stripBannedCodeunits(String)} keeps.
   * @return -1 if all of s is kept.
   */
  @TCB
  private static int longestPrefixOfGoodCodeunits(String s) {
    int n = s.length(), i;
    for (i = 0; i < n; ++i) {
      char ch = s.charAt(i);
      if (ch < 0x20) {
        if (IS_BANNED_ASCII[ch]) {
          return i;
        }
      } else if (0x7f <= ch && ch <= 0x9f) {
        return i;
      } else if (0xd800 <= ch) {
        if (ch <= 0xdfff) {
          if (i + 1 < n) {
            char next = s.charAt(i + 1);
            if (Character.isSurrogatePair(ch, next)
                && !isNoncharacter(Character.toCodePoint(ch, next))) {
              ++i;  // Skip over low surrogate since we know it's ok.
            } else {
              return i;
            }
          } else {
            return i;  // Orphaned surrogate at the end of the string.
          }
        } else if (isNoncharacter(ch)) {
          return i;
        }
      }
    }
    return -1;
  }

  /**
   * True for the 66 Unicode noncharacters: U+FDD0..U+FDEF and the last two
   * code points of every plane.  HTML treats them as parse errors and forbids
   * numeric character references to them.
   * @see <a href="https://infra.spec.whatwg.org/#noncharacter">Infra - noncharacter</a>
   */
  static boolean isNoncharacter(int codepoint) {
    return (codepoint & 0xfffe) == 0xfffe
        || (0xfdd0 <= codepoint && codepoint <= 0xfdef);
  }

  /**
   * Appends an encoded form of plainText to output where the encoding is
   * sufficient to prevent an HTML parser from interpreting any characters in
   * the appended chunk as part of an attribute or tag boundary.
   *
   * @param plainText text/plain
   * @param output a buffer of text/html that has a well-formed HTML prefix that
   *     ends after the open-quote of an attribute value and does not yet contain
   *     a corresponding close quote.
   *     Modified in place.
   */
  static void encodeHtmlAttribOnto(String plainText, Appendable output)
      throws IOException {
    encodeHtmlOnto(plainText, output, "{\u200B");
  }

  /**
   * Appends an encoded form of plainText to putput where the encoding is
   * sufficient to prevent an HTML parser from transitioning out of the
   * <a href="https://html.spec.whatwg.org/multipage/parsing.html#data-state">
   * Data state</a>.
   *
   * This is suitable for encoding a text node inside any element that does not
   * require special handling as a context element (see "context element" in
   * <a href="https://html.spec.whatwg.org/multipage/parsing.html#parsing-html-fragments">
   * step 4</a>.)
   *
   * @param plainText text/plain
   * @param output a buffer of text/html that has a well-formed HTML prefix that
   *     would leave an HTML parser in the Data state if it were to encounter a space
   *     character as the next character.  In practice this means that the buffer
   *     does not contain partial tags or comments, and does not have an unclosed
   *     element with a special content model.
   */
  static void encodePcdataOnto(String plainText, Appendable output)
      throws IOException {
    // Avoid problems with client-side template languages like
    // Angular & Polymer which attach special significance to text like
    // {{...}}.
    // We split brackets so that these template languages don't end up
    // executing expressions in sanitized text.
    encodeHtmlOnto(plainText, output, "{<!-- -->");
  }

  /**
   * Appends an encoded form of plainText to putput where the encoding is
   * sufficient to prevent an HTML parser from transitioning out of the
   * <a href="https://html.spec.whatwg.org/multipage/parsing.html#rcdata-state">
   * RCDATA state</a>.
   *
   * This is suitable for encoding a text node inside a {@code <textarea>} or
   * {@code <title>} element outside foreign content.
   *
   * @param plainText text/plain
   * @param output a buffer of text/html that has a well-formed HTML prefix that
   *     would leave an HTML parser in the Data state if it were to encounter a space
   *     character as the next character.  In practice this means that the buffer
   *     does not contain partial tags or comments, and the most recently opened
   *     element is {@code <textarea>} or {@code <title>} and that element is
   *     still open.
   */
  public static void encodeRcdataOnto(String plainText, Appendable output)
      throws IOException {
    // Avoid problems with client-side template languages like
    // Angular & Polymer which attach special significance to text like
    // {{...}}.
    // We split brackets so that these template languages don't end up
    // executing expressions in sanitized text.
    encodeHtmlOnto(plainText, output, "{\u200B");
  }

  /**
   * Writes the HTML equivalent of the given plain text to output.
   * For example, {@code escapeHtmlOnto("1 < 2", w)},
   * is equivalent to {@code w.append("1 &lt; 2")} but possibly with fewer
   * smaller appends.
   *
   * <p>Elides code-units that are not valid XML Characters, and the
   * noncharacters, DEL and C1 controls that HTML forbids in character
   * references and treats as parse errors in the input stream.  Normalizes
   * CR and CRLF to LF as the HTML input stream preprocessor does, so the
   * output never contains a raw carriage return.
   * @see <a href="http://www.w3.org/TR/2008/REC-xml-20081126/#charsets">XML Ch. 2.2 - Characters</a>
   * @see <a href="https://html.spec.whatwg.org/multipage/syntax.html#character-references">HTML 13.1.4 - Character references</a>
   * @see <a href="https://infra.spec.whatwg.org/#normalize-newlines">Infra - normalize newlines</a>
   */
  @TCB
  private static void encodeHtmlOnto(
      String plainText, Appendable output, @Nullable String braceReplacement)
          throws IOException {
    int n = plainText.length();
    int pos = 0;
    for (int i = 0; i < n; ++i) {
      char ch = plainText.charAt(i);
      if (ch < REPLACEMENTS.length) {  // Handles all ASCII.
        String repl = REPLACEMENTS[ch];
        if (repl == null) {
          if (ch == '{') {
            if (i + 1 == n || plainText.charAt(i + 1) == '{') {
              repl = braceReplacement;
            }
          } else if (ch == '\r') {
            // CRLF becomes LF by dropping the CR; a lone CR becomes LF.
            repl = (i + 1 < n && plainText.charAt(i + 1) == '\n') ? "" : "\n";
          }
        }
        if (repl != null) {
          output.append(plainText, pos, i).append(repl);
          pos = i + 1;
        }
      } else if (ch <= 0x9f || isNoncharacter(ch)) {
        // Elide the C1 controls and the BMP noncharacters.
        output.append(plainText, pos, i);
        pos = i + 1;
      } else if (0xd800 <= ch && ch <= 0xdfff) {
        char next;
        if (i + 1 < n
            && Character.isSurrogatePair(ch, next = plainText.charAt(i + 1))) {
          int codepoint = Character.toCodePoint(ch, next);
          output.append(plainText, pos, i);
          if (!isNoncharacter(codepoint)) {
            // Emit supplemental codepoints as entity so that they cannot
            // be mis-encoded as UTF-8 of surrogates instead of UTF-8 proper
            // and get involved in UTF-16/UCS-2 confusion.
            appendNumericEntity(codepoint, output);
          }
          ++i;
          pos = i + 1;
        } else {
          output.append(plainText, pos, i);
          // Elide the orphaned surrogate.
          pos = i + 1;
        }
      } else if (0xfe60 <= ch || isRiskyNormalization(ch)) {
        // Above U+FE60 lie the small form variants, Arabic presentation
        // forms, the halfwidth and fullwidth forms, the byte order mark and
        // the specials block: full-width versions of HTML special characters
        // and code points that an encoding conversion may drop or mangle.
        // Elsewhere in the BMP, isRiskyNormalization picks out characters
        // whose compatibility decomposition contains ASCII punctuation, such
        // as U+1FEF GREEK VARIA which normalizes to a backtick.
        // Either way, a numeric reference survives any later normalization
        // of the output unchanged.
        output.append(plainText, pos, i);
        pos = i + 1;
        appendNumericEntity(ch, output);
      }
    }
    output.append(plainText, pos, n);
  }

  /**
   * Appends a numeric character reference for the code point to the output.
   *
   * @throws IllegalArgumentException if HTML forbids a numeric character
   *     reference to the code point: controls other than TAB and LF,
   *     surrogates, noncharacters and values above U+10FFFF.
   * @see <a href="https://html.spec.whatwg.org/multipage/syntax.html#character-references">HTML 13.1.4 - Character references</a>
   */
  @TCB
  static void appendNumericEntity(int codepoint, Appendable output)
      throws IOException {
    if ((codepoint < 0x20 && codepoint != '\t' && codepoint != '\n')
        || (0x7f <= codepoint && codepoint <= 0x9f)
        || (0xd800 <= codepoint && codepoint <= 0xdfff)
        || codepoint > Character.MAX_CODE_POINT
        || isNoncharacter(codepoint)) {
      throw new IllegalArgumentException(
          "Cannot write a character reference to U+"
          + Integer.toHexString(codepoint));
    }
    output.append("&#");
    if (codepoint < 100) {
      // Below 100 the decimal form is shortest.
      output.append(Integer.toString(codepoint));
    } else {
      output.append('x').append(Integer.toHexString(codepoint));
    }
    output.append(';');
  }

  /** Maps ASCII chars that need to be encoded to an equivalent HTML entity. */
  private static final String[] REPLACEMENTS = new String[0x80];
  static {
    for (int i = 0; i < ' '; ++i) {
      // We elide control characters so that we can ensure that our output is
      // in the intersection of valid HTML5 and XML.  According to
      // http://www.w3.org/TR/2008/REC-xml-20081126/#charsets
      // Char      ::=          #x9 | #xA | #xD | [#x20-#xD7FF]
      //             |          [#xE000-#xFFFD] | [#x10000-#x10FFFF]
      if (i != '\t' && i != '\n' && i != '\r') {
        REPLACEMENTS[i] = "";  // Elide
      }
    }
    // "&#34;" is shorter than "&quot;"
    REPLACEMENTS['"']  = "&#" + ((int) '"')  + ";";  // Attribute delimiter.
    REPLACEMENTS['&']  = "&amp;";                    // HTML special.
    // We don't use &apos; since that is not in the intersection of HTML&XML.
    REPLACEMENTS['\''] = "&#" + ((int) '\'') + ";";  // Attribute delimiter.
    REPLACEMENTS['+']  = "&#" + ((int) '+')  + ";";  // UTF-7 special.
    REPLACEMENTS['<']  = "&lt;";                     // HTML special.
    REPLACEMENTS['=']  = "&#" + ((int) '=')  + ";";  // Special in attributes.
    REPLACEMENTS['>']  = "&gt;";                     // HTML special.
    REPLACEMENTS['@']  = "&#" + ((int) '@')  + ";";  // Conditional compilation.
    REPLACEMENTS['`']  = "&#" + ((int) '`')  + ";";  // Attribute delimiter.
    REPLACEMENTS[0x7f] = "";                         // DEL is a control; elide.
  }

  /**
   * IS_BANNED_ASCII[i] where is an ASCII control character codepoint (&lt; 0x20)
   * is true for control characters that are not allowed in an XML source text.
   */
  private static final boolean[] IS_BANNED_ASCII = new boolean[0x20];
  static {
    for (int i = 0; i < IS_BANNED_ASCII.length; ++i) {
      IS_BANNED_ASCII[i] = !(i == '\t' || i == '\n' || i == '\r');
    }
  }

  /**
   * Bit {@code c} is set when the BMP character U+c has a compatibility
   * decomposition (NFKD) that contains a printable, non-alphanumeric ASCII
   * character, so that a downstream normalization could turn it into an HTML
   * special character: U+FE64 SMALL LESS-THAN SIGN normalizes to {@code <}.
   *
   * <p>The table is spelled out rather than derived from
   * {@code java.text.Normalizer} at class load so that output does not vary
   * with the JDK's Unicode version; {@code EncodingTest} checks it against
   * the running JDK's tables and says which characters to add if they drift.
   */
  private static final BitSet RISKY_NORMALIZATION = new BitSet(0x10000);
  static {
    // Single characters.
    String singles = "\u037e\u1fef\u203c\u207a\u208a\u2100\u2101\u2105\u2106"
        + "\u2260\u226e\u226f\u33c2\u33c7\u33d8\ufb29\ufe10\ufe19\ufe30\ufe47"
        + "\ufe48\ufe52";
    for (int i = 0, n = singles.length(); i < n; ++i) {
      RISKY_NORMALIZATION.set(singles.charAt(i));
    }
    // Pairs of characters bounding inclusive ranges.
    String ranges = "\u2024\u2026\u2047\u2049\u207c\u207e\u208c\u208e\u2474"
        + "\u24b5\u2a74\u2a76\u3200\u321e\u3220\u3243\ufe13\ufe16\ufe33\ufe38"
        + "\ufe4d\ufe50\ufe54\ufe57\ufe59\ufe5c\ufe5f\ufe66\ufe68\ufe6b\uff01"
        + "\uff0f\uff1a\uff20\uff3b\uff40\uff5b\uff5e";
    for (int i = 0, n = ranges.length(); i < n; i += 2) {
      RISKY_NORMALIZATION.set(ranges.charAt(i), ranges.charAt(i + 1) + 1);
    }
  }

  /**
   * True if a compatibility normalization of ch could produce an ASCII
   * punctuation character.
   * @see #RISKY_NORMALIZATION
   */
  static boolean isRiskyNormalization(char ch) {
    return RISKY_NORMALIZATION.get(ch);
  }
}
