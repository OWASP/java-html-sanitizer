// Copyright (c) 2012, Mike Samuel
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

import java.io.IOException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import javax.annotation.Nullable;

/** Encoders and decoders for HTML. */
public final class Encoding {

  /**
   * Decodes HTML entities to produce a string containing only valid
   * Unicode scalar values.
   *
   * @param s text/html
   * @return text/plain
   */
  public static String decodeHtml(String s) {
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
        int end = HtmlEntities.appendDecodedEntity(s, amp, n, sb);
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
   * Returns the portion of its input that consists of XML safe chars.
   * @see <a href="http://www.w3.org/TR/2008/REC-xml-20081126/#charsets">XML Ch. 2.2 - Characters</a>
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
   * Leaves in the input buffer only code-units that comprise XML safe chars.
   * @see <a href="http://www.w3.org/TR/2008/REC-xml-20081126/#charsets">XML Ch. 2.2 - Characters</a>
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
      } else if (0xd800 <= ch) {
        if (ch <= 0xdfff) {
          if (i+1 < n) {
            char next = sb.charAt(i+1);
            if (Character.isSurrogatePair(ch, next)) {
              // The last two code points in each plane are non-characters that should be elided.
              if ((ch & 0xfc3f) != 0xd83f || (next & 0xfffe) != 0xdffe) {
                sb.setCharAt(k++, ch);
                sb.setCharAt(k++, next);
              }
              ++i;
            }
          }
          continue;
        } else if ((ch & 0xfffe) == 0xfffe || (0xfdd0 <= ch && ch <= 0xfdef)) {
          continue;
        }
      }
      sb.setCharAt(k++, ch);
    }
    sb.setLength(k);
  }

  /**
   * The number of code-units at the front of s that form code-points in the
   * XML Character production.
   * @return -1 if all of s is in the XML Character production.
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
      } else if (0xd800 <= ch) {
        if (ch <= 0xdfff) {
          if (i + 1 < n ) {
            // could be a surrogate pair
            char cn = s.charAt(i+1);
            if( Character.isSurrogatePair(ch,cn) ) {
              int cp = Character.toCodePoint(ch, cn);
              // Could be a non-character
              if ((cp & 0xfffe) == 0xfffe) {
                // not valid
                return i;
              }

              // skip over trailing surrogate since we know it is OK
              i++;
            } else {
              // not a surrogate pair
              return i;
            }
          } else {
            // isolated surrogate at end of string
            return i;
          }
        } else if ((ch & 0xfffe) == 0xfffe || (0xfdd0 <= ch && ch <= 0xfdef)) {
          return i;
        }
      }
    }
    return -1;
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
   *     element is `<textarea>` or `<title>` and that element is still open.
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
   * Elides code-units that are not valid XML Characters.
   * @see <a href="http://www.w3.org/TR/2008/REC-xml-20081126/#charsets">XML Ch. 2.2 - Characters</a>
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
        if( repl==null ) {
          if (ch == '{') {
            if (i + 1 == n || plainText.charAt(i + 1) == '{') {
              // "{{" detected, so use the brace replacement
              repl = braceReplacement;
            }
          }
          if (ch == '\r') {
            // If this CR is followed by a LF, just remove it. Otherwise replace it with a LF.
            if (i + 1 == n || plainText.charAt(i + 1) != '\n' ) {
              // CR not followed by LF, so turn into LF
              repl = "\n";
            } else {
              // CRLF, so remove CR
              repl = "";
            }
          }
        }
        if (repl != null) {
          output.append(plainText, pos, i).append(repl);
          pos = i + 1;
        }
      } else if (RISKY_NORMALIZATION.contains(ch)) {
        // Application of unicode compatibility normalization produces a risky character.
        output.append(plainText, pos, i);
        pos = i + 1;
        appendNumericEntity(ch,output);
      } else if ((ch <= 0x9f) || (0xfdd0 <= ch && ch <= 0xfdef) || ((ch & 0xfffe) == 0xfffe)) {
        // Elide C1 escapes and BMP non-characters.
        output.append(plainText, pos, i);
        pos = i + 1;
      } else if (0xd800 <= ch && ch <= 0xdfff) {
        // handle surrogates
        char next;
        if (i + 1 < n && Character.isSurrogatePair(ch, next = plainText.charAt(i + 1))) {
          // Emit supplemental codepoints as entity so that they cannot
          // be mis-encoded as UTF-8 of surrogates instead of UTF-8 proper
          // and get involved in UTF-16/UCS-2 confusion.
          int codepoint = Character.toCodePoint(ch, next);
          output.append(plainText, pos, i);
          // do not append 0xfffe and 0xffff from any plane
          if( (codepoint & 0xfffe) != 0xfffe ) {
            appendNumericEntity(codepoint, output);
          }
          ++i;
          pos = i + 1;
        } else {
          output.append(plainText, pos, i);
          // Elide the orphaned surrogate.
          pos = i + 1;
        }
      }
    }
    output.append(plainText, pos, n);
  }


  /**
   * Append a codepoint to the output as a numeric entity.
   *
   * @param codepoint the codepoint
   * @param output    the output
   *
   * @throws IOException              if the output cannot be written to
   * @throws IllegalArgumentException if the codepoint cannot be represented as a numeric escape.
   */
  @TCB
  static void appendNumericEntity(int codepoint, Appendable output)
      throws IOException {
    if (((codepoint <= 0x1f) && (codepoint != 9 && codepoint != 0xa)) || (0x7f <= codepoint && codepoint <= 0x9f)) {
      throw new IllegalArgumentException("Illegal numeric escape. Cannot represent control code: " + codepoint);
    }
    if ((0xfdd0 <= codepoint && codepoint <= 0xfdef) || ((codepoint & 0xfffe) == 0xfffe)) {
      throw new IllegalArgumentException("Illegal numeric escape. Cannot represent non-character: " + codepoint);
    }

    output.append("&#");
    if (codepoint < 100) {
      // Below 100, a decimal representation is shortest
      output.append(Integer.toString(codepoint));
    } else {
      // Append a hexadecimal value
      output.append('x');
      output.append(Integer.toHexString(codepoint));
    }
    output.append(";");
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
    REPLACEMENTS['\u007f']  = "";                    // Elide delete
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

  /** Set of all Unicode characters which when processed with unicode compatibility decomposition will include a non-alphanumeric ascii character. */
  static final Set<Character> RISKY_NORMALIZATION;
  static {
    HashSet<Character> set = new HashSet<Character>();

    // These characters all decompose riskily
    String singles = "\u037e\u1fef\u203c\u207a\u208a\u2100\u2101\u2105\u2106\u2260\u226e\u226f\u33c2\u33c7\u33d8\ufb29\ufe10\ufe19\ufe30\ufe47\ufe48\ufe52";
    for(char ch : singles.toCharArray()) {
      set.add(ch);
    }

    // This string is composed of pairs of characters defining inclusive start and end ranges.
    String pairs =
              "\u2024\u2026\u2047\u2049\u207c\u207e\u208c\u208e\u2474\u24b5\u2a74\u2a76\u3200\u321e\u3220\u3243\ufe13\ufe16\ufe33"
            + "\ufe38\ufe4d\ufe50\ufe54\ufe57\ufe59\ufe5c\ufe5f\ufe66\ufe68\ufe6b\uff01\uff0f\uff1a\uff20\uff3b\uff40\uff5b\uff5e";
    for(int i=0;i<pairs.length();i+=2) {
      for(char ch=pairs.charAt(i);ch<=pairs.charAt(i+1);ch++) {
        set.add(ch);
      }
    }

    RISKY_NORMALIZATION = Collections.unmodifiableSet(set);
  }
}
