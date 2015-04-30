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

import com.google.common.annotations.VisibleForTesting;

/** Encoders and decoders for HTML. */
final class Encoding {

  /**
   * Decodes HTML entities to produce a string containing only valid
   * Unicode scalar values.
   */
  @VisibleForTesting
  static String decodeHtml(String s) {
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
        long endAndCodepoint = HtmlEntities.decodeEntityAt(s, amp, n);
        int end = (int) (endAndCodepoint >>> 32);
        int codepoint = (int) endAndCodepoint;
        sb.append(s, pos, amp).appendCodePoint(codepoint);
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
              sb.setCharAt(k++, ch);
              sb.setCharAt(k++, next);
              ++i;
            }
          }
          continue;
        } else if ((ch & 0xfffe) == 0xfffe) {
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
          if (i+1 < n && Character.isSurrogatePair(ch, s.charAt(i+1))) {
            ++i;  // Skip over low surrogate since we know it's ok.
          } else {
            return i;
          }
        } else if ((ch & 0xfffe) == 0xfffe) {
          return i;
        }
      }
    }
    return -1;
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
  static void encodeHtmlOnto(String plainText, Appendable output)
      throws IOException {
    int n = plainText.length();
    int pos = 0;
    for (int i = 0; i < n; ++i) {
      char ch = plainText.charAt(i);
      if (ch < REPLACEMENTS.length) {  // Handles all ASCII.
        String repl = REPLACEMENTS[ch];
        if (repl != null) {
          output.append(plainText, pos, i).append(repl);
          pos = i + 1;
        }
      } else if (((char) 0xd800) <= ch) {
        if (ch <= ((char) 0xdfff)) {
          char next;
          if (i + 1 < n
              && Character.isSurrogatePair(
                  ch, next = plainText.charAt(i + 1))) {
            // Emit supplemental codepoints as entity so that they cannot
            // be mis-encoded as UTF-8 of surrogates instead of UTF-8 proper
            // and get involved in UTF-16/UCS-2 confusion.
            int codepoint = Character.toCodePoint(ch, next);
            output.append(plainText, pos, i);
            appendNumericEntity(codepoint, output);
            ++i;
            pos = i + 1;
          } else {
            output.append(plainText, pos, i);
            // Elide the orphaned surrogate.
            pos = i + 1;
          }
        } else if (0xfe60 <= ch) {
          // Is a control character or possible full-width version of a
          // special character, a BOM, or one of the FE60 block that might
          // be elided or normalized to an HTML special character.
          // Running
          //   cat NormalizationText.txt \
          //     | perl -pe 's/ ?#.*//' \
          //     | egrep '(;003C(;|$)|003E|0026|0022|0027|0060)'
          // dumps a list of code-points that can normalize to HTML special
          // characters.
          output.append(plainText, pos, i);
          pos = i + 1;
          if ((ch & 0xfffe) == 0xfffe) {
            // Elide since not an the XML Character.
          } else {
            appendNumericEntity(ch, output);
          }
        }
      } else if (ch == '\u1FEF') {  // Normalizes to backtick.
        output.append(plainText, pos, i).append("&#8175;");
        pos = i + 1;
      }
    }
    output.append(plainText, pos, n);
  }

  @TCB
  static void appendNumericEntity(int codepoint, Appendable output)
      throws IOException {
    output.append("&#");
    if (codepoint < 100) {
      // TODO: is this dead code due to REPLACEMENTS above.
      if (codepoint < 10) {
        output.append((char) ('0' + codepoint));
      } else {
        output.append((char) ('0' + (codepoint / 10)));
        output.append((char) ('0' + (codepoint % 10)));
      }
    } else {
      int nDigits = (codepoint < 0x1000
                     ? codepoint < 0x100 ? 2 : 3
                     : (codepoint < 0x10000 ? 4
                        : codepoint < 0x100000 ? 5 : 6));
      output.append('x');
      for (int digit = nDigits; --digit >= 0;) {
        int hexDigit = (codepoint >>> (digit << 2)) & 0xf;
        output.append(HEX_NUMERAL[hexDigit]);
      }
    }
    output.append(";");
  }

  private static final char[] HEX_NUMERAL = {
   '0', '1', '2', '3', '4', '5', '6', '7',
   '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
  };

  /** Maps ASCII chars that need to be encoded to an equivalent HTML entity. */
  static final String[] REPLACEMENTS = new String[0x80];
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
  }

  /**
   * {@code DECODES_TO_SELF[c]} is true iff the codepoint c decodes to itself in
   * an HTML5 text node or properly quoted attribute value.
   */
  private static boolean[] IS_BANNED_ASCII = new boolean[0x20];
  static {
    for (int i = 0; i < IS_BANNED_ASCII.length; ++i) {
      IS_BANNED_ASCII[i] = !(i == '\t' || i == '\n' || i == '\r');
    }
  }

}
