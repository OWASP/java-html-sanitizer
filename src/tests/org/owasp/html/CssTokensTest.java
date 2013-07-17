// Copyright (c) 2013, Mike Samuel
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

import java.util.Arrays;
import java.util.List;

import junit.framework.TestCase;

import org.junit.Test;
import org.owasp.html.CssTokens.TokenType;

import com.google.common.collect.Lists;

import static org.owasp.html.CssTokens.TokenType.*;

public class CssTokensTest extends TestCase {

  @Test
  public static final void testBracketIndices() {
    CssTokens tokens = CssTokens.lex("([foo[[||]])");
    assertEquals("([foo[[||]]])", tokens.normalizedCss);

    List<String> tokenTexts = Lists.newArrayList();
    List<CssTokens.TokenType> types = Lists.newArrayList();
    List<Integer> partners = Lists.newArrayList();
    for (CssTokens.TokenIterator it = tokens.iterator(); it.hasNext();) {
      types.add(it.type());
      partners.add(tokens.brackets.partner(it.tokenIndex()));
      tokenTexts.add(it.next());
    }
    assertEquals(
        Arrays.asList("(", "[", "foo", "[", "[", "||", "]", "]", "]", ")"),
        tokenTexts);
    assertEquals(
        Arrays.asList(
            LEFT_PAREN, LEFT_SQUARE, IDENT, LEFT_SQUARE, LEFT_SQUARE, COLUMN,
            RIGHT_SQUARE, RIGHT_SQUARE, RIGHT_SQUARE, RIGHT_PAREN),
        types);
    // ([foo[[||]]])
    // 012  345 6789
    assertEquals(
        Arrays.asList(9, 8, -1, 7, 6, -1, 4, 3, 1, 0),
        partners);
  }

  @Test
  public static final void testStringEscaping() throws Exception {
    // input                         golden
    String[] tests = {
        "''",                          "''",
        "\"\"",                        "''",
        "\"\\a\"",                     "'\\a'",
        "\"\\0d\\0a\"",                "'\\d\\a'",
        "'\\000000d'",                 "'\\0 d'",   // too many hex digits
        "'\\1fffff'",                  "'\ufffd'",  // exceeeds max codepoint
        "\"'\"",                       "'\\27'",
        "\"\\\"\"",                    "'\\22'",
        "'\\\\'",                      "'\\\\'",
        "'-->'",                       "'-\\-\\3e'",
        "'</style>'",                  "'\\3c/style\\3e'",
        "\"<![CDATA[...]]>\"",         "'\\3c![CDATA[...]]\\3e'",
        "\"&quot;/*\"",                "'\\26quot;/*'",
        "\"\u0000AB\"",                "'\\0 AB'",
        "\"\u0000 AB\"",               "'\\0  AB'",
        "\"\u0000\\000020AB\"",        "'\\0  AB'",
        "\"\u0000\\000009AB\"",        "'\\0 \tAB'",
        "\"",                          null,
        "'",                           null,
        "\"\n",                        null,
        "\"\r",                        null,
        "'\f",                         null,
        "'\\22",                       null,
        "'foo\\\n",                    null,
        "'foo\\\r\n",                  null,
        "//\\a'foo'",                  null,
        "/*'foo\\2a/'//*/",            null,
    };
    for (int i = 0, n = tests.length; i < n; i += 2) {
      String input = tests[i],
          golden = tests[i+1];
      CssTokens tokens = CssTokens.lex(input);
      assertEquals(input, golden != null ? golden : "", tokens.normalizedCss);
      CssTokens.TokenIterator it = tokens.iterator();
      assertEquals(input, it.hasNext(), golden != null);
      if (golden != null) {
        assertEquals(input, STRING, it.type());
        assertEquals(input, golden, it.next());
        assertFalse(input, it.hasNext());
      }
    }
  }

  @Test
  public static final void testComments() throws Exception {
    assertEquals(
        "a b c d e f g h",
        CssTokens.lex(
            "//\na/*z*/b//z*/z\\az\nc/*z/**/d//*/\f/**/e/***/f/*//*/g/*z**z*/h"
            ).normalizedCss);
  }

  @Test
  public static final void testNonCommentSlash() throws Exception {
    assertEquals("foo/ bar/", CssTokens.lex("foo/bar/").normalizedCss);
  }

  @Test
  public static final void testCdoCdc() throws Exception {
    assertEquals(
        "|| and are ignorable||",
        CssTokens.lex("||<!-- and --> are ignorable||").normalizedCss);
    assertEquals(
        "<!-\\- and -\\-> are not ignorable",
        CssTokens.lex("<!\\-- and -\\-> are not ignorable").normalizedCss);
  }

  @Test
  public static final void testIdentReencoding() throws Exception {
    // input                         golden
    String[] tests = {
        "\\",                        null,
        "a",                         "a",
        "\\61",                      "a",
        "\\061",                     "a",
        "\\0061",                    "a",
        "\\00061",                   "a",
        "\\000061",                  "a",
        // First character is not an identifier part.
        "\\0000061",                 "61:NUMBER",
        "\\61 b",                    "ab",
        "\\61\tb",                   "ab",
        "\\61\nb",                   "ab",
        "\\61\fb",                   "ab",
        "\\61\rb",                   "ab",
        "ab",                        "ab",
        "_ab",                       "_ab",
        "_42",                       "_42",
        "foo-bar",                   "foo-bar",
        "-foo-bar",                  "-foo-bar",
        "\\2d foo-bar",              "-foo-bar",
        "-\\66oo-bar",               "-foo-bar",
        // \\5c66 is a single escape sequence, not \\5c66 -> \\66 -> f .
        "\\5c66oo-bar",              "\u5c66" + "oo-bar",
        "\\22foo-bar",               "\u022f" + "oo-bar",
        // \\5c is not a valid identifier
        "\\5c",                      "5c:DIMENSION",
        "\\22oo-bar",                "22oo-bar:DIMENSION",
        "\\27oo-bar",                "27oo-bar:DIMENSION",
        // \\34 encodes a digit so slash is dropped.
        "\\34mm",                    "34mm:DIMENSION",
        // Number ambiguity can arise when - is escaped.
        // We disallow such ambiguity even in the encoded output since it is
        // of little value, and a possible source of confusion.
        // In these cases, the \\ is just dropped.
        "-42",                       "-42:NUMBER",
        "\\-42",                     "-42:NUMBER",
    };
    for (int i = 0, n = tests.length; i < n; i += 2) {
      String input = tests[i],
          golden = tests[i+1];
      // Invalid escape sequences can lead to things that are not identifiers
      // once error recovery happens.
      CssTokens.TokenType type = IDENT;
      if (golden != null) {
        int colon = golden.lastIndexOf(':');
        if (colon >= 0) {  // Unambiguous since : not allowed in identifier.
          type = TokenType.valueOf(golden.substring(colon + 1));
          golden = golden.substring(0, colon);
        }
      }
      CssTokens tokens = CssTokens.lex(input);
      assertEquals(input, golden != null ? golden : "", tokens.normalizedCss);
      CssTokens.TokenIterator it = tokens.iterator();
      assertEquals(input, it.hasNext(), golden != null);
      if (golden != null) {
        assertEquals(input, type, it.type());
        assertEquals(input, golden, it.next());
        assertFalse(input, it.hasNext());
      }
    }
    // More number ambiguity.
    assertTokens("\\2d 42", "2d:DIMENSION", " ", "42:NUMBER");
    assertTokens("\\2d\t42", "2d:DIMENSION", " ", "42:NUMBER");
    assertTokens("\\2d\n42", "2d:DIMENSION", " ", "42:NUMBER");
  }

  @Test
  public static final void testOrphanedCloseBrackets() throws Exception {
    assertEquals("{foo bar}", CssTokens.lex("{foo]bar").normalizedCss);
  }

  @Test
  public static final void testAtDirectives() throws Exception {
    assertTokens(
        "@import \"foo/bar\"; @ at, @34",
        "@import:AT", " ", "'foo/bar':STRING", ";:SEMICOLON",
        " ", "@:DELIM", " ", "at:IDENT", ",:COMMA", " ",
        "@:DELIM", " ", "34:NUMBER");
  }

  @Test
  public static final void testHash() throws Exception {
    assertTokens(
        "#fff #foo #-moz-foo #abcd #abcdef #012f34 #888 #42foo # #",
        "#fff:HASH_UNRESTRICTED", " ",
        "#foo:HASH_ID", " ",
        "#-moz-foo:HASH_ID", " ",
        "#abcd:HASH_UNRESTRICTED", " ",
        "#abcdef:HASH_UNRESTRICTED", " ",
        "#012f34:HASH_UNRESTRICTED", " ",
        "#888:HASH_UNRESTRICTED", " ",
        "#42foo:HASH_ID", " ",
        "#:DELIM", " ", "#:DELIM");
  }

  @Test
  public static final void testSignsAndDots() throws Exception {
    assertTokens(
        "- . + +1 + 1 (1 + 1)--> .5 -.5 +.5 ++.5 .foo -",
        "-:IDENT", " ", ".:DELIM", " ", "+:DELIM", " ", "1:NUMBER", " ",
        "+:DELIM", " ", "1:NUMBER", " ", "(:LEFT_PAREN", "1:NUMBER", " ",
        "+:DELIM", " ", "1:NUMBER", "):RIGHT_PAREN", " ", "0.5:NUMBER", " ",
        "-0.5:NUMBER", " ", "0.5:NUMBER", " ", "+:DELIM", " ", "0.5:NUMBER",
        " ", ".foo:DOT_IDENT", " ", "-:IDENT");
    // TODO: is a single "-" an IDENT or a DELIM?  "--"?  "---"?
  }

  public static final void testMultiCharPunctuation() throws Exception {
    assertTokens(
        "|| ~= === |= =^= $= *= = : % & ~",
        "||:COLUMN", " ", "~=:MATCH", " ", "=:DELIM", "=:DELIM", "=:DELIM", " ",
        "|=:MATCH", " ", "=:DELIM", "^=:MATCH", " ", "$=:MATCH", " ",
        "*=:MATCH", " ", "=:DELIM", " ", "::COLON", " ", "%:DELIM", " ",
        "&:DELIM", " ", "~:DELIM");
  }

  @Test
  public static final void testNul() throws Exception {
    assertTokens("\u0000");
    assertTokens("\u0000x\u0000", "x:IDENT");
  }

  @Test
  public static final void testNumbers() throws Exception {
    assertTokens(
        "0 -0 +0 0.0 -0.0 -.0 0e12 0e-12 0e+12",
        "0:NUMBER", " ",
        "0:NUMBER", " ",
        "0:NUMBER", " ",
        "0:NUMBER", " ",
        "0:NUMBER", " ",
        "0:NUMBER", " ",
        "0:NUMBER", " ",
        "0:NUMBER", " ",
        "0:NUMBER");
    assertTokens(
        "1 -1 +1 1.0 -1.0 -.1e1 10e-1 .1e+1",
        "1:NUMBER", " ",
        "-1:NUMBER", " ",
        "1:NUMBER", " ",
        "1:NUMBER", " ",
        "-1:NUMBER", " ",
        "-0.1e1:NUMBER", " ",
        "10e-1:NUMBER", " ",
        "0.1e1:NUMBER");
    assertTokens(
        ".1 -.1 +.1 0.1 -0.100 -.1e0 10e-2% .01e+01 IN",
        "0.1:NUMBER", " ",
        "-0.1:NUMBER", " ",
        "0.1:NUMBER", " ",
        "0.1:NUMBER", " ",
        "-0.1:NUMBER", " ",
        "-0.1:NUMBER", " ",
        "10e-2%:PERCENTAGE", " ",
        "0.01e1in:DIMENSION");
    assertTokens("01234.567890", "1234.56789:NUMBER");
  }

  @Test
  public static final void testUrls() throws Exception {
    assertTokens(
        "url() url('..')url( \"foo\" ) URL( f\"/(bar'\\\\baz ) url('foo \\a b')"
        + "Url( \u0080\u1234\ud801\udc02\\110000)",
        "url(''):URL", " ",
        "url('..'):URL",
        "url('foo'):URL", " ",
        "url('f%22/%28bar%27%5cbaz'):URL", " ",
        "url('foo%20%0ab'):URL",
        "url('%c2%80%e1%88%b4%f0%90%90%82%ef%bf%bd'):URL"
        );
  }

  @Test
  public static final void testFunctions() throws Exception {
    assertTokens("( rgb(0,0,0) rgba(0,50%,0,100%)",
        "(:LEFT_PAREN",
        " ",
        "rgb(:FUNCTION",
        "0:NUMBER",
        ",:COMMA",
        "0:NUMBER",
        ",:COMMA",
        "0:NUMBER",
        "):RIGHT_PAREN",
        " ",
        "rgba(:FUNCTION",
        "0:NUMBER",
        ",:COMMA",
        "50%:PERCENTAGE",
        ",:COMMA",
        "0:NUMBER",
        ",:COMMA",
        "100%:PERCENTAGE",
        "):RIGHT_PAREN",
        "):RIGHT_PAREN");
  }

  @Test
  public static final void testUnicodeRanges() {
    assertTokens(
        "U+2028 U+000-49F U+2000-27FF U+2900-2BFF U+1D400-1D7FF"
        + " u+ff?? u+d8??-dc??",
        "U+2028:UNICODE_RANGE", " ",
        "U+000-49f:UNICODE_RANGE", " ",
        "U+2000-27ff:UNICODE_RANGE", " ",
        "U+2900-2bff:UNICODE_RANGE", " ",
        "U+1d400-1d7ff:UNICODE_RANGE", " ",
        "U+ff??:UNICODE_RANGE", " ",
        // Question-marked ranges cannot be dashed.
        "U+d8??:UNICODE_RANGE", " ",
        "-dc:IDENT",
        "?:DELIM", "?:DELIM");
    // TODO: invalid code-units in unicode ranges, and out of order values.
  }

  public static final void testTokenMerging() {
    assertTokens(
        "/\\* */", "/:DELIM", " ", "*:DELIM", " ", "*:DELIM", "/:DELIM");
    assertTokens(
        "/\\/", "/:DELIM", " ", "/:DELIM");
    assertTokens(
        "url\\('evil:magic()') uRl\\('.')",
        // url is not an allowable identifier.
        "(:LEFT_PAREN", "'evil:magic()':STRING", "):RIGHT_PAREN", " ",
        "(:LEFT_PAREN", "'.':STRING", "):RIGHT_PAREN");
    assertTokens(
        "foo\\(1,2)",
        "foo:IDENT",
        " ",
        // TODO: Should we be more aggressive with functions than just making
        // sure there is a space between the name and a parenthesis?
        "(:LEFT_PAREN", "1:NUMBER", ",:COMMA", "2:NUMBER",
        "):RIGHT_PAREN");
  }

  private static final void assertTokens(String css, String... goldens) {
    List<String> expectedTokens = Lists.newArrayList();
    List<CssTokens.TokenType> expectedTypes = Lists.newArrayList();
    for (String golden : goldens) {
      if (" ".equals(golden)) {
        expectedTokens.add(golden);
        expectedTypes.add(WHITESPACE);
      } else {
        int colon = golden.lastIndexOf(':');
        expectedTokens.add(golden.substring(0, colon));
        expectedTypes.add(
            CssTokens.TokenType.valueOf(golden.substring(colon+1)));
      }
    }
    List<String> actualTokens = Lists.newArrayList();
    List<CssTokens.TokenType> actualTypes = Lists.newArrayList();
    for (CssTokens.TokenIterator it = CssTokens.lex(css).iterator();
         it.hasNext();) {
      actualTypes.add(it.type());
      actualTokens.add(it.next());
    }

    // Slightly better debugging output
    assertEquals(css, expectedTokens.toString(), actualTokens.toString());
    assertEquals(css, expectedTypes.toString(), actualTypes.toString());
    // The real assertions
    assertEquals(css, expectedTokens, actualTokens);
    assertEquals(css, expectedTypes, actualTypes);
  }
}
