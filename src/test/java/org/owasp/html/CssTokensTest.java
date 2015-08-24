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

@SuppressWarnings({ "javadoc" })
public class CssTokensTest extends TestCase {

  private static CssTokens lex(String s) {
    CssTokens tokens = CssTokens.lex(s);
    // Check that lexing is idempotent.
    assertEquals(
        "`" + s + "` not idempotent",
        tokens.normalizedCss,
        CssTokens.lex(tokens.normalizedCss).normalizedCss);
    return tokens;
  }

  @Test
  public static final void testBracketIndices() {
    CssTokens tokens = lex("([foo[[||]])");
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
  public static final void testStringEscaping() {
    // input                         golden
    String[] tests = {
        "''",                          "''",
        "\"\"",                        "''",
        "\"\\a\"",                     "'\\a'",
        "\"\\0d\\0a\"",                "'\\d\\a'",
        "'\\000000d'",                 "'\\0 d'",   // too many hex digits
        "'\\1fffff'",                  "'\ufffd'",  // exceeds max codepoint
        "\"'\"",                       "'\\27'",
        "\"\\\"\"",                    "'\\22'",
        "'\\\\'",                      "'\\\\'",
        "'-->'",                       "'--\\3e'",
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
      CssTokens tokens = lex(input);
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
  public static final void testComments() {
    assertEquals(
        "a b c d e f g h",
        lex(
            "//\na/*z*/b//z*/z\\az\nc/*z/**/d//*/\f/**/e/***/f/*//*/g/*z**z*/h"
            ).normalizedCss);
  }

  @Test
  public static final void testNonCommentSlash() {
    assertEquals("foo/ bar/", lex("foo/bar/").normalizedCss);
  }

  @Test
  public static final void testCdoCdc() {
    assertEquals(
        "|| and are ignorable||",
        lex("||<!-- and --> are ignorable||").normalizedCss);
    assertEquals(
        "< !-- and -- > are not ignorable",
        lex("<!-\\- and -\\-> are not ignorable").normalizedCss);
  }

  @Test
  public static final void testIdentReencoding() {
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
        "\\5c",                      "5c:BAD_DIMENSION",
        "\\22oo-bar",                "22oo-bar:BAD_DIMENSION",
        "\\27oo-bar",                "27oo-bar:BAD_DIMENSION",
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
      CssTokens tokens = lex(input);
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
    assertTokens("\\2d 42", "2d:BAD_DIMENSION", " ", "42:NUMBER");
    assertTokens("\\2d\t42", "2d:BAD_DIMENSION", " ", "42:NUMBER");
    assertTokens("\\2d\n42", "2d:BAD_DIMENSION", " ", "42:NUMBER");
  }

  @Test
  public static final void testOrphanedCloseBrackets() {
    assertEquals("{foo bar}", lex("{foo]bar").normalizedCss);
  }

  @Test
  public static final void testAtDirectives() {
    assertTokens(
        "@import \"foo/bar\"; @ at, @34",
        "@import:AT", " ", "'foo/bar':STRING", ";:SEMICOLON",
        " ", "@:DELIM", " ", "at:IDENT", ",:COMMA", " ",
        "@:DELIM", " ", "34:NUMBER");
  }

  @Test
  public static final void testHash() {
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
  public static final void testSignsAndDots() {
    assertTokens(
        "- . + +1 + 1 (1 + 1)--> .5 -.5 +.5 ++.5 .foo -",
        "-:IDENT", " ", ".:DELIM", " ", "+:DELIM", " ", "1:NUMBER", " ",
        "+:DELIM", " ", "1:NUMBER", " ", "(:LEFT_PAREN", "1:NUMBER", " ",
        "+:DELIM", " ", "1:NUMBER", "):RIGHT_PAREN", " ", "0.5:NUMBER", " ",
        "-0.5:NUMBER", " ", "0.5:NUMBER", " ", "+:DELIM", " ", "0.5:NUMBER",
        " ", ".foo:DOT_IDENT", " ", "-:IDENT");
    // TODO: is a single "-" an IDENT or a DELIM?  "--"?  "---"?
  }

  public static final void testMultiCharPunctuation() {
    assertTokens(
        "|| ~= === |= =^= $= *= = : % & ~",
        "||:COLUMN", " ", "~=:MATCH", " ", "=:DELIM", "=:DELIM", "=:DELIM", " ",
        "|=:MATCH", " ", "=:DELIM", "^=:MATCH", " ", "$=:MATCH", " ",
        "*=:MATCH", " ", "=:DELIM", " ", "::COLON", " ", "%:DELIM", " ",
        "&:DELIM", " ", "~:DELIM");
  }

  @Test
  public static final void testNul() {
    assertTokens("\u0000");
    assertTokens("\u0000x\u0000", "x:IDENT");
  }

  @Test
  public static final void testNumbers() {
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
  public static final void testUrls() {
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
  public static final void testFunctions() {
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
    assertTokens(
        "U+?",
        "U:IDENT", "+:DELIM", " ", "?:DELIM");
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
    List<String> expected = Lists.newArrayList();
    for (String golden : goldens) {
      if (" ".equals(golden)) {
        expected.add(" :" + WHITESPACE.name());
      } else {
        int colon = golden.lastIndexOf(':');
        expected.add(
            golden.substring(0, colon) + ":"
            + CssTokens.TokenType.valueOf(golden.substring(colon+1)).name());
      }
    }
    List<String> actual = Lists.newArrayList();
    for (CssTokens.TokenIterator it = lex(css).iterator();
         it.hasNext(); it.advance()) {
      actual.add(it.token() + ":" + it.type());
    }

    // Slightly better debugging output
    assertEquals(css, expected.toString(), actual.toString());
    // The real assertions
    assertEquals(css, expected, actual);
  }

  private static void assertLexedCss(String input, String... goldens) {
    List<String> actual = Lists.newArrayList();
    for (String token : lex(input)) {
      actual.add(token);
    }
    List<String> goldensList = Arrays.asList(goldens);
    assertEquals(input, goldensList.toString(), actual.toString());
    assertEquals(input, goldensList, actual);
  }

  @Test
  public static final void testLex01() {
    assertLexedCss(
      "body {\n"
      + "	color:green;\n"
      + "}\r\n"
      + "\n"
      + "div#foo { content:\"bar{foo}\"; }",
      "body", " ", "{", " ",
      "color", ":", "green", ";", " ",
      "}", " ",
      "div", "#foo", " ", "{", " ", "content", ":", "'bar{foo}'", ";", " ", "}");
  }

  @Test
  public static final void testLex02() {
    assertLexedCss(
      "body div {\n"
      + "\tcolor:red;\n"
      + "}\n",
      "body", " ", "div", " ", "{", " ",
      "color", ":", "red", ";", " ",
      "}");
  }

  @Test
  public static final void testLex03() {
    assertLexedCss(
      "div#foo { background:url(img/blubb.png) top left repeat-y; }\n"
      + "\n"
      + "body { font-family:Verdana, Geneva, Arial, Helvetica, sans-serif; font-size:12px; }\n"
      + "\n"
      + "@import url(\"foo.css\");\n"
      + "\n"
      + "@import \"bar.css\" screen;",
      "div", "#foo", " ", "{",
      " ", "background", ":", "url('img/blubb.png')",
      " ", "top", " ", "left", " ", "repeat-y", ";", " ", "}", " ",
      "body", " ", "{", " ", "font-family", ":", "Verdana", ",",
      " ", "Geneva", ",", " ", "Arial", ",", " ", "Helvetica", ",",
      " ", "sans-serif", ";",
      " ", "font-size", ":", "12px", ";", " ", "}", " ",
      "@import", " ", "url('foo.css')", ";", " ",
      "@import", " ", "'bar.css'", " ", "screen", ";");
  }

  @Test
  public static final void testLex04() {
    assertLexedCss(
      "\n"
      + "\n"
      + "/* Komentar! */\n"
      + "@media projection {\n"
      + "\t#blubb {\n"
      + "\t\tfont-weight: /* Komentar! */ bold;\n"
      + "\t\tcontent:\';{!\"\"())!\"\';\n"
      + "\t}\n"
      + "}\n"
      + "#gnnf{\n"
      + "\tbackground:green url(\'img/beispiel.png\') top left no-repeat;\n"
      + "\ttext-align:left\n"
      + "}",
      "@media", " ", "projection", " ", "{", " ",
      "#blubb", " ", "{", " ",
      "font-weight", ":", " ", "bold", ";", " ",
      "content", ":", "';{!\\22\\22())!\\22'", ";", " ",
      "}", " ",
      "}", " ",
      "#gnnf", "{", " ",
      "background", ":", "green", " ", "url('img/beispiel.png')",
      " ", "top", " ", "left", " ", "no-repeat", ";", " ",
      "text-align", ":", "left", " ",
      "}");
  }

  @Test
  public static final void testLex05() {
    assertLexedCss(
      "/**\n"
      + " * FETTER Komentar!\n"
      + " * \n"
      + " * Bla bla bla\n"
      + " */\n"
      + "@media screen {\n"
      + "\t#test[foo] {\n"
      + "\t\tcolor:red !important;\n"
      + "\t}\n"
      + "\t#test[foo] {\n"
      + "\t\tcolor:blue;\n"
      + "\t}\n"
      + "}",
      "@media", " ", "screen", " ", "{", " ",
      "#test", "[", "foo", "]", " ", "{", " ",
      "color", ":", "red", " ", "!", "important", ";", " ",
      "}", " ",
      "#test", "[", "foo", "]", " ", "{", " ",
      "color", ":", "blue", ";", " ",
      "}", " ",
      "}");
  }

  @Test
  public static final void testLex06() {
    assertLexedCss(
      "#blah[rel=\"/{_-;!\"] div > #blargh span.narf {\n"
      + "\tbackground:green;\n"
      + "\ttext-align:left;\n"
      + "}",
      "#blah", "[", "rel", "=", "'/{_-;!'", "]", " ", "div",
      " ", ">", " ", "#blargh", " ", "span", ".narf", " ", "{", " ",
      "background", ":", "green", ";", " ",
      "text-align", ":", "left", ";", " ",
      "}");
  }

  @Test
  public static final void testLex07() {
    assertLexedCss(
      "/* Komentar! */\n"
      + "@media print {\n"
      + "\t#gnarf {\n"
      + "\t\tfont-weight:normal;\n"
      + "\t\tfont-size:2em\n"
      + "\t}\n"
      + "}",
      "@media", " ", "print", " ", "{", " ",
      "#gnarf", " ", "{", " ",
      "font-weight", ":", "normal", ";", " ",
      "font-size", ":", "2em", " ",
      "}", " ",
      "}");
  }

  @Test
  public static final void testLex08() {
    assertLexedCss(
      "#foobar {\n"
      + "\tfont-family:\"Trebuchet MS\", Verdana, Arial, sans-serif;\n"
      + "}",
      "#foobar", " ", "{", " ",
      "font-family", ":", "'Trebuchet MS'", ",", " ", "Verdana", ",",
      " ", "Arial", ",", " ", "sans-serif", ";", " ",
      "}");
  }

  @Test
  public static final void testLex09() {
    assertLexedCss(
      "p { color:red !important; }\n"
      + ".foo { color:green; }",
      "p", " ", "{", " ", "color", ":", "red", " ", "!", "important", ";",
      " ", "}", " ",
      ".foo", " ", "{", " ", "color", ":", "green", ";", " ", "}");
  }

  @Test
  public static final void testLex10() {
    assertLexedCss(
      "@media screen{\n"
      + "\t#wrapper {\n"
      + "\t\tcolor:blue;\n"
      + "\t\tfont-weight:bold !important;\n"
      + "\t\ttext-decoration:underline;\n"
      + "\t}\n"
      + "\t#wrapper {\n"
      + "\t\tcolor:red;\n"
      + "\t\tfont-weight:normal;\n"
      + "\t\tfont-style:italic;\n"
      + "\t}\n"
      + "}\n"
      + "\n"
      + "@media print {\n"
      + "\t#wrapper {\n"
      + "\t\tcolor:green;\n"
      + "\t}\n"
      + "}",
      "@media", " ", "screen", "{", " ",
      "#wrapper", " ", "{", " ",
      "color", ":", "blue", ";", " ",
      "font-weight", ":", "bold", " ", "!", "important", ";", " ",
      "text-decoration", ":", "underline", ";", " ",
      "}", " ",
      "#wrapper", " ", "{", " ",
      "color", ":", "red", ";", " ",
      "font-weight", ":", "normal", ";", " ",
      "font-style", ":", "italic", ";", " ",
      "}", " ",
      "}", " ",
      "@media", " ", "print", " ", "{", " ",
      "#wrapper", " ", "{", " ",
      "color", ":", "green", ";", " ",
      "}", " ",
      "}");
  }

  @Test
  public static final void testLex11() {
    assertLexedCss(
      "\n"
      + "ADDRESS,\n"
      + "BLOCKQUOTE, \n"
      + "BODY, DD, DIV, \n"
      + "DL, DT, \n"
      + "FIELDSET, FORM,\n"
      + "FRAME, FRAMESET,\n"
      + "H1, H2, H3, H4, \n"
      + "H5, H6, IFRAME, \n"
      + "NOFRAMES, \n"
      + "OBJECT, OL, P, \n"
      + "UL, APPLET, \n"
      + "CENTER, DIR, \n"
      + "HR, MENU, PRE   { display: block }\n"
      + "LI              { display: list-item }\n"
      + "HEAD            { display: none }\n"
      + "TABLE           { display: table }\n"
      + "TR              { display: table-row }\n"
      + "THEAD           { display: table-header-group }\n"
      + "TBODY           { display: table-row-group }\n"
      + "TFOOT           { display: table-footer-group }\n"
      + "COL             { display: table-column }\n"
      + "COLGROUP        { display: table-column-group }\n"
      + "TD, TH          { display: table-cell }\n"
      + "CAPTION         { display: table-caption }\n"
      + "TH              { font-weight: bolder; text-align: center }\n"
      + "CAPTION         { text-align: center }\n"
      + "BODY            { padding: 8px; line-height: 1.33 }\n"
      + "H1              { font-size: 2em; margin: .67em 0 }\n"
      + "H2              { font-size: 1.5em; margin: .83em 0 }\n"
      + "H3              { font-size: 1.17em; margin: 1em 0 }\n"
      + "H4, P,\n"
      + "BLOCKQUOTE, UL,\n"
      + "FIELDSET, FORM,\n"
      + "OL, DL, DIR,\n"
      + "MENU            { margin: 1.33em 0 }\n"
      + "H5              { font-size: .83em; line-height: 1.17em; margin: 1.67em 0 }\n"
      + "H6              { font-size: .67em; margin: 2.33em 0 }\n"
      + "H1, H2, H3, H4,\n"
      + "H5, H6, B,\n"
      + "STRONG          { font-weight: bolder }\n"
      + "BLOCKQUOTE      { margin-left: 40px; margin-right: 40px }\n"
      + "I, CITE, EM,\n"
      + "VAR, ADDRESS    { font-style: italic }\n"
      + "PRE, TT, CODE,\n"
      + "KBD, SAMP       { font-family: monospace }\n"
      + "PRE             { white-space: pre }\n"
      + "BIG             { font-size: 1.17em }\n"
      + "SMALL, SUB, SUP { font-size: .83em }\n"
      + "SUB             { vertical-align: sub }\n"
      + "SUP             { vertical-align: super }\n"
      + "S, STRIKE, DEL  { text-decoration: line-through }\n"
      + "HR              { border: 1px inset }\n"
      + "OL, UL, DIR,\n"
      + "MENU, DD        { margin-left: 40px }\n"
      + "OL              { list-style-type: decimal }\n"
      + "OL UL, UL OL,\n"
      + "UL UL, OL OL    { margin-top: 0; margin-bottom: 0 }\n"
      + "U, INS          { text-decoration: underline }\n"
      + "CENTER          { text-align: center }\n"
      + "BR:before       { content: \"\\A\" }\n"
      + "COLOR_NOHASH\t{ color:987E81 }",
      "ADDRESS", ",", " ",
      "BLOCKQUOTE", ",", " ",
      "BODY", ",", " ", "DD", ",", " ", "DIV", ",", " ",
      "DL", ",", " ", "DT", ",", " ",
      "FIELDSET", ",", " ", "FORM", ",", " ",
      "FRAME", ",", " ", "FRAMESET", ",", " ",
      "H1", ",", " ", "H2", ",", " ", "H3", ",", " ", "H4", ",", " ",
      "H5", ",", " ", "H6", ",", " ", "IFRAME", ",", " ",
      "NOFRAMES", ",", " ",
      "OBJECT", ",", " ", "OL", ",", " ", "P", ",", " ",
      "UL", ",", " ", "APPLET", ",", " ",
      "CENTER", ",", " ", "DIR", ",", " ",
      "HR", ",", " ", "MENU", ",", " ", "PRE", " ", "{",
      " ", "display", ":", " ", "block", " ", "}", " ",
      "LI", " ", "{", " ", "display", ":", " ", "list-item", " ", "}", " ",
      "HEAD", " ", "{", " ", "display", ":", " ", "none", " ", "}", " ",
      "TABLE", " ", "{", " ", "display", ":", " ", "table", " ", "}", " ",
      "TR", " ", "{", " ", "display", ":", " ", "table-row", " ", "}", " ",
      "THEAD", " ", "{",
      " ", "display", ":", " ", "table-header-group", " ", "}", " ",
      "TBODY", " ", "{",
      " ", "display", ":", " ", "table-row-group", " ", "}", " ",
      "TFOOT", " ", "{",
      " ", "display", ":", " ", "table-footer-group", " ", "}", " ",
      "COL", " ", "{", " ", "display", ":", " ", "table-column", " ", "}", " ",
      "COLGROUP", " ", "{",
      " ", "display", ":", " ", "table-column-group", " ", "}", " ",
      "TD", ",", " ", "TH", " ", "{",
      " ", "display", ":", " ", "table-cell", " ", "}", " ",
      "CAPTION", " ", "{",
      " ", "display", ":", " ", "table-caption", " ", "}", " ",
      "TH", " ", "{",
      " ", "font-weight", ":", " ", "bolder", ";",
      " ", "text-align", ":", " ", "center", " ", "}", " ",
      "CAPTION", " ", "{",
      " ", "text-align", ":", " ", "center", " ", "}", " ",
      "BODY", " ", "{",
      " ", "padding", ":", " ", "8px", ";",
      " ", "line-height", ":", " ", "1.33", " ", "}", " ",
      "H1", " ", "{",
      " ", "font-size", ":", " ", "2em", ";",
      " ", "margin", ":", " ", "0.67em", " ", "0", " ", "}", " ",
      "H2", " ", "{",
      " ", "font-size", ":", " ", "1.5em", ";",
      " ", "margin", ":", " ", "0.83em", " ", "0", " ", "}", " ",
      "H3", " ", "{",
      " ", "font-size", ":", " ", "1.17em", ";",
      " ", "margin", ":", " ", "1em", " ", "0", " ", "}", " ",
      "H4", ",", " ", "P", ",", " ",
      "BLOCKQUOTE", ",", " ", "UL", ",", " ",
      "FIELDSET", ",", " ", "FORM", ",", " ",
      "OL", ",", " ", "DL", ",", " ", "DIR", ",", " ",
      "MENU", " ", "{", " ", "margin", ":", " ", "1.33em", " ", "0", " ", "}", " ",
      "H5", " ", "{", " ", "font-size", ":", " ", "0.83em", ";",
      " ", "line-height", ":", " ", "1.17em",  ";",
      " ", "margin", ":", " ", "1.67em", " ", "0", " ", "}", " ",
      "H6", " ", "{", " ", "font-size", ":", " ", "0.67em", ";",
      " ", "margin", ":", " ", "2.33em", " ", "0", " ", "}", " ",
      "H1", ",", " ", "H2", ",", " ", "H3", ",", " ", "H4", ",", " ",
      "H5", ",", " ", "H6", ",", " ", "B", ",", " ",
      "STRONG", " ", "{", " ", "font-weight", ":", " ", "bolder", " ", "}", " ",
      "BLOCKQUOTE", " ", "{", " ", "margin-left", ":", " ", "40px", ";",
      " ", "margin-right", ":", " ", "40px", " ", "}", " ",
      "I", ",", " ", "CITE", ",", " ", "EM", ",", " ",
      "VAR", ",", " ", "ADDRESS", " ", "{",
      " ", "font-style", ":", " ", "italic", " ", "}", " ",
      "PRE", ",", " ", "TT", ",", " ", "CODE", ",", " ",
      "KBD", ",", " ", "SAMP", " ", "{",
      " ", "font-family", ":", " ", "monospace", " ", "}", " ",
      "PRE", " ", "{", " ", "white-space", ":", " ", "pre", " ", "}", " ",
      "BIG", " ", "{", " ", "font-size", ":", " ", "1.17em", " ", "}", " ",
      "SMALL", ",", " ", "SUB", ",", " ", "SUP", " ", "{", " ", "font-size",
      ":", " ", "0.83em", " ", "}", " ",
      "SUB", " ", "{", " ", "vertical-align", ":", " ", "sub", " ", "}", " ",
      "SUP", " ", "{", " ", "vertical-align", ":", " ", "super", " ", "}", " ",
      "S", ",", " ", "STRIKE", ",", " ", "DEL", " ", "{",
      " ", "text-decoration", ":", " ", "line-through", " ", "}", " ",
      "HR", " ", "{", " ", "border", ":", " ", "1px", " ", "inset", " ", "}", " ",
      "OL", ",", " ", "UL", ",", " ", "DIR", ",", " ",
      "MENU", ",", " ", "DD", " ", "{",
      " ", "margin-left", ":", " ", "40px", " ", "}", " ",
      "OL", " ", "{", " ", "list-style-type", ":", " ", "decimal", " ", "}", " ",
      "OL", " ", "UL", ",", " ", "UL", " ", "OL", ",", " ",
      "UL", " ", "UL", ",", " ", "OL", " ", "OL", " ", "{",
      " ", "margin-top", ":", " ", "0", ";",
      " ", "margin-bottom", ":", " ", "0", " ", "}", " ",
      "U", ",", " ", "INS", " ", "{",
      " ", "text-decoration", ":", " ", "underline", " ", "}", " ",
      "CENTER", " ", "{", " ", "text-align", ":", " ", "center", " ", "}", " ",
      "BR", ":", "before", " ", "{",
      " ", "content", ":", " ", "'\\a'", " ", "}", " ",
      "COLOR_NOHASH", " ", "{", " ", "color", ":", "987e81", " ", "}");
  }

  @Test
  public static final void testLex12() {
    assertLexedCss(
      "/* An example of style for HTML 4.0\'s ABBR/ACRONYM elements */\n"
      + "\n"
      + "ABBR, ACRONYM   { font-variant: small-caps; letter-spacing: 0.1em }\n"
      + "A[href]         { text-decoration: underline }\n"
      + ":focus          { outline: thin dotted invert }",
      "ABBR", ",", " ", "ACRONYM", " ", "{",
      " ", "font-variant", ":", " ", "small-caps", ";",
      " ", "letter-spacing", ":", " ", "0.1em", " ", "}", " ",
      "A", "[", "href", "]", " ", "{",
      " ", "text-decoration", ":", " ", "underline", " ", "}", " ",
      ":", "focus", " ", "{",
      " ", "outline", ":", " ", "thin", " ", "dotted", " ", "invert", " ", "}");
  }

  @Test
  public static final void testLex13() {
    assertLexedCss(
      "/* Begin bidirectionality settings (do not change) */\n"
      + "BDO[DIR=\"ltr\"]  { direction: ltr; unicode-bidi: bidi-override }\n"
      + "BDO[DIR=\"rtl\"]  { direction: rtl; unicode-bidi: bidi-override }\n"
      + "\n"
      + "*[DIR=\"ltr\"]    { direction: ltr; unicode-bidi: embed }\n"
      + "*[DIR=\"rtl\"]    { direction: rtl; unicode-bidi: embed }\n"
      + "\n"
      + "/* Elements that are block-level in HTML4 */\n"
      + "ADDRESS, BLOCKQUOTE, BODY, DD, DIV, DL, DT, FIELDSET, \n"
      + "FORM, FRAME, FRAMESET, H1, H2, H3, H4, H5, H6, IFRAME,\n"
      + "NOSCRIPT, NOFRAMES, OBJECT, OL, P, UL, APPLET, CENTER, \n"
      + "DIR, HR, MENU, PRE, LI, TABLE, TR, THEAD, TBODY, TFOOT, \n"
      + "COL, COLGROUP, TD, TH, CAPTION \n"
      + "                { unicode-bidi: embed }\n"
      + "/* End bidi settings */",
      "BDO", "[", "DIR", "=", "'ltr'", "]", " ", "{",
      " ", "direction", ":", " ", "ltr", ";",
      " ", "unicode-bidi", ":", " ", "bidi-override", " ", "}", " ",
      "BDO", "[", "DIR", "=", "'rtl'", "]", " ", "{",
      " ", "direction", ":", " ", "rtl", ";",
      " ", "unicode-bidi", ":", " ", "bidi-override", " ", "}", " ",
      "*", "[", "DIR", "=", "'ltr'", "]", " ", "{",
      " ", "direction", ":", " ", "ltr", ";",
      " ", "unicode-bidi", ":", " ", "embed", " ", "}", " ",
      "*", "[", "DIR", "=", "'rtl'", "]", " ", "{",
      " ", "direction", ":", " ", "rtl", ";",
      " ", "unicode-bidi", ":", " ", "embed", " ", "}", " ",
      "ADDRESS", ",", " ", "BLOCKQUOTE", ",", " ", "BODY", ",",
      " ", "DD", ",", " ", "DIV", ",", " ", "DL", ",", " ", "DT", ",",
      " ", "FIELDSET", ",", " ",
      "FORM", ",", " ", "FRAME", ",", " ", "FRAMESET", ",", " ", "H1", ",",
      " ", "H2", ",", " ", "H3", ",", " ", "H4", ",", " ", "H5", ",",
      " ", "H6", ",", " ", "IFRAME", ",", " ",
      "NOSCRIPT", ",", " ", "NOFRAMES", ",", " ", "OBJECT", ",",
      " ", "OL", ",", " ", "P", ",", " ", "UL", ",", " ", "APPLET", ",",
      " ", "CENTER", ",", " ",
      "DIR", ",", " ", "HR", ",", " ", "MENU", ",", " ", "PRE", ",",
      " ", "LI", ",", " ", "TABLE", ",", " ", "TR", ",", " ", "THEAD", ",",
      " ", "TBODY", ",", " ", "TFOOT", ",", " ",
      "COL", ",", " ", "COLGROUP", ",", " ", "TD", ",", " ", "TH", ",",
      " ", "CAPTION", " ",
      "{", " ", "unicode-bidi", ":", " ", "embed", " ", "}");
  }

  @Test
  public static final void testLex14() {
    assertLexedCss(
      "\n"
      + "@media print {\n"
      + "  /* @page         { margin: 10% }  */ /* not allowed according to spec */\n"
      + "  H1, H2, H3,\n"
      + "  H4, H5, H6    { page-break-after: avoid; page-break-inside: avoid }\n"
      + "  BLOCKQUOTE, \n"
      + "  PRE           { page-break-inside: avoid }\n"
      + "  UL, OL, DL    { page-break-before: avoid }\n"
      + "}",
      "@media", " ", "print", " ", "{", " ",
      "H1", ",", " ", "H2", ",", " ", "H3", ",", " ",
      "H4", ",", " ", "H5", ",", " ", "H6", " ", "{",
      " ", "page-break-after", ":", " ", "avoid", ";",
      " ", "page-break-inside", ":", " ", "avoid", " ", "}", " ",
      "BLOCKQUOTE", ",", " ",
      "PRE", " ", "{", " ", "page-break-inside", ":", " ", "avoid", " ", "}", " ",
      "UL", ",", " ", "OL", ",", " ", "DL", " ", "{",
      " ", "page-break-before", ":", " ", "avoid", " ", "}", " ",
      "}");
  }

  @Test
  public static final void testLex15() {
    assertLexedCss(
      "@media speech {\n"
      + "  H1, H2, H3, \n"
      + "  H4, H5, H6    { voice-family: paul, male; stress: 20; richness: 90 }\n"
      + "  H1            { pitch: x-low; pitch-range: 90 }\n"
      + "  H2            { pitch: x-low; pitch-range: 80 }\n"
      + "  H3            { pitch: low; pitch-range: 70 }\n"
      + "  H4            { pitch: medium; pitch-range: 60 }\n"
      + "  H5            { pitch: medium; pitch-range: 50 }\n"
      + "  H6            { pitch: medium; pitch-range: 40 }\n"
      + "  LI, DT, DD    { pitch: medium; richness: 60 }\n"
      + "  DT            { stress: 80 }\n"
      + "  PRE, CODE, TT { pitch: medium; pitch-range: 0; stress: 0; richness: 80 }\n"
      + "  EM            { pitch: medium; pitch-range: 60; stress: 60; richness: 50 }\n"
      + "  STRONG        { pitch: medium; pitch-range: 60; stress: 90; richness: 90 }\n"
      + "  DFN           { pitch: high; pitch-range: 60; stress: 60 }\n"
      + "  S, STRIKE     { richness: 0 }\n"
      + "  I             { pitch: medium; pitch-range: 60; stress: 60; richness: 50 }\n"
      + "  B             { pitch: medium; pitch-range: 60; stress: 90; richness: 90 }\n"
      + "  U             { richness: 0 }\n"
      + "  A:link        { voice-family: harry, male }\n"
      + "  A:visited     { voice-family: betty, female }\n"
      + "  A:active      { voice-family: betty, female; pitch-range: 80; pitch: x-high }\n"
      + "}",
      "@media", " ", "speech", " ", "{", " ",
      "H1", ",", " ", "H2", ",", " ", "H3", ",", " ",
      "H4", ",", " ", "H5", ",", " ", "H6",
      " ", "{", " ", "voice-family", ":", " ", "paul", ",", " ", "male", ";",
      " ", "stress", ":", " ", "20", ";", " ", "richness", ":", " ", "90",
      " ", "}", " ",
      "H1", " ", "{", " ", "pitch", ":", " ", "x-low", ";",
      " ", "pitch-range", ":", " ", "90", " ", "}", " ",
      "H2", " ", "{", " ", "pitch", ":", " ", "x-low", ";",
      " ", "pitch-range", ":", " ", "80", " ", "}", " ",
      "H3", " ", "{", " ", "pitch", ":", " ", "low", ";",
      " ", "pitch-range", ":", " ", "70", " ", "}", " ",
      "H4", " ", "{", " ", "pitch", ":", " ", "medium", ";",
      " ", "pitch-range", ":", " ", "60", " ", "}", " ",
      "H5", " ", "{", " ", "pitch", ":", " ", "medium", ";",
      " ", "pitch-range", ":", " ", "50", " ", "}", " ",
      "H6", " ", "{", " ", "pitch", ":", " ", "medium", ";",
      " ", "pitch-range", ":", " ", "40", " ", "}", " ",
      "LI", ",", " ", "DT", ",", " ", "DD", " ", "{",
      " ", "pitch", ":", " ", "medium", ";",
      " ", "richness", ":", " ", "60", " ", "}", " ",
      "DT", " ", "{", " ", "stress", ":", " ", "80", " ", "}", " ",
      "PRE", ",", " ", "CODE", ",", " ", "TT", " ", "{",
      " ", "pitch", ":", " ", "medium", ";",
      " ", "pitch-range", ":", " ", "0", ";",
      " ", "stress", ":", " ", "0", ";",
      " ", "richness", ":", " ", "80", " ", "}", " ",
      "EM", " ", "{", " ", "pitch", ":", " ", "medium", ";",
      " ", "pitch-range", ":", " ", "60", ";",
      " ", "stress", ":", " ", "60", ";",
      " ", "richness", ":", " ", "50", " ", "}", " ",
      "STRONG", " ", "{", " ", "pitch", ":", " ", "medium", ";",
      " ", "pitch-range", ":", " ", "60", ";",
      " ", "stress", ":", " ", "90", ";",
      " ", "richness", ":", " ", "90", " ", "}", " ",
      "DFN", " ", "{", " ", "pitch", ":", " ", "high", ";",
      " ", "pitch-range", ":", " ", "60", ";", " ",
      "stress", ":", " ", "60", " ", "}", " ",
      "S", ",", " ", "STRIKE", " ", "{",
      " ", "richness", ":", " ", "0", " ", "}", " ",
      "I", " ", "{", " ", "pitch", ":", " ", "medium", ";",
      " ", "pitch-range", ":", " ", "60", ";",
      " ", "stress", ":", " ", "60", ";",
      " ", "richness", ":", " ", "50", " ", "}", " ",
      "B", " ", "{", " ", "pitch", ":", " ", "medium", ";",
      " ", "pitch-range", ":", " ", "60", ";",
      " ", "stress", ":", " ", "90", ";",
      " ", "richness", ":", " ", "90", " ", "}", " ",
      "U", " ", "{", " ", "richness", ":", " ", "0", " ", "}", " ",
      "A", ":", "link", " ", "{",
      " ", "voice-family", ":", " ", "harry", ",", " ", "male", " ", "}", " ",
      "A", ":", "visited", " ", "{",
      " ", "voice-family", ":", " ", "betty", ",", " ", "female", " ", "}", " ",
      "A", ":", "active", " ", "{",
      " ", "voice-family", ":", " ", "betty", ",", " ", "female", ";",
      " ", "pitch-range", ":", " ", "80", ";",
      " ", "pitch", ":", " ", "x-high", " ", "}", " ",
      "}");
  }

  @Test
  public static final void testLex16() {
    assertLexedCss(
      "FOO > BAR + BAZ {  }",
      "FOO", " ", ">", " ", "BAR", " ", "+", " ", "BAZ", " ", "{", " ", "}");
  }

  @Test
  public static final void testLex17() {
    assertLexedCss(
      "A[href] BOO[zwop |= \"hello\"]:blinky {\n"
      + "  color: #fff;\n"
      + "  background: +#000000 ! important\n"
      + "}",
      "A", "[", "href", "]",
      " ", "BOO", "[", "zwop", " ", "|=", " ", "'hello'", "]", ":", "blinky",
      " ", "{", " ",
      "color", ":", " ", "#fff", ";", " ",
      "background", ":", " ", "+", " ", "#000000", " ", "!", " ", "important",
      " ",
      "}");
  }

  @Test
  public static final void testLex18() {
    assertLexedCss(
      ".myclass[attr ~= almost] #id:hover(languidly) {\n"
      + "  font-weight: super(bold / italic)\n"
      + "}",
      ".myclass", "[", "attr", " ", "~=", " ", "almost", "]",
      " ", "#id", ":", "hover(", "languidly", ")", " ", "{", " ",
      "font-weight", ":", " ", "super(", "bold", " ", "/", " ", "italic", ")",
      " ", "}");
  }

  @Test
  public static final void testLex19() {
    assertLexedCss(
      "/* The RHS of the attribute comparison operators parse to quoted\n"
      + " * parse to quoted strings since they are surrounded by quotes. */\n"
      + "foo[attr = \'bar\'] {}\n"
      + "foo[attr = \"bar\"] {}\n"
      + "foo[attr ~= \'bar baz\'] {}\n"
      + "foo[attr |= \'bar-baz\'] {}",
      "foo", "[", "attr", " ", "=", " ", "'bar'", "]", " ", "{", "}", " ",
      "foo", "[", "attr", " ", "=", " ", "'bar'", "]", " ", "{", "}", " ",
      "foo", "[", "attr", " ", "~=", " ", "'bar baz'", "]", " ", "{", "}", " ",
      "foo", "[", "attr", " ", "|=", " ", "'bar-baz'", "]", " ", "{", "}");
  }

  @Test
  public static final void testLex20() {
    assertLexedCss(
      "/* The RHS of the attribute comparison operator in the following cases\n"
      + " * will parse to an IdentLiteral since it is unquoted. */\n"
      + "foo[attr = bar] {}\n"
      + "foo[attr |= bar-baz] {}",
      "foo", "[", "attr", " ", "=", " ", "bar", "]", " ", "{", "}", " ",
      "foo", "[", "attr", " ", "|=", " ", "bar-baz", "]", " ", "{", "}");
  }

  @Test
  public static final void testLex21() {
    assertLexedCss(
      "foo.bar { }",
      "foo", ".bar", " ", "{", " ", "}");
  }

  @Test
  public static final void testLex22() {
    assertLexedCss(
      "foo .bar { }",
      "foo", " ", ".bar", " ", "{", " ", "}");
  }

  @Test
  public static final void testLex23() {
    assertLexedCss(
      "foo .quoted { content: \'contains \\\'quotes\\\'\' }",
      "foo", " ", ".quoted", " ", "{", " ", "content", ":", " ",
      "'contains \\27quotes\\27\'", " ", "}");
  }

  @Test
  public static final void testLex24() {
    assertLexedCss(
      "foo .dquoted { content: \"\'contains\'\\\\\\\"double quotes\\\"\" }",
      "foo", " ", ".dquoted", " ", "{", " ", "content", ":", " ",
      "'\\27 contains\\27\\\\\\22 double quotes\\22'", " ", "}");
  }

  @Test
  public static final void testLex25() {
    assertLexedCss(
      "foo .long { content: \'spans \\\n"
      + "multiple \\\n"
      + "lines\' }\n",
      "foo", " ", ".long", " ", "{", " ", "content", ":", " ",
      "'spans multiple lines'", " ", "}");
  }

  @Test
  public static final void testLex26() {
    assertLexedCss(
      "foo .extended-unicode { content: \'a1 \\61\\31  \\0000611 \\000061 1 \\0061\\0031\' }",
      "foo", " ", ".extended-unicode", " ", "{", " ", "content", ":", " ",
      "'a1 a1 a1 a1 a1'", " ", "}");
  }

  @Test
  public static final void testLex27() {
    assertLexedCss(
      "/* CSS 2.1 allows _ in identifiers */\n"
      + "#a_b {}\n"
      + ".a_b {}",
      "#a_b", " ", "{", "}", " ", ".a_b", " ", "{", "}");
  }

  @Test
  public static final void testLex28() {
    assertLexedCss(
      "#xxx {\n"
      + "  filter:alpha(opacity=50);\n"
      + "}",
      "#xxx", " ", "{", " ",
      "filter", ":", "alpha(", "opacity", "=", "50", ")", ";", " ",
      "}");
  }

  @Test
  public static final void testLex29() {
    assertLexedCss(
      "p { margin: -3px -3px }\n"
      + "p { margin: -3px 3px }",
      "p", " ", "{", " ", "margin", ":", " ", "-3px", " ", "-3px", " ", "}", " ",
      "p", " ", "{", " ", "margin", ":", " ", "-3px", " ", "3px", " ", "}");
  }

  @Test
  public static final void testLex30() {
    assertLexedCss(
      "<!-- \n"
      + "p { content: \'-->foo<!--\' }  /* - -> bar <!--- */\n"
      + "-->",
      "p", " ", "{", " ", "content", ":",
      " ", "'--\\3e foo\\3c!--'", " ", "}");
  }

  @Test
  public static final void testLex31() {
    assertLexedCss(
      "@bogus hello {\n"
      + "  balanced { curly \"brackets\" };\n"
      + "}",
      "@bogus", " ", "hello", " ", "{", " ",
      "balanced", " ", "{", " ", "curly", " ", "'brackets'", " ", "}", ";",
      " ", "}");
  }

  @Test
  public static final void testLex32() {
    assertLexedCss(
      "/* Not treated as part of the bogus symbol block */\n"
      + "* { color: red }",
      "*", " ", "{", " ", "color", ":", " ", "red", " ", "}");
  }

  @Test
  public static final void testLex33() {
    assertLexedCss(
      "@unknown(\'hi\');",
      "@unknown", "(", "'hi'", ")", ";");
  }

  @Test
  public static final void testLex34() {
    assertLexedCss(
      "/* list applies to body, input, and td.  Extraneous , skip. */\n"
      + "body, input, , td {\n"
      + "  /* missing property name causes skip until ; */\n"
      + "  Arial, sans-serif;\n"
      + "  color: blue;\n"
      + "  /* missing value.  skipped. */\n"
      + "  background-color:\n"
      + "}",
      "body", ",", " ", "input", ",", " ", ",", " ", "td",
      " ", "{", " ", "Arial", ",", " ", "sans-serif", ";",
      " ", "color", ":", " ", "blue", ";",
      " ", "background-color", ":", " ", "}");
  }

  @Test
  public static final void testLex35() {
    assertLexedCss(
      "/* not thrown out, but 2 digit color is discarded */\n"
      + "@media print {\n"
      + "  * { color: black !important; background-color: #ff }\n"
      + "}",
      "@media", " ", "print", " ", "{",
      " ", "*", " ", "{", " ", "color", ":", " ", "black", " ", "!", "important", ";", " ", "background-color", ":", " ", "#ff", " ", "}", " ", "}");
  }

  @Test
  public static final void testLex36() {
    assertLexedCss(
      "@page :{broken { margin-left: 4cm; }  /* extra { */",
      "@page", " ", ":", "{", "broken", " ", "{",
      " ", "margin-left", ":", " ", "4cm", ";", " ", "}", " ", "}");
  }

  @Test
  public static final void testLex37() {
    assertLexedCss(
      "@page .broken {}  /* no colon */",
      "@page", " ", ".broken", " ", "{", "}");
  }

  @Test
  public static final void testLex38() {
    assertLexedCss(
      "@page :{}  /* no pseudo-page */",
      "@page", " ", ":", "{", "}");
  }

  @Test
  public static final void testLex39() {
    assertLexedCss(
      "@page :broken {  /* missing \'}\' */",
      "@page", " ", ":", "broken", " ", "{", " ", "}");
  }

  @Test
  public static final void testLex40() {
    assertLexedCss(
      "@page :left { margin-left: 4cm;; size: 8.5in 11in; }  /* ok */",
      "@page", " ", ":", "left", " ", "{",
      " ", "margin-left", ":", " ", "4cm", ";", ";",
      " ", "size", ":", " ", "8.5in", " ", "11in", ";", " ", "}");
  }

  @Test
  public static final void testLex41() {
    assertLexedCss(
      "/* missing property */\n"
      + "body { : blue }",
      "body", " ", "{", " ", ":", " ", "blue", " ", "}");
  }

  @Test
  public static final void testLex42() {
    assertLexedCss(
      "color: blue;",
      "color", ":", " ", "blue", ";");
  }

  @Test
  public static final void testLex43() {
    assertLexedCss(
      "a:visited, :unvisited, a::before { color: blue }",
      "a", ":", "visited", ",",
      " ", ":", "unvisited", ",",
      " ", "a", ":", ":", "before",
      " ", "{", " ", "color", ":", " ", "blue", " ", "}");
  }

  @Test
  public static final void testLex44() {
    assertLexedCss(
      "/* not a valid wildcard wiseguy */\n"
      + "? { color: blue }",
      "?", " ", "{", " ", "color", ":", " ", "blue", " ", "}");
  }

  @Test
  public static final void testLex45() {
    assertLexedCss(
      "/* lots of invalid selectors */\n"
      + ".3, #333, a[href=\'foo\', a[href=], a[=\'foo\'], body:, ok {}",
      "0.3", ",",
      " ", "#333", ",",
      " ", "a", "[", "href", "=", "'foo'", ",",
      " ", "a", "[", "href", "=", "]", ",",
      " ", "a", "[", "=", "'foo'", "]", ",",
      " ", "body", ":", ",",
      " ", "ok", " ", "{", "}",
      "]");
  }

  @Test
  public static final void testLex46() {
    assertLexedCss(
      "/* all invalid selectors */\n"
      + "#333, .3, .,  {}",
      "#333", ",", " ", "0.3", ",", " ", ".", " ", ",", " ", "{", "}");
  }

  @Test
  public static final void testLex47() {
    assertLexedCss(
      "/* valid selectors missing a body */\n"
      + "a, b, i, p, q, s, u, ;",
      "a", ",", " ", "b", ",", " ", "i", ",", " ", "p", ",", " ", "q", ",",
      " ", "s", ",", " ", "u", ",", " ", ";");
  }

  @Test
  public static final void testLex48() {
    assertLexedCss(
      "/* expression cruft. Make sure parsing before and after ok. */\n"
      + "a1 { a: ok;  color: red:;              a: ok }  /* cruft after : */\n"
      + "a2 { a: ok;  width: 0 !import;         a: ok }  /* !important misspelled */\n"
      + "a3 { a: ok;  unicode-range: U+0-FFFF;  a: ok }  /* ok */ \n"
      + "a4 { a: ok;  color: #g00;              a: ok }  /* bad hex digit */\n"
      + "a5 { a: ok;  image: url(\'::\');       a: ok }  /* malformed URI */\n"
      + "a6 { a: ok;  image: url(::);           a: ok }  /* malformed URI */",
      "a1", " ", "{", " ", "a", ":", " ", "ok", ";",
      " ", "color", ":", " ", "red", ":", ";",
      " ", "a", ":", " ", "ok", " ", "}", " ",
      "a2", " ", "{", " ", "a", ":", " ", "ok", ";",
      " ", "width", ":", " ", "0", " ", "!", "import", ";",
      " ", "a", ":", " ", "ok", " ", "}", " ",
      "a3", " ", "{", " ", "a", ":", " ", "ok", ";",
      " ", "unicode-range", ":", " ", "U+0-ffff", ";",
      " ", "a", ":", " ", "ok", " ", "}", " ",
      "a4", " ", "{", " ", "a", ":", " ", "ok", ";",
      " ", "color", ":", " ", "#g00",
      ";", " ", "a", ":", " ", "ok", " ", "}", " ",
      "a5", " ", "{", " ", "a", ":", " ", "ok", ";",
      " ", "image", ":", " ", "url('::')", ";",
      " ", "a", ":", " ", "ok", " ", "}", " ",
      "a6", " ", "{", " ", "a", ":", " ", "ok", ";",
      " ", "image", ":", " ", "url('::')", ";",
      " ", "a", ":", " ", "ok", " ", "}");
  }

  @Test
  public static final void testLex49() {
    assertLexedCss(
      "/* functions allow for lots of mischief */\n"
      + "a7 { a: ok;  font-size: expression(Math.random());  a: ok }  /* ok.  TODO */\n"
      + "a8 { a: ok;  font-size: expression(Math.random();   a: ok }  /* missing paren */\n"
      + "a9 { a: ok;  font-size: expression();               a: ok }  /* missing param */\n"
      + "aa { a: ok;  font-size: expression({});             a: ok }  /* bad param */",
      "a7", " ", "{", " ", "a", ":", " ", "ok", ";", " ", "font-size", ":",
      " ", "expression(", "Math", ".random", " ", "(", ")", ")", ";",
      " ", "a", ":", " ", "ok", " ", "}", " ",
      "a8", " ", "{", " ", "a", ":", " ", "ok", ";", " ", "font-size", ":",
      " ", "expression(", "Math", ".random", " ", "(", ")", ";",
      " ", "a", ":", " ", "ok", " ", ")", "}", " ",
      "a9", " ", "{", " ", "a", ":", " ", "ok", ";", " ", "font-size", ":",
      " ", "expression(", ")", ";", " ", "a", ":", " ", "ok", " ", "}", " ",
      "aa", " ", "{", " ", "a", ":", " ", "ok", ";", " ", "font-size", ":",
      " ", "expression(", "{", "}", ")", ";",
      " ", "a", ":", " ", "ok", " ", "}");
  }

  @Test
  public static final void testLex50() {
    assertLexedCss(
      "@font-face; @font-face {}\n"
      + "@font-face @font-face"
      + " { font-family: Letters; src: url(\'Letters.ttf\') }",
      "@font-face", ";", " ", "@font-face", " ", "{", "}", " ",
      "@font-face", " ", "@font-face", " ", "{",
      " ", "font-family", ":", " ", "Letters", ";",
      " ", "src", ":", " ", "url('Letters.ttf')", " ", "}");
  }

  @Test
  public static final void testLex51() {
    assertLexedCss(
      "@charset \"utf-8\";",
      "@charset", " ", "'utf-8'", ";");
  }

  @Test
  public static final void testLex52() {
    assertLexedCss(
      "@import url(\'nonsense.css\') mumbling, blather;",
      "@import", " ", "url('nonsense.css')",
      " ", "mumbling", ",", " ", "blather", ";");
  }

  @Test
  public static final void testLex53() {
    assertLexedCss(
      "@page { background: url(\'sparkley.jpg\'); }",
      "@page", " ", "{", " ", "background", ":",
      " ", "url('sparkley.jpg')", ";", " ", "}");
  }

  @Test
  public static final void testLex54() {
    assertLexedCss(
      "@charset \"non-utf-8\";",
      "@charset", " ", "'non-utf-8'", ";");
  }

  @Test
  public static final void testLex55() {
    assertLexedCss(
      "/* non utf-8 */\n"
      + "@import \'foo.css\';\n"
      + "@unknown(\'hi\');",
      "@import", " ", "'foo.css'", ";", " ",
      "@unknown", "(", "'hi'", ")", ";");
  }

  @Test
  public static final void testLex56() {
    assertLexedCss(
      "\ufeff"
      + "values: 100% -12.5% \'\' \"\" .5em 0 12 url() url(\'\') url(\"\");",
      // Do not treat a BOM as a part of an identifier.
      "values", ":", " ", "100%", " ", "-12.5%", " ", "''", " ", "''",
      " ", "0.5em", " ", "0", " ", "12",
      " ", "url('')", " ", "url('')", " ", "url('')", ";");
  }

  @Test
  public static final void testLex57() {
    assertLexedCss(
      "// line comment 1\nline2\n//line comment 3\r\nline4//line comment 4\f",
      "line2", " ", "line4");
  }

  @Test
  public static final void testLex58() {
    assertLexedCss(
      "\"\\\r\n\"",
      "''");
  }

  @Test
  public static final void testLex59() {
    assertLexedCss(
      "url()",
      "url('')");
  }


  @Test
  public static final void testLex60() {
    assertLexedCss(
      "\t\ufeff x",
      "x");
  }

  @Test
  public static final void testLex61() {
    assertTokens(
      "x.1",
      "x:IDENT", " ", "0.1:NUMBER");
  }

  @Test
  public static final void testLex62() {
    assertTokens(
      "0.. 1. . 0e1. 0e1 .",
      "0:NUMBER", " ", ".:DELIM", " ", "1:NUMBER", " ", ".:DELIM", " ",
      "0:NUMBER", " ", ".:DELIM", " ", "0:NUMBER", " ", ".:DELIM");
  }

  @Test
  public static final void testLex63() {
    assertTokens(
        "[[ ]]>",
        "[:LEFT_SQUARE",
        "[:LEFT_SQUARE",
        " ",
        "]:RIGHT_SQUARE",
        "]:RIGHT_SQUARE",
        " ",  // Inserted
        ">:DELIM");
    assertTokens(
        "[[ ]] >",
        "[:LEFT_SQUARE",
        "[:LEFT_SQUARE",
        " ",
        "]:RIGHT_SQUARE",
        "]:RIGHT_SQUARE",
        " ",
        ">:DELIM");
  }

  @Test
  public static final void testLex64() {
    assertTokens(
        "<![CDATA[",
        "<:DELIM",
        " ", // inserted
        "!:DELIM",
        "[:LEFT_SQUARE",
        "CDATA:IDENT",
        "[:LEFT_SQUARE",
        "]:RIGHT_SQUARE",
        "]:RIGHT_SQUARE");
    assertTokens(
        "<\\![\\43 DATA[",
        "<:DELIM",
        " ", // inserted
        "!:DELIM",
        "[:LEFT_SQUARE",
        "CDATA:IDENT",
        "[:LEFT_SQUARE",
        "]:RIGHT_SQUARE",
        "]:RIGHT_SQUARE");
  }

  @Test
  public static final void testLex65() {
    assertTokens(
        "<\\/St\\79le",
        "<:DELIM",
        " ", // inserted
        "/:DELIM",
        " ", // inserted
        "Style:IDENT");
  }

  @Test
  public static final void testLex66() {
    assertTokens(
        "/\\/foo\n/\\*bar*/",
        "/:DELIM",
        " ",
        "/:DELIM",
        " ",
        "foo:IDENT",
        " ",
        "/:DELIM",
        " ",
        "*:DELIM",
        "bar:IDENT",
        "*:DELIM",
        "/:DELIM");
  }

  @Test
  public static final void testLex67() {
    assertTokens(
        "0 .-42",
        "0:NUMBER",
        " ",
        ".:DELIM",
        " ",
        "-42:NUMBER");
  }

  @Test
  public static final void testLex68() {
    assertTokens(
        "#.42",
        "#:DELIM",
        " ",
        "0.42:NUMBER"
        );
    assertTokens(
        "#-.42",
        "#-:HASH_ID",
        " ",
        "0.42:NUMBER"
        );
  }

  @Test
  public static final void testLex69() {
    assertTokens(
        "font: 24ex\0pression",
        "font:IDENT",
        "::COLON",
        " ",
        "24ex:DIMENSION",
        " ",
        "pression:IDENT");
  }
}
