// Copyright (c) 2011, Mike Samuel
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

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class HtmlLexerTest {

  @Test
  void testHtmlLexer() throws Exception {
    // Do the lexing.
    String input = new String(Files.readAllBytes(Paths.get(getClass().getResource("htmllexerinput1.html").toURI())), StandardCharsets.UTF_8);
    // Normalize line endings in input to handle Windows/Unix differences
    input = input.replace("\r\n", "\n").replace("\r", "\n");
    StringBuilder actual = new StringBuilder();
    lex(input, actual);

    // Get the golden.
    String golden = new String(Files.readAllBytes(Paths.get(getClass().getResource("htmllexergolden1.txt").toURI())), StandardCharsets.UTF_8);
    // Normalize line endings to handle Windows/Unix differences
    golden = golden.replace("\r\n", "\n").replace("\r", "\n");
    String actualStr = actual.toString().replace("\r\n", "\n").replace("\r", "\n");

    // Compare.
    assertEquals(golden, actualStr);
  }

  @Test
  void testEofInTag() {
    assertTokens("<div", "TAGBEGIN: <div");
    assertTokens("</div", "TAGBEGIN: </div");
    assertTokens("<div\n", "TAGBEGIN: <div");
    assertTokens("</div\n", "TAGBEGIN: </div");
    assertTokens("<div", "TAGBEGIN: <div");
    assertTokens("</div", "TAGBEGIN: </div");
    assertTokens("<div\n", "TAGBEGIN: <div");
    assertTokens("</div\n", "TAGBEGIN: </div");
  }

  /**
   * After {@code </}, only a letter starts an end tag.  A browser drops
   * {@code </>} outright, turns anything else into a bogus comment that
   * runs to the next {@code >}, and takes {@code </} at the end of input as
   * text (#410).  Inside literal content none of that applies.
   */
  @Test
  void testEndTagOpenFollowedByANonLetter() {
    assertTokens("</>", "COMMENT: </>");
    assertTokens("</ notatag>x", "COMMENT: </ notatag>", "TEXT: x");
    assertTokens(
        "</\"<p>y</p>",
        "COMMENT: </\"<p>", "TEXT: y", "TAGBEGIN: </p", "TAGEND: >");
    assertTokens("</<p>y", "COMMENT: </<p>", "TEXT: y");
    // Unterminated, the bogus comment runs to the end of input.
    assertTokens("</\"", "COMMENT: </\"");
    assertTokens("</", "TEXT: </");
    assertTokens("a</", "TEXT: a</");
    // Literal content is text whatever follows "</", up to its end tag.
    assertTokens(
        "<script></\"</script>",
        "TAGBEGIN: <script", "TAGEND: >", "UNESCAPED: </\"",
        "TAGBEGIN: </script", "TAGEND: >");
    assertTokens(
        "<style>a</ b</style>",
        "TAGBEGIN: <style", "TAGEND: >", "UNESCAPED: a</ b",
        "TAGBEGIN: </style", "TAGEND: >");
  }

  @Test
  void testPartialTagInCData() {
    assertTokens(
        "<script>w('</b')</script>",
        "TAGBEGIN: <script",
        "TAGEND: >",
        "UNESCAPED: w('</b')",
        "TAGBEGIN: </script",
        "TAGEND: >");
  }

  @Test
  void testUrlEndingInSlashOutsideQuotes() {
    assertTokens(
        "<a href=http://foo.com/>Clicky</a>",
        "TAGBEGIN: <a",
        "ATTRNAME: href",
        "ATTRVALUE: http://foo.com/",
        "TAGEND: >",
        "TEXT: Clicky",
        "TAGBEGIN: </a",
        "TAGEND: >");
  }

  @Test
  void testSlashStartsAnUnquotedValueAfterEquals() {
    assertTokens(
        "<path d=/>x</path>",
        "TAGBEGIN: <path",
        "ATTRNAME: d",
        "ATTRVALUE: /",
        "TAGEND: >",
        "TEXT: x",
        "TAGBEGIN: </path",
        "TAGEND: >");
    assertTokens(
        "<path d = />x</path>",
        "TAGBEGIN: <path",
        "ATTRNAME: d",
        "ATTRVALUE: /",
        "TAGEND: >",
        "TEXT: x",
        "TAGBEGIN: </path",
        "TAGEND: >");
  }

  @Test
  void testShortTags() {
    // See comments in html-sanitizer-test.js as to why we don't bother with
    // short tags.  In short, they are not in HTML5 and not implemented properly
    // in existing HTML4 clients.
    assertTokens(
        "<p<a href=\"/\">first part of the text</> second part",
        "TAGBEGIN: <p",
        "ATTRNAME: <a",
        "ATTRNAME: href",
        "ATTRVALUE: \"/\"",
        "TAGEND: >",
        "TEXT: first part of the text",
        // "</>" is nothing to a browser: an empty comment here.
        "COMMENT: </>",
        "TEXT:  second part");
    assertTokens(
        "<p/b/",
        "TAGBEGIN: <p",
        "ATTRNAME: /",
        "ATTRNAME: b/");
    assertTokens(
        "<p<b>",
        "TAGBEGIN: <p",
        "ATTRNAME: <b",
        "TAGEND: >");
  }

  @Test
  void testCommentDeclarationWith0CommentsAndXss() throws Exception
  {
    //check https://datatracker.ietf.org/doc/html/rfc1866#section-3.2.5
    assertTokens("<!><img src=1 onError=alert(\"nice\")>",
            "COMMENT: <!>",
            "TAGBEGIN: <img",
            "ATTRNAME: src",
            "ATTRVALUE: 1",
            "ATTRNAME: onError",
            "ATTRVALUE: alert(\"nice\")",
            "TAGEND: >"
    );
  }

  @Test
  void testTextEndingWithTagOpenAndBang() throws Exception
  {
    //taken from https://html.spec.whatwg.org/#comments
    assertTokens("<!--My favorite operators are > and <!--><a></a>",
            "COMMENT: <!--My favorite operators are > and <!-->",
            "TAGBEGIN: <a",
            "TAGEND: >",
            "TAGBEGIN: </a",
            "TAGEND: >"
    );
  }

  @Test
  void testDashDashBangComment() throws Exception
  {
    assertTokens("<!-- --!-->",
            "COMMENT: <!-- --!-->"
    );
  }
  @Test
  void testAbruptClosingOfEmptyComment() throws Exception
  {
    assertTokens("<!--><img>a<!--->b<!->c",
            "COMMENT: <!-->",
            "TAGBEGIN: <img",
            "TAGEND: >",
            "TEXT: a",
            "COMMENT: <!--->",
            "TEXT: b",
            "COMMENT: <!->",
            "TEXT: c"
    );
  }

  @Test
  void testBangDashIsABogusComment() throws Exception
  {
    // <!- followed by anything but a dash is a bogus comment that ends at
    // the first '>', so <!-> must not swallow the following tag.
    assertTokens("<!->c<b>after</b>",
            "COMMENT: <!->",
            "TEXT: c",
            "TAGBEGIN: <b",
            "TAGEND: >",
            "TEXT: after",
            "TAGBEGIN: </b",
            "TAGEND: >"
    );
    assertTokens("<!-x>c<b>after</b>",
            "DIRECTIVE: <!-x>",
            "TEXT: c",
            "TAGBEGIN: <b",
            "TAGEND: >",
            "TEXT: after",
            "TAGBEGIN: </b",
            "TAGEND: >"
    );
  }

  @Test
  void testDashDashBangClosesCommentAfterLeadingDashes() throws Exception
  {
    // Issue #258: <!-- followed only by dashes and then --!> must terminate
    // rather than swallowing the rest of the document.
    assertTokens("<!----!><b>after</b>",
            "COMMENT: <!----!>",
            "TAGBEGIN: <b",
            "TAGEND: >",
            "TEXT: after",
            "TAGBEGIN: </b",
            "TAGEND: >"
    );
    assertTokens("<!-----!><b>after</b>",
            "COMMENT: <!-----!>",
            "TAGBEGIN: <b",
            "TAGEND: >",
            "TEXT: after",
            "TAGBEGIN: </b",
            "TAGEND: >"
    );
    // Fewer than two dashes after <!-- do not reach the comment end state,
    // so !> is ordinary comment content and the comment runs to the end.
    assertTokens("<!--!><b>after</b>",
            "COMMENT: <!--!><b>after</b>"
    );
    assertTokens("<!---!><b>after</b>",
            "COMMENT: <!---!><b>after</b>"
    );
  }

  @Test
  void testCommentCloseRequiresAdjacentDashes() throws Exception
  {
    // A dash followed by other content is ordinary comment text; only a
    // contiguous "-->" (or "--!>") closes the comment, as in a browser.
    assertTokens("<!-- a -x-><b>after</b>",
            "COMMENT: <!-- a -x-><b>after</b>"
    );
    assertTokens("<!-- a --b-><b>after</b>",
            "COMMENT: <!-- a --b-><b>after</b>"
    );
    assertTokens("<!-- a -x--><b>after</b>",
            "COMMENT: <!-- a -x-->",
            "TAGBEGIN: <b",
            "TAGEND: >",
            "TEXT: after",
            "TAGBEGIN: </b",
            "TAGEND: >"
    );
    assertTokens("<!-- a --b--><b>after</b>",
            "COMMENT: <!-- a --b-->",
            "TAGBEGIN: <b",
            "TAGEND: >",
            "TEXT: after",
            "TAGBEGIN: </b",
            "TAGEND: >"
    );
    // Issue #231: the comment used to end at "->" before "I'M".
    assertTokens("<!-- COMMENT -- ME -> I'M ALONE --> MY CODE",
            "COMMENT: <!-- COMMENT -- ME -> I'M ALONE -->",
            "TEXT:  MY CODE"
    );
  }

  @Test
  void testIncorrectlyClosedComment() throws Exception
  {
    assertTokens("<!-- Comment --!><img>",
            "COMMENT: <!-- Comment --!>",
            "TAGBEGIN: <img",
            "TAGEND: >"
    );
  }

  @Test
  void testQuoteNotAfterEqualsIsPartOfAttributeName() throws Exception
  {
    // Issue #189: the WHATWG tokenizer only starts a quoted value directly
    // after an attribute name and '='.  A quote anywhere else in a tag is an
    // ordinary character of an attribute name, so it must not pair with a
    // later quote and swallow the tag's '>' and the content after it.
    assertTokens("<p class=\"test\" \"=\"\">bar</p> <p>baz</p>",
            "TAGBEGIN: <p",
            "ATTRNAME: class",
            "ATTRVALUE: \"test\"",
            "ATTRNAME: \"",
            "ATTRVALUE: \"\"",
            "TAGEND: >",
            "TEXT: bar",
            "TAGBEGIN: </p",
            "TAGEND: >",
            "TEXT:  ",
            "TAGBEGIN: <p",
            "TAGEND: >",
            "TEXT: baz",
            "TAGBEGIN: </p",
            "TAGEND: >"
    );
    assertTokens("<p class=\"test\" \">bar</p>",
            "TAGBEGIN: <p",
            "ATTRNAME: class",
            "ATTRVALUE: \"test\"",
            "ATTRNAME: \"",
            "TAGEND: >",
            "TEXT: bar",
            "TAGBEGIN: </p",
            "TAGEND: >"
    );
    assertTokens("<p \"a>b\">c</p>",
            "TAGBEGIN: <p",
            "ATTRNAME: \"a",
            "TAGEND: >",
            "TEXT: b\">c",
            "TAGBEGIN: </p",
            "TAGEND: >"
    );
    assertTokens("<p class=\"a\"\"b\">x</p>",
            "TAGBEGIN: <p",
            "ATTRNAME: class",
            "ATTRVALUE: \"a\"",
            "ATTRNAME: \"b\"",
            "TAGEND: >",
            "TEXT: x",
            "TAGBEGIN: </p",
            "TAGEND: >"
    );
    assertTokens("<p 'class'=\"test\">bar</p>",
            "TAGBEGIN: <p",
            "ATTRNAME: 'class'",
            "ATTRVALUE: \"test\"",
            "TAGEND: >",
            "TEXT: bar",
            "TAGBEGIN: </p",
            "TAGEND: >"
    );
  }

  @Test
  void testSlashInTagReturnsToBeforeAttributeName() throws Exception
  {
    // A '/' that does not close the tag puts the tokenizer back before an
    // attribute name, so the '=' after it starts a name rather than
    // introducing a value, and the quote after that is not a delimiter.
    // HtmlLexer still pairs the '/' name with the quote as its value, which
    // is harmless: no policy allows either name and the tag ends at the '>'.
    assertTokens("<p a/=\">y</p>",
            "TAGBEGIN: <p",
            "ATTRNAME: a/",
            "ATTRVALUE: \"",
            "TAGEND: >",
            "TEXT: y",
            "TAGBEGIN: </p",
            "TAGEND: >"
    );
    assertTokens("<p a=\"x\"/=\">y</p>",
            "TAGBEGIN: <p",
            "ATTRNAME: a",
            "ATTRVALUE: \"x\"",
            "ATTRNAME: /",
            "ATTRVALUE: \"",
            "TAGEND: >",
            "TEXT: y",
            "TAGBEGIN: </p",
            "TAGEND: >"
    );
    // A '/' inside a name is just a character of it, so the value follows.
    assertTokens("<p a/b=\"x\">y</p>",
            "TAGBEGIN: <p",
            "ATTRNAME: a/b",
            "ATTRVALUE: \"x\"",
            "TAGEND: >",
            "TEXT: y",
            "TAGBEGIN: </p",
            "TAGEND: >"
    );
  }

  @Test
  void testQuoteInUnquotedValueIsPartOfTheValue() throws Exception
  {
    // Once an unquoted value has started, a quote belongs to that value even
    // when it directly follows an '=', as in the tokenizer's unquoted value
    // state, so it does not start a new quoted value either.
    assertTokens("<p class=x=\"y\">z</p>",
            "TAGBEGIN: <p",
            "ATTRNAME: class",
            "ATTRVALUE: x=\"y\"",
            "TAGEND: >",
            "TEXT: z",
            "TAGBEGIN: </p",
            "TAGEND: >"
    );
    assertTokens("<p class=x=\">y</p>",
            "TAGBEGIN: <p",
            "ATTRNAME: class",
            "ATTRVALUE: x=\"",
            "TAGEND: >",
            "TEXT: y",
            "TAGBEGIN: </p",
            "TAGEND: >"
    );
  }

  @Test
  void testUnterminatedQuotedValueRunsToEndOfInput() throws Exception
  {
    // Conversely, a quote that does begin a value and is never closed takes
    // the rest of the input, which is where a browser hits EOF in the tag.
    assertTokens("<p class=\">y</p>",
            "TAGBEGIN: <p",
            "ATTRNAME: class",
            "ATTRVALUE: \">y</p>"
    );
    assertTokens("<p class = \">y</p>",
            "TAGBEGIN: <p",
            "ATTRNAME: class",
            "ATTRVALUE: \">y</p>"
    );
    // In "=", the first quote names an attribute and the second, which
    // follows the '=', begins its value.
    assertTokens("<p \"=\">y</p>",
            "TAGBEGIN: <p",
            "ATTRNAME: \"",
            "ATTRVALUE: \">y</p>"
    );
  }

  @Test
  void testOnlyAsciiWhitespaceSeparatesTagTokens()
      throws Exception {
    // The five ASCII whitespace characters end a tag name or an unquoted
    // attribute value.  Character.isWhitespace also accepts U+000B,
    // U+001C..U+001F and the Unicode space separators, but the WHATWG
    // tokenizer keeps those inside names and values, as validator.nu
    // confirms for each of the characters below.
    for (String ws : new String[] {" ", "\t", "\n", "\f", "\r"}) {
      assertTokens("<b" + ws + "title=x>y</b>",
          "TAGBEGIN: <b", "ATTRNAME: title", "ATTRVALUE: x", "TAGEND: >",
          "TEXT: y", "TAGBEGIN: </b", "TAGEND: >");
      assertTokens("<style>a</style" + ws + ">b",
          "TAGBEGIN: <style", "TAGEND: >", "UNESCAPED: a",
          "TAGBEGIN: </style", "TAGEND: >", "TEXT: b");
    }
    for (String notWs : new String[] {
        "\u000b", "\u001c", "\u001f", "\u0085", "\u00a0", "\u1680",
        "\u2000", "\u2028", "\u2029", "\u205f", "\u3000"}) {
      String m = String.format("U+%04X", (int) notWs.charAt(0));
      // Part of the tag name.
      assertTokensFor(m, "<b" + notWs + "title=x>y</b>",
          "TAGBEGIN: <b" + notWs + "title=x", "TAGEND: >",
          "TEXT: y", "TAGBEGIN: </b", "TAGEND: >");
      // Part of an unquoted attribute value.
      assertTokensFor(m, "<b title=x" + notWs + "id=z>y</b>",
          "TAGBEGIN: <b", "ATTRNAME: title", "ATTRVALUE: x" + notWs + "id=z",
          "TAGEND: >", "TEXT: y", "TAGBEGIN: </b", "TAGEND: >");
      // Part of the next attribute's name after a quoted value.
      assertTokensFor(m, "<b title='x'" + notWs + "id=z>y</b>",
          "TAGBEGIN: <b", "ATTRNAME: title", "ATTRVALUE: 'x'",
          "ATTRNAME: " + notWs + "id", "ATTRVALUE: z", "TAGEND: >",
          "TEXT: y", "TAGBEGIN: </b", "TAGEND: >");
      // Does not end the end tag of a raw text element, so the element
      // stays open just as it does in a browser.
      assertTokensFor(m, "<style>a</style" + notWs + ">b",
          "TAGBEGIN: <style", "TAGEND: >",
          "UNESCAPED: a</style" + notWs + ">b");
    }
  }

  private static void lex(String input, Appendable out) throws Exception {
    HtmlLexer lexer = new HtmlLexer(input);
    int maxTypeLength = 0;
    for (HtmlTokenType t : HtmlTokenType.values()) {
      maxTypeLength = Math.max(maxTypeLength, t.name().length());
    }

    while (lexer.hasNext()) {
      HtmlToken t = lexer.next();
      // Do C style escaping of the token text so that each token in the golden
      // file can fit on one line.
      String escaped = input.substring(t.start, t.end)
          .replace("\\", "\\\\").replace("\n", "\\n");
      String type = t.type.toString();
      int nPadding = maxTypeLength - type.length();
      out.append(type);
      while (--nPadding >= 0) { out.append(' '); }
      out.append(" [").append(escaped).append("]  :  ")
          .append(String.valueOf(t.start)).append('-')
          .append(String.valueOf(t.end))
          .append("\n");
    }
  }

  private static void assertTokens(String markup, String... golden) {
    assertTokensFor(markup, markup, golden);
  }

  private static void assertTokensFor(
      String message, String markup, String... golden) {
    HtmlLexer lexer = new HtmlLexer(markup);
    List<String> actual = new ArrayList<>();
    while (lexer.hasNext()) {
      HtmlToken t = lexer.next();
      actual.add(t.type + ": " + markup.substring(t.start, t.end));
    }
    assertEquals(Arrays.asList(golden), actual, message);
  }
}
