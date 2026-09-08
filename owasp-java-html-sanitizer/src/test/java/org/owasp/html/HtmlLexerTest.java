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

import org.junit.Test;

import junit.framework.TestCase;

@SuppressWarnings("javadoc")
public class HtmlLexerTest extends TestCase {

  @Test
  public final void testHtmlLexer() throws Exception {
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
  public static final void testEofInTag() {
    assertTokens("<div", "TAGBEGIN: <div");
    assertTokens("</div", "TAGBEGIN: </div");
    assertTokens("<div\n", "TAGBEGIN: <div");
    assertTokens("</div\n", "TAGBEGIN: </div");
    assertTokens("<div", "TAGBEGIN: <div");
    assertTokens("</div", "TAGBEGIN: </div");
    assertTokens("<div\n", "TAGBEGIN: <div");
    assertTokens("</div\n", "TAGBEGIN: </div");
  }

  @Test
  public static final void testPartialTagInCData() {
    assertTokens(
        "<script>w('</b')</script>",
        "TAGBEGIN: <script",
        "TAGEND: >",
        "UNESCAPED: w('</b')",
        "TAGBEGIN: </script",
        "TAGEND: >");
  }

  @Test
  public static final void testUrlEndingInSlashOutsideQuotes() {
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
  public static final void testShortTags() {
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
        "TEXT: first part of the text</> second part");
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
  public static final void testCommentDeclarationWith0CommentsAndXss() throws Exception
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
  public static final void testTextEndingWithTagOpenAndBang() throws Exception
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
  public static final void testDashDashBangComment() throws Exception
  {
    assertTokens("<!-- --!-->",
            "COMMENT: <!-- --!-->"
    );
  }
  @Test
  public static final void testAbruptClosingOfEmptyComment() throws Exception
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
  public static final void testBangDashIsABogusComment() throws Exception
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
  public static final void testDashDashBangClosesCommentAfterLeadingDashes() throws Exception
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
  public static final void testCommentCloseRequiresAdjacentDashes() throws Exception
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
  public static final void testIncorrectlyClosedComment() throws Exception
  {
    assertTokens("<!-- Comment --!><img>",
            "COMMENT: <!-- Comment --!>",
            "TAGBEGIN: <img",
            "TAGEND: >"
    );
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
    HtmlLexer lexer = new HtmlLexer(markup);
    List<String> actual = new ArrayList<>();
    while (lexer.hasNext()) {
      HtmlToken t = lexer.next();
      actual.add(t.type + ": " + markup.substring(t.start, t.end));
    }
    assertEquals(Arrays.asList(golden), actual);
  }
}
