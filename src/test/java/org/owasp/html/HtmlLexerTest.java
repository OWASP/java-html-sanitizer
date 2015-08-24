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

import junit.framework.TestCase;

import java.util.Arrays;
import java.util.List;

import org.junit.Test;

import com.google.common.base.Charsets;
import com.google.common.collect.Lists;
import com.google.common.io.Resources;

@SuppressWarnings("javadoc")
public class HtmlLexerTest extends TestCase {

  @Test
  public final void testHtmlLexer() throws Exception {
    // Do the lexing.
    String input = Resources.toString(
        Resources.getResource(getClass(), "htmllexerinput1.html"),
        Charsets.UTF_8);
    StringBuilder actual = new StringBuilder();
    lex(input, actual);

    // Get the golden.
    String golden = Resources.toString(
        Resources.getResource(getClass(), "htmllexergolden1.txt"),
        Charsets.UTF_8);

    // Compare.
    assertEquals(golden, actual.toString());
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
    List<String> actual = Lists.newArrayList();
    while (lexer.hasNext()) {
      HtmlToken t = lexer.next();
      actual.add(t.type + ": " + markup.substring(t.start, t.end));
    }
    assertEquals(Arrays.asList(golden), actual);
  }
}
