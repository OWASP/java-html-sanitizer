package org.owasp.html;

import junit.framework.TestCase;

import java.util.Arrays;
import java.util.List;

import com.google.common.base.Charsets;
import com.google.common.collect.Lists;
import com.google.common.io.Resources;

/**
 *
 * @author mikesamuel@gmail.com
 */
public class HtmlLexerTest extends TestCase {

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

  public final void testEofInTag() throws Exception {
    assertTokens("<div", "TAGBEGIN: <div");
    assertTokens("</div", "TAGBEGIN: </div");
    assertTokens("<div\n", "TAGBEGIN: <div");
    assertTokens("</div\n", "TAGBEGIN: </div");
    assertTokens("<div", "TAGBEGIN: <div");
    assertTokens("</div", "TAGBEGIN: </div");
    assertTokens("<div\n", "TAGBEGIN: <div");
    assertTokens("</div\n", "TAGBEGIN: </div");
  }

  public final void testPartialTagInCData() throws Exception {
    assertTokens(
        "<script>w('</b')</script>",
        "TAGBEGIN: <script",
        "TAGEND: >",
        "UNESCAPED: w('</b')",
        "TAGBEGIN: </script",
        "TAGEND: >");
  }

  public final void testUrlEndingInSlashOutsideQuotes() throws Exception {
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

  public final void testShortTags() throws Exception {
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

  private void lex(String input, Appendable out) throws Exception {
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

  private void assertTokens(String markup, String... golden) {
    HtmlLexer lexer = new HtmlLexer(markup);
    List<String> actual = Lists.newArrayList();
    while (lexer.hasNext()) {
      HtmlToken t = lexer.next();
      actual.add(t.type + ": " + markup.substring(t.start, t.end));
    }
    assertEquals(Arrays.asList(golden), actual);
  }
}
