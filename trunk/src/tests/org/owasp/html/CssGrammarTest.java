package org.owasp.html;

import java.util.List;
import java.util.regex.Matcher;

import com.google.common.base.Joiner;
import com.google.common.collect.Lists;

import junit.framework.TestCase;

public class CssGrammarTest extends TestCase {
  public final void testLex() throws Exception {
    Matcher m = CssGrammar.lex(Joiner.on('\n').join(
        "/* A comment */",
        "words with-dashes #hashes .dots. -and-leading-dashes",
        "quantities: 3px 4ex -.5pt 12.5%",
        "punctuation: { } / , ;",
        "url( http://example.com )",
        "rgb(255, 127, 127)",
        "'strings' \"oh \\\"my\"",
        ""));

    List<String> actualTokens = Lists.newArrayList();
    while (m.find()) {
      String token = m.group();
      if (!"".equals(token.trim())) {
        actualTokens.add(token);
      }
    }

    assertEquals(
        Joiner.on('\n').join(
            "/* A comment */",
            "words", "with-dashes", "#hashes", ".", "dots", ".",
            "-and-leading-dashes",
            "quantities", ":", "3px", "4ex", "-.5pt", "12.5%",
            "punctuation", ":", "{", "}", "/", ",", ";",
            "url( http://example.com )",
            "rgb", "(", "255", ",", "127", ",", "127", ")",
            "'strings'", "\"oh \\\"my\""
            ),
        Joiner.on('\n').join(actualTokens));
  }

  public final void testCssContent() {
    assertEquals("", CssGrammar.cssContent(""));
    assertEquals("azimuth", CssGrammar.cssContent("\\61zimuth"));
    assertEquals("table-cell", CssGrammar.cssContent("t\\61\tble-cell"));
    assertEquals("foo", CssGrammar.cssContent("foo"));
    assertEquals("foo", CssGrammar.cssContent("'foo'"));
    assertEquals("foo", CssGrammar.cssContent("\"foo\""));
    assertEquals("'", CssGrammar.cssContent("'"));
    assertEquals("\"", CssGrammar.cssContent("\""));
    assertEquals("\"\"", CssGrammar.cssContent("\"\\22\\22\""));
    assertEquals("\"\"", CssGrammar.cssContent("\"\\22 \\22\""));
    assertEquals("\"\"", CssGrammar.cssContent("\\22\\22"));
    assertEquals("\\", CssGrammar.cssContent("'\\\\'"));
    assertEquals("\n", CssGrammar.cssContent("'\\a'"));
  }
}
