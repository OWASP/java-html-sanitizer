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

import java.util.List;

import org.junit.Test;

import com.google.common.base.Joiner;
import com.google.common.collect.Lists;

import junit.framework.TestCase;

@SuppressWarnings("javadoc")
public class CssGrammarTest extends TestCase {
  @Test
  public static final void testLex() {
    CssTokens tokens = CssTokens.lex(Joiner.on('\n').join(
        "/* A comment */",
        "words with-dashes #hashes .dots. -and-leading-dashes",
        "quantities: 3px 4ex -.5pt 12.5%",
        "punctuation: { ( } / , ;",
        "[ url( http://example.com )",
        "rgb(255, 127, 127)",
        "'strings' \"oh \\\"my\" 'foo bar'",
        ""));

    List<String> actualTokens = Lists.newArrayList();
    for (CssTokens.TokenIterator it = tokens.iterator(); it.hasNext();) {
      CssTokens.TokenType type = it.type();
      String token = it.next();
      if (!" ".equals(token)) {
        actualTokens.add(token + ":" + type.name());
      }
    }

    assertEquals(
        Joiner.on('\n').join(
            // "/* A comment */",  // Comments are elided.
            "words:IDENT",
            "with-dashes:IDENT",
            "#hashes:HASH_ID",
            ".dots:DOT_IDENT",
            ".:DELIM",
            "-and-leading-dashes:IDENT",
            "quantities:IDENT",
            "::COLON",
            "3px:DIMENSION",
            "4ex:DIMENSION",
            "-0.5pt:DIMENSION",
            "12.5%:PERCENTAGE",
            "punctuation:IDENT",
            "::COLON",
            "{:LEFT_CURLY",
            "(:LEFT_PAREN",  // Explicit
            "):RIGHT_PAREN",  // Implicit closing bracket to keep balance.
            "}:RIGHT_CURLY",
            "/:DELIM",
            ",:COMMA",
            ";:SEMICOLON",
            "[:LEFT_SQUARE",
            "url('http://example.com'):URL",
            "rgb(:FUNCTION",
            "255:NUMBER",
            ",:COMMA",
            "127:NUMBER",
            ",:COMMA",
            "127:NUMBER",
            "):RIGHT_PAREN",
            "'strings':STRING",
            "'oh \\22my':STRING",
            "'foo bar':STRING",
            "]:RIGHT_SQUARE"
            ),
        Joiner.on('\n').join(actualTokens));
  }

  @Test
  public static final void testCssContent() {
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
