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
