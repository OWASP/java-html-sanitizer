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

import com.google.common.collect.Lists;

import static org.owasp.html.CssTokens.TokenType.*;

public class CssTokensTest extends TestCase {

  @Test
  public void testBracketIndices() {
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

}
