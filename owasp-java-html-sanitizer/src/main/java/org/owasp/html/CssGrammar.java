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

import java.util.Arrays;

final class CssGrammar {

  /**
   * The deepest a declaration's value may nest functions before the
   * declaration is dropped without being parsed.
   *
   * <p>{@link #parsePropertyValue} recurses once per function, so a value
   * that nests functions without bound would overflow the thread's stack:
   * about 60&nbsp;KB of {@code rgb(} did on a default-sized stack, and about
   * 5&nbsp;KB on a 256&nbsp;KB one, and the {@code StackOverflowError}
   * escaped from {@code sanitize()}.  Nothing in {@link CssSchema} has a use
   * for anything like this depth: a colour function inside a gradient, or a
   * {@code calc()} inside a transform, nests two or three levels.
   */
  static final int MAX_FUNCTION_DEPTH = 16;

  private static void errorRecoveryUntilSemiOrCloseBracket(
      CssTokens.TokenIterator it) {
    int bracketDepth = 0;
    for (; it.hasNext(); it.advance()) {
      switch (it.type()) {
        case SEMICOLON:
          it.advance();
          return;
        case LEFT_CURLY:
        case LEFT_PAREN:
        case LEFT_SQUARE:
          ++bracketDepth;
          break;
        case RIGHT_CURLY:
        case RIGHT_PAREN:
        case RIGHT_SQUARE:
          --bracketDepth;
          if (bracketDepth <= 0) {
            if (bracketDepth != 0) { it.advance(); }
            return;
          }
          break;
        default:
          break;
      }
    }
  }

  static void parsePropertyGroup(String css, PropertyHandler handler) {
    // Split tokens by semicolons/curly-braces, then by first colon,
    // dropping spaces and comments to identify property names and token runs
    // that form the value.

    CssTokens tokens = CssTokens.lex(css);
    CssTokens.TokenIterator it = tokens.iterator();
    propertyNameLoop:
    while (it.hasTokenAfterSpace()) {
      // Check that we have an identifier that might be a property name.
      if (it.type() != CssTokens.TokenType.IDENT) {
        errorRecoveryUntilSemiOrCloseBracket(it);
        continue;
      }

      String name = it.next();

      // Look for a colon.
      if (!(it.hasTokenAfterSpace() && ":".equals(it.token()))) {
        errorRecoveryUntilSemiOrCloseBracket(it);
        continue propertyNameLoop;
      }
      it.advance();

      if (skipIfNestedTooDeeply(it)) {
        continue;
      }

      handler.startProperty(Strings.toLowerCase(name));
      parsePropertyValue(it, handler);
      handler.endProperty();
    }
  }

  /**
   * If the value at the iterator's position nests functions deeper than
   * {@link #MAX_FUNCTION_DEPTH}, moves the iterator past the end of the
   * declaration and returns true, so the handler never hears of it.
   * Otherwise leaves the iterator where it was and returns false.
   *
   * <p>The declaration ends where {@link #parsePropertyValue} would stop:
   * at the first semicolon that is inside no function, or at the end of the
   * input.  A semicolon inside a function ends only that function's
   * arguments, and one inside a bare bracket ends the declaration.
   * Stopping exactly there matters: stopping later and seeking back would
   * read the same tokens again for the next declaration, and again for the
   * one after, which is quadratic.
   *
   * <p>The lexer pairs every bracket, closing what the input left open and
   * dropping what it never opened, so a close bracket here always closes
   * the innermost open one.  {@code functionAt} records, per depth, whether
   * that open bracket is a function.  It is a plain array grown by
   * doubling, so every open and close costs constant time however deep the
   * value goes: a {@code BitSet} would not, since clearing a bit makes it
   * look back for its highest set word, which on a value that opens deep,
   * then sets and clears its top mark over and over, is quadratic.  A close
   * bracket with no open partner in this value is left over from an
   * earlier declaration that ended inside it, and is ignored, as the value
   * parse ignores it.
   *
   * <p>Every function the value parse recurses into lies in this range and
   * is counted here, so the recursion that follows goes no more than
   * {@code MAX_FUNCTION_DEPTH} frames deep, however long the input.
   */
  private static boolean skipIfNestedTooDeeply(CssTokens.TokenIterator it) {
    int start = it.tokenIndex();
    boolean[] functionAt = new boolean[16];
    int depth = 0;
    int functionDepth = 0;
    boolean tooDeep = false;
    declaration:
    while (it.hasNext()) {
      CssTokens.TokenType type = it.type();
      it.advance();
      switch (type) {
        case SEMICOLON:
          if (functionDepth == 0) { break declaration; }
          break;
        case FUNCTION:
        case LEFT_CURLY:
        case LEFT_PAREN:
        case LEFT_SQUARE:
          if (depth == functionAt.length) {
            functionAt = Arrays.copyOf(functionAt, depth * 2);
          }
          if (functionAt[depth++] = (type == CssTokens.TokenType.FUNCTION)) {
            if (++functionDepth > MAX_FUNCTION_DEPTH) { tooDeep = true; }
          }
          break;
        case RIGHT_CURLY:
        case RIGHT_PAREN:
        case RIGHT_SQUARE:
          if (depth != 0 && functionAt[--depth]) { --functionDepth; }
          break;
        default:
          break;
      }
    }
    if (!tooDeep) { it.seek(start); }
    return tooDeep;
  }

  private static void parsePropertyValue(
      CssTokens.TokenIterator it, PropertyHandler handler) {
    propertyValueLoop:
    while (it.hasNext()) {
      CssTokens.TokenType type = it.type();
      String token = it.token();
      switch (type) {
        case SEMICOLON:
          it.advance();
          break propertyValueLoop;
        case FUNCTION:
          CssTokens.TokenIterator actuals = it.spliceToEnd();
          handler.startFunction(token);
          parsePropertyValue(actuals, handler);
          handler.endFunction(token);
          continue;  // Skip the advance over token.
        case IDENT:
          handler.identifier(token);
          break;
        case HASH_UNRESTRICTED:
          if (token.length() == 4 || token.length() == 7) {
            handler.hash(token);
          }
          break;
        case STRING:
          handler.quotedString(token);
          break;
        case URL:
          handler.url(token);
          break;
        case DIMENSION:
        case NUMBER:
        case PERCENTAGE:
          handler.quantity(token);
          break;
        case AT:
        case BAD_DIMENSION:
        case COLUMN:
        case DOT_IDENT:
        case HASH_ID:
        case MATCH:
        case UNICODE_RANGE:
        case WHITESPACE:
          break;
        case LEFT_CURLY:
        case LEFT_PAREN:
        case LEFT_SQUARE:
        case RIGHT_CURLY:
        case RIGHT_PAREN:
        case RIGHT_SQUARE:
        case COMMA:
        case COLON:
        case DELIM:
          handler.punctuation(token);
          break;
      }
      it.advance();
    }
  }

  /**
   * Decodes any escape sequences and strips any quotes from the input.
   */
  static String cssContent(String token) {
    int n = token.length();
    int pos = 0;
    StringBuilder sb = null;
    if (n >= 2) {
      char ch0 = token.charAt(0);
      if (ch0 == '"' || ch0 == '\'') {
        if (ch0 == token.charAt(n - 1)) {
          pos = 1;
          --n;
          sb = new StringBuilder(n);
        }
      }
    }
    for (int esc; (esc = token.indexOf('\\', pos)) >= 0;) {
      int end = esc + 2;
      if (esc > n) { break; }
      if (sb == null) { sb = new StringBuilder(n); }
      sb.append(token, pos, esc);
      int codepoint = token.charAt(end - 1);
      if (isHex(codepoint)) {
        // Parse \hhhhh<opt-break> where hhhhh is one or more hex digits
        // and <opt-break> is an optional space or tab character that can be
        // used to separate an escape sequence from a following literal hex
        // digit.
        while (end < n && isHex(token.charAt(end))) { ++end; }
        try {
          codepoint = Integer.parseInt(token.substring(esc + 1, end), 16);
        } catch (RuntimeException ex) {
          ignore(ex);
          codepoint = 0xfffd;  // Unknown codepoint.
        }
        if (end < n) {
          char ch = token.charAt(end);
          if (ch == ' ' || ch == '\t') {  // Ignorable hex follower.
            ++end;
          }
        }
      }
      sb.appendCodePoint(codepoint);
      pos = end;
    }
    if (sb == null) { return token; }
    return sb.append(token, pos, n).toString();
  }

  private static boolean isHex(int codepoint) {
    return ('0' <= codepoint && codepoint <= '9')
        || ('A' <= codepoint && codepoint <= 'F')
        || ('a' <= codepoint && codepoint <= 'f');
  }

  interface PropertyHandler {
    void startProperty(String propertyName);
    void quantity(String token);
    void identifier(String token);
    void hash(String token);
    void quotedString(String token);
    void url(String token);
    void punctuation(String token);
    void startFunction(String token);
    void endFunction(String token);
    void endProperty();
  }

  /** @param o ignored */
  private static void ignore(Object o) {
    // Do nothing
  }
}
