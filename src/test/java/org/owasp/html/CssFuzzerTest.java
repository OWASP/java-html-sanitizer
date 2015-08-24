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
import java.util.EnumMap;
import java.util.Random;
import java.util.regex.Pattern;

import org.junit.Test;
import org.owasp.html.CssTokens.TokenType;

import com.google.common.collect.Maps;

@SuppressWarnings("javadoc")
public class CssFuzzerTest extends FuzzyTestCase {

  private static final String[] TOKEN_PARTS = new String[] {
    "'", "\"", "<!--", "-->", "/*", "*/", "***", "//", "\r", "\n",
    "<", ">", "/", ",", ";", ":", "(", "url", "Url", ")", "[", "]", "{", "}",
    "\\", "\\a", "\\d", "\\0", " ", "\t", "42", ".", "ex", "auto", "foo", "BAr",
    "important", "!", "\ufeff", "\u0000", "\u00a0", "\ufffd", "\ud801\udc02",
    "\u007f", "\u000c", "CDATA", "style"
  };

  private static final String[] FREQUENT_TOKEN_PARTS = new String[] {
    "*/", " ", "\t", "\r", "\n",
  };

  private static final String[] DISALLOWED_IN_OUTPUT = {
    "</style", "<![CDATA[", "]]>", "\r", "\n",
  };

  final class Watcher implements Runnable {
    String input;
    long started;

    public void run() {
      synchronized (this) {
        try {
          while (true) {
            this.wait(1000 /* ms = 1s */);
            if (input == null) { break; }  // Done
            long now = System.nanoTime();
            if (now - started >= 1000000000L /* ns = 1s */) {
              System.err.println(
                  "`" + input + "` is slow. seed=" + CssFuzzerTest.this.seed);
            }
          }
        } catch (InterruptedException ex) {
          // Done
          ignore(ex);
        }
      }
    }
  }

  @Test
  public final void testUnderStress() {
    Random r = this.rnd;
    Watcher watcher = new Watcher();
    Thread watcherThread = null;
    for (int run = 0, nRuns = (1 << 16); run < nRuns; ++run) {
      // Compose a random string from token parts.
      StringBuilder sb = new StringBuilder();
      int nParts = r.nextInt(64) + 16;
      for (int j = nParts; --j >= 0;) {
        int die = r.nextInt(32);
        switch (die) {
        case 0: sb.append((char) rnd.nextInt(0x80)); break;
        case 1: sb.append((char) rnd.nextInt(0x1800)); break;
        default:
          String[] arr = (die & 1) != 0 ? TOKEN_PARTS : FREQUENT_TOKEN_PARTS;
          sb.append(arr[rnd.nextInt(arr.length)]);
          break;
        }
      }
      String randomCss = sb.toString();

      synchronized (watcher) {
        watcher.input = randomCss;
        watcher.started = System.nanoTime();
      }
      if (watcherThread == null) {
        watcherThread = new Thread(watcher);
        watcherThread.setDaemon(true);
        watcherThread.start();
      }

      String msg = "seed=" + this.seed + ", css=`" + randomCss + "`";
      CssTokens tokens = CssTokens.lex(randomCss);

      // Test idempotent
      String renormalized = CssTokens.lex(tokens.normalizedCss).normalizedCss;
      if (!renormalized.equals(tokens.normalizedCss)) {
        if (!renormalized.equals(fixDigitSpaceUnit(tokens))) {
          for (CssTokens.TokenIterator it = tokens.iterator(); it.hasNext();
               it.advance()) {
            System.err.println(it.token() + ":" + it.type());
          }
          assertEquals(
              "not idempotent, " + msg,
              tokens.normalizedCss,
              renormalized);
        }
      }

      // Test normalized CSS does not contain HTML/XML breaking tokens.
      for (String disallowed : DISALLOWED_IN_OUTPUT) {
        assertFalse(
            "contains " + disallowed + ", " + msg,
            tokens.normalizedCss.contains(disallowed));
      }

      // Test that tokens are roughly well-formed.
      int nTokens = 0;
      for (CssTokens.TokenIterator it = tokens.iterator(); it.hasNext();) {
        CssTokens.TokenType type = it.type();
        String token = it.next();
        Pattern filter = TOKEN_TYPE_FILTERS.get(type);
        if (filter != null && !filter.matcher(token).matches()) {
          fail(type + " `" + token + "`, " + msg);
        }
        ++nTokens;
      }

      // Test that walking the bracket list works.
      int[] reverse = new int[nTokens];
      Arrays.fill(reverse, -1);
      for (int j = 0; j < nTokens; ++j) {
        int partner = tokens.brackets.partner(j);
        if (partner != -1) {
          reverse[partner] = j;
        }
      }
      for (int j = 0; j < nTokens; ++j) {
        if (reverse[j] != -1) {
          assertEquals(msg, reverse[reverse[j]], j);
        }
      }
    }
    synchronized (watcher) {
      watcher.input = null;
      watcher.notifyAll();
    }
  }

  private static final EnumMap<CssTokens.TokenType, Pattern> TOKEN_TYPE_FILTERS
    = Maps.newEnumMap(CssTokens.TokenType.class);
  static {
    String NUMBER = "-?(?:0|[1-9][0-9]*)(?:\\.[0-9]*[1-9])?(?:e-?[1-9][0-9]*)?";
    String IDENT_START = "[a-zA-Z_\\u0080-\udbff\udfff\\-]";
    String IDENT_PART = "(?:" + IDENT_START + "|[0-9])";
    String IDENT = IDENT_START + IDENT_PART + "*";
    TOKEN_TYPE_FILTERS.put(
        CssTokens.TokenType.AT, Pattern.compile("@" + IDENT));
    TOKEN_TYPE_FILTERS.put(
        CssTokens.TokenType.COLON, Pattern.compile(":"));
    TOKEN_TYPE_FILTERS.put(
        CssTokens.TokenType.COLUMN, Pattern.compile("\\|\\|"));
    TOKEN_TYPE_FILTERS.put(
        CssTokens.TokenType.COMMA, Pattern.compile(","));
    TOKEN_TYPE_FILTERS.put(
        CssTokens.TokenType.DELIM,
        Pattern.compile("[^\\w\u0000- \u0080-\uffff\\-]"));
    TOKEN_TYPE_FILTERS.put(
        CssTokens.TokenType.DIMENSION, Pattern.compile(NUMBER + "[a-z]+"));
    TOKEN_TYPE_FILTERS.put(
        CssTokens.TokenType.DOT_IDENT, Pattern.compile("\\." + IDENT));
    TOKEN_TYPE_FILTERS.put(
        CssTokens.TokenType.FUNCTION, Pattern.compile(IDENT + "[(]"));
    TOKEN_TYPE_FILTERS.put(
        CssTokens.TokenType.HASH_ID, Pattern.compile("#" + IDENT_PART + "+"));
    TOKEN_TYPE_FILTERS.put(
        CssTokens.TokenType.HASH_UNRESTRICTED,
        Pattern.compile("#[a-fA-F0-9]+"));
    TOKEN_TYPE_FILTERS.put(
        CssTokens.TokenType.IDENT,
        Pattern.compile(IDENT));
    TOKEN_TYPE_FILTERS.put(
        CssTokens.TokenType.LEFT_CURLY,
        Pattern.compile("[{]"));
    TOKEN_TYPE_FILTERS.put(
        CssTokens.TokenType.LEFT_PAREN,
        Pattern.compile("[(]"));
    TOKEN_TYPE_FILTERS.put(
        CssTokens.TokenType.LEFT_SQUARE,
        Pattern.compile("[\\[]"));
    TOKEN_TYPE_FILTERS.put(
        CssTokens.TokenType.MATCH,
        Pattern.compile("[~^$|*]="));
    TOKEN_TYPE_FILTERS.put(
        CssTokens.TokenType.NUMBER,
        Pattern.compile(NUMBER));
    TOKEN_TYPE_FILTERS.put(
        CssTokens.TokenType.PERCENTAGE,
        Pattern.compile(NUMBER + "%"));
    TOKEN_TYPE_FILTERS.put(
        CssTokens.TokenType.RIGHT_CURLY,
        Pattern.compile("[}]"));
    TOKEN_TYPE_FILTERS.put(
        CssTokens.TokenType.RIGHT_PAREN,
        Pattern.compile("[)]"));
    TOKEN_TYPE_FILTERS.put(
        CssTokens.TokenType.RIGHT_SQUARE,
        Pattern.compile("[\\]]"));
    TOKEN_TYPE_FILTERS.put(
        CssTokens.TokenType.SEMICOLON,
        Pattern.compile(";"));
    TOKEN_TYPE_FILTERS.put(
        CssTokens.TokenType.STRING,
        Pattern.compile("'(?:[^'\r\n\\\\]|\\\\[^\r\n])*'"));
    TOKEN_TYPE_FILTERS.put(
        CssTokens.TokenType.UNICODE_RANGE,
        Pattern.compile("U\\+[0-9a-f]{1,6}(?:-[0-9a-f]{1,6}|\\?{0,5})?"));
    TOKEN_TYPE_FILTERS.put(
        CssTokens.TokenType.URL,
        Pattern.compile("url\\('[0-9A-Za-z\\-_.~:/?#\\[\\]@!$&+,;=%]*'\\)"));
    TOKEN_TYPE_FILTERS.put(
        CssTokens.TokenType.WHITESPACE,
        Pattern.compile(" "));
  }

  /**
   * "1:NUMBER ex:IDENT" -> "1ex:DIMENSION" is a common source source of
   * a-idempotency, but not one that causes problems in practice.
   * This hack helps ignore it.
   */
  static String fixDigitSpaceUnit(CssTokens tokens) {
    StringBuilder sb = new StringBuilder();
    for (CssTokens.TokenIterator it = tokens.iterator(); it.hasNext();) {
      if (it.type() != TokenType.NUMBER) {
        sb.append(it.next());
      } else {
        do {
          sb.append(it.next());
        } while (it.hasNext() && it.type() == TokenType.NUMBER);
        if (it.hasNext() && it.type() == TokenType.WHITESPACE) {
          it.advance();
          String numberFollower = null;
          if (it.hasNext()) {
            String token = it.token();
            switch (it.type()) {
              case IDENT:
                if (CssTokens.isWellKnownUnit(token)) {
                  numberFollower = token;
                  it.advance();
                  if (it.hasNext() && it.token().startsWith(".")) {
                    numberFollower += " ";
                  }
                  it.backup();
                }
                break;
              case FUNCTION:
                String name = token.substring(0, token.length() - 1);
                if (CssTokens.isWellKnownUnit(name)) {
                  numberFollower = token;
                }
                break;
              case DELIM:
                if ("%".equals(token)) {
                  numberFollower = token;
                }
                break;
              default: break;
            }
          }
          if (numberFollower == null) {
            sb.append(' ');
          } else {
            // Drop the space and append a lower-case version of the unit.
            sb.append(Strings.toLowerCase(numberFollower));
            it.advance();
          }
        }
      }
    }
    return sb.toString();
  }

  /** @param o ignored */
  static void ignore(Object o) {
    // Do nothing.
  }
}
