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

import java.util.regex.Matcher;
import java.util.regex.Pattern;

class CssGrammar {

  /**
   * Lexical grammar for CSS tokens converted from
   * http://www.w3.org/TR/CSS2/grammar.html
   */
  private static final Pattern CSS_TOKEN;
  static {
    // nl                      \n|\r\n|\r|\f ; a newline
    //String nl = "\n|\r\n|\r|\f";

    // h                       [0-9a-f]      ; a hexadecimal digit
    String h = "[0-9a-f]";

    // nonascii                [\200-\377]
    String nonascii = "[" + ((char) 0200) + "-" + ((char) 0377) + "]";

    // unicode                 \\{h}{1,6}(\r\n|[ \t\r\n\f])?
    String unicode = "(?:(?:\\\\" + h + "{1,6})(?:\r\n|[ \t\r\n\f])?)";

    // escape                  {unicode}|\\[^\r\n\f0-9a-f]
    String escape = "(?:" + unicode + "|\\\\[^\r\n\f0-9a-f])";

    // nmstart                 [_a-z]|{nonascii}|{escape}
    String nmstart = "(?:[_a-z]|" + nonascii + "|" + escape + ")";

    // nmchar                  [_a-z0-9-]|{nonascii}|{escape}
    String nmchar = "(?:[_a-z0-9-]|" + nonascii + "|" + escape + ")";

    // ident                   -?{nmstart}{nmchar}*
    String ident = "-?" + nmstart + nmchar + "*";

    // name                    {nmchar}+
    String name = nmchar + "+";

    // hash
    String hash = "#" + name;

    // string1                 \"([^\n\r\f\\"]|\\{nl}|{escape})*\"  ; "string"
    String string1 = "\"(?:[^\n\r\f\"\\\\]|\\\\.)*\"";

    // string2                 \'([^\n\r\f\\']|\\{nl}|{escape})*\'  ; 'string'
    String string2 = "'(?:[^\n\r\f\'\\\\]|\\\\.)*'";

    // string                  {string1}|{string2}
    String string = "(?:" + string1 + "|" + string2 + ")";

    // num                     [0-9]+|[0-9]*"."[0-9]+
    String num = "(?:[0-9]*\\.[0-9]+|[0-9]+)";

    // s                       [ \t\r\n\f]
    String s = "[ \t\r\n\f]";

    // w                       {s}*
    String w = "(?:" + s + "*)";

    // url special chars
    String url_special_chars = "[!#$%&*-~]";

    // url chars               ({url_special_chars}|{nonascii}|{escape})*
    String URL_CHARS = "(?:"
        + url_special_chars + "|" + nonascii + "|" + escape + ")*";

    // url
    String url = "url\\(" + w + "(" + string + "|" + URL_CHARS + ")"
        + w + "\\)";

    // comments
    // see http://www.w3.org/TR/CSS21/grammar.html
    String comment = "/\\*(?:\\**[^*])*\\*+/";

    // {E}{M}             {return EMS;}
    // {E}{X}             {return EXS;}
    // {P}{X}             {return LENGTH;}
    // {C}{M}             {return LENGTH;}
    // {M}{M}             {return LENGTH;}
    // {I}{N}             {return LENGTH;}
    // {P}{T}             {return LENGTH;}
    // {P}{C}             {return LENGTH;}
    // {D}{E}{G}          {return ANGLE;}
    // {R}{A}{D}          {return ANGLE;}
    // {G}{R}{A}{D}       {return ANGLE;}
    // {M}{S}             {return TIME;}
    // {S}                {return TIME;}
    // {H}{Z}             {return FREQ;}
    // {K}{H}{Z}          {return FREQ;}
    // %                  {return PERCENTAGE;}
    String unit = "(?:em|ex|px|cm|mm|in|pt|pc|deg|rad|grad|ms|s|hz|khz|%)";

    // {num}{UNIT|IDENT}                   {return NUMBER;}
    String quantity = num + w + "(?:" + unit + "|" + ident + ")?";

    // "<!--"                  {return CDO;}
    // "-->"                   {return CDC;}
    // "~="                    {return INCLUDES;}
    // "|="                    {return DASHMATCH;}
    // {w}"{"                  {return LBRACE;}
    // {w}"+"                  {return PLUS;}
    // {w}">"                  {return GREATER;}
    // {w}","                  {return COMMA;}
    // Extra punctuation: brackets, dots, slash.
    String punc = "<!--|-->|~=|\\|=|[\\{\\}\\+>,:;()\\[\\]\\./]";

    CSS_TOKEN = Pattern.compile(
        // Identifier, keyword, or hash in group 1,
        "((?!url\\b)" + ident + "|" + hash + ")"
        + "|([+-]?" + quantity + ")"  // A quantity in group 2,
        // A comment in group 0.
        + "|" + comment
        // A string, URL, or punctuation in group 3,
        + "|(" + string + "|" + url + "|" + punc + ")"
        // or a whitespace in group 0.
        + "|(?:" + s + "+)|",
        Pattern.CASE_INSENSITIVE);
  }

  /**
   * Creates a matcher that will match tokens in the CSS in order.
   * The matcher will have the token in group 0.  If the token is an identifier,
   * keyword, or hash token (color or HTML ID) then it group 1 will be present.
   * If the token is a quantity, group 2 will be present.
   * If the token is a string, url, or punctuation, group 3 will be present.
   */
  static Matcher lex(String css) {
    return CSS_TOKEN.matcher(css);
  }

  static void asPropertyGroup(String css, PropertyHandler handler) {
    // Split tokens by semicolons/curly-braces, then by first colon,
    // dropping spaces and comments to identify property names and token runs
    // that form the value.

    Matcher m = lex(css);
    propertyNameLoop:
    while (m.find()) {
      // Check that we have an identifier that might be a property name.
      if (m.start(1) < 0 || css.charAt(m.start(1)) == '#') { continue; }

      String name = m.group(0);

      // Look for a colon.
      while (m.find()) {
        if (m.start(1) >= 0) {
          if (css.charAt(m.start(1)) == '#') { continue propertyNameLoop; }
          name = m.group(0);
        } else if (m.start(2) >= 0) {
          continue propertyNameLoop;
        } else if (m.start(3) + 1 == m.end(3)) {
          if (':' == css.charAt(m.start(3))) {
            break;
          } else {
            continue propertyNameLoop;
          }
        }
      }

      handler.startProperty(Strings.toLowerCase(cssContent(name)));

      propertyValueLoop:
      while (m.find()) {
        if (m.start(1) >= 0) {
          handler.identifierOrHash(m.group());
        } else if (m.start(2) >= 0) {
          handler.quantity(m.group());
        } else if (m.start(3) >= 0) {
          String token = m.group(0);
          switch (token.charAt(0)) {
            case '"': case '\'':
              handler.quotedString(token);
              break;
            case 'u': case 'U':
              handler.url(token);
              break;
            case ';': case '{': case '}': case ':':
              break propertyValueLoop;
            default:
              handler.punctuation(token);
          }
        }
      }

      handler.endProperty();
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
    void identifierOrHash(String token);
    void quotedString(String token);
    void url(String token);
    void punctuation(String token);
    void endProperty();
  }

}
