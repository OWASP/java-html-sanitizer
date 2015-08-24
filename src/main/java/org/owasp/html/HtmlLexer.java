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

import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Lists;
import java.util.LinkedList;
import java.util.NoSuchElementException;
import java.util.Set;

import javax.annotation.concurrent.NotThreadSafe;

/**
 * A flexible lexer for HTML.
 * This is hairy code, but it is outside the TCB for the HTML sanitizer.
 *
 * @author Mike Samuel (mikesamuel@gmail.com)
 */
@NotThreadSafe
final class HtmlLexer extends AbstractTokenStream {
  private final String input;
  private final HtmlInputSplitter splitter;
  private State state = State.OUTSIDE_TAG;

  public HtmlLexer(String input) {
    this.input = input;
    this.splitter = new HtmlInputSplitter(input);
  }

  /**
   * Normalize case of names that are not name-spaced.  This lower-cases HTML
   * element and attribute names, but not ones for embedded SVG or MATHML.
   */
  static String canonicalName(String elementOrAttribName) {
    return elementOrAttribName.indexOf(':') >= 0
        ? elementOrAttribName : Strings.toLowerCase(elementOrAttribName);
  }

  /**
   * An FSM that lets us reclassify text tokens inside tags as attribute
   * names/values
   */
  private static enum State {
    OUTSIDE_TAG,
    IN_TAG,
    SAW_NAME,
    SAW_EQ,
    ;
  }

  /**
   * Makes sure that this.token contains a token if one is available.
   * This may require fetching and combining multiple tokens from the underlying
   * splitter.
   */
  @Override
  protected HtmlToken produce() {
    HtmlToken token = readToken();
    if (token == null) { return null; }

    switch (token.type) {

      // Keep track of whether we're inside a tag or not.
      case TAGBEGIN:
        state = State.IN_TAG;
        break;
      case TAGEND:
        if (state == State.SAW_EQ && HtmlTokenType.TAGEND == token.type) {
          // Distinguish <input type=checkbox checked=> from
          // <input type=checkbox checked>
          pushbackToken(token);
          state = State.IN_TAG;
          return HtmlToken.instance(
              token.start, token.start, HtmlTokenType.ATTRVALUE);
        }

        state = State.OUTSIDE_TAG;
        break;

      // Drop ignorable tokens by zeroing out the one received and recursing
      case IGNORABLE:
        return produce();

      // collapse adjacent text nodes if we're outside a tag, or otherwise,
      // Recognize attribute names and values.
      default:
        switch (state) {
          case OUTSIDE_TAG:
            if (HtmlTokenType.TEXT == token.type
                || HtmlTokenType.UNESCAPED == token.type) {
              token = collapseSubsequent(token);
            }
            break;
          case IN_TAG:
            if (HtmlTokenType.TEXT == token.type
                && !token.tokenInContextMatches(input, "=")) {
              // Reclassify as attribute name
              token = HtmlInputSplitter.reclassify(
                  token, HtmlTokenType.ATTRNAME);
              state = State.SAW_NAME;
            }
            break;
          case SAW_NAME:
            if (HtmlTokenType.TEXT == token.type) {
              if (token.tokenInContextMatches(input, "=")) {
                state = State.SAW_EQ;
                // Skip the '=' token
                return produce();
              } else {
                // Reclassify as attribute name
                token = HtmlInputSplitter.reclassify(
                    token, HtmlTokenType.ATTRNAME);
              }
            } else {
              state = State.IN_TAG;
            }
            break;
          case SAW_EQ:
            if (HtmlTokenType.TEXT == token.type
                || HtmlTokenType.QSTRING == token.type) {
              if (HtmlTokenType.TEXT == token.type) {
                // Collapse adjacent text nodes to properly handle
                //   <a onclick=this.clicked=true>
                //   <a title=foo bar>
                token = collapseAttributeName(token);
              }
              // Reclassify as value
              token = HtmlInputSplitter.reclassify(
                  token, HtmlTokenType.ATTRVALUE);
              state = State.IN_TAG;
            }
            break;
        }
        break;
    }

    return token;
  }

  /**
   * Collapses all the following tokens of the same type into this.token.
   */
  private HtmlToken collapseSubsequent(HtmlToken token) {
    HtmlToken collapsed = token;
    for (HtmlToken next;
         (next= peekToken(0)) != null && next.type == token.type;
         readToken()) {
      collapsed = join(collapsed, next);
    }
    return collapsed;
  }

  private HtmlToken collapseAttributeName(HtmlToken token) {
    // We want to collapse tokens into the value that are not parts of an
    // attribute value.  We should include any space or text adjacent to the
    // value, but should stop at any of the following constructions:
    //   space end-of-file              e.g. name=foo_
    //   space valueless-attrib-name    e.g. name=foo checked
    //   space tag-end                  e.g. name=foo />
    //   space text space? '='          e.g. name=foo bar=
    int nToMerge = 0;
    for (HtmlToken t; (t = peekToken(nToMerge)) != null;) {
      if (t.type == HtmlTokenType.IGNORABLE) {
        HtmlToken tok = peekToken(nToMerge + 1);
        if (tok == null) { break; }
        if (tok.type != HtmlTokenType.TEXT) { break; }
        if (isValuelessAttribute(input.substring(tok.start, tok.end))) {
          break;
        }
        HtmlToken eq = peekToken(nToMerge + 2);
        if (eq != null && eq.type == HtmlTokenType.IGNORABLE) {
          eq = peekToken(nToMerge + 3);
        }
        if (eq == null || eq.tokenInContextMatches(input, "=")) {
          break;
        }
      } else if (t.type != HtmlTokenType.TEXT) {
        break;
      }
      ++nToMerge;
    }
    if (nToMerge == 0) { return token; }

    int end = token.end;
    do {
      end = readToken().end;
    } while (--nToMerge > 0);

    return HtmlToken.instance(token.start, end, HtmlTokenType.TEXT);
  }

  private static HtmlToken join(HtmlToken a, HtmlToken b) {
    return HtmlToken.instance(a.start, b.end, a.type);
  }

  private final LinkedList<HtmlToken> lookahead = Lists.newLinkedList();
  private HtmlToken readToken() {
    if (!lookahead.isEmpty()) {
      return lookahead.remove();
    } else if (splitter.hasNext()) {
      return splitter.next();
    } else {
      return null;
    }
  }

  private HtmlToken peekToken(int i) {
    while (lookahead.size() <= i && splitter.hasNext()) {
      lookahead.add(splitter.next());
    }
    return lookahead.size() > i ? lookahead.get(i) : null;
  }

  private void pushbackToken(HtmlToken token) {
    lookahead.addFirst(token);
  }

  /** Can the attribute appear in HTML without a value. */
  private static boolean isValuelessAttribute(String attribName) {
    boolean valueless = VALUELESS_ATTRIB_NAMES.contains(
        Strings.toLowerCase(attribName));
    return valueless;
  }

  // From http://issues.apache.org/jira/browse/XALANC-519
  private static final Set<String> VALUELESS_ATTRIB_NAMES = ImmutableSet.of(
      "checked", "compact", "declare", "defer", "disabled",
      "ismap", "multiple", "nohref", "noresize", "noshade",
      "nowrap", "readonly", "selected");
}

/**
 * A token stream that breaks a character stream into <tt>
 * HtmlTokenType.{TEXT,TAGBEGIN,TAGEND,DIRECTIVE,COMMENT,CDATA,DIRECTIVE}</tt>
 * tokens.  The matching of attribute names and values is done in a later step.
 */
final class HtmlInputSplitter extends AbstractTokenStream {
  /** The source of HTML character data. */
  private final String input;
  /** An offset into input. */
  private int offset;
  /** True iff the current character is inside a tag. */
  private boolean inTag;
  /**
   * True if inside a script, xmp, listing, or similar tag whose content does
   * not follow the normal escaping rules.
   */
  private boolean inEscapeExemptBlock;

  /**
   * Null or the name of the close tag required to end the current escape exempt
   * block.
   * Preformatted tags include &lt;script&gt;, &lt;xmp&gt;, etc. that may
   * contain unescaped HTML input.
   */
  private String escapeExemptTagName = null;

  private HtmlTextEscapingMode textEscapingMode;

  public HtmlInputSplitter(String input) {
    this.input = input;
  }

  /**
   * Make sure that there is a token ready to yield in this.token.
   */
  @Override
  protected HtmlToken produce() {
    HtmlToken token = parseToken();
    if (null == token) { return null; }

    // Handle escape-exempt blocks.
    // The parse() method is only dimly aware of escape-excempt blocks, so
    // here we detect the beginning and ends of escape exempt blocks, and
    // reclassify as UNESCAPED, any tokens that appear in the middle.
    if (inEscapeExemptBlock) {
      if (token.type != HtmlTokenType.SERVERCODE) {
        // classify RCDATA as text since it can contain entities
        token = reclassify(
            token, (this.textEscapingMode == HtmlTextEscapingMode.RCDATA
                    ? HtmlTokenType.TEXT
                    : HtmlTokenType.UNESCAPED));
      }
    } else {
      switch (token.type) {
        case TAGBEGIN:
          {
            String canonTagName = canonicalName(
                token.start + 1, token.end);
            if (HtmlTextEscapingMode.isTagFollowedByLiteralContent(
                    canonTagName)) {
              this.escapeExemptTagName = canonTagName;
              this.textEscapingMode = HtmlTextEscapingMode.getModeForTag(
                  canonTagName);
            }
            break;
          }
        case TAGEND:
          this.inEscapeExemptBlock = null != this.escapeExemptTagName;
          break;
        default:
          break;
      }
    }
    return token;
  }

  /**
   * States for a state machine for optimistically identifying tags and other
   * html/xml/phpish structures.
   */
  private static enum State {
    TAGNAME,
    SLASH,
    BANG,
    BANG_DASH,
    COMMENT,
    COMMENT_DASH,
    COMMENT_DASH_DASH,
    DIRECTIVE,
    DONE,
    BOGUS_COMMENT,
    SERVER_CODE,
    SERVER_CODE_PCT,

    // From HTML 5 section 8.1.2.6

    // The text in CDATA and RCDATA elements must not contain any
    // occurrences of the string "</" followed by characters that
    // case-insensitively match the tag name of the element followed
    // by one of U+0009 CHARACTER TABULATION, U+000A LINE FEED (LF),
    // U+000B LINE TABULATION, U+000C FORM FEED (FF), U+0020 SPACE,
    // U+003E GREATER-THAN SIGN (>), or U+002F SOLIDUS (/), unless
    // that string is part of an escaping text span.

    // An escaping text span is a span of text (in CDATA and RCDATA
    // elements) and character entity references (in RCDATA elements)
    // that starts with an escaping text span start that is not itself
    // in an escaping text span, and ends at the next escaping text
    // span end.

    // An escaping text span start is a part of text that consists of
    // the four character sequence "<!--".

    // An escaping text span end is a part of text that consists of
    // the three character sequence "-->".

    // An escaping text span start may share its U+002D HYPHEN-MINUS characters
    // with its corresponding escaping text span end.
    UNESCAPED_LT_BANG,             // <!
    UNESCAPED_LT_BANG_DASH,        // <!-
    ESCAPING_TEXT_SPAN,            // Inside an escaping text span
    ESCAPING_TEXT_SPAN_DASH,       // Seen - inside an escaping text span
    ESCAPING_TEXT_SPAN_DASH_DASH,  // Seen -- inside an escaping text span
    ;
  }

  private HtmlToken lastNonIgnorable = null;
  /**
   * Breaks the character stream into tokens.
   * This method returns a stream of tokens such that each token starts where
   * the last token ended.
   *
   * <p>This property is useful as it allows fetch to collapse and reclassify
   * ranges of tokens based on state that is easy to maintain there.
   *
   * <p>Later passes are responsible for throwing away useless tokens.
   */
  private HtmlToken parseToken() {
    int start = offset;
    int limit = input.length();
    if (start == limit) { return null; }

    int end = start + 1;
    HtmlTokenType type;

    char ch = input.charAt(start);
    if (inTag) {
      if ('>' == ch) {
        type = HtmlTokenType.TAGEND;
        inTag = false;
      } else if ('/' == ch) {
        if (end != limit && '>' == input.charAt(end)) {
          type = HtmlTokenType.TAGEND;
          inTag = false;
          ++end;
        } else {
          type = HtmlTokenType.TEXT;
        }
      } else if ('=' == ch) {
        type = HtmlTokenType.TEXT;
      } else if ('"' == ch || '\'' == ch) {
        type = HtmlTokenType.QSTRING;
        int delim = ch;
        for (; end < limit; ++end) {
          if (input.charAt(end) == delim) {
            ++end;
            break;
          }
        }
      } else if (!Character.isWhitespace(ch)) {
        type = HtmlTokenType.TEXT;
        for (; end < limit; ++end) {
          ch = input.charAt(end);
          // End a text chunk before />
          if ((lastNonIgnorable == null
               || !lastNonIgnorable.tokenInContextMatches(input, "="))
              && '/' == ch && end + 1 < limit
              && '>' == input.charAt(end + 1)) {
            break;
          } else if ('>' == ch || '=' == ch
                     || Character.isWhitespace(ch)) {
            break;
          } else if ('"' == ch || '\'' == ch) {
            if (end + 1 < limit) {
              char ch2 = input.charAt(end + 1);
              if (Character.isWhitespace(ch2)
                  || ch2 == '>' || ch2 == '/') {
                ++end;
                break;
              }
            }
          }
        }
      } else {
        // We skip whitespace tokens inside tag bodies.
        type = HtmlTokenType.IGNORABLE;
        while (end < limit && Character.isWhitespace(input.charAt(end))) {
          ++end;
        }
      }
    } else {
      if (ch == '<') {
        if (end == limit) {
          type = HtmlTokenType.TEXT;
        } else {
          ch = input.charAt(end);
          type = null;
          State state = null;
          switch (ch) {
            case '/':  // close tag?
              state = State.SLASH;
              ++end;
              break;
            case '!':  // Comment or declaration
              if (!this.inEscapeExemptBlock) {
                state = State.BANG;
              } else if (HtmlTextEscapingMode.allowsEscapingTextSpan(
                             escapeExemptTagName)) {
                // Directives, and cdata suppressed in escape
                // exempt mode as they could obscure the close of the
                // escape exempty block, but comments are similar to escaping
                // text spans, and are significant in all CDATA and RCDATA
                // blocks except those inside <xmp> tags.
                // See "Escaping text spans" in section 8.1.2.6 of HTML5.
                // http://www.w3.org/html/wg/html5/#cdata-rcdata-restrictions
                state = State.UNESCAPED_LT_BANG;
              }
              ++end;
              break;
            case '?':
              if (!this.inEscapeExemptBlock) {
                state = State.BOGUS_COMMENT;
              }
              ++end;
              break;
            case '%':
              state = State.SERVER_CODE;
              ++end;
              break;
            default:
              if (isIdentStart(ch) && !this.inEscapeExemptBlock) {
                state = State.TAGNAME;
                ++end;
              } else if ('<' == ch) {
                type = HtmlTokenType.TEXT;
              } else {
                ++end;
              }
              break;
          }
          if (null != state) {
            charloop:
            while (end < limit) {
              ch = input.charAt(end);
              switch (state) {
                case TAGNAME:
                  if (Character.isWhitespace(ch)
                      || '>' == ch || '/' == ch || '<' == ch) {
                    // End processing of an escape exempt block when we see
                    // a corresponding end tag.
                    if (this.inEscapeExemptBlock
                        && '/' == input.charAt(start + 1)
                        && textEscapingMode != HtmlTextEscapingMode.PLAIN_TEXT
                        && canonicalName(start + 2, end)
                            .equals(escapeExemptTagName)) {
                      this.inEscapeExemptBlock = false;
                      this.escapeExemptTagName = null;
                      this.textEscapingMode = null;
                    }
                    type = HtmlTokenType.TAGBEGIN;
                    // Don't process content as attributes if we're inside
                    // an escape exempt block.
                    inTag = !this.inEscapeExemptBlock;
                    state = State.DONE;
                    break charloop;
                  }
                  break;
                case SLASH:
                  if (Character.isLetter(ch)) {
                    state = State.TAGNAME;
                  } else {
                    if ('<' == ch) {
                      type = HtmlTokenType.TEXT;
                    } else {
                      ++end;
                    }
                    break charloop;
                  }
                  break;
                case BANG:
                  if ('-' == ch) {
                    state = State.BANG_DASH;
                  } else {
                    state = State.DIRECTIVE;
                  }
                  break;
                case BANG_DASH:
                  if ('-' == ch) {
                    state = State.COMMENT;
                  } else {
                    state = State.DIRECTIVE;
                  }
                  break;
                case COMMENT:
                  if ('-' == ch) {
                    state = State.COMMENT_DASH;
                  }
                  break;
                case COMMENT_DASH:
                  state = ('-' == ch)
                      ? State.COMMENT_DASH_DASH
                      : State.COMMENT_DASH;
                  break;
                case COMMENT_DASH_DASH:
                  if ('>' == ch) {
                    state = State.DONE;
                    type = HtmlTokenType.COMMENT;
                  } else if ('-' == ch) {
                    state = State.COMMENT_DASH_DASH;
                  } else {
                    state = State.COMMENT_DASH;
                  }
                  break;
                case DIRECTIVE:
                  if ('>' == ch) {
                    type = HtmlTokenType.DIRECTIVE;
                    state = State.DONE;
                  }
                  break;
                case BOGUS_COMMENT:
                  if ('>' == ch) {
                    type = HtmlTokenType.QMARKMETA;
                    state = State.DONE;
                  }
                  break;
                case SERVER_CODE:
                  if ('%' == ch) {
                    state = State.SERVER_CODE_PCT;
                  }
                  break;
                case SERVER_CODE_PCT:
                  if ('>' == ch) {
                    type = HtmlTokenType.SERVERCODE;
                    state = State.DONE;
                  } else if ('%' != ch) {
                    state = State.SERVER_CODE;
                  }
                  break;
                case UNESCAPED_LT_BANG:
                  if ('-' == ch) {
                    state = State.UNESCAPED_LT_BANG_DASH;
                  } else {
                    type = HtmlTokenType.TEXT;
                    state = State.DONE;
                  }
                  break;
                case UNESCAPED_LT_BANG_DASH:
                  if ('-' == ch) {
                    // According to HTML 5 section 8.1.2.6

                    // An escaping text span start may share its
                    // U+002D HYPHEN-MINUS characters with its
                    // corresponding escaping text span end.
                    state = State.ESCAPING_TEXT_SPAN_DASH_DASH;
                  } else {
                    type = HtmlTokenType.TEXT;
                    state = State.DONE;
                  }
                  break;
                case ESCAPING_TEXT_SPAN:
                  if ('-' == ch) {
                    state = State.ESCAPING_TEXT_SPAN_DASH;
                  }
                  break;
                case ESCAPING_TEXT_SPAN_DASH:
                  if ('-' == ch) {
                    state = State.ESCAPING_TEXT_SPAN_DASH_DASH;
                  } else {
                    state = State.ESCAPING_TEXT_SPAN;
                  }
                  break;
                case ESCAPING_TEXT_SPAN_DASH_DASH:
                  if ('>' == ch) {
                    type = HtmlTokenType.TEXT;
                    state = State.DONE;
                  } else if ('-' != ch) {
                    state = State.ESCAPING_TEXT_SPAN;
                  }
                  break;
                case DONE:
                  throw new AssertionError(
                      "Unexpectedly DONE while lexing HTML token stream");
              }
              ++end;
              if (State.DONE == state) { break; }
            }
            if (end == limit) {
              switch (state) {
                case DONE:
                  break;
                case BOGUS_COMMENT:
                  type = HtmlTokenType.QMARKMETA;
                  break;
                case COMMENT:
                case COMMENT_DASH:
                case COMMENT_DASH_DASH:
                  type = HtmlTokenType.COMMENT;
                  break;
                case DIRECTIVE:
                case SERVER_CODE:
                case SERVER_CODE_PCT:
                  type = HtmlTokenType.SERVERCODE;
                  break;
                case TAGNAME:
                  type = HtmlTokenType.TAGBEGIN;
                  break;
                default:
                  type = HtmlTokenType.TEXT;
                  break;
              }
            }
          }
        }
      } else {
        type = null;
      }
    }
    if (null == type) {
      while (end < limit && '<' != input.charAt(end)) { ++end; }
      type = HtmlTokenType.TEXT;
    }

    offset = end;
    HtmlToken result = HtmlToken.instance(start, end, type);
    if (type != HtmlTokenType.IGNORABLE) { lastNonIgnorable = result; }
    return result;
  }

  private String canonicalName(int start, int end) {
    return HtmlLexer.canonicalName(input.substring(start, end));
  }

  private static boolean isIdentStart(char ch) {
    return ch >= 'A' && ch <= 'z' && (ch <= 'Z' || ch >= 'a');
  }

  static HtmlToken reclassify(HtmlToken token, HtmlTokenType type) {
    return HtmlToken.instance(token.start, token.end, type);
  }
}


/**
 * A TokenStream that lazily fetches one token at a time.
 *
 * @author Mike Samuel (mikesamuel@gmail.com)
 */
abstract class AbstractTokenStream implements TokenStream {
  private HtmlToken tok;

  public final boolean hasNext() {
    if (tok == null) { tok = produce(); }
    return tok != null;
  }

  public HtmlToken next() {
    if (this.tok == null) { this.tok = produce(); }
    HtmlToken t = this.tok;
    if (t == null) { throw new NoSuchElementException(); }
    this.tok = null;
    return t;
  }

  protected abstract HtmlToken produce();
}
