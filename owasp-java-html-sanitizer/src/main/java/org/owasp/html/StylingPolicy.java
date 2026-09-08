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

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import javax.annotation.Nullable;

import org.owasp.html.AttributePolicy.JoinableAttributePolicy;

/**
 * An HTML sanitizer policy that tries to preserve simple CSS by white-listing
 * property values and splitting combo properties into multiple more specific
 * ones to reduce the attack-surface.
 */
@TCB
final class StylingPolicy implements JoinableAttributePolicy {

  final CssSchema cssSchema;
  final Function<String, String> urlRewriter;

  StylingPolicy(CssSchema cssSchema, Function<String, String> urlRewriter) {
    this.cssSchema = cssSchema;
    this.urlRewriter = urlRewriter;
  }

  public @Nullable String apply(
      String elementName, String attributeName, String value) {
    return value != null ? sanitizeCssProperties(value) : null;
  }

  /**
   * Lossy filtering of CSS properties that allows textual styling that affects
   * layout, but does not allow breaking out of a clipping region, absolute
   * positioning, image loading, tab index changes, or code execution.
   *
   * @return A sanitized version of the input.
   */
  //only visible for testing
  String sanitizeCssProperties(String style) {
    final StringBuilder sanitizedCss = new StringBuilder();
    CssGrammar.parsePropertyGroup(style, new CssGrammar.PropertyHandler() {
      CssSchema.Property cssProperty = CssSchema.DISALLOWED;
      List<CssSchema.Property> cssProperties = null;
      int propertyStart = 0;
      boolean hasTokens;
      boolean inQuotedIdents;
      String lastToken = null;

      private void emitToken(String token) {
        closeQuotedIdents();
        if (hasTokens) { sanitizedCss.append(' '); }
        sanitizedCss.append(token);
        hasTokens = true;
      }

      private void closeQuotedIdents() {
        if (inQuotedIdents) {
          sanitizedCss.append('\'');
          inQuotedIdents = false;
        }
      }

      private void sanitizeAndAppendUrl(String urlContent) {
        if (urlContent.length() < 1024) {
          String rewrittenUrl = urlRewriter.apply(urlContent);
          if (rewrittenUrl != null && !rewrittenUrl.isEmpty()) {
            if (hasTokens) { sanitizedCss.append(' '); }
            sanitizedCss.append("url('").append(rewrittenUrl).append("')");
            hasTokens = true;
          }
        }
      }

      public void url(String token) {
        closeQuotedIdents();
        if (cssProperty != null) {
          if ((cssProperty.bits & CssSchema.BIT_URL) != 0) {
            String urlContent = CssGrammar.cssContent(
                Strings.stripHtmlSpaces(  // TODO: css spaces
                    token.substring(4, token.length() - 1)));
            sanitizeAndAppendUrl(urlContent);
          }
        }
        lastToken = token;
      }

      public void startProperty(String propertyName) {
        if (cssProperties != null) { cssProperties.clear(); }
        cssProperty = cssSchema.forKey(propertyName);
        hasTokens = false;
        propertyStart = sanitizedCss.length();
        if (sanitizedCss.length() != 0) {
          sanitizedCss.append(';');
        }
        sanitizedCss.append(propertyName).append(':');
      }

      public void startFunction(String uncanonToken) {
        closeQuotedIdents();
        if (cssProperties == null) { cssProperties = new ArrayList<>(); }
        cssProperties.add(cssProperty);
        String token = Strings.toLowerCase(uncanonToken);
        String key = cssProperty.fnKeys.get(token);
        cssProperty = key != null
            ? cssSchema.forKey(key)
            : CssSchema.DISALLOWED;
        if (cssProperty != CssSchema.DISALLOWED) {
          emitToken(token);
        }
        lastToken = token;
      }

      public void quotedString(String token) {
        closeQuotedIdents();
        // The contents of a quoted string could be treated as
        // 1. a run of space-separated words, as in a font family name,
        // 2. as a URL,
        // 3. as plain text content as in a list-item bullet,
        // 4. or it could be ambiguous as when multiple bits are set.
        int meaning =
            cssProperty.bits
            & (CssSchema.BIT_UNRESERVED_WORD | CssSchema.BIT_URL);
        if ((meaning & (meaning - 1)) == 0) {  // meaning is unambiguous
          if (meaning == CssSchema.BIT_UNRESERVED_WORD
              && token.length() > 2
              && isSafeQuotedIdentifier(token, 1, token.length() - 1)) {
            // Emit as written: a font name is a name, not a keyword, so its
            // case matters to the reader even though CSS matches it
            // case-insensitively.
            emitToken(token);
          } else if (meaning == CssSchema.BIT_URL) {
            // convert to a URL token and hand-off to the appropriate method
            sanitizeAndAppendUrl(CssGrammar.cssContent(token));
          }
        }
        lastToken = token;
      }

      public void quantity(String token) {
        int test = token.startsWith("-")
            ? CssSchema.BIT_NEGATIVE : CssSchema.BIT_QUANTITY;
        if ((cssProperty.bits & test) != 0
            // font-weight uses 100, 200, 300, etc.
            || cssProperty.literals.contains(token)) {
          emitToken(token);
        }
        lastToken = token;
      }

      public void punctuation(String token) {
        closeQuotedIdents();
        if (cssProperty.literals.contains(token)) {
          emitToken(token);
        }
        lastToken = token;
      }

      private static final int IDENT_TO_STRING =
          CssSchema.BIT_UNRESERVED_WORD | CssSchema.BIT_STRING;
      public void identifier(String uncanonToken) {
        String token = Strings.toLowerCase(uncanonToken);
        if ("!".equals(lastToken) && "important".equals(token)) {
          emitToken("!important");
        } else if (cssProperty.literals.contains(token)) {
          emitToken(token);
        } else if ((cssProperty.bits & IDENT_TO_STRING) == IDENT_TO_STRING
                   && isSafeQuotedIdentifier(
                       uncanonToken, 0, uncanonToken.length())) {
          // Same test as the quoted path.  This path had none at all, so a
          // bare name could carry a format character -- a bidi override, say
          // -- into the output, and a name the quoted path would reject
          // survived one pass and vanished on the next.
          if (!inQuotedIdents) {
            inQuotedIdents = true;
            if (hasTokens) { sanitizedCss.append(' '); }
            sanitizedCss.append('\'');
            hasTokens = true;
          } else {
            sanitizedCss.append(' ');
          }
          // As above: emit the name as the author wrote it.  Matching against
          // the schema is case-insensitive, but the output is a name.
          sanitizedCss.append(uncanonToken);
        }
        lastToken = token;
      }

      public void hash(String token) {
        closeQuotedIdents();
        if ((cssProperty.bits & CssSchema.BIT_HASH_VALUE) != 0) {
          emitToken(Strings.toLowerCase(token));
        }
        lastToken = token;
      }

      public void endProperty() {
        if (!hasTokens) {
          sanitizedCss.setLength(propertyStart);
        } else {
          closeQuotedIdents();
        }
        lastToken = null;
      }

      public void endFunction(String token) {
        if (cssProperty != CssSchema.DISALLOWED) { emitToken(")"); }
        cssProperty = cssProperties.remove(cssProperties.size() - 1);
        lastToken = ")";
      }
    });
    return sanitizedCss.length() == 0 ? null : sanitizedCss.toString();
  }

  /**
   * True if the given range of a quoted token can be re-emitted between single
   * quotes without any further escaping.
   *
   * <p>This is deliberately a small set.  The CSS lexer normalizes a string's
   * contents, so a quote or a backslash reaches us already escaped -- {@code
   * 'it\27s'}, {@code 'a\5c b'} -- and re-emitting an escape verbatim would
   * mean reasoning about escape parity to be sure the closing quote is still
   * the closing quote.  Rejecting the backslash outright avoids that question
   * entirely, at the cost of dropping the rare font name that needs one.
   *
   * <p>What it does allow is a letter or digit from the basic multilingual
   * plane, a space, and the hyphen, underscore and period that appear in names
   * like {@code Foo_Bar} and {@code Helvetica Neue LT Std.55 Roman}.  The
   * underscore matters in practice because Word emits font names containing
   * one, and because the unquoted path already accepted it -- so a name would
   * survive sanitization once and be dropped on the way back in.
   *
   * <p>That covers Latin, Cyrillic, Greek, Han, Hangul, kana and the base
   * letters of the Arabic, Hebrew, Devanagari and Thai scripts.  It does not
   * cover a name carrying a combining mark -- a Devanagari matra, an Arabic
   * diacritic, Hebrew niqqud, a Thai vowel sign -- nor one containing a
   * character outside the basic multilingual plane, such as a CJK extension B
   * ideograph.  Those never reach this method: the CSS lexer excludes them
   * from a token before the policy sees it, and has always done so.  So this
   * test is defence in depth for non-ASCII rather than the decisive gate, and
   * relaxing it alone would not make such a name work.
   */
  static boolean isSafeQuotedIdentifier(
      String token, int start, int end) {
    for (int i = start; i < end; ++i) {
      char ch = token.charAt(i);
      if (ch <= 0x20) {
        if (ch != '\t' && ch != ' ') {
          return false;
        }
      } else if (ch < 0x80) {
        int chLower = ch | 32;
        if (!(('0' <= chLower && chLower <= '9')
              || ('a' <= chLower && chLower <= 'z')
              || '-' == ch || '_' == ch || '.' == ch)) {
          return false;
        }
      } else if (!Character.isLetterOrDigit(ch)) {
        // Non-ASCII font names are ordinary -- CJK families, for instance --
        // but only letters and digits, so that a format character such as a
        // bidi override cannot ride along.  Note this reads one char at a
        // time, so it would also reject a supplementary code point; nothing
        // reaches here with one today, because the lexer has already excluded
        // it, but a lexer that stopped doing so would need this to use
        // codePointAt.
        return false;
      }
    }
    return true;
  }

  // The url rewriter takes part in equality because joining groups policies
  // into a Set first: two styling policies that share a schema but vet URLs
  // differently must both survive to be joined, or one rewriter would be
  // dropped silently.
  @Override
  public boolean equals(Object o) {
    if (o == null || getClass() != o.getClass()) { return false; }
    StylingPolicy that = (StylingPolicy) o;
    return cssSchema.equals(that.cssSchema)
        && urlRewriter.equals(that.urlRewriter);
  }

  @Override
  public int hashCode() {
    return cssSchema.hashCode() + 31 * urlRewriter.hashCode();
  }

  public Joinable.JoinStrategy<JoinableAttributePolicy> getJoinStrategy() {
    return StylingPolicyJoinStrategy.INSTANCE;
  }

  static final class StylingPolicyJoinStrategy
  implements Joinable.JoinStrategy<JoinableAttributePolicy> {
    static final StylingPolicyJoinStrategy INSTANCE =
        new StylingPolicyJoinStrategy();

    public JoinableAttributePolicy join(
        Iterable<? extends JoinableAttributePolicy> toJoin) {
      Function<String, String> identity = Function.<String>identity();
      CssSchema cssSchema = null;
      Function<String, String> urlRewriter = identity;
      for (JoinableAttributePolicy p : toJoin) {
        StylingPolicy sp = (StylingPolicy) p;
        // Joining narrows: a value has to satisfy every policy being joined,
        // which is how every other joined attribute policy behaves and what
        // PolicyFactory.and promises.  Unioning here let a.and(b) allow
        // properties that neither a nor b allowed on its own.
        cssSchema = cssSchema == null
            ? sp.cssSchema : CssSchema.intersection(cssSchema, sp.cssSchema);
        urlRewriter = urlRewriter.equals(identity)
            || urlRewriter.equals(sp.urlRewriter)
            ? sp.urlRewriter
            : andThen(urlRewriter, sp.urlRewriter);
      }
      return new StylingPolicy(cssSchema, urlRewriter);
    }

    /**
     * A rewriter that runs both in turn, so a URL has to satisfy both to
     * survive.  A rewriter signals "dropped" by returning null or the empty
     * string, which is not a URL, so it short-circuits instead of being
     * passed on to the next rewriter.
     */
    private static Function<String, String> andThen(
        final Function<String, String> first,
        final Function<String, String> second) {
      return new Function<String, String>() {
        public @Nullable String apply(String url) {
          String rewritten = first.apply(url);
          return rewritten == null || rewritten.isEmpty()
              ? null
              : second.apply(rewritten);
        }
      };
    }
  }
}
