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

import javax.annotation.Nullable;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.Lists;

/**
 * An HTML sanitizer policy that tries to preserve simple CSS by white-listing
 * property values and splitting combo properties into multiple more specific
 * ones to reduce the attack-surface.
 */
@TCB
final class StylingPolicy implements AttributePolicy {

  final CssSchema cssSchema;

  StylingPolicy(CssSchema cssSchema) {
    this.cssSchema = cssSchema;
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
  @VisibleForTesting
  String sanitizeCssProperties(String style) {
    final StringBuilder sanitizedCss = new StringBuilder();
    CssGrammar.parsePropertyGroup(style, new CssGrammar.PropertyHandler() {
      CssSchema.Property cssProperty = CssSchema.DISALLOWED;
      List<CssSchema.Property> cssProperties = null;
      int propertyStart = 0;
      boolean hasTokens;
      boolean inQuotedIdents;

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

      public void url(String token) {
        closeQuotedIdents();
        //if ((schema.bits & CssSchema.BIT_URL) != 0) {
        // TODO: sanitize the URL.
        //}
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
        if (cssProperties == null) { cssProperties = Lists.newArrayList(); }
        cssProperties.add(cssProperty);
        String token = Strings.toLowerCase(uncanonToken);
        String key = cssProperty.fnKeys.get(token);
        cssProperty = key != null
            ? cssSchema.forKey(key)
            : CssSchema.DISALLOWED;
        if (cssProperty != CssSchema.DISALLOWED) {
          emitToken(token);
        }
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
              && isAlphanumericOrSpace(token, 1, token.length() - 1)) {
            emitToken(Strings.toLowerCase(token));
          } else if (meaning == CssSchema.BIT_URL) {
            // convert to a URL token and hand-off to the appropriate method
            // url("url(" + token + ")");  // TODO: %-encode properly
          }
        }
      }

      public void quantity(String token) {
        int test = token.startsWith("-")
            ? CssSchema.BIT_NEGATIVE : CssSchema.BIT_QUANTITY;
        if ((cssProperty.bits & test) != 0
            // font-weight uses 100, 200, 300, etc.
            || cssProperty.literals.contains(token)) {
          emitToken(token);
        }
      }

      public void punctuation(String token) {
        closeQuotedIdents();
        if (cssProperty.literals.contains(token)) {
          emitToken(token);
        }
      }

      private static final int IDENT_TO_STRING =
          CssSchema.BIT_UNRESERVED_WORD | CssSchema.BIT_STRING;
      public void identifier(String uncanonToken) {
        String token = Strings.toLowerCase(uncanonToken);
        if (cssProperty.literals.contains(token)) {
          emitToken(token);
        } else if ((cssProperty.bits & IDENT_TO_STRING) == IDENT_TO_STRING) {
          if (!inQuotedIdents) {
            inQuotedIdents = true;
            if (hasTokens) { sanitizedCss.append(' '); }
            sanitizedCss.append('\'');
            hasTokens = true;
          } else {
            sanitizedCss.append(' ');
          }
          sanitizedCss.append(Strings.toLowerCase(token));
        }
      }

      public void hash(String token) {
        closeQuotedIdents();
        if ((cssProperty.bits & CssSchema.BIT_HASH_VALUE) != 0) {
          emitToken(Strings.toLowerCase(token));
        }
      }

      public void endProperty() {
        if (!hasTokens) {
          sanitizedCss.setLength(propertyStart);
        } else {
          closeQuotedIdents();
        }
      }

      public void endFunction(String token) {
        if (cssProperty != CssSchema.DISALLOWED) { emitToken(")"); }
        cssProperty = cssProperties.remove(cssProperties.size() - 1);
      }
    });
    return sanitizedCss.length() == 0 ? null : sanitizedCss.toString();
  }

  static boolean isAlphanumericOrSpace(
      String token, int start, int end) {
    for (int i = start; i < end; ++i) {
      char ch = token.charAt(i);
      if (ch <= 0x20) {
        if (ch != '\t' && ch != ' ') {
          return false;
        }
      } else {
        int chLower = ch | 32;
        if (!(('0' <= chLower && chLower <= '9')
              || ('a' <= chLower && chLower <= 'z'))) {
          return false;
        }
      }
    }
    return true;
  }

  @Override
  public boolean equals(Object o) {
    return o != null && getClass() == o.getClass()
        && cssSchema.equals(((StylingPolicy) o).cssSchema);
  }

  @Override
  public int hashCode() {
    return cssSchema.hashCode();
  }

}
