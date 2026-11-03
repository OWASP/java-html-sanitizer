// SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause

package org.owasp.html;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.annotation.Nullable;

import org.owasp.html.AttributePolicy.JoinableAttributePolicy;

/**
 * Vets an SVG presentation attribute, such as {@code fill} or
 * {@code clip-path}, whose value is CSS that can name a resource with
 * {@code url(...)}.  Browsers fetch that resource when the page loads, as they
 * do one named in a {@code style} attribute, so each URL in the value has to
 * pass the policy a URL in {@code style} has to pass: the one given to
 * {@link HtmlPolicyBuilder#allowUrlsInStyles}, then the URL protocol guard.
 * A reference to an element in the same document, such as
 * {@code url(#gradient)}, loads nothing and is always allowed.
 * <p>
 * The value is tokenized as CSS, which decodes escapes, so every spelling of
 * {@code url(} is seen, and the result is emitted in the normalized form that
 * was vetted.  Only the kinds of token a single property value needs are
 * allowed.  CSS can also take a URL from a string inside a function, as
 * {@code image-set("x.png" 1x)} does, so a value that calls any function
 * outside {@link #ALLOWED_FUNCTIONS}, which compute colors, numbers, filter
 * effects, shapes and gradients or read a custom property, is dropped.  If a
 * URL in the value is rejected, the whole value is dropped.
 */
@TCB
final class PresentationAttributePolicy implements JoinableAttributePolicy {

  /**
   * The CSS functions a value may call, lower-cased.  None of them takes a
   * URL or a string that the browser treats as one.
   */
  static final Set<String> ALLOWED_FUNCTIONS;
  static {
    Set<String> names = new HashSet<>();
    Collections.addAll(
        names,
        // Colors.
        "rgb", "rgba", "hsl", "hsla", "hwb", "lab", "lch", "oklab", "oklch",
        "color", "color-mix", "light-dark",
        // Math.
        "calc", "min", "max", "clamp",
        // Custom properties, which only the page's own CSS can define: the
        // style guard allows none.  Any url(...) or function in a fallback
        // is vetted like the rest of the value.
        "var",
        // Filter effects.
        "blur", "brightness", "contrast", "drop-shadow", "grayscale",
        "hue-rotate", "invert", "opacity", "saturate", "sepia",
        // Basic shapes.
        "inset", "circle", "ellipse", "polygon", "path", "rect", "shape",
        "xywh",
        // Gradients.
        "linear-gradient", "radial-gradient", "conic-gradient",
        "repeating-linear-gradient", "repeating-radial-gradient",
        "repeating-conic-gradient");
    ALLOWED_FUNCTIONS = Collections.unmodifiableSet(names);
  }

  private final AttributePolicy urlPolicy;

  PresentationAttributePolicy(AttributePolicy urlPolicy) {
    this.urlPolicy = urlPolicy;
  }

  public @Nullable String apply(
      String elementName, String attributeName, String value) {
    CssTokens tokens = CssTokens.lex(value);
    StringBuilder sb = new StringBuilder(tokens.normalizedCss.length());
    boolean afterUrl = false;
    for (CssTokens.TokenIterator it = tokens.iterator(); it.hasNext();
         it.advance()) {
      String token = it.token();
      CssTokens.TokenType type = it.type();
      // The tokenizer repairs a url( that the browser rejects, such as
      // url(a b), into a url(...) followed directly by another token.  The
      // browser would load nothing for the input, so emit nothing it would.
      if (afterUrl && type != CssTokens.TokenType.WHITESPACE
          && type != CssTokens.TokenType.COMMA
          && type != CssTokens.TokenType.RIGHT_PAREN) {
        return null;
      }
      afterUrl = false;
      switch (type) {
        case URL: {
          // CssTokens has dropped the spaces at either end of the URL.
          String url = CssGrammar.cssContent(
              token.substring(4, token.length() - 1));
          String okUrl = vetUrl(url);
          if (okUrl == null) {
            return null;
          }
          sb.append("url('");
          StylingPolicy.appendCssUrlContent(okUrl, sb);
          sb.append("')");
          afterUrl = true;
          break;
        }
        case FUNCTION: {
          String name = Strings.toLowerCase(
              token.substring(0, token.length() - 1));
          if (!ALLOWED_FUNCTIONS.contains(name)) {
            return null;
          }
          sb.append(token);
          break;
        }
        case IDENT: case HASH_ID: case HASH_UNRESTRICTED: case STRING:
        case NUMBER: case PERCENTAGE: case DIMENSION: case BAD_DIMENSION:
        case DELIM: case COMMA: case WHITESPACE:
        case LEFT_PAREN: case RIGHT_PAREN:
          sb.append(token);
          break;
        default:
          return null;
      }
    }
    return sb.toString();
  }

  /**
   * The URL to emit for one in the value, or null to drop the value.
   */
  private @Nullable String vetUrl(String url) {
    if (url.isEmpty() || url.length() >= StylingPolicy.MAX_CSS_URL_LENGTH) {
      return null;
    }
    if (url.charAt(0) == '#') {
      // A reference to an element in this document, whatever the base URL.
      return FilterUrlByProtocolAttributePolicy.normalizeUri(url);
    }
    String okUrl = urlPolicy.apply("img", "src", url);
    return okUrl == null || okUrl.isEmpty() ? null : okUrl;
  }

  @Override
  public boolean equals(Object o) {
    return o instanceof PresentationAttributePolicy
        && urlPolicy.equals(((PresentationAttributePolicy) o).urlPolicy);
  }

  @Override
  public int hashCode() {
    return urlPolicy.hashCode();
  }

  public Joinable.JoinStrategy<JoinableAttributePolicy> getJoinStrategy() {
    return PresentationAttributeJoinStrategy.INSTANCE;
  }

  /**
   * Joins presentation attribute policies by joining the policies they apply
   * to each URL, so that the URL protocol guards inside them meet and join as
   * they do on {@code href}: a builder that allowed no protocol yields to one
   * that did, and two allowlists intersect.
   */
  static final class PresentationAttributeJoinStrategy
  implements Joinable.JoinStrategy<JoinableAttributePolicy> {
    static final PresentationAttributeJoinStrategy INSTANCE =
        new PresentationAttributeJoinStrategy();

    public JoinableAttributePolicy join(
        Iterable<? extends JoinableAttributePolicy> toJoin) {
      List<AttributePolicy> urlPolicies = new ArrayList<>();
      for (JoinableAttributePolicy p : toJoin) {
        urlPolicies.add(((PresentationAttributePolicy) p).urlPolicy);
      }
      return new PresentationAttributePolicy(
          AttributePolicy.Util.join(
              urlPolicies.toArray(new AttributePolicy[0])));
    }
  }

}
