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
 * pass the URL policy, as a URL in {@code href} does.
 * <p>
 * The value is tokenized as CSS, which decodes escapes, so every spelling of
 * {@code url(} is seen, and the result is emitted in the normalized form that
 * was vetted.  CSS can also take a URL from a string inside a function, as
 * {@code image-set("x.png" 1x)} does, so a value that calls any function
 * outside {@link #ALLOWED_FUNCTIONS}, which compute colors, numbers, filter
 * effects and shapes, is dropped.  So is a value with a {@code ;}, a brace or
 * an at-keyword, none of which belongs in a single property value.  If a URL
 * in the value is rejected, the whole value is dropped.
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
        // Filter effects.
        "blur", "brightness", "contrast", "drop-shadow", "grayscale",
        "hue-rotate", "invert", "opacity", "saturate", "sepia",
        // Basic shapes.
        "inset", "circle", "ellipse", "polygon", "path", "rect", "xywh",
        // Gradients.
        "linear-gradient", "radial-gradient", "conic-gradient",
        "repeating-linear-gradient", "repeating-radial-gradient",
        "repeating-conic-gradient");
    ALLOWED_FUNCTIONS = Collections.unmodifiableSet(names);
  }

  private static final String HEX_DIGITS = "0123456789abcdef";

  private final AttributePolicy urlPolicy;

  PresentationAttributePolicy(AttributePolicy urlPolicy) {
    this.urlPolicy = urlPolicy;
  }

  public @Nullable String apply(
      String elementName, String attributeName, String value) {
    CssTokens tokens = CssTokens.lex(value);
    StringBuilder sb = new StringBuilder(tokens.normalizedCss.length());
    for (CssTokens.TokenIterator it = tokens.iterator(); it.hasNext();) {
      String token = it.token();
      switch (it.type()) {
        case URL: {
          String url = CssGrammar.cssContent(
              Strings.stripHtmlSpaces(token.substring(4, token.length() - 1)));
          String okUrl = urlPolicy.apply(elementName, attributeName, url);
          if (okUrl == null || okUrl.isEmpty()) {
            return null;
          }
          sb.append("url('");
          appendCssUrlContent(okUrl, sb);
          sb.append("')");
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
        case AT: case SEMICOLON: case LEFT_CURLY: case RIGHT_CURLY:
          return null;
        default:
          sb.append(token);
          break;
      }
      it.advance();
    }
    return sb.toString();
  }

  /**
   * Appends a URL inside {@code url('...')}, percent-encoding what would end
   * or escape the CSS string, as {@link StylingPolicy} does.
   */
  private static void appendCssUrlContent(String url, StringBuilder sb) {
    for (int i = 0, n = url.length(); i < n; ++i) {
      char ch = url.charAt(i);
      if (ch == '\'' || ch == '\\' || ch <= 0x20 || ch == 0x7f) {
        sb.append('%')
            .append(HEX_DIGITS.charAt(ch >> 4))
            .append(HEX_DIGITS.charAt(ch & 0xf));
      } else {
        sb.append(ch);
      }
    }
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
