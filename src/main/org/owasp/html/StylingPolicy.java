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

import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Lists;

/**
 * An HTML sanitizer policy that tries to preserve simple CSS by converting it
 * to {@code <font>} tags which allow fewer ways to embed JavaScript.
 */
@TCB
class StylingPolicy extends ElementAndAttributePolicyBasedSanitizerPolicy {
  StylingPolicy(
      HtmlStreamEventReceiver out,
      ImmutableMap<String, ElementAndAttributePolicies> elAndAttrPolicies) {
    super(out, elAndAttrPolicies);
  }

  @Override public void openTag(String elementName, List<String> attrs) {
    // Parts of the superclass method are repeated here, so if you change this,
    // be sure to check the super-class.
    String style = null;
    for (Iterator<String> it = attrs.iterator(); it.hasNext();) {
      String name = it.next();
      if ("style".equals(name)) {
        style = it.next();
        break;
      } else {
        it.next();
      }
    }
    ElementAndAttributePolicies policies = elAndAttrPolicies.get(elementName);
    String adjustedElementName = applyPolicies(elementName, attrs, policies);
    if (adjustedElementName != null) {
      List<String> fontAttributes = null;
      if (style != null) {
        fontAttributes = cssPropertiesToFontAttributes(style);
        if (fontAttributes.isEmpty()) {
          fontAttributes = null;
        }
      }
      // If we have something to output, emit it.
      if (!(attrs.isEmpty() && policies.skipIfEmpty
            && fontAttributes == null)) {
        skipText = false;
        writeOpenTag(policies, adjustedElementName, attrs);
        if (fontAttributes != null) {
          synthesizeOpenTag("font", fontAttributes);
          // Rely on the tag balancer to close it.
        }
        return;
      }
    }
    deferOpenTag(elementName);
  }

  /** Used to track CSS property names while processing CSS. */
  private enum CssPropertyType {
    FONT,
    FACE,
    SIZE,
    BACKGROUND_COLOR,
    COLOR,
    DIRECTION,
    UNICODE_BIDI,
    ALIGN,
    WEIGHT,
    STYLE,
    TEXT_DECORATION,
    NONE,
    ;
  }

  private static final Pattern ALLOWED_CSS_SIZE = Pattern.compile(
      "medium|(?:small|large)r|(?:xx?-)(?:small|large)|[0-9]+(p[tx]|%)");

  private static final Pattern ALLOWED_CSS_WEIGHT = Pattern.compile(
      "normal|bold(?:er)?|lighter|[1-9]00");

  private static final Set<String> ALLOWED_CSS_STYLE = ImmutableSet.of(
      "italic", "oblique", "normal");

  private static final Set<String> ALLOWED_TEXT_DECORATION = ImmutableSet.of(
      "underline", "overline", "line-through");

  private static final Set<String> ALLOWED_UNICODE_BIDI = ImmutableSet.of(
      "inherit", "normal", "embed", "bidi-override");

  private static final Set<String> ALLOWED_DIRECTION = ImmutableSet.of(
      "inherit", "ltr", "rtl");

  private static final ImmutableMap<String, CssPropertyType>
      BY_CSS_PROPERTY_NAME = ImmutableMap.<String, CssPropertyType>builder()
      .put("font", CssPropertyType.FONT)
      .put("font-family", CssPropertyType.FACE)
      .put("font-size", CssPropertyType.SIZE)
      .put("color", CssPropertyType.COLOR)
      .put("text-align", CssPropertyType.ALIGN)
      .put("direction", CssPropertyType.DIRECTION)
      .put("font-weight", CssPropertyType.WEIGHT)
      .put("font-style", CssPropertyType.STYLE)
      .put("text-decoration", CssPropertyType.TEXT_DECORATION)
      .put("unicode-bidi", CssPropertyType.UNICODE_BIDI)
      .put("background", CssPropertyType.BACKGROUND_COLOR)
      .put("background-color", CssPropertyType.BACKGROUND_COLOR)
      .build();

  /**
   * Lossy conversion from CSS properties into the attributes of a
   * <code>&lt;font&gt;</code> tag that allows textual styling that affects
   * layout, but does not allow breaking out of a clipping region, absolute
   * positioning, image loading, tab index changes, or code execution.
   *
   * @return A list of alternating attribute names and values.
   */
  @VisibleForTesting
  static List<String> cssPropertiesToFontAttributes(String style) {

    // We walk over CSS tokens to extract salient bits.
    class StyleExtractor implements CssGrammar.PropertyHandler {
      CssPropertyType type = CssPropertyType.NONE;

      // Values that are not-whitelisted are put into font attributes to render
      // the innocuous.
      StringBuilder face, color, backgroundColor;
      String align;
      // These values are white-listed so we know they can't affect anything
      // other than font-face appearance, and layout.
      String cssSize, cssWeight, cssFontStyle, cssTextDecoration;
      // Bidi support styles.
      String cssDir, cssUnicodeBidi;

      public void url(String token) {
        // Ignore.
      }
      public void startProperty(String propertyName) {
        CssPropertyType type = BY_CSS_PROPERTY_NAME.get(propertyName);
        this.type = type != null ? type : CssPropertyType.NONE;
      }
      public void quotedString(String token) {
        switch (type) {
          case FONT: case FACE:
            if (face == null) { face = new StringBuilder(); }
            face.append(' ').append(CssGrammar.cssContent(token));
            break;
          default: break;
        }
      }

      public void quantity(String token) {
        switch (type) {
          case FONT:
          case SIZE:
            token = Strings.toLowerCase(token);
            if (ALLOWED_CSS_SIZE.matcher(token).matches()) {
              cssSize = token;
            }
            break;
          case FACE:
            if (face == null) { face = new StringBuilder(); }
            face.append(' ').append(token);
            break;
          case BACKGROUND_COLOR:
            if (backgroundColor == null) {
              backgroundColor = new StringBuilder();
            } else {
              backgroundColor.append(' ');
            }
            backgroundColor.append(token);
            break;
          case COLOR:
            if (color == null) {
              color = new StringBuilder();
            } else {
              color.append(' ');
            }
            color.append(token);
            break;
          case WEIGHT:
            if (ALLOWED_CSS_WEIGHT.matcher(token).matches()) {
              cssWeight = token;
            }
            break;
          default: break;
        }
      }

      public void identifierOrHash(String token) {
        switch (type) {
          case SIZE:
            token = Strings.toLowerCase(token);
            if (ALLOWED_CSS_SIZE.matcher(token).matches()) {
              cssSize = token;
            }
            break;
          case WEIGHT:
            token = Strings.toLowerCase(token);
            if (ALLOWED_CSS_WEIGHT.matcher(token).matches()) {
              cssWeight = token;
            }
            break;
          case FACE:
            if (face == null) { face = new StringBuilder(); }
            face.append(' ').append(token);
            break;
          case FONT:
            token = Strings.toLowerCase(token);
            if (ALLOWED_CSS_WEIGHT.matcher(token).matches()) {
              cssWeight = token;
            } else if (ALLOWED_CSS_SIZE.matcher(token).matches()) {
              cssSize = token;
            } else if (ALLOWED_CSS_STYLE.contains(token)) {
              cssFontStyle = token;
            } else {
              if (face == null) { face = new StringBuilder(); }
              face.append(' ').append(token);
            }
            break;
          case BACKGROUND_COLOR:
            if (backgroundColor == null) {
              backgroundColor = new StringBuilder();
              backgroundColor.append(token);
            }
            break;
          case COLOR:
            if (color == null) {
              color = new StringBuilder();
              color.append(token);
            }
            break;
          case STYLE:
            token = Strings.toLowerCase(token);
            if (ALLOWED_CSS_STYLE.contains(token)) {
              cssFontStyle = token;
            }
            break;
          case ALIGN:
            align = token;
            break;
          case DIRECTION:
            token = Strings.toLowerCase(token);
            if (ALLOWED_DIRECTION.contains(token)) {
              cssDir = token;
            }
            break;
          case UNICODE_BIDI:
            token = Strings.toLowerCase(token);
            if (ALLOWED_UNICODE_BIDI.contains(token)) {
              cssUnicodeBidi = token;
            }
            break;
          case TEXT_DECORATION:
            token = Strings.toLowerCase(token);
            if (ALLOWED_TEXT_DECORATION.contains(token)) {
              cssTextDecoration = token;
            }
            break;
          default: break;
        }
      }

      public void punctuation(String token) {
        switch (type) {
          case FACE: case FONT:
            // Commas separate font-families since HTML fonts fall-back to
            // simpler forms based on the installed font-set.
            if (",".equals(token) && face != null) { face.append(','); }
            break;
          case BACKGROUND_COLOR:
            // Parentheses and commas in the rgb(...) color form.
            if (backgroundColor != null) { backgroundColor.append(token); }
            break;
          case COLOR:
            // Parentheses and commas in the rgb(...) color form.
            if (color != null) { color.append(token); }
            break;
          default: break;
        }
      }

      public void endProperty() {
        type = CssPropertyType.NONE;
      }

      @TCB
      List<String> toFontAttributes() {
        List<String> fontAttributes = Lists.newArrayList();
        if (face != null) {
          fontAttributes.add("face");
          fontAttributes.add(face.toString().trim());
        }
        if (align != null) {
          fontAttributes.add("align");
          fontAttributes.add(align);
        }
        ImmutableList<String> styleParts;
        {
          ImmutableList.Builder<String> b = ImmutableList.builder();
          if (cssWeight != null) {
            b.add("font-weight").add(cssWeight);
          }
          if (cssSize != null) {
            b.add("font-size").add(cssSize);
          }
          if (cssFontStyle != null) {
            b.add("font-style").add(cssFontStyle);
          }
          if (cssTextDecoration != null) {
            b.add("text-decoration").add(cssTextDecoration);
          }
          if (cssDir != null) {
            b.add("direction").add(cssDir);
          }
          if (cssUnicodeBidi != null) {
            b.add("unicode-bidi").add(cssUnicodeBidi);
          }
          if (backgroundColor != null) {
            String safeColor = sanitizeColor(backgroundColor.toString());
            if (safeColor != null) {
              b.add("background-color").add(safeColor);
            }
          }
          if (color != null) {
            String safeColor = sanitizeColor(color.toString());
            if (safeColor != null) {
              b.add("color").add(safeColor);
            }
          }
          styleParts = b.build();
        }
        if (!styleParts.isEmpty()) {
          StringBuilder cssProperties = new StringBuilder();
          boolean isPropertyName = true;
          for (String stylePart : styleParts) {
            cssProperties.append(stylePart).append(isPropertyName ? ':' : ';');
            isPropertyName = !isPropertyName;
          }
          int len = cssProperties.length();
          if (len != 0 && cssProperties.charAt(len - 1) == ';') {
            cssProperties.setLength(len - 1);
          }
          fontAttributes.add("style");
          fontAttributes.add(cssProperties.toString());
        }

        return fontAttributes;
      }
    }


    StyleExtractor extractor = new StyleExtractor();
    CssGrammar.asPropertyGroup(style, extractor);
    return extractor.toFontAttributes();
  }

  /**
   * Converts the various CSS syntactic forms for colors to a hex value or null.
   * If the input is not a valid CSS color expression, then this method either
   * returns null or returns a valid CSS hash color but the particular hash
   * color is not well specified (besides being deterministic).
   */
  static String sanitizeColor(String s) {
    if (s.length() == 0) { return null; }
    s = Strings.toLowerCase(s);
    String hex = COLOR_TABLE.get(s);
    if (hex != null) { return hex; }
    int n = s.length();
    if (s.charAt(0) == '#') {
      if (n != 4 && n != 7) { return null; }
      for (int i = 1; i < n; ++i) {
        char ch = s.charAt(i);
        if (!(('0' <= ch && ch <= '9') || ('a' <= ch && ch <= 'f'))) {
          return null;
        }
      }
      return s;
    }
    // Handle rgb and rgba
    if (!s.startsWith("rgb")) { return null; }
    StringBuilder sb = new StringBuilder(7);
    sb.append('#');
    if (translateDecimalOrPctByteToHex(
            s, translateDecimalOrPctByteToHex(
                s, translateDecimalOrPctByteToHex(s, 3, sb), sb), sb) == -1) {
      return null;
    }
    // #aabbcc -> #abc
    if (sb.charAt(1) == sb.charAt(2) && sb.charAt(3) == sb.charAt(4)
        && sb.charAt(5) == sb.charAt(6)) {
      sb.setCharAt(2, sb.charAt(3));
      sb.setCharAt(3, sb.charAt(5));
      sb.setLength(4);
    }
    return sb.toString();
  }

  private static boolean isDecimalDigit(char ch) {
    return '0' <= ch && ch <= '9';
  }

  /**
   * Looks for a decimal number in the range 0-255 or a percentage into a
   * hex pair written to out.  Returns the index after the number.
   */
  private static int translateDecimalOrPctByteToHex(
      String s, int i, StringBuilder out) {
    if (i == -1) { return -1; }
    int n = s.length();
    for (; i < n; ++i) {
      char ch = s.charAt(i);
      // Look for the first digit.
      if (isDecimalDigit(ch) || ch == '.') {
        int value;
        if (ch != '.') {
          value = ch - '0';
          // Reduce the run of digits to a decimal number.
          while (++i < n) {
            ch = s.charAt(i);
            if (isDecimalDigit(ch)) {
              value = value * 10 + (ch - '0');
            } else {
              break;
            }
          }
        } else {
          value = 0;
        }
        float fraction = 0;
        if (s.charAt(i) == '.') {
          int numerator = 0;
          int denominator = 1;
          // Consume any decimal portion.
          // TODO: Maybe incorporate into value.
          while (++i < n) {
            ch = s.charAt(i);
            if (!isDecimalDigit(ch)) { break; }
            numerator = numerator * 10 + (ch - '0');
            denominator *= 10;
          }
          fraction = ((float) numerator) / denominator;
        }
        // Convert the decimal number to a percentage if appropriate.
        if (i < n && s.charAt(i) == '%') {
          // TODO: is this the right rounding mode?
          value = (int) Math.round((value + fraction) * 2.55);
          ++i;
        } else if (value < 0xff && fraction > 0.5) {
          ++value;
        }
        if (0 <= value && value <= 0xff) {
          out.append("0123456789abcdef".charAt(value >>> 4))
              .append("0123456789abcdef".charAt(value & 0xf));
          return i;
        }
        return -1;
      }
    }
    return -1;
  }

  /** Maps CSS3 color keywords to unambiguous hash values. */
  private static final ImmutableMap<String, String> COLOR_TABLE
      = ImmutableMap.<String, String>builder()
      .put("aliceblue", "#f0f8ff")
      .put("antiquewhite", "#faebd7")
      .put("aqua", "#0ff")
      .put("aquamarine", "#7fffd4")
      .put("azure", "#f0ffff")
      .put("beige", "#f5f5dc")
      .put("bisque", "#ffe4c4")
      .put("black", "#000")
      .put("blanchedalmond", "#ffebcd")
      .put("blue", "#00f")
      .put("blueviolet", "#8a2be2")
      .put("brown", "#a52a2a")
      .put("burlywood", "#deb887")
      .put("cadetblue", "#5f9ea0")
      .put("chartreuse", "#7fff00")
      .put("chocolate", "#d2691e")
      .put("coral", "#ff7f50")
      .put("cornflowerblue", "#6495ed")
      .put("cornsilk", "#fff8dc")
      .put("crimson", "#dc143c")
      .put("cyan", "#0ff")
      .put("darkblue", "#00008b")
      .put("darkcyan", "#008b8b")
      .put("darkgoldenrod", "#b8860b")
      .put("darkgray", "#a9a9a9")
      .put("darkgreen", "#006400")
      .put("darkgrey", "#a9a9a9")
      .put("darkkhaki", "#bdb76b")
      .put("darkmagenta", "#8b008b")
      .put("darkolivegreen", "#556b2f")
      .put("darkorange", "#ff8c00")
      .put("darkorchid", "#9932cc")
      .put("darkred", "#8b0000")
      .put("darksalmon", "#e9967a")
      .put("darkseagreen", "#8fbc8f")
      .put("darkslateblue", "#483d8b")
      .put("darkslategray", "#2f4f4f")
      .put("darkslategrey", "#2f4f4f")
      .put("darkturquoise", "#00ced1")
      .put("darkviolet", "#9400d3")
      .put("deeppink", "#ff1493")
      .put("deepskyblue", "#00bfff")
      .put("dimgray", "#696969")
      .put("dimgrey", "#696969")
      .put("dodgerblue", "#1e90ff")
      .put("firebrick", "#b22222")
      .put("floralwhite", "#fffaf0")
      .put("forestgreen", "#228b22")
      .put("fuchsia", "#f0f")
      .put("gainsboro", "#dcdcdc")
      .put("ghostwhite", "#f8f8ff")
      .put("gold", "#ffd700")
      .put("goldenrod", "#daa520")
      .put("gray", "#808080")
      .put("green", "#008000")
      .put("greenyellow", "#adff2f")
      .put("grey", "#808080")
      .put("honeydew", "#f0fff0")
      .put("hotpink", "#ff69b4")
      .put("indianred", "#cd5c5c")
      .put("indigo", "#4b0082")
      .put("ivory", "#fffff0")
      .put("khaki", "#f0e68c")
      .put("lavender", "#e6e6fa")
      .put("lavenderblush", "#fff0f5")
      .put("lawngreen", "#7cfc00")
      .put("lemonchiffon", "#fffacd")
      .put("lightblue", "#add8e6")
      .put("lightcoral", "#f08080")
      .put("lightcyan", "#e0ffff")
      .put("lightgoldenrodyellow", "#fafad2")
      .put("lightgray", "#d3d3d3")
      .put("lightgreen", "#90ee90")
      .put("lightgrey", "#d3d3d3")
      .put("lightpink", "#ffb6c1")
      .put("lightsalmon", "#ffa07a")
      .put("lightseagreen", "#20b2aa")
      .put("lightskyblue", "#87cefa")
      .put("lightslategray", "#789")
      .put("lightslategrey", "#789")
      .put("lightsteelblue", "#b0c4de")
      .put("lightyellow", "#ffffe0")
      .put("lime", "#0f0")
      .put("limegreen", "#32cd32")
      .put("linen", "#faf0e6")
      .put("magenta", "#f0f")
      .put("maroon", "#800000")
      .put("mediumaquamarine", "#66cdaa")
      .put("mediumblue", "#0000cd")
      .put("mediumorchid", "#ba55d3")
      .put("mediumpurple", "#9370db")
      .put("mediumseagreen", "#3cb371")
      .put("mediumslateblue", "#7b68ee")
      .put("mediumspringgreen", "#00fa9a")
      .put("mediumturquoise", "#48d1cc")
      .put("mediumvioletred", "#c71585")
      .put("midnightblue", "#191970")
      .put("mintcream", "#f5fffa")
      .put("mistyrose", "#ffe4e1")
      .put("moccasin", "#ffe4b5")
      .put("navajowhite", "#ffdead")
      .put("navy", "#000080")
      .put("oldlace", "#fdf5e6")
      .put("olive", "#808000")
      .put("olivedrab", "#6b8e23")
      .put("orange", "#ffa500")
      .put("orangered", "#ff4500")
      .put("orchid", "#da70d6")
      .put("palegoldenrod", "#eee8aa")
      .put("palegreen", "#98fb98")
      .put("paleturquoise", "#afeeee")
      .put("palevioletred", "#db7093")
      .put("papayawhip", "#ffefd5")
      .put("peachpuff", "#ffdab9")
      .put("peru", "#cd853f")
      .put("pink", "#ffc0cb")
      .put("plum", "#dda0dd")
      .put("powderblue", "#b0e0e6")
      .put("purple", "#800080")
      .put("red", "#f00")
      .put("rosybrown", "#bc8f8f")
      .put("royalblue", "#4169e1")
      .put("saddlebrown", "#8b4513")
      .put("salmon", "#fa8072")
      .put("sandybrown", "#f4a460")
      .put("seagreen", "#2e8b57")
      .put("seashell", "#fff5ee")
      .put("sienna", "#a0522d")
      .put("silver", "#c0c0c0")
      .put("skyblue", "#87ceeb")
      .put("slateblue", "#6a5acd")
      .put("slategray", "#708090")
      .put("slategrey", "#708090")
      .put("snow", "#fffafa")
      .put("springgreen", "#00ff7f")
      .put("steelblue", "#4682b4")
      .put("tan", "#d2b48c")
      .put("teal", "#008080")
      .put("thistle", "#d8bfd8")
      .put("tomato", "#ff6347")
      .put("turquoise", "#40e0d0")
      .put("violet", "#ee82ee")
      .put("wheat", "#f5deb3")
      .put("white", "#fff")
      .put("whitesmoke", "#f5f5f5")
      .put("yellow", "#ff0")
      .put("yellowgreen", "#9acd32")
      .build();
}
