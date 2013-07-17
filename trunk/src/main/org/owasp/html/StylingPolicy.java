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
import java.util.Set;
import java.util.regex.Pattern;

import javax.annotation.Nullable;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Lists;

/**
 * An HTML sanitizer policy that tries to preserve simple CSS by whitelisting
 * property values and splitting combo properties into multiple more specific
 * ones to reduce the attack-surface.
 */
@TCB
class StylingPolicy implements AttributePolicy {

  public @Nullable String apply(
      String elementName, String attributeName, String value) {
    return value != null ? sanitizeCssProperties(value) : null;
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
    HEIGHT,
    WIDTH,
    MARGIN,
    MARGIN_BOTTOM,
    MARGIN_LEFT,
    MARGIN_RIGHT,
    MARGIN_TOP,
    PADDING,
    PADDING_BOTTOM,
    PADDING_LEFT,
    PADDING_RIGHT,
    PADDING_TOP,
    DIMS,
    NONE,
    ;
  }

  private static final Pattern ALLOWED_CSS_SIZE = Pattern.compile(
      "medium|smaller|larger|(?:xx?-)(?:small|large)|[0-9]+(p[tx]|%)");

  private static final Pattern ALLOWED_CSS_WEIGHT = Pattern.compile(
      "normal|bold(?:er)?|lighter|[1-9]00");

  private static final Set<String> ALLOWED_FONT_STYLE = ImmutableSet.of(
      "italic", "oblique", "normal");

  private static final Set<String> ALLOWED_TEXT_ALIGN = ImmutableSet.of(
      "start", "end", "left", "right", "center", "justify");

  private static final Set<String> ALLOWED_TEXT_DECORATION = ImmutableSet.of(
      "underline", "overline", "line-through");

  private static final Set<String> ALLOWED_UNICODE_BIDI = ImmutableSet.of(
      "inherit", "normal", "embed", "bidi-override");

  private static final Set<String> ALLOWED_DIRECTION = ImmutableSet.of(
      "inherit", "ltr", "rtl");

  private static final Pattern NON_NEGATIVE_LENGTH = Pattern.compile(
      "(?:0|[1-9][0-9]*)([.][0-9]+)?(ex|[ecm]m|v[hw]|p[xct]|in|%)?");

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
      .put("height", CssPropertyType.HEIGHT)
      .put("width", CssPropertyType.WIDTH)
      .put("margin", CssPropertyType.MARGIN)
      .put("margin-top", CssPropertyType.MARGIN_TOP)
      .put("margin-left", CssPropertyType.MARGIN_LEFT)
      .put("margin-bottom", CssPropertyType.MARGIN_BOTTOM)
      .put("margin-right", CssPropertyType.MARGIN_RIGHT)
      .put("padding", CssPropertyType.PADDING)
      .put("padding-top", CssPropertyType.PADDING_TOP)
      .put("padding-left", CssPropertyType.PADDING_LEFT)
      .put("padding-bottom", CssPropertyType.PADDING_BOTTOM)
      .put("padding-right", CssPropertyType.PADDING_RIGHT)
      .build();

  /**
   * Serializes a CSS property group based on a series of name and value calls.
   */
  private static final class PropertyGroup {
    private final StringBuilder buf = new StringBuilder();
    private boolean inPropertyName = true;

    PropertyGroup name(String s) {
      assert inPropertyName;
      if (buf.length() != 0) { buf.append(';'); }
      buf.append(s);
      inPropertyName = false;
      return this;
    }

    PropertyGroup name(String s, String suffix) {
      assert inPropertyName;
      if (buf.length() != 0) { buf.append(';'); }
      buf.append(s).append(suffix);
      inPropertyName = false;
      return this;
    }

    PropertyGroup value(String s) {
      assert !inPropertyName;
      buf.append(':').append(s);
      inPropertyName = true;
      return this;
    }

    PropertyGroup value(String s0, String s1) {
      assert !inPropertyName;
      buf.append(':').append(s0).append(' ').append(s1);
      inPropertyName = true;
      return this;
    }

    PropertyGroup value(String s0, String s1, String s2) {
      assert !inPropertyName;
      buf.append(':').append(s0).append(' ').append(s1).append(' ').append(s2);
      inPropertyName = true;
      return this;
    }

    PropertyGroup value(String s0, String s1, String s2, String s3) {
      assert !inPropertyName;
      buf.append(':').append(s0).append(' ').append(s1)
         .append(' ').append(s2).append(' ').append(s3);
      inPropertyName = true;
      return this;
    }

    boolean isEmpty() { return buf.length() == 0; }

    @Override
    public String toString() {
      return buf.toString();
    }
  }

  /**
   * A group of CSS Length properties that define the boundaries of a
   * rectangular area.  The rectangle may be defined in terms of a delta to
   * an inner rectangle as in padding, margin, and border.
   * <p>
   * TODO: handle the keyword "auto" as a valid length.
   */
  private static final class Box {
    /** Safe CSS length quantities. */
    String bottom, left, right, top;
    /** Aggregates positional parameters as in {@code padding: 4px 2cm}. */
    private List<String> positional = null;

    /**
     * Another positional parameter whose meaning cannot be completely
     * determined until we see how many follow it.
     */
    void positional(String s) {
      if (positional == null) {
        positional = Lists.newArrayListWithCapacity(4);
      }
      positional.add(s);
    }

    /**
     * Called after all positional quantities have been seen to figure out
     * how they relate to the edges of a rectangle.
     */
    void contextualizePositionalQuantities() {
      if (positional != null) {
        String explicitTop = top,
          explicitRight = right,
          explicitLeft = left,
          explicitBottom = bottom;
        switch (positional.size()) {
          case 0:
            break;
          case 1:
            top = right = left = bottom = positional.get(0);
            break;
          case 2:
            top = bottom = positional.get(0);
            right = left = positional.get(1);
            break;
          case 3:
            top = positional.get(0);
            right = left = positional.get(1);
            bottom = positional.get(2);
            break;
          default:
            top = positional.get(0);
            right = positional.get(1);
            bottom = positional.get(2);
            left = positional.get(3);
            break;
        }
        positional = null;
        if (explicitTop != null) { top = explicitTop; }
        if (explicitRight != null) { top = explicitRight; }
        if (explicitBottom != null) { top = explicitBottom; }
        if (explicitLeft != null) { top = explicitLeft; }
      }
    }

    /**
     * Given a CSS property name, generates a box definition with as few
     * CSS properties as possible.
     */
    void toPropertyGroup(String basePropertyName, PropertyGroup out) {
      if (bottom != null && left != null && right != null && top != null) {
        if (left.equals(right)) {
          if (bottom.equals(top)) {
            if (bottom.equals(left)) {
              out.name(basePropertyName).value(bottom);
            } else {
              out.name(basePropertyName).value(bottom, left);
            }
          } else {
            out.name(basePropertyName).value(top, left, bottom);
          }
        } else {
          out.name(basePropertyName).value(top, right, bottom, left);
        }
      } else {
        if (top != null) {
          out.name(basePropertyName, "-top").value(top);
        }
        if (right != null) {
          out.name(basePropertyName, "-right").value(right);
        }
        if (bottom!= null) {
          out.name(basePropertyName, "-bottom").value(bottom);
        }
        if (left != null) {
          out.name(basePropertyName, "-left").value(left);
        }
      }
    }
  }

  /**
   * Lossy filtering of CSS properties that allows textual styling that affects
   * layout, but does not allow breaking out of a clipping region, absolute
   * positioning, image loading, tab index changes, or code execution.
   *
   * @return A sanitized version of the input.
   */
  @VisibleForTesting
  static String sanitizeCssProperties(String style) {

    // We walk over CSS tokens to extract salient bits.
    class StyleExtractor implements CssGrammar.PropertyHandler {
      CssPropertyType type = CssPropertyType.NONE;

      // Depth of fns that we have started but not finished.
      int fnDepth = 0;
      StringBuilder fn;
      // Values that are not-whitelisted are put into font attributes to render
      // the innocuous.
      List<String> faces;
      StringBuilder color, backgroundColor;
      String align;
      // These values are white-listed so we know they can't affect anything
      // other than font-face appearance, and layout.
      String cssSize, cssWeight, cssFontStyle, cssTextDecoration;
      // Bidi support styles.
      String cssDir, cssUnicodeBidi;
      // Bounding box styles.
      String height, width;
      Box paddings;
      Box margins;

      public void url(String token) {
        // Ignore.
      }

      public void startProperty(String propertyName) {
        CssPropertyType type = BY_CSS_PROPERTY_NAME.get(propertyName);
        this.type = type != null ? type : CssPropertyType.NONE;
      }

      public void quotedString(String token) {
        if (fn != null) {
          fn.append(token);
          return;
        }
        switch (type) {
          case FONT: case FACE:
            if (faces == null) { faces = Lists.newArrayList(); }
            faces.add(token);
            break;
          default: break;
        }
      }

      public void quantity(String token) {
        if (fn != null) {
          fn.append(token);
          return;
        }
        switch (type) {
          case FONT:
          case SIZE:
            token = Strings.toLowerCase(token);
            if (ALLOWED_CSS_SIZE.matcher(token).matches()) {
              cssSize = token;
            }
            break;
          case FACE:
            if (faces == null) { faces = Lists.newArrayList(); }
            faces.add(token);
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
          case WIDTH:
            if (NON_NEGATIVE_LENGTH.matcher(token).matches()) {
              width = token;
            }
            break;
          case HEIGHT:
            if (NON_NEGATIVE_LENGTH.matcher(token).matches()) {
              height = token;
            }
            break;
          case MARGIN:
            if (NON_NEGATIVE_LENGTH.matcher(token).matches()) {
              if (margins == null) { margins = new Box(); }
              margins.positional(token);
            }
            break;
          case MARGIN_LEFT:
            if (NON_NEGATIVE_LENGTH.matcher(token).matches()) {
              if (margins == null) { margins = new Box(); }
              margins.left = token;
            }
            break;
          case MARGIN_RIGHT:
            if (NON_NEGATIVE_LENGTH.matcher(token).matches()) {
              if (margins == null) { margins = new Box(); }
              margins.right = token;
            }
            break;
          case MARGIN_TOP:
            if (NON_NEGATIVE_LENGTH.matcher(token).matches()) {
              if (margins == null) { margins = new Box(); }
              margins.top = token;
            }
            break;
          case MARGIN_BOTTOM:
            if (NON_NEGATIVE_LENGTH.matcher(token).matches()) {
              if (margins == null) { margins = new Box(); }
              margins.bottom = token;
            }
            break;
          case PADDING:
            if (NON_NEGATIVE_LENGTH.matcher(token).matches()) {
              if (paddings == null) { paddings = new Box(); }
              paddings.positional(token);
            }
            break;
          case PADDING_LEFT:
            if (NON_NEGATIVE_LENGTH.matcher(token).matches()) {
              if (paddings == null) { paddings = new Box(); }
              paddings.left = token;
            }
            break;
          case PADDING_RIGHT:
            if (NON_NEGATIVE_LENGTH.matcher(token).matches()) {
              if (paddings == null) { paddings = new Box(); }
              paddings.right = token;
            }
            break;
          case PADDING_TOP:
            if (NON_NEGATIVE_LENGTH.matcher(token).matches()) {
              if (paddings == null) { paddings = new Box(); }
              paddings.top = token;
            }
            break;
          case PADDING_BOTTOM:
            if (NON_NEGATIVE_LENGTH.matcher(token).matches()) {
              if (paddings == null) { paddings = new Box(); }
              paddings.bottom = token;
            }
            break;
          default: break;
        }
      }

      public void identifier(String token) {
        if (fn != null) {
          fn.append(token);
          return;
        }
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
            if (faces == null) { faces = Lists.newArrayList(); }
            faces.add(token);
            break;
          case FONT:
            token = Strings.toLowerCase(token);
            if (ALLOWED_CSS_WEIGHT.matcher(token).matches()) {
              cssWeight = token;
            } else if (ALLOWED_CSS_SIZE.matcher(token).matches()) {
              cssSize = token;
            } else if (ALLOWED_FONT_STYLE.contains(token)) {
              cssFontStyle = token;
            } else {
              if (faces == null) { faces = Lists.newArrayList(); }
              faces.add(token);
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
            if (ALLOWED_FONT_STYLE.contains(token)) {
              cssFontStyle = token;
            }
            break;
          case ALIGN:
            token = Strings.toLowerCase(token);
            if (ALLOWED_TEXT_ALIGN.contains(token)) {
              align = token;
            }
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

      public void hash(String token) {
        if (fn != null) {
          fn.append(token);
          return;
        }
        switch (type) {
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
          default:
            break;
        }
      }

      public void punctuation(String token) {
        if (fn != null) {
          fn.append(token);
          return;
        }
        switch (type) {
          case FACE: case FONT:
            // Commas separate font-families since HTML fonts fall-back to
            // simpler forms based on the installed font-set.
            if (",".equals(token) && faces != null) { faces.add(","); }
            break;
          default: break;
        }
      }

      public void startFunction(String token) {
        if (fn == null) { fn = new StringBuilder(); }
        fn.append(token);
        ++fnDepth;
      }

      public void endFunction(String token) {
        fn.append(')');
        if (--fnDepth == 0) {
          StringBuilder fnContent = fn;
          fn = null;
          // Use rgb and rgba in color.
          switch (type) {
            case BACKGROUND_COLOR:
              if (backgroundColor == null) {
                backgroundColor = fnContent;
              }
              break;
            case COLOR:
              if (color == null) {
                color = fnContent;
              }
              break;
            default: break;
          }
        }
      }

      public void endProperty() {
        type = CssPropertyType.NONE;
      }

      @TCB
      String toCssProperties() {
        PropertyGroup pg = new PropertyGroup();
        String face = sanitizeFontFamilies(faces);
        if (face != null) {
          pg.name("font-family").value(face);
        }
        if (align != null) {
          pg.name("text-align").value(align);
        }
        if (cssWeight != null) {
          pg.name("font-weight").value(cssWeight);
        }
        if (cssSize != null) {
          pg.name("font-size").value(cssSize);
        }
        if (cssFontStyle != null) {
          pg.name("font-style").value(cssFontStyle);
        }
        if (cssTextDecoration != null) {
          pg.name("text-decoration").value(cssTextDecoration);
        }
        if (cssDir != null) {
          pg.name("direction").value(cssDir);
        }
        if (cssUnicodeBidi != null) {
          pg.name("unicode-bidi").value(cssUnicodeBidi);
        }
        if (backgroundColor != null) {
          String safeColor = sanitizeColor(backgroundColor.toString());
          if (safeColor != null) {
            pg.name("background-color").value(safeColor);
          }
        }
        if (color != null) {
          String safeColor = sanitizeColor(color.toString());
          if (safeColor != null) {
            pg.name("color").value(safeColor);
          }
        }
        if (height != null) {
          pg.name("height").value(height);
        }
        if (width != null) {
          pg.name("width").value(width);
        }
        if (margins != null) {
          margins.contextualizePositionalQuantities();
          margins.toPropertyGroup("margin", pg);
        }
        if (paddings != null) {
          paddings.contextualizePositionalQuantities();
          paddings.toPropertyGroup("padding", pg);
        }
        return pg.isEmpty() ? null : pg.toString();
      }
    }


    StyleExtractor extractor = new StyleExtractor();
    CssGrammar.parsePropertyGroup(style, extractor);
    return extractor.toCssProperties();
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

  static @Nullable String sanitizeFontFamilies(
      @Nullable List<String> families) {
    if (families == null) { return null; }
    StringBuilder css = new StringBuilder();
    int nFamilies = families.size();
    for (int i = 0; i < nFamilies; ++i) {
      String token = families.get(i);
      if (",".equals(token)) { continue; }
      int familyEnd = i + 1;
      while (familyEnd < nFamilies && !",".equals(families.get(familyEnd))) {
        ++familyEnd;
      }
      int cssFamilyStart = css.length();
      if (!sanitizeFontFamilyOnto(families.subList(i, familyEnd), css)) {
        css.setLength(cssFamilyStart);
      }
      i = familyEnd;
    }
    return css.length() == 0 ? null : css.toString();
  }

  private static boolean sanitizeFontFamilyOnto(
      List<String> tokens, StringBuilder out) {
    int n = tokens.size();
    if (n == 0) { return false; }
    if (out.length() != 0) { out.append(','); }
    if (n == 1) {
      String token = tokens.get(0);
      if (token.length() != 0
          && (token.charAt(0) == '"' || token.charAt(0) == '\'')) {
        token = CssGrammar.cssContent(token).trim();
        if (!isNonEmptyAsciiAlnumSpaceSeparated(token)) { return false; }
        out.append('"').append(token).append('"');
        return true;
      }
      token = Strings.toLowerCase(token);
      if (GENERIC_FONT_FAMILIES.contains(token)) {
        out.append(token);
        return true;
      }
    }
    // Quote space separated words so that they are not confused with user-agent
    // extensions like expression(...) or -webkit-small-control.
    out.append('"');
    for (int i = 0; i < n; ++i) {
      String token = tokens.get(i);
      if (!isNonEmptyAsciiAlnum(token)) { return false; }
      if (i != 0) { out.append(' '); }
      out.append(token);
    }
    out.append('"');
    return true;
  }

  // Intentionally excludes -webkit-small-control an similar user-agent
  // extensions since allowing skinning oF OS controls is a potential trusted
  // path violation.
  private static Set<String> GENERIC_FONT_FAMILIES = ImmutableSet.of(
      "serif", "sans-serif", "cursive", "fantasy", "monospace");

  static boolean isNonEmptyAsciiAlnumSpaceSeparated(String s) {
    int i = 0;
    int n = s.length();
    while (i < n && s.charAt(i) == ' ') { ++i; }
    while (n > i && s.charAt(n - 1) == ' ') { --n; }
    if (i == n) { return false; }
    while (i < n) {
      int e = i + 1;
      while (e < n && s.charAt(e) != ' ') {
        ++e;
      }
      if (!isNonEmptyAsciiAlnum(s.substring(i, e))) {
        return false;
      }
      i = e;
      while (i < n && s.charAt(i) == ' ') { ++i; }
    }
    return true;
  }

  private static final boolean[] ASCII_ALNUM = new boolean['z' + 1];
  static {
    for (int i = '0'; i <= '9'; ++i) { ASCII_ALNUM[i] = true; }
    for (int i = 'A'; i <= 'Z'; ++i) { ASCII_ALNUM[i] = true; }
    for (int i = 'a'; i <= 'z'; ++i) { ASCII_ALNUM[i] = true; }
  }

  private static boolean isNonEmptyAsciiAlnum(String s) {
    int n = s.length();
    for (int i = 0; i < n; ++i) {
      char ch = s.charAt(i);
      if (ch < ASCII_ALNUM.length && ASCII_ALNUM[ch]) {
        continue;
      } else {
        return false;
      }
    }
    return n != 0;
  }
}
