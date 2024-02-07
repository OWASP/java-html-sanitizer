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

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import javax.annotation.Nullable;

/** Describes the kinds of tokens a CSS property's value can safely contain. */
@TCB
public final class CssSchema {

  /**
   * Describes how CSS interprets tokens after the ":" for a property.
   * For example, if the property name "color" maps to this, then it
   * should record that '#' literals are innocuous colors, and that functions
   * like "rgb", "rgba", "hsl", etc. are allowed functions.
   */
  public static final class Property {
    /** A bitfield of BIT_* constants describing groups of allowed tokens. */
    final int bits;
    /** Specific allowed values. */
	final Set<String> literals;
    /**
     * Maps lower-case function tokens to the schema key for their parameters.
     */
	final Map<String, String> fnKeys;

    /**
     * @param bits A bitfield of BIT_* constants describing groups of allowed tokens.
     * @param literals Specific allowed values.
     * @param fnKeys Maps lower-case function tokens to the schema key for their parameters.
     */
    public Property(
        int bits, Set<String> literals,
        Map<String, String> fnKeys) {
      this.bits = bits;
      this.literals = Set.copyOf(literals);
      this.fnKeys = Map.copyOf(fnKeys);
    }

    @Override
    public int hashCode() {
      final int prime = 31;
      int result = 1;
      result = prime * result + bits;
      result = prime * result + ((fnKeys == null) ? 0 : fnKeys.hashCode());
      result = prime * result + ((literals == null) ? 0 : literals.hashCode());
      return result;
    }

    @Override
    public boolean equals(Object obj) {
      if (this == obj) {
        return true;
      }
      if (obj == null) {
        return false;
      }
      if (getClass() != obj.getClass()) {
        return false;
      }
      Property other = (Property) obj;
      if (bits != other.bits) {
        return false;
      }
      if (fnKeys == null) {
        if (other.fnKeys != null) {
          return false;
        }
      } else if (!fnKeys.equals(other.fnKeys)) {
        return false;
      }
      if (literals == null) {
        if (other.literals != null) {
          return false;
        }
      } else if (!literals.equals(other.literals)) {
        return false;
      }
      return true;
    }
  }

  static final int BIT_QUANTITY = 1;
  static final int BIT_HASH_VALUE = 2;
  static final int BIT_NEGATIVE = 4;
  static final int BIT_STRING = 8;
  static final int BIT_URL = 16;
  static final int BIT_UNRESERVED_WORD = 64;
  static final int BIT_UNICODE_RANGE = 128;

  static final Property DISALLOWED = new Property(
      0, Collections.emptySet(), Collections.emptyMap());

  private final Map<String, Property> properties;

  private CssSchema(Map<String, Property> properties) {
    if (properties == null) { throw new NullPointerException(); }
    this.properties = properties;
  }

  /**
   * A schema that includes all and only the named properties.
   *
   * @param propertyNames a series of lower-case CSS property names that appear
   *    in the built-in CSS definitions.  It is an error to mention an unknown
   *    property name.  This class's {@code main} method will dump a list of
   *    known property names when run with zero arguments.
   */
  public static CssSchema withProperties(
      Iterable<? extends String> propertyNames) {
    Map<String, Property> propertiesBuilder =
        new HashMap<>();
    for (String propertyName : propertyNames) {
      Property prop = DEFINITIONS.get(propertyName);
      if (prop == null) { throw new IllegalArgumentException(propertyName); }
      propertiesBuilder.put(propertyName, prop);
    }
    return new CssSchema(Collections.unmodifiableMap(propertiesBuilder));
  }

  /**
   * A schema that includes all and only the named properties.
   *
   * @param properties maps lower-case CSS property names to property objects.
   */
  public static CssSchema withProperties(
      Map<? extends String, ? extends Property> properties) {
    Map<String, Property> propertyMapBuilder =
        new HashMap<>();
    // check that all fnKeys are defined in properties.
    for (Map.Entry<? extends String, ? extends Property> e : properties.entrySet()) {
      Property property = e.getValue();
      for (String fnKey : property.fnKeys.values()) {
        if (!properties.containsKey(fnKey)) {
          throw new IllegalArgumentException(
              "Property map is not self contained.  " + e.getValue()
              + " depends on undefined function key " + fnKey);
        }
      }
      propertyMapBuilder.put(e.getKey(), e.getValue());
    }
    return new CssSchema(Collections.unmodifiableMap(propertyMapBuilder));
  }

  /**
   * A schema that represents the union of the input schemas.
   *
   * @return A schema that allows all and only CSS properties that are allowed
   *    by at least one of the inputs.
   * @throws IllegalArgumentException if two schemas have properties with the
   *    same name, but different (per .equals) {@link Property} values.
   */
  public static CssSchema union(CssSchema... cssSchemas) {
    if (cssSchemas.length == 1) { return cssSchemas[0]; }
    Map<String, Property> propertyMapBuilder = new LinkedHashMap<>();
    for (CssSchema cssSchema : cssSchemas) {
      for (Map.Entry<String, Property> e : cssSchema.properties.entrySet()) {
        String name = e.getKey();
        Property newProp = e.getValue();
        if (Objects.isNull(name)) {
          throw new NullPointerException("An entry was returned with null key from cssSchema.properties");
        }
        if (Objects.isNull(newProp)) {
          throw new NullPointerException("An entry was returned with null value from cssSchema.properties");
        }
        Property oldProp = propertyMapBuilder.put(name, newProp);
        if (oldProp != null && !oldProp.equals(newProp)) {
          throw new IllegalArgumentException(
              "Duplicate irreconcilable definitions for " + name);
        }
      }
    }
    return new CssSchema(Collections.unmodifiableMap(propertyMapBuilder));
  }

  /**
   * The set of CSS properties allowed by this schema.
   *
   * @return an immutable set.
   */
  public Set<String> allowedProperties() {
    return properties.keySet();
  }

  /** The schema for the named property or function key. */
  Property forKey(String propertyName) {
    String propertyNameCanon = Strings.toLowerCase(propertyName);
    Property property = properties.get(propertyNameCanon);
    if (property != null) { return property; }
    int n = propertyNameCanon.length();
    if (n != 0 && propertyNameCanon.charAt(0) == '-') {
      String barePropertyNameCanon = stripVendorPrefix(propertyNameCanon);
      if (barePropertyNameCanon == null) { return DISALLOWED; }
      property = properties.get(barePropertyNameCanon);
      if (property != null) { return property; }
    }
    return DISALLOWED;
  }

  /** {@code "-moz-foo"} &rarr; {@code "foo"}. */
  private static @Nullable String stripVendorPrefix(String cssKeyword) {
    int prefixLen = 0;
    if (cssKeyword.length() >= 2) {
      switch (cssKeyword.charAt(1)) {
        case 'm':
          if (cssKeyword.startsWith("-ms-")) {
            prefixLen = 4;
          } else if (cssKeyword.startsWith("-moz-")) {
            prefixLen = 5;
          }
          break;
        case 'o':
          if (cssKeyword.startsWith("-o-")) { prefixLen = 3; }
          break;
        case 'w':
          if (cssKeyword.startsWith("-webkit-")) { prefixLen = 8; }
          break;
        default: break;
      }
    }
    return prefixLen == 0 ? null : cssKeyword.substring(prefixLen);
  }

  /** Maps lower-cased CSS property names to information about them. */
  static final Map<String, Property> DEFINITIONS;
  static {
    Map<String, String> zeroFns = Collections.emptyMap();
    Map<String, Property> builder = new HashMap<>();
    Set<String> mozBorderRadiusLiterals0 = Set.of("/");
    Set<String> mozOpacityLiterals0 = Set.of("inherit");
    Set<String> mozOutlineLiterals0 = Set.of(
        "aliceblue", "antiquewhite", "aqua", "aquamarine", "azure", "beige",
        "bisque", "black", "blanchedalmond", "blue", "blueviolet", "brown",
        "burlywood", "cadetblue", "chartreuse", "chocolate", "coral",
        "cornflowerblue", "cornsilk", "crimson", "cyan", "darkblue", "darkcyan",
        "darkgoldenrod", "darkgray", "darkgreen", "darkkhaki", "darkmagenta",
        "darkolivegreen", "darkorange", "darkorchid", "darkred", "darksalmon",
        "darkseagreen", "darkslateblue", "darkslategray", "darkturquoise",
        "darkviolet", "deeppink", "deepskyblue", "dimgray", "dodgerblue",
        "firebrick", "floralwhite", "forestgreen", "fuchsia", "gainsboro",
        "ghostwhite", "gold", "goldenrod", "gray", "green", "greenyellow",
        "honeydew", "hotpink", "indianred", "indigo", "ivory", "khaki",
        "lavender", "lavenderblush", "lawngreen", "lemonchiffon", "lightblue",
        "lightcoral", "lightcyan", "lightgoldenrodyellow", "lightgreen",
        "lightgrey", "lightpink", "lightsalmon", "lightseagreen",
        "lightskyblue", "lightslategray", "lightsteelblue", "lightyellow",
        "lime", "limegreen", "linen", "magenta", "maroon", "mediumaquamarine",
        "mediumblue", "mediumorchid", "mediumpurple", "mediumseagreen",
        "mediumslateblue", "mediumspringgreen", "mediumturquoise",
        "mediumvioletred", "midnightblue", "mintcream", "mistyrose",
        "moccasin", "navajowhite", "navy", "oldlace", "olive", "olivedrab",
        "orange", "orangered", "orchid", "palegoldenrod", "palegreen",
        "paleturquoise", "palevioletred", "papayawhip", "peachpuff", "peru",
        "pink", "plum", "powderblue", "purple", "red", "rosybrown", "royalblue",
        "saddlebrown", "salmon", "sandybrown", "seagreen", "seashell", "sienna",
        "silver", "skyblue", "slateblue", "slategray", "snow", "springgreen",
        "steelblue", "tan", "teal", "thistle", "tomato", "turquoise", "violet",
        "wheat", "white", "whitesmoke", "yellow", "yellowgreen");
    Set<String> mozOutlineLiterals1 = Set.of(
        "dashed", "dotted", "double", "groove", "outset", "ridge", "solid");
    Set<String> mozOutlineLiterals2 = Set.of("thick", "thin");
    Set<String> mozOutlineLiterals3 = Set.of(
        "hidden", "inherit", "inset", "invert", "medium", "none");
    Map<String, String> mozOutlineFunctions =
      Map.<String, String>of(
        "rgb(", "rgb()", "rgba(", "rgba()",
        "hsl(", "hsl()", "hsla(", "hsla()");
    Set<String> mozOutlineColorLiterals0 =
      Set.of("inherit", "invert");
    Set<String> mozOutlineStyleLiterals0 =
      Set.of("hidden", "inherit", "inset", "none");
    Set<String> mozOutlineWidthLiterals0 =
      Set.of("inherit", "medium");
    Set<String> oTextOverflowLiterals0 =
      Set.of("clip", "ellipsis");
    Set<String> azimuthLiterals0 = Set.of(
        "behind", "center-left", "center-right", "far-left", "far-right",
        "left-side", "leftwards", "right-side", "rightwards");
    Set<String> azimuthLiterals1 = Set.of("left", "right");
    Set<String> azimuthLiterals2 =
      Set.of("center", "inherit");
    Set<String> backgroundLiterals0 = Set.of(
        "border-box", "contain", "content-box", "cover", "padding-box");
    Set<String> backgroundLiterals1 =
      Set.of("no-repeat", "repeat-x", "repeat-y", "round", "space");
    Set<String> backgroundLiterals2 = Set.of("bottom", "top");
    Set<String> backgroundLiterals3 = Set.of(
        ",", "/", "auto", "center", "fixed", "inherit", "local", "none",
        "repeat", "scroll", "transparent");
    Map<String, String> backgroundFunctions =
      Map.of(
      "image(", "image()",
      "linear-gradient(", "linear-gradient()",
      "radial-gradient(", "radial-gradient()",
      "repeating-linear-gradient(", "repeating-linear-gradient()",
      "repeating-radial-gradient(", "repeating-radial-gradient()",
      "rgb(", "rgb()", "rgba(", "rgba()",
      "hsl(", "hsl()", "hsla(", "hsla()");
    Set<String> backgroundAttachmentLiterals0 =
      Set.of(",", "fixed", "local", "scroll");
    Set<String> backgroundColorLiterals0 =
      Set.of("inherit", "transparent");
    Set<String> backgroundImageLiterals0 =
      Set.of(",", "none");
    Map<String, String> backgroundImageFunctions =
      Map.<String, String>of(
          "image(", "image()",
          "linear-gradient(", "linear-gradient()",
          "radial-gradient(", "radial-gradient()",
          "repeating-linear-gradient(", "repeating-linear-gradient()",
          "repeating-radial-gradient(", "repeating-radial-gradient()");
    Set<String> backgroundPositionLiterals0 = Set.of(
        ",", "center");
    Set<String> backgroundRepeatLiterals0 = Set.of(
        ",", "repeat");
    Set<String> borderLiterals0 = Set.of(
        "hidden", "inherit", "inset", "medium", "none", "transparent");
    Set<String> borderCollapseLiterals0 = Set.of(
        "collapse", "inherit", "separate");
    Set<String> bottomLiterals0 = Set.of("auto", "inherit");
    Set<String> boxShadowLiterals0 = Set.of(
        ",", "inset", "none");
    Set<String> clearLiterals0 = Set.of(
        "both", "inherit", "none");
    Map<String, String> clipFunctions =
        Map.<String, String>of("rect(", "rect()");
    Set<String> contentLiterals0 = Set.of("none", "normal");
    Set<String> cueLiterals0 = Set.of("inherit", "none");
    Set<String> cursorLiterals0 = Set.of(
        "all-scroll", "col-resize", "crosshair", "default", "e-resize",
        "hand", "help", "move", "n-resize", "ne-resize", "no-drop",
        "not-allowed", "nw-resize", "pointer", "progress", "row-resize",
        "s-resize", "se-resize", "sw-resize", "text", "vertical-text",
        "w-resize", "wait");
    Set<String> cursorLiterals1 = Set.of(
        ",", "auto", "inherit");
    Set<String> directionLiterals0 = Set.of("ltr", "rtl");
    Set<String> displayLiterals0 = Set.of(
        "-moz-inline-box", "-moz-inline-stack", "block", "inline",
        "inline-block", "inline-table", "list-item", "run-in", "table",
        "table-caption", "table-cell", "table-column", "table-column-group",
        "table-footer-group", "table-header-group", "table-row",
        "table-row-group");
    Set<String> elevationLiterals0 = Set.of(
        "above", "below", "higher", "level", "lower");
    Set<String> emptyCellsLiterals0 = Set.of("hide", "show");
    //Map<String, String> filterFunctions =
    //  Map.<String, String>of("alpha(", "alpha()");
    Set<String> fontLiterals0 = Set.of(
        "100", "200", "300", "400", "500", "600", "700", "800", "900", "bold",
        "bolder", "lighter");
    Set<String> fontLiterals1 = Set.of(
        "large", "larger", "small", "smaller", "x-large", "x-small",
        "xx-large", "xx-small", "xxx-large", "medium");
    Set<String> fontLiterals2 = Set.of(
        "caption", "icon", "menu", "message-box", "small-caption",
        "status-bar");
    Set<String> fontLiterals3 = Set.of(
        "cursive", "fantasy", "monospace", "sans-serif", "serif");
    Set<String> fontLiterals4 = Set.of("italic", "oblique");
    Set<String> fontLiterals5 = Set.of(
        ",", "/", "inherit", "medium", "normal", "small-caps");
    Set<String> fontFamilyLiterals0 = Set.of(",", "inherit");
    Set<String> fontStretchLiterals0 = Set.of(
        "condensed", "expanded", "extra-condensed", "extra-expanded",
        "narrower", "semi-condensed", "semi-expanded", "ultra-condensed",
        "ultra-expanded", "wider");
    Set<String> fontStretchLiterals1 = Set.of("normal");
    Set<String> fontStyleLiterals0 = Set.of(
        "inherit", "normal");
    Set<String> fontVariantLiterals0 = Set.of(
        "inherit", "normal", "small-caps");
    Set<String> listStyleLiterals0 = Set.of(
        "armenian", "cjk-decimal", "decimal", "decimal-leading-zero", "disc",
        "disclosure-closed", "disclosure-open", "ethiopic-numeric", "georgian",
        "hebrew", "hiragana", "hiragana-iroha", "japanese-formal",
        "japanese-informal", "katakana", "katakana-iroha",
        "korean-hangul-formal", "korean-hanja-formal",
        "korean-hanja-informal", "lower-alpha", "lower-greek", "lower-latin",
        "lower-roman", "simp-chinese-formal", "simp-chinese-informal",
        "square", "trad-chinese-formal", "trad-chinese-informal",
        "upper-alpha", "upper-latin", "upper-roman");
    Set<String> listStyleLiterals1 = Set.of(
        "inside", "outside");
    Set<String> listStyleLiterals2 = Set.of(
        "circle", "inherit", "none");
    Set<String> maxHeightLiterals0 = Set.of(
        "auto", "inherit", "none");
    Set<String> overflowLiterals0 = Set.of(
        "auto", "hidden", "inherit", "scroll", "visible");
    Set<String> overflowWrapLiterals0 = Set.of(
        "normal", "break-word", "anywhere", "inherit");
    Set<String> overflowXLiterals0 = Set.of(
        "no-content", "no-display");
    Set<String> overflowXLiterals1 = Set.of(
        "auto", "hidden", "scroll", "visible");
    Set<String> pageBreakAfterLiterals0 = Set.of(
        "always", "auto", "avoid", "inherit");
    Set<String> pageBreakInsideLiterals0 = Set.of(
        "auto", "avoid", "inherit");
    Set<String> pitchLiterals0 = Set.of(
        "high", "low", "x-high", "x-low");
    Set<String> playDuringLiterals0 = Set.of(
        "auto", "inherit", "mix", "none", "repeat");
    Set<String> positionLiterals0 = Set.of(
        "absolute", "relative", "static");
    Set<String> speakLiterals0 = Set.of(
        "inherit", "none", "normal", "spell-out");
    Set<String> speakHeaderLiterals0 = Set.of(
        "always", "inherit", "once");
    Set<String> speakNumeralLiterals0 = Set.of(
        "continuous", "digits");
    Set<String> speakPunctuationLiterals0 = Set.of(
        "code", "inherit", "none");
    Set<String> speechRateLiterals0 = Set.of(
        "fast", "faster", "slow", "slower", "x-fast", "x-slow");
    Set<String> tableLayoutLiterals0 = Set.of(
        "auto", "fixed", "inherit");
    Set<String> textAlignLiterals0 = Set.of(
        "center", "inherit", "justify");
    Set<String> textDecorationLiterals0 = Set.of(
        "blink", "line-through", "overline", "underline");
    Set<String> textTransformLiterals0 = Set.of(
        "capitalize", "lowercase", "uppercase");
    Set<String> textWrapLiterals0 = Set.of(
        "suppress", "unrestricted");
    Set<String> unicodeBidiLiterals0 = Set.of(
        "bidi-override", "embed");
    Set<String> verticalAlignLiterals0 = Set.of(
        "baseline", "middle", "sub", "super", "text-bottom", "text-top");
    Set<String> visibilityLiterals0 = Set.of(
        "collapse", "hidden", "inherit", "visible");
    Set<String> voiceFamilyLiterals0 = Set.of(
        "child", "female", "male");
    Set<String> volumeLiterals0 = Set.of(
        "loud", "silent", "soft", "x-loud", "x-soft");
    Set<String> whiteSpaceLiterals0 = Set.of(
        "-moz-pre-wrap", "-o-pre-wrap", "-pre-wrap", "nowrap", "pre",
        "pre-line", "pre-wrap");
    Set<String> wordBreakLiterals0 = Set.of(
        "break-all", "break-word", "keep-all", "normal");
    Set<String> wordWrapLiterals0 = Set.of(
        "anywhere", "break-word", "normal");
    Set<String> rgb$FunLiterals0 = Set.of(",");
    Set<String> linearGradient$FunLiterals0 = Set.of(
        ",", "to");
    Set<String> radialGradient$FunLiterals0 = Set.of(
        "at", "closest-corner", "closest-side", "ellipse", "farthest-corner",
        "farthest-side");
    Set<String> radialGradient$FunLiterals1 = Set.of(
        ",", "center", "circle");
    Set<String> rect$FunLiterals0 = Set.of(",", "auto");
	//Set<String> alpha$FunLiterals0 = Set.of("=", "opacity");
    Property mozBorderRadius =
       new Property(5, mozBorderRadiusLiterals0, zeroFns);
    builder.put("-moz-border-radius", mozBorderRadius);
    Property mozBorderRadiusBottomleft =
       new Property(5, Set.<String>of(), zeroFns);
    builder.put("-moz-border-radius-bottomleft", mozBorderRadiusBottomleft);
    Property mozOpacity = new Property(1, mozOpacityLiterals0, zeroFns);
    builder.put("-moz-opacity", mozOpacity);
    @SuppressWarnings("unchecked")
    Property mozOutline = new Property(
        7,
        union(mozOutlineLiterals0, mozOutlineLiterals1, mozOutlineLiterals2,
              mozOutlineLiterals3),
        mozOutlineFunctions);
    builder.put("-moz-outline", mozOutline);
    @SuppressWarnings("unchecked")
    Property mozOutlineColor = new Property(
        2, union(mozOutlineColorLiterals0, mozOutlineLiterals0),
        mozOutlineFunctions);
    builder.put("-moz-outline-color", mozOutlineColor);
    @SuppressWarnings("unchecked")
    Property mozOutlineStyle = new Property(
        0, union(mozOutlineLiterals1, mozOutlineStyleLiterals0), zeroFns);
    builder.put("-moz-outline-style", mozOutlineStyle);
    @SuppressWarnings("unchecked")
    Property mozOutlineWidth = new Property(
        5, union(mozOutlineLiterals2, mozOutlineWidthLiterals0), zeroFns);
    builder.put("-moz-outline-width", mozOutlineWidth);
    Property oTextOverflow = new Property(0, oTextOverflowLiterals0, zeroFns);
    builder.put("-o-text-overflow", oTextOverflow);
    @SuppressWarnings("unchecked")
    Property azimuth = new Property(
        5, union(azimuthLiterals0, azimuthLiterals1, azimuthLiterals2),
        zeroFns);
    builder.put("azimuth", azimuth);
    @SuppressWarnings("unchecked")
    Property background = new Property(
        23,
        union(azimuthLiterals1, backgroundLiterals0, backgroundLiterals1,
              backgroundLiterals2, backgroundLiterals3, mozOutlineLiterals0),
        backgroundFunctions);
    builder.put("background", background);
    builder.put("background-attachment",
                new Property(0, backgroundAttachmentLiterals0, zeroFns));
    @SuppressWarnings("unchecked")
    Property backgroundColor = new Property(
        258, union(backgroundColorLiterals0, mozOutlineLiterals0),
        mozOutlineFunctions);
    builder.put("background-color", backgroundColor);
    builder.put("background-image",
                new Property(16, backgroundImageLiterals0,
                             backgroundImageFunctions));
    @SuppressWarnings("unchecked")
    Property backgroundPosition = new Property(
        5,
        union(azimuthLiterals1, backgroundLiterals2,
              backgroundPositionLiterals0),
        zeroFns);
    builder.put("background-position", backgroundPosition);
    @SuppressWarnings("unchecked")
    Property backgroundRepeat = new Property(
        0, union(backgroundLiterals1, backgroundRepeatLiterals0), zeroFns);
    builder.put("background-repeat", backgroundRepeat);
    @SuppressWarnings("unchecked")
    Property border = new Property(
        7,
        union(borderLiterals0, mozOutlineLiterals0, mozOutlineLiterals1,
              mozOutlineLiterals2),
        mozOutlineFunctions);
    builder.put("border", border);
    @SuppressWarnings("unchecked")
    Property borderBottomColor = new Property(
        2, union(backgroundColorLiterals0, mozOutlineLiterals0),
        mozOutlineFunctions);
    builder.put("border-bottom-color", borderBottomColor);
    builder.put("border-collapse",
                new Property(0, borderCollapseLiterals0, zeroFns));
    Property borderSpacing = new Property(5, mozOpacityLiterals0, zeroFns);
    builder.put("border-spacing", borderSpacing);
    Property bottom = new Property(5, bottomLiterals0, zeroFns);
    builder.put("bottom", bottom);
    @SuppressWarnings("unchecked")
    Property boxShadow = new Property(
        7, union(boxShadowLiterals0, mozOutlineLiterals0), mozOutlineFunctions);
    builder.put("box-shadow", boxShadow);
    @SuppressWarnings("unchecked")
    Property captionSide = new Property(
        0, union(backgroundLiterals2, mozOpacityLiterals0), zeroFns);
    builder.put("caption-side", captionSide);
    @SuppressWarnings("unchecked")
    Property clear = new Property(
        0, union(azimuthLiterals1, clearLiterals0), zeroFns);
    builder.put("clear", clear);
    builder.put("clip", new Property(0, bottomLiterals0, clipFunctions));
    @SuppressWarnings("unchecked")
    Property color = new Property(
        258, union(mozOpacityLiterals0, mozOutlineLiterals0),
        mozOutlineFunctions);
    builder.put("color", color);
    builder.put("content", new Property(8, contentLiterals0, zeroFns));
    Property cue = new Property(16, cueLiterals0, zeroFns);
    builder.put("cue", cue);
    @SuppressWarnings("unchecked")
    Property cursor = new Property(
        272, union(cursorLiterals0, cursorLiterals1), zeroFns);
    builder.put("cursor", cursor);
    @SuppressWarnings("unchecked")
    Property direction = new Property(
        0, union(directionLiterals0, mozOpacityLiterals0), zeroFns);
    builder.put("direction", direction);
    @SuppressWarnings("unchecked")
    Property display = new Property(
        0, union(cueLiterals0, displayLiterals0), zeroFns);
    builder.put("display", display);
    @SuppressWarnings("unchecked")
    Property elevation = new Property(
        5, union(elevationLiterals0, mozOpacityLiterals0), zeroFns);
    builder.put("elevation", elevation);
    @SuppressWarnings("unchecked")
    Property emptyCells = new Property(
        0, union(emptyCellsLiterals0, mozOpacityLiterals0), zeroFns);
    builder.put("empty-cells", emptyCells);
    //builder.put("filter",
    //            new Property(0, ImmutableSet.<String>of(), filterFunctions));
    @SuppressWarnings("unchecked")
    Property cssFloat = new Property(
        0, union(azimuthLiterals1, cueLiterals0), zeroFns);
    builder.put("float", cssFloat);
    @SuppressWarnings("unchecked")
    Property font = new Property(
        73,
        union(fontLiterals0, fontLiterals1, fontLiterals2, fontLiterals3,
              fontLiterals4, fontLiterals5),
        zeroFns);
    builder.put("font", font);
    @SuppressWarnings("unchecked")
    Property fontFamily = new Property(
        72, union(fontFamilyLiterals0, fontLiterals3), zeroFns);
    builder.put("font-family", fontFamily);
    @SuppressWarnings("unchecked")
    Property fontSize = new Property(
        1, union(fontLiterals1, mozOutlineWidthLiterals0), zeroFns);
    builder.put("font-size", fontSize);
    @SuppressWarnings("unchecked")
    Property fontStretch = new Property(
        0, union(fontStretchLiterals0, fontStretchLiterals1), zeroFns);
    builder.put("font-stretch", fontStretch);
    @SuppressWarnings("unchecked")
    Property fontStyle = new Property(
        0, union(fontLiterals4, fontStyleLiterals0), zeroFns);
    builder.put("font-style", fontStyle);
    builder.put("font-variant", new Property(
        0, fontVariantLiterals0, zeroFns));
    @SuppressWarnings("unchecked")
    Property fontWeight = new Property(
        0, union(fontLiterals0, fontStyleLiterals0), zeroFns);
    builder.put("font-weight", fontWeight);
    Property height = new Property(5, bottomLiterals0, zeroFns);
    builder.put("height", height);
    Property letterSpacing = new Property(5, fontStyleLiterals0, zeroFns);
    builder.put("letter-spacing", letterSpacing);
    builder.put("line-height", new Property(1, fontStyleLiterals0, zeroFns));
    @SuppressWarnings("unchecked")
    Property listStyle = new Property(
        16,
        union(listStyleLiterals0, listStyleLiterals1, listStyleLiterals2),
        backgroundImageFunctions);
    builder.put("list-style", listStyle);
    builder.put("list-style-image", new Property(
        16, cueLiterals0, backgroundImageFunctions));
    @SuppressWarnings("unchecked")
    Property listStylePosition = new Property(
        0, union(listStyleLiterals1, mozOpacityLiterals0), zeroFns);
    builder.put("list-style-position", listStylePosition);
    @SuppressWarnings("unchecked")
    Property listStyleType = new Property(
        0, union(listStyleLiterals0, listStyleLiterals2), zeroFns);
    builder.put("list-style-type", listStyleType);
    Property margin = new Property(1, bottomLiterals0, zeroFns);
    builder.put("margin", margin);
    Property maxHeight = new Property(1, maxHeightLiterals0, zeroFns);
    builder.put("max-height", maxHeight);
    Property opacity = new Property(1, mozOpacityLiterals0, zeroFns);
    builder.put("opacity", opacity);
    builder.put("overflow", new Property(0, overflowLiterals0, zeroFns));
    builder.put("overflow-wrap", new Property(0, overflowWrapLiterals0, zeroFns));
    @SuppressWarnings("unchecked")
    Property overflowX = new Property(
        0, union(overflowXLiterals0, overflowXLiterals1), zeroFns);
    builder.put("overflow-x", overflowX);
    Property padding = new Property(1, mozOpacityLiterals0, zeroFns);
    builder.put("padding", padding);
    @SuppressWarnings("unchecked")
    Property pageBreakAfter = new Property(
        0, union(azimuthLiterals1, pageBreakAfterLiterals0), zeroFns);
    builder.put("page-break-after", pageBreakAfter);
    builder.put("page-break-inside", new Property(
        0, pageBreakInsideLiterals0, zeroFns));
    @SuppressWarnings("unchecked")
    Property pitch = new Property(
        5, union(mozOutlineWidthLiterals0, pitchLiterals0), zeroFns);
    builder.put("pitch", pitch);
    builder.put("play-during", new Property(
        16, playDuringLiterals0, zeroFns));
    @SuppressWarnings("unchecked")
    Property position = new Property(
        0, union(mozOpacityLiterals0, positionLiterals0), zeroFns);
    builder.put("position", position);
    builder.put("quotes", new Property(8, cueLiterals0, zeroFns));
    builder.put("speak", new Property(0, speakLiterals0, zeroFns));
    builder.put("speak-header", new Property(
        0, speakHeaderLiterals0, zeroFns));
    @SuppressWarnings("unchecked")
    Property speakNumeral = new Property(
        0, union(mozOpacityLiterals0, speakNumeralLiterals0), zeroFns);
    builder.put("speak-numeral", speakNumeral);
    builder.put("speak-punctuation", new Property(
        0, speakPunctuationLiterals0, zeroFns));
    @SuppressWarnings("unchecked")
    Property speechRate = new Property(
        5, union(mozOutlineWidthLiterals0, speechRateLiterals0), zeroFns);
    builder.put("speech-rate", speechRate);
    builder.put("table-layout", new Property(
        0, tableLayoutLiterals0, zeroFns));
    @SuppressWarnings("unchecked")
    Property textAlign = new Property(
        0, union(azimuthLiterals1, textAlignLiterals0), zeroFns);
    builder.put("text-align", textAlign);
    @SuppressWarnings("unchecked")
    Property textDecoration = new Property(
        0, union(cueLiterals0, textDecorationLiterals0), zeroFns);
    builder.put("text-decoration", textDecoration);
    @SuppressWarnings("unchecked")
    Property textTransform = new Property(
        0, union(cueLiterals0, textTransformLiterals0), zeroFns);
    builder.put("text-transform", textTransform);
    @SuppressWarnings("unchecked")
    Property textWrap = new Property(
        0, union(contentLiterals0, textWrapLiterals0), zeroFns);
    builder.put("text-wrap", textWrap);
    @SuppressWarnings("unchecked")
    Property unicodeBidi = new Property(
        0, union(fontStyleLiterals0, unicodeBidiLiterals0), zeroFns);
    builder.put("unicode-bidi", unicodeBidi);
    @SuppressWarnings("unchecked")
    Property verticalAlign = new Property(
        5,
        union(backgroundLiterals2, mozOpacityLiterals0, verticalAlignLiterals0),
        zeroFns);
    builder.put("vertical-align", verticalAlign);
    builder.put("visibility", new Property(0, visibilityLiterals0, zeroFns));
    @SuppressWarnings("unchecked")
    Property voiceFamily = new Property(
        8, union(fontFamilyLiterals0, voiceFamilyLiterals0), zeroFns);
    builder.put("voice-family", voiceFamily);
    @SuppressWarnings("unchecked")
    Property volume = new Property(
        1, union(mozOutlineWidthLiterals0, volumeLiterals0), zeroFns);
    builder.put("volume", volume);
    @SuppressWarnings("unchecked")
    Property whiteSpace = new Property(
        0, union(fontStyleLiterals0, whiteSpaceLiterals0), zeroFns);
    builder.put("white-space", whiteSpace);
    builder.put("word-break", new Property(0, wordBreakLiterals0, zeroFns));
    builder.put("word-wrap", new Property(0, wordWrapLiterals0, zeroFns));
    builder.put("zoom", new Property(1, fontStretchLiterals1, zeroFns));
    Property rgb$Fun = new Property(1, rgb$FunLiterals0, zeroFns);
    builder.put("rgb()", rgb$Fun);
    builder.put("rgba()", rgb$Fun);
    builder.put("hsl()", rgb$Fun);
    builder.put("hsla()", rgb$Fun);
    @SuppressWarnings("unchecked")
    Property image$Fun = new Property(
        18, union(mozOutlineLiterals0, rgb$FunLiterals0), mozOutlineFunctions);
    builder.put("image()", image$Fun);
    @SuppressWarnings("unchecked")
    Property linearGradient$Fun = new Property(
        7,
        union(azimuthLiterals1, backgroundLiterals2,
              linearGradient$FunLiterals0, mozOutlineLiterals0),
        mozOutlineFunctions);
    builder.put("linear-gradient()", linearGradient$Fun);
    @SuppressWarnings("unchecked")
    Property radialGradient$Fun = new Property(
        7,
        union(azimuthLiterals1, backgroundLiterals2, mozOutlineLiterals0,
              radialGradient$FunLiterals0, radialGradient$FunLiterals1),
        mozOutlineFunctions);
    builder.put("radial-gradient()", radialGradient$Fun);
    builder.put("rect()", new Property(5, rect$FunLiterals0, zeroFns));
    //builder.put("alpha()", new Property(1, alpha$FunLiterals0, zeroFns));
    builder.put("-moz-border-radius-bottomright", mozBorderRadiusBottomleft);
    builder.put("-moz-border-radius-topleft", mozBorderRadiusBottomleft);
    builder.put("-moz-border-radius-topright", mozBorderRadiusBottomleft);
    builder.put("-moz-box-shadow", boxShadow);
    builder.put("-webkit-border-bottom-left-radius", mozBorderRadiusBottomleft);
    builder.put("-webkit-border-bottom-right-radius",
                mozBorderRadiusBottomleft);
    builder.put("-webkit-border-radius", mozBorderRadius);
    builder.put("-webkit-border-radius-bottom-left", mozBorderRadiusBottomleft);
    builder.put("-webkit-border-radius-bottom-right",
                mozBorderRadiusBottomleft);
    builder.put("-webkit-border-radius-top-left", mozBorderRadiusBottomleft);
    builder.put("-webkit-border-radius-top-right", mozBorderRadiusBottomleft);
    builder.put("-webkit-border-top-left-radius", mozBorderRadiusBottomleft);
    builder.put("-webkit-border-top-right-radius", mozBorderRadiusBottomleft);
    builder.put("-webkit-box-shadow", boxShadow);
    builder.put("border-bottom", border);
    builder.put("border-bottom-left-radius", mozBorderRadiusBottomleft);
    builder.put("border-bottom-right-radius", mozBorderRadiusBottomleft);
    builder.put("border-bottom-style", mozOutlineStyle);
    builder.put("border-bottom-width", mozOutlineWidth);
    builder.put("border-color", borderBottomColor);
    builder.put("border-left", border);
    builder.put("border-left-color", borderBottomColor);
    builder.put("border-left-style", mozOutlineStyle);
    builder.put("border-left-width", mozOutlineWidth);
    builder.put("border-radius", mozBorderRadius);
    builder.put("border-right", border);
    builder.put("border-right-color", borderBottomColor);
    builder.put("border-right-style", mozOutlineStyle);
    builder.put("border-right-width", mozOutlineWidth);
    builder.put("border-style", mozOutlineStyle);
    builder.put("border-top", border);
    builder.put("border-top-color", borderBottomColor);
    builder.put("border-top-left-radius", mozBorderRadiusBottomleft);
    builder.put("border-top-right-radius", mozBorderRadiusBottomleft);
    builder.put("border-top-style", mozOutlineStyle);
    builder.put("border-top-width", mozOutlineWidth);
    builder.put("border-width", mozOutlineWidth);
    builder.put("cue-after", cue);
    builder.put("cue-before", cue);
    builder.put("left", height);
    builder.put("margin-bottom", margin);
    builder.put("margin-left", margin);
    builder.put("margin-right", margin);
    builder.put("margin-top", margin);
    builder.put("max-width", maxHeight);
    builder.put("min-height", margin);
    builder.put("min-width", margin);
    builder.put("outline", mozOutline);
    builder.put("outline-color", mozOutlineColor);
    builder.put("outline-style", mozOutlineStyle);
    builder.put("outline-width", mozOutlineWidth);
    builder.put("overflow-y", overflowX);
    builder.put("padding-bottom", padding);
    builder.put("padding-left", padding);
    builder.put("padding-right", padding);
    builder.put("padding-top", padding);
    builder.put("page-break-before", pageBreakAfter);
    builder.put("pause", borderSpacing);
    builder.put("pause-after", borderSpacing);
    builder.put("pause-before", borderSpacing);
    builder.put("pitch-range", borderSpacing);
    builder.put("richness", borderSpacing);
    builder.put("right", height);
    builder.put("stress", borderSpacing);
    builder.put("text-indent", borderSpacing);
    builder.put("text-overflow", oTextOverflow);
    builder.put("text-shadow", boxShadow);
    builder.put("top", height);
    builder.put("width", margin);
    builder.put("word-spacing", letterSpacing);
    builder.put("z-index", bottom);
    builder.put("repeating-linear-gradient()", linearGradient$Fun);
    builder.put("repeating-radial-gradient()", radialGradient$Fun);
    DEFINITIONS = Collections.unmodifiableMap(builder);
  }

  private static <T> Set<T> union(Set<T>... subsets) {
    Set<T> all = new HashSet<>();
    for (Set<T> subset : subsets) {
      all.addAll(subset);
    }
    return Collections.unmodifiableSet(all);
  }

  static final Set<String> DEFAULT_WHITELIST = Set.of(
      "-moz-border-radius",
      "-moz-border-radius-bottomleft",
      "-moz-border-radius-bottomright",
      "-moz-border-radius-topleft",
      "-moz-border-radius-topright",
      "-moz-box-shadow",
      "-moz-outline",
      "-moz-outline-color",
      "-moz-outline-style",
      "-moz-outline-width",
      "-o-text-overflow",
      "-webkit-border-bottom-left-radius",
      "-webkit-border-bottom-right-radius",
      "-webkit-border-radius",
      "-webkit-border-radius-bottom-left",
      "-webkit-border-radius-bottom-right",
      "-webkit-border-radius-top-left",
      "-webkit-border-radius-top-right",
      "-webkit-border-top-left-radius",
      "-webkit-border-top-right-radius",
      "-webkit-box-shadow",
      "azimuth",
      "background",
      "background-attachment",
      "background-color",
      "background-image",
      "background-position",
      "background-repeat",
      "border",
      "border-bottom",
      "border-bottom-color",
      "border-bottom-left-radius",
      "border-bottom-right-radius",
      "border-bottom-style",
      "border-bottom-width",
      "border-collapse",
      "border-color",
      "border-left",
      "border-left-color",
      "border-left-style",
      "border-left-width",
      "border-radius",
      "border-right",
      "border-right-color",
      "border-right-style",
      "border-right-width",
      "border-spacing",
      "border-style",
      "border-top",
      "border-top-color",
      "border-top-left-radius",
      "border-top-right-radius",
      "border-top-style",
      "border-top-width",
      "border-width",
      "box-shadow",
      "caption-side",
      "color",
      "cue",
      "cue-after",
      "cue-before",
      "direction",
      "elevation",
      "empty-cells",
      "font",
      "font-family",
      "font-size",
      "font-stretch",
      "font-style",
      "font-variant",
      "font-weight",
      "height",
      "image()",
      "letter-spacing",
      "line-height",
      "linear-gradient()",
      "list-style",
      "list-style-image",
      "list-style-position",
      "list-style-type",
      "margin",
      "margin-bottom",
      "margin-left",
      "margin-right",
      "margin-top",
      "max-height",
      "max-width",
      "min-height",
      "min-width",
      "outline",
      "outline-color",
      "outline-style",
      "outline-width",
      "padding",
      "padding-bottom",
      "padding-left",
      "padding-right",
      "padding-top",
      "pause",
      "pause-after",
      "pause-before",
      "pitch",
      "pitch-range",
      "quotes",
      "radial-gradient()",
      "rect()",
      "repeating-linear-gradient()",
      "repeating-radial-gradient()",
      "rgb()",
      "rgba()",
      "hsl()",
      "hsla()",
      "richness",
      "speak",
      "speak-header",
      "speak-numeral",
      "speak-punctuation",
      "speech-rate",
      "stress",
      "table-layout",
      "text-align",
      "text-decoration",
      "text-indent",
      "text-overflow",
      "text-shadow",
      "text-transform",
      "text-wrap",
      "unicode-bidi",
      "vertical-align",
      "voice-family",
      "volume",
      "white-space",
      "width",
      "word-spacing",
      "word-wrap"
  );

  /**
   * A schema that includes only those properties on the default schema
   * white-list.
   */
  public static final CssSchema DEFAULT =
      CssSchema.withProperties(DEFAULT_WHITELIST);

  /** Dumps key and literal list to stdout for easy examination. */
  public static void main(String... argv) {
    SortedSet<String> keys = new TreeSet<>();
    SortedSet<String> literals = new TreeSet<>();

    for (Map.Entry<String, Property> e : DEFINITIONS.entrySet()) {
      keys.add(e.getKey());
      literals.addAll(e.getValue().literals);
    }

    System.out.println(
        "# Below two blocks of tokens.\n"
            + "#\n"
        + "# First are all property names.\n"
        + "# Those followed by an asterisk (*) are in the default white-list.\n"
        + "#\n"
        + "# Second are the literal tokens recognized in any defined property\n"
        + "# value.\n"
        );
    for (String key : keys) {
      System.out.print(key);
      if (DEFAULT_WHITELIST.contains(key)) { System.out.print("*"); }
      System.out.println();
    }
    System.out.println();
    for (String literal : literals) {
      System.out.println(literal);
    }
  }
}
