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

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;

/** Describes the kinds of tokens a CSS property's value can safely contain. */
final class CssSchema {
  /** A bitfield of the BIT_* constants describing groups of allowed tokens. */
  final int bits;
  /** Specific allowed values. */
  final ImmutableSet<String> literals;
  /** Maps lower-case function tokens to the schema key for their parameters. */
  final ImmutableMap<String, String> fnKeys;

  private CssSchema(
      int bits, ImmutableSet<String> literals,
      ImmutableMap<String, String> fnKeys) {
    this.bits = bits;
    this.literals = literals;
    this.fnKeys = fnKeys;
  }

  static final int BIT_QUANTITY = 1;
  static final int BIT_HASH_VALUE = 2;
  static final int BIT_NEGATIVE = 4;
  static final int BIT_STRING = 8;
  static final int BIT_URL = 16;
  static final int BIT_UNRESERVED_WORD = 64;
  static final int BIT_UNICODE_RANGE = 128;

  public static final CssSchema DISALLOWED = new CssSchema(
      0, ImmutableSet.<String>of(), ImmutableMap.<String, String>of());

  /** The schema for the named property or function key. */
  public static CssSchema forKey(String propertyName) {
    CssSchema schema = SCHEMA.get(Strings.toLowerCase(propertyName));
    return schema == null ? DISALLOWED : schema;
  }

  /** Maps lower-cased CSS property names to information about them. */
  private static final ImmutableMap<String, CssSchema> SCHEMA;
  static {
    ImmutableMap<String, String> zeroFns = ImmutableMap.of();
    ImmutableMap.Builder<String, CssSchema> builder
        = ImmutableMap.builder();
    ImmutableSet<String> mozBorderRadiusLiterals0 = ImmutableSet.of("/");
    ImmutableSet<String> mozOpacityLiterals0 = ImmutableSet.of("inherit");
    ImmutableSet<String> mozOutlineLiterals0 = ImmutableSet.of("aliceblue", "antiquewhite", "aqua", "aquamarine", "azure", "beige", "bisque", "black", "blanchedalmond", "blue", "blueviolet", "brown", "burlywood", "cadetblue", "chartreuse", "chocolate", "coral", "cornflowerblue", "cornsilk", "crimson", "cyan", "darkblue", "darkcyan", "darkgoldenrod", "darkgray", "darkgreen", "darkkhaki", "darkmagenta", "darkolivegreen", "darkorange", "darkorchid", "darkred", "darksalmon", "darkseagreen", "darkslateblue", "darkslategray", "darkturquoise", "darkviolet", "deeppink", "deepskyblue", "dimgray", "dodgerblue", "firebrick", "floralwhite", "forestgreen", "fuchsia", "gainsboro", "ghostwhite", "gold", "goldenrod", "gray", "green", "greenyellow", "honeydew", "hotpink", "indianred", "indigo", "ivory", "khaki", "lavender", "lavenderblush", "lawngreen", "lemonchiffon", "lightblue", "lightcoral", "lightcyan", "lightgoldenrodyellow", "lightgreen", "lightgrey", "lightpink", "lightsalmon", "lightseagreen", "lightskyblue", "lightslategray", "lightsteelblue", "lightyellow", "lime", "limegreen", "linen", "magenta", "maroon", "mediumaquamarine", "mediumblue", "mediumorchid", "mediumpurple", "mediumseagreen", "mediumslateblue", "mediumspringgreen", "mediumturquoise", "mediumvioletred", "midnightblue", "mintcream", "mistyrose", "moccasin", "navajowhite", "navy", "oldlace", "olive", "olivedrab", "orange", "orangered", "orchid", "palegoldenrod", "palegreen", "paleturquoise", "palevioletred", "papayawhip", "peachpuff", "peru", "pink", "plum", "powderblue", "purple", "red", "rosybrown", "royalblue", "saddlebrown", "salmon", "sandybrown", "seagreen", "seashell", "sienna", "silver", "skyblue", "slateblue", "slategray", "snow", "springgreen", "steelblue", "tan", "teal", "thistle", "tomato", "turquoise", "violet", "wheat", "white", "whitesmoke", "yellow", "yellowgreen");
    ImmutableSet<String> mozOutlineLiterals1 = ImmutableSet.of("dashed", "dotted", "double", "groove", "outset", "ridge", "solid");
    ImmutableSet<String> mozOutlineLiterals2 = ImmutableSet.of("thick", "thin");
    ImmutableSet<String> mozOutlineLiterals3 = ImmutableSet.of("hidden", "inherit", "inset", "invert", "medium", "none");
    ImmutableMap<String, String> mozOutlineFunctions = ImmutableMap.<String, String>of("rgb(", "rgb()", "rgba(", "rgba()");
    ImmutableSet<String> mozOutlineColorLiterals0 = ImmutableSet.of("inherit", "invert");
    ImmutableSet<String> mozOutlineStyleLiterals0 = ImmutableSet.of("hidden", "inherit", "inset", "none");
    ImmutableSet<String> mozOutlineWidthLiterals0 = ImmutableSet.of("inherit", "medium");
    ImmutableSet<String> oTextOverflowLiterals0 = ImmutableSet.of("clip", "ellipsis");
    ImmutableSet<String> azimuthLiterals0 = ImmutableSet.of("behind", "center-left", "center-right", "far-left", "far-right", "left-side", "leftwards", "right-side", "rightwards");
    ImmutableSet<String> azimuthLiterals1 = ImmutableSet.of("left", "right");
    ImmutableSet<String> azimuthLiterals2 = ImmutableSet.of("center", "inherit");
    ImmutableSet<String> backgroundLiterals0 = ImmutableSet.of("border-box", "contain", "content-box", "cover", "padding-box");
    ImmutableSet<String> backgroundLiterals1 = ImmutableSet.of("no-repeat", "repeat-x", "repeat-y", "round", "space");
    ImmutableSet<String> backgroundLiterals2 = ImmutableSet.of("bottom", "top");
    ImmutableSet<String> backgroundLiterals3 = ImmutableSet.of(",", "/", "auto", "center", "fixed", "inherit", "local", "none", "repeat", "scroll", "transparent");
    ImmutableMap<String, String> backgroundFunctions = ImmutableMap.<String, String>builder().put("image(", "image()").put("linear-gradient(", "linear-gradient()").put("radial-gradient(", "radial-gradient()").put("repeating-linear-gradient(", "repeating-linear-gradient()").put("repeating-radial-gradient(", "repeating-radial-gradient()").put("rgb(", "rgb()").put("rgba(", "rgba()").build();
    ImmutableSet<String> backgroundAttachmentLiterals0 = ImmutableSet.of(",", "fixed", "local", "scroll");
    ImmutableSet<String> backgroundColorLiterals0 = ImmutableSet.of("inherit", "transparent");
    ImmutableSet<String> backgroundImageLiterals0 = ImmutableSet.of(",", "none");
    ImmutableMap<String, String> backgroundImageFunctions = ImmutableMap.<String, String>of("image(", "image()", "linear-gradient(", "linear-gradient()", "radial-gradient(", "radial-gradient()", "repeating-linear-gradient(", "repeating-linear-gradient()", "repeating-radial-gradient(", "repeating-radial-gradient()");
    ImmutableSet<String> backgroundPositionLiterals0 = ImmutableSet.of(",", "center");
    ImmutableSet<String> backgroundRepeatLiterals0 = ImmutableSet.of(",", "repeat");
    ImmutableSet<String> borderLiterals0 = ImmutableSet.of("hidden", "inherit", "inset", "medium", "none", "transparent");
    ImmutableSet<String> borderCollapseLiterals0 = ImmutableSet.of("collapse", "inherit", "separate");
    ImmutableSet<String> bottomLiterals0 = ImmutableSet.of("auto", "inherit");
    ImmutableSet<String> boxShadowLiterals0 = ImmutableSet.of(",", "inset", "none");
    //ImmutableSet<String> clearLiterals0 = ImmutableSet.of("both", "inherit", "none");
    //ImmutableMap<String, String> clipFunctions = ImmutableMap.<String, String>of("rect(", "rect()");
    ImmutableSet<String> contentLiterals0 = ImmutableSet.of("none", "normal");
    ImmutableSet<String> cueLiterals0 = ImmutableSet.of("inherit", "none");
    //ImmutableSet<String> cursorLiterals0 = ImmutableSet.of("all-scroll", "col-resize", "crosshair", "default", "e-resize", "hand", "help", "move", "n-resize", "ne-resize", "no-drop", "not-allowed", "nw-resize", "pointer", "progress", "row-resize", "s-resize", "se-resize", "sw-resize", "text", "vertical-text", "w-resize", "wait");
    //ImmutableSet<String> cursorLiterals1 = ImmutableSet.of(",", "auto", "inherit");
    ImmutableSet<String> directionLiterals0 = ImmutableSet.of("ltr", "rtl");
    //ImmutableSet<String> displayLiterals0 = ImmutableSet.of("-moz-inline-box", "-moz-inline-stack", "block", "inline", "inline-block", "inline-table", "list-item", "run-in", "table", "table-caption", "table-cell", "table-column", "table-column-group", "table-footer-group", "table-header-group", "table-row", "table-row-group");
    ImmutableSet<String> elevationLiterals0 = ImmutableSet.of("above", "below", "higher", "level", "lower");
    ImmutableSet<String> emptyCellsLiterals0 = ImmutableSet.of("hide", "show");
    //ImmutableMap<String, String> filterFunctions = ImmutableMap.<String, String>of("alpha(", "alpha()");
    ImmutableSet<String> fontLiterals0 = ImmutableSet.of("100", "200", "300", "400", "500", "600", "700", "800", "900", "bold", "bolder", "lighter");
    ImmutableSet<String> fontLiterals1 = ImmutableSet.of("large", "larger", "small", "smaller", "x-large", "x-small", "xx-large", "xx-small");
    ImmutableSet<String> fontLiterals2 = ImmutableSet.of("caption", "icon", "menu", "message-box", "small-caption", "status-bar");
    ImmutableSet<String> fontLiterals3 = ImmutableSet.of("cursive", "fantasy", "monospace", "sans-serif", "serif");
    ImmutableSet<String> fontLiterals4 = ImmutableSet.of("italic", "oblique");
    ImmutableSet<String> fontLiterals5 = ImmutableSet.of(",", "/", "inherit", "medium", "normal", "small-caps");
    ImmutableSet<String> fontFamilyLiterals0 = ImmutableSet.of(",", "inherit");
    ImmutableSet<String> fontStretchLiterals0 = ImmutableSet.of("condensed", "expanded", "extra-condensed", "extra-expanded", "narrower", "semi-condensed", "semi-expanded", "ultra-condensed", "ultra-expanded", "wider");
    ImmutableSet<String> fontStretchLiterals1 = ImmutableSet.of("normal");
    ImmutableSet<String> fontStyleLiterals0 = ImmutableSet.of("inherit", "normal");
    ImmutableSet<String> fontVariantLiterals0 = ImmutableSet.of("inherit", "normal", "small-caps");
    ImmutableSet<String> listStyleLiterals0 = ImmutableSet.of("armenian", "cjk-decimal", "decimal", "decimal-leading-zero", "disc", "disclosure-closed", "disclosure-open", "ethiopic-numeric", "georgian", "hebrew", "hiragana", "hiragana-iroha", "japanese-formal", "japanese-informal", "katakana", "katakana-iroha", "korean-hangul-formal", "korean-hanja-formal", "korean-hanja-informal", "lower-alpha", "lower-greek", "lower-latin", "lower-roman", "simp-chinese-formal", "simp-chinese-informal", "square", "trad-chinese-formal", "trad-chinese-informal", "upper-alpha", "upper-latin", "upper-roman");
    ImmutableSet<String> listStyleLiterals1 = ImmutableSet.of("inside", "outside");
    ImmutableSet<String> listStyleLiterals2 = ImmutableSet.of("circle", "inherit", "none");
    ImmutableSet<String> maxHeightLiterals0 = ImmutableSet.of("auto", "inherit", "none");
    //ImmutableSet<String> overflowLiterals0 = ImmutableSet.of("auto", "hidden", "inherit", "scroll", "visible");
    //ImmutableSet<String> overflowXLiterals0 = ImmutableSet.of("no-content", "no-display");
    //ImmutableSet<String> overflowXLiterals1 = ImmutableSet.of("auto", "hidden", "scroll", "visible");
    //ImmutableSet<String> pageBreakAfterLiterals0 = ImmutableSet.of("always", "auto", "avoid", "inherit");
    //ImmutableSet<String> pageBreakInsideLiterals0 = ImmutableSet.of("auto", "avoid", "inherit");
    ImmutableSet<String> pitchLiterals0 = ImmutableSet.of("high", "low", "x-high", "x-low");
    //ImmutableSet<String> playDuringLiterals0 = ImmutableSet.of("auto", "inherit", "mix", "none", "repeat");
    //ImmutableSet<String> positionLiterals0 = ImmutableSet.of("absolute", "relative", "static");
    ImmutableSet<String> speakLiterals0 = ImmutableSet.of("inherit", "none", "normal", "spell-out");
    ImmutableSet<String> speakHeaderLiterals0 = ImmutableSet.of("always", "inherit", "once");
    ImmutableSet<String> speakNumeralLiterals0 = ImmutableSet.of("continuous", "digits");
    ImmutableSet<String> speakPunctuationLiterals0 = ImmutableSet.of("code", "inherit", "none");
    ImmutableSet<String> speechRateLiterals0 = ImmutableSet.of("fast", "faster", "slow", "slower", "x-fast", "x-slow");
    ImmutableSet<String> tableLayoutLiterals0 = ImmutableSet.of("auto", "fixed", "inherit");
    ImmutableSet<String> textAlignLiterals0 = ImmutableSet.of("center", "inherit", "justify");
    ImmutableSet<String> textDecorationLiterals0 = ImmutableSet.of("blink", "line-through", "overline", "underline");
    ImmutableSet<String> textTransformLiterals0 = ImmutableSet.of("capitalize", "lowercase", "uppercase");
    ImmutableSet<String> textWrapLiterals0 = ImmutableSet.of("suppress", "unrestricted");
    ImmutableSet<String> unicodeBidiLiterals0 = ImmutableSet.of("bidi-override", "embed");
    ImmutableSet<String> verticalAlignLiterals0 = ImmutableSet.of("baseline", "middle", "sub", "super", "text-bottom", "text-top");
    //ImmutableSet<String> visibilityLiterals0 = ImmutableSet.of("collapse", "hidden", "inherit", "visible");
    ImmutableSet<String> voiceFamilyLiterals0 = ImmutableSet.of("child", "female", "male");
    ImmutableSet<String> volumeLiterals0 = ImmutableSet.of("loud", "silent", "soft", "x-loud", "x-soft");
    ImmutableSet<String> whiteSpaceLiterals0 = ImmutableSet.of("-moz-pre-wrap", "-o-pre-wrap", "-pre-wrap", "nowrap", "pre", "pre-line", "pre-wrap");
    ImmutableSet<String> wordWrapLiterals0 = ImmutableSet.of("break-word", "normal");
    ImmutableSet<String> rgb$FunLiterals0 = ImmutableSet.of(",");
    ImmutableSet<String> linearGradient$FunLiterals0 = ImmutableSet.of(",", "to");
    ImmutableSet<String> radialGradient$FunLiterals0 = ImmutableSet.of("at", "closest-corner", "closest-side", "ellipse", "farthest-corner", "farthest-side");
    ImmutableSet<String> radialGradient$FunLiterals1 = ImmutableSet.of(",", "center", "circle");
    ImmutableSet<String> rect$FunLiterals0 = ImmutableSet.of(",", "auto");
    ImmutableSet<String> alpha$FunLiterals0 = ImmutableSet.of("=", "opacity");
    CssSchema mozBorderRadius = new CssSchema(5, mozBorderRadiusLiterals0, zeroFns);
    builder.put("-moz-border-radius", mozBorderRadius);
    CssSchema mozBorderRadiusBottomleft = new CssSchema(5, ImmutableSet.<String>of(), zeroFns);
    builder.put("-moz-border-radius-bottomleft", mozBorderRadiusBottomleft);
    //CssSchema mozOpacity = new CssSchema(1, mozOpacityLiterals0, zeroFns);
    //builder.put("-moz-opacity", mozOpacity);
    @SuppressWarnings("unchecked")
    CssSchema mozOutline = new CssSchema(7, union(mozOutlineLiterals0, mozOutlineLiterals1, mozOutlineLiterals2, mozOutlineLiterals3), mozOutlineFunctions);
    builder.put("-moz-outline", mozOutline);
    @SuppressWarnings("unchecked")
    CssSchema mozOutlineColor = new CssSchema(2, union(mozOutlineColorLiterals0, mozOutlineLiterals0), mozOutlineFunctions);
    builder.put("-moz-outline-color", mozOutlineColor);
    @SuppressWarnings("unchecked")
    CssSchema mozOutlineStyle = new CssSchema(0, union(mozOutlineLiterals1, mozOutlineStyleLiterals0), zeroFns);
    builder.put("-moz-outline-style", mozOutlineStyle);
    @SuppressWarnings("unchecked")
    CssSchema mozOutlineWidth = new CssSchema(5, union(mozOutlineLiterals2, mozOutlineWidthLiterals0), zeroFns);
    builder.put("-moz-outline-width", mozOutlineWidth);
    CssSchema oTextOverflow = new CssSchema(0, oTextOverflowLiterals0, zeroFns);
    builder.put("-o-text-overflow", oTextOverflow);
    @SuppressWarnings("unchecked")
    CssSchema azimuth = new CssSchema(5, union(azimuthLiterals0, azimuthLiterals1, azimuthLiterals2), zeroFns);
    builder.put("azimuth", azimuth);
    @SuppressWarnings("unchecked")
    CssSchema background = new CssSchema(23, union(azimuthLiterals1, backgroundLiterals0, backgroundLiterals1, backgroundLiterals2, backgroundLiterals3, mozOutlineLiterals0), backgroundFunctions);
    builder.put("background", background);
    builder.put("background-attachment", new CssSchema(0, backgroundAttachmentLiterals0, zeroFns));
    @SuppressWarnings("unchecked")
    CssSchema backgroundColor = new CssSchema(258, union(backgroundColorLiterals0, mozOutlineLiterals0), mozOutlineFunctions);
    builder.put("background-color", backgroundColor);
    builder.put("background-image", new CssSchema(16, backgroundImageLiterals0, backgroundImageFunctions));
    @SuppressWarnings("unchecked")
    CssSchema backgroundPosition = new CssSchema(5, union(azimuthLiterals1, backgroundLiterals2, backgroundPositionLiterals0), zeroFns);
    builder.put("background-position", backgroundPosition);
    @SuppressWarnings("unchecked")
    CssSchema backgroundRepeat = new CssSchema(0, union(backgroundLiterals1, backgroundRepeatLiterals0), zeroFns);
    builder.put("background-repeat", backgroundRepeat);
    @SuppressWarnings("unchecked")
    CssSchema border = new CssSchema(7, union(borderLiterals0, mozOutlineLiterals0, mozOutlineLiterals1, mozOutlineLiterals2), mozOutlineFunctions);
    builder.put("border", border);
    @SuppressWarnings("unchecked")
    CssSchema borderBottomColor = new CssSchema(2, union(backgroundColorLiterals0, mozOutlineLiterals0), mozOutlineFunctions);
    builder.put("border-bottom-color", borderBottomColor);
    builder.put("border-collapse", new CssSchema(0, borderCollapseLiterals0, zeroFns));
    CssSchema borderSpacing = new CssSchema(5, mozOpacityLiterals0, zeroFns);
    builder.put("border-spacing", borderSpacing);
    //CssSchema bottom = new CssSchema(5, bottomLiterals0, zeroFns);
    //builder.put("bottom", bottom);
    @SuppressWarnings("unchecked")
    CssSchema boxShadow = new CssSchema(7, union(boxShadowLiterals0, mozOutlineLiterals0), mozOutlineFunctions);
    builder.put("box-shadow", boxShadow);
    @SuppressWarnings("unchecked")
    CssSchema captionSide = new CssSchema(0, union(backgroundLiterals2, mozOpacityLiterals0), zeroFns);
    builder.put("caption-side", captionSide);
    //@SuppressWarnings("unchecked")
    //CssSchema clear = new CssSchema(0, union(azimuthLiterals1, clearLiterals0), zeroFns);
    //builder.put("clear", clear);
    //builder.put("clip", new CssSchema(0, bottomLiterals0, clipFunctions));
    @SuppressWarnings("unchecked")
    CssSchema color = new CssSchema(258, union(mozOpacityLiterals0, mozOutlineLiterals0), mozOutlineFunctions);
    builder.put("color", color);
    //builder.put("content", new CssSchema(8, contentLiterals0, zeroFns));
    CssSchema cue = new CssSchema(16, cueLiterals0, zeroFns);
    builder.put("cue", cue);
    //@SuppressWarnings("unchecked")
    //CssSchema cursor = new CssSchema(272, union(cursorLiterals0, cursorLiterals1), zeroFns);
    //builder.put("cursor", cursor);
    @SuppressWarnings("unchecked")
    CssSchema direction = new CssSchema(0, union(directionLiterals0, mozOpacityLiterals0), zeroFns);
    builder.put("direction", direction);
    //@SuppressWarnings("unchecked")
    //CssSchema display = new CssSchema(0, union(cueLiterals0, displayLiterals0), zeroFns);
    //builder.put("display", display);
    @SuppressWarnings("unchecked")
    CssSchema elevation = new CssSchema(5, union(elevationLiterals0, mozOpacityLiterals0), zeroFns);
    builder.put("elevation", elevation);
    @SuppressWarnings("unchecked")
    CssSchema emptyCells = new CssSchema(0, union(emptyCellsLiterals0, mozOpacityLiterals0), zeroFns);
    builder.put("empty-cells", emptyCells);
    //builder.put("filter", new CssSchema(0, ImmutableSet.<String>of(), filterFunctions));
    //@SuppressWarnings("unchecked")
    //CssSchema cssFloat = new CssSchema(0, union(azimuthLiterals1, cueLiterals0), zeroFns);
    //builder.put("float", cssFloat);
    @SuppressWarnings("unchecked")
    CssSchema font = new CssSchema(73, union(fontLiterals0, fontLiterals1, fontLiterals2, fontLiterals3, fontLiterals4, fontLiterals5), zeroFns);
    builder.put("font", font);
    @SuppressWarnings("unchecked")
    CssSchema fontFamily = new CssSchema(72, union(fontFamilyLiterals0, fontLiterals3), zeroFns);
    builder.put("font-family", fontFamily);
    @SuppressWarnings("unchecked")
    CssSchema fontSize = new CssSchema(1, union(fontLiterals1, mozOutlineWidthLiterals0), zeroFns);
    builder.put("font-size", fontSize);
    @SuppressWarnings("unchecked")
    CssSchema fontStretch = new CssSchema(0, union(fontStretchLiterals0, fontStretchLiterals1), zeroFns);
    builder.put("font-stretch", fontStretch);
    @SuppressWarnings("unchecked")
    CssSchema fontStyle = new CssSchema(0, union(fontLiterals4, fontStyleLiterals0), zeroFns);
    builder.put("font-style", fontStyle);
    builder.put("font-variant", new CssSchema(0, fontVariantLiterals0, zeroFns));
    @SuppressWarnings("unchecked")
    CssSchema fontWeight = new CssSchema(0, union(fontLiterals0, fontStyleLiterals0), zeroFns);
    builder.put("font-weight", fontWeight);
    CssSchema height = new CssSchema(5, bottomLiterals0, zeroFns);
    builder.put("height", height);
    CssSchema letterSpacing = new CssSchema(5, fontStyleLiterals0, zeroFns);
    builder.put("letter-spacing", letterSpacing);
    builder.put("line-height", new CssSchema(1, fontStyleLiterals0, zeroFns));
    @SuppressWarnings("unchecked")
    CssSchema listStyle = new CssSchema(16, union(listStyleLiterals0, listStyleLiterals1, listStyleLiterals2), backgroundImageFunctions);
    builder.put("list-style", listStyle);
    builder.put("list-style-image", new CssSchema(16, cueLiterals0, backgroundImageFunctions));
    @SuppressWarnings("unchecked")
    CssSchema listStylePosition = new CssSchema(0, union(listStyleLiterals1, mozOpacityLiterals0), zeroFns);
    builder.put("list-style-position", listStylePosition);
    @SuppressWarnings("unchecked")
    CssSchema listStyleType = new CssSchema(0, union(listStyleLiterals0, listStyleLiterals2), zeroFns);
    builder.put("list-style-type", listStyleType);
    CssSchema margin = new CssSchema(1, bottomLiterals0, zeroFns);
    builder.put("margin", margin);
    CssSchema maxHeight = new CssSchema(1, maxHeightLiterals0, zeroFns);
    builder.put("max-height", maxHeight);
    //CssSchema opacity = new CssSchema(1, mozOpacityLiterals0, zeroFns);
    //builder.put("opacity", opacity);
    //builder.put("overflow", new CssSchema(0, overflowLiterals0, zeroFns));
    //@SuppressWarnings("unchecked")
    //CssSchema overflowX = new CssSchema(0, union(overflowXLiterals0, overflowXLiterals1), zeroFns);
    //builder.put("overflow-x", overflowX);
    CssSchema padding = new CssSchema(1, mozOpacityLiterals0, zeroFns);
    builder.put("padding", padding);
    //@SuppressWarnings("unchecked")
    //CssSchema pageBreakAfter = new CssSchema(0, union(azimuthLiterals1, pageBreakAfterLiterals0), zeroFns);
    //builder.put("page-break-after", pageBreakAfter);
    //builder.put("page-break-inside", new CssSchema(0, pageBreakInsideLiterals0, zeroFns));
    @SuppressWarnings("unchecked")
    CssSchema pitch = new CssSchema(5, union(mozOutlineWidthLiterals0, pitchLiterals0), zeroFns);
    builder.put("pitch", pitch);
    //builder.put("play-during", new CssSchema(16, playDuringLiterals0, zeroFns));
    //@SuppressWarnings("unchecked")
    //CssSchema position = new CssSchema(0, union(mozOpacityLiterals0, positionLiterals0), zeroFns);
    //builder.put("position", position);
    builder.put("quotes", new CssSchema(8, cueLiterals0, zeroFns));
    builder.put("speak", new CssSchema(0, speakLiterals0, zeroFns));
    builder.put("speak-header", new CssSchema(0, speakHeaderLiterals0, zeroFns));
    @SuppressWarnings("unchecked")
    CssSchema speakNumeral = new CssSchema(0, union(mozOpacityLiterals0, speakNumeralLiterals0), zeroFns);
    builder.put("speak-numeral", speakNumeral);
    builder.put("speak-punctuation", new CssSchema(0, speakPunctuationLiterals0, zeroFns));
    @SuppressWarnings("unchecked")
    CssSchema speechRate = new CssSchema(5, union(mozOutlineWidthLiterals0, speechRateLiterals0), zeroFns);
    builder.put("speech-rate", speechRate);
    builder.put("table-layout", new CssSchema(0, tableLayoutLiterals0, zeroFns));
    @SuppressWarnings("unchecked")
    CssSchema textAlign = new CssSchema(0, union(azimuthLiterals1, textAlignLiterals0), zeroFns);
    builder.put("text-align", textAlign);
    @SuppressWarnings("unchecked")
    CssSchema textDecoration = new CssSchema(0, union(cueLiterals0, textDecorationLiterals0), zeroFns);
    builder.put("text-decoration", textDecoration);
    @SuppressWarnings("unchecked")
    CssSchema textTransform = new CssSchema(0, union(cueLiterals0, textTransformLiterals0), zeroFns);
    builder.put("text-transform", textTransform);
    @SuppressWarnings("unchecked")
    CssSchema textWrap = new CssSchema(0, union(contentLiterals0, textWrapLiterals0), zeroFns);
    builder.put("text-wrap", textWrap);
    @SuppressWarnings("unchecked")
    CssSchema unicodeBidi = new CssSchema(0, union(fontStyleLiterals0, unicodeBidiLiterals0), zeroFns);
    builder.put("unicode-bidi", unicodeBidi);
    @SuppressWarnings("unchecked")
    CssSchema verticalAlign = new CssSchema(5, union(backgroundLiterals2, mozOpacityLiterals0, verticalAlignLiterals0), zeroFns);
    builder.put("vertical-align", verticalAlign);
    //builder.put("visibility", new CssSchema(0, visibilityLiterals0, zeroFns));
    @SuppressWarnings("unchecked")
    CssSchema voiceFamily = new CssSchema(8, union(fontFamilyLiterals0, voiceFamilyLiterals0), zeroFns);
    builder.put("voice-family", voiceFamily);
    @SuppressWarnings("unchecked")
    CssSchema volume = new CssSchema(1, union(mozOutlineWidthLiterals0, volumeLiterals0), zeroFns);
    builder.put("volume", volume);
    @SuppressWarnings("unchecked")
    CssSchema whiteSpace = new CssSchema(0, union(fontStyleLiterals0, whiteSpaceLiterals0), zeroFns);
    builder.put("white-space", whiteSpace);
    builder.put("word-wrap", new CssSchema(0, wordWrapLiterals0, zeroFns));
    //builder.put("zoom", new CssSchema(1, fontStretchLiterals1, zeroFns));
    CssSchema rgb$Fun = new CssSchema(1, rgb$FunLiterals0, zeroFns);
    builder.put("rgb()", rgb$Fun);
    @SuppressWarnings("unchecked")
    CssSchema image$Fun = new CssSchema(18, union(mozOutlineLiterals0, rgb$FunLiterals0), mozOutlineFunctions);
    builder.put("image()", image$Fun);
    @SuppressWarnings("unchecked")
    CssSchema linearGradient$Fun = new CssSchema(7, union(azimuthLiterals1, backgroundLiterals2, linearGradient$FunLiterals0, mozOutlineLiterals0), mozOutlineFunctions);
    builder.put("linear-gradient()", linearGradient$Fun);
    @SuppressWarnings("unchecked")
    CssSchema radialGradient$Fun = new CssSchema(7, union(azimuthLiterals1, backgroundLiterals2, mozOutlineLiterals0, radialGradient$FunLiterals0, radialGradient$FunLiterals1), mozOutlineFunctions);
    builder.put("radial-gradient()", radialGradient$Fun);
    builder.put("rect()", new CssSchema(5, rect$FunLiterals0, zeroFns));
    builder.put("alpha()", new CssSchema(1, alpha$FunLiterals0, zeroFns));
    builder.put("-moz-border-radius-bottomright", mozBorderRadiusBottomleft);
    builder.put("-moz-border-radius-topleft", mozBorderRadiusBottomleft);
    builder.put("-moz-border-radius-topright", mozBorderRadiusBottomleft);
    builder.put("-moz-box-shadow", boxShadow);
    builder.put("-webkit-border-bottom-left-radius", mozBorderRadiusBottomleft);
    builder.put("-webkit-border-bottom-right-radius", mozBorderRadiusBottomleft);
    builder.put("-webkit-border-radius", mozBorderRadius);
    builder.put("-webkit-border-radius-bottom-left", mozBorderRadiusBottomleft);
    builder.put("-webkit-border-radius-bottom-right", mozBorderRadiusBottomleft);
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
    //builder.put("left", height);
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
    //builder.put("overflow-y", overflowX);
    builder.put("padding-bottom", padding);
    builder.put("padding-left", padding);
    builder.put("padding-right", padding);
    builder.put("padding-top", padding);
    //builder.put("page-break-before", pageBreakAfter);
    builder.put("pause", borderSpacing);
    builder.put("pause-after", borderSpacing);
    builder.put("pause-before", borderSpacing);
    builder.put("pitch-range", borderSpacing);
    builder.put("richness", borderSpacing);
    //builder.put("right", height);
    builder.put("stress", borderSpacing);
    builder.put("text-indent", borderSpacing);
    builder.put("text-overflow", oTextOverflow);
    builder.put("text-shadow", boxShadow);
    //builder.put("top", height);
    builder.put("width", margin);
    builder.put("word-spacing", letterSpacing);
    //builder.put("z-index", bottom);
    builder.put("rgba()", rgb$Fun);
    builder.put("repeating-linear-gradient()", linearGradient$Fun);
    builder.put("repeating-radial-gradient()", radialGradient$Fun);
    SCHEMA = builder.build();
  }

  private static <T> ImmutableSet<T> union(ImmutableSet<T>... subsets) {
    ImmutableSet.Builder<T> all = ImmutableSet.builder();
    for (ImmutableSet<T> subset : subsets) {
      all.addAll(subset);
    }
    return all.build();
  }
}
