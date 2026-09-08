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

import java.util.Arrays;
import javax.annotation.Nullable;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class StylingPolicyTest {
  @Test
  void testNothingToOutput() {
    assertSanitizedCss(null, "");
    assertSanitizedCss(null, "/** no CSS here */");
    assertSanitizedCss(null, "/* props: disabled; font-weight: bold */");
    assertSanitizedCss(null, "position: fixed");
    assertSanitizedCss(
        null, "background: url('javascript:alert%281337%29')");
  }

  @Test
  void testColors() {
    assertSanitizedCss("color:red", "color: red");
    assertSanitizedCss("background-color:#f00", "background-color: #f00");
    assertSanitizedCss("background:#f00", "background: #f00");
    assertSanitizedCss("color:#f00", "color: #F00");
    assertSanitizedCss(null, "color: #F000");
    assertSanitizedCss("color:#ff0000", "color: #ff0000");
    assertSanitizedCss("color:rgb( 255 , 0 , 0 )", "color: rgb(255, 0, 0)");
    assertSanitizedCss("background:rgb( 100% , 0 , 0 )",
                       "background: rgb(100%, 0, 0)");
    assertSanitizedCss(
        "color:rgba( 100% , 0 , 0 , 100% )", "color: RGBA(100%, 0, 0, 100%)");
    assertSanitizedCss(null, "color: transparent");
    assertSanitizedCss(null, "color: bogus");
    assertSanitizedCss(null, "color: expression(alert(1337))");
    assertSanitizedCss(null, "color: 000");
    assertSanitizedCss(null, "background-color: 000");
    // Not colors.
    assertSanitizedCss(
        "background:url('pic.jpg#sanitized')", "background: \"pic.jpg\"");
    assertSanitizedCss(
        "background:url('pic.jpg#sanitized')", "background: url(pic.jpg)");
    assertSanitizedCss(null, "color:#urlabc");
    assertSanitizedCss(null, "color:#urlabcd");
  }

  @Test
  void testFontWeight() {
    assertSanitizedCss(
        "font-weight:bold", "font-weight: bold");
    assertSanitizedCss(
        "font:bold", "font: bold");
    assertSanitizedCss(
        "font:bolder", "font: Bolder");
    assertSanitizedCss(
        "font-weight:800", "font-weight: 800");
    assertSanitizedCss(
        null, "font-weight: expression(alert(1337))");
    assertSanitizedCss(
        "font:'evil'",
        "font: 3execute evil");
  }

  @Test
  void testFontStyle() {
    assertSanitizedCss(
        "font-style:italic", "font-style: Italic");
    assertSanitizedCss(
        "font:italic", "font: italic");
    assertSanitizedCss(
        "font:oblique", "font: Oblique");
    assertSanitizedCss(
        null, "font-style: expression(alert(1337))");
  }

  @Test
  void testFontFace() {
    // A font name is a name, not a keyword: it is emitted as the author wrote
    // it, even though the schema matches it case-insensitively.  See #289.
    assertSanitizedCss(
        "font:'Arial' , 'Helvetica'", "font: Arial, Helvetica");
    assertSanitizedCss(
        "font-family:'Arial' , 'Helvetica' , sans-serif",
        "Font-family: Arial, Helvetica, sans-serif");
    // A quoted "Monospace" is a font name, not the generic family keyword, so
    // it stays quoted; the bare keyword below does not.
    assertSanitizedCss(
        "font-family:'Monospace' , sans-serif",
        "Font-family: \"Monospace\", Sans-serif");
    assertSanitizedCss(
        "font:'Arial Bold' , 'Helvetica' , monospace",
        "FONT: \"Arial Bold\", Helvetica, monospace");
    assertSanitizedCss(
        "font-family:'Arial Bold' , 'Helvetica'",
        "font-family: \"Arial Bold\", Helvetica");
    assertSanitizedCss(
        "font-family:'Arial Bold' , 'Helvetica'",
        "font-family: 'Arial Bold', Helvetica");
    assertSanitizedCss(
        "font-family:'evil'",
        "font-family: 3execute evil");
    // An empty name really is empty, so it drops and leaves the separators.
    assertSanitizedCss(
        "font-family:'Arial Bold' , , , 'Helvetica' , sans-serif",
        "font-family: 'Arial Bold',,\"\",Helvetica,sans-serif");
    assertSanitizedCss(
        "font:'ChalkboardSE-Light' , 'Helvetica' , monospace",
        "FONT: \"ChalkboardSE-Light\", Helvetica, monospace");
  }

  /**
   * Issue #232.  Sanitizing twice must not change the result.  A font name
   * containing an underscore -- which is what Word emits -- was accepted
   * unquoted but rejected once quoted, so the first pass produced a name the
   * second pass dropped, leaving a stray comma and invalid CSS.
   */
  @Test
  void testFontFamilyIsIdempotent() {
    String once = "font-family:'WordVisi_MSFontService' , 'Algerian' ,"
        + " 'Algerian_EmbeddedFont' , sans-serif";
    assertSanitizedCss(
        once,
        "font-family: WordVisi_MSFontService, Algerian,"
        + " Algerian_EmbeddedFont, sans-serif");
    // The output of the first pass survives a second unchanged.
    assertSanitizedCss(once, once);
    // Periods and non-ASCII names round-trip too.
    assertSanitizedCss("font-family:'Foo.Bar_1'", "font-family: 'Foo.Bar_1'");
    assertSanitizedCss("font-family:'\u4e2d\u6587\u5b57\u4f53'",
                       "font-family: '\u4e2d\u6587\u5b57\u4f53'");
  }

  /**
   * Issue #229.  A generic family is a keyword and must not be quoted, or the
   * declaration stops meaning what it said.
   */
  @Test
  void testGenericFontFamiliesAreNotQuoted() {
    assertSanitizedCss(
        "font-family:sans-serif , system-ui , -apple-system",
        "font-family: sans-serif, system-ui, -apple-system");
    assertSanitizedCss(
        "font-family:ui-serif , ui-sans-serif , ui-monospace , ui-rounded",
        "font-family: ui-serif, ui-sans-serif, ui-monospace, ui-rounded");
    assertSanitizedCss(
        "font-family:math , emoji , fangsong , cursive , fantasy",
        "font-family: math, emoji, fangsong, cursive, fantasy");
    // A real font name is still quoted.
    assertSanitizedCss(
        "font-family:'BlinkMacSystemFont' , sans-serif",
        "font-family: BlinkMacSystemFont, sans-serif");
  }

  /**
   * Both paths that emit a font name apply the same test, so a name cannot
   * survive one sanitization pass and vanish on the next, and a format
   * character cannot ride into the output on the unquoted path.
   */
  @Test
  void testFontNamePathsAgree() {
    // U+202E RIGHT-TO-LEFT OVERRIDE reorders the text around it, so it has no
    // business in a font name.  It used to be accepted unquoted and rejected
    // quoted, which also made sanitization non-idempotent.
    assertSanitizedCss(null, "font-family: a\u202eb");
    assertSanitizedCss(null, "font-family: 'a\u202eb'");
    // U+FEFF ZERO WIDTH NO-BREAK SPACE never reaches the output either, but
    // by a different route: quoted it is rejected here, and unquoted the
    // lexer has already split it into two identifiers.
    assertSanitizedCss("font-family:'a b'", "font-family: a\ufeffb");
    assertSanitizedCss(null, "font-family: 'a\ufeffb'");
    // Ordinary names go through either way, and agree.
    assertSanitizedCss("font-family:'Foo_Bar'", "font-family: Foo_Bar");
    assertSanitizedCss("font-family:'Foo_Bar'", "font-family: 'Foo_Bar'");
  }

  /**
   * Which non-ASCII font names survive, pinned so the claim in
   * {@code isSafeQuotedIdentifier}'s javadoc stays honest.
   *
   * <p>The limitation on combining marks and supplementary code points is not
   * imposed here -- the CSS lexer drops them from a token before the policy
   * runs, and did so before the widening in #232 as well.
   */
  @Test
  void testNonAsciiFontNames() {
    // Letters and digits from the basic multilingual plane go through, quoted
    // or not.
    for (String name : new String[] {
        "\u0422\u0430\u0439\u043c\u0441",              // Cyrillic
        "\u0395\u03bb\u03bb\u03b7\u03bd\u03b9\u03ba\u03ac",  // Greek, precomposed accent
        "\u4e2d\u6587\u5b57\u4f53",                     // Han
        "\ub9d1\uc740\uace0\ub515",                     // Hangul
        "\u30d2\u30e9\u30ae\u30ce",                     // Katakana
        "\u0646\u0633\u062e",                            // Arabic base letters
        "\u05d0\u05dc\u05e3" }) {                        // Hebrew base letters
      assertSanitizedCss("font-family:'" + name + "'", "font-family: " + name);
      assertSanitizedCss(
          "font-family:'" + name + "'", "font-family: '" + name + "'");
    }

    // A combining mark does not, on either path.  This is the lexer's doing,
    // not this policy's.
    for (String name : new String[] {
        "\u0646\u064e\u0633",              // Arabic with fatha
        "\u0926\u0947\u0935",              // Devanagari with matra
        "\u05d0\u05b8\u05dc",              // Hebrew with qamats
        "\u0e1a\u0e31\u0e0d" }) {          // Thai with vowel sign
      assertSanitizedCss(null, "font-family: " + name);
      assertSanitizedCss(null, "font-family: '" + name + "'");
    }

    // Nor does a supplementary code point: U+20000, a CJK extension B
    // ideograph.
    assertSanitizedCss(null, "font-family: \ud840\udc00");
    assertSanitizedCss(null, "font-family: '\ud840\udc00'");
  }

  /**
   * Widening what a quoted name may contain must not let a name break out of
   * the quotes it is emitted in.  The lexer hands us quotes and backslashes
   * already escaped, and an escape is exactly what is rejected.
   */
  @Test
  void testQuotedFontNamesCannotBreakOut() {
    assertSanitizedCss(null, "font-family: 'it\\27s'");
    assertSanitizedCss(null, "font-family: 'a\\5c b'");
    assertSanitizedCss(null, "font-family: 'a\\22 b'");
    assertSanitizedCss(null, "font-family: '</style>'");
    assertSanitizedCss(null, "font-family: 'a\\a b'");
  }

  @Test
  void testFont() {
    assertSanitizedCss(
        "font:'Arial' 12pt bold oblique",
        "font: Arial 12pt bold oblique");
    assertSanitizedCss(
        "font:'Times New Roman' 24px bolder",
        "font: \"Times New Roman\" 24px bolder");
    assertSanitizedCss("font:24px", "font: 24px");
    // Non-ascii characters discarded.
    assertSanitizedCss(null, "font: 24ex\\pression");
    // Harmless garbage.
    assertSanitizedCss(
        "font:24ex 'pression'", "font: 24ex\0pression");
    assertSanitizedCss(
        null, "font: expression(arial)");
    assertSanitizedCss(
        null, "font: rgb(\"expression(alert(1337))//\")");
    assertSanitizedCss("font-size:smaller", "font-size: smaller");
    assertSanitizedCss("font:smaller", "font: smaller");
    assertSanitizedCss("font:'ChalkboardSE-Light'", "font: 'ChalkboardSE-Light'");
    assertSanitizedCss(null, "font: '---");
  }

  @Test
  void testBidiAndAlignmentAttributes() {
    assertSanitizedCss(
        "text-align:left;unicode-bidi:embed;direction:ltr",
        "Text-align: left; Unicode-bidi: Embed; Direction: LTR;");
    assertSanitizedCss(
        null, "text-align:expression(left())");
    assertSanitizedCss(null, "text-align: bogus");
    assertSanitizedCss("unicode-bidi:embed", "unicode-bidi:embed");
    assertSanitizedCss(null, "unicode-bidi:expression(embed)");
    assertSanitizedCss(null, "unicode-bidi:bogus");
    assertSanitizedCss(null, "direction:expression(ltr())");
  }

  @Test
  void testTextDecoration() {
    assertSanitizedCss(
        "text-decoration:underline",
        "Text-Decoration: Underline");
    assertSanitizedCss(
        "text-decoration:overline",
        "text-decoration: overline");
    assertSanitizedCss(
        "text-decoration:line-through",
        "text-decoration: line-through");
    assertSanitizedCss(
        null,
        "text-decoration: expression(document.location=42)");
  }

  @Test
  void testBoxProperties() {
    // http://www.w3.org/TR/CSS2/box.html
    assertSanitizedCss("height:0", "height:0");
    assertSanitizedCss("width:0", "width:0");
    assertSanitizedCss("width:20px", "width:20px");
    assertSanitizedCss("width:20", "width:20");
    assertSanitizedCss("width:100%", "width:100%");
    assertSanitizedCss("height:6in", "height:6in");
    assertSanitizedCss(null, "width:-20");
    assertSanitizedCss(null, "width:url('foo')");
    assertSanitizedCss(null, "height:6fixed");
    assertSanitizedCss("margin:2 2 2 2", "margin:2 2 2 2");
    assertSanitizedCss("margin:2 2 2", "margin:2 2 2");
    assertSanitizedCss("padding:2 2", "padding:2 2");
    assertSanitizedCss("margin:2", "margin:2");
    assertSanitizedCss("margin:2px 4px 6px 8px", "margin:2px 4px 6px 8px");
    assertSanitizedCss("padding:0 4px 6px", "padding:0 4px 6px");
    assertSanitizedCss("margin:2px 4px 6px 4px", "margin:2px 4px 6px 4px");
    assertSanitizedCss("margin:0 4px", "margin:0 4px");
    assertSanitizedCss("margin:0 4px", "margin:0 4 px");
    assertSanitizedCss("padding-left:4px", "padding-left:4px");
    assertSanitizedCss("padding-left:0.4em;padding-top:2px;margin-bottom:3px",
                       "padding-left:0.4em;padding-top:2px;margin-bottom:3px");
    assertSanitizedCss("padding:0 1em 0.5in 1.5cm",
                       "padding:00. 1EM +00.5 In 1.50cm");
    // Mixed.
    assertSanitizedCss("margin:1em;margin-top:0.25em",
                       "margin:1em; margin-top:.25em");
  }

  @Test
  void testCalc() {
    // https://drafts.csswg.org/css-values-4/#calc-func
    // calc() is allowed in the six sizing properties (issue #361).
    assertSanitizedCss(
        "width:calc( 100% - 20px )", "width: calc(100% - 20px)");
    assertSanitizedCss(
        "min-width:calc( 100% - 20px )", "min-width: calc(100% - 20px)");
    assertSanitizedCss(
        "max-width:calc( 100% - 20px )", "max-width: calc(100% - 20px)");
    assertSanitizedCss(
        "height:calc( 100% - 20px )", "height: calc(100% - 20px)");
    assertSanitizedCss(
        "min-height:calc( 100% - 20px )", "min-height: calc(100% - 20px)");
    assertSanitizedCss(
        "max-height:calc( 100% - 20px )", "max-height: calc(100% - 20px)");
    // All four operators, grouping, negative operands, and the function
    // name is case-insensitive.
    assertSanitizedCss(
        "width:calc( 2 * 1em + 10px )", "width: calc(2 * 1em + 10px)");
    assertSanitizedCss(
        "width:calc( ( 100% - 20px ) / 2 )",
        "width: calc((100% - 20px) / 2)");
    assertSanitizedCss(
        "width:calc( -1 * 20px + 100% )", "width: CALC(-1 * 20px + 100%)");
    assertSanitizedCss(
        "width:calc( 100% - 20px ) !important",
        "width: calc(100% - 20px) !important");
    assertSanitizedCss(
        "width:calc( 100% - 20px );color:red",
        "width: calc(100% - 20px); color: red");
    // Comments are dropped and unbalanced parentheses are repaired.
    assertSanitizedCss(
        "width:calc( 100% - 20px )", "width: calc(100%/*a*/-/*b*/20px");
    assertSanitizedCss(
        "width:calc( 100% - 20px )", "width: calc(100% - 20px))");
    // Only quantities and arithmetic survive inside calc().  Anything else
    // is stripped, leaving an invalid expression that browsers ignore.
    assertSanitizedCss(
        "width:calc( )", "width: calc(expression(alert(1337)))");
    assertSanitizedCss(
        "width:calc( )", "width: calc(url('//evil.org/x'))");
    assertSanitizedCss(
        "width:calc( )", "width: calc(\"//evil.org/x\")");
    assertSanitizedCss(
        "width:calc( 100% - )", "width: calc(100% - var(--x))");
    assertSanitizedCss(
        "width:calc( 100% - )", "width: calc(100% - attr(data-x px))");
    assertSanitizedCss(
        "width:calc( 100% - )",
        "width: calc(100% - env(safe-area-inset-left))");
    assertSanitizedCss(
        "width:calc( 100% - )", "width: calc(100% - rgb(0, 0, 0))");
    assertSanitizedCss(
        "width:calc( 100% - )", "width: calc(100% - #fff)");
    assertSanitizedCss(
        "width:calc( 100% - )", "width: calc(100% - auto)");
    // calc() is not allowed in properties outside the sizing set, ...
    assertSanitizedCss(null, "margin: calc(100% - 20px)");
    assertSanitizedCss(null, "padding-left: calc(100% - 20px)");
    assertSanitizedCss(null, "font-size: calc(1em + 2px)");
    assertSanitizedCss(null, "border-width: calc(1px + 1px)");
    assertSanitizedCss("margin:20px", "margin: calc(100% - 20px) 20px");
    // ... and its operators are not allowed outside calc().
    assertSanitizedCss("width:100% 20px", "width: 100% - 20px");
    assertSanitizedCss("width:20px", "width: (20px)");
  }

  @Test
  void testCalcRequiresOptIn() {
    // As with rgb() and color, a custom schema has to list calc() next to
    // the sizing property for the function to be accepted.
    CssSchema widthOnly = CssSchema.withProperties(Arrays.asList("width"));
    assertSanitizedCss(widthOnly, "width:20px", "width: 20px");
    assertSanitizedCss(widthOnly, null, "width: calc(100% - 20px)");
    CssSchema widthAndCalc = CssSchema.withProperties(
        Arrays.asList("width", "calc()"));
    assertSanitizedCss(
        widthAndCalc, "width:calc( 100% - 20px )", "width: calc(100% - 20px)");
  }

  @Test
  void testLongUrls() {
    // Test that a long URL does not blow out the stack or consume quadratic
    // amounts of processor as when the CSS lexer was implemented as a bunch of
    // regular expressions.
    String longUrl = ""
        + "background-image:url(data:image/gif;base64,"
        + "R0lGODlhMgCaAPf/AO5ZOuRpTfXSyvro5Pz08uCEb+ShkeummPOMdPOqmdZdQvbEud1"
        + "UNuqmlvqbhchNMfnTyvXPxu6pmtFkTeJ6Y9JxXPR8YNRSNvyunP3Mwd1zW+iCau9dPt"
        + "BOMe69sutwVPGGbuFcPvmRefqAZuhiQ/rJv9pFJf3h2up0WttCItmBbv3r5/26q/bc1"
        + "v3XzvHOx8tML/nf2cpAI+hfQf3GufVbOvyrmvCkk/7r5vnm4t+BbPism/apmN9DI+hN"
        + "LrkrD/x4V98+HeFBIPt0U/x2VflaOfdwT/lzUvhYN/p2VfhWNd47Gvx5WPtyUflcO+J"
        + "EI/VsS/FjQvRpSPtwT/tuTebm5vpmRfppSPlePeRIJ8XFxdRQNPpsS8I9IYyMjOhQL+"
        + "xYN+ZMK/liQflgP+1dO+pUM//188RBJZGRkff39/718vFZOcA/JtVXO8VEKPvVzeuhk"
        + "Pynk/ermsdHK/7Yz/ehjvi2p9Z4ZPre2NRDJPVkRPzz8d9NLdR1YNM2F/SkksBBKOdX"
        + "OfaHbdhsVPFbO81cQs1UOO2HcPNTM/708dd7Zt1GJuFRMd1JKfBiQvyNcuF1XfqOd+6"
        + "gj+SDbPuJb/re1/TUzeReP+mHce1zWeOdjthYPOaSgO2LdOyllPFzWPezpPe7rfVzVO"
        + "6Hb/vz8f7f2eGJdOKMee54XeBiR/Z5XeNlSfyVfPJtT++ikf7i3POrnPGun9+VhOVSM"
        + "vzo499/as1EJup5YPvUy+abi+tjRPNrS91aPfCCafyxn/SCaNVZPeu7r+B+ad1WOOuy"
        + "pOm3rPt6W/OikPvq5vCmlt6Qf/ygivp2V/OTfPrb1eKfkP7Z0OyBaeibiuieju+ciu2"
        + "ejeKCbOatn+2YhOFVN+eRfedWNvWplvLRyuF4Xs5kTdlOL+3Eu+1mR/zp5fzq5dVMLt"
        + "JTOPvDtvKgjvy1pe9yVchFKeafj+WYh/nBs/HIvv3Ctd9YONdVOM5BI8pXP/jUzOqKd"
        + "OiMd9toUN1iSONuU8HBwYmJifX19f///////yH/C1hNUCBEYXRhWE1QPD94cGFja2V0"
        + "IGJlZ2luPSLvu78iIGlkPSJXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQiPz4gPHg6eG1"
        + "wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyIgeDp4bXB0az0iQWRvYmUgWE1QIE"
        + "NvcmUgNS4wLWMwNjEgNjQuMTQwOTQ5LCAyMDEwLzEyLzA3LTEwOjU3OjAxICAgICAgI"
        + "CAiPiA8cmRmOlJERiB4bWxuczpyZGY9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkvMDIv"
        + "MjItcmRmLXN5bnRheC1ucyMiPiA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0iIiB"
        + "4bWxuczp4bXBNTT0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL21tLyIgeG1sbn"
        + "M6c3RSZWY9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9zVHlwZS9SZXNvdXJjZ"
        + "VJlZiMiIHhtbG5zOnhtcD0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wLyIgeG1w"
        + "TU06T3JpZ2luYWxEb2N1bWVudElEPSJ4bXAuZGlkOkEyRDgxODE2MkMyMDY4MTE4NzF"
        + "GRDNDMzU5QkE3OTE3IiB4bXBNTTpEb2N1bWVudElEPSJ4bXAuZGlkOkMzMjA1M0I4Qk"
        + "M4RjExRTBCRDBEQkE0MTlGMTc4MDZGIiB4bXBNTTpJbnN0YW5jZUlEPSJ4bXAuaWlkO"
        + "jlFQzFFMTZFQkM4RDExRTBCRDBEQkE0MTlGMTc4MDZGIiB4bXA6Q3JlYXRvclRvb2w9"
        + "IkFkb2JlIFBob3Rvc2hvcCBDUzUuMSBNYWNpbnRvc2giPiA8eG1wTU06RGVyaXZlZEZ"
        + "yb20gc3RSZWY6aW5zdGFuY2VJRD0ieG1wLmlpZDpDMjFGMUIwQjMyMjA2ODExODcxRk"
        + "QzQzM1OUJBNzkxNyIgc3RSZWY6ZG9jdW1lbnRJRD0ieG1wLmRpZDpBMkQ4MTgxNjJDM"
        + "jA2ODExODcxRkQzQzM1OUJBNzkxNyIvPiA8L3JkZjpEZXNjcmlwdGlvbj4gPC9yZGY6"
        + "UkRGPiA8L3g6eG1wbWV0YT4gPD94cGFja2V0IGVuZD0iciI/PgH//v38+/r5+Pf29fT"
        + "z8vHw7+7t7Ovq6ejn5uXk4+Lh4N/e3dzb2tnY19bV1NPS0dDPzs3My8rJyMfGxcTDws"
        + "HAv769vLu6ubi3trW0s7KxsK+urayrqqmop6alpKOioaCfnp2cm5qZmJeWlZSTkpGQj"
        + "46NjIuKiYiHhoWEg4KBgH9+fXx7enl4d3Z1dHNycXBvbm1sa2ppaGdmZWRjYmFgX15d"
        + "XFtaWVhXVlVUU1JRUE9OTUxLSklIR0ZFRENCQUA/Pj08Ozo5ODc2NTQzMjEwLy4tLCs"
        + "qKSgnJiUkIyIhIB8eHRwbGhkYFxYVFBMSERAPDg0MCwoJCAcGBQQDAgEAACH5BAEAAP"
        + "8ALAAAAAAyAJoAAAj/AP+h8EGwoMGDCBMqXOgDxb8ZUphInEixosWLGDMykTLDB5CPI"
        + "EOKHEmypEmQBImoXMmypcuXMGOuJDikps2bOHPq3MnTJsEmQJv4G0rUX9CjSJMqXXqU"
        + "4JSnRaM+nWKMxtBXy6Y8gvZoqtevYL8SpEK2KJWiCsjSMIPNlCUC6lj5u7eLrN27ePO"
        + "SJcilb1EuaPvSQaZBnAUJGkT487DCTBwulOj4M8OCSxw6vvwxYzH5cV8uBK+IHiq69F"
        + "Bgoh0MPcHCAgnF7+zFIKArw4kAufxFw+AvBixiODo18IeqNEEryItaKdoGuRUEHgj4I"
        + "6Aqkr8CIeT422QF0wEX13f4/xvEi1y9A9ob6EF+PDnR5USbW8EQydElaf4aWC/giHcb"
        + "eGbYkcB12rWhhxkCSJBAAgXMwJ4PYkQYVVEXRIgDHp+IMYI/7Rzijw4c2ODPBf4kIw8"
        + "1H/IwohgZCJDKBxAcwkGEBI1h4xgTjniBjSMMQBQuF4DwYYgjpuMPBKX4c4qKO44wzl"
        + "AlDMOBjQRhYaWVW2Sp5RZXYkEIJLUosAUDWACwBQBYBMLlLfgwwMCZalr5pQZbZHMlQ"
        + "U7kqeeefOq5BgA19LnnGoEK6sQaa+xJUBGMNuroo5BGKumkjRKExKWYZqrpppx26imm"
        + "PsyAiBKklmrqqaimquqqSiAyw0MMxf8q66yv/lPID7jmquuuvPbq668/FPIPGyGcZOy"
        + "xyIbAxg9JNOvss9BGK+201DqL6xHYZqvtttx26+232eJqxLjklmvuueimqy65uELhLh"
        + "Q5vivvvPTWa6+8uEqhb45D6SuFKOes5oAUgrggiL8IJ6xwwrhG4bBZRRnisDtqaKNCN"
        + "wQEgMB1Mzjs8ccgh+xwww8TBRhREkfxxgCDXIJCA4NsHAw5atQRxS9v+KOGHVHU8YZ4"
        + "rdihs80e40rG0aSVdsVQDxzdzFB4gPLBMKP4E441LewRTwmVKCCLP95w408LnlwzziQ"
        + "G+KPP0WTgCsbbyhUFw9tgbFAMKf7s8YGQimz/cYM/cwtjAAT+KPL3BB0MIIABfz+zzd"
        + "u4liF53ETNIfkfvTBSjjL+aBKNP3cw8oc/c4SSSCxwgO4K6bMk8gI7cMBxBziS4/rF7"
        + "fz648bttLSwyheZ+KMMBf70wccxuvszzTqcFC+J7l8s8II5+URAAR+34xrG9mHkeMYZ"
        + "23+QA1ERnEF8H42g488ZsPgTgTP+qFDN+mGIP9QCtjSyPa5Z9N9/FwAMYBf8l4VFTKA"
        + "CD+iCDLJggi6YIAt5GCA+6CEDGTgwgv0z4De6MA//4eoJIAyhCEcYwhSkoAckFOEJUw"
        + "hCE4oQV0KIoQxnSMMa2vCGOJQhroLAwx768IdADKIQ/4fYwx8Awg9LSKISl8jEJjrxi"
        + "VBcgh8AMSxgWfGKWGTDP/6hhX148YtgDKMYx0jGMu5DC1zsR+7WyMY2FqUfXXSjHOc4"
        + "IS/S8Y5ztCMe97hGPfLxj1HxIyAHKchB/rGQhtwjIhN5x0UyMo/7eOQhIylJRVKyko2"
        + "8JCYhuclMdpKOjvxkjkIpykBqspS5IyUqh6LKVbYSla8sZSxFOctP1rKTt9xkLjG5y0"
        + "r2UpJnTMMqc5cGNHbRjGVU4xuRSUY0bvGZ0IymNLe4D2X6ox/7mKY2t8lNblbzmtnsp"
        + "jjHuc1IhpOc6EznP86pzmiigR/wjKc850nPetrznvxAwz+8UP+FfvjznwANqEAHStCC"
        + "9qMKXuCHQRfK0Ib6E54OjahE/wnRiVqUoRW9qEYHmtGNevShCv2oSDsqUo2StKQWPSl"
        + "KJarSlTq0pS7FaEhjOlGY0rSgNr0pR2eq04bmtKcA/SlQQTpUn/K0qAQV6lCVClSm9t"
        + "SpOoXqTaVKU6rG1KouxepKtYpSfvATqQVF6D7xic9+ArQKZLWnF9oZTX6Y9aD8YKtc2"
        + "9pPtM71rs90a1zxyte98vWZx2SmYL/oTHRqwZqPhGM6T/lIdoqTsYx0bDchm0jJehOX"
        + "i8UsOb+py80i1pfj5KxmvflZXoa2tMD0rC3RKVrQsna0oYXtY2U7WdplclMLwqxkMdU"
        + "Z2MEKtrDofGdahytPfabzqzEVKzqPutV0Mrerzo1qdKc63aou961XJadbnzrO7XK3m9"
        + "79Lnixa93ukjer15XuctWrXfZ2173ifG5J/TpO5LpUuehMKHH3u1ZxBgQAOw==);";
    assertSanitizedCss(null, longUrl);
  }

  @Test
  void testUrls() {
    assertSanitizedCss(
        "background-image:url('foo.gif#sanitized')",
        "background-image: \"foo.gif\"");
    assertSanitizedCss(
        "background-image:url('foo.gif#sanitized')",
        "background-image: 'foo.gif'");
    assertSanitizedCss(
        "background-image:url('foo.gif#sanitized')",
        "background-image:url(foo.gif)");
    assertSanitizedCss(
        "background-image:url('foo.gif#sanitized')",
        "background-image : url( foo.gif )");
    assertSanitizedCss(
        "background-image:url('foo.gif#sanitized')",
        "background-image: url('foo.gif')");
    assertSanitizedCss(
        "background-image:url('foo.gif#sanitized')",
        "background-image: URL( \"foo.gif\" )");
  }

  @Test
  void testImportant() {
    assertSanitizedCss(
        "color:blue !important",
        "color:blue !important");
    assertSanitizedCss(
        "color:red !important",
        "color:red ! IMPORTANT");
    assertSanitizedCss(
        "color:purple",
        "color:purple !foo(bar) important");
  }

  @Test
  void testCdoCdc() {
    // No <!-- or --> in output.
    assertSanitizedCss("font-family:'a--' 'b'", "font-family: a--\\>b");
    assertSanitizedCss("font-family:'a' '--b'", "font-family: a<\\!--b");
    assertSanitizedCss("font-family:'a--' 'b'", "font-family: a-->b");
    assertSanitizedCss("font-family:'a b'", "font-family: a<!--b");
  }

  /** A schema that opts into the layout families the way callers would. */
  private static final CssSchema LAYOUT = CssSchema.union(
      CssSchema.DEFAULT,
      CssSchema.withProperties(Arrays.asList(
          "display", "grid-template-columns", "grid-template-rows",
          "grid-auto-flow", "grid-column", "grid-row", "gap", "row-gap",
          "column-gap", "flex", "flex-direction", "flex-wrap", "flex-grow",
          "flex-basis", "order", "justify-content", "align-items",
          "align-self", "transform", "transform-origin",
          "repeat()", "minmax()", "fit-content()", "transform-function()",
          "calc()")));

  /** Issue #228: the text-decoration longhands and a richer shorthand. */
  @Test
  void testTextDecorationLonghands() {
    assertSanitizedCss(
        "text-decoration-line:line-through", "text-decoration-line: line-through");
    assertSanitizedCss("text-decoration-style:wavy", "text-decoration-style: wavy");
    assertSanitizedCss("text-decoration-color:red", "text-decoration-color: red");
    assertSanitizedCss(
        "text-decoration-thickness:2px", "text-decoration-thickness: 2px");
    assertSanitizedCss(
        "text-decoration:underline dotted red",
        "text-decoration: underline dotted red");
    assertSanitizedCss(null, "text-decoration-line: url(javascript:alert(1))");
  }

  /** Issue #265: SVG stroke paint, but never a paint-server URL. */
  @Test
  void testStroke() {
    assertSanitizedCss(
        "stroke-width:4;stroke:rgb( 138 , 232 , 242 )",
        "stroke-width: 4; stroke: rgb(138,232,242)");
    assertSanitizedCss("stroke:none", "stroke: none");
    assertSanitizedCss(null, "stroke: url(#paintserver)");
    assertSanitizedCss(null, "stroke: url('javascript:alert%281337%29')");
  }

  /** Issue #380 item 6: conic gradients alongside linear and radial. */
  @Test
  void testConicGradient() {
    assertSanitizedCss(
        "background:conic-gradient( red , blue )",
        "background: conic-gradient(red, blue)");
    assertSanitizedCss(
        "background-image:repeating-conic-gradient( red , blue )",
        "background-image: repeating-conic-gradient(red, blue)");
  }

  /**
   * DEFAULT withholds layout control, so none of the modern layout families
   * are reachable without opting in.  This is the security-relevant half of
   * the change and it must keep failing closed.
   */
  @Test
  void testLayoutRequiresOptIn() {
    assertSanitizedCss(null, "display: block");
    assertSanitizedCss(null, "display: none");
    assertSanitizedCss(null, "display: flex");
    assertSanitizedCss(null, "display: grid");
    assertSanitizedCss(null, "grid-template-columns: 1fr 280px");
    assertSanitizedCss(null, "gap: 10px");
    assertSanitizedCss(null, "flex: 1 1 auto");
    assertSanitizedCss(null, "order: -5");
    assertSanitizedCss(null, "justify-content: center");
    assertSanitizedCss(null, "transform: translate(-9999px, 0)");
  }

  /** Issues #242 and #234: flex and grid for a policy that opts in. */
  @Test
  void testFlexAndGridWhenOptedIn() {
    assertSanitizedCss(LAYOUT, "display:flex", "display: flex");
    assertSanitizedCss(
        LAYOUT, "display:flex;flex-direction:column",
        "display: flex; flex-direction: column");
    assertSanitizedCss(LAYOUT, "flex:1 1 auto", "flex: 1 1 auto");
    assertSanitizedCss(LAYOUT, "order:-1", "order: -1");
    assertSanitizedCss(
        LAYOUT, "justify-content:space-between", "justify-content: space-between");
    assertSanitizedCss(LAYOUT, "display:grid", "display: grid");
    // The exact value from issue #234.
    assertSanitizedCss(
        LAYOUT,
        "display:grid;grid-template-columns:repeat( auto-fit , minmax( 160px , 1fr ) )",
        "display: grid; grid-template-columns: repeat( auto-fit, minmax(160px, 1fr) )");
    // The exact value from issue #380 item 1.
    assertSanitizedCss(
        LAYOUT, "grid-template-columns:1fr 280px",
        "grid-template-columns: 1fr 280px");
    assertSanitizedCss(LAYOUT, "gap:10px 20px", "gap: 10px 20px");
    assertSanitizedCss(LAYOUT, "grid-column:1 / 3", "grid-column: 1 / 3");
  }

  /** Issue #71: transform functions for a policy that opts in. */
  @Test
  void testTransformWhenOptedIn() {
    assertSanitizedCss(
        LAYOUT, "transform:rotate( 30deg ) translate( 10px , 20px )",
        "transform: rotate(30deg) translate(10px, 20px)");
    assertSanitizedCss(
        LAYOUT, "transform:matrix( 1 , 0 , 0 , 1 , 10 , 20 )",
        "transform: matrix(1, 0, 0, 1, 10, 20)");
    assertSanitizedCss(LAYOUT, "transform:none", "transform: none");
    assertSanitizedCss(LAYOUT, "transform-origin:top left", "transform-origin: top left");
    // A transform function is not a way to smuggle a URL or a script.  The
    // payload is dropped and an empty function shell is left behind, which is
    // how rgb(), linear-gradient() and calc() have always behaved.
    assertSanitizedCss(
        LAYOUT, "transform:translate( )",
        "transform: translate(url(javascript:alert(1)))");
    assertSanitizedCss(LAYOUT, null, "transform: expression(alert(1))");
    assertSanitizedCss(
        LAYOUT, "transform:translate( )",
        "transform: translate(expression(alert(1)))");
  }

  /**
   * position:fixed escapes a scrolling container, so opting into layout must
   * not bring it along.
   */
  @Test
  void testFixedPositioningStaysBlockedWhenOptedIn() {
    CssSchema withPosition = CssSchema.union(
        CssSchema.DEFAULT, CssSchema.withProperties(Arrays.asList("position")));
    assertSanitizedCss(withPosition, "position:absolute", "position: absolute");
    assertSanitizedCss(withPosition, null, "position: fixed");
    assertSanitizedCss(withPosition, null, "position: sticky");
  }

  /**
   * The cap sits between these two lengths, so one URL survives and the other
   * takes its whole property with it.  1024 used to sit between them, which is
   * what #187 was about.
   */
  @Test
  void testLongCssUrlsAreKeptUpToTheLengthCap() {
    String under = "http://example.com/" + repeat("a", 1500);
    String over = "http://example.com/" + repeat("a", 2100);

    assertSanitizedCss(
        "background-image:url('" + under + "#sanitized')",
        "background-image: url(" + under + ")");
    assertSanitizedCss(null, "background-image: url(" + over + ")");
  }

  private static String repeat(String s, int n) {
    StringBuilder sb = new StringBuilder(s.length() * n);
    for (int i = 0; i < n; ++i) {
      sb.append(s);
    }
    return sb.toString();
  }

  private static void assertSanitizedCss(
      @Nullable String expectedCss, String css) {
    assertSanitizedCss(CssSchema.DEFAULT, expectedCss, css);
  }

  private static void assertSanitizedCss(
      CssSchema cssSchema, @Nullable String expectedCss, String css) {
    StylingPolicy stylingPolicy = new StylingPolicy(
        cssSchema,
        url -> {
          String safeUrl =
              StandardUrlAttributePolicy.INSTANCE.apply("img", "src", url);
          return safeUrl != null ? safeUrl + "#sanitized" : null;
        });
    assertEquals(expectedCss, stylingPolicy.sanitizeCssProperties(css));
  }
}
