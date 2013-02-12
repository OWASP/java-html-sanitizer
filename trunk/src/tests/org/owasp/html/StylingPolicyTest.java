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

import javax.annotation.Nullable;

import junit.framework.TestCase;

public class StylingPolicyTest extends TestCase {
  public final void testNothingToOutput() {
    assertSanitizedCss(null, "");
    assertSanitizedCss(null, "/** no CSS here */");
    assertSanitizedCss(null, "/* props: disabled; font-weight: bold */");
    assertSanitizedCss(null, "position: fixed");
    assertSanitizedCss(
        null, "background: url('javascript:alert%281337%29')");
  }

  public final void testColors() {
    assertSanitizedCss("color:#f00", "color: red");
    assertSanitizedCss(
        "background-color:#f00", "background: #f00");
    assertSanitizedCss("color:#f00", "color: #F00");
    assertSanitizedCss(null, "color: #F000");
    assertSanitizedCss("color:#ff0000", "color: #ff0000");
    assertSanitizedCss(
        "color:#f00", "color: rgb(255, 0, 0)");
    assertSanitizedCss(
        "background-color:#f00", "background: rgb(100%, 0, 0)");
    assertSanitizedCss(
        "color:#f00", "color: rgba(100%, 0, 0, 100%)");
    assertSanitizedCss(null, "color: transparent");
    assertSanitizedCss(null, "color: bogus");
    assertSanitizedCss(null, "color: expression(alert(1337))");
    assertSanitizedCss(null, "color: 000");
    assertSanitizedCss(null, "background-color: 000");
    // Not colors.
    assertSanitizedCss(null, "background: \"pwned.jpg\"");
    assertSanitizedCss(null, "background: url(pwned.jpg)");
    assertSanitizedCss(null, "color:#urlabc");
    assertSanitizedCss(null, "color:#urlabcd");
  }

  public final void testFontWeight() {
    assertSanitizedCss(
        "font-weight:bold", "font-weight: bold");
    assertSanitizedCss(
        "font-weight:bold", "font: bold");
    assertSanitizedCss(
        "font-weight:bolder", "font: Bolder");
    assertSanitizedCss(
        "font-weight:800", "font-weight: 800");
    assertSanitizedCss(
        null, "font-weight: expression(alert(1337))");
    assertSanitizedCss(
        "font-family:\"ecute evil\"",
        "font: 3execute evil");
  }

  public final void testFontStyle() {
    assertSanitizedCss(
        "font-style:italic", "font-style: Italic");
    assertSanitizedCss(
        "font-style:italic", "font: italic");
    assertSanitizedCss(
        "font-style:oblique", "font: Oblique");
    assertSanitizedCss(
        null, "font-style: expression(alert(1337))");
  }

  public final void testFontFace() {
    assertSanitizedCss(
        "font-family:\"arial\",\"helvetica\"", "font: Arial, Helvetica");
    assertSanitizedCss(
        "font-family:\"Arial\",\"Helvetica\",sans-serif",
        "Font-family: Arial, Helvetica, sans-serif");
    assertSanitizedCss(
        "font-family:\"Monospace\",sans-serif",
        "Font-family: \"Monospace\", Sans-serif");
    assertSanitizedCss(
        "font-family:\"Arial Bold\",\"helvetica\",monospace",
        "FONT: \"Arial Bold\", Helvetica, monospace");
    assertSanitizedCss(
        "font-family:\"Arial Bold\",\"Helvetica\"",
        "font-family: \"Arial Bold\", Helvetica");
    assertSanitizedCss(
        "font-family:\"Arial Bold\",\"Helvetica\"",
        "font-family: 'Arial Bold', Helvetica");
    assertSanitizedCss(
        "font-family:\"3ex ecute evil\"",
        "font-family: 3execute evil");
    assertSanitizedCss(
        "font-family:\"Arial Bold\",\"Helvetica\",sans-serif",
        "font-family: 'Arial Bold',,\"\",Helvetica,sans-serif");
  }

  public final void testFont() {
    assertSanitizedCss(
        "font-family:\"arial\";"
        + "font-weight:bold;font-size:12pt;font-style:oblique",
        "font: Arial 12pt bold oblique");
    assertSanitizedCss(
        "font-family:\"Times New Roman\";font-weight:bolder;font-size:24px",
        "font: \"Times New Roman\" 24px bolder");
    assertSanitizedCss("font-size:24px", "font: 24px");
    // Non-ascii characters discarded.
    assertSanitizedCss(null, "font: 24ex\\pression");
    // Harmless garbage.
    assertSanitizedCss(
        "font-family:\"pression\"", "font: 24ex\0pression");
    assertSanitizedCss(
        "font-family:\"expression arial\"", "font: expression(arial)");
    assertSanitizedCss(
        null, "font: rgb(\"expression(alert(1337))//\")");
    assertSanitizedCss("font-size:smaller", "font-size: smaller");
    assertSanitizedCss("font-size:smaller", "font: smaller");
  }

  public final void testBidiAndAlignmentAttributes() {
    assertSanitizedCss(
        "text-align:left;direction:ltr;unicode-bidi:embed",
        "Text-align: left; Unicode-bidi: Embed; Direction: LTR;");
    assertSanitizedCss(
        "text-align:left", "text-align:expression(left())");
    assertSanitizedCss(null, "text-align: bogus");
    assertSanitizedCss(
        "unicode-bidi:embed", "unicode-bidi:expression(embed)");
    assertSanitizedCss(null, "unicode-bidi:bogus");
    assertSanitizedCss(
        "direction:ltr", "direction:expression(ltr())");
  }

  public final void testTextDecoration() {
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

  public final void testSanitizeColor() {
    assertEquals(null, StylingPolicy.sanitizeColor(""));
    assertEquals(null, StylingPolicy.sanitizeColor("bogus"));
    assertEquals(null, StylingPolicy.sanitizeColor("javascript:evil"));
    assertEquals(null, StylingPolicy.sanitizeColor("expression(evil)"));
    assertEquals(null, StylingPolicy.sanitizeColor("moz-binding"));
    assertEquals(null, StylingPolicy.sanitizeColor("rgb()"));
    assertEquals(null, StylingPolicy.sanitizeColor("rgba()"));
    assertEquals(null, StylingPolicy.sanitizeColor("rgb(255, 255)"));
    assertEquals(null, StylingPolicy.sanitizeColor("rgb(256, 0, 0)"));
    assertEquals(null, StylingPolicy.sanitizeColor("rgb(0, 120%, 0)"));
    assertEquals("#fff", StylingPolicy.sanitizeColor("white"));
    assertEquals("#000", StylingPolicy.sanitizeColor("black"));
    assertEquals("#f00", StylingPolicy.sanitizeColor("red"));
    assertEquals("#f00", StylingPolicy.sanitizeColor("red"));
    assertEquals("#fa8072", StylingPolicy.sanitizeColor("salmon"));
    assertEquals("#ff0080", StylingPolicy.sanitizeColor("rgb(255, 0, 128)"));
    assertEquals("#ff0080", StylingPolicy.sanitizeColor("rgb(255,0,128)"));
    assertEquals("#ff007f", StylingPolicy.sanitizeColor("rgb(100%,0,50%)"));
    assertEquals(
        "#ff0080", StylingPolicy.sanitizeColor("rgba(100%,0,128,255)"));
    assertEquals("#ff0080", StylingPolicy.sanitizeColor("RGB(255, 0, 128)"));
    assertEquals(
        "#550102", StylingPolicy.sanitizeColor("Rgb( 33.333% , .9 , .9% )"));
    assertEquals(
        "#540000", StylingPolicy.sanitizeColor("Rgb( 33.03% , .09 , .09% )"));
  }

  private static void assertIsNotNonEmptyAsciiAlnumSpaceSeparated(String s) {
    assertFalse(s, StylingPolicy.isNonEmptyAsciiAlnumSpaceSeparated(s));
  }
  private static void assertIsNonEmptyAsciiAlnumSpaceSeparated(String s) {
    assertTrue(s, StylingPolicy.isNonEmptyAsciiAlnumSpaceSeparated(s));
  }
  public final void testIsNonEmptyAsciiAlnumSpaceSeparated() {
    assertIsNotNonEmptyAsciiAlnumSpaceSeparated("");
    assertIsNotNonEmptyAsciiAlnumSpaceSeparated(" ");

    assertIsNotNonEmptyAsciiAlnumSpaceSeparated("\u002f");
    assertIsNonEmptyAsciiAlnumSpaceSeparated("0");
    assertIsNonEmptyAsciiAlnumSpaceSeparated("9");
    assertIsNotNonEmptyAsciiAlnumSpaceSeparated("\u003a");
    assertIsNotNonEmptyAsciiAlnumSpaceSeparated("\u0040");
    assertIsNonEmptyAsciiAlnumSpaceSeparated("A");
    assertIsNonEmptyAsciiAlnumSpaceSeparated("Z");
    assertIsNotNonEmptyAsciiAlnumSpaceSeparated("\u005b");
    assertIsNotNonEmptyAsciiAlnumSpaceSeparated("\u0060");
    assertIsNonEmptyAsciiAlnumSpaceSeparated("a");
    assertIsNonEmptyAsciiAlnumSpaceSeparated("z");
    assertIsNotNonEmptyAsciiAlnumSpaceSeparated("\u007b");

    assertIsNotNonEmptyAsciiAlnumSpaceSeparated("Arial/Helvetica");
    assertIsNotNonEmptyAsciiAlnumSpaceSeparated("Arial#Helvetica");
    assertIsNotNonEmptyAsciiAlnumSpaceSeparated("!Arial Helvetica");
    assertIsNotNonEmptyAsciiAlnumSpaceSeparated("Arial Helvetica!");
    assertIsNotNonEmptyAsciiAlnumSpaceSeparated("Arial Helve!tica");
    assertIsNotNonEmptyAsciiAlnumSpaceSeparated("Arial\u0000Helvetica");
    assertIsNotNonEmptyAsciiAlnumSpaceSeparated("<script>evil()</script>");
    assertIsNotNonEmptyAsciiAlnumSpaceSeparated("Arial\uFF26elvetica");
    assertIsNonEmptyAsciiAlnumSpaceSeparated("x y");
    assertIsNonEmptyAsciiAlnumSpaceSeparated(" x y ");
    assertIsNonEmptyAsciiAlnumSpaceSeparated("foo");
    assertIsNonEmptyAsciiAlnumSpaceSeparated(" foo ");
    assertIsNonEmptyAsciiAlnumSpaceSeparated("foo bar");
    assertIsNonEmptyAsciiAlnumSpaceSeparated(" foo 92 ");
    assertIsNonEmptyAsciiAlnumSpaceSeparated("Foo  Bar");
    assertIsNonEmptyAsciiAlnumSpaceSeparated("Arial Helvetica");
  }

  private void assertSanitizedCss(@Nullable String expectedCss, String css) {
    assertEquals(expectedCss, StylingPolicy.sanitizeCssProperties(css));
  }
}
