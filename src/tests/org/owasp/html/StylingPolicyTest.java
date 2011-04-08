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

import junit.framework.TestCase;

public class StylingPolicyTest extends TestCase {
  public final void testNothingToOutput() {
    assertAttributesFromStyle("", "");
    assertAttributesFromStyle("", "/** no CSS here */");
    assertAttributesFromStyle("", "/* props: disabled; font-weight: bold */");
    assertAttributesFromStyle("", "position: fixed");
    assertAttributesFromStyle(
        "", "background: url('javascript:alert%281337%29')");
  }

  public final void testColors() {
    assertAttributesFromStyle("color=\"red\"", "color: red");
    assertAttributesFromStyle("color=\"#ff0000\"", "color: #f00");
    assertAttributesFromStyle("color=\"#ff0000\"", "color: #ff0000");
    // TODO: do these work in all browsers?
    assertAttributesFromStyle(
        "color=\"rgb( 255, 0, 0)\"", "color: rgb(255, 0, 0)");
    assertAttributesFromStyle(
        "color=\"rgb( 100%, 0, 0)\"", "color: rgb(100%, 0, 0)");
  }

  public final void testFontWeight() {
    assertAttributesFromStyle(
        "style=\"font-weight:bold\"", "font-weight: bold");
    assertAttributesFromStyle(
        "style=\"font-weight:bold\"", "font: bold");
    assertAttributesFromStyle(
        "style=\"font-weight:bolder\"", "font: Bolder");
    assertAttributesFromStyle(
        "", "font-weight: expression(alert(1337))");
  }

  public final void testFontStyle() {
    assertAttributesFromStyle(
        "style=\"font-style:italic\"", "font-style: Italic");
    assertAttributesFromStyle(
        "style=\"font-style:italic\"", "font: italic");
    assertAttributesFromStyle(
        "style=\"font-style:oblique\"", "font: Oblique");
    assertAttributesFromStyle(
        "", "font-style: expression(alert(1337))");
  }

  public final void testFontFace() {
    assertAttributesFromStyle(
        "face=\"arial, helvetica\"", "font: Arial, Helvetica");
    assertAttributesFromStyle(
        "face=\"Arial, Helvetica\"", "Font-family: Arial, Helvetica");
    assertAttributesFromStyle(
        "face=\"Arial Bold, helvetica\"", "FONT: \"Arial Bold\", Helvetica");
    assertAttributesFromStyle(
        "face=\"Arial Bold, Helvetica\"",
        "font-family: \"Arial Bold\", Helvetica");
    assertAttributesFromStyle(
        "face=\"Arial Bold, Helvetica\"",
        "font-family: 'Arial Bold', Helvetica");
  }

  public final void testFont() {
    assertAttributesFromStyle(
        "face=\"arial\""
        + " style=\"font-weight:bold;font-size:12pt;font-style:oblique\"",
        "font: Arial 12pt bold oblique");
  }

  public final void testBidiAndAlignmentAttributes() {
    assertAttributesFromStyle(
        "align=\"left\" style=\"direction:ltr;unicode-bidi:embed\"",
        "Text-align: left; Unicode-bidi: Embed; Direction: LTR;");
  }

  public final void testTextDecoration() {
    assertAttributesFromStyle(
        "style=\"text-decoration:underline\"",
        "Text-Decoration: Underline");
    assertAttributesFromStyle(
        "style=\"text-decoration:overline\"",
        "text-decoration: overline");
    assertAttributesFromStyle(
        "style=\"text-decoration:line-through\"",
        "text-decoration: line-through");
    assertAttributesFromStyle(
        "",
        "text-decoration: expression(document.location=42)");
  }

  private void assertAttributesFromStyle(String expectedAttrs, String css) {
    List<String> attributes = StylingPolicy.cssPropertiesToFontAttributes(css);
    StringBuilder sb = new StringBuilder();
    boolean isName = true;
    for (String attribute : attributes) {
      if (isName) {
        if (sb.length() != 0) { sb.append(' '); }
        sb.append(attribute).append("=\"");
      } else {
        sb.append(attribute.replace("&", "&amp;").replace("\"", "&quot;"))
            .append('"');
      }
      isName = !isName;
    }
    assertEquals(expectedAttrs, sb.toString());
  }
}
