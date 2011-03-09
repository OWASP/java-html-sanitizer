package org.owasp.html;

import java.util.List;

import junit.framework.TestCase;

public class StylingPolicyTest extends TestCase {
  public final void testNothingToOutput() {
    assertAttributesFromStyle("", "");
    assertAttributesFromStyle("", "/** no CSS here */");
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
        "style=\"font-weight:bold;\"", "font-weight: bold");
    assertAttributesFromStyle(
        "style=\"font-weight:bold;\"", "font: bold");
    assertAttributesFromStyle(
        "style=\"font-weight:bolder;\"", "font: bolder");
    assertAttributesFromStyle(
        "", "font-weight: expression(alert(1337))");
  }

  public final void testFontStyle() {
    assertAttributesFromStyle(
        "style=\"font-style:italic;\"", "font-style: italic");
    assertAttributesFromStyle(
        "style=\"font-style:italic;\"", "font: italic");
    assertAttributesFromStyle(
        "style=\"font-style:oblique;\"", "font: oblique");
    assertAttributesFromStyle(
        "", "font-style: expression(alert(1337))");
  }

  public final void testFontFace() {
    assertAttributesFromStyle(
        "face=\"arial, helvetica\"", "font: Arial, Helvetica");
    assertAttributesFromStyle(
        "face=\"Arial, Helvetica\"", "font-family: Arial, Helvetica");
    assertAttributesFromStyle(
        "face=\"Arial Bold, helvetica\"", "font: \"Arial Bold\", Helvetica");
    assertAttributesFromStyle(
        "face=\"Arial Bold, Helvetica\"",
        "font-family: \"Arial Bold\", Helvetica");
  }

  public final void testFont() {
    assertAttributesFromStyle(
        "face=\"arial\""
        + " style=\"font-weight:bold;font-size:12pt;font-style:oblique;\"",
        "font: Arial 12pt bold oblique");
  }

  public final void testDirectionAttributes() {
    assertAttributesFromStyle(
        "align=\"left\" dir=\"ltr\"",
        "text-align: left; direction: ltr;");
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
