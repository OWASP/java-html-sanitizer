// Copyright (c) 2013, Mike Samuel
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
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class CssSchemaTest {

  @Test
  void testDangerousProperties() {
    for (String key : new String[] {
          // May allow escaping informal visual containment when embedders are
          // not particular about establishing a clipping region.
          "display",
          "float",
          "clear",
          "left",
          "right",
          // May ease trusted path violations by allowing links to impersonate
          // controls in the embedding page.
          "cursor",
          // Allows code execution.
          "-moz-binding",
          // Prefix corner cases.
          "-",
          "-moz-",
          "-ms-",
          "-o-",
          "-webkit-",
        }) {
      assertSame(CssSchema.DISALLOWED, CssSchema.DEFAULT.forKey(key), key);
    }
  }

  @Test
  void testDangerousTokens() {
    for (String propName : CssSchema.DEFAULT_WHITELIST) {
      CssSchema.Property property = CssSchema.DEFAULT.forKey(propName);
      assertFalse(
          property.literals.contains("expression"),
          propName);
      assertFalse(
          property.fnKeys.containsKey("expression("),
          propName);
      assertFalse(
          property.literals.contains("url"),
          propName);
      assertFalse(
          property.fnKeys.containsKey("url("),
          propName);
    }
  }

  @Test
  void testCalcIsScopedToSizingProperties() {
    Set<String> withCalc = new TreeSet<>();
    for (Map.Entry<String, CssSchema.Property> e
         : CssSchema.DEFINITIONS.entrySet()) {
      if (e.getValue().fnKeys.containsKey("calc(")) {
        withCalc.add(e.getKey());
      }
    }
    assertEquals(
        new TreeSet<>(Arrays.asList(
            // Sizing properties, which are in DEFAULT.
            "height", "max-height", "max-width",
            "min-height", "min-width", "width",
            // Grid track sizing, where calc() is equally valid CSS.  These
            // are definitions only -- none of them is in DEFAULT_WHITELIST --
            // so this does not widen what a bare allowStyling() accepts.
            "grid", "grid-auto-columns", "grid-auto-rows", "grid-template",
            "grid-template-columns", "grid-template-rows", "repeat()")),
        withCalc);
    assertTrue(CssSchema.DEFAULT_WHITELIST.contains("calc()"));
    CssSchema.Property calc = CssSchema.DEFAULT.forKey("calc()");
    assertNotSame(CssSchema.DISALLOWED, calc);
    // Operands are quantities only: no strings, URLs, colors, words or
    // nested functions.
    assertEquals(CssSchema.BIT_QUANTITY | CssSchema.BIT_NEGATIVE, calc.bits);
    assertTrue(calc.fnKeys.isEmpty());
  }

  @Test
  void testCssWideKeywordsAllowedOnEveryProperty() {
    for (Map.Entry<String, CssSchema.Property> e
         : CssSchema.DEFINITIONS.entrySet()) {
      String key = e.getKey();
      // Keys ending in "()" describe a function's arguments rather than a
      // property, and must not pick the keywords up: "initial" is a value
      // for "color", not for a channel of "rgb(...)".
      boolean isFunction = key.endsWith("()");
      for (String keyword : CssSchema.CSS_WIDE_KEYWORDS) {
        assertEquals(
            !isFunction,
            e.getValue().literals.contains(keyword),
            key + " should" + (isFunction ? " not" : "") + " allow " + keyword);
      }
    }
  }

  /**
   * DEFAULT withholds every property that changes how an element takes part
   * in page layout, so that a style attribute can restyle content but cannot
   * reposition it, overlay something else, or hide it.  Adding the modern
   * layout families to the definitions must not erode that.
   */
  @Test
  void testDefaultGrantsNoLayoutControl() {
    List<String> layoutProperties = Arrays.asList(
        "display", "position", "float", "clear", "overflow", "overflow-x",
        "overflow-y", "z-index", "opacity", "visibility", "top", "left",
        "right", "bottom", "transform", "transform-origin",
        "grid", "grid-area", "grid-auto-flow", "grid-column", "grid-row",
        "grid-template", "grid-template-areas", "grid-template-columns",
        "grid-template-rows", "grid-auto-columns", "grid-auto-rows",
        "grid-column-start", "grid-column-end", "grid-row-start",
        "grid-row-end", "gap", "row-gap", "column-gap",
        "grid-gap", "grid-row-gap", "grid-column-gap",
        "flex", "flex-basis", "flex-direction", "flex-flow", "flex-grow",
        "flex-shrink", "flex-wrap", "order",
        "align-content", "align-items", "align-self", "justify-content",
        "justify-items", "justify-self", "place-content", "place-items",
        "place-self");
    for (String propName : layoutProperties) {
      assertFalse(
          CssSchema.DEFAULT_WHITELIST.contains(propName),
          propName + " must not be in DEFAULT");
      assertSame(
          CssSchema.DISALLOWED, CssSchema.DEFAULT.forKey(propName),
          propName + " must be disallowed by DEFAULT");
    }
  }

  /**
   * position:fixed and position:sticky escape a scrolling container, so they
   * are withheld even from a policy that opts into layout.  That floor lives
   * in the literal set rather than the whitelist, so opting in must not
   * reach it.
   */
  @Test
  void testFixedPositioningIsWithheldEvenWhenOptingIn() {
    CssSchema.Property position = CssSchema.DEFINITIONS.get("position");
    assertTrue(position.literals.contains("absolute"));
    assertTrue(position.literals.contains("relative"));
    assertTrue(position.literals.contains("static"));
    assertFalse(position.literals.contains("fixed"));
    assertFalse(position.literals.contains("sticky"));
  }

  /** The layout families are defined, so a caller can union them into DEFAULT. */
  @Test
  void testLayoutFamiliesAreDefinedForOptIn() {
    for (String propName : Arrays.asList(
        "grid-template-columns", "grid-column", "gap", "flex",
        "flex-direction", "order", "justify-content", "align-items",
        "transform", "repeat()", "minmax()", "fit-content()")) {
      assertNotSame(
          CssSchema.DISALLOWED, CssSchema.DEFINITIONS.get(propName),
          propName);
    }
    CssSchema.Property display = CssSchema.DEFINITIONS.get("display");
    assertTrue(display.literals.contains("flex"), "display:flex");
    assertTrue(display.literals.contains("grid"), "display:grid");
  }

  /**
   * The decorative additions do go into DEFAULT, but stroke must not become a
   * URL vector: "stroke: url(#paintserver)" is valid CSS we deliberately
   * decline to support.
   */
  @Test
  void testDecorativeAdditionsAreInDefaultAndTakeNoUrl() {
    for (String propName : Arrays.asList(
        "text-decoration-line", "text-decoration-style", "text-decoration-color",
        "text-decoration-thickness", "stroke", "stroke-width",
        "conic-gradient()", "repeating-conic-gradient()")) {
      assertTrue(
          CssSchema.DEFAULT_WHITELIST.contains(propName), propName);
      assertNotSame(
          CssSchema.DISALLOWED, CssSchema.DEFAULT.forKey(propName), propName);
    }
    CssSchema.Property stroke = CssSchema.DEFAULT.forKey("stroke");
    assertEquals(0, stroke.bits & CssSchema.BIT_URL);
    assertFalse(stroke.fnKeys.containsKey("url("));
  }

  /** #380 item 4: a DEFAULT property can be widened without rebuilding. */
  @Test
  void testWithOverridesCanWidenADefaultProperty() {
    CssSchema.Property style = CssSchema.DEFAULT.property("text-decoration-style");
    assertFalse(style.literals().contains("zigzag"));
    CssSchema widened = CssSchema.DEFAULT.withOverrides(
        Collections.singletonMap(
            "text-decoration-style", style.withLiterals("zigzag")));
    assertTrue(
        widened.property("text-decoration-style").literals().contains("zigzag"));
    // The schema it was derived from is untouched.
    assertFalse(
        CssSchema.DEFAULT.property("text-decoration-style")
            .literals().contains("zigzag"));
    // Everything else came along.
    assertTrue(widened.allowedProperties().contains("color"));
  }

  /** #380 item 4: and narrowed, which is the safe direction. */
  @Test
  void testWithOverridesCanNarrowADefaultProperty() {
    CssSchema narrowed = CssSchema.DEFAULT.withOverrides(
        Collections.singletonMap(
            "color", CssSchema.DEFAULT.property("color").withoutLiterals("red")));
    assertFalse(narrowed.property("color").literals().contains("red"));
    assertTrue(narrowed.property("color").literals().contains("blue"));
    assertTrue(CssSchema.DEFAULT.property("color").literals().contains("red"));
  }

  /**
   * #380 item 5: an override may name a function the base schema already
   * defines, without the caller supplying that definition again.
   */
  @Test
  void testWithOverridesResolvesFunctionKeysAgainstTheBase() {
    CssSchema.Property borderColor =
        CssSchema.DEFAULT.property("border-top-color");
    CssSchema extended = CssSchema.DEFAULT.withOverrides(
        Collections.singletonMap(
            "border-top-color",
            borderColor.withFunctions(Collections.singletonMap(
                "linear-gradient(", "linear-gradient()"))));
    assertTrue(
        extended.property("border-top-color").fnKeys()
            .containsKey("linear-gradient("));
    // Building the same property standalone still fails, because there the
    // function really would be unreachable.
    Map<String, CssSchema.Property> standalone = new HashMap<>();
    standalone.put("border-top-color",
                   borderColor.withFunctions(Collections.singletonMap(
                       "linear-gradient(", "linear-gradient()")));
    try {
      CssSchema.withProperties(standalone);
      throw new AssertionError("expected a self-containment failure");
    } catch (IllegalArgumentException ex) {
      // It names the property and whichever function key it reached first
      // -- border-top-color already refers to rgb(), hsl() and friends.
      assertTrue(ex.getMessage().contains("border-top-color"), ex.getMessage());
      assertTrue(ex.getMessage().contains("withOverrides"), ex.getMessage());
    }
  }

  /** A dangling function key in an override is still an error. */
  @Test
  void testWithOverridesRejectsADanglingFunctionKey() {
    try {
      CssSchema.DEFAULT.withOverrides(Collections.singletonMap(
          "color",
          new CssSchema.Property(
              0, Collections.<String>emptySet(),
              Collections.singletonMap("nope(", "nope()"))));
      throw new AssertionError("expected a dangling function key to be rejected");
    } catch (IllegalArgumentException ex) {
      assertTrue(ex.getMessage().contains("nope()"), ex.getMessage());
    }
  }

  /** union still refuses to pick a winner; that is what withOverrides is for. */
  @Test
  void testUnionStillRefusesToReconcile() {
    CssSchema narrowed = CssSchema.DEFAULT.withOverrides(
        Collections.singletonMap(
            "color", CssSchema.DEFAULT.property("color").withoutLiterals("red")));
    try {
      CssSchema.union(CssSchema.DEFAULT, narrowed);
      throw new AssertionError("expected union to refuse");
    } catch (IllegalArgumentException ex) {
      assertTrue(ex.getMessage().contains("color"), ex.getMessage());
    }
  }

  /** A property this schema does not allow reads as null, not DISALLOWED. */
  @Test
  void testPropertyAccessor() {
    assertNotSame(null, CssSchema.DEFAULT.property("color"));
    assertEquals(null, CssSchema.DEFAULT.property("position"));
    assertEquals(null, CssSchema.DEFAULT.property("no-such-property"));
    // Case-insensitive, like forKey.
    assertEquals(
        CssSchema.DEFAULT.property("color"), CssSchema.DEFAULT.property("COLOR"));
  }

  /**
   * Literals are matched against a lower-cased token, so a literal that is not
   * lower case could never match.  Canonicalizing in the constructor keeps a
   * hand-built property from silently allowing nothing -- and, more to the
   * point, keeps withoutLiterals("RED") from silently removing nothing and
   * leaving a caller believing they narrowed the schema.
   */
  @Test
  void testPropertyLiteralsAreCanonicalized() {
    CssSchema.Property p = new CssSchema.Property(
        0, Collections.singleton("ZigZag"),
        Collections.singletonMap("RGB(", "rgb()"));
    assertTrue(p.literals().contains("zigzag"));
    assertFalse(p.literals().contains("ZigZag"));
    assertTrue(p.fnKeys().containsKey("rgb("));

    CssSchema.Property widened =
        CssSchema.DEFAULT.property("text-decoration-style").withLiterals("ZigZag");
    assertTrue(widened.literals().contains("zigzag"));

    CssSchema.Property narrowed =
        CssSchema.DEFAULT.property("color").withoutLiterals("RED");
    assertFalse(narrowed.literals().contains("red"), "RED should remove red");
    assertTrue(narrowed.literals().contains("blue"));
  }

  /** #423: combining policies must narrow, never widen. */
  @Test
  void testIntersection() {
    CssSchema color = CssSchema.withProperties(Arrays.asList("color"));
    CssSchema width = CssSchema.withProperties(Arrays.asList("width"));
    CssSchema both = CssSchema.withProperties(Arrays.asList("color", "width"));

    assertEquals(
        Collections.emptySet(),
        CssSchema.intersection(color, width).allowedProperties());
    assertEquals(
        Collections.singleton("color"),
        CssSchema.intersection(both, color).allowedProperties());
    assertEquals(
        Collections.singleton("color"),
        CssSchema.intersection(color, both).allowedProperties());
    // A single schema intersects to itself; none of them is an error rather
    // than the universal schema.
    assertSame(color, CssSchema.intersection(color));
    try {
      CssSchema.intersection();
      throw new AssertionError("expected intersecting nothing to be rejected");
    } catch (IllegalArgumentException expected) {
      // pass
    }
  }

  /**
   * Where two schemas define the same property differently, the definitions
   * intersect too, so the result is never wider than either input.
   */
  @Test
  void testIntersectionNarrowsAConflictingProperty() {
    CssSchema.Property colorProp = CssSchema.DEFAULT.property("color");
    CssSchema noRed = CssSchema.DEFAULT.withOverrides(
        Collections.singletonMap("color", colorProp.withoutLiterals("red")));
    CssSchema noBlue = CssSchema.DEFAULT.withOverrides(
        Collections.singletonMap("color", colorProp.withoutLiterals("blue")));

    CssSchema.Property merged =
        CssSchema.intersection(noRed, noBlue).property("color");
    assertFalse(merged.literals().contains("red"));
    assertFalse(merged.literals().contains("blue"));
    assertTrue(merged.literals().contains("green"));

    // A function survives only where both sides agree on its argument schema.
    CssSchema noRgb = CssSchema.DEFAULT.withOverrides(
        Collections.singletonMap(
            "color",
            new CssSchema.Property(
                colorProp.bits(), colorProp.literals(),
                Collections.<String, String>emptyMap())));
    assertTrue(CssSchema.DEFAULT.property("color").fnKeys().containsKey("rgb("));
    assertFalse(
        CssSchema.intersection(CssSchema.DEFAULT, noRgb)
            .property("color").fnKeys().containsKey("rgb("));
  }

  @Test
  void testCustom() {
    CssSchema custom = CssSchema.union(
        CssSchema.DEFAULT,
        CssSchema.withProperties(Collections.singleton("float"))
    );
    for (String key : CssSchema.DEFINITIONS.keySet()) {
      if (!key.equals("float")) {
        assertSame(custom.forKey(key), CssSchema.DEFAULT.forKey(key), key);
      }
    }
    CssSchema.Property cssFloat = custom.forKey("float");
    assertTrue(cssFloat.literals.contains("left"), "left in float");
  }

}
