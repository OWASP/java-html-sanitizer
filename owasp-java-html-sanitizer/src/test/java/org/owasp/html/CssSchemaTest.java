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
            "height", "max-height", "max-width",
            "min-height", "min-width", "width")),
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
