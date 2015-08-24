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

import org.junit.Test;

import junit.framework.TestCase;

@SuppressWarnings("javadoc")
public final class CssSchemaTest extends TestCase {

  @Test
  public static final void testDangerousProperties() {
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
        }) {
      assertSame(key, CssSchema.DISALLOWED, CssSchema.DEFAULT.forKey(key));
    }
  }

  @Test
  public static final void testDangerousTokens() {
    for (String propName : CssSchema.DEFAULT_WHITELIST) {
      CssSchema.Property property = CssSchema.DEFAULT.forKey(propName);
      assertFalse(
          propName,
          property.literals.contains("expression"));
      assertFalse(
          propName,
          property.fnKeys.containsKey("expression("));
      assertFalse(
          propName,
          property.literals.contains("url"));
      assertFalse(
          propName,
          property.fnKeys.containsKey("url("));
    }
  }

  @Test
  public static final void testCustom() {
    CssSchema custom = CssSchema.union(
        CssSchema.DEFAULT,
        CssSchema.withProperties(Collections.singleton("float"))
    );
    for (String key : CssSchema.DEFINITIONS.keySet()) {
      if (!key.equals("float")) {
        assertSame(key, custom.forKey(key), CssSchema.DEFAULT.forKey(key));
      }
    }
    CssSchema.Property cssFloat = custom.forKey("float");
    assertTrue("left in float", cssFloat.literals.contains("left"));
  }

}
