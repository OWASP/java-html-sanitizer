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
import java.util.function.Function;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** Tests {@link CssSchema#toAttributePolicy}. */
final class CssSchemaAttributePolicyTest {

  private static final CssSchema TEXT_SCHEMA = CssSchema.withProperties(
      Arrays.asList("color", "background-color"));
  private static final CssSchema BOX_SCHEMA = CssSchema.withProperties(
      Arrays.asList("width", "height"));
  private static final CssSchema IMAGE_SCHEMA = CssSchema.withProperties(
      Arrays.asList("background-image", "background-position"));

  /** The motivating use case from issue #381: a schema per element. */
  @Test
  void testDifferentSchemasOnDifferentElements() {
    PolicyFactory policy = new HtmlPolicyBuilder()
        .allowElements("span", "div")
        .allowAttributes("style")
            .matching(TEXT_SCHEMA.toAttributePolicy())
            .onElements("span")
        .allowAttributes("style")
            .matching(BOX_SCHEMA.toAttributePolicy())
            .onElements("div")
        .toFactory();

    assertEquals(
        "<span style=\"color:red\">x</span>",
        policy.sanitize("<span style=\"color: red; width: 10px\">x</span>"));
    assertEquals(
        "<div style=\"width:10px\">x</div>",
        policy.sanitize("<div style=\"color: red; width: 10px\">x</div>"));
  }

  /**
   * A property allowed on one element does not leak onto an element whose own
   * schema omits it, and a style attribute left with nothing goes away.
   */
  @Test
  void testStyleDroppedEntirelyWhenNothingSurvives() {
    PolicyFactory policy = new HtmlPolicyBuilder()
        .allowElements("span", "div")
        .allowAttributes("style")
            .matching(BOX_SCHEMA.toAttributePolicy())
            .onElements("div")
        .toFactory();

    assertEquals(
        "<div>x</div>",
        policy.sanitize("<div style=\"color: red\">x</div>"));
    // No policy at all for style on span, so it is not allowed there, and a
    // span with no attributes is elided by default.
    assertEquals(
        "x",
        policy.sanitize("<span style=\"width: 10px\">x</span>"));
  }

  /** The no-arg factory is not wired to any URL policy, so it drops URLs. */
  @Test
  void testUrlsDroppedByDefault() {
    PolicyFactory policy = new HtmlPolicyBuilder()
        .allowElements("div")
        .allowStandardUrlProtocols()
        .allowAttributes("style")
            .matching(IMAGE_SCHEMA.toAttributePolicy())
            .onElements("div")
        .toFactory();

    // The url() token goes, and with it the only value of the property.
    assertEquals(
        "<div>x</div>",
        policy.sanitize(
            "<div style=\"background-image: url(http://example.com/i.png)\">"
            + "x</div>"));
    // Surviving values of an allowed property are kept.
    assertEquals(
        "<div style=\"background-position:left\">x</div>",
        policy.sanitize(
            "<div style=\"background-image: url(http://example.com/i.png);"
            + " background-position: left\">x</div>"));
  }

  /** The caller's rewriter sees the URL and decides. */
  @Test
  void testUrlRewriterHonored() {
    Function<String, String> rewriter = new Function<String, String>() {
      public String apply(String url) {
        return url.startsWith("http://example.com/")
            ? url + "?vetted" : null;
      }
    };
    PolicyFactory policy = new HtmlPolicyBuilder()
        .allowElements("div")
        .allowAttributes("style")
            .matching(IMAGE_SCHEMA.toAttributePolicy(rewriter))
            .onElements("div")
        .toFactory();

    assertEquals(
        "<div style=\"background-image:url(&#39;"
        + "http://example.com/i.png?vetted&#39;)\">x</div>",
        policy.sanitize(
            "<div style=\"background-image: url(http://example.com/i.png)\">"
            + "x</div>"));
    // Returning null drops the URL.
    assertEquals(
        "<div>x</div>",
        policy.sanitize(
            "<div style=\"background-image: url(http://evil.example/i.png)\">"
            + "x</div>"));
  }

  /** A rewriter never has to cope with a null URL, so it may not be null. */
  @Test
  void testNullUrlRewriterRejected() {
    assertThrows(
        NullPointerException.class,
        () -> TEXT_SCHEMA.toAttributePolicy(null));
  }

  /**
   * A per-element schema and a global {@code allowStyling} schema join to the
   * union of the two, on that element only.
   */
  @Test
  void testJoinsWithGlobalAllowStyling() {
    PolicyFactory policy = new HtmlPolicyBuilder()
        .allowElements("span", "div")
        .allowStyling(BOX_SCHEMA)
        .allowAttributes("style")
            .matching(TEXT_SCHEMA.toAttributePolicy())
            .onElements("span")
        .toFactory();

    assertEquals(
        "<span style=\"color:red;width:10px\">x</span>",
        policy.sanitize("<span style=\"color: red; width: 10px\">x</span>"));
    assertEquals(
        "<div style=\"width:10px\">x</div>",
        policy.sanitize("<div style=\"color: red; width: 10px\">x</div>"));
  }

  /**
   * Joining takes the union of the schemas but the intersection of the URL
   * policies, so a URL-dropping per-element policy is not widened by a
   * permissive global one.
   */
  @Test
  void testJoiningDoesNotWidenUrlPolicy() {
    PolicyFactory policy = new HtmlPolicyBuilder()
        .allowElements("p", "div")
        .allowStandardUrlProtocols()
        .allowStyling(IMAGE_SCHEMA)
        .allowUrlsInStyles(AttributePolicy.IDENTITY_ATTRIBUTE_POLICY)
        .allowAttributes("style")
            .matching(IMAGE_SCHEMA.toAttributePolicy())
            .onElements("div")
        .toFactory();

    // The global policy alone still lets the URL through.
    assertEquals(
        "<p style=\"background-image:url(&#39;http://example.com/i.png&#39;)\">"
        + "x</p>",
        policy.sanitize(
            "<p style=\"background-image: url(http://example.com/i.png)\">"
            + "x</p>"));
    // On div, the per-element policy's veto wins.
    assertEquals(
        "<div>x</div>",
        policy.sanitize(
            "<div style=\"background-image: url(http://example.com/i.png)\">"
            + "x</div>"));
  }

  /**
   * A rewriter signals "dropped" by returning null, which is not a URL, so a
   * joined rewriter is never handed one.
   */
  @Test
  void testCallerRewriterNeverSeesADroppedUrl() {
    Function<String, String> rewriter = new Function<String, String>() {
      public String apply(String url) {
        // Would throw if handed the null that means "dropped".
        return url.startsWith("http://example.com/") ? url : null;
      }
    };
    PolicyFactory policy = new HtmlPolicyBuilder()
        .allowElements("div")
        .allowStandardUrlProtocols()
        // No allowUrlsInStyles, so the global guard vetoes every URL.
        .allowStyling(IMAGE_SCHEMA)
        .allowAttributes("style")
            .matching(IMAGE_SCHEMA.toAttributePolicy(rewriter))
            .onElements("div")
        .toFactory();

    assertEquals(
        "<div>x</div>",
        policy.sanitize(
            "<div style=\"background-image: url(http://example.com/i.png)\">"
            + "x</div>"));
  }

  /** Joined rewriters run in turn, each seeing the previous one's output. */
  @Test
  void testJoinedRewritersRunInTurn() {
    Function<String, String> rewriter = new Function<String, String>() {
      public String apply(String url) {
        return url + "?vetted";
      }
    };
    PolicyFactory policy = new HtmlPolicyBuilder()
        .allowElements("div")
        .allowStandardUrlProtocols()
        .allowStyling(IMAGE_SCHEMA)
        .allowUrlsInStyles(AttributePolicy.IDENTITY_ATTRIBUTE_POLICY)
        .allowAttributes("style")
            .matching(IMAGE_SCHEMA.toAttributePolicy(rewriter))
            .onElements("div")
        .toFactory();

    // The caller's rewrite survives, and the global protocol policy still
    // gets to veto what comes out of it.
    assertEquals(
        "<div style=\"background-image:url(&#39;"
        + "http://example.com/i.png?vetted&#39;)\">x</div>",
        policy.sanitize(
            "<div style=\"background-image: url(http://example.com/i.png)\">"
            + "x</div>"));
    assertEquals(
        "<div>x</div>",
        policy.sanitize(
            "<div style=\"background-image: url(javascript:alert%281%29)\">"
            + "x</div>"));
  }
}
