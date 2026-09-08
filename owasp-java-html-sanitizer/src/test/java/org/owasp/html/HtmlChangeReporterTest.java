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

import java.util.List;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

class HtmlChangeReporterTest {

  static class Context {
    // Opaque test value compared via equality.
  }

  @Test
  void testChangeReporting() {
    Result result = sanitize(
        Sanitizers.FORMATTING,
        "<textarea>Hello</textarea>,<b onclick=alert(42)>World</B>!"
        + "<Script type=text/javascript>doEvil()</script><PLAINTEXT>");

    assertEquals("Hello,<b>World</b>!", result.html);
    assertEquals("<textarea> <b onclick> <script> <plaintext> ", result.log);
  }

  /**
   * HTML forbids repeating an attribute name on one tag, so the sanitizer
   * keeps the first and drops the rest.  Those drops used to be invisible to
   * the listener because the surviving attribute left the name in the output.
   */
  @Test
  void testDuplicateAttributesAreReported() {
    Result result = sanitize(
        Sanitizers.LINKS,
        "<a href=\"https://www.example.org/\" HREF=\"javascript:alert(1)\">"
        + "legal link</a>");

    assertEquals(
        "<a href=\"https://www.example.org/\" rel=\"nofollow\">legal link</a>",
        result.html);
    assertEquals("<a href> ", result.log);
  }

  @Test
  void testDuplicateAttributesReportedOncePerExtraCopy() {
    Result result = sanitize(
        Sanitizers.LINKS,
        "<a href=\"https://www.example.org/\" href=\"/one\" href=\"/two\">"
        + "link</a>");

    assertEquals(
        "<a href=\"https://www.example.org/\" rel=\"nofollow\">link</a>",
        result.html);
    assertEquals("<a href href> ", result.log);
  }

  /** Attributes the policy rejects and duplicates arrive in one report. */
  @Test
  void testRejectedAndDuplicateAttributesReportedTogether() {
    Result result = sanitize(
        Sanitizers.LINKS,
        "<a onclick=alert(42) href=\"https://www.example.org/\" href=\"/x\">"
        + "link</a>");

    assertEquals(
        "<a href=\"https://www.example.org/\" rel=\"nofollow\">link</a>",
        result.html);
    assertEquals("<a onclick href> ", result.log);
  }

  /**
   * When the whole tag goes, it is reported as a discarded tag and its
   * attributes are not reported separately, duplicates included.
   */
  @Test
  void testDuplicateAttributesOnADiscardedTagReportOnlyTheTag() {
    Result result = sanitize(
        Sanitizers.FORMATTING,
        "<script src=\"a.js\" SRC=\"b.js\">doEvil()</script>");

    assertEquals("", result.html);
    assertEquals("<script> ", result.log);
  }

  /**
   * The report is a diff against what the policy actually emitted, not a
   * prediction from the input, so a policy that keeps a repeated attribute is
   * not reported as having dropped one.
   */
  @Test
  void testRepeatsThePolicyKeepsAreNotReported() {
    final Context testContext = new Context();
    StringBuilder out = new StringBuilder();
    final StringBuilder log = new StringBuilder();
    HtmlStreamRenderer renderer = HtmlStreamRenderer.create(
        out, Handler.DO_NOTHING);
    HtmlChangeReporter<Context> hcr = new HtmlChangeReporter<>(
        renderer, loggingListener(testContext, log), testContext);
    // A policy that forwards every event through untouched, deduping nothing.
    hcr.setPolicy(new HtmlSanitizer.Policy() {
      final HtmlStreamEventReceiver out = hcr.getWrappedRenderer();

      public void openDocument() { out.openDocument(); }

      public void closeDocument() { out.closeDocument(); }

      public void openTag(String elementName, List<String> attrs) {
        out.openTag(elementName, attrs);
      }

      public void closeTag(String elementName) { out.closeTag(elementName); }

      public void text(String textChunk) { out.text(textChunk); }
    });

    HtmlSanitizer.sanitize("<b id=one id=two>x</b>", hcr.getWrappedPolicy());

    assertEquals("<b id=\"one\" id=\"two\">x</b>", out.toString());
    assertEquals("", log.toString());
  }

  /** The sanitized HTML and the log of what the listener was told about it. */
  static final class Result {
    final String html;
    final String log;

    Result(String html, String log) {
      this.html = html;
      this.log = log;
    }
  }

  /** Sanitizes html under policy, recording every listener notification. */
  private static Result sanitize(PolicyFactory policy, String html) {
    Context testContext = new Context();
    StringBuilder out = new StringBuilder();
    StringBuilder log = new StringBuilder();
    HtmlStreamRenderer renderer = HtmlStreamRenderer.create(
        out, Handler.DO_NOTHING);
    HtmlChangeReporter<Context> hcr = new HtmlChangeReporter<>(
        renderer, loggingListener(testContext, log), testContext);
    hcr.setPolicy(policy.apply(hcr.getWrappedRenderer()));
    HtmlSanitizer.sanitize(html, hcr.getWrappedPolicy());
    return new Result(out.toString(), log.toString());
  }

  /**
   * Appends each notification to log as {@code <tag>} for a discarded tag or
   * {@code <tag attr...>} for discarded attributes.
   */
  private static HtmlChangeListener<Context> loggingListener(
      final Context expectedContext, final StringBuilder log) {
    return new HtmlChangeListener<Context>() {
      public void discardedTag(Context context, String elementName) {
        assertSame(expectedContext, context);
        log.append('<').append(elementName).append("> ");
      }

      public void discardedAttributes(
          Context context, String tagName, String... attributeNames) {
        assertSame(expectedContext, context);
        log.append('<').append(tagName);
        for (String attributeName : attributeNames) {
          log.append(' ').append(attributeName);
        }
        log.append("> ");
      }
    };
  }
}
