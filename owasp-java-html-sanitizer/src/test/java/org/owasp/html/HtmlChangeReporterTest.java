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

import java.util.ArrayList;
import java.util.Arrays;
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

  /**
   * {@link ElementPolicy#apply} may return another element name, and the
   * reporter used to decide whether a tag survived by comparing names, so a
   * renamed element was reported as discarded and, because a discarded tag's
   * attributes are not reported, its attribute drops went unreported too
   * (#435).
   */
  @Test
  void testRenamedElementIsNotReportedAsDiscarded() {
    Result result = sanitize(
        renamingSpanToDiv(), "<span id=a id=b>hi</span>");

    assertEquals("<div id=\"a\">hi</div>", result.html);
    assertEquals("<span id> ", result.log);
  }

  /** Attribute reports on a renamed element carry the input element name. */
  @Test
  void testRejectedAttributesOnARenamedElementAreReported() {
    Result result = sanitize(
        renamingSpanToDiv(), "<span id=a onclick=alert(1)>hi</span>");

    assertEquals("<div id=\"a\">hi</div>", result.html);
    assertEquals("<span onclick> ", result.log);
  }

  @Test
  void testRenamedElementWithNothingDroppedReportsNothing() {
    Result result = sanitize(renamingSpanToDiv(), "<span id=a>hi</span>");

    assertEquals("<div id=\"a\">hi</div>", result.html);
    assertEquals("", result.log);
  }

  /**
   * Renames {@code span} to {@code div}.  {@code div} is allowed as well so
   * that text inside the renamed element is kept: the policy decides whether
   * an element may hold text by the name it is emitted under.
   */
  private static PolicyFactory renamingSpanToDiv() {
    return new HtmlPolicyBuilder()
        .allowElements((elementName, attrs) -> "div", "span")
        .allowElements("div")
        .allowAttributes("id").onElements("span")
        .toFactory();
  }

  /**
   * An element the policy allows but skips when attribute-less goes when
   * every attribute on it is rejected.  The attributes are still reported:
   * rejecting them was the policy's decision, and the tag went as a
   * consequence (#447).  Each is also reported with its value (#243).
   */
  @Test
  void testAttributesRejectedFromAnElementThenSkippedAreReported() {
    PolicyFactory p = new HtmlPolicyBuilder()
        .allowElements("span")
        .allowAttributes("id").onElements("span")
        .toFactory();
    Result result = sanitizeVerbose(p, "<span onclick=x>hi</span>");

    assertEquals("hi", result.html);
    assertEquals("<span> <span onclick> span.onclick=\"x\" ", result.log);
  }

  /** The intrusion-detection case from #447: the rejected URL is the signal. */
  @Test
  void testRejectedUrlOnASkippedLinkIsReportedWithItsValue() {
    Result result = sanitizeVerbose(
        Sanitizers.LINKS, "<a href=\"javascript:alert(1)\">x</a>");

    assertEquals("x", result.html);
    assertEquals(
        "<a> <a href> a.href=\"javascript:alert(1)\" ", result.log);
  }

  /** Attributes on an element the policy does not allow go with the tag. */
  @Test
  void testAttributesOnADisallowedElementAreNotReported() {
    Result result = sanitizeVerbose(
        Sanitizers.FORMATTING, "<div onclick=x>hi</div>");

    assertEquals("hi", result.html);
    assertEquals("<div> ", result.log);
  }

  /** Nothing to report but the tag when it had no attributes to begin with. */
  @Test
  void testSkippedAttributelessElementReportsOnlyTheTag() {
    Result result = sanitizeVerbose(Sanitizers.LINKS, "<a>x</a>");

    assertEquals("x", result.html);
    assertEquals("<a> ", result.log);
  }

  /** A kept element reports as before, and now with the values. */
  @Test
  void testRejectedAttributesOnAKeptElementAreReportedWithValues() {
    Result result = sanitizeVerbose(
        Sanitizers.FORMATTING, "<b onclick=\"alert(42)\" title=t>x</b>");

    assertEquals("<b>x</b>", result.html);
    assertEquals(
        "<b onclick title> b.onclick=\"alert(42)\" b.title=\"t\" ",
        result.log);
  }

  /** Each dropped copy of a repeated attribute carries its own value. */
  @Test
  void testEachDroppedCopyOfARepeatedAttributeReportsItsOwnValue() {
    Result result = sanitizeVerbose(
        Sanitizers.LINKS,
        "<a href=\"https://www.example.org/\" href=\"/one\" href=\"/two\">"
        + "link</a>");

    assertEquals(
        "<a href=\"https://www.example.org/\" rel=\"nofollow\">link</a>",
        result.html);
    assertEquals(
        "<a href href> a.href=\"/one\" a.href=\"/two\" ", result.log);
  }

  /** The value reported is the input value after character references. */
  @Test
  void testReportedValueIsTheDecodedInputValue() {
    Result result = sanitizeVerbose(
        Sanitizers.FORMATTING, "<b onclick=\"a&amp;b&lt;c\">x</b>");

    assertEquals("<b>x</b>", result.html);
    assertEquals("<b onclick> b.onclick=\"a&b<c\" ", result.log);
  }

  /** An attribute the policy rewrote was kept, so nothing is reported. */
  @Test
  void testARewrittenAttributeIsNotReported() {
    PolicyFactory p = new HtmlPolicyBuilder()
        .allowElements("a")
        .allowAttributes("href")
            .matching(
                (element, attribute, url) -> "https://example.com/go?u=" + url)
            .onElements("a")
        .allowUrlProtocols("https")
        .toFactory();
    Result result = sanitizeVerbose(p, "<a href=\"x\">l</a>");

    assertEquals(
        "<a href=\"https://example.com/go?u&#61;x\">l</a>", result.html);
    assertEquals("", result.log);
  }

  /**
   * The renderer drops the content of a script or style element that it
   * cannot emit without a browser reading it differently, such as a
   * {@code -->} with no comment open.  That loss happens downstream of the
   * policy and used to be invisible to the listener (#155, from #153).
   */
  @Test
  void testUnrenderableScriptContentIsReported() {
    Result result = sanitizeVerbose(
        scriptAndStyleWithText(), "<script>x --> y</script>");

    assertEquals("<script></script>", result.html);
    assertEquals("script{x --> y} ", result.log);
  }

  /** A comment opened and never closed is the other unrenderable shape. */
  @Test
  void testUnrenderableStyleContentIsReported() {
    Result result = sanitizeVerbose(
        scriptAndStyleWithText(), "<style>a{} <!-- b > c</style>");

    assertEquals("<style></style>", result.html);
    assertEquals("style{a{} <!-- b > c} ", result.log);
  }

  /** Content the renderer can emit is not reported. */
  @Test
  void testRenderableScriptContentIsNotReported() {
    Result result = sanitizeVerbose(
        scriptAndStyleWithText(), "<script><!-- x --></script>");

    assertEquals("<script><!-- x --></script>", result.html);
    assertEquals("", result.log);
  }

  /**
   * A tag in kept literal content reaches the policy as text, so the policy's
   * removal of it must use the text channel rather than the tag channel.
   * Issue #468.
   */
  @Test
  void testTagRemovedFromKeptLiteralContentIsReportedAsText() {
    Result result = sanitizeVerbose(
        scriptAndStyleWithText(),
        "<style>.x{}<div id=\"evil\">XSS?</div>y{}</style>");

    assertEquals("<style>.x{}y{}</style>", result.html);
    assertEquals("style{<div id=\"evil\">XSS?</div>} ", result.log);
  }

  /** Each report contains only the exact input range the policy removed. */
  @Test
  void testPolicyReportsSeparateLiteralTextDropsExactly() {
    Result result = sanitizeVerbose(
        scriptAndStyleWithText(),
        "<style>a<div>x</div>b</noscript>c</style>");

    assertEquals("<style>abc</style>", result.html);
    assertEquals(
        "style{<div>x</div>} style{</noscript>} ", result.log);
  }

  /** Policy and renderer drops are both reported, without overlap. */
  @Test
  void testPolicyAndRendererTextDropsAreBothReported() {
    Result result = sanitizeVerbose(
        scriptAndStyleWithText(),
        "<style>a<div>x</div>-->b</style>");

    assertEquals("<style></style>", result.html);
    assertEquals("style{<div>x</div>} style{a-->b} ", result.log);
  }

  /** A postprocessor rewrite is not a policy rejection and is not reported. */
  @Test
  void testPostprocessorTextRewriteIsNotReported() {
    PolicyFactory policy = new HtmlPolicyBuilder()
        .allowElements("style")
        .allowTextIn("style")
        .withPostprocessor(r -> new HtmlStreamEventReceiverWrapper(r) {
          @Override
          public void text(String text) {
            underlying.text(text.replace("red", "blue"));
          }
        })
        .toFactory();
    Result result = sanitizeVerbose(
        policy, "<style>.x{color:red}</style>");

    assertEquals("<style>.x{color:blue}</style>", result.html);
    assertEquals("", result.log);
  }

  /**
   * The reported container is the literal name emitted by an element policy.
   */
  @Test
  void testPolicyDropUsesAdjustedLiteralElementName() {
    PolicyFactory policy = new HtmlPolicyBuilder()
        .allowElements((elementName, attrs) -> "style", "div")
        .allowTextIn("style")
        .toFactory();
    Result result = sanitizeVerbose(
        policy, "<div>a&lt;img onerror=alert(1)&gt;b</div>");

    assertEquals("<style>ab</style>", result.html);
    assertEquals("style{<img onerror=alert(1)>} ", result.log);
  }

  /** Policy-side drops do not depend on HtmlStreamRenderer's callback. */
  @Test
  void testPolicyDroppedTextReachesListenerWithAForeignReceiver() {
    final List<String> dropped = new ArrayList<>();
    HtmlChangeListener<Object> listener =
        textAndTagCollector(dropped, new ArrayList<String>());
    StringBuilder out = new StringBuilder();
    final HtmlStreamRenderer renderer =
        HtmlStreamRenderer.create(out, Handler.DO_NOTHING);
    HtmlStreamEventReceiver foreign = new HtmlStreamEventReceiver() {
      public void openDocument() { renderer.openDocument(); }

      public void closeDocument() { renderer.closeDocument(); }

      public void openTag(String elementName, List<String> attrs) {
        renderer.openTag(elementName, attrs);
      }

      public void closeTag(String elementName) {
        renderer.closeTag(elementName);
      }

      public void text(String text) { renderer.text(text); }
    };

    HtmlSanitizer.sanitize(
        "<style>a<div>x</div>b</style>",
        scriptAndStyleWithText().apply(foreign, listener, null));

    assertEquals("<style>ab</style>", out.toString());
    assertEquals(Arrays.asList("style:<div>x</div>"), dropped);
  }

  /**
   * The convenience method renders with HtmlStreamRenderer, so dropped
   * content reaches the listener, as it does through the library's own
   * receiver wrapper around one.  A sanitizer built on some other receiver
   * has no renderer to hear from and reports tags and attributes only.
   */
  @Test
  void testDroppedTextReachesTheListenerOnlyThroughTheRenderer() {
    final List<String> dropped = new ArrayList<>();
    final List<String> tags = new ArrayList<>();
    HtmlChangeListener<Object> listener =
        textAndTagCollector(dropped, tags);
    PolicyFactory p = scriptAndStyleWithText();
    String html = "<script>x --> y</script><b>z</b>";

    assertEquals("<script></script>z", p.sanitize(html, listener, null));
    assertEquals(Arrays.asList("script:x --> y"), dropped);
    assertEquals(Arrays.asList("b"), tags);

    // Through the library's wrapper, which a postprocessor would extend.
    dropped.clear();
    tags.clear();
    StringBuilder out = new StringBuilder();
    HtmlStreamEventReceiver wrapped = new HtmlStreamEventReceiverWrapper(
        HtmlStreamRenderer.create(out, Handler.DO_NOTHING)) {
      // Forwards everything; only its type differs from the renderer's.
    };
    HtmlSanitizer.sanitize(html, p.apply(wrapped, listener, null));

    assertEquals("<script></script>z", out.toString());
    assertEquals(Arrays.asList("script:x --> y"), dropped);
    assertEquals(Arrays.asList("b"), tags);

    // Through a receiver of some other kind, which cannot be seen through.
    dropped.clear();
    tags.clear();
    final StringBuilder out2 = new StringBuilder();
    final HtmlStreamRenderer renderer =
        HtmlStreamRenderer.create(out2, Handler.DO_NOTHING);
    HtmlStreamEventReceiver foreign = new HtmlStreamEventReceiver() {
      public void openDocument() { renderer.openDocument(); }

      public void closeDocument() { renderer.closeDocument(); }

      public void openTag(String elementName, List<String> attrs) {
        renderer.openTag(elementName, attrs);
      }

      public void closeTag(String elementName) {
        renderer.closeTag(elementName);
      }

      public void text(String text) { renderer.text(text); }
    };
    HtmlSanitizer.sanitize(html, p.apply(foreign, listener, null));

    assertEquals("<script></script>z", out2.toString());
    assertEquals(Arrays.asList(), dropped);
    assertEquals(Arrays.asList("b"), tags);
  }

  /**
   * A reporter listens to the renderer for one document.  The renderer,
   * reused for another document without that reporter, must not go on
   * reporting to it under the old context.
   */
  @Test
  void testARenderersNextDocumentDoesNotReportToTheLastReporter() {
    final List<String> dropped = new ArrayList<>();
    HtmlChangeListener<Object> listener =
        textAndTagCollector(dropped, new ArrayList<String>());
    PolicyFactory p = scriptAndStyleWithText();
    StringBuilder out = new StringBuilder();
    HtmlStreamRenderer renderer =
        HtmlStreamRenderer.create(out, Handler.DO_NOTHING);
    String html = "<script>x --> y</script>";

    HtmlSanitizer.sanitize(html, p.apply(renderer, listener, null));
    assertEquals(Arrays.asList("script:x --> y"), dropped);

    dropped.clear();
    HtmlSanitizer.sanitize(html, p.apply(renderer));
    assertEquals("<script></script><script></script>", out.toString());
    assertEquals(Arrays.asList(), dropped);
  }

  /** Collects dropped text as {@code element:text} and discarded tags. */
  private static HtmlChangeListener<Object> textAndTagCollector(
      final List<String> dropped, final List<String> tags) {
    return new HtmlChangeListener<Object>() {
      public void discardedTag(Object context, String elementName) {
        tags.add(elementName);
      }

      public void discardedAttributes(
          Object context, String tagName, String... attributeNames) {
        // Not under test.
      }

      @Override
      public void discardedText(
          Object context, String elementName, String text) {
        dropped.add(elementName + ":" + text);
      }
    };
  }

  /** Keeps script and style with their content, as a template host might. */
  private static PolicyFactory scriptAndStyleWithText() {
    return new HtmlPolicyBuilder()
        .allowElements("script", "style")
        .allowTextIn("script", "style")
        .toFactory();
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
    return sanitize(policy, html, false);
  }

  /**
   * Like {@link #sanitize} but also records each discarded attribute's value
   * and any dropped text; see {@link #verboseListener}.
   */
  private static Result sanitizeVerbose(PolicyFactory policy, String html) {
    return sanitize(policy, html, true);
  }

  private static Result sanitize(
      PolicyFactory policy, String html, boolean verbose) {
    Context testContext = new Context();
    StringBuilder out = new StringBuilder();
    StringBuilder log = new StringBuilder();
    HtmlStreamRenderer renderer = HtmlStreamRenderer.create(
        out, Handler.DO_NOTHING);
    HtmlChangeListener<Context> listener = verbose
        ? verboseListener(testContext, log)
        : loggingListener(testContext, log);
    HtmlChangeReporter<Context> hcr = new HtmlChangeReporter<>(
        renderer, listener, testContext);
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

  /**
   * Logs as {@link #loggingListener} does, and additionally each discarded
   * attribute's value as {@code tag.attr="value"} and dropped text as
   * {@code element{text}}.
   */
  private static HtmlChangeListener<Context> verboseListener(
      final Context expectedContext, final StringBuilder log) {
    final HtmlChangeListener<Context> base =
        loggingListener(expectedContext, log);
    return new HtmlChangeListener<Context>() {
      public void discardedTag(Context context, String elementName) {
        base.discardedTag(context, elementName);
      }

      public void discardedAttributes(
          Context context, String tagName, String... attributeNames) {
        base.discardedAttributes(context, tagName, attributeNames);
      }

      @Override
      public void discardedAttribute(
          Context context, String tagName, String attributeName,
          String attributeValue) {
        assertSame(expectedContext, context);
        log.append(tagName).append('.').append(attributeName)
            .append("=\"").append(attributeValue).append("\" ");
      }

      @Override
      public void discardedText(
          Context context, String elementName, String text) {
        assertSame(expectedContext, context);
        log.append(elementName).append('{').append(text).append("} ");
      }
    };
  }
}
