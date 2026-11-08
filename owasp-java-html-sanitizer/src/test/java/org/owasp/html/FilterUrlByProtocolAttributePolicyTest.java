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

import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

class FilterUrlByProtocolAttributePolicyTest {
  private static final String[] SLASH_PAIRS = { "//", "/\\", "\\/", "\\\\" };
  private static final String TARGET = "attacker.example/resource";

  private static String[] nulUrls(String pair) {
    return new String[] {
        "\0" + pair + TARGET,
        pair.charAt(0) + "\0" + pair.charAt(1) + TARGET,
        "\0\0" + pair + TARGET,
        pair.charAt(0) + "\0\0" + pair.charAt(1) + TARGET,
        "\0" + pair.charAt(0) + "\0\0" + pair.charAt(1) + TARGET,
        "\0 " + pair + TARGET,
    };
  }

  @Test
  void testNulCannotCreateAnAuthorityAfterValidation() {
    for (AttributePolicy guard : new AttributePolicy[] {
        new FilterUrlByProtocolAttributePolicy(Collections.emptySet()),
        new FilterUrlByProtocolAttributePolicy(Collections.singleton("https")),
        UrlProtocolGuard.NONE, UrlProtocolGuard.RELATIVE_ONLY,
    }) {
      for (String pair : SLASH_PAIRS) {
        assertNull(guard.apply("img", "src", pair + TARGET));
        assertNull(guard.apply("img", "src", pair + "\0" + TARGET));
        for (String url : nulUrls(pair)) {
          assertEquals(encoded(url), guard.apply("img", "src", url));
        }
      }
    }
  }

  @Test
  void testMutableEventApiPreservesNulAsAnEscape() {
    for (String element : new String[] { "img", "script" }) {
      PolicyFactory policy = relativeBuilder(element).toFactory();
      for (String pair : SLASH_PAIRS) {
        for (String url : nulUrls(pair)) {
          assertEquals(markup(element, encoded(url)), eventOutput(policy, element, url));
        }
      }
    }
  }

  @Test
  void testPreprocessorCannotCreateAnAuthorityAfterValidation() {
    for (String element : new String[] { "img", "script" }) {
      PolicyFactory policy = relativeBuilder(element)
          .withPreprocessor(r -> new HtmlStreamEventReceiverWrapper(r) {
            @Override
            public void openTag(String elementName, List<String> attrs) {
              List<String> rewritten = new ArrayList<>();
              for (String attr : attrs) {
                rewritten.add(attr.replace("%00", "\0"));
              }
              underlying.openTag(elementName, rewritten);
            }
          }).toFactory();
      for (String pair : SLASH_PAIRS) {
        for (String url : nulUrls(pair)) {
          assertEquals(markup(element, encoded(url)),
              policy.sanitize(markup(element, url.replace("\0", "%00"))));
        }
      }
    }
  }

  @Test
  void testPlainStringStillRemovesLiteralNulBeforeValidation() {
    for (String element : new String[] { "img", "script" }) {
      PolicyFactory policy = relativeBuilder(element).toFactory();
      String dropped = "img".equals(element) ? "" : "<script></script>";
      for (String pair : SLASH_PAIRS) {
        for (String url : nulUrls(pair)) {
          assertEquals(dropped, policy.sanitize(markup(element, url)));
        }
        for (String entity : new String[] { "&#0;", "&#x0;" }) {
          assertEquals(dropped,
              policy.sanitize(markup(element, entity + pair + TARGET)));
        }
      }
      assertEquals(markup(element, "local.png"),
          policy.sanitize(markup(element, "lo\0cal.png")));
    }
  }

  @Test
  void testRelativeUrlsAndExplicitlyAllowedAuthorities() {
    AttributePolicy relative = UrlProtocolGuard.RELATIVE_ONLY;
    PolicyFactory policy = relativeBuilder("img").toFactory();
    for (String url : new String[] {
        "a/b", "/a", "?q", "#f", "%00//example.org/a", "a%00b",
    }) {
      assertEquals(url, relative.apply("img", "src", url));
      assertEquals(markup("img", url), eventOutput(policy, "img", url));
      assertEquals(markup("img", url), policy.sanitize(markup("img", url)));
    }
    assertEquals("a%00b", relative.apply("img", "src", "a\0b"));
    AttributePolicy web = new FilterUrlByProtocolAttributePolicy(
        Arrays.asList("http", "https"));
    for (String pair : SLASH_PAIRS) {
      assertEquals(pair + TARGET, web.apply("img", "src", pair + TARGET));
    }
    assertEquals("https://example.org/a%00b",
        web.apply("img", "src", "https://example.org/a\0b"));
    assertEquals("https://example.org/a%00b",
        StandardUrlAttributePolicy.INSTANCE.apply("img", "src", "https://example.org/a\0b"));
    assertNull(relative.apply("img", "src", "javascript:alert(1)"));
    assertNull(relative.apply("img", "src", "https://example.org/a"));
  }

  /** Code units the renderer drops, each with the escape the guard emits. */
  private static final String[][] ELIDED = {
      { "\u007f", "%7f" },
      { "\u0080", "%c2%80" },
      { "\u0085", "%c2%85" },
      { "\u009f", "%c2%9f" },
      { "\ufdd0", "%ef%b7%90" },
      { "\ufffe", "%ef%bf%be" },
      { "\uffff", "%ef%bf%bf" },
      { "\ud800", "%ef%bf%bd" },
      { "\udc00", "%ef%bf%bd" },
      { "\ud83f\udffe", "%f0%9f%bf%be" },
      { "\udbff\udfff", "%f4%8f%bf%bf" },
  };

  @Test
  void testElidedCodeUnitsCannotCreateAnAuthorityAfterValidation() {
    PolicyFactory policy = relativeBuilder("img").toFactory();
    PolicyFactory preprocessed = relativeBuilder("img")
        .withPreprocessor(r -> new HtmlStreamEventReceiverWrapper(r) {
          @Override
          public void openTag(String elementName, List<String> attrs) {
            List<String> rewritten = new ArrayList<>();
            for (String attr : attrs) {
              for (String[] e : ELIDED) {
                attr = attr.replace("{" + e[1] + "}", e[0]);
              }
              rewritten.add(attr);
            }
            underlying.openTag(elementName, rewritten);
          }
        }).toFactory();
    for (String[] e : ELIDED) {
      for (String pair : SLASH_PAIRS) {
        for (String url : new String[] {
            pair.charAt(0) + e[0] + pair.charAt(1) + TARGET,
            e[0] + pair + TARGET,
            pair.charAt(0) + e[0] + e[0] + pair.charAt(1) + TARGET,
        }) {
          String expected = url.replace(e[0], e[1]);
          assertEquals(expected,
              UrlProtocolGuard.RELATIVE_ONLY.apply("img", "src", url));
          assertEquals(expected,
              UrlProtocolGuard.NONE.apply("img", "src", url));
          assertEquals(markup("img", expected), eventOutput(policy, "img", url));
          assertEquals(markup("img", expected), preprocessed.sanitize(
              markup("img", url.replace(e[0], "{" + e[1] + "}"))));
          assertEquals("", policy.sanitize(markup("img", url)));
        }
      }
    }
    // Surrogates in the wrong order are two lone surrogates.
    assertEquals("/%ef%bf%bd%ef%bf%bd/" + TARGET,
        UrlProtocolGuard.RELATIVE_ONLY.apply("img", "src", "/\udc00\ud800/" + TARGET));
    // A well-formed supplementary character is not elided, so it stays.
    String emoji = "/\ud83d\ude00/" + TARGET;
    assertEquals(emoji, UrlProtocolGuard.RELATIVE_ONLY.apply("img", "src", emoji));
    assertEquals(markup("img", "/&#x1f600;/" + TARGET),
        eventOutput(policy, "img", emoji));
  }

  @Test
  void testElidedCodeUnitsCannotCreateAnAuthorityInAUrlList() {
    for (String[] tagAndAttr : new String[][] {
        { "img", "srcset" }, { "link", "imagesrcset" },
    }) {
      String element = tagAndAttr[0], attr = tagAndAttr[1];
      PolicyFactory policy = new HtmlPolicyBuilder().allowElements(element)
          .allowAttributes(attr).onElements(element).allowOnlyRelativeUrls()
          .toFactory();
      for (String[] e : new String[][] { { "\0", "%00" }, { "\u0085", "%c2%85" } }) {
        for (String pair : SLASH_PAIRS) {
          String list = "a.png 1x, " + e[0] + pair + TARGET + " 2x";
          StringBuilder out = new StringBuilder();
          HtmlSanitizer.Policy receiver = policy.apply(
              HtmlStreamRenderer.create(out, Handler.DO_NOTHING));
          receiver.openDocument();
          receiver.openTag(element, new ArrayList<>(Arrays.asList(attr, list)));
          receiver.closeTag(element);
          receiver.closeDocument();
          assertEquals("<" + element + " " + attr + "=\"a.png 1x , " + e[1]
              + pair + TARGET + " 2x\" />", out.toString());
        }
      }
    }
  }

  @Test
  void testSupplementaryCharacterAfterSchemeColonPreservesColonLikeCharacters() {
    AttributePolicy web = new FilterUrlByProtocolAttributePolicy(
        Collections.singleton("https"));
    for (String colonLike : new String[] { "\u0589", "\u05c3", "\u2236", "\uff1a" }) {
      String url = "https:\ud83d\ude00" + colonLike + "resource";
      assertEquals(url, FilterUrlByProtocolAttributePolicy.normalizeUri(url));
      assertEquals(url, web.apply("img", "src", url));
    }
  }

  @Test
  void testHundredsOfThousandsOfNulsHaveBoundedExpansion() {
    assertTimeoutPreemptively(Duration.ofSeconds(10), () -> {
      for (int size : new int[] { 100000, 300000 }) {
        char[] nuls = new char[size];
        String url = "/" + new String(nuls) + "/" + TARGET;
        String expected = encoded(url);
        assertEquals(url.length() + 2 * size, expected.length());
        assertEquals(expected, UrlProtocolGuard.RELATIVE_ONLY.apply("img", "src", url));
        assertEquals(markup("img", expected),
            eventOutput(relativeBuilder("img").toFactory(), "img", url));
        char[] surrogates = new char[size];
        Arrays.fill(surrogates, '\ud800');
        String lone = "/" + new String(surrogates) + "/" + TARGET;
        String loneExpected = lone.replace("\ud800", "%ef%bf%bd");
        assertEquals(lone.length() + 8 * size, loneExpected.length());
        assertEquals(loneExpected,
            UrlProtocolGuard.RELATIVE_ONLY.apply("img", "src", lone));
        assertEquals(markup("img", loneExpected),
            eventOutput(relativeBuilder("img").toFactory(), "img", lone));
      }
    });
  }

  private static String encoded(String url) {
    return url.replace("\0", "%00").replace(" ", "%20");
  }

  private static HtmlPolicyBuilder relativeBuilder(String element) {
    return new HtmlPolicyBuilder().allowElements(element)
        .allowAttributes("src").onElements(element).allowOnlyRelativeUrls();
  }

  private static String markup(String element, String url) {
    return "<" + element + " src=\"" + url + "\""
        + ("img".equals(element) ? " />" : "></" + element + ">");
  }

  private static String eventOutput(PolicyFactory policy, String element, String url) {
    StringBuilder out = new StringBuilder();
    HtmlSanitizer.Policy receiver = policy.apply(
        HtmlStreamRenderer.create(out, Handler.DO_NOTHING));
    receiver.openDocument();
    receiver.openTag(element, new ArrayList<>(Arrays.asList("src", url)));
    receiver.closeTag(element);
    receiver.closeDocument();
    return out.toString();
  }
}
