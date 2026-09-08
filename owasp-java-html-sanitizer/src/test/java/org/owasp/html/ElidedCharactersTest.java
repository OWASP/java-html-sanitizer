// Copyright (c) 2021, Simon Greatrix
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

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.junit.Test;

import junit.framework.TestCase;

/**
 * Some characters must not appear in HTML documents: the standard treats them
 * as parse errors in the input stream and forbids character references to
 * them.  Others, such as a raw U+000D, are a log injection risk.  These tests
 * check that the sanitizer does not emit such characters, and that dropping
 * one never joins the text around it into a tag, attribute or URL protocol
 * that a policy would have rejected had it seen the joined form.
 *
 * @author Simon Greatrix on 25/01/2021.
 * @see <a href="https://html.spec.whatwg.org/multipage/syntax.html#character-references">HTML 13.1.4 - Character references</a>
 */
@SuppressWarnings("javadoc")
public class ElidedCharactersTest extends TestCase {

  /** Every code point that must not appear in sanitized output. */
  static final List<String> DISCOURAGED;

  static {
    List<String> list = new ArrayList<String>();

    // C0 controls, except the whitespace characters that XML allows.
    // U+000C FORM FEED is elided from text too, but it is ASCII whitespace
    // inside a tag, so it separates tag tokens like a space does; see
    // testFormFeedIsTagWhitespaceButElidedFromText.
    for (char i = 0; i <= 0x1f; i++) {
      if (i != '\t' && i != '\n' && i != '\r' && i != '\f') {
        list.add(Character.toString(i));
      }
    }

    // DEL and the C1 controls, which HTML forbids as character references
    // and XML discourages.  U+0085 NEL is among them: some systems read it
    // as a line break and others as an ellipsis, so it has no safe meaning.
    for (char i = 0x7f; i <= 0x9f; i++) {
      list.add(Character.toString(i));
    }

    // Isolated surrogates.  testSurrogatePairsAreKept checks that a valid
    // pair survives.
    for (char i = 0xd800; i <= 0xdfff; i++) {
      list.add(Character.toString(i));
    }

    // The noncharacters in Arabic Presentation Forms-A.
    for (char i = 0xfdd0; i <= 0xfdef; i++) {
      list.add(Character.toString(i));
    }

    // The last two code points of the BMP and of every supplementary plane.
    list.add(Character.toString((char) 0xfffe));
    list.add(Character.toString((char) 0xffff));
    for (int plane = 1; plane <= 16; plane++) {
      list.add(new String(Character.toChars(0x10000 * plane + 0xfffe)));
      list.add(new String(Character.toChars(0x10000 * plane + 0xffff)));
    }

    DISCOURAGED = Collections.unmodifiableList(list);
  }

  /** Lets through the attributes that the token merging cases aim at. */
  private static final PolicyFactory LINKS_WITH_TITLES = new HtmlPolicyBuilder()
      .allowElements("a", "b")
      .allowAttributes("href", "title").onElements("a")
      .allowStandardUrlProtocols()
      .toFactory();

  private static String describe(String d) {
    return String.format("U+%04X", d.codePointAt(0));
  }

  @Test
  public static final void testRemoveDiscouragedCharacterFromTagStart() {
    // "<?h1>" is text, since '<' is not followed by a letter.
    for (String d : DISCOURAGED) {
      String html = Sanitizers.BLOCKS.sanitize("<" + d + "h1></h1>");
      assertEquals(describe(d), "&lt;h1&gt;", html);
    }
    assertEquals("<h1></h1>", Sanitizers.BLOCKS.sanitize("<h1></h1>"));
  }

  @Test
  public static final void testRemoveDiscouragedCharacterFromInsideTag() {
    // "<h?1>" is an unrecognised element and "</h1>" an unmatched end tag.
    for (String d : DISCOURAGED) {
      String html = Sanitizers.BLOCKS.sanitize("<h" + d + "1></h1>");
      assertEquals(describe(d), "", html);
    }
    assertEquals("<h1></h1>", Sanitizers.BLOCKS.sanitize("<h1></h1>"));
  }

  @Test
  public static final void testRemoveDiscouragedCharacterFromTagEnd() {
    // "<h1?>" is an unrecognised element: the character is not whitespace,
    // so it does not end the tag name.
    for (String d : DISCOURAGED) {
      String html = Sanitizers.BLOCKS.sanitize("<h1" + d + "></h1>");
      assertEquals(describe(d), "", html);
    }
    assertEquals("<h1></h1>", Sanitizers.BLOCKS.sanitize("<h1></h1>"));
  }

  @Test
  public static final void testRemoveDiscouragedCharacterFromEndWhenEncoding()
      throws IOException {
    for (String d : DISCOURAGED) {
      StringBuilder builder = new StringBuilder();
      Encoding.encodePcdataOnto("Hello" + d, builder);
      assertEquals(describe(d), "Hello", builder.toString());
    }
  }

  @Test
  public static final void testRemoveDiscouragedCharacterFromMiddleWhenEncoding()
      throws IOException {
    for (String d : DISCOURAGED) {
      StringBuilder builder = new StringBuilder();
      Encoding.encodePcdataOnto("Hel" + d + "lo", builder);
      assertEquals(describe(d), "Hello", builder.toString());
    }
  }

  @Test
  public static final void testRemoveDiscouragedCharacterFromStartWhenEncoding()
      throws IOException {
    for (String d : DISCOURAGED) {
      StringBuilder builder = new StringBuilder();
      Encoding.encodePcdataOnto(d + "Hello", builder);
      assertEquals(describe(d), "Hello", builder.toString());
    }
  }

  @Test
  public static final void testDiscouragedCharacterIsStrippedWhenDecoding() {
    for (String d : DISCOURAGED) {
      String m = describe(d);
      assertEquals(m, "Hello", Encoding.decodeHtml("Hel" + d + "lo", false));
      assertEquals(m, "Hello", Encoding.decodeHtml("Hel" + d + "lo", true));
      // Stripping happens after references are decoded, so a stripped
      // character cannot turn the text around it into a reference.
      assertEquals(m, "&lt;", Encoding.decodeHtml("&l" + d + "t;", false));
    }
  }

  @Test
  public static final void testDiscouragedCharacterDoesNotHideAScriptTag() {
    for (String d : DISCOURAGED) {
      String m = describe(d);
      // '<' followed by a non-letter is text.
      assertEquals(m, "&lt;script&gt;alert(1)",
          LINKS_WITH_TITLES.sanitize("<" + d + "script>alert(1)</script>"));
      // "<s?cript>" is an unknown element, so its content is ordinary text
      // and the end tag matches nothing.  It must not become <script>.
      assertEquals(m, "alert(1)",
          LINKS_WITH_TITLES.sanitize("<s" + d + "cript>alert(1)</script>"));
      assertEquals(m, "x",
          LINKS_WITH_TITLES.sanitize("<b" + d + ">x</b>"));
    }
  }

  @Test
  public static final void testDiscouragedCharacterDoesNotSplitAnAttribute() {
    for (String d : DISCOURAGED) {
      String m = describe(d);
      // Inside a tag the character is not whitespace, so "a?href=..." is one
      // unknown element name rather than an <a> with an href.
      assertEquals(m, "x",
          LINKS_WITH_TITLES.sanitize(
              "<a" + d + "href=\"javascript:alert(1)\">x</a>"));
      // An unquoted value runs on past the character, so "onclick=alert(1)"
      // stays inside the title value and never becomes an attribute.
      assertEquals(m, "<a href=\"/\" title=\"onclick&#61;alert(1)\">x</a>",
          LINKS_WITH_TITLES.sanitize(
              "<a href=\"/\" title=" + d + "onclick=alert(1)>x</a>"));
      assertEquals(m, "<a href=\"/\" title=\"onclick&#61;alert(1)\">x</a>",
          LINKS_WITH_TITLES.sanitize(
              "<a href=\"/\" title=\"" + d + "onclick=alert(1)\">x</a>"));
    }
  }

  @Test
  public static final void testDiscouragedCharacterDoesNotHideAUrlProtocol() {
    for (String d : DISCOURAGED) {
      String m = describe(d);
      // The character is stripped before the URL policy runs, so the policy
      // sees "javascript:" and rejects it.  Stripping it only on output
      // would let "java?script:" through as an unknown protocol and then
      // emit "javascript:".
      assertEquals(m, "x",
          LINKS_WITH_TITLES.sanitize(
              "<a href=\"java" + d + "script:alert(1)\">x</a>"));
      // Nor can it hide a character reference from the decoder: "&?#58;"
      // stays a literal ampersand, which the encoder escapes.
      assertEquals(m, "<a href=\"javascript&amp;#58;alert%281%29\">x</a>",
          LINKS_WITH_TITLES.sanitize(
              "<a href=\"javascript&" + d + "#58;alert(1)\">x</a>"));
    }
  }

  @Test
  public static final void testSurrogatePairsAreKept() throws IOException {
    StringBuilder sb = new StringBuilder();
    Encoding.encodePcdataOnto("a\ud83d\ude00b", sb);  // U+1F600
    assertEquals("a&#x1f600;b", sb.toString());
    assertEquals(
        "<b>a&#x1f600;b</b>",
        LINKS_WITH_TITLES.sanitize("<b>a\ud83d\ude00b</b>"));
    // The last assigned code point of a plane is kept; the two
    // noncharacters after it are not.
    sb.setLength(0);
    Encoding.encodePcdataOnto("a\ud83f\udffdb\ud83f\udffe\ud83f\udfff", sb);
    assertEquals("a&#x1fffd;b", sb.toString());
  }

  @Test
  public static final void testFormFeedIsTagWhitespaceButElidedFromText()
      throws IOException {
    // U+000C is one of the five ASCII whitespace characters, so inside a tag
    // it separates tokens like a space; it is not an XML character, so it
    // is dropped from text.
    assertEquals("<b>x</b>", LINKS_WITH_TITLES.sanitize("<b\f>x</b>"));
    StringBuilder sb = new StringBuilder();
    Encoding.encodePcdataOnto("a\fb", sb);
    assertEquals("ab", sb.toString());
  }

  @Test
  public static final void testCarriageReturnsAreNormalizedToLineFeeds() {
    // As the HTML input stream preprocessor does, so rendering is unchanged
    // and the output never contains a raw U+000D.
    // CRLF and a lone CR each become LF; LF CR is two line breaks.
    assertEquals("a\nb\nc\n\n", LINKS_WITH_TITLES.sanitize("a\r\nb\rc\n\r"));
    assertEquals("a\nb", LINKS_WITH_TITLES.sanitize("a&#13;b"));
    assertEquals(
        "<a href=\"/\" title=\"a\nb\">x</a>",
        LINKS_WITH_TITLES.sanitize("<a href=\"/\" title=\"a\r\nb\">x</a>"));
  }
}
