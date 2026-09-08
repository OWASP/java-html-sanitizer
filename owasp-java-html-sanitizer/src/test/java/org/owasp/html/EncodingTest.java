// Copyright (c) 2012, Mike Samuel
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
import java.text.Normalizer;
import java.text.Normalizer.Form;

import org.junit.Test;

import junit.framework.TestCase;

@SuppressWarnings("javadoc")
public final class EncodingTest extends TestCase {
  private static void assertDecodedHtml(String want, String inputHtml) {
    assertDecodedHtml(want, want, inputHtml);
  }

  private static void assertDecodedHtml(
      String wantText, String wantAttr, String inputHtml
  ) {
    assertEquals(
        "!inAttribute: " + inputHtml,
        wantText,
        Encoding.decodeHtml(inputHtml, false)
    );
    assertEquals(
        "inAttribute: " + inputHtml,
        wantAttr,
        Encoding.decodeHtml(inputHtml, true)
    );
  }

  @Test
  public static final void testDecodeHtml() {
    String html =
      "The quick&nbsp;brown fox&#xa;jumps over&#xd;&#10;the lazy dog&#x000a;";
    //          1         2         3         4         5         6
    // 123456789012345678901234567890123456789012345678901234567890123456789
    String golden =
      "The quick\u00a0brown fox\njumps over\r\nthe lazy dog\n";
    assertDecodedHtml(golden, html);

    // Don't allocate a new string when no entities.
    assertSame(golden, golden);

    // test interrupted escapes and escapes at end of file handled gracefully
    assertDecodedHtml("\\\\u000a", "\\\\u000a");
    assertDecodedHtml("\n", "&#x000a;");
    assertDecodedHtml("\n", "&#x00a;");
    assertDecodedHtml("\n", "&#x0a;");
    assertDecodedHtml("\n", "&#xa;");
    assertDecodedHtml(
        String.valueOf(Character.toChars(0x10000)),
        "&#x10000;"
    );
    assertDecodedHtml("\n", "&#xa");
    assertDecodedHtml("&#x00ziggy", "&#x00ziggy");
    assertDecodedHtml("&#xa00z;", "&#xa00z;");
    assertDecodedHtml("&#\n", "&#&#x000a;");
    assertDecodedHtml("&#x\n", "&#x&#x000a;");
    assertDecodedHtml("\n\n", "&#xa&#x000a;");
    assertDecodedHtml("&#\n", "&#&#xa;");
    assertDecodedHtml("&#x", "&#x");
    assertDecodedHtml("", "&#x0"); // NUL elided.
    assertDecodedHtml("&#", "&#");

    assertDecodedHtml("\\", "\\");
    assertDecodedHtml("&", "&");

    assertDecodedHtml("&#000a;", "&#000a;");
    assertDecodedHtml("\n", "&#10;");
    assertDecodedHtml("\n", "&#010;");
    assertDecodedHtml("\n", "&#0010;");
    assertDecodedHtml("\t", "&#9;");
    assertDecodedHtml("\n", "&#10");
    assertDecodedHtml("&#00ziggy", "&#00ziggy");
    assertDecodedHtml("&#\n", "&#&#010;");
    assertDecodedHtml("\n", "&#0&#010;");
    assertDecodedHtml("\n", "&#01&#10;");
    assertDecodedHtml("&#\n", "&#&#10;");
    assertDecodedHtml("", "&#1"); // Invalid XML char elided.
    assertDecodedHtml("\t", "&#9");
    assertDecodedHtml("\n", "&#10");

    // test the named escapes
    assertDecodedHtml("<", "&lt;");
    assertDecodedHtml(">", "&gt;");
    assertDecodedHtml("\"", "&quot;");
    assertDecodedHtml("'", "&apos;");
    assertDecodedHtml("'", "&#39;");
    assertDecodedHtml("'", "&#x27;");
    assertDecodedHtml("&", "&amp;");
    assertDecodedHtml("&lt;", "&amp;lt;");
    assertDecodedHtml("&", "&AMP;");
    assertDecodedHtml("&", "&AMP");
    assertDecodedHtml("&", "&AmP;");
    assertDecodedHtml("\u0391", "&Alpha;");
    assertDecodedHtml("\u03b1", "&alpha;");
    // U+1D49C requires a surrogate pair in UTF-16.
    assertDecodedHtml("\ud835\udc9c", "&Ascr;");
    // &fjlig; refers to 2 characters.
    assertDecodedHtml("fj", "&fjlig;");
    // HTML entity with the longest name.
    assertDecodedHtml("\u2233", "&CounterClockwiseContourIntegral;");
    // Missing the semicolon.
    assertDecodedHtml(
       "&CounterClockwiseContourIntegral",
       "&CounterClockwiseContourIntegral"
    );

    assertDecodedHtml("&;", "&;");
    assertDecodedHtml("&bogus;", "&bogus;");

    // Some strings decode differently depending on whether or not they're in an HTML attribute.
    assertDecodedHtml(
        "?foo\u00B6m=bar",
        "?foo&param=bar",
        "?foo&param=bar"
    );
    assertDecodedHtml(
        "?foo\u00B6=bar",
        "?foo&para=bar",
        "?foo&para=bar"
    );

    // Banned code units are stripped after character references are decoded,
    // so a banned code unit cannot split text that would otherwise be a
    // character reference into one.
    assertDecodedHtml("lt<", "lt&lt;");
    assertDecodedHtml("ltlt;", "ltlt;");
    assertDecodedHtml("lt&lt;", "lt&&#108;t;");
    assertDecodedHtml("lt&<", "lt&&lt;");

    assertDecodedHtml("lt&&lt;gt", "\ufdddlt&&l\ufffet;\udc9c\ud835gt");
    assertDecodedHtml("lt&<", "lt&&lt;\udc9c");
    assertDecodedHtml("lt&<", "lt&&lt;\ud835");

    // DEL and the C1 controls are stripped, raw or as references, like the
    // C0 controls; encodeHtmlOnto elides them, and policies must see the
    // same text that will be emitted.
    assertDecodedHtml("ab", "a\u007fb");
    assertDecodedHtml("ab", "a&#x7f;b");
    assertDecodedHtml("ab", "a\u0085b");
    assertDecodedHtml("ab", "a\u009fb");
    assertDecodedHtml("a&lt;b", "a\u0085&l\u0085t;b");

    // A numeric reference in the C1 range is read as a Windows-1252 byte,
    // as browsers do, so it is a printable character rather than a control.
    assertDecodedHtml("a\u2026b", "a&#x85;b");
    assertDecodedHtml("a\u2026b", "a&#133;b");
    assertDecodedHtml("a\u2026b", "a&#x0085;b");
    assertDecodedHtml("a\u20acb", "a&#x80;b");
    assertDecodedHtml("a\u0178b", "a&#x9f;b");
    assertDecodedHtml("a\u2122b", "a&#153;b");
    // The bytes that Windows-1252 leaves undefined stay C1 controls, which
    // are stripped.
    assertDecodedHtml("ab", "a&#x81;b");
    assertDecodedHtml("ab", "a&#x8d;b");
    assertDecodedHtml("ab", "a&#x8f;b");
    assertDecodedHtml("ab", "a&#x90;b");
    assertDecodedHtml("ab", "a&#x9d;b");
    // The mapping applies only to references, not to raw characters, and
    // not to the neighbouring ranges.
    assertDecodedHtml("ab", "a\u0080b");
    assertDecodedHtml("a\u00a0b", "a&#xa0;b");
    assertDecodedHtml("ab", "a&#x7f;b");
    assertDecodedHtml("a\u00a0b", "a\u00a0b");

    // Noncharacters, in the BMP and in the supplementary planes.
    assertDecodedHtml("ab", "a\ufdd0b");
    assertDecodedHtml("ab", "a&#xfdd0;b");
    assertDecodedHtml("a\ufdcf\ufdf0b", "a\ufdcf\ufdf0b");
    assertDecodedHtml("ab", "a\ud83f\udffeb");
    assertDecodedHtml("ab", "a&#x1fffe;b");
    assertDecodedHtml("ab", "a&#x10ffff;b");
    assertDecodedHtml("a\ud83f\udffdb", "a\ud83f\udffdb");
  }

  @Test
  public static final void testC1NumericReferencesDecodeAsWindows1252() {
    // https://html.spec.whatwg.org/multipage/parsing.html#numeric-character-reference-end-state
    int[][] table = {
        {0x80, 0x20ac}, {0x82, 0x201a}, {0x83, 0x0192}, {0x84, 0x201e},
        {0x85, 0x2026}, {0x86, 0x2020}, {0x87, 0x2021}, {0x88, 0x02c6},
        {0x89, 0x2030}, {0x8a, 0x0160}, {0x8b, 0x2039}, {0x8c, 0x0152},
        {0x8e, 0x017d}, {0x91, 0x2018}, {0x92, 0x2019}, {0x93, 0x201c},
        {0x94, 0x201d}, {0x95, 0x2022}, {0x96, 0x2013}, {0x97, 0x2014},
        {0x98, 0x02dc}, {0x99, 0x2122}, {0x9a, 0x0161}, {0x9b, 0x203a},
        {0x9c, 0x0153}, {0x9e, 0x017e}, {0x9f, 0x0178},
    };
    boolean[] mapped = new boolean[0x20];
    for (int[] row : table) {
      String want = String.valueOf((char) row[1]);
      assertDecodedHtml(want, "&#x" + Integer.toHexString(row[0]) + ";");
      assertDecodedHtml(want, "&#" + row[0] + ";");
      mapped[row[0] - 0x80] = true;
    }
    for (int b = 0x80; b <= 0x9f; ++b) {
      if (!mapped[b - 0x80]) {
        assertDecodedHtml("", "&#x" + Integer.toHexString(b) + ";");
      }
    }
  }

  @Test
  public static final void testAppendNumericEntityAndEncodeOnto()
      throws Exception {
    StringBuilder sb = new StringBuilder();
    StringBuilder cps = new StringBuilder();
    // Test with a set of legal code points
    for (int codepoint : new int[] {
        9, '\n', '@', 0xa0, 0xff, 0x100, 0xfff, 0x1000, 0x123a, 0xfffd,
        0x10000, Character.MAX_CODE_POINT-2 }) {
      Encoding.appendNumericEntity(codepoint, sb);
      sb.append(' ');

      cps.appendCodePoint(codepoint).append(' ');
    }

    assertEquals(
         "&#9; &#10; &#64; &#xa0; &#xff; &#x100; &#xfff; &#x1000; "
         + "&#x123a; &#xfffd; &#x10000; &#x10fffd; ",
         sb.toString());

    StringBuilder out = new StringBuilder();
    Encoding.encodeHtmlAttribOnto(cps.toString(), out);
    assertEquals(
        "\t \n &#64; \u00a0 \u00ff \u0100 \u0fff \u1000 "
        + "\u123a &#xfffd; &#x10000; &#x10fffd; ",
        out.toString());
  }

  @Test
  public static final void testAppendIllegalNumericEntityAndEncodeOnto()
      throws Exception {
    StringBuilder sb = new StringBuilder();
    StringBuilder cps = new StringBuilder();
    // Code points to which HTML forbids a numeric character reference.
    for (int codepoint : new int[] {
        0, 8, '\r', 0x1f, 0x7f, 0x80, 0x85, 0x9f, 0xd800, 0xdfff,
        0xfdd0, 0xfdef, 0xfffe, 0xffff, 0x1fffe, 0x3ffff, 0x10ffff,
        Character.MAX_CODE_POINT + 1, -1 }) {
      try {
        Encoding.appendNumericEntity(codepoint, sb);
        fail("Illegal code point was accepted: " + codepoint);
      } catch (IllegalArgumentException e) {
        // expected behaviour
      }
      if (0 <= codepoint && codepoint <= Character.MAX_CODE_POINT) {
        cps.appendCodePoint(codepoint).append(',');
      }
    }
    assertEquals("", sb.toString());

    // The encoder elides all of them, except that CR becomes LF.
    StringBuilder out = new StringBuilder();
    Encoding.encodeHtmlAttribOnto(cps.toString(), out);
    assertEquals(",,\n,,,,,,,,,,,,,,,", out.toString());
  }

  @Test
  public static final void testAngularJsBracesInTextNode() throws Exception {
    StringBuilder sb = new StringBuilder();

    Encoding.encodePcdataOnto("{{angularVariable}}", sb);
    assertEquals("{<!-- -->{angularVariable}}", sb.toString());

    sb.setLength(0);

    Encoding.encodePcdataOnto("{", sb);
    Encoding.encodePcdataOnto("{angularVariable}}", sb);
    assertEquals("{<!-- -->{angularVariable}}", sb.toString());
  }

  private static final void assertStripped(String stripped, String orig) {
    String actual = Encoding.stripBannedCodeunits(orig);
    assertEquals(orig, stripped, actual);
    if (stripped.equals(orig)) {
      assertSame(actual, orig);
    }

    StringBuilder sb = new StringBuilder(orig);
    Encoding.stripBannedCodeunits(sb);
    assertEquals(orig, stripped, sb.toString());
  }

  @Test
  public static final void testStripBannedCodeunits() {
    assertStripped("", "");
    assertStripped("foo", "foo");
    assertStripped("foobar", "foo\u0000bar");
    assertStripped("foobar", "foo\u0000bar\u0000");
    assertStripped("foobar", "foo\ufffebar\u0008");
    assertStripped("foobar", "foo\ud800bar\udc00");
    assertStripped("foo\ud800\udc00bar", "foo\ud800\ud800\udc00bar");
    assertStripped("foo\ud800\udc00bar", "foo\ud800\udc00\ud800bar");
    assertStripped("foo\ud800\udc00bar", "foo\ud800\udc00\udc00bar");
    assertStripped("foo\ud800\udc00bar", "foo\udc00\ud800\udc00bar");
    assertStripped("foo\ud834\udd1ebar", "foo\ud834\udd1ebar");
    assertStripped("foo\ud834\udd1e", "foo\ud834\udd1e");
    assertStripped("foobar", "foo\u007fbar");
    assertStripped("foobar", "foo\u0080\u0085\u009fbar");
    assertStripped("foo\u00a0bar", "foo\u00a0bar");
    assertStripped("foobar", "foo\ufdd0bar\ufdef");
    assertStripped("foo\ufdcf\ufdf0bar", "foo\ufdcf\ufdf0bar");

    // The last two code points of every plane are noncharacters.
    for (int plane = 0; plane <= 16; plane++) {
      int o = 0x10000 * plane;
      String s = new StringBuilder()
          .append(String.format("%02x", plane))
          .appendCodePoint(o + 0xffef).appendCodePoint(o + 0xfffd)
          .appendCodePoint(o + 0xfffe).appendCodePoint(o + 0xffff)
          .toString();
      String t = s.substring(0, plane == 0 ? 4 : 6);
      assertStripped(t, s);

      s = new StringBuilder().append("foo")
          .appendCodePoint(o + 0xfffe).appendCodePoint(o + 0xffff)
          .append("bar").toString();
      assertStripped("foobar", s);
    }
  }

  @Test
  public static final
  void testBadlyDonePostProcessingWillnotAllowInsertingNonceAttributes()
  throws Exception {
    // Some clients do ad-hoc post processing of the output.
    // String replace of {{...}} shouldn't turn
    //   <span title="{{">}} <br class="a nonce=xyz "></span>
    // into
    //   <span title="x <br class="a nonce=xyz "></span>
    // which contains CSP directives.
    // We prevent this by being strict about quotes to prevent ending an
    // attribute with quotes about strict mode, and being strict about equals
    // signs to prevent text nodes or attribute values from introducing an
    // attribute with a value.
    StringBuilder pcdata = new StringBuilder();
    Encoding.encodePcdataOnto("\" nonce=xyz", pcdata);
    assertEquals("&#34; nonce&#61;xyz", pcdata.toString());

    StringBuilder rcdata = new StringBuilder();
    Encoding.encodeRcdataOnto("\" nonce=xyz", rcdata);
    assertEquals("&#34; nonce&#61;xyz", rcdata.toString());

    StringBuilder attrib = new StringBuilder();
    Encoding.encodeHtmlAttribOnto("a nonce=xyz ", attrib);
    assertEquals("a nonce&#61;xyz ", attrib.toString());
  }

  @Test
  public static final void testRiskyNormalizationSetContents() {
    // The table in Encoding is spelled out so that output does not depend
    // on the JDK's Unicode version.  Check it against the running JDK.
    for (char c = '\u0080'; c < '\ufffe'; c++) {
      boolean isRisky = false;
      String decomposed = Normalizer.normalize(String.valueOf(c), Form.NFKD);
      for (int i = 0; i < decomposed.length(); i++) {
        char ch = decomposed.charAt(i);
        if ((' ' < ch && ch < '0') || ('9' < ch && ch < 'A')
            || ('Z' < ch && ch < 'a') || ('z' < ch && ch < '\u007f')) {
          // A printable, non-alphanumeric ASCII character.
          isRisky = true;
          break;
        }
      }
      if (isRisky != Encoding.isRiskyNormalization(c)) {
        fail(String.format(
            "U+%04X has NFKD form %s: %s.  If this JDK's Unicode tables are"
            + " newer than Encoding.RISKY_NORMALIZATION, update the table.",
            (int) c, decomposed,
            isRisky ? "missing from the table" : "should not be in the table"));
      }
    }
  }

  private static void assertRcdataEncoded(String want, String plainText)
      throws IOException {
    StringBuilder sb = new StringBuilder();
    Encoding.encodeRcdataOnto(plainText, sb);
    assertEquals(plainText, want, sb.toString());
  }

  @Test
  public static final void testRiskyNormalization() throws IOException {
    // Characters whose compatibility decomposition contains ASCII
    // punctuation are written as references so that a later normalization
    // of the output cannot produce an HTML special character.
    assertRcdataEncoded("Small Less-than Sign : &#xfe64;",
        "Small Less-than Sign : \ufe64");
    assertRcdataEncoded("Fullwidth Quotation Mark : &#xff02;",
        "Fullwidth Quotation Mark : \uff02");
    assertRcdataEncoded("Greek Varia : &#x1fef;", "Greek Varia : \u1fef");
    assertRcdataEncoded("Greek Question Mark : &#x37e;",
        "Greek Question Mark : \u037e");
    assertRcdataEncoded("One Dot Leader : &#x2024;", "One Dot Leader : \u2024");
    assertRcdataEncoded("Double Exclamation Mark : &#x203c;",
        "Double Exclamation Mark : \u203c");

    // Everything from U+FE60 up is written as a reference whether or not it
    // normalizes to something risky: the byte order mark, the fullwidth
    // letters and the replacement character among them.
    assertRcdataEncoded("BOM : &#xfeff;", "BOM : \ufeff");
    assertRcdataEncoded("Fullwidth A : &#xff21;", "Fullwidth A : \uff21");
    assertRcdataEncoded("Replacement : &#xfffd;", "Replacement : \ufffd");
    assertRcdataEncoded("Arabic ligature : &#xfefb;", "Arabic ligature : \ufefb");

    // Below U+FE60, characters with a harmless or no decomposition pass.
    assertRcdataEncoded("NBSP : \u00a0", "NBSP : \u00a0");
    assertRcdataEncoded("Ligature : \ufb01", "Ligature : \ufb01");
    assertRcdataEncoded("CJK : \u4e2d\u6587", "CJK : \u4e2d\u6587");
  }

  @Test
  public static final void testNewLineNormalization() throws IOException {
    // https://infra.spec.whatwg.org/#normalize-newlines
    assertRcdataEncoded("\none\ntwo\n", "\rone\ntwo\r");
    assertRcdataEncoded("\none\ntwo\n", "\none\rtwo\n");
    assertRcdataEncoded("\none\ntwo\n", "\r\none\r\ntwo\r\n");
    assertRcdataEncoded("\n\none\n\ntwo\n\n", "\n\rone\n\rtwo\n\r");
    assertRcdataEncoded("\n\none\n\ntwo\n\n", "\r\rone\n\ntwo\r\r");
    assertRcdataEncoded("\n", "\r");
    assertRcdataEncoded("", "");

    StringBuilder attrib = new StringBuilder();
    Encoding.encodeHtmlAttribOnto("a\r\nb\rc", attrib);
    assertEquals("a\nb\nc", attrib.toString());
    StringBuilder pcdata = new StringBuilder();
    Encoding.encodePcdataOnto("a\r\nb\rc", pcdata);
    assertEquals("a\nb\nc", pcdata.toString());
  }
}
