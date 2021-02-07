// Copyright (c) 2012, Mike Samuel
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

import org.junit.Test;

import junit.framework.TestCase;

@SuppressWarnings("javadoc")
public final class EncodingTest extends TestCase {

  @Test
  public static final void testDecodeHtml() {
    String html =
      "The quick&nbsp;brown fox&#xa;jumps over&#xd;&#10;the lazy dog&#x000a;";
    //          1         2         3         4         5         6
    // 123456789012345678901234567890123456789012345678901234567890123456789
    String golden =
      "The quick\u00a0brown fox\njumps over\r\nthe lazy dog\n";
    assertEquals(golden, Encoding.decodeHtml(html));

    // Don't allocate a new string when no entities.
    assertSame(golden, Encoding.decodeHtml(golden));

    // test interrupted escapes and escapes at end of file handled gracefully
    assertEquals(
        "\\\\u000a",
        Encoding.decodeHtml("\\\\u000a"));
    assertEquals(
        "\n",
        Encoding.decodeHtml("&#x000a;"));
    assertEquals(
        "\n",
        Encoding.decodeHtml("&#x00a;"));
    assertEquals(
        "\n",
        Encoding.decodeHtml("&#x0a;"));
    assertEquals(
        "\n",
        Encoding.decodeHtml("&#xa;"));
    assertEquals(
        String.valueOf(Character.toChars(0x10000)),
        Encoding.decodeHtml("&#x10000;"));
    assertEquals(
        "\n",
        Encoding.decodeHtml("&#xa"));
    assertEquals(
        "&#x00ziggy",
        Encoding.decodeHtml("&#x00ziggy"));
    assertEquals(
        "&#xa00z;",
        Encoding.decodeHtml("&#xa00z;"));
    assertEquals(
        "&#\n",
        Encoding.decodeHtml("&#&#x000a;"));
    assertEquals(
        "&#x\n",
        Encoding.decodeHtml("&#x&#x000a;"));
    assertEquals(
        "\n\n",
        Encoding.decodeHtml("&#xa&#x000a;"));
    assertEquals(
        "&#\n",
        Encoding.decodeHtml("&#&#xa;"));
    assertEquals(
        "&#x",
        Encoding.decodeHtml("&#x"));
    assertEquals(
        "",  // NUL elided.
        Encoding.decodeHtml("&#x0"));
    assertEquals(
        "&#",
        Encoding.decodeHtml("&#"));

    assertEquals(
        "\\",
        Encoding.decodeHtml("\\"));
    assertEquals(
        "&",
        Encoding.decodeHtml("&"));

    assertEquals(
        "&#000a;",
        Encoding.decodeHtml("&#000a;"));
    assertEquals(
        "\n",
        Encoding.decodeHtml("&#10;"));
    assertEquals(
        "\n",
        Encoding.decodeHtml("&#010;"));
    assertEquals(
        "\n",
        Encoding.decodeHtml("&#0010;"));
    assertEquals(
        "\t",
        Encoding.decodeHtml("&#9;"));
    assertEquals(
        "\n",
        Encoding.decodeHtml("&#10"));
    assertEquals(
        "&#00ziggy",
        Encoding.decodeHtml("&#00ziggy"));
    assertEquals(
        "&#\n",
        Encoding.decodeHtml("&#&#010;"));
    assertEquals(
        "\n",
        Encoding.decodeHtml("&#0&#010;"));
    assertEquals(
        "\n",
        Encoding.decodeHtml("&#01&#10;"));
    assertEquals(
        "&#\n",
        Encoding.decodeHtml("&#&#10;"));
    assertEquals(
        "",  // Invalid XML char elided.
        Encoding.decodeHtml("&#1"));
    assertEquals(
        "\t",
        Encoding.decodeHtml("&#9"));
    assertEquals(
        "\n",
        Encoding.decodeHtml("&#10"));

    // test the named escapes
    assertEquals(
        "<",
        Encoding.decodeHtml("&lt;"));
    assertEquals(
        ">",
        Encoding.decodeHtml("&gt;"));
    assertEquals(
        "\"",
        Encoding.decodeHtml("&quot;"));
    assertEquals(
        "'",
        Encoding.decodeHtml("&apos;"));
    assertEquals(
        "'",
        Encoding.decodeHtml("&#39;"));
    assertEquals(
        "'",
        Encoding.decodeHtml("&#x27;"));
    assertEquals(
        "&",
        Encoding.decodeHtml("&amp;"));
    assertEquals(
        "&lt;",
        Encoding.decodeHtml("&amp;lt;"));
    assertEquals(
        "&",
        Encoding.decodeHtml("&AMP;"));
    assertEquals(
        "&",
        Encoding.decodeHtml("&AMP"));
    assertEquals(
        "&",
        Encoding.decodeHtml("&AmP;"));
    assertEquals(
        "\u0391",
        Encoding.decodeHtml("&Alpha;"));
    assertEquals(
        "\u03b1",
        Encoding.decodeHtml("&alpha;"));
    assertEquals(
        "\ud835\udc9c",  // U+1D49C requires a surrogate pair in UTF-16.
        Encoding.decodeHtml("&Ascr;"));
    assertEquals(
        "fj",  // &fjlig; refers to 2 characters.
        Encoding.decodeHtml("&fjlig;"));
    assertEquals(
        "\u2233",  // HTML entity with the longest name.
        Encoding.decodeHtml("&CounterClockwiseContourIntegral;"));
    assertEquals( // Missing the semicolon.
        "&CounterClockwiseContourIntegral",
        Encoding.decodeHtml("&CounterClockwiseContourIntegral"));

    assertEquals(
        "&;",
        Encoding.decodeHtml("&;"));
    assertEquals(
        "&bogus;",
        Encoding.decodeHtml("&bogus;"));
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
        + "\u123a \ufffd &#x10000; &#x10fffd; ",
        out.toString());
  }

  @Test
  public static final void testAppendIllegalNumericEntityAndEncodeOnto()
      throws Exception {
    StringBuilder sb = new StringBuilder();
    StringBuilder cps = new StringBuilder();
    // Test with a set of legal code points
    for (int codepoint : new int[] { 8, '\r', 0x7f, 0x85, 0xfdd0, 0xfffe, 0x1fffe, 0x3ffff }) {
      try {
        Encoding.appendNumericEntity(codepoint, sb);
        fail("Illegal character was accepted: "+codepoint);
      } catch ( IllegalArgumentException e ) {
        // expected behaviour
      }

      cps.appendCodePoint(codepoint).append(',');
    }

    assertEquals("", sb.toString());

    StringBuilder out = new StringBuilder();
    Encoding.encodeHtmlAttribOnto(cps.toString(), out);
    assertEquals(
        ",\n,,,,,,,",
        out.toString());
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

    // Check stripping of non-characters from all planes
    for(int i=0;i<=16;i++) {
      int o = 0x10000 * i;
      String s = new StringBuilder().append(String.format("%02x",i)).appendCodePoint(o+0xffef).appendCodePoint(o+0xfffd)
          .appendCodePoint(o+0xfffe).appendCodePoint(o+0xffff).toString();
      String t = s.substring(0,(i==0)?4:6);
      assertStripped(t,s);

      s = new StringBuilder().append("foo").appendCodePoint(o+0xfffe).appendCodePoint(o+0xffff).append("bar").toString();
      assertStripped("foobar",s);
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

}
