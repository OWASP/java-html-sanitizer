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

package org.owasp.html.examples;

import java.io.IOException;
import java.io.StringReader;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ExamplesTest {

  /** Each example must run to completion, and emit nothing, on empty input. */
  @Test
  void testRunOnEmptyInput() throws IOException {
    StringBuilder ebay = new StringBuilder();
    EbayPolicyExample.run(new StringReader(""), ebay);
    assertEquals("", ebay.toString());

    StringBuilder slashdot = new StringBuilder();
    SlashdotPolicyExample.run(new StringReader(""), slashdot);
    assertEquals("", slashdot.toString());

    StringBuilder urlText = new StringBuilder();
    UrlTextExample.run(urlText);
    assertEquals("", urlText.toString());
  }

  /**
   * Exercises the Slashdot policy: allowed elements ({@code p}, {@code b},
   * {@code tt}, {@code blockquote}, {@code a}, and the custom {@code quote}
   * and {@code ecode}) survive; {@code align} is kept but lower-cased;
   * {@code href} is kept and gains {@code rel="nofollow"}; {@code style},
   * {@code onclick}, {@code script} (with its body) and a
   * {@code javascript:} link are dropped, the latter leaving only its text.
   */
  @Test
  void testSlashdotRun() throws IOException {
    String input =
        "<p align=\"Right\" style=\"color:red\">Hello <b>bold</b>"
        + " <tt>mono</tt> <script>alert(1)</script></p>\n"
        + "<blockquote>quoted <a href=\"http://example.com/\""
        + " onclick=\"evil()\">link</a>"
        + " <a href=\"javascript:alert(1)\">bad</a></blockquote>\n"
        + "<quote>custom</quote><ecode>x &lt; y</ecode>";
    StringBuilder out = new StringBuilder();
    SlashdotPolicyExample.run(new StringReader(input), out);
    assertEquals(
        "<p align=\"right\">Hello <b>bold</b> <tt>mono</tt> </p>\n"
        + "<blockquote>quoted <a href=\"http://example.com/\""
        + " rel=\"nofollow\">link</a> bad</blockquote>\n"
        + "<quote>custom</quote><ecode>x &lt; y</ecode>",
        out.toString());
  }

  /**
   * Exercises the eBay policy through {@code run}: ids, classes, styling,
   * titles, fonts, on-site image URLs and sized images survive; event
   * handlers, {@code script} and {@code iframe} are dropped; links gain
   * {@code rel="nofollow"} and have {@code =} encoded in the URL.
   */
  @Test
  void testEbayRun() throws IOException {
    String input =
        "<div id=\"listing\" class=\"item\" style=\"color: red\">\n"
        + "<h1 title=\"Sale!\">Big <font color=\"#ff0000\" size=\"3\">Sale"
        + "</font></h1>\n"
        + "<p align=\"center\" onclick=\"alert(1)\">Buy "
        + "<a href=\"http://example.com/item?id=1\">now</a>\n"
        + "<img src=\"/images/item.png\" alt=\"Item\" width=\"100\""
        + " onerror=\"alert(1)\"></p>"
        + "<script>alert(\"bad\")</script>"
        + "<iframe src=\"http://evil.example.com/\"></iframe>\n"
        + "</div>";
    StringBuilder out = new StringBuilder();
    EbayPolicyExample.run(new StringReader(input), out);
    assertEquals(
        "<div id=\"listing\" class=\"item\" style=\"color:red\">\n"
        + "<h1 title=\"Sale!\">Big <font color=\"#ff0000\" size=\"3\">Sale"
        + "</font></h1>\n"
        + "<p align=\"center\">Buy "
        + "<a href=\"http://example.com/item?id&#61;1\" rel=\"nofollow\">"
        + "now</a>\n"
        + "<img src=\"/images/item.png\" alt=\"Item\" width=\"100\" /></p>\n"
        + "</div>",
        out.toString());
  }

  @Test
  void testSanitizeRemovesScripts() {
    String input =
      "<p>Hello World</p>"
      + "<script language=\"text/javascript\">alert(\"bad\");</script>";
    String sanitized = EbayPolicyExample.POLICY_DEFINITION.sanitize(input);
    assertEquals("<p>Hello World</p>", sanitized);
  }

  @Test
  void testSanitizeRemovesOnclick() {
    String input = "<p onclick=\"alert(\"bad\");\">Hello World</p>";
    String sanitized = EbayPolicyExample.POLICY_DEFINITION.sanitize(input);
    assertEquals("<p>Hello World</p>", sanitized);
  }

  @Test
  void testTextAllowedInLinks() {
    String input = "<a href=\"../good.html\">click here</a>";
    String sanitized = EbayPolicyExample.POLICY_DEFINITION.sanitize(input);
    assertEquals(
        "<a href=\"../good.html\" rel=\"nofollow\">click here</a>",
        sanitized);
  }
}
