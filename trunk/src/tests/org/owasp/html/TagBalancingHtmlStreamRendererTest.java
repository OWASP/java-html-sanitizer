// Copyright (c) 2011, Mike Samuel
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

import com.google.common.collect.ImmutableList;

import junit.framework.TestCase;

public class TagBalancingHtmlStreamRendererTest extends TestCase {

  StringBuilder htmlOutputBuffer;
  HtmlStreamEventReceiver balancer;

  @Override protected void setUp() throws Exception {
    super.setUp();
    htmlOutputBuffer = new StringBuilder();
    balancer = new TagBalancingHtmlStreamEventReceiver(
        HtmlStreamRenderer.create(htmlOutputBuffer, new Handler<String>() {
          public void handle(String x) {
            fail("An unexpected error was raised during the testcase");
          }
        }));
  }

  public final void testTagBalancing() {
    balancer.openDocument();
    balancer.openTag("html", ImmutableList.<String>of());
    balancer.openTag("head", ImmutableList.<String>of());
    balancer.openTag("title", ImmutableList.<String>of());
    balancer.text("Hello, <<World>>!");
    // TITLE closed with case-insensitive differnet name.
    balancer.closeTag("TITLE");
    balancer.closeTag("head");
    balancer.openTag("body", ImmutableList.<String>of());
    balancer.openTag("p", ImmutableList.of("id", "p'0"));
    balancer.text("Hello,");
    balancer.openTag("Br", ImmutableList.<String>of());
    balancer.text("<<World>>!");
    // HTML, P, and BODY unclosed, but BR not.
    balancer.closeDocument();

    assertEquals(
        "<html><head><title>Hello, &lt;&lt;World&gt;&gt;!</title></head>"
        + "<body><p id=\"p&#39;0\">Hello,"
        + "<br>&lt;&lt;World&gt;&gt;!</p></body></html>",
        htmlOutputBuffer.toString());
  }

  public final void testTagSoupIronedOut() {
    balancer.openDocument();
    balancer.openTag("i", ImmutableList.<String>of());
    balancer.text("a");
    balancer.openTag("b", ImmutableList.<String>of());
    balancer.text("b");
    balancer.closeTag("i");
    balancer.text("c");
    balancer.closeDocument();

    assertEquals(
        "<i>a<b>b</b></i><b>c</b>",
        htmlOutputBuffer.toString());
  }

  public final void testListNesting() {
    balancer.openDocument();
    balancer.openTag("ul", ImmutableList.<String>of());
    balancer.openTag("li", ImmutableList.<String>of());
    balancer.openTag("ul", ImmutableList.<String>of());
    balancer.openTag("li", ImmutableList.<String>of());
    balancer.text("foo");
    balancer.closeTag("li");
    balancer.closeTag("li");
    balancer.openTag("ul", ImmutableList.<String>of());
    balancer.openTag("li", ImmutableList.<String>of());
    balancer.text("bar");
    balancer.closeDocument();

    assertEquals(
        "<ul><li><ul><li>foo</li></ul></li></ul><ul><li>bar</li></ul>",
        htmlOutputBuffer.toString());
  }

}
