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

import org.junit.Test;

import junit.framework.TestCase;

@SuppressWarnings("javadoc")
public class HtmlChangeReporterTest extends TestCase {

  static class Context {
    // Opaque test value compared via equality.
  }

  @Test
  public static final void testChangeReporting() {
    final Context testContext = new Context();

    StringBuilder out = new StringBuilder();
    final StringBuilder log = new StringBuilder();
    HtmlStreamRenderer renderer = HtmlStreamRenderer.create(
        out, Handler.DO_NOTHING);
    HtmlChangeListener<Context> listener = new HtmlChangeListener<Context>() {
      public void discardedTag(Context context, String elementName) {
        assertSame(testContext, context);
        log.append('<').append(elementName).append("> ");
      }

      public void discardedAttributes(
          Context context, String tagName, String... attributeNames) {
        assertSame(testContext, context);
        log.append('<').append(tagName);
        for (String attributeName : attributeNames) {
          log.append(' ').append(attributeName);
        }
        log.append("> ");
      }
    };
    HtmlChangeReporter<Context> hcr = new HtmlChangeReporter<Context>(
        renderer, listener, testContext);

    hcr.setPolicy(Sanitizers.FORMATTING.apply(hcr.getWrappedRenderer()));
    String html =
        "<textarea>Hello</textarea>,<b onclick=alert(42)>World</B>!"
        + "<Script type=text/javascript>doEvil()</script><PLAINTEXT>";
    HtmlSanitizer.sanitize(
        html,
        hcr.getWrappedPolicy());
    assertEquals("Hello,<b>World</b>!", out.toString());
    assertEquals(
        "<textarea> <b onclick> <script> <plaintext> ", log.toString());
  }
}
