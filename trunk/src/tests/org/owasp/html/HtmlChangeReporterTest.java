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

import junit.framework.TestCase;

public class HtmlChangeReporterTest extends TestCase {

  public final void testChangeReporting() {
    final Integer testContext = 123;

    StringBuilder out = new StringBuilder();
    final StringBuilder log = new StringBuilder();
    HtmlStreamRenderer renderer = HtmlStreamRenderer.create(
        out, Handler.DO_NOTHING);
    HtmlChangeListener<Integer> listener = new HtmlChangeListener<Integer>() {
      public void discardedTag(Integer context, String elementName) {
        assertSame(testContext, context);
        log.append('<').append(elementName).append("> ");
      }

      public void discardedAttribute(
          Integer context, String tagName, String attributeName) {
        assertSame(testContext, context);
        log.append('<').append(tagName).append(' ').append(attributeName)
           .append("> ");
      }
    };
    HtmlChangeReporter<Integer> hcr = new HtmlChangeReporter<Integer>(
        renderer, listener, testContext);

    hcr.setPolicy(Sanitizers.FORMATTING.apply(hcr.getWrappedRenderer()));
    HtmlSanitizer.sanitize(
        "<textarea>Hello</textarea>,<b onclick=alert(42)>World</B>!<PLAINTEXT>",
        hcr);
    assertEquals("Hello,<b>World</b>!", out.toString());
    assertEquals("<textarea> <b onclick> <plaintext> ", log.toString());
  }
}
