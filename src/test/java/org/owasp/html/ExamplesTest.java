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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.PrintStream;
import java.lang.reflect.Method;

import com.google.common.base.Throwables;

import org.junit.Test;
import org.owasp.html.examples.EbayPolicyExample;

import junit.framework.TestCase;

@SuppressWarnings("javadoc")
public class ExamplesTest extends TestCase {
  @Test
  public static final void testExamplesRun() throws Exception {
    InputStream stdin = System.in;
    PrintStream stdout = System.out;
    PrintStream stderr = System.err;
    for (Class<?> exampleClass : AllExamples.CLASSES) {
      InputStream emptyIn = new ByteArrayInputStream(new byte[0]);
      ByteArrayOutputStream captured = new ByteArrayOutputStream();
      PrintStream capturingOut = new PrintStream(captured, true, "UTF-8");
      System.setIn(emptyIn);
      System.setOut(capturingOut);
      System.setErr(capturingOut);

      Method main;
      try {
        main = exampleClass.getDeclaredMethod("main", String[].class);
        // Invoke with no arguments to sanitize empty input stream to output.
        main.invoke(null, new Object[] { new String[0] });
      } catch (Exception ex) {
        capturingOut.flush();
        System.err.println(
            "Example " + exampleClass.getSimpleName() + "\n"
            + captured.toString("UTF-8"));
        Throwables.propagate(ex);
      } finally {
        System.setIn(stdin);
        System.setOut(stdout);
        System.setErr(stderr);
      }
    }
  }

  @Test
  public static final void testSanitizeRemovesScripts() {
    String input =
      "<p>Hello World</p>"
      + "<script language=\"text/javascript\">alert(\"bad\");</script>";
    String sanitized = EbayPolicyExample.POLICY_DEFINITION.sanitize(input);
    assertEquals("<p>Hello World</p>", sanitized);
  }

  @Test
  public static final void testSanitizeRemovesOnclick() {
    String input = "<p onclick=\"alert(\"bad\");\">Hello World</p>";
    String sanitized = EbayPolicyExample.POLICY_DEFINITION.sanitize(input);
    assertEquals("<p>Hello World</p>", sanitized);
  }

  @Test
  public static final void testTextAllowedInLinks() {
    String input = "<a href=\"../good.html\">click here</a>";
    String sanitized = EbayPolicyExample.POLICY_DEFINITION.sanitize(input);
    assertEquals("<a href=\"../good.html\" rel=\"nofollow\">click here</a>",
                 sanitized);
  }
}
