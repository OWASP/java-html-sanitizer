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
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.lang.reflect.Method;

import com.google.common.base.Charsets;
import com.google.common.base.Throwables;
import com.google.common.io.CharStreams;

import junit.framework.TestCase;

public class ExamplesTest extends TestCase {
  public final void testExamplesRun() throws Exception {
    String[] allExamples;
    InputStream in = AllTests.class.getResourceAsStream("allexamples");
    if (in == null) {
      throw new AssertionError("Failed to load list of examples");
    }
    try {
      try {
        allExamples = CharStreams.toString(
            new InputStreamReader(in, Charsets.UTF_8)).split("\r\n?|\n");
      } finally {
        in.close();
      }
    } catch (IOException ex) {
      Throwables.propagate(ex);
      return;
    }

    ClassLoader loader = AllTests.class.getClass().getClassLoader();
    if (loader == null) { loader = ClassLoader.getSystemClassLoader(); }
    InputStream stdin = System.in;
    PrintStream stdout = System.out;
    PrintStream stderr = System.err;
    for (String example : allExamples) {
      InputStream emptyIn = new ByteArrayInputStream(new byte[0]);
      ByteArrayOutputStream captured = new ByteArrayOutputStream();
      PrintStream capturingOut = new PrintStream(captured, true, "UTF-8");
      System.setIn(emptyIn);
      System.setOut(capturingOut);
      System.setErr(capturingOut);

      Method main;
      try {
        Class<?> exampleClass = loader.loadClass(example);
        main = exampleClass.getDeclaredMethod("main", String[].class);
        // Invoke with no arguments to sanitize empty input stream to output.
        main.invoke(null, new Object[] { new String[0] });
      } catch (Exception ex) {
        capturingOut.flush();
        System.err.println(
            "Example " + example + "\n" + captured.toString("UTF-8"));
        Throwables.propagate(ex);
      } finally {
        System.setIn(stdin);
        System.setOut(stdout);
        System.setErr(stderr);
      }
    }
  }
}
