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

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

import org.junit.runner.RunWith;

import com.google.common.base.Charsets;
import com.google.common.base.Throwables;
import com.google.common.io.CharStreams;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

@RunWith(org.junit.runners.AllTests.class)
public class AllTests {

  public static Test suite() {
    String[] allTests;
    InputStream in = AllTests.class.getResourceAsStream("alltests");
    if (in == null) {
      throw new AssertionError("Failed to load list of tests");
    }
    try {
      try {
        allTests = CharStreams.toString(
            new InputStreamReader(in, Charsets.UTF_8)).split("\r\n?|\n");
      } finally {
        in.close();
      }
    } catch (IOException ex) {
      Throwables.propagate(ex);
      return null;
    }

    TestSuite suite = new TestSuite();
    ClassLoader loader = AllTests.class.getClass().getClassLoader();
    if (loader == null) { loader = ClassLoader.getSystemClassLoader(); }
    for (String test : allTests) {
      try {
        suite.addTestSuite(loader.loadClass(test).asSubclass(TestCase.class));
      } catch (ClassNotFoundException ex) {
        Throwables.propagate(ex);
      }
    }
    return suite;
  }

}
