// Copyright (c) 2013, Mike Samuel
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

import java.io.PrintStream;

import junit.framework.Test;
import junit.framework.TestResult;
import junit.textui.ResultPrinter;
import junit.textui.TestRunner;

/**
 * A test runner that dumps the names of tests as they start and finish to
 * make debugging hanging tests easier.
 */
public class VerboseTestRunner extends TestRunner {
  final PrintStream out;

  /** */
  public VerboseTestRunner() {
    out = System.out;
    setPrinter(new VerboseResultPrinter(out));
  }

  private final class VerboseResultPrinter extends ResultPrinter {

    VerboseResultPrinter(PrintStream out) {
      super(out);
    }

    @Override
    public void startTest(Test test) {
      out.println("Started " + test);
      out.flush();
      super.startTest(test);
    }

    @Override
    public void endTest(Test test) {
      super.endTest(test);
      out.println("ended " + test);
      out.flush();
    }
  }

  public static void main(String[] argv) {
    VerboseTestRunner runner = new VerboseTestRunner();
    try {
      TestResult result = runner.start(argv);
      if (!result.wasSuccessful()) {
        System.exit(FAILURE_EXIT);
      }
      System.exit(SUCCESS_EXIT);
    } catch (Exception ex) {
      ex.printStackTrace();
      System.exit(EXCEPTION_EXIT);
    }
  }
}
