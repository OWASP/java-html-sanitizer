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

package org.owasp.html;

import java.util.Random;

import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.TestWatcher;

/**
 * A test case that has a random seed.
 * Subclasses are stochastic -- are not guaranteed to pass or fail consistently.
 * If you see a failure, please report it along with the seed from the output.
 * If you want to repeat a failure, set the system property "junit.seed".
 *
 * @author Mike Samuel (mikesamuel@gmail.com)
 */
@ExtendWith(FuzzyTestCase.SeedReporter.class)
abstract class FuzzyTestCase {

  /** From the {@code junit.seed} system property when set, else the clock. */
  protected final long seed = seedFromProperty();

  /** A fresh generator seeded with {@link #seed} for each test method. */
  protected final Random rnd = new Random(seed);

  private static long seedFromProperty() {
    String seedStr = System.getProperty("junit.seed");
    if (seedStr == null) {
      return System.currentTimeMillis();
    }
    try {
      return Long.parseLong(seedStr);
    } catch (NumberFormatException ex) {
      throw new IllegalArgumentException(
          "junit.seed must be a long, not `" + seedStr + "`", ex);
    }
  }

  /** Prints the seed of a failed test so that the failure can be replayed. */
  static final class SeedReporter implements TestWatcher {
    @Override
    public void testFailed(ExtensionContext context, Throwable cause) {
      FuzzyTestCase test = (FuzzyTestCase) context.getRequiredTestInstance();
      System.err.println(
          context.getDisplayName() + " failed; replay it with -Djunit.seed="
          + test.seed);
    }
  }
}
