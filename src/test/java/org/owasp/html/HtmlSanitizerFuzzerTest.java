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

import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import com.google.common.base.Charsets;
import com.google.common.base.Throwables;
import com.google.common.io.Resources;

/**
 * Throws malformed inputs at the HTML sanitizer to try and crash it.
 * This test is stochastic -- not guaranteed to pass or fail consistently.
 * If you see a failure, please report it along with the seed from the output.
 * If you want to repeat a failure, set the system property "junit.seed".
 *
 * @author Mike Samuel (mikesamuel@gmail.com)
 */
@SuppressWarnings("javadoc")
public class HtmlSanitizerFuzzerTest extends FuzzyTestCase {

  static final HtmlSanitizer.Policy DO_NOTHING_POLICY
      = new HtmlSanitizer.Policy() {
        public void openDocument() { /* do nothing */ }
        public void closeDocument() { /* do nothing */ }
        public void openTag(String elementName, List<String> attrs) {
          /* do nothing */
        }
        public void closeTag(String elementName) { /* do nothing */ }
        public void text(String textChunk) { /* do nothing */ }
      };

  public final void testFuzzHtmlParser() throws Exception {
    String html = Resources.toString(
        Resources.getResource("benchmark-data/Yahoo!.html"), Charsets.UTF_8);
    int length = html.length();

    char[] fuzzyHtml0 = new char[length];
    char[] fuzzyHtml1 = new char[length];

    final LinkedBlockingQueue<Throwable> failures
        = new LinkedBlockingQueue<Throwable>();

    final int runCount = 1000;
    // Use an executor so that any infinite loops do not cause the test runner
    // to fail.
    ThreadPoolExecutor executor = new ThreadPoolExecutor(
        10, 10, 10, TimeUnit.SECONDS, new LinkedBlockingQueue<Runnable>());

    for (int run = runCount; --run >= 0;) {
      for (int i = length; --i >= 0;) { fuzzyHtml0[i] = html.charAt(i); }
      for (int fuzz = 1 + rnd.nextInt(25); --fuzz >= 0;) {
        if (rnd.nextBoolean()) {
          fuzzyHtml0[rnd.nextInt(length)] = (char) rnd.nextInt(0x10000);
          continue;
        }
        int s0 = rnd.nextInt(length - 1);
        double d = Math.abs(rnd.nextGaussian()) / 3.0d;
        int e0 = s0 + (int) (rnd.nextInt(length - s0) * d);
        if (e0 >= length) { e0 = s0 + 1; }

        int s1 = rnd.nextInt(length - 1);
        d = Math.abs(rnd.nextGaussian()) / 3.0d;
        int e1 = s1 + (int) (rnd.nextInt(length - s1) * d);
        if (e1 >= length) { e1 = s1 + 1; }

        if (s0 > s1) {
          int st = s0, et = e0;
          s0 = s1;
          e0 = e1;
          s1 = st;
          e1 = et;
        }

        if (e0 > s1) { e0 = s1; }

        // Swap the ranges [s0, e0) and [s1, e1) into fuzzyHtml1.
        int i0, i1 = 0;
        for (i0 = 0; i0 < s0; ++i0, ++i1) {
          fuzzyHtml1[i1] = fuzzyHtml0[i0];
        }
        for (i0 = s1; i0 < e1; ++i0, ++i1) {
          fuzzyHtml1[i1] = fuzzyHtml0[i0];
        }
        for (i0 = e0; i0 < s1; ++i0, ++i1) {
          fuzzyHtml1[i1] = fuzzyHtml0[i0];
        }
        for (i0 = s0; i0 < e0; ++i0, ++i1) {
          fuzzyHtml1[i1] = fuzzyHtml0[i0];
        }
        for (i0 = e1; i0 < length; ++i0, ++i1) {
          fuzzyHtml1[i1] = fuzzyHtml0[i0];
        }
        // Swap the two buffers.
        char[] swap = fuzzyHtml0;
        fuzzyHtml0 = fuzzyHtml1;
        fuzzyHtml1 = swap;
      }
      final String fuzzyHtml = new String(fuzzyHtml0);
      executor.execute(new Runnable() {
        public void run() {
          try {
            HtmlSanitizer.sanitize(fuzzyHtml, DO_NOTHING_POLICY);
          } catch (Exception ex) {
            System.err.println(
                "Using seed " + seed + "L\n"
                + "Failed on <<<" + fuzzyHtml + ">>>");
            failures.add(ex);
          }
        }
      });
    }
    executor.shutdown();
    executor.awaitTermination(runCount * 4, TimeUnit.SECONDS);
    assertTrue("seed=" + seed, executor.isTerminated());
    Throwable failure = failures.poll();
    if (failure != null) {
      Throwables.propagate(failure);
    }
  }

}
