/*
 * Copyright (c) 2007-2010, Arshan Dabirsiaghi, Jason Li
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * Neither the name of OWASP nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

 package org.owasp.html;

import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Benchmarks extracted from {@link AntiSamyTest}.
 * These do network fetches.
 *
 * @author Arshan Dabirsiaghi
 *
 */
public final class AntiSamyBenchmark {

  /**
   * @param argv ignored.
   */
  public static void main(String... argv) throws Exception {

    long totalTime = 0;
    long averageTime = 0;

    int testReps = 15;

    for (String url : new String[] {
            "http://slashdot.org/", "http://www.fark.com/",
            "http://www.cnn.com/", "http://google.com/",
            "http://www.microsoft.com/en/us/default.aspx",
            "http://deadspin.com/",
        }) {
      URLConnection conn = new URL(url).openConnection();
      String ct = guessCharsetFromContentType(conn.getContentType());
      InputStreamReader in = new InputStreamReader(conn.getInputStream(), ct);
      StringBuilder out = new StringBuilder();
      char[] buffer = new char[5000];
      int read = 0;
      do {
        read = in.read(buffer, 0, buffer.length);
        if (read > 0) {
          out.append(buffer, 0, read);
        }
      } while (read >= 0);

      in.close();

      String html = out.toString();

      System.out.println("About to scan: " + url + " size: " + html.length());
      if (html.length() > 640000) {
        System.out.println("   -Maximum input size 640000 exceeded. SKIPPING.");
        continue;
      }

      long startTime = 0;
      long endTime = 0;

      for (int j = 0; j < testReps; j++) {
        startTime = System.nanoTime();
        AntiSamyTest.sanitize(html);
        endTime = System.nanoTime();

        System.out.println(
            "    Took " + ((endTime - startTime) / 1000000) + " ms");
        totalTime = totalTime + (endTime - startTime);
      }

      averageTime = totalTime / testReps;
    }

    System.out.println("Total time ms: " + totalTime/1000000L);
    System.out.println("Average time per rep ms: " + averageTime/1000000L);
  }


  private static String guessCharsetFromContentType(String contentType) {
    Matcher m = Pattern.compile(";\\s*charset=(?:\"([^\"]*)\"|([^\\s;]*))")
      .matcher(contentType);
    if (m.find()) {
      String ct;
      ct = m.group(1);
      if (ct != null) { return ct; }
      ct = m.group(2);
      if (ct != null) { return ct; }
    }
    return "UTF-8";
  }

}
