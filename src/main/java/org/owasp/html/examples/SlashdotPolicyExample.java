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

package org.owasp.html.examples;

import java.io.IOException;
import java.io.InputStreamReader;
import java.util.regex.Pattern;

import org.owasp.html.Handler;
import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.HtmlSanitizer;
import org.owasp.html.HtmlStreamEventReceiver;
import org.owasp.html.HtmlStreamRenderer;

import com.google.common.base.Charsets;
import com.google.common.base.Function;
import com.google.common.base.Throwables;
import com.google.common.io.CharStreams;

/**
 * Based on the
 * <a href="http://www.owasp.org/index.php/Category:OWASP_AntiSamy_Project#Stage_2_-_Choosing_a_base_policy_file">AntiSamy Slashdot example</a>.
 * <blockquote>
 * Slashdot (http://www.slashdot.org/) is a techie news site that allows users
 * to respond anonymously to news posts with very limited HTML markup. Now
 * Slashdot is not only one of the coolest sites around, it's also one that's
 * been subject to many different successful attacks. Even more unfortunate is
 * the fact that most of the attacks led users to the infamous goatse.cx picture
 * (please don't go look it up). The rules for Slashdot are fairly strict: users
 * can only submit the following HTML tags and no CSS: {@code <b>}, {@code <u>},
 * {@code <i>}, {@code <a>}, {@code <blockquote>}.
 * <br>
 * Accordingly, we've built a policy file that allows fairly similar
 * functionality. All text-formatting tags that operate directly on the font,
 * color or emphasis have been allowed.
 * </blockquote>
 */
public class SlashdotPolicyExample {

  /** A policy definition that matches the minimal HTML that Slashdot allows. */
  public static final Function<HtmlStreamEventReceiver, HtmlSanitizer.Policy>
      POLICY_DEFINITION = new HtmlPolicyBuilder()
          .allowStandardUrlProtocols()
          // Allow title="..." on any element.
          .allowAttributes("title").globally()
          // Allow href="..." on <a> elements.
          .allowAttributes("href").onElements("a")
          // Defeat link spammers.
          .requireRelNofollowOnLinks()
          // Allow lang= with an alphabetic value on any element.
          .allowAttributes("lang").matching(Pattern.compile("[a-zA-Z]{2,20}"))
              .globally()
          // The align attribute on <p> elements can have any value below.
          .allowAttributes("align")
              .matching(true, "center", "left", "right", "justify", "char")
              .onElements("p")
          // These elements are allowed.
          .allowElements(
              "a", "p", "div", "i", "b", "em", "blockquote", "tt", "strong",
              "br", "ul", "ol", "li")
          // Custom slashdot tags.
          // These could be rewritten in the sanitizer using an ElementPolicy.
          .allowElements("quote", "ecode")
          .toFactory();

  /**
   * A test-bed that reads HTML from stdin and writes sanitized content to
   * stdout.
   */
  public static void main(String[] args) throws IOException {
    if (args.length != 0) {
      System.err.println("Reads from STDIN and writes to STDOUT");
      System.exit(-1);
    }
    System.err.println("[Reading from STDIN]");
    // Fetch the HTML to sanitize.
    String html = CharStreams.toString(
        new InputStreamReader(System.in, Charsets.UTF_8));
    // Set up an output channel to receive the sanitized HTML.
    HtmlStreamRenderer renderer = HtmlStreamRenderer.create(
        System.out,
        // Receives notifications on a failure to write to the output.
        new Handler<IOException>() {
          public void handle(IOException ex) {
            Throwables.propagate(ex);  // System.out suppresses IOExceptions
          }
        },
        // Our HTML parser is very lenient, but this receives notifications on
        // truly bizarre inputs.
        new Handler<String>() {
          public void handle(String x) {
            throw new AssertionError(x);
          }
        });
    // Use the policy defined above to sanitize the HTML.
    HtmlSanitizer.sanitize(html, POLICY_DEFINITION.apply(renderer));
  }
}
