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

/**
 * Pre-packaged HTML sanitizer policies.
 *
 * <p>
 * These policies can be used to sanitize content.
 * </p>
 * <pre>
 *   Sanitizers.FORMATTING.sanitize({@code "<b>Hello, World!</b>"})
 * </pre>
 * and can be chained
 * <pre>
 *   PolicyFactory sanitizer = Sanitizers.FORMATTING.and(Sanitizers.BLOCKS);
 *   System.out.println(sanitizer.sanitize({@code "<p>Hello, <b>World!</b>"}));
 * </pre>
 *
 * <p>
 * For more fine-grained control over sanitization, use
 * {@link HtmlPolicyBuilder}.
 * </p>
 *
 * @author Mike Samuel (mikesamuel@gmail.com)
 */
public final class Sanitizers {

  /**
   * Allows common formatting elements including {@code <b>}, {@code <i>}, etc.
   */
  public static final PolicyFactory FORMATTING = new HtmlPolicyBuilder()
      .allowCommonInlineFormattingElements().toFactory();

  /**
   * Allows common block elements including <code>&lt;p&gt;</code>,
   * <code>&lt;h1&gt;</code>, etc.
   */
  public static final PolicyFactory BLOCKS = new HtmlPolicyBuilder()
      .allowCommonBlockElements().toFactory();

  /**
   * Allows certain safe CSS properties in {@code style="..."} attributes.
   */
  public static final PolicyFactory STYLES = new HtmlPolicyBuilder()
      .allowStyling().toFactory();

  /**
   * Allows HTTP, HTTPS, MAILTO, and relative links.
   */
  public static final PolicyFactory LINKS = new HtmlPolicyBuilder()
      .allowStandardUrlProtocols().allowElements("a")
      .allowAttributes("href").onElements("a").requireRelNofollowOnLinks()
      .toFactory();

  /**
   * Allows common table elements.
   */
  public static final PolicyFactory TABLES = new HtmlPolicyBuilder()
    .allowStandardUrlProtocols()
    .allowElements(
                   "table", "tr", "td", "th",
                   "colgroup", "caption", "col",
                   "thead", "tbody", "tfoot")
    .allowAttributes("summary").onElements("table")
    .allowAttributes("align", "valign")
    .onElements("table", "tr", "td", "th",
                "colgroup", "col",
                "thead", "tbody", "tfoot")
    .allowTextIn("table")  // WIDGY
    .toFactory();

  private static final AttributePolicy INTEGER = new AttributePolicy() {
    public String apply(
        String elementName, String attributeName, String value) {
      int n = value.length();
      if (n == 0) { return null; }
      for (int i = 0; i < n; ++i) {
        char ch = value.charAt(i);
        if (ch == '.') {
          if (i == 0) { return null; }
          return value.substring(0, i);  // truncate to integer.
        } else if (!('0' <= ch && ch <= '9')) {
          return null;
        }
      }
      return value;
    }
  };

  /**
   * Allows {@code <img>} elements from HTTP, HTTPS, and relative sources.
   */
  public static final PolicyFactory IMAGES = new HtmlPolicyBuilder()
      .allowUrlProtocols("http", "https").allowElements("img")
      .allowAttributes("alt", "src").onElements("img")
      .allowAttributes("border", "height", "width").matching(INTEGER)
          .onElements("img")
      .toFactory();

  private Sanitizers() {
    // Uninstantiable.
  }
}
