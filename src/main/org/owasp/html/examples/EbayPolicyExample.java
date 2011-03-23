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
import com.google.common.base.Predicate;
import com.google.common.base.Throwables;
import com.google.common.io.CharStreams;

/**
 * Based on the
 * <a href="http://www.owasp.org/index.php/Category:OWASP_AntiSamy_Project#Stage_2_-_Choosing_a_base_policy_file">AntiSamy EBay example</a>.
 * <blockquote>
 * eBay (http://www.ebay.com/) is the most popular online auction site in the
 * universe, as far as I can tell. It is a public site so anyone is allowed to
 * post listings with rich HTML content. It's not surprising that given the
 * attractiveness of eBay as a target that it has been subject to a few complex
 * XSS attacks. Listings are allowed to contain much more rich content than,
 * say, Slashdot- so it's attack surface is considerably larger. The following
 * tags appear to be accepted by eBay (they don't publish rules):
 * {@code <a>},...
 * </blockquote>
 */
public class EbayPolicyExample {

  // Some common regular expression definitions.

  // The 16 colors defined by the HTML Spec (also used by the CSS Spec)
  private static final Pattern COLOR_NAME = Pattern.compile(
      "(aqua|black|blue|fuchsia|gray|grey|green|lime|maroon|navy|olive|purple"
      + "|red|silver|teal|white|yellow)");

  // HTML/CSS Spec allows 3 or 6 digit hex to specify color
  private static final Pattern COLOR_CODE = Pattern.compile(
      "(#([0-9a-fA-F]{6}|[0-9a-fA-F]{3}))");

  private static final Pattern NUMBER_OR_PERCENT = Pattern.compile(
      "(\\d)+(%{0,1})");
  private static final Pattern PARAGRAPH = Pattern.compile(
      "([\\p{L}\\p{N},'\\.\\s\\-_\\(\\)]|&[0-9]{2};)*");
  private static final Pattern HTML_ID = Pattern.compile(
      "[a-zA-Z0-9\\:\\-_\\.]+");
  // force non-empty with a '+' at the end instead of '*'
  private static final Pattern HTML_TITLE = Pattern.compile(
      "[\\p{L}\\p{N}\\s\\-_',:\\[\\]!\\./\\\\\\(\\)&]*");
  private static final Pattern HTML_CLASS = Pattern.compile(
      "[a-zA-Z0-9\\s,\\-_]+");

  private static final Pattern ONSITE_URL = Pattern.compile(
      "([\\p{L}\\p{N}\\\\\\.\\#@\\$%\\+&;\\-_~,\\?=/!]+|\\#(\\w)+)");
  private static final Pattern OFFSITE_URL = Pattern.compile(
      "(\\s)*((ht|f)tp(s?)://|mailto:)[\\p{L}\\p{N}]+"
      + "[\\p{L}\\p{N}\\p{Zs}\\.\\#@\\$%\\+&;:\\-_~,\\?=/!\\(\\)]*(\\s)*");

  private static final Pattern NUMBER = Pattern.compile(
      "(-|\\+)?([0-9]+(\\.[0-9]+)?)");

  private static final Pattern NAME = Pattern.compile("[a-zA-Z0-9\\-_\\$]+");

  private static final Pattern ALIGN = Pattern.compile(
      "(?i)cener|left|right|justify|char");

  private static final Pattern VALIGN = Pattern.compile(
      "(?i)baseline|bottom|middle|top");

  private static final Predicate<String> COLOR_NAME_OR_COLOR_CODE
      = new Predicate<String>() {
        public boolean apply(String s) {
          return COLOR_NAME.matcher(s).matches()
              || COLOR_CODE.matcher(s).matches();
        }
      };

  private static final Predicate<String> ONSITE_OR_OFFSITE_URL
      = new Predicate<String>() {
        public boolean apply(String s) {
          return ONSITE_URL.matcher(s).matches()
              || OFFSITE_URL.matcher(s).matches();
        }
      };

  private static final Pattern HISTORY_BACK = Pattern.compile(
      "(?:javascript:)?\\Qhistory.go(-1)\\E");

  private static final Pattern ONE_CHAR = Pattern.compile(".?");



  public static final Function<HtmlStreamEventReceiver, HtmlSanitizer.Policy>
      POLICY_DEFINITION = new HtmlPolicyBuilder()
          .allowAttributesGlobally(HTML_ID, "id")
          .allowAttributesGlobally(HTML_CLASS, "class")
          .allowAttributesGlobally(Pattern.compile("[a-zA-Z]{2,20}"), "lang")
          .allowAttributesGlobally(HTML_TITLE, "title")
          .allowStyling()
          .allowAttributesOnElement(ALIGN, "p", "align")
          .allowAttributesOnElement(HTML_ID, "label", "for")
          .allowAttributesOnElement(
              COLOR_NAME_OR_COLOR_CODE, "font", "color")
          .allowAttributesOnElement(
              Pattern.compile("[\\w;, \\-]+"), "font", "face")
          .allowAttributesOnElement(NUMBER, "font", "size")
          .allowAttributesOnElement(ONSITE_OR_OFFSITE_URL, "a", "href")
          .allowStandardUrlProtocols()
          .allowAttributesOnElement("a", "nohref")
          .allowAttributesOnElement(NAME, "a", "name")
          .allowAttributesOnElement(
              HISTORY_BACK, "a",
              "onfocus", "onblur", "onclick", "onmousedown", "onmouseup")
          .requireRelNofollowOnLinks()
          .allowAttributesOnElement(ONSITE_OR_OFFSITE_URL, "img", "src")
          .allowAttributesOnElement(NAME, "img", "name")
          .allowAttributesOnElement(PARAGRAPH, "img", "alt")
          .allowAttributesOnElement(NUMBER_OR_PERCENT, "img", "height", "width")
          .allowAttributesOnElement(NUMBER, "img", "border", "hspace", "vspace")
          .allowAttributesOnElement(ALIGN, "img", "align")
          .allowAttributesOnElement(ALIGN, "thead", "align")
          .allowAttributesOnElement(VALIGN, "thead", "valign")
          .allowAttributesOnElement(NUMBER_OR_PERCENT, "thead", "charoff")
          .allowAttributesOnElement(ONE_CHAR, "thead", "char")
          .allowAttributesOnElement(ALIGN, "tfoot", "align")
          .allowAttributesOnElement(VALIGN, "tfoot", "valign")
          .allowAttributesOnElement(NUMBER_OR_PERCENT, "tfoot", "charoff")
          .allowAttributesOnElement(ONE_CHAR, "tfoot", "char")
          .allowAttributesOnElement(ALIGN, "tbody", "align")
          .allowAttributesOnElement(VALIGN, "tbody", "valign")
          .allowAttributesOnElement(NUMBER_OR_PERCENT, "tbody", "charoff")
          .allowAttributesOnElement(ONE_CHAR, "tbody", "char")
          .allowAttributesOnElement(
              NUMBER_OR_PERCENT, "table", "height", "width")
          .allowAttributesOnElement(
              NUMBER, "table", "border", "cellpadding", "cellspacing")
          .allowAttributesOnElement(COLOR_NAME_OR_COLOR_CODE,
              "table", "bgcolor")
          .allowAttributesOnElement(ONSITE_URL, "table", "background")
          .allowAttributesOnElement(ALIGN, "table", "align")
          .allowAttributesOnElement(
              Pattern.compile("(?i)noresize"), "table", "noresize")
          .allowAttributesOnElement(ONSITE_URL, "td", "background")
          .allowAttributesOnElement(COLOR_NAME_OR_COLOR_CODE,
              "td", "bgcolor")
          .allowAttributesOnElement(PARAGRAPH, "td", "abbr")
          .allowAttributesOnElement(NAME, "td", "axis", "headers")
          .allowAttributesOnElement(
              Pattern.compile("(?i)(?:row|col)(?:group)?"), "td", "scope")
          .allowAttributesOnElement("td", "nowrap")
          .allowAttributesOnElement(
              NUMBER_OR_PERCENT, "td", "height", "width")
          .allowAttributesOnElement(ALIGN, "td", "align")
          .allowAttributesOnElement(VALIGN, "td", "valign")
          .allowAttributesOnElement(NUMBER_OR_PERCENT, "td", "charoff")
          .allowAttributesOnElement(ONE_CHAR, "td", "char")
          .allowAttributesOnElement(NUMBER, "td", "colspan", "rowspan")
          .allowAttributesOnElement(ONSITE_URL, "th", "background")
          .allowAttributesOnElement(COLOR_NAME_OR_COLOR_CODE,
              "th", "bgcolor")
          .allowAttributesOnElement(PARAGRAPH, "th", "abbr")
          .allowAttributesOnElement(NAME, "th", "axis", "headers")
          .allowAttributesOnElement(
              Pattern.compile("(?i)(?:row|col)(?:group)?"), "th", "scope")
          .allowAttributesOnElement("th", "nowrap")
          .allowAttributesOnElement(
              NUMBER_OR_PERCENT, "th", "height", "width")
          .allowAttributesOnElement(ALIGN, "th", "align")
          .allowAttributesOnElement(VALIGN, "th", "valign")
          .allowAttributesOnElement(NUMBER_OR_PERCENT, "th", "charoff")
          .allowAttributesOnElement(ONE_CHAR, "th", "char")
          .allowAttributesOnElement(NUMBER, "th", "colspan", "rowspan")
          .allowAttributesOnElement(
              NUMBER_OR_PERCENT, "tr", "height", "width")
          .allowAttributesOnElement(ALIGN, "tr", "align")
          .allowAttributesOnElement(VALIGN, "tr", "valign")
          .allowAttributesOnElement(NUMBER_OR_PERCENT, "tr", "charoff")
          .allowAttributesOnElement(ONE_CHAR, "tr", "char")
          .allowAttributesOnElement(ONSITE_URL, "tr", "background")
          .allowAttributesOnElement(
              NUMBER_OR_PERCENT, "colgroup", "span", "width")
          .allowAttributesOnElement(ALIGN, "colgroup", "align")
          .allowAttributesOnElement(VALIGN, "colgroup", "valign")
          .allowAttributesOnElement(NUMBER_OR_PERCENT, "colgroup", "charoff")
          .allowAttributesOnElement(ONE_CHAR, "colgroup", "char")
          .allowAttributesOnElement(
              NUMBER_OR_PERCENT, "col", "span", "width")
          .allowAttributesOnElement(ALIGN, "col", "align")
          .allowAttributesOnElement(VALIGN, "col", "valign")
          .allowAttributesOnElement(NUMBER_OR_PERCENT, "col", "charoff")
          .allowAttributesOnElement(ONE_CHAR, "col", "char")
          .allowElements(
              "label", "noscript", "h1", "h2", "h3", "h4", "h5", "h6",
              "p", "i", "b", "u", "strong", "em", "small", "big", "pre", "code",
              "cite", "samp", "sub", "sup", "strike", "center", "blockquote",
              "hr", "br", "col", "font", "map", "span", "div", "img",
              "ul", "ol", "li", "dd", "dt", "dl", "tbody", "thead", "tfoot",
              "table", "td", "th", "tr", "colgroup", "fieldset", "legend")
          .toFactory();

  public static void main(String[] args) throws IOException {
    if (args.length == 1) {
      System.err.println("Reads from STDIN and writes to STDOUT");
      System.exit(-1);
    }
    System.err.println("[Reading from STDIN]");
    String html = CharStreams.toString(
        new InputStreamReader(System.in, Charsets.UTF_8));
    HtmlStreamRenderer renderer = HtmlStreamRenderer.create(
        System.out,
        new Handler<IOException>() {
          public void handle(IOException ex) {
            Throwables.propagate(ex);  // System.out suppresses IOExceptions
          }
        },
        new Handler<String>() {
          public void handle(String x) {
            throw new AssertionError(x);
          }
        });
    HtmlSanitizer.sanitize(html, POLICY_DEFINITION.apply(renderer));
  }
}
