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

import org.junit.Test;

import com.google.common.base.Joiner;

import junit.framework.TestCase;

@SuppressWarnings("javadoc")
public class HtmlPolicyBuilderTest extends TestCase {

  static final String EXAMPLE = Joiner.on('\n').join(
      "<h1 id='foo'>Header</h1>",
      "<p onclick='alert(42)'>Paragraph 1<script>evil()</script></p>",
      ("<p><a href='java\0script:bad()'>Click</a> <a href='foo.html'>me</a>"
       + " <a href='http://outside.org/'>out</a></p>"),
      ("<p><img src=canary.png alt=local-canary>" +
       "<img src='http://canaries.org/canary.png'></p>"),
      "<p><b style=font-size:bigger>Fancy</b> with <i><b>soupy</i> tags</b>.",
      "<p style='color: expression(foo()); text-align: center;",
      "          /* direction: ltr */; font-weight: bold'>Stylish Para 1</p>",
      "<p style='color: red; font-weight; expression(foo());",
      "          direction: rtl; font-weight: bold'>Stylish Para 2</p>",
      "");

  @Test
  public static final void testTextFilter() {
    assertEquals(
        Joiner.on('\n').join(
            "Header",
            "Paragraph 1",
            "Click me out",
            "",
            "Fancy with soupy tags.",
            "Stylish Para 1",
            "Stylish Para 2",
            ""),
        apply(new HtmlPolicyBuilder()));
  }

  @Test
  public static final void testCannedFormattingTagFilter() {
    assertEquals(
        Joiner.on('\n').join(
            "Header",
            "Paragraph 1",
            "Click me out",
            "",
            "<b>Fancy</b> with <i><b>soupy</b></i><b> tags</b>.",
            "Stylish Para 1",
            "Stylish Para 2",
            ""),
        apply(new HtmlPolicyBuilder()
              .allowCommonInlineFormattingElements()));
  }

  @Test
  public static final void testCannedFormattingTagFilterNoItalics() {
    assertEquals(
        Joiner.on('\n').join(
            "Header",
            "Paragraph 1",
            "Click me out",
            "",
            "<b>Fancy</b> with <b>soupy</b><b> tags</b>.",
            "Stylish Para 1",
            "Stylish Para 2",
            ""),
        apply(new HtmlPolicyBuilder()
              .allowCommonInlineFormattingElements()
              .disallowElements("I")));
  }

  @Test
  public static final void testSimpleTagFilter() {
    assertEquals(
        Joiner.on('\n').join(
            "<h1>Header</h1>",
            "Paragraph 1",
            "Click me out",
            "",
            "Fancy with <i>soupy</i> tags.",
            "Stylish Para 1",
            "Stylish Para 2",
            ""),
        apply(new HtmlPolicyBuilder()
              .allowElements("h1", "i")));
  }

  @Test
  public static final void testLinksAllowed() {
    assertEquals(
        Joiner.on('\n').join(
            "Header",
            "Paragraph 1",
            // We haven't allowed any protocols so only relative URLs are OK.
            "Click <a href=\"foo.html\">me</a> out",
            "",
            "Fancy with soupy tags.",
            "Stylish Para 1",
            "Stylish Para 2",
            ""),
        apply(new HtmlPolicyBuilder()
              .allowElements("a")
              .allowAttributes("href").onElements("a")));
  }

  @Test
  public static final void testExternalLinksAllowed() {
    assertEquals(
        Joiner.on('\n').join(
            "Header",
            "Paragraph 1",
            "Click <a href=\"foo.html\">me</a>"
            + " <a href=\"http://outside.org/\">out</a>",
            "",
            "Fancy with soupy tags.",
            "Stylish Para 1",
            "Stylish Para 2",
            ""),
        apply(new HtmlPolicyBuilder()
              .allowElements("a")
              // Allows http.
              .allowStandardUrlProtocols()
              .allowAttributes("href").onElements("a")));
  }

  @Test
  public static final void testLinksWithNofollow() {
    assertEquals(
        Joiner.on('\n').join(
            "Header",
            "Paragraph 1",
            "Click <a href=\"foo.html\" rel=\"nofollow\">me</a> out",
            "",
            "Fancy with soupy tags.",
            "Stylish Para 1",
            "Stylish Para 2",
            ""),
        apply(new HtmlPolicyBuilder()
              .allowElements("a")
              // Allows http.
              .allowAttributes("href").onElements("a")
              .requireRelNofollowOnLinks()));
  }

  @Test
  public static final void testImagesAllowed() {
    assertEquals(
        Joiner.on('\n').join(
            "Header",
            "Paragraph 1",
            "Click me out",
            "<img src=\"canary.png\" alt=\"local-canary\" />",
            // HTTP img not output because only HTTPS allowed.
            "Fancy with soupy tags.",
            "Stylish Para 1",
            "Stylish Para 2",
            ""),
        apply(new HtmlPolicyBuilder()
              .allowElements("img")
              .allowAttributes("src", "alt").onElements("img")
              .allowUrlProtocols("https")));
  }

  @Test
  public static final void testStyleFiltering() {
    assertEquals(
        Joiner.on('\n').join(
            "<h1>Header</h1>",
            "<p>Paragraph 1</p>",
            "<p>Click me out</p>",
            "<p></p>",
            "<p><b>Fancy</b> with <i><b>soupy</b></i><b> tags</b>.",
            ("</p><p style=\"text-align:center;font-weight:bold\">"
             + "Stylish Para 1</p>"),
            ("<p style=\"color:red;direction:rtl;font-weight:bold\">"
             + "Stylish Para 2</p>"),
            ""),
        apply(new HtmlPolicyBuilder()
              .allowCommonInlineFormattingElements()
              .allowCommonBlockElements()
              .allowStyling()
              .allowStandardUrlProtocols()));
  }

  @Test
  public static final void testElementTransforming() {
    assertEquals(
        Joiner.on('\n').join(
            "<div class=\"header-h1\">Header</div>",
            "<p>Paragraph 1</p>",
            "<p>Click me out</p>",
            "<p></p>",
            "<p>Fancy with soupy tags.",
            "</p><p>Stylish Para 1</p>",
            "<p>Stylish Para 2</p>",
            ""),
        apply(new HtmlPolicyBuilder()
              .allowElements("h1", "p", "div")
              .allowElements(
                  new ElementPolicy() {
                    public String apply(
                        String elementName, List<String> attrs) {
                      attrs.add("class");
                      attrs.add("header-" + elementName);
                      return "div";
                    }
                  }, "h1")));
  }

  @Test
  public static final void testAllowUrlProtocols() {
    assertEquals(
        Joiner.on('\n').join(
            "Header",
            "Paragraph 1",
            "Click me out",
            "<img src=\"canary.png\" alt=\"local-canary\" />"
            + "<img src=\"http://canaries.org/canary.png\" />",
            "Fancy with soupy tags.",
            "Stylish Para 1",
            "Stylish Para 2",
            ""),
            apply(new HtmlPolicyBuilder()
            .allowElements("img")
            .allowAttributes("src", "alt").onElements("img")
            .allowUrlProtocols("http")));
  }

  @Test
  public static final void testPossibleFalloutFromIssue5() {
    assertEquals(
        "Bad",
        apply(
            new HtmlPolicyBuilder()
            .allowElements("a")
            .allowAttributes("href").onElements("a")
            .allowUrlProtocols("http"),

            "<a href='javascript:alert(1337)//:http'>Bad</a>"));
  }

  @Test
  public static final void testTextInOption() {
    assertEquals(
        "<select><option>1</option><option>2</option></select>",
        apply(
            new HtmlPolicyBuilder()
            .allowElements("select", "option"),

            "<select>\n  <option>1</option>\n  <option>2</option>\n</select>"));
  }

  @Test
  public static final void testEntities() {
    assertEquals(
        "(Foo)\u00a0(Bar)\u2666\u2666\u2666\u2666(Baz)"
        + "&#x14834;&#x14834;&#x14834;(Boo)",
        apply(
            new HtmlPolicyBuilder(),
            "(Foo)&nbsp;(Bar)&diams;&#9830;&#x2666;&#X2666;(Baz)"
            + "\ud812\udc34&#x14834;&#x014834;(Boo)"));
  }

  private static String apply(HtmlPolicyBuilder b) {
    return apply(b, EXAMPLE);
  }

  private static String apply(HtmlPolicyBuilder b, String src) {
    StringBuilder sb = new StringBuilder();
    HtmlSanitizer.Policy policy = b.build(HtmlStreamRenderer.create(sb,
        new Handler<String>() {
          public void handle(String x) { fail(x); }
        }));
    HtmlSanitizer.sanitize(src, policy);
    return sb.toString();
  }
}
