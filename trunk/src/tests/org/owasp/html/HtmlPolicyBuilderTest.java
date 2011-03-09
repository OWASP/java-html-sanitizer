package org.owasp.html;

import java.util.List;

import com.google.common.base.Joiner;

import junit.framework.TestCase;

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

  public final void testTextFilter() throws Exception {
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

  public final void testCannedFormattingTagFilter() throws Exception {
    assertEquals(
        Joiner.on('\n').join(
            "Header",
            "Paragraph 1",
            "Click me out",
            "",
            "<b>Fancy</b> with <i><b>soupy</b></i> tags.",
            "Stylish Para 1",
            "Stylish Para 2",
            ""),
        apply(new HtmlPolicyBuilder()
              .allowCommonInlineFormattingElements()));
  }

  public final void testCannedFormattingTagFilterNoItalics() throws Exception {
    assertEquals(
        Joiner.on('\n').join(
            "Header",
            "Paragraph 1",
            "Click me out",
            "",
            "<b>Fancy</b> with <b>soupy</b> tags.",
            "Stylish Para 1",
            "Stylish Para 2",
            ""),
        apply(new HtmlPolicyBuilder()
              .allowCommonInlineFormattingElements()
              .disallowElements("I")));
  }

  public final void testSimpleTagFilter() throws Exception {
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

  public final void testLinksAllowed() throws Exception {
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
              .allowAttributesOnElement("a", "href")));
  }

  public final void testExternalLinksAllowed() throws Exception {
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
              .allowAttributesOnElement("a", "href")));
  }

  public final void testLinksWithNofollow() throws Exception {
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
              .allowAttributesOnElement("a", "href")
              .requireRelNofollowOnLinks()));
  }

  public final void testImagesAllowed() throws Exception {
    assertEquals(
        Joiner.on('\n').join(
            "Header",
            "Paragraph 1",
            "Click me out",
            "<img src=\"canary.png\" alt=\"local-canary\">",
            // HTTP img not output because only HTTPS allowed.
            "Fancy with soupy tags.",
            "Stylish Para 1",
            "Stylish Para 2",
            ""),
        apply(new HtmlPolicyBuilder()
              .allowElements("img")
              .allowAttributesOnElement("img", "src", "alt")
              .allowUrlProtocols("https")));
  }

  public final void testStyleFiltering() throws Exception {
    assertEquals(
        Joiner.on('\n').join(
            "<h1>Header</h1>",
            "<p>Paragraph 1</p>",
            "<p>Click me out</p>",
            "<p></p>",
            "<p><b>Fancy</b> with <i><b>soupy</b></i> tags.",
            ("</p><p><font color=\"expression(foo())\" align=\"center\""
             + " style=\"font-weight:bold;\">"
             + "Stylish Para 1</font></p>"),
            ("<p><font color=\"red\" dir=\"rtl\" style=\"font-weight:bold;\">"
             + "Stylish Para 2</font></p>"),
            ""),
        apply(new HtmlPolicyBuilder()
              .allowCommonInlineFormattingElements()
              .allowCommonBlockElements()
              .allowStyling()
              .allowStandardUrlProtocols()));
  }

  public final void testElementTransforming() throws Exception {
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
              .allowElements("h1", "p")
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

  private String apply(HtmlPolicyBuilder b) throws Exception {
    StringBuilder sb = new StringBuilder();
    HtmlSanitizer.Policy policy = b.build(HtmlStreamRenderer.create(sb,
        new Handler<String>() {
          public void handle(String x) { fail(x); }
        }));
    HtmlSanitizer.sanitize(EXAMPLE, policy);
    return sb.toString();
  }

}
