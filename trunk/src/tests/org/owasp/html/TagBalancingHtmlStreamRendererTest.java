package org.owasp.html;

import com.google.common.collect.ImmutableList;

import junit.framework.TestCase;

public class TagBalancingHtmlStreamRendererTest extends TestCase {

  public final void testTagBalancing() {
    final StringBuilder htmlOutputBuffer = new StringBuilder();
    HtmlStreamEventReceiver balancer = new TagBalancingHtmlStreamEventReceiver(
        HtmlStreamRenderer.create(htmlOutputBuffer, new Handler<String>() {
          @Override
          public void handle(String x) {
            fail("An unexpected error was raised during the testcase");
          }
        }));

    balancer.openDocument();
    balancer.openTag("html", ImmutableList.<String>of());
    balancer.openTag("head", ImmutableList.<String>of());
    balancer.openTag("title", ImmutableList.<String>of());
    balancer.text("Hello, <<World>>!");
    // TITLE closed with case-insensitive differnet name.
    balancer.closeTag("TITLE");
    balancer.closeTag("head");
    balancer.openTag("body", ImmutableList.<String>of());
    balancer.openTag("p", ImmutableList.of("id", "p'0"));
    balancer.text("Hello,");
    balancer.openTag("Br", ImmutableList.<String>of());
    balancer.text("<<World>>!");
    // HTML, P, and BODY unclosed, but BR not.
    balancer.closeDocument();

    assertEquals(
        "<html><head><title>Hello, &lt;&lt;World&gt;&gt;!</title></head>"
        + "<body><p id=\"p&#39;0\">Hello,"
        + "<br>&lt;&lt;World&gt;&gt;!</p></body></html>",
        htmlOutputBuffer.toString());
  }
}
