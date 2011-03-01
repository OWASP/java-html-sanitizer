package org.owasp.html;

import java.io.File;
import java.io.StringReader;
import java.util.List;
import java.util.ListIterator;

import org.w3c.dom.Node;
import org.xml.sax.InputSource;

import com.google.common.base.Charsets;
import com.google.common.io.Files;

import nu.validator.htmlparser.dom.HtmlDocumentBuilder;

public class Benchmark {

  public static void main(String[] args) throws Exception {
    int n = 0;

    String html = Files.toString(new File(args[0]), Charsets.UTF_8);
    for (int i = 100; --i >= 0;) {
      n += parseUsingLibhtmlparser(html);
    }

    for (int i = 100; --i >= 0;) {
      n += sanitize(html).length();
    }

    long t0 = System.nanoTime();
    for (int i = 100; --i >= 0;) {
      n += parseUsingLibhtmlparser(html);
    }
    long t1 = System.nanoTime();

    long t2 = System.nanoTime();
    for (int i = 100; --i >= 0;) {
      n += sanitize(html).length();
    }
    long t3 = System.nanoTime();

    System.err.println(String.format("Tree parse    : %12d", (t1 - t0)));
    System.err.println(String.format("Full sanitize : %12d", (t3 - t2)));
  }

  private static int parseUsingLibhtmlparser(String html) throws Exception {
    HtmlDocumentBuilder parser = new HtmlDocumentBuilder();
    Node node = parser.parse(new InputSource(new StringReader(html)));
    return System.identityHashCode(node);
  }

  private static String sanitize(String html) throws Exception {
    StringBuilder sb = new StringBuilder(html.length());

    final HtmlStreamRenderer renderer = HtmlStreamRenderer.create(
        sb, new Handler<String>() {

          @Override
          public void handle(String x) {
            throw new AssertionError(x);
          }
        });

    new HtmlSanitizer().sanitize(html, new HtmlSanitizer.Policy() {

      @Override
      public void openDocument() {
        renderer.openDocument();
      }

      @Override
      public void closeDocument() {
        renderer.closeDocument();
      }

      @Override
      public void text(String textChunk) {
        renderer.text(textChunk);
      }

      @Override
      public void openTag(String elementName, List<String> attrs) {
        if ("a".equals(elementName)) {
          for (ListIterator<String> it = attrs.listIterator(); it.hasNext();) {
            String name = it.next();
            if ("href".equals(name)) {
              it.next();
            } else {
              it.remove();
              it.next();
              it.remove();
            }
          }
          renderer.openTag(elementName, attrs);
        }
      }

      @Override
      public void closeTag(String elementName) {
        if ("a".equals(elementName)) {
          renderer.closeTag(elementName);
        }
      }
    });
    return sb.toString();
  }

}
