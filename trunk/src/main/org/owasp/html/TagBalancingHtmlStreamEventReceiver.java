package org.owasp.html;

import java.util.List;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Lists;

/**
 * Wraps an HTML stream event receiver to fill in missing close tags.
 * If the balancer is given the HTML {@code <p>1<p>2}, the wrapped receiver will
 * see events equivalent to {@code <p>1</p><p>2</p>}.
 *
 * @author Mike Samuel <mikesamuel@gmail.com>
 */
@TCB
public class TagBalancingHtmlStreamEventReceiver
    implements HtmlStreamEventReceiver {
  private final HtmlStreamEventReceiver underlying;
  private final List<String> openElements = Lists.newArrayList();

  public TagBalancingHtmlStreamEventReceiver(
      HtmlStreamEventReceiver underlying) {
    this.underlying = underlying;
  }

  public void openDocument() {
    underlying.openDocument();
  }

  public void closeDocument() {
    while (!openElements.isEmpty()) {
      closeTag(openElements.get(openElements.size() - 1));
    }
    underlying.closeDocument();
  }

  public void openTag(String elementName, List<String> attrs) {
    String canonElementName = HtmlLexer.canonicalName(elementName);
    String optionalEndTagPartition = END_TAG_PARTITIONS.get(canonElementName);
    if (optionalEndTagPartition != null) {
      int n = openElements.size();
      while (--n >= 0) {
        if (!optionalEndTagPartition.equals(
                END_TAG_PARTITIONS.get(openElements.get(n)))) {
          break;
        }
        underlying.closeTag(openElements.remove(n));
      }
    }
    if (HtmlTextEscapingMode.VOID != HtmlTextEscapingMode.getModeForTag(
            canonElementName)) {
      openElements.add(canonElementName);
    }
    underlying.openTag(elementName, attrs);
  }

  public void closeTag(String elementName) {
    String canonElementName = HtmlLexer.canonicalName(elementName);
    int index = openElements.lastIndexOf(canonElementName);
    if (index < 0) { return; }  // Don't close unopened tags.
    int last = openElements.size();
    while (--last > index) {
      String unclosedElementName = openElements.remove(last);
      underlying.closeTag(unclosedElementName);
    }
    openElements.remove(index);
    underlying.closeTag(elementName);
  }

  public void text(String text) {
    underlying.text(text);
  }


  private static final ImmutableMap<String, String> END_TAG_PARTITIONS
      = ImmutableMap.<String, String>builder()
      .put("body", "body")
      .put("colgroup", "colgroup")
      .put("dd", "dd")
      .put("dt", "dd")
      .put("head", "body")
      .put("li", "li")
      .put("option", "option")
      .put("p", "p")
      .put("tbody", "tbody")
      .put("td", "td")
      .put("tfoot", "tbody")
      .put("th", "td")
      .put("thead", "tbody")
      .put("tr", "tr")
      .build();
}
