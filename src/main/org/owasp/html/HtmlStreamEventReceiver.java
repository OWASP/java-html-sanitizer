package org.owasp.html;

import java.util.List;

/**
 * A light-weight SAX-like listener for HTML.
 */
public interface HtmlStreamEventReceiver {

  public void openDocument();

  public void closeDocument();

  /**
   * @param attrs alternating attribute names and values.
   */
  public void openTag(String elementName, List<String> attrs);

  public void closeTag(String elementName);

  public void text(String text);

}
