package org.owasp.html;

import java.util.List;

public interface HtmlStreamEventReceiver {

  public void openDocument();

  public void closeDocument();

  public void openTag(String elementName, List<String> attrs);

  public void closeTag(String elementName);

  public void text(String text);

}
