package org.owasp.html;

public interface TokenStream {
  HtmlToken next() throws ParseException;
  boolean hasNext() throws ParseException;
}
