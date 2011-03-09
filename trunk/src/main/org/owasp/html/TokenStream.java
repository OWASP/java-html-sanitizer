package org.owasp.html;

interface TokenStream {
  HtmlToken next();
  boolean hasNext();
}
