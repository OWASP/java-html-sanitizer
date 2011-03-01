package org.owasp.html;

/**
 * Types of html tokens.
 *
 * @author mikesamuel@gmail.com
 */
public enum HtmlTokenType {
  /**
   * An html or xml attribute name consisting of characters other than
   * whitespace, =, or specials.
   */
  ATTRNAME,
  /** An html value, possibly a quoted string. */
  ATTRVALUE,
  /** An html or xml style comment, <tt>&lt;!-- for example --></tt>. */
  COMMENT,
  /**
   * A directive such as a DOCTYPE declaration.
   */
  DIRECTIVE,
  /** Unescaped tag, for instance, inside a script, or xmp tag. */
  UNESCAPED,
  /**
   * A quoted string.  Should not show up in well formed html, but may where
   * there is an attribute value without a corresponding name.
   */
  QSTRING,
  /**
   * The beginning of a tag -- not to be confused with a start tag.
   * Valid tag beginnings include <tt>&lt;a</tt> and <tt>&lt;/a</tt>.  The
   * rest of the tag is a series of attribute names, values, and the tag end.
   */
  TAGBEGIN,
  /** The end of a tag.  Either <tt>&gt;</tt> or <tt>/&gt;</tt>. */
  TAGEND,
  /** A block of text, either inside a tag, or as element content. */
  TEXT,
  /** Ignorable whitespace nodes. */
  IGNORABLE,
  /** A server side script block a la php or jsp. */
  SERVERCODE,
  ;
}
