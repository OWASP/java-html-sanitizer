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

/**
 * Types of HTML tokens.
 *
 * @author Mike Samuel (mikesamuel@gmail.com)
 */
enum HtmlTokenType {
  /**
   * An HTML or XML attribute name consisting of characters other than
   * whitespace, =, or specials.
   */
  ATTRNAME,
  /** An HTML value, possibly a quoted string. */
  ATTRVALUE,
  /**
   * An HTML bogus comment, XML Prologue, or XML processing instruction like
   * <tt>&lt;? content &gt;</tt>.
   */
  QMARKMETA,
  /** An HTML or XML style comment, <tt>&lt;!-- for example --></tt>. */
  COMMENT,
  /**
   * A directive such as a DOCTYPE declaration.
   */
  DIRECTIVE,
  /** Unescaped tag, for instance, inside a script, or {@code xmp} tag. */
  UNESCAPED,
  /**
   * A quoted string.  Should not show up in well formed HTML, but may where
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
