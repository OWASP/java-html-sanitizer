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

import com.google.common.collect.ImmutableMap;

/**
 * From section 8.1.2.6 of http://www.whatwg.org/specs/web-apps/current-work/
 * <p>
 * The text in CDATA and RCDATA elements must not contain any
 * occurrences of the string {@code "</"} (U+003C LESS-THAN SIGN, U+002F
 * SOLIDUS) followed by characters that case-insensitively match the
 * tag name of the element followed by one of U+0009 CHARACTER
 * TABULATION, U+000A LINE FEED (LF), U+000B LINE TABULATION, U+000C
 * FORM FEED (FF), U+0020 SPACE, U+003E GREATER-THAN SIGN ({@code >}), or
 * U+002F SOLIDUS (/), unless that string is part of an escaping
 * text span.
 * </p>
 *
 * <p>
 * See also
 * http://www.whatwg.org/specs/web-apps/current-work/#cdata-rcdata-restrictions
 * for the elements which fall in each category.
 * </p>
 *
 * @author Mike Samuel (mikesamuel@gmail.com)
 */
public enum HtmlTextEscapingMode {
  /**
   * Normally escaped character data that breaks around comments and tags.
   */
  PCDATA,
  /**
   * A span of text where HTML special characters are interpreted literally,
   * as in a SCRIPT tag.
   */
  CDATA,
  /**
   * Like {@link #CDATA} but only for certain browsers.
   */
  CDATA_SOMETIMES,
  /**
   * A span of text and character entity references where HTML special
   * characters are interpreted literally, as in a TITLE tag.
   */
  RCDATA,
  /**
   * A span of text where HTML special characters are interpreted literally,
   * where there is no end tag.  PLAIN_TEXT runs until the end of the file.
   */
  PLAIN_TEXT,

  /**
   * Cannot contain data.
   */
  VOID,
  ;

  private static final ImmutableMap<String, HtmlTextEscapingMode> ESCAPING_MODES
      = ImmutableMap.<String, HtmlTextEscapingMode>builder()
      .put("iframe", CDATA)
      // HTML5 does not treat listing as CDATA and treats XMP as deprecated,
      // but HTML2 does at
      // http://www.w3.org/MarkUp/1995-archive/NonStandard.html
      // Listing is not supported by browsers.
      .put("listing", CDATA_SOMETIMES)
      .put("xmp", CDATA)

      // Technically, noembed, noscript and noframes are CDATA_SOMETIMES but
      // we can only be hurt by allowing tag content that looks like text so
      // we treat them as regular..
      //.put("noembed", CDATA_SOMETIMES)
      //.put("noframes", CDATA_SOMETIMES)
      //.put("noscript", CDATA_SOMETIMES)
      .put("comment", CDATA_SOMETIMES)  // IE only

      // Runs till end of file.
      .put("plaintext", PLAIN_TEXT)

      .put("script", CDATA)
      .put("style", CDATA)

      // Textarea and Title are RCDATA, not CDATA, so decode entity references.
      .put("textarea", RCDATA)
      .put("title", RCDATA)

      // Nodes that can't contain content.
      // http://www.w3.org/TR/html-markup/syntax.html#void-elements
      .put("area", VOID)
      .put("base", VOID)
      .put("br", VOID)
      .put("col", VOID)
      .put("command", VOID)
      .put("embed", VOID)
      .put("hr", VOID)
      .put("img", VOID)
      .put("input", VOID)
      .put("keygen", VOID)
      .put("link", VOID)
      .put("meta", VOID)
      .put("param", VOID)
      .put("source", VOID)
      .put("track", VOID)
      .put("wbr", VOID)

       // EMPTY per http://www.w3.org/TR/REC-html32#basefont
      .put("basefont", VOID)
      .put("isindex", VOID)
      .build();


  /**
   * The mode used for content following a start tag with the given name.
   */
  public static HtmlTextEscapingMode getModeForTag(String canonTagName) {
    HtmlTextEscapingMode mode = ESCAPING_MODES.get(canonTagName);
    return mode != null ? mode : PCDATA;
  }

  /**
   * True iff the content following the given tag allows escaping text
   * spans: {@code <!--&hellip;-->} that escape even things that might
   * be an end tag for the corresponding open tag.
   */
  public static boolean allowsEscapingTextSpan(String canonTagName) {
    // <xmp> and <plaintext> do not admit escaping text spans.
    return "style".equals(canonTagName) || "script".equals(canonTagName)
        || "noembed".equals(canonTagName) || "noscript".equals(canonTagName)
        || "noframes".equals(canonTagName);
  }

  /**
   * True if content immediately following the start tag must be treated as
   * special CDATA so that &lt;'s are not treated as starting tags, comments
   * or directives.
   */
  public static boolean isTagFollowedByLiteralContent(String canonTagName) {
    HtmlTextEscapingMode mode = getModeForTag(canonTagName);
    return mode != PCDATA && mode != VOID;
  }

  /**
   * True iff the tag cannot contain any content -- will an HTML parser consider
   * the element to have ended immediately after the start tag.
   */
  public static boolean isVoidElement(String canonTagName) {
    return getModeForTag(canonTagName) == VOID;
  }
}
