package org.owasp.html;

import com.google.common.collect.ImmutableMap;

/**
 * From section 8.1.2.6 of http://www.whatwg.org/specs/web-apps/current-work/
 * <p>
 * The text in CDATA and RCDATA elements must not contain any
 * occurrences of the string "</" (U+003C LESS-THAN SIGN, U+002F
 * SOLIDUS) followed by characters that case-insensitively match the
 * tag name of the element followed by one of U+0009 CHARACTER
 * TABULATION, U+000A LINE FEED (LF), U+000B LINE TABULATION, U+000C
 * FORM FEED (FF), U+0020 SPACE, U+003E GREATER-THAN SIGN (>), or
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
 * @author mikesamuel@gmail.com
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
      // HTML5 does not treat listing as CDATA, but HTML2 does
      // at http://www.w3.org/MarkUp/1995-archive/NonStandard.html
      // Listing is not supported by browsers.
      .put("listing", CDATA_SOMETIMES)

      // Technically, only if embeds, frames, and scripts, respectively, are
      // enabled.
      .put("noembed", CDATA_SOMETIMES)
      .put("noframes", CDATA_SOMETIMES)
      .put("noscript", CDATA_SOMETIMES)
      .put("comment", CDATA_SOMETIMES)  // IE only

      // Runs till end of file.
      .put("plaintext", PLAIN_TEXT)

      .put("script", CDATA)
      .put("style", CDATA)

      // Textarea and Title are RCDATA, not CDATA, so decode entity references.
      .put("textarea", RCDATA)
      .put("title", RCDATA)

      .put("xmp", CDATA)

      // Nodes that can't contain content.
      .put("base", VOID)
      .put("link", VOID)
      .put("meta", VOID)
      .put("hr", VOID)
      .put("br", VOID)
      .put("img", VOID)
      .put("embed", VOID)
      .put("param", VOID)
      .put("area", VOID)
      .put("col", VOID)
      .put("input", VOID)
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
