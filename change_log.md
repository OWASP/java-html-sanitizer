# OWASP Java HTML Sanitizer Change Log

Most recent at top.

  * Release 20160924.1
    * Allow !important in style attributes when styling is allowed.
  * Release 20160827.1
    * When `target="..."` is present on a link, add `rel="noopener noreferrer"`
      to prevent linked pages from using the JavaScript `window.opener` to
      redirect to phishing pages.
    * No longer depends on an obsolete guava via a transitive dependency and
      the explicit guava dependency is now `<scope>provided</scope>` for
      greater compatibility.
  * Release 20160614.1
    * URLs are allowed in style="..." via HtmlPolicyBuilder.allowUrlsInStyles
  * Release 20160526.1
    * Added support for pre-processors and post-processors so that there
      is no need for clients to do textual search/replace on the
      untrusted input or the trusted output.
  * Release 20160413.1
    * Integrated support for Safe HTML Types and the Fences enforcer to allow
      the sanitizer to produce safe-contract-types.
    * Fixed bug 52: `<a>` can contain `<div>` per HTML5 rules.
  * 1.1.  Fixed bug that was causing end tags that matched dropped open tags to be mismatched.
    Changed escaping of HTML text nodes to prevent [client-side template systems](docs/client-side-templates.md) from mistakenly finding executable code in sanitized HTML fragments.
  * Migrated from SVN repo on code.google.com to Github.  Following numbers are SVN revision numbers
  * SVN r234.  Cross-licensed under BSD 3 and Apache 2 Licenses.
  * SVN r231.  Fixed bug: `Sanitizers.STYLES.and(...)` dropped `style="..."` attributes.
  * SVN r220.  `allowWithoutAttributes(true)` was being ignored for a subset of elements when policies were ANDED.
  * SVN r218.  Fixed bug: case-sensitivity of URL protocols was ignored when a set of protocols other than the standard set was used.
  * SVN r209.  Reworked `CssSchema` to allow users to extend the default property white-list.
  * SVN r198.  Replaced CSS sanitizer with one that does token-level filtering, and replaces the old CSS lexer that used regular expressions with one that doesn't back-track, or behave quadratically on crafted inputs.
  * SVN r173.  Fixed bug: tag balancer allowed `</p>` to close a table, so rewrote tag balancer to recognize scoping elements per HTML5.
  * SVN r164.  Fixed bug: missing bit in HTML schema led to text in `<option>` elements being elided even when the elements themselves were white-listed.
  * SVN r161.  Fixed bug: `requireRelNoFollowOnLinks()` was implicitly allowing the `a` element.  Changed this to be consistent with document: no elements are allowed that do not appear in a call to `allowElements`.
  * SVN r132.  Add methods to policy builder to specify which elements are allowed to contain text and change default to disallow text in CDATA elements whose content is often not plain text.  If custom element policies that change the element type fail, make sure the policy allows the output element type.
  * SVN r122.  Restrict where text-nodes can validly appear in output per HTML5 rules and changed the tag balancer to do better error recovery on misplaced phrasing content.
  * SVN r114.  Changed rendering to ensure that the output HTML is valid XML when the policy prohibits [HTML raw text & RCDATA](http://www.whatwg.org/specs/web-apps/current-work/multipage/syntax.html#raw-text-elements) elements as is almost always the case.
  * SVN r104.  Changed lexer to treat `<?...>` using the HTML5 bogus comment state grammar which agrees with XML's processing instruction production.  Previously, the token ended at the first `"?>"` or end-of-file instead of the first `">"`.
  * SVN r99.  Fixed problem with URL protocol white-listing that caused legitimate URLs to be rejected.
  * SVN r88.  Cleaned up raw-text tag handling. XMP, LISTING, PLAINTEXT now handled by substitution in the renderer and changed NOSCRIPT and friends so they are treated consistently when elided as when present in output.  Added workaround for IE8 innerHTML wierdness.
  * SVN r83.  Prevent DoS of browsers via extremely deeply nested tags.  In sanitized CSS, allow CSS property `background-color` and `font-size`s specified in `px`.
  * SVN r74.  Added convenient pre-packaged policies in Sanitizers.  Fixed bug in how warnings are reported via the badHtml Handler.
  * SVN r50.  Better handling of supplementary codepoints to avoid UTF-16/UCS-2 confusion in browsers.
  * SVN r48.  Added new HTML5 URL attributes to list used to safeguard URL attributes in `HtmlPolicyBuilder`.
  * SVN r42.  Changed `HtmlSanitizer.sanitize` to allow `null` as a valid value for the HTML snippet.
