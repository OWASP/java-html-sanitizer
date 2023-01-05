# OWASP Java HTML Sanitizer Change Log

Most recent at top.
  * Release 20220608.1
    * Fix bugs in CSS tokenization
    * Fix deocding of HTML character references that lack semicolons
      like `&para` in HTML attribute values that affected
      URL query parameters.
  * Release 20211018.2
    * Tweak how we address CVE-2021-42575 to be more tailored and to
      interfere less with `<style>` element content in general.  We
      still advise not allowing attacker controlled `<style>` content.
  * Release 20211018.1
    * Fix [CVE-2021-42575](https://docs.google.com/document/d/11SoX296sMS0XoQiQbpxc5pNxSdbJKDJkm5BDv0zrX50/edit#)
    * Changes rendering of `<style>` elements by wrapping text content
      in HTML comments and CDATA section tags so that even when
      content is not treated as CDATA, it will not be treated as
      active content.
  * Release 20200713.1
    * Do not lower-case SVG/MathML names.
      This shouldn't cause problems since it was hard to write policies for
      SBG, but be aware that SVG's `<textArea>` is now distinct from HTML's `<textarea>`.
  * Release 20200615.1
    * Change `.and` when combining two policies to respect explicit `skipIfEmpty` decisions.
    * HTML entity decoding now follows HTML standard rules about when a semicolon is optional.
      [Fixes #193](https://github.com/OWASP/java-html-sanitizer/issues/193)
    * Fix table formatting [#137](https://github.com/OWASP/java-html-sanitizer/issues/137)
  * Release 20191001.1
    * Package as an OSGI bundle
  * Release 20190610.1
    * Recognize named HTML entities added in the last few years.
  * Release 20190503.1
    * Make Encoding class public so that clients can use HTML text decoder.
    * Fix bug in srcset handling.
  * Release 20190325.1
    * Properly parse `srcset` attribute values to apply URL policy to
      each URL in turn.
    * Update dependency on guava version to 27.1-jre to avoid causing clients
      problems with CVE-2018-10237.  Specify Maven property `guava.version`
      to override.
    * Compatible with JDK 11.
  * Release 20181114.1
    * Compatible with guava > 19 including 21.x.x - 27.x.x
    * Public API now supports custom style creation.
    * Tweaks to handline of [HTML comment like constructs](https://www.w3.org/TR/html5/scripting-1.html#restrictions-for-contents-of-script-elements) in script element bodies.
  * Release 20180219.1
    * Strip ZWNJ from MacOS and iOS [crashing text sequences](https://manishearth.github.io/blog/2018/02/15/picking-apart-the-crashing-ios-string/)
  * Release 20171016.1
    * Allow underscores in attribute names.
  * Release 20170515.1
    * Fixed performance regression in 20170512.1
    * Fixed code layout issue that was breaking j2objc.
  * Release 20170512.1
    * Allow hyphens in font-family names.
    * Rework policy compilation of policies so PolicyFactory.and(...) is
      commutative.
  * Release 20170411.1
    * Get rid of dependency on resource to ease use with j2objc
  * Release 20170408.1
    * Fix some bugs in the tag balancer introduced when we swapped in
      the empirically derived tag metadata.
  * Release 20170329.1
    * Rework how element containment is done to use element metadata
      derived by interrogating browsers.
      See [announcement](https://groups.google.com/forum/#!topic/owasp-java-html-sanitizer-support/KPOEjctiB_A) for more detail.
    * Minor bugfixes
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
