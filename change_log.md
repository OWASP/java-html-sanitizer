# OWASP Java HTML Sanitizer Change Log

Most recent at top.
  * Next release
    * Text kept inside a `style`, `script` or `iframe` element, or any other
      element whose content the renderer emits unescaped, now has every tag
      removed, end tags included, instead of only the tags of elements the
      policy does not allow.  An allowed element's start tag was copied
      through with its attributes unvetted, and an end tag was kept when its
      element was allowed, so
      `<noscript><style></noscript><img src=x onerror=alert(1)></style></noscript>`
      came out unchanged under a policy allowing `noscript`, `style` with
      text and `img`.  A browser with scripting on reads `noscript` as raw
      text up to that inner `</noscript>` and then runs the handler; the
      same holds for `noframes` and `noembed` with scripting off, and a
      `comment` element's content is markup to every current browser.  The
      filter also keeps the text after a start tag with no matching end tag,
      which it used to discard to the end of the chunk, and keeps a `<` that
      opens no tag.
    * `HtmlPolicyBuilder.allowOnlyRelativeUrls()` now provides an explicit
      relative-only URL policy.  It allows URLs with neither a protocol nor
      an authority, but rejects absolute URLs and protocol-relative URLs such
      as `//example.org/`, including equivalent slash and backslash spellings
      that browsers resolve to an authority.  Unlike the default guard on a
      builder that never called `allowUrlProtocols`, this restriction
      intersects with every protocol allowlist and remains relative-only
      through `PolicyFactory.and`, including for `srcset` and `url()` in
      styles.
      Existing `and()` compositions that deliberately relied on a
      protocol-less factory to strip absolute URLs allowed by another factory
      should call `allowOnlyRelativeUrls()` on the restrictive builder before
      upgrading; without it, the change for issue #204 may widen those
      compositions to the protocols the other factory allows.  Issue #453.
    * `FilterUrlByProtocolAttributePolicy`, and so the protocol guard on every
      builder that did not allow both `http` and `https`, now rejects
      `/\`, `\/`, and `\\` at the start of a URL as it already rejected
      `//`.  Browsers resolving against an `http:` or `https:` page treat a
      backslash as a slash, so `\\example.org/` names the same authority
      as `//example.org/`.  Policies that allow both web protocols keep
      accepting these values, as they accept `//example.org/`.  Issue #453.
    * Self-closing SVG and MathML handling now follows the browser's current
      tree-construction context through HTML integration points, foreign
      content breakout tags, mismatched foreign end tags, and the end tags
      of HTML elements enclosing the foreign content.  A slash after
      an equals sign remains part of an unquoted attribute value, and a
      self-closing foreign element named `<title>`, `<style>`, `<textarea>`,
      or another HTML literal-content element closes without consuming the
      markup that follows it.  Issue #457.
    * Self-closing tags inside `<svg>` and `<math>` now close.  Browsers
      honor the self-closing flag on a start tag in foreign content, so
      `<path d="..."/>` is a complete, empty element there, and on `<svg/>`
      and `<math/>` themselves.  The sanitizer discarded the flag, so each
      self-closing `<path/>` nested inside the one before it and the end of
      the SVG closed them all at once:
      `<svg><path d="M0 0"/><path d="M1 1"/></svg>` came out as
      `<svg><path d="M0 0"><path d="M1 1"></path></path></svg>`, and now
      comes out as `<svg><path d="M0 0"></path><path d="M1 1"></path></svg>`.
      A policy sees such a tag as an open tag followed at once by its close
      tag.  Nothing changes in HTML content, where the flag means nothing on
      a non-void element, nor for the tags that break out of foreign
      content, such as `<div/>` or `<p/>` inside `<svg>`, which browsers
      process as HTML.  Issue #122.
    * `PolicyFactory.and` no longer lets a factory that allowed no URL
      protocol veto the protocols the other factory allowed.  A builder that
      never called `allowUrlProtocols` guards its URL attributes with a
      default that rejects every absolute URL, and `and()` joined that
      default in as though it were a policy, so `noProtocols.and(httpLinks)`
      dropped every `http:` link that `httpLinks` allowed, in either order.
      `Sanitizers.LINKS.and(f)` suffered the same way whenever `f` mentioned
      `href` without allowing a protocol, which is how a factory that only
      meant to restrict `href` to a pattern silently dropped every absolute
      link.  The default now yields to the other factory's allowlist.  Two
      allowlists still intersect, as `and()` documents, so
      `httpsOnly.and(Sanitizers.LINKS)` still allows only `https:`, and the
      default never yields to a policy attached with `matching`, so a
      builder that allowed no protocol still rejects every absolute URL on
      its own.  This holds for `srcset`, and for `url()` in `style` between
      factories that both allowed URLs in styles, as well as for `href` and
      `src`, and the same factories combined in any grouping allow the same
      URLs.  One consequence to know about: the
      protocol guard now runs after the policies an author attached with
      `matching`, as the `style` guard already did, rather than before them.
      So a `matching` policy on a URL attribute sees the value as written,
      before the guard trims surrounding whitespace and percent-encodes
      parentheses and control characters, and a policy that rewrites a URL
      can no longer hand the output a protocol the builder did not allow.
      A composition that relied on the old behavior to keep another
      factory's links relative should call `allowOnlyRelativeUrls()` on the
      restrictive builder; see the entry for issue #453 above.
      Issue #204.
    * The javadoc for `matching`, `allowUrlProtocols` and `allowUrlsInStyles`
      now says where the URL protocol guard runs: after the policies an
      author attaches, which see the value as written and can be handed a
      protocol the builder never allowed.  A policy that rewrites a URL into
      another, such as a redirector, should vet the protocol itself, and the
      javadoc shows how with `FilterUrlByProtocolAttributePolicy`.  The
      `allowUrlsInStyles` javadoc had the order backwards, and said the
      policy was never consulted without `allowUrlProtocols` when it always
      was.  Issue #454.
    * Text inside a dropped element is now gated by every element enclosing
      it, not by the last tag the policy saw.  The policy kept one flag for
      whether text may be emitted and set it from each open tag alone, so a
      dropped tag inside `<noscript>`, `<object>` or any other element whose
      content is never shown reset the gate and let the content through:
      `<noscript><b>text</b></noscript>` came out as `text`, and
      `<div><object><b>x</b>y</object>z</div>` as `<div>xyz</div>`.  The
      same slip defeated `disallowTextIn`: with text disallowed in
      `<template>`, `<template><p>x</p></template>` kept `x` whenever `<p>`
      was not allowed.  Text now belongs to the nearest enclosing element the
      policy kept, and a dropped element in between suppresses it only when
      its content is never shown or text in it is disallowed.  Two
      consequences of that rule are worth knowing.  Text that follows a kept
      child inside such an element stays suppressed:
      `<noscript>a<p>b</p>c</noscript>` gives `<p>b</p>`, where `c` used to
      leak.  And text inside a dropped child of a kept element that cannot
      hold text itself is dropped rather than written straight into that
      element: `<tr><td>cell</td></tr>` with `td` not allowed gives an empty
      row, not `<tr>cell</tr>`.  Not an XSS -- the text was escaped -- but
      content the policy said to suppress was shown.  The gate now costs
      constant time per tag.  The close-tag path used to re-scan the open
      elements, as did the check for text inside a kept `<style>` or
      `<script>`, and both were quadratic on a long run of unknown tags,
      which the balancer forwards without counting them toward its nesting
      limit; a test pins that 200,000 of them finish in linear time.
      Closes #444.
    * `disallowTextIn(x)` now applies to `x` as the author wrote it, whether
      the policy keeps it, renames it or drops it, rather than only when it
      keeps it under its own name.  The builder discarded the disallowed
      names when it compiled, so `disallowElements("template")` together
      with `disallowTextIn("template")` still emitted the template's text as
      bare text, and a policy that renamed `span` to `div` ignored
      `disallowTextIn("span")` unless the span happened to be dropped.  The
      names now travel through `PolicyFactory`, and `and()` keeps them
      unless the other factory allows text in that element -- the same union
      of grants it applies to everything else.  `disallowElements(x)` no
      longer records `x` as a text container, since a rejected element
      grants nothing; it used to, and under `and()` that record would have
      cancelled the other factory's `disallowTextIn(x)`.  The tag balancer,
      which drops a start tag past the 256-deep nesting limit before the
      policy sees it, now asks the policy whether that element's text is
      suppressed instead of consulting only its fixed list, so
      `disallowTextIn` holds past the limit too.  This also reaches an
      allowed element dropped for having no attributes, such as a bare
      `<span>` with `disallowTextIn("span")`.  Text inside a nested element
      that survives the policy is that element's, and still shows; this is
      not a way to drop an element with all of its content.  Closes #194.
    * `HtmlChangeReporter` no longer reports an element that an
      `ElementPolicy` renamed as a discarded tag.  It decided whether a tag
      survived by comparing the output element name with the input one, so a
      rename never matched: the listener heard `discardedTag` for an element
      that was kept, and, since attribute reports are suppressed for a
      discarded tag, never heard about the attributes the policy dropped from
      it.  It now judges survival by whether the policy opened a tag at all.
      Reports still carry the input element name.  Closes #435.
    * `<template>` keeps its children.  The browser probe that generates the
      element tables cannot see into `template.content`, so the tables said a
      template could hold nothing, and the tag balancer hoisted every child
      out to be its sibling: `<template><b>x</b></template>` came out as
      `<template></template><b>x</b>`.  A template now takes flow content and
      table parts, as the "in template" insertion mode does, and
      `disallowTextIn("template")` -- the documented way to keep template
      text out of the output -- has a template to apply to.  Table parts
      directly inside a template still get the implied `<table><tbody>` they
      get anywhere else.  Closes #113.
    * `PolicyFactory` no longer keeps the `HtmlPolicyBuilder` that built it
      alive.  The value policies behind `matching(Pattern)`,
      `matching(Predicate)` and `matching(ignoreCase, values)` were anonymous
      classes, and each captured the `AttributeBuilder` and through it the
      whole builder, so a factory held in a `static final` -- the usual way
      to hold one -- pinned the builder and its intermediate maps for the
      life of the JVM.  They are now lambdas that capture only the pattern,
      predicate or value set.  A test walks the object graph under a factory
      and fails naming the field if any builder is reachable.  Closes #441.
    * **Breaking:** the `org.owasp.html.examples` package no longer ships in
      the jar.  `EbayPolicyExample`, `SlashdotPolicyExample` and
      `UrlTextExample` move to a new `examples` module that is built and
      tested with everything else but never published.  They were
      illustrations of how to build a policy, never API.

      This breaks any code that imported them, whether off the classpath or
      through the module path: the jar declares only an
      `Automatic-Module-Name`, and an automatic module exports every package
      it contains, so `requires owasp.java.html.sanitizer` reached them too.
      OSGi consumers are the exception -- the bundle manifest exports only
      `org.owasp.html`, so the package was already unreachable there.  The
      classes also leave the published `-sources.jar`.  Anyone who was
      importing one should copy it into their own source -- it is a handful
      of builder calls, meant to be edited rather than depended on.

      A build check now fails if anything reappears under
      `target/classes/org/owasp/html/examples`.  Closes #180.
    * CSS: the cap on the length of a `url(...)` in a style attribute rises
      from 1024 to 2048 and is now a named, documented constant rather than a
      literal buried in `StylingPolicy`.  Over the limit, the URL and the
      property holding it are dropped silently.  The cap is CSS-only by
      design -- `href` and `src` are not length limited -- and 1024 predates
      the widespread use of `data:` URLs for images, which is what made it
      visible.  Requested in #187 by sapio-dwelch and ioleo; 2048 is the
      figure mikesamuel suggested in that thread.
    * Docs: `disallowAttributes(...)` now says that a `matching(...)` call on
      the builder it returns has no effect -- it already rejects every value,
      and joining a narrower policy onto one that rejects everything cannot
      widen it -- and shows the inverted `allowAttributes` that rejects only
      some values, which also composes through `PolicyFactory.and`.  Two tests
      pin both behaviours.  Reported in #292 by subbudvk.
    * Attributes: an attribute whose name matched an **earlier attribute's
      value** on the same tag was silently dropped as a duplicate.  The
      duplicate scan walks a flat list of alternating names and values but
      stepped through it one slot at a time, so it compared names against
      values as well as against names.  `<img style="color:red" alt="src"
      src="...">` lost its `src`.  It only ever dropped attributes, never
      kept one it should have removed, so no policy was widened.  Closes #433.
    * `HtmlChangeListener`: attributes dropped because their name was
      already used on the tag are now reported to `discardedAttributes`.
      HTML forbids repeating an attribute name, so the sanitizer keeps the
      first and drops the rest, but `HtmlChangeReporter` tracked the names it
      was waiting to see in the output in a set, so the surviving copy
      accounted for all of them and the drops went unreported.  Given
      `<a href="https://example.org/" HREF="javascript:alert(1)">` a listener
      now hears about the discarded `href` instead of nothing.  The report is
      still a diff against what the policy emitted rather than a prediction
      from the input, so a policy that keeps both copies is not reported as
      having dropped one.  Two consequences worth noting for listeners that
      count: a name now appears in `discardedAttributes` once per discarded
      copy, where repeats used to collapse to a single entry, and the names
      arrive in the order they appeared on the tag.  Reported in #94 by
      lillesand.
    * CSS: `CssSchema.toAttributePolicy()` and
      `toAttributePolicy(Function<String, String> urlRewriter)` turn a schema
      into an `AttributePolicy`, so a policy can allow different CSS
      properties on different elements -- `color` on `span`, `width` on
      `table` -- which the global `allowStyling(CssSchema)` cannot express.
      Such a policy is **not** wired to `allowUrlsInStyles` /
      `allowUrlProtocols`, since that wiring lives in the `style` attribute
      guard and cannot see a policy handed to `matching`: the no-arg variant
      therefore drops every `url(...)` value, and the rewriter variant puts
      URL vetting entirely on the caller.  Joining one of these with a global
      `allowStyling` takes the union of the schemas but runs both URL
      rewriters in turn, so a per-element policy that drops URLs is never
      widened by a permissive global one, and a rewriter is never handed the
      null that means the URL before it was dropped.  Requested in #131 by ggrandes and EugenMayer;
      an alternative to PR #339 that keeps `StylingPolicy` internal.
      Closes #381.
    * CSS: joining two styling policies -- which `PolicyFactory.and` can do
      when both factories allow styling -- now runs both URL policies instead
      of keeping whichever of the two the join happened to visit first.  This
      is what `and` documents ("intersects policies where they overlap"), and
      it is the stricter of the two, so a combined factory can only drop URLs
      it used to allow, never the reverse.
    * CSS: the CSS-wide keywords -- `inherit`, `initial`, `revert`,
      `revert-layer` and `unset` -- are now accepted on **every** property,
      not just the handful whose literal sets happened to name `inherit`.
      They are valid on any property per CSS Cascade, and only ever reset a
      property to a value the cascade already chose, so `color: revert` and
      `font-size: unset` now survive sanitizing instead of being dropped.
      Schemas for function arguments are deliberately excluded: `initial` is
      a value for `color`, not for a channel of `rgb(...)`.  This widens what
      round-trips, not what can execute.  Follow-up to PR #335; reported by
      EugenMayer.
    * Examples: `EbayPolicyExample` and `SlashdotPolicyExample` gain a
      `run(Reader, Appendable)` method that does the sanitizing; `main` now
      handles only the command line and delegates to it.  Purely additive;
      command-line behaviour is unchanged.  The example classes also drop out
      of the published javadoc, as the exclusion pattern always intended.
    * Tests: the suite now runs on JUnit Jupiter (JUnit 5.14) instead of the
      JUnit 3 `TestCase` style.  This affects only contributors: `./mvnw
      verify` works as before, a failing fuzz test now prints the exact
      `-Djunit.seed=<seed>` that replays it (a malformed seed is rejected
      instead of silently ignored), builder tests fail on renderer errors
      that were previously swallowed, and the nested-anchor tag balancing
      case that was hidden behind a `failingtest` prefix now runs and passes.
      Based on PR #374 by strangelookingnerd.
    * Licensing: the BSD arm of the dual license is **BSD 2-Clause**, and the
      whole repository now says so consistently.  `COPYING` had offered
      "Apache-2.0 or BSD 3-Clause" since 2014 while printing BSD 2-Clause text
      beneath it (issues #271, #288), and every source header carried the
      3-Clause form.  Headers are normalized to 2-Clause and every source file
      now carries `SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause`.
      This only widens the grant -- the 2-Clause text has been the published
      offer for over a decade -- so no action is required of existing users.
      Two AntiSamy-derived test files remain BSD 3-Clause and are now listed
      as third-party code in `COPYING`.
    * Fix: `java8-shim` and `java10-shim` are now bundled inside the main JAR,
      resolving the JPMS split-package error on the module path. The shim
      artifacts are no longer published separately. If you added an explicit
      dependency on `java8-shim` or `java10-shim` as a workaround, remove it.
    * The jar is now an explicit JPMS module, `owasp.java.html.sanitizer`,
      rather than an automatic one.  A module descriptor compiled for Java 9
      ships at `META-INF/versions/9/module-info.class` and the manifest is
      marked `Multi-Release: true`, so Java 9 and later read it while Java 8,
      which never looks there, is unaffected.  The module name is the one
      the jar already had, so `requires owasp.java.html.sanitizer` keeps
      working; what changes is what it reaches.  The module exports
      `org.owasp.html` and nothing else, so the bundled `org.owasp.shim`
      package, which an automatic module exported along with everything
      else, is now encapsulated.  The JSR 305 annotations on the API are a
      `requires static jsr305`, so nothing new is needed on the module
      path.  The build compiles and runs a small consumer module against
      the packaged jar on every JDK in the CI matrix and fails if the jar
      resolves as an automatic module, exports more than `org.owasp.html`,
      or lets another module reach the shim.  Closes #389.
    * HTML: Follow the WHATWG tokenizer for degenerate comments. `<!>`,
      `<!-->`, `<!--->` and `<!->` are complete empty comments, and `--!>`
      closes a comment even when only dashes precede it (`<!----!>`),
      matching browser behaviour instead of swallowing the content that
      followed (issue #258).  Conversely, only a contiguous `-->` or `--!>`
      closes a comment: `<!-- a -x->` no longer ends it early.
    * HTML: A quote inside a tag starts a quoted attribute value only when it
      directly follows an attribute name and `=`, as in the WHATWG tokenizer.
      Anywhere else it is an ordinary character of an attribute name, so
      `<p class="test" "="">bar</p> <p>baz</p>` now keeps `bar` and `baz`
      instead of pairing the stray quote with the next one and swallowing the
      rest of the document (issue #189).
    * HTML: Sanitized output no longer contains code points that HTML
      forbids (issue #223, from PR #225 by Simon Greatrix).  The 66 Unicode
      noncharacters, U+007F and the C1 controls U+0080..U+009F are removed
      from text and attribute values, as the C0 controls already were,
      instead of being passed through raw or written as `&#x5fffe;`-style
      references, which browsers treat as parse errors.  CR and CRLF in
      text and attribute values are normalized to LF as the HTML input
      stream preprocessor does, so rendering is unchanged but the output
      never contains a raw carriage return.  Characters whose compatibility
      decomposition contains ASCII punctuation, such as U+FE64 SMALL
      LESS-THAN SIGN, are written as numeric references so that a later
      normalization of the output cannot produce an HTML special character;
      everything from U+FE60 up is still written as a reference, as before.
      Stripping happens after character references are decoded, so a
      forbidden code point can neither hide a `javascript:` protocol from a
      URL policy nor turn `&l?t;` into `&lt;`.  The February 2018 iOS
      "query of death" workaround, which dropped U+200C before some
      Devanagari, Bengali and Telugu vowels, is removed.
    * HTML: Only the five ASCII whitespace characters separate tokens inside
      a tag, as in the WHATWG tokenizer.  `Character.isWhitespace` also
      accepted U+000B, U+001C..U+001F and Unicode space separators such as
      U+3000, so `<b\u3000onclick=x>` was read as `<b onclick=x>` where a
      browser sees an unknown element named `b\u3000onclick=x`.
    * HTML: Numeric character references in the C1 range, `&#x80;` through
      `&#x9f;`, decode to the Windows-1252 characters that browsers use, so
      `&#x85;` is U+2026 HORIZONTAL ELLIPSIS and `&#x99;` is U+2122 TRADE
      MARK SIGN rather than control characters that are then removed.  The
      five bytes Windows-1252 leaves undefined, 0x81, 0x8D, 0x8F, 0x90 and
      0x9D, remain controls and are removed.
    * HTML: Attribute names may begin with an underscore.
    * HTML: `Sanitizers.TABLES` allows integer `colspan` and `rowspan` on
      `td` and `th`; `Sanitizers.IMAGES` allows `loading="lazy|eager"`.
    * HTML: `Sanitizers.TABLES` allows `headers` on `td` and `th`, limited to a
      space-separated list of ID tokens, and `scope` on `th`, limited to `row`,
      `col`, `rowgroup` and `colgroup` and canonicalized to lower case (PR #326).
    * CSS: A `-` after a unicode-range start that is not followed by hex
      digits, as in `U+a-x` or `U+a-->`, is no longer emitted as part of the
      range token.  It was written to the output and then lexed again as the
      next token, so `U+a-x` normalized to `U+a- -x`, which did not survive a
      second pass through the lexer (issue #245).
    * Build: `.gitattributes` now forces LF line endings on the HTML lexer
      golden files at their current path under `owasp-java-html-sanitizer/`,
      so `HtmlLexerTest` passes on Windows checkouts with `core.autocrlf`
      (also noted in issue #245).
    * CSS: `text-align` accepts `start`, `end`, `justify-all` and `match-parent`.
    * CSS: `calc()` is allowed in `width`, `min-width`, `max-width`, `height`,
      `min-height` and `max-height` (issue #361).  Operands are limited to
      numbers, dimensions and percentages joined by `+`, `-`, `*`, `/` and
      parentheses; anything else inside the call, including `var()`, `attr()`
      and `url()`, is stripped.  Custom schemas built from property names must
      list `calc()` next to the sizing property to accept it, just as `color`
      needs `rgb()`.
    * Build: Dependency version ranges replaced with pinned versions; the
      findbugs `jsr305`/`annotations` pair is replaced by `spotbugs-annotations`.
    * Build: The `empiricism` test harness is no longer published to Maven Central.
    * Build: Pull requests now run the full build matrix.
    * Build: Removed the legacy manual release scaffolding (`RELEASE-checklist.sh`,
      the `aggregate` POM and `scripts/fix_javadoc_links.sh`) together with the
      unused `maven-release-plugin` and `jgitflow` configuration.  Releases are
      cut by the GitHub `Release` workflow.
    * Build: `empiricism/rebuild.sh` regenerates `HtmlElementTablesCanned.java`
      again.  The 2024 Guava removal had turned the generator's array-length
      check into a literal `3`, so it rejected every `explicitClosers` entry.
    * Build: Coveralls coverage reporting is removed.  The plugin had not run
      since the Travis scripts were deleted in 2024, and the repo token that
      was committed with it in 2019 has been revoked.
    * Docs: the `matching(ignoreCase, ...)` overloads say that the allowed
      values must already be lower-case when `ignoreCase` is true.  The
      attribute value is lower-cased before it is looked up but the allowed
      values are used as given, so `matching(true, "Note")` matches nothing.
      It fails closed, and a test pins it.
    * Build: `dependabot.yml` now lists every directory holding a POM, where
      it named two of them.  The `examples` module was not configured, so
      Dependabot read its `${project.version}` dependency on the sanitizer as
      an ancient release and proposed rewriting the root POM's `<version>` to
      `20211018.1` (PR #439, and #383 before it).  A glob would cover modules
      added later, but dependabot-core#12348 reports globbing silently
      matching no manifests, so the directories are listed by hand and a new
      module needs a line.
    * Docs: README examples compile again; Javadoc links point at `latest`.
    * Special thanks to (in lexicographic order):
      Alessandro Ruzzon, corebonts, Daham Chinthana, Domi, hwangjeyeon,
      Martin Jackson, Raibipasha-24, Simon Greatrix, strangelookingnerd,
      subbudvk, Sven Strickroth, yangbongsoo
    * HTML: Inside `<svg>` / `<math>`, the content of raw text elements such
      as `<style>` is escaped rather than emitted verbatim (since 20240325.1),
      but it was escaped without first decoding character references, so
      `&amp;` came out as `&amp;amp;`.  References are now decoded once
      before re-encoding (issue #411).
  * Release 20260313.1
    * Fix: Preserve the order of `rel` attribute values while still
      de-duplicating them.
    * Fix: Invalid nested `<select>` when sanitizing `<optgroup>`.
    * Fix: The shim loader catches `Throwable` rather than `Error` so class
      loaders that throw checked exceptions fall back to the Java 8 shim.
    * Docs: SECURITY.md updated with CVE-2025-66021 details.
    * Special thanks to (in lexicographic order):
      Andres Almiray, Melloware, Shangeeth Rajasekar, strangelookingnerd,
      Sven Strickroth
  * Release 20260102.1
    * Fix: The `owasp-java-html-sanitizer` artifact targets Java 8 again
      ([#369](https://github.com/OWASP/java-html-sanitizer/issues/369)).
    * Docs: Fixed broken examples link.
  * Release 20260101.1
    * Security: Fix [CVE-2025-66021](https://github.com/OWASP/java-html-sanitizer/security/advisories)
      ([#363](https://github.com/OWASP/java-html-sanitizer/issues/363)).
    * Build: Maven wrapper, GitHub Actions release workflow via JReleaser,
      updated Maven configuration.
    * Build: `empiricism` no longer uses Guava; defunct `html-types` removed.
    * Special thanks to (in lexicographic order):
      Andres Almiray, José Pintado, Melloware
  * Release 20240325.1
    * Remove dependency on Guava
    * Raise minimum supported JVM release to 8
    * HTML: Avoid duplicate link `rel` values.
    * HTML: Recognize foreign content syntactic context: `mathml` / `svg`.
    * CSS: Better support for `font-size`, `overflow-wrap`, `word-break`.
    * CSS: Better child combinator parsing.
    * Bug: Fixed out of bounds when mixing global style attribute with others.
    * Special thanks to (in lexicographic order):
      Claudio Weiler, Josh England, Prakhar Maurya, Sven Strickroth, subbudvk
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
