# OWASP Java HTML Sanitizer

[![Build](https://github.com/OWASP/java-html-sanitizer/actions/workflows/build.yml/badge.svg)](https://github.com/OWASP/java-html-sanitizer/actions/workflows/build.yml) [![OpenSSF Best Practices](https://www.bestpractices.dev/projects/2602/badge)](https://www.bestpractices.dev/projects/2602) [![Maven Central](https://img.shields.io/maven-central/v/com.googlecode.owasp-java-html-sanitizer/owasp-java-html-sanitizer.svg)](https://search.maven.org/artifact/com.googlecode.owasp-java-html-sanitizer/owasp-java-html-sanitizer)


A fast and easy to configure HTML Sanitizer written in Java which lets
you include HTML authored by third-parties in your web application while
protecting against XSS.

The sanitizer JAR has no runtime dependencies.  Its only compile-time
dependency is `spotbugs-annotations` (provided scope, annotations only);
the other jars are only needed by the test suite.

This code was written with security best practices in mind, has an
extensive test suite, and has undergone
[adversarial security review](docs/attack_review_ground_rules.md).

## Table Of Contents

*  [Getting Started](#getting-started)
*  [Repository Layout](#repository-layout)
*  [Prepackaged Policies](#prepackaged-policies)
*  [Crafting a policy](#crafting-a-policy)
*  [Custom policies](#custom-policies)
*  [Preprocessors](#preprocessors)
*  [Telemetry](#telemetry)
*  [Questions\?](#questions)
*  [Contributing](#contributing)
*  [License](#license)
*  [Credits](#credits)

## Getting Started

[Getting Started](docs/getting_started.md) includes instructions on
how to get started with or without Maven.

## Repository Layout

The project is built as one Maven reactor.  Build it from this directory with
`./mvnw clean verify`; if you select a module with `-pl`, also use `-am` so
Maven builds the modules it depends on.

* [`owasp-java-html-sanitizer/`](owasp-java-html-sanitizer/) contains the
  published library, its tests, and its Java module descriptor.
* [`java8-shim/`](java8-shim/) and [`java10-shim/`](java10-shim/) implement
  compatibility code that is bundled into the library JAR.
* [`examples/`](examples/) contains sample policies to read and copy; it is
  tested but not published.
* [`empiricism/`](empiricism/) contains the browser experiments used to
  generate the sanitizer's HTML element tables.
* [`docs/`](docs/) contains user, security, and historical documentation.

## Prepackaged Policies

You can use
[prepackaged policies](https://www.javadoc.io/doc/com.googlecode.owasp-java-html-sanitizer/owasp-java-html-sanitizer/latest/org/owasp/html/Sanitizers.html):

```Java
PolicyFactory policy = Sanitizers.FORMATTING.and(Sanitizers.LINKS);
String safeHTML = policy.sanitize(untrustedHTML);
```

## Crafting a policy

The
[tests](https://github.com/OWASP/java-html-sanitizer/blob/main/owasp-java-html-sanitizer/src/test/java/org/owasp/html/HtmlPolicyBuilderTest.java)
show how to configure your own
[policy](https://www.javadoc.io/doc/com.googlecode.owasp-java-html-sanitizer/owasp-java-html-sanitizer/latest/org/owasp/html/HtmlPolicyBuilder.html):

```Java
PolicyFactory policy = new HtmlPolicyBuilder()
    .allowElements("a")
    .allowUrlProtocols("https")
    .allowAttributes("href").onElements("a")
    .requireRelNofollowOnLinks()
    .toFactory();
String safeHTML = policy.sanitize(untrustedHTML);
```

## Custom Policies

You can write
[custom policies](https://www.javadoc.io/doc/com.googlecode.owasp-java-html-sanitizer/owasp-java-html-sanitizer/latest/org/owasp/html/ElementPolicy.html)
to do things like changing `h1`s to `div`s with a certain class:

```Java
PolicyFactory policy = new HtmlPolicyBuilder()
    .allowElements("p")
    .allowElements(
        (String elementName, List<String> attrs) -> {
          // Add a class attribute.
          attrs.add("class");
          attrs.add("header-" + elementName);
          // Return elementName to include, null to drop.
          return "div";
        }, "h1", "h2", "h3", "h4", "h5", "h6")
    .toFactory();
String safeHTML = policy.sanitize(untrustedHTML);
```

Please note that the elements "a", "font", "img", "input" and "span"
need to be explicitly whitelisted using the `allowWithoutAttributes()`
method if you want them to be allowed through the filter when these
elements do not include any attributes.

[Attribute policies](https://www.javadoc.io/doc/com.googlecode.owasp-java-html-sanitizer/owasp-java-html-sanitizer/latest/org/owasp/html/AttributePolicy.html) allow running custom code too.  Adding an attribute policy will not water down any default policy like `style` or URL attribute checks.

```Java
PolicyFactory myPolicy = new HtmlPolicyBuilder()
    .allowElements("div", "span")
    .allowAttributes("data-foo")
        .matching(
            (String elementName, String attributeName, String value) -> {
              // Return value for the attribute or null to drop.
              return value;
            })
        .onElements("div", "span")
    .toFactory();
```

## Preprocessors

Preprocessors allow inserting text and large scale structural changes.

```Java
PolicyFactory myPolicy = new HtmlPolicyBuilder()
    .withPreprocessor(
        (HtmlStreamEventReceiver r) -> {
          // Provide user with info about links before they click.
          // Before:                       <a href="https://example.com/...">
          // After:  (https://example.com) <a href="https://example.com/...">
          return new HtmlStreamEventReceiverWrapper(r) {
            @Override public void openTag(String elementName, List<String> attrs) {
              if ("a".equals(elementName)) {
                for (int i = 0, n = attrs.size(); i < n; i += 2) {
                  if ("href".equals(attrs.get(i))) {
                    String url = attrs.get(i + 1);
                    String origin;
                    try {
                      URI uri = new URI(url);
                      String scheme = uri.getScheme();
                      String authority = uri.getRawAuthority();
                      if (scheme == null && authority == null) {
                        origin = null;
                      } else {
                        origin = (scheme != null ? scheme + ":" : "")
                               + (authority != null ? "//" + authority : "");
                      }
                    } catch (URISyntaxException ex) {
                      origin = "about:invalid";
                    }
                    if (origin != null) {
                      text(" (" + origin + ") ");
                    }
                  }
                }
              }
              super.openTag(elementName, attrs);
            }
          };
        })
     .allowElements("a")
     .allowAttributes("href").onElements("a")
     .allowStandardUrlProtocols()
    ...
    .toFactory();

```

Preprocessing happens before a policy is applied, so cannot affect the security
of the output.

## Telemetry

When a policy rejects an element or attribute it notifies an [HtmlChangeListener](https://www.javadoc.io/doc/com.googlecode.owasp-java-html-sanitizer/owasp-java-html-sanitizer/latest/org/owasp/html/HtmlChangeListener.html).

You can use this to keep track of policy violation trends and find out when someone
is making an effort to breach your security.

```Java
PolicyFactory myPolicyFactory = ...;
// If you need to associate reports with some context, you can do so.
MyContextClass myContext = ...;

String sanitizedHtml = myPolicyFactory.sanitize(
    unsanitizedHtml,
    new HtmlChangeListener<MyContextClass>() {
      @Override
      public void discardedTag(MyContextClass context, String elementName) {
        // ...
      }
      @Override
      public void discardedAttributes(
          MyContextClass context, String elementName, String... attributeNames) {
        // ...
      }
    },
    myContext);
```

`discardedAttributes` also fires for attributes rejected from an element that
was then dropped for having none left, such as a link whose only `href` was
rejected.  Two default methods carry more detail for listeners that override
them: `discardedAttribute` receives each rejected attribute's value, and
`discardedText` receives tag-like content the policy removed from a kept
literal-content element, and content the renderer could not emit from one.

**Note**: If a string sanitizes with no change notifications, it is not the case
that the input string is necessarily safe to use. Only use the output of the sanitizer.

The sanitizer ensures that the output is in a sub-set of HTML that commonly
used HTML parsers will agree on the meaning of, but the absence of
notifications does not mean that the input is in such a sub-set,
only that it does not contain structural content that was removed.

See ["Why sanitize when you can validate"](https://github.com/OWASP/java-html-sanitizer/blob/main/docs/html-validation.md) for more on this topic.

## Questions?

If you wish to report a vulnerability, please see the
[security policy](SECURITY.md) and the
[attack review ground rules](docs/attack_review_ground_rules.md).

Subscribe to the
[mailing list](https://groups.google.com/g/owasp-java-html-sanitizer-support)
or watch this repository's
[releases](https://github.com/OWASP/java-html-sanitizer/releases) and
[security advisories](https://github.com/OWASP/java-html-sanitizer/security/advisories)
to be notified of known [Vulnerabilities](docs/vulnerabilities.md) and important updates.

## Contributing

The project is led by [Jim Manico](https://github.com/jmanico).  Release
management and maintenance are shared with
[Abhishek](https://github.com/mrabhishek),
[Andres Almiray](https://github.com/aalmiray),
[Ben Evans](https://github.com/kittylyst),
[Erik Costlow](https://github.com/erikcostlow) and
[Brian Fox](https://github.com/brianf).
[Mike Samuel](https://github.com/mikesamuel) founded the project and wrote the
original sanitizer; he is no longer involved in day-to-day maintenance.

If you would like to contribute, open an
[issue](https://github.com/OWASP/java-html-sanitizer/issues) -- that is the
best way to reach the maintainers.

We welcome [issue reports](https://github.com/OWASP/java-html-sanitizer/issues) and PRs.
PRs that change behavior or that add functionality should include both positive and
[negative tests](https://www.guru99.com/negative-testing.html).

Please be aware that contributions fall under the project's dual license:
`Apache-2.0 OR BSD-2-Clause`, at the recipient's option. See
[COPYING](https://github.com/OWASP/java-html-sanitizer/blob/main/COPYING).

## License

Dual licensed: **`Apache-2.0 OR BSD-2-Clause`**.  You may use this software
under either the [Apache License, Version 2.0](LICENSE) or the BSD 2-Clause
License, at your option -- you do not need to comply with both.

[COPYING](COPYING) is the authoritative statement of the grant and contains
the full text of both licenses.  `LICENSE` holds only the Apache-2.0 arm, so
that automated tooling which understands a single license file detects one;
it does not narrow the choice offered by `COPYING`.

Every source file carries an SPDX identifier.  Two AntiSamy-derived test
files are third-party code under `BSD-3-Clause` and are listed under
THIRD-PARTY CODE in `COPYING`; they are not compiled into the published
artifact.

## Credits

[Thanks to everyone who has helped with criticism and code](docs/credits.md)
