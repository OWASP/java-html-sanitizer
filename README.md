# OWASP Java HTML Sanitizer [<img src="https://travis-ci.org/OWASP/java-html-sanitizer.svg">](https://travis-ci.org/OWASP/java-html-sanitizer) [![Coverage Status](https://coveralls.io/repos/github/OWASP/java-html-sanitizer/badge.svg?branch=master)](https://coveralls.io/github/OWASP/java-html-sanitizer?branch=master) [![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/2602/badge)](https://bestpractices.coreinfrastructure.org/projects/2602)

A fast and easy to configure HTML Sanitizer written in Java which lets
you include HTML authored by third-parties in your web application while
protecting against XSS.

The existing dependencies are on guava and JSR 305.  The other jars
are only needed by the test suite.  The JSR 305 dependency is a
compile-only dependency, only needed for annotations.

This code was written with security best practices in mind, has an
extensive test suite, and has undergone
[adversarial security review](docs/attack_review_ground_rules.md).

## Table Of Contents

*  [Getting Started](#getting-started)
*  [Prepackaged Policies](#prepackaged-policies)
*  [Crafting a policy](#crafting-a-policy)
*  [Custom policies](#custom-policies)
*  [Preprocessors](#preprocessors)
*  [Telemetry](#telemetry)
*  [Questions\?](#questions)
*  [Contributing](#contributing)
*  [Credits](#credits)

## Getting Started

[Getting Started](docs/getting_started.md) includes instructions on
how to get started with or without Maven.

## Prepackaged Policies

You can use
[prepackaged policies](https://static.javadoc.io/com.googlecode.owasp-java-html-sanitizer/owasp-java-html-sanitizer/20190610.1/org/owasp/html/Sanitizers.html):

```Java
PolicyFactory policy = Sanitizers.FORMATTING.and(Sanitizers.LINKS);
String safeHTML = policy.sanitize(untrustedHTML);
```

## Crafting a policy

The
[tests](https://github.com/OWASP/java-html-sanitizer/blob/master/src/test/java/org/owasp/html/HtmlPolicyBuilderTest.java)
show how to configure your own
[policy](https://static.javadoc.io/com.googlecode.owasp-java-html-sanitizer/owasp-java-html-sanitizer/20190610.1/org/owasp/html/HtmlPolicyBuilder.html):

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
[custom policies](https://static.javadoc.io/com.googlecode.owasp-java-html-sanitizer/owasp-java-html-sanitizer/20190610.1/org/owasp/html/ElementPolicy.html)
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

[Attribute policies](https://static.javadoc.io/com.googlecode.owasp-java-html-sanitizer/owasp-java-html-sanitizer/20190610.1/org/owasp/html/AttributePolicy.html) allow running custom code too.  Adding an attribute policy will not water down any default policy like `style` or URL attribute checks.

```Java
new HtmlPolicyBuilder = new HtmlPolicyBuilder()
    .allowElement("div", "span")
    .allowAttributes("data-foo")
        .matching(
            (String elementName, String attributeName, String value) -> {
              // Return value for the attribute or null to drop.
            })
        .onElements("div", "span")
    .build()
```

## Preprocessors

Preprocessors allow inserting text and large scale structural changes.

```Java
new HtmlPolicyBuilder = new HtmlPolicyBuilder()
    // Use a preprocessor to be backwards compatible with the
    // <plaintext> element which 
    .withPreprocessor(
        (HtmlStreamEventReceiver r) -> {
          // Provide user with info about links before they click.
          // Before:                       <a href="https://example.com/...">
          // After:  (https://example.com) <a href="https://example.com/...">
          return new HtmlStreamEventReceiverWrapper(r) {
            @Override public void openTag(String elementName, List<String> attrs) {
              if ("a".equals(elementName)) {
                for (int i = 0, n = attrs.size(); i < n; i += 2) {
                  if ("href".equals(attrs.get(i)) {
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
        }
    .allowElement("a")
    ...
    .build()

```

Preprocessing happens before a policy is applied, so cannot affect the security
of the output.

## Telemetry

When a policy rejects an element or attribute it notifies an [HtmlChangeListener](https://static.javadoc.io/com.googlecode.owasp-java-html-sanitizer/owasp-java-html-sanitizer/20190610.1/org/owasp/html/HtmlChangeListener.html).

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

**Note**: If a string sanitizes with no change notifications, it is not the case
that the input string is necessarily safe to use. Only use the output of the sanitizer.

The sanitizer ensures that the output is in a sub-set of HTML that commonly
used HTML parsers will agree on the meaning of, but the absence of
notifications does not mean that the input is in such a sub-set,
only that it does not contain elements or attributes that were removed.

See ["Why sanitize when you can validate"](https://github.com/OWASP/java-html-sanitizer/blob/master/docs/html-validation.md) for more on this topic.

## Questions?

If you wish to report a vulnerability, please see
[AttackReviewGroundRules](docs/attack_review_ground_rules.md).

Subscribe to the
[mailing list](http://groups.google.com/group/owasp-java-html-sanitizer-support)
to be notified of known [Vulnerabilities](docs/vulnerabilities.md) and important updates.

## Contributing

If you would like to contribute, please ping [@mvsamuel](https://twitter.com/mvsamuel) or [@manicode](https://twitter.com/manicode).

We welcome [issue reports](https://github.com/OWASP/java-html-sanitizer/issues) and PRs.
PRs that change behavior or that add functionality should include both positive and
[negative tests](https://www.guru99.com/negative-testing.html).

Please be aware that contributions fall under the [Apache 2.0 License](https://github.com/OWASP/java-html-sanitizer/blob/master/COPYING).

## Credits

[Thanks to everyone who has helped with criticism and code](docs/credits.md)
