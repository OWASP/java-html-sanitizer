# OWASP Java HTML Sanitizer [<img src="https://travis-ci.org/OWASP/java-html-sanitizer.svg">](https://travis-ci.org/OWASP/java-html-sanitizer) [![Coverage Status](https://coveralls.io/repos/github/OWASP/java-html-sanitizer/badge.svg?branch=master)](https://coveralls.io/github/OWASP/java-html-sanitizer?branch=master)

A fast and easy to configure HTML Sanitizer written in Java which lets
you include HTML authored by third-parties in your web application while
protecting against XSS.

The existing dependencies are on guava and JSR 305.  The other jars
are only needed by the test suite.  The JSR 305 dependency is a
compile-only dependency, only needed for annotations.

This code was written with security best practices in mind, has an
extensive test suite, and has undergone
[adversarial security review](docs/attack_review_ground_rules.md).

----

[Getting Started](docs/getting_started.md) includes instructions on
how to get started with or without Maven.

You can use
[prepackaged policies](https://static.javadoc.io/com.googlecode.owasp-java-html-sanitizer/owasp-java-html-sanitizer/20181114.1/org/owasp/html/Sanitizers.html):

```Java
PolicyFactory policy = Sanitizers.FORMATTING.and(Sanitizers.LINKS);
String safeHTML = policy.sanitize(untrustedHTML);
```

or the
[tests](https://github.com/OWASP/java-html-sanitizer/blob/master/src/test/java/org/owasp/html/HtmlPolicyBuilderTest.java)
show how to configure your own
[policy](https://static.javadoc.io/com.googlecode.owasp-java-html-sanitizer/owasp-java-html-sanitizer/20181114.1/org/owasp/html/HtmlPolicyBuilder.html):

```Java
PolicyFactory policy = new HtmlPolicyBuilder()
    .allowElements("a")
    .allowUrlProtocols("https")
    .allowAttributes("href").onElements("a")
    .requireRelNofollowOnLinks()
    .toFactory();
String safeHTML = policy.sanitize(untrustedHTML);
```

or you can write
[custom policies](https://static.javadoc.io/com.googlecode.owasp-java-html-sanitizer/owasp-java-html-sanitizer/20181114.1/org/owasp/html/ElementPolicy.html)
to do things like changing `h1`s to `div`s with a certain class:

```Java
PolicyFactory policy = new HtmlPolicyBuilder()
    .allowElements("p")
    .allowElements(
        new ElementPolicy() {
          public String apply(String elementName, List<String> attrs) {
            attrs.add("class");
            attrs.add("header-" + elementName);
            return "div";
          }
        }, "h1", "h2", "h3", "h4", "h5", "h6")
    .toFactory();
String safeHTML = policy.sanitize(untrustedHTML);
```

Please note that the elements "a", "font", "img", "input" and "span"
need to be explicitly whitelisted using the `allowWithoutAttributes()`
method if you want them to be allowed through the filter when these
elements do not include any attributes.

----

Subscribe to the
[mailing list](http://groups.google.com/group/owasp-java-html-sanitizer-support)
to be notified of known [Vulnerabilities](docs/vulnerabilities.md).
If you wish to report a vulnerability, please see
[AttackReviewGroundRules](docs/attack_review_ground_rules.md).

----

[Thanks to everyone who has helped with criticism and code](docs/credits.md)
