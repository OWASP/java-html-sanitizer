# OWASP Java HTML Sanitizer 

A fast and easy to configure HTML Sanitizer written in Java which lets
you include HTML authored by third-parties in your web application while
protecting against XSS.

The existing dependencies are on guava and JSR 305.  The other jars
are only needed by the test suite.  The JSR 305 dependency is a
compile-only dependency, only needed for annotations. 

This code was written with security best practices in mind, has an
extensive test suite, and has undergone [adversarial security review](AttackReviewGroundRules).

----

[Getting Started](GettingStarted) includes instructions on how to get started with or without Maven.

You can use [prepackaged policies](http://owasp-java-html-sanitizer.googlecode.com/svn/trunk/distrib/javadoc/org/owasp/html/Sanitizers.html):

```Java
PolicyFactory policy = Sanitizers.FORMATTING.and(Sanitizers.LINKS);
String safeHTML = policy.sanitize(untrustedHTML);
```

or the [tests](http://code.google.com/p/owasp-java-html-sanitizer/source/browse/trunk/src/tests/org/owasp/html/HtmlPolicyBuilderTest.java) show how to configure your own [policy](http://owasp-java-html-sanitizer.googlecode.com/svn/trunk/distrib/javadoc/org/owasp/html/HtmlPolicyBuilder.html):

```Java
PolicyFactory policy = new HtmlPolicyBuilder()
    .allowElements("a")
    .allowUrlProtocols("https")
    .allowAttributes("href").onElements("a")
    .requireRelNofollowOnLinks()
    .build();
String safeHTML = policy.sanitize(untrustedHTML);
```

or you can write [custom policies](http://owasp-java-html-sanitizer.googlecode.com/svn/trunk/distrib/javadoc/org/owasp/html/ElementPolicy.html) to do things like changing `h1`s to `div`s with a certain class:

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
        }, "h1", "h2", "h3", "h4", "h5", "h6"))
    .build();
String safeHTML = policy.sanitize(untrustedHTML);
```

----

Subscribe to the [mailing list](http://groups.google.com/group/owasp-java-html-sanitizer-support) to be notified of known [Vulnerabilities](Vulnerabilities).  If you wish to report a vulnerability, please see [AttackReviewGroundRules](AttackReviewGroundRules).

----

[Thanks to everyone who has helped with criticism and code](Credits)
