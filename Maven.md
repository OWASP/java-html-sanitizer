# Using with Maven #

The HTML Sanitizer is available from [Maven Central](https://search.maven.org/#search%7Cga%7C1%7Cowasp-java-html-sanitizer)

Including among your POMs `<dependencies>` this snippet of XML

```
    <dependency>
        <groupId>com.googlecode.owasp-java-html-sanitizer</groupId>
        <artifactId>owasp-java-html-sanitizer</artifactId>
        <version>[r136,)</version>
    </dependency>
```

will make the sanitizer available.

Be sure to change the [version](http://docs.codehaus.org/display/MAVEN/Dependency+Mediation+and+Conflict+Resolution#DependencyMediationandConflictResolution-DependencyVersionRanges) to a range suitable to your project.  There are no unstable releases in maven.  Bigger numbers are more recent and the [change log](http://owasp-java-html-sanitizer.googlecode.com/svn/trunk/CHANGE_LOG.html) can shed light on the salient differences.

You should be able to build with the HTML sanitizer.  You can peruse the [javadoc](http://owasp-java-html-sanitizer.googlecode.com/svn/trunk/distrib/javadoc/index.html), and if you have questions that aren't answered by these wiki pages, you can ask on the [mailing list](http://groups.google.com/group/owasp-java-html-sanitizer-support).

Happy sanitizing...