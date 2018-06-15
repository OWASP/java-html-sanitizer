# Using with Maven

The HTML Sanitizer is available from
[Maven Central](https://search.maven.org/#browse%7C84770979)

Including among your POMs `<dependencies>` this snippet of XML...

```Java
<dependency>
    <groupId>com.googlecode.owasp-java-html-sanitizer</groupId>
    <artifactId>owasp-java-html-sanitizer</artifactId>
    <version>20180219.1</version>
</dependency>
```

...will make the sanitizer available.

Be sure to change the
[version](https://cwiki.apache.org/confluence/display/MAVENOLD/Dependency+Mediation+and+Conflict+Resolution#DependencyMediationandConflictResolution-DependencyVersionRanges)
to a range suitable to your project.  There are no unstable releases
in maven.
Bigger numbers are more recent and the [change log](../change_log.md)
can shed light on the salient differences.

You should be able to build with the HTML sanitizer.  You can read the
[javadoc](https://static.javadoc.io/com.googlecode.owasp-java-html-sanitizer/owasp-java-html-sanitizer/20180219.1/index.html),
and if you have questions that aren't answered by these wiki pages,
you can ask on the
[mailing list](http://groups.google.com/group/owasp-java-html-sanitizer-support).

Happy sanitizing...
