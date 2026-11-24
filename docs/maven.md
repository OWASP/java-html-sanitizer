# Using with Maven 

The HTML Sanitizer is available from
[Maven Central](https://central.sonatype.com/artifact/org.owasp.html-sanitizer/html-sanitizer)

Including among your POMs `<dependencies>` this snippet of XML...

```Java
<dependency>
    <groupId>org.owasp.html-sanitizer</groupId>
    <artifactId>html-sanitizer</artifactId>
    <version>20261110.1</version>
</dependency>
```

...will make the sanitizer available.

Releases up to 20261110.1 were published as
`com.googlecode.owasp-java-html-sanitizer:owasp-java-html-sanitizer`.  If
your build names those coordinates, see
[Migrating from the old coordinates](#migrating-from-the-old-coordinates).

The sanitizer JAR is self-contained: the `java8-shim` and `java10-shim` artifacts
are bundled inside it and do **not** need to be declared as separate dependencies,
including when using the JPMS module path.

In releases after 20260924.2, every class outside `META-INF/versions/` is
Java 8 bytecode, so a Java 8 build that checks its dependencies with the Maven
Enforcer rule `enforceBytecodeVersion` and a `maxJdkVersion` of 1.8 accepts
the JAR without `ignoreClasses`.  The shim for Java 10 and later is in
`META-INF/versions/10/`, which Java 8 never reads and which that rule allows
unless it is set to `strict`, which holds versioned classes to `maxJdkVersion`
too.

On the module path the JAR is an explicit module named
`owasp.java.html.sanitizer` that exports the `org.owasp.html` package:

```Java
module com.example.app {
    requires owasp.java.html.sanitizer;
}
```

Be sure to change the
[version](https://cwiki.apache.org/confluence/display/MAVENOLD/Dependency+Mediation+and+Conflict+Resolution#DependencyMediationandConflictResolution-DependencyVersionRanges)
to a range suitable to your project.  There are no unstable releases
in maven.
Bigger numbers are more recent and the [change log](../change_log.md)
can shed light on the salient differences.

You should be able to build with the HTML sanitizer.  You can read the
[javadoc](https://static.javadoc.io/org.owasp.html-sanitizer/html-sanitizer/latest/index.html),
and if you have questions that aren't answered by these pages,
you can ask in
[GitHub Discussions](https://github.com/OWASP/java-html-sanitizer/discussions/categories/q-a).

Happy sanitizing...

## Migrating from the old coordinates

Releases up to 20261110.1 were published as
`com.googlecode.owasp-java-html-sanitizer:owasp-java-html-sanitizer`.  Later
releases are published as `org.owasp.html-sanitizer:html-sanitizer`.  Only
the coordinates changed: the Java package is still `org.owasp.html`, the JPMS
module is still `owasp.java.html.sanitizer`, the OSGi bundle symbolic name is
still `com.googlecode.owasp-java-html-sanitizer`, version numbers continue
the same sequence, and the JAR still runs on Java 8.

Replace the old coordinates with the new ones wherever your build names
them:

  * dependency declarations and `<dependencyManagement>` entries, BOMs and
    Gradle version catalogs;
  * exclusions, which match on coordinates: an exclusion of the old
    coordinates does not exclude the new ones;
  * lock files and dependency verification files, which need regenerating;
  * allowlists in repository managers and license or security scanners.

The old coordinates keep getting a relocation POM with each release.  It
contains no code.  A build that asks for a later release under the old
coordinates gets the JAR from the new ones, and Maven prints a warning that
the artifact has been relocated.  This keeps dependency update tools working,
but it is a bridge, not a place to stay.

**A build pinned to 20261110.1 or earlier does not migrate by itself, and
gets no further fixes.**  Those releases are unchanged and carry no
relocation.

### Two copies on the class path

Maven and Gradle treat the old and new coordinates as unrelated artifacts.
If your build depends on the new coordinates while another dependency still
brings in 20261110.1 or earlier under the old ones, both JARs are resolved.
They contain the same classes, and the JVM uses whichever comes first on the
class path or module path, so an older sanitizer can silently be the one
that runs.  Check for this after migrating:

```
mvn dependency:tree -Dincludes=com.googlecode.owasp-java-html-sanitizer
gradle dependencyInsight --dependency owasp-java-html-sanitizer
```

If either shows the old coordinates at 20261110.1 or earlier, do one of
these.  Each leaves a single JAR, the new one.  The old coordinates at a
later version are only the relocation, which Gradle still lists, and are
harmless.

Maven, manage the old coordinates to a relocated version, the one you use
under the new coordinates:

```Java
<dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>com.googlecode.owasp-java-html-sanitizer</groupId>
      <artifactId>owasp-java-html-sanitizer</artifactId>
      <version>20261110.1</version>
    </dependency>
  </dependencies>
</dependencyManagement>
```

Maven, or exclude them from the dependency that brings them in:

```Java
<exclusions>
  <exclusion>
    <groupId>com.googlecode.owasp-java-html-sanitizer</groupId>
    <artifactId>owasp-java-html-sanitizer</artifactId>
  </exclusion>
</exclusions>
```

Gradle, substitute the new module for the old one in every configuration,
with the version you use in place of `VERSION`:

```
configurations.all {
  resolutionStrategy.dependencySubstitution {
    substitute module('com.googlecode.owasp-java-html-sanitizer:owasp-java-html-sanitizer') using module('org.owasp.html-sanitizer:html-sanitizer:VERSION')
  }
}
```

A Gradle dependency constraint on the old coordinates at a relocated
version, or an `exclude`, works as well.
