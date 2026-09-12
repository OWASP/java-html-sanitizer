<!-- SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause -->

# Core Library Module

This module builds the published
`com.googlecode.owasp-java-html-sanitizer:owasp-java-html-sanitizer` artifact.
It combines HTML parsing, tag balancing, allowlist policy enforcement, and
rendering to produce sanitized HTML.  See the
[getting-started guide](../docs/getting_started.md) for using the public API.

## Layout

* [Library sources](src/main/java/org/owasp/html/) contain the Java 8 library
  and its public API.  `HtmlPolicyBuilder`, `PolicyFactory`, and `Sanitizers`
  are the usual entry points.
* [Tests](src/test/java/org/owasp/html/) include JUnit 5 unit, regression, and
  fuzzer tests.
* [Test resources](src/test/resources/) include lexer fixtures, benchmark
  input, and checks for the packaged artifact.
* The [module descriptor](src/main/java9/module-info.java) is compiled
  separately for Java 9 and put in `META-INF/versions/9/` of the multi-release
  JAR.  It exports only `org.owasp.html`.
* The [JPMS consumer](src/it/jpms-consumer/) is compiled for Java 9 and run
  against the packaged JAR during the `integration-test` phase, included in
  `verify`.  It checks the descriptor and confirms that the bundled shim
  package remains encapsulated.

`HtmlElementTablesCanned.java` is generated from browser observations.  Do
not edit it directly; update the experiment or data in
[the browser experiments module](../empiricism/README.md) and follow its
regeneration instructions.

## Build and test

Use JDK 11 or newer to build, and run from the repository root:

```sh
./mvnw clean verify
```

To select this module while still building its in-repository dependencies,
use:

```sh
./mvnw -pl owasp-java-html-sanitizer -am test
```

`test` runs the unit, regression, and fuzzer tests.  `verify` also checks the
packaged JAR and module descriptor.  Ordinary library and test sources must
remain compatible with Java 8; the descriptor and JPMS consumer use Java 9.

## Security-sensitive changes

Parser, policy, URL, CSS, encoding, balancing, and rendering changes need
hostile regression cases as well as positive tests.  Preserve default-deny
behavior and public API compatibility.  Report a possible bypass privately as
described in the [security policy](../SECURITY.md); do not publish a regression
payload before the coordinated fix is released.
