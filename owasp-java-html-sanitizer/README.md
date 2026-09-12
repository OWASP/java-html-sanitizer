<!-- SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause -->

# Core Library Module

This module builds the published
`com.googlecode.owasp-java-html-sanitizer:owasp-java-html-sanitizer` artifact.
It parses attacker-controlled HTML, applies an allowlist policy, balances the
result, and renders HTML that is safe to embed in a web page.

## Layout

* `src/main/java/org/owasp/html/` contains the Java 8 library and its public
  API.  `HtmlPolicyBuilder`, `PolicyFactory`, and `Sanitizers` are the usual
  entry points.
* `src/test/java/org/owasp/html/` contains the JUnit 5 unit, regression, and
  fuzzer tests.
* `src/test/resources/` contains lexer fixtures, benchmark input, and checks
  for the packaged artifact.
* `src/main/java9/module-info.java` is compiled separately for Java 9 and put
  in `META-INF/versions/9/` of the multi-release JAR.  It exports only
  `org.owasp.html`.
* `src/it/jpms-consumer/` is compiled and run during `verify` against the
  packaged JAR.  It checks the JPMS descriptor and confirms that the bundled
  shim package remains encapsulated.

`HtmlElementTablesCanned.java` is generated from browser observations.  Do
not edit it directly; update the experiment or data in
[`../empiricism/`](../empiricism/) and run `empiricism/rebuild.sh`.

## Build and test

Run the full reactor from the repository root:

```sh
./mvnw clean verify
```

To select this module while still building its in-repository dependencies,
use:

```sh
./mvnw -pl owasp-java-html-sanitizer -am test
```

Use `verify`, rather than `test`, when a change can affect the packaged JAR or
module descriptor.  The project requires JDK 11 or newer to build, while the
ordinary library and test sources must remain compatible with Java 8.

## Security-sensitive changes

Parser, policy, URL, CSS, encoding, balancing, and rendering changes need
hostile regression cases as well as positive tests.  Preserve default-deny
behavior and public API compatibility.  Report a possible bypass privately as
described in [`../SECURITY.md`](../SECURITY.md); do not publish a regression
payload before the coordinated fix is released.
