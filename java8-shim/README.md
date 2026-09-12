<!-- SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause -->

# Java 8 Compatibility Shim

This internal module adapts collection APIs introduced in Java 9 and 10 for
the sanitizer's Java 8-compatible source.
[Java8Shim](src/main/java/org/owasp/shim/Java8Shim.java) defines the adapter
API, and [ForJava8](src/main/java/org/owasp/shim/ForJava8.java) provides
the fallback implementation.

At runtime `Java8Shim` first tries the implementation from
[java10-shim](../java10-shim/README.md) and falls back to `ForJava8` when that
newer class cannot load, including on Java 8 and 9.  Both shim modules are
shaded into the published sanitizer JAR; neither is a separate dependency for
library users or a supported public API.

## Build

Keep this module compatible with the repository's Java 8 source and bytecode
target.  Follow the [build prerequisites](../README.md#repository-layout)
(JDK 11 or newer), and run from the repository root:

```sh
./mvnw -pl java8-shim -am package
```

Changes to the shim should also be checked in the final shaded artifact with
the full `./mvnw clean verify` build.
