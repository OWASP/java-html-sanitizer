<!-- SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause -->

# Java 8 Compatibility Shim

This internal module lets the Java 8-compatible sanitizer source use immutable
collection operations corresponding to newer JDK APIs.  `Java8Shim` defines
the small adapter surface, and `ForJava8` provides the fallback implementation
available on Java 8.

At runtime `Java8Shim` first tries the implementation from
[`../java10-shim/`](../java10-shim/) and falls back to `ForJava8` when that
newer class cannot load.  Both shim modules are shaded into the published
sanitizer JAR; neither is a separate dependency for library users or a
supported public API.

Keep this module compatible with the repository's Java 8 source and bytecode
target.  Build it through the reactor from the repository root:

```sh
./mvnw -pl java8-shim -am package
```

Changes to the shim should also be checked in the final shaded artifact with
the full `./mvnw clean verify` build.
