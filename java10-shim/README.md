<!-- SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause -->

# Java 10 Compatibility Shim

This internal module provides
[ForJava10AndLater](src/main/java/org/owasp/shim/ForJava10AndLater.java), the
implementation of the [java8-shim](../java8-shim/README.md) adapter that uses
newer JDK collection factories and copy operations.  Its `setCopyOf` method
uses an unmodifiable `LinkedHashSet` to preserve encounter order.

It is compiled with `maven.compiler.release` set to 10 and may use Java 9 and
Java 10 APIs, but no newer APIs.

The core library loads this implementation when the running JDK supports it
and otherwise uses the Java 8 fallback.  Both shim modules are shaded into the
published sanitizer JAR; this module is not independently published and is not
a supported consumer API.

## Build

The [build requires JDK 11 or newer](../README.md#repository-layout).
Run from the repository root to build this module and its dependencies:

```sh
./mvnw -pl java10-shim -am package
```

Changes to the shim should also be checked in the final shaded artifact with
the full `./mvnw clean verify` build.
