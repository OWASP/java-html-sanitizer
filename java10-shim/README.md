<!-- SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause -->

# Java 10 Compatibility Shim

This internal module provides `ForJava10AndLater`, the implementation of the
[`java8-shim`](../java8-shim/) adapter that delegates to the JDK's immutable
collection factories and copy operations.  It is compiled with
`maven.compiler.release` set to 10 and may use Java 9 and Java 10 APIs, but no
newer APIs.

The core library loads this implementation when the running JDK supports it
and otherwise uses the Java 8 fallback.  Both shim modules are shaded into the
published sanitizer JAR; this module is not independently published and is not
a supported consumer API.

Build it with its reactor dependencies from the repository root:

```sh
./mvnw -pl java10-shim -am package
```

Changes to the shim should also be checked in the final shaded artifact with
the full `./mvnw clean verify` build.
