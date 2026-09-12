<!-- SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause -->

# Examples

This module contains worked examples of building and applying sanitizer
policies.  The sources are meant to be read and adapted; the module is tested
as part of the reactor but is not published, so applications should not import
`org.owasp.html.examples`.

## Included examples

* `EbayPolicyExample.java` demonstrates a broad, attribute-aware policy and
  streaming input and output.
* `SlashdotPolicyExample.java` demonstrates a smaller policy, custom element
  handling, and normalized attributes.
* `UrlTextExample.java` demonstrates a postprocessor that appends a URL's
  authority as visible text after links and images.

The tests under `src/test/java/` exercise both accepted markup and hostile
input.  Run them from the repository root so Maven also builds the sanitizer
and shim modules:

```sh
./mvnw -pl examples -am test
```

Treat these policies as examples, not universal security profiles.  Start from
default deny, allow only the markup an application needs, restrict URL
protocols explicitly, and add negative tests for the application's threat
model.  The root [README](../README.md) and
[getting-started guide](../docs/getting_started.md) cover the supported public
API.
