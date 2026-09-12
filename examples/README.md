<!-- SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause -->

# Examples

This module contains worked examples of building and applying sanitizer
policies.  The sources are meant to be read and adapted; the module is tested
as part of the reactor but is not published, so applications should not import
`org.owasp.html.examples`.

## Included examples

* [EbayPolicyExample.java](src/main/java/org/owasp/html/examples/EbayPolicyExample.java)
  demonstrates a rich-text policy with CSS and attribute rules.
* [SlashdotPolicyExample.java](src/main/java/org/owasp/html/examples/SlashdotPolicyExample.java)
  demonstrates a smaller policy, custom element names, and normalized attributes.
* [UrlTextExample.java](src/main/java/org/owasp/html/examples/UrlTextExample.java)
  demonstrates a postprocessor that appends a URL's
  authority as visible text after links and images.

The eBay and Slashdot programs read UTF-8 HTML from standard input and write
sanitized HTML to standard output; each buffers the complete input before
sanitizing.  `UrlTextExample` accepts HTML as command-line arguments.

## Build and test

The [tests](src/test/java/org/owasp/html/examples/) exercise both accepted
markup and hostile input.  With JDK 11 or newer, run them from the repository
root so Maven also builds the sanitizer and shim modules:

```sh
./mvnw -pl examples -am test
```

Treat these policies as examples, not universal security profiles.  Start from
default deny, allow only the markup an application needs, restrict URL
protocols explicitly, and add negative tests for the application's threat
model.  The root [README](../README.md) and
[getting-started guide](../docs/getting_started.md) cover the supported public
API.
