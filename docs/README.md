<!-- SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause -->

# Documentation

This directory holds supporting documentation for the OWASP Java HTML
Sanitizer.  Start with the [project README](../README.md) for a short API
example and links to the current Javadoc.

## Using the sanitizer

* [Getting started](getting_started.md) explains how to obtain the library and
  identifies the main policy-building APIs.
* [Using with Maven](maven.md) gives the dependency coordinates and JPMS
  module name.
* [Why sanitize when you can validate?](html-validation.md) explains why the
  library returns normalized, sanitized output instead of declaring arbitrary
  input safe.
* [Client-side templates](client-side-templates.md) records interactions
  between sanitized HTML and template-language syntax.

## Security

* [Known public vulnerabilities](vulnerabilities.md) lists published
  advisories and the first fixed versions.
* [Attack review ground rules](attack_review_ground_rules.md) defines the
  scope for adversarial testing and links to the private reporting process.
* [CVE-2011-4457](cve20114457.md) and
  [CVE-2021-42575](cve202142575.md) provide historical details for those
  issues.

Do not open a public issue for a suspected sanitizer bypass.  Follow the
repository's [security policy](../SECURITY.md) so maintainers can coordinate a
fix and disclosure.

## Project history

The [credits](credits.md) recognize project contributors.  Release-by-release
changes are recorded in the repository [change log](../change_log.md).
