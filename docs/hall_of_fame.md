<!-- SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause -->

# Security Hall of Fame

These researchers found vulnerabilities in the sanitizer and reported them
privately under the project's [security policy](../SECURITY.md), so each
could be fixed and released before it was disclosed.  Each is also credited
on the advisory for the issue.  Thank you.

Most recent at top.

| Researcher | Advisory | Finding | Fixed in |
| ---------- | -------- | ------- | -------- |
| Irhas Abdul Rosyid ([@analisaperlengkapan](https://github.com/analisaperlengkapan)) | [GHSA-47x2-9gq9-jg3m](https://github.com/OWASP/java-html-sanitizer/security/advisories/GHSA-47x2-9gq9-jg3m) | Denial of service via a tag with many repeated allowed attributes | 20261031.1 |
| [@tndud042713](https://github.com/tndud042713) | [GHSA-6rfr-g8xv-xrp3](https://github.com/OWASP/java-html-sanitizer/security/advisories/GHSA-6rfr-g8xv-xrp3) | CSS property injection via a single-quote breakout in style URLs | 20260922.1 |
| [@thientd](https://github.com/thientd) | [GHSA-vqwm-jvq2-mfwc](https://github.com/OWASP/java-html-sanitizer/security/advisories/GHSA-vqwm-jvq2-mfwc) | Incomplete fix of CVE-2025-66021 | 20260921.1 |
| [@ironfisto](https://github.com/ironfisto) | [CVE-2025-66021](https://github.com/OWASP/java-html-sanitizer/security/advisories/GHSA-g9gq-3pfx-2gw2) | XSS via `noscript` and improper sanitization in `style` | 20260921.1 |

The full list of advisories, with the versions that fix them, is in
[Known public vulnerabilities](vulnerabilities.md).  To be listed here,
report a vulnerability as [SECURITY.md](../SECURITY.md) describes and give a
name or handle to credit.  Contributors of code and review are thanked in
the [credits](credits.md).
