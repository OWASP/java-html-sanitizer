<!-- SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause -->

# Security Hall of Fame

These researchers reported vulnerabilities in the sanitizer that have been
fixed and released.  Reports should follow the project's
[security policy](../SECURITY.md) so fixes can be coordinated before
disclosure.  Thank you.

Most recent at top.

| Researcher | Advisory or fix | Finding | Fixed in |
| ---------- | -------- | ------- | -------- |
| Irhas Abdul Rosyid ([@analisaperlengkapan](https://github.com/analisaperlengkapan)) | [PR #541](https://github.com/OWASP/java-html-sanitizer/pull/541) | `xmp`, written as `pre`, ended SVG content in the browser but not in the sanitizer, so `image` became `img` | 20261110.1 |
| Irhas Abdul Rosyid ([@analisaperlengkapan](https://github.com/analisaperlengkapan)) | [PR #534](https://github.com/OWASP/java-html-sanitizer/pull/534) | HTML `<image>` interpreted as `img` outside foreign content | 20261107.1 |
| Irhas Abdul Rosyid ([@analisaperlengkapan](https://github.com/analisaperlengkapan)) | [PR #533](https://github.com/OWASP/java-html-sanitizer/pull/533) | Renderer-elided URL characters could create an authority after validation | 20261107.1 |
| Irhas Abdul Rosyid ([@analisaperlengkapan](https://github.com/analisaperlengkapan)) | [GHSA-x759-2xw8-gp4m](https://github.com/OWASP/java-html-sanitizer/security/advisories/GHSA-x759-2xw8-gp4m) | URL policy bypass via `imagesrcset`, which the `srcset` guard did not cover | 20261103.1 |
| Irhas Abdul Rosyid ([@analisaperlengkapan](https://github.com/analisaperlengkapan)); [@sysmustang](https://github.com/sysmustang) and [@cipa5](https://github.com/cipa5), independently | [GHSA-643j-x48g-g86p](https://github.com/OWASP/java-html-sanitizer/security/advisories/GHSA-643j-x48g-g86p) | XSS via `javascript:` URLs in SVG `xlink:href`, which the URL protocol guard did not cover | 20261102.1 |
| Irhas Abdul Rosyid ([@analisaperlengkapan](https://github.com/analisaperlengkapan)) | [GHSA-47x2-9gq9-jg3m](https://github.com/OWASP/java-html-sanitizer/security/advisories/GHSA-47x2-9gq9-jg3m) | Denial of service via a tag with many repeated allowed attributes | 20261031.1 |
| [@tndud042713](https://github.com/tndud042713) | [GHSA-6rfr-g8xv-xrp3](https://github.com/OWASP/java-html-sanitizer/security/advisories/GHSA-6rfr-g8xv-xrp3) | CSS property injection via a single-quote breakout in style URLs | 20260922.1 |
| [@thientd](https://github.com/thientd) | [GHSA-vqwm-jvq2-mfwc](https://github.com/OWASP/java-html-sanitizer/security/advisories/GHSA-vqwm-jvq2-mfwc) | Incomplete fix of CVE-2025-66021 | 20260921.1 |
| [@ironfisto](https://github.com/ironfisto) | [CVE-2025-66021](https://github.com/OWASP/java-html-sanitizer/security/advisories/GHSA-g9gq-3pfx-2gw2) | XSS via `noscript` and improper sanitization in `style` | 20260921.1 |

The full list of published advisories, with the versions that fix them, is in
[Known public vulnerabilities](vulnerabilities.md).  To be listed here,
report a vulnerability as [SECURITY.md](../SECURITY.md) describes and give a
name or handle to credit.  Contributors of code and review are thanked in
the [credits](credits.md).
