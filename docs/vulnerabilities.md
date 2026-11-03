# Known & public vulnerabilities in this project

  * [GHSA-ppfr-7xq6-p6c2](https://github.com/OWASP/java-html-sanitizer/security/advisories/GHSA-ppfr-7xq6-p6c2) - 2 Nov. 2026 - Moderate severity; XSS via SVG `set` and `animate` rewriting `href`, affects only policies that allow `attributeName` on SVG animation elements. Recommend upgrade to v20261102.2 or later.
  * [GHSA-643j-x48g-g86p](https://github.com/OWASP/java-html-sanitizer/security/advisories/GHSA-643j-x48g-g86p) - 2 Nov. 2026 - Moderate severity; XSS via `javascript:` URLs in SVG `xlink:href`, affects only policies that allow `xlink:href`. Recommend upgrade to v20261102.1 or later.
  * [GHSA-47x2-9gq9-jg3m](https://github.com/OWASP/java-html-sanitizer/security/advisories/GHSA-47x2-9gq9-jg3m) - 31 Oct. 2026 - Moderate severity; denial of service via a tag with many attributes, quadratic in the tag, under any policy that allows an attribute. Recommend upgrade to v20261031.1 or later.
  * [GHSA-x6fc-6qh4-g3wr](https://github.com/OWASP/java-html-sanitizer/security/advisories/GHSA-x6fc-6qh4-g3wr) - 24 Sep. 2026 - Moderate severity; denial of service via deeply nested CSS functions in style attributes, affects only policies that allow styling. Recommend upgrade to v20260924.1 or later.
  * [GHSA-6rfr-g8xv-xrp3](https://github.com/OWASP/java-html-sanitizer/security/advisories/GHSA-6rfr-g8xv-xrp3) - 22 Sep. 2026 - Low severity; affects only policies that allow URLs in styles. Recommend upgrade to v20260922.1 or later.
  * [GHSA-vqwm-jvq2-mfwc](https://github.com/OWASP/java-html-sanitizer/security/advisories/GHSA-vqwm-jvq2-mfwc) - 22 Sep. 2026 - Incomplete fix of CVE-2025-66021. Recommend upgrade to v20260921.1 or later.
  * [CVE-2025-66021](https://github.com/OWASP/java-html-sanitizer/security/advisories/GHSA-g9gq-3pfx-2gw2) - 25 Nov. 2025 - Recommend upgrade to v20260921.1 or later. The first fix, in v20260101.1, was incomplete (GHSA-vqwm-jvq2-mfwc).
  * [CVE-2021-42575](cve202142575.md) - 18 Oct. 2021 - Recommend upgrade to v20211018.1 or later.
  * [CVE-2011-4457](cve20114457.md) - 17 Nov. 2011 - Recommend upgrade to r88 or later.
