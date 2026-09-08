# Attack Review Ground Rules

## How to win

There are many ways we might have failed.

If you are the first to provide a payload that does any of the following on a current release of a mainstream browser (Chrome, Firefox, Safari, or Edge), we will be happy to give credit in the project documentation and README.  Only the first reported payload that demonstrates a particular bug counts.

  * Pop up an `alert` with any text.
  * Cause a network load of `https://attacker.example/xss.js` as JS
  * Set or retrieve `document.cookie`.
  * Cause the DOM to contain an element or attribute not explicitly allowed by the policy in use.
  * Cause an redirect to `https://attacker.example/` or a URL of your choosing without user interaction.
  * Cause a save-file dialog to pop-up.
  * Crash the browser or cause it to loop infinitely until the browser halts JS or consume inordinate resources for an input of that size.
  * Cause an exception, crash, or inf. loop in the sanitizer that causes it to fail to provide service or consume inordinate resources for an input of that size.
  * Exfiltrate information from the page, such as the name or value of an input or the page title.
  * Exfiltrate keystrokes from the page.

This is not an exhaustive list and creative attacks are welcome.

See [GettingStarted](getting_started.md) for how to build the sanitizer and run it locally against a policy of your choosing.

## Reporting Vulnerabilities

Please follow the project's [security policy](../SECURITY.md).  In short: report successful attacks with example input via [OWASP's Bugcrowd queue](https://bugcrowd.com/owaspjavasanitizer) or by email to `jim@owasp.org`, and a maintainer will create a [repository security advisory](https://docs.github.com/en/code-security/security-advisories/repository-security-advisories/creating-a-repository-security-advisory) to coordinate a fix.

If you wish to be credited, please provide a name or handle.

If you wish to remain anonymous, say so in your report.

## Out of Bounds

The target is the sanitizer as written.  Attacks on the project's infrastructure, such as GitHub, the CI runners, or Bugcrowd, are out of bounds.

## Questions

Feel free to ask questions in the project's [GitHub Discussions](https://github.com/OWASP/java-html-sanitizer/discussions/categories/q-a).
