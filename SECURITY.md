# Security Policy

## Supported Versions

Only the latest version is supported with updates.

| Version    | Supported          |
| ---------- | ------------------ |
| 20260924.2 | :white_check_mark: |

## Scope

The target is the sanitizer library as written: HTML input that the
sanitizer lets through and a browser then acts on, or input that makes the
sanitizer throw, hang, or consume inordinate resources.  The
[attack review ground rules](docs/attack_review_ground_rules.md) list what
counts as a win.

Out of scope:

* The project's infrastructure: GitHub, the CI runners, and Bugcrowd.
* Other OWASP repositories, projects, and websites.
* Information that is public by design, such as author and committer
  addresses in the commit history of a public git repository.

A report needs an example input and what it does.  A report with no input
is closed as not applicable.

## Reporting a Vulnerability

Please report successful attacks with example input via OWASP's bugcrowd queue or contact jim@owasp.org and I will create a repository security advisory to coordinate.

If you wish to be credited, please provide a name or handle for me to credit.

If you wish to remain anonymous, please create a sock account, and email the address above.
