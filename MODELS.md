<!-- SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause -->

# Model-assisted development and review

Use this workflow for OWASP Java HTML Sanitizer. Follow [AGENTS.md](AGENTS.md)
for security invariants, compatibility, tests, and release restrictions, and
[SECURITY.md](SECURITY.md) for private vulnerability handling. Model reviews
supplement maintainer review; they do not authorize posting, merging, or releases.

## Lineup

These are selected model IDs, not claims about current availability. Use Codex
for OpenAI models and Claude Code for Anthropic models. Check installed CLI help
and authenticated access when invoking them; never silently substitute models.

| Stage | Model | Responsibility |
| --- | --- | --- |
| Build | Astra (`gpt-6-astra`) | Implement one scoped change with regression coverage. |
| Second build | Opus 5.5 (`claude-opus-5-5`) | Check the implementation and tests; correct gaps without widening policy. |
| Independent review | Sol 6.1 (`gpt-6.1-sol`) | Check Java correctness, public APIs, thread safety, and packaged compatibility. |
| Independent review | Daybreak Blue (`gpt-daybreak-blue-latest`) | Challenge XSS/mXSS defenses, parser boundaries, and resource bounds using explicit Blue access. |
| Independent review | Mythos 5.1 (`claude-mythos-5-1`) | Independently challenge security assumptions with browser behavior and hostile inputs. |
| Independent review | Sonnet 5.5 (`claude-sonnet-5-5`) | Check policy examples, Javadocs, migration guidance, and concision. |
| Resolve | Astra (`gpt-6-astra`) | Resolve findings against evidence and report validation and remaining blockers. |

## Execution

### CLI access and process ownership

On macOS, a sandboxed `claude auth status` can report no login because it
cannot read Keychain. If Claude works in the user's Terminal, repeat the
status check with approved access outside the sandbox before asking the user
to log in again. Run authenticated Claude stages with that same approved
access. Do not export credentials or disable approval controls.

Use plain `codex exec` for Daybreak Blue; the `review` subcommand does not
support the access-program flag. Check installed help before use:

```sh
codex exec --ephemeral -s read-only \
  --cyber-access-program daybreak_blue -m gpt-daybreak-blue-latest \
  -o /tmp/daybreak-review.md - < /tmp/review-prompt.txt
```

Set `--cyber-access-program standard` explicitly for other Codex models when
the local default might select Daybreak; an incompatible access program exits
without a review. For a writable Codex build using `--approve-for-me`, do not
also pass `-s`/`--sandbox`: that flag combination is rejected. Check installed
CLI help before choosing flags.

Keep prompts limited to the authorized defensive task, with local evidence
and explicit restrictions against publication and recursive delegation.
Report access failures and policy rejections accurately; do not reword a
request to evade a safety decision or silently substitute another model.

Only one build process may edit a checkout at a time. Record its process or
session identifier and wait for its exit status. Empty redirected output is
not evidence of termination: inspect or resume the existing process before
launching a replacement. After an interruption, establish that prior writers
have exited before continuing. Independent read-only reviews may run together
only after the revision is frozen.

For redirected CLI runs, capture the exit status before accepting the output
file. A long silent run may still be working; inspect its state before retrying,
and mark a failed or interrupted slot unavailable unless a substantive
replacement run completes. An incremental Maven test may fail before executing
tests, including during module-info compilation. Check its exit status and the
current test report; use a clean reactor build to establish the result.

- **Full:** Run both builds sequentially, freeze the revision, run independent
  reviews (parallel is allowed), then resolve findings. Use for substantial
  security changes or an explicitly requested full run.
- **Review-only:** Skip builds and review the same existing revision or proposal;
  clearly distinguish proposals from implemented changes.
- **Focused:** For bounded corrections, select relevant reviewers and explain
  omitted stages. Small security diffs still need adversarial review.

Give reviewers the same commit SHA, complete diff, relevant source/tests, intent,
and repository guidance. For uncommitted work, record the baseline SHA and hash
of the captured diff. Reviewers must not edit, publish, or recursively delegate.
Send material fixes back to affected reviewers against the updated revision.

Record each stage as completed, skipped, or unavailable, with requested model,
access program, tool version, exit status, result location, and reviewed revision.
Keep prompts and outputs outside tracked content. Require a substantive completed
response; a catalog entry, successful probe, or model's self-description is not
proof of a completed review or backend identity. Attempt the configured Daybreak
slot for a full run with explicit Blue access; report failures without fallback.
Do not call a run complete while required reviews are missing.

## Sanitizer review priorities

Apply the detailed contracts in AGENTS.md, especially:

- Allowlist enforcement and unchanged safety promises in `Sanitizers`.
- Browser re-parsing, raw-text/RCDATA contexts, SVG/MathML namespaces and case,
  URL attributes/protocols, CSS, entities, and serialization.
- Bounded stack, linear input processing, and bounded output expansion under
  hostile nesting, repeated tokens, and large attribute lists.
- Java 8 compatibility, zero runtime dependencies, public APIs, and the shaded
  shims and multi-release JAR's Java 8 and JPMS consumer checks.

Require findings with severity, file/line, evidence, and a concrete fix, plus a
MERGE, REQUEST_CHANGES, or CLOSE recommendation. Label hypotheses and inherited
issues. Resolve disagreements using specifications, code, and reproductions;
model agreement and green tests alone do not establish security correctness.
Keep undisclosed vulnerability evidence out of public issues, PRs, and CI logs.

## Validation and delivery

Run `./mvnw clean verify` from the repository root using JDK 11 or newer. For
resource-bound regressions, also run `./mvnw test -DargLine=-Xmx256m`. Preserve
fuzzer failure seeds and investigate failures; never retry until green or weaken
tests. Check documentation links and `git diff --check` after edits.

Report actual checks and review coverage, unresolved findings, and compatibility
impact. Record user-visible changes under `Next release` in `change_log.md`.
Follow the README contribution process and AGENTS.md release restrictions;
model recommendations do not replace required human approvals.
For releases, verify the published tag resolves to the release commit and is
an annotated PGP-signed tag (`git cat-file -t` and `git tag -v`). JReleaser's
GitHub `sign` option signs commits, not tags; check the actual remote tag type
and signature after publication.
