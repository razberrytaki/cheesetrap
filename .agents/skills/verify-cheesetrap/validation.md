# Validation record

## Draft-only integration run

On 2026-11-06, the four active feature files received source review and owned E2E
coverage at `cbe2701d1f260b89d6434077fbd4dc38fd49ac66` after integrating master
`b6c204e06b752f8bc16ce7c28dc55935889d764e`. Both HTTP browser cases and
`TestHTTPSProxyAuth` passed. Real settings persistence, archived legacy drafts,
read-only mutations, removed endpoints and settings, and zero outbound jobs were
asserted without restoring sending behavior. The runner cleaned its DB; exact
owned-project queries found no remaining containers. Current-run artifacts and
exit-zero proof were archived privately.

The first E2E failed on a new filter locator and remains in the evidence. The
corrected combobox-role locator passed without a timeout or assertion reduction.
Inspected PNGs have incomplete Korean glyphs; automated accessible-name and
persistence assertions passed, but Korean visual quality is unverified.
The records below apply to their historical revisions.

## Maintenance run

On 2026-11-06, all five feature files received read-only source review at
`6636c60` and live coverage through the owned E2E runner on Linux ARM64.
`npm --prefix web run test:e2e`, using the documented temporary Docker group
prefix, exited zero:

- Both HTTP browser cases passed with no skipped, unexpected, or flaky cases.
  `TestReviewFlow` and `TestHTTPSProxyAuth` passed, including their authenticated
  doctor checks and persisted state assertions.
- The runner reported cleanup success; an exact owned-project Docker query
  returned no containers. Current-run JSONL, browser results, screenshots, and
  command evidence were archived and checked after cleanup.
- The skill moved to `.agents/skills/verify-cheesetrap`.
  Relative links and the five-entry feature index were checked.
- The map now names existing evidence-result and keyboard detection-detail
  checks, distinguishes synthetic overview counts, records the fixed synthetic
  operator-recipient prerequisite, and identifies additional unverified controls.

Only the verification skill changed.
No product or test-runner changes were needed. The limits below still apply.

## Earlier maintenance run

On 2026-11-05, the maintenance pass reviewed all five feature files against
source at `1c02c03`. Initial preflight could not find Go or access the Docker
socket. When resumed, the locked Go toolchain was available; the non-root caller
still lacked the socket group.

The [temporary Docker group procedure](SKILL.md#temporary-access-to-the-local-docker-socket)
was then exercised on Linux ARM64 with the owned E2E runner. The documented
command exited zero, covering all five mapped features:

- Both HTTP browser cases and `TestReviewFlow` passed, with no skipped or flaky
  browser cases. `TestHTTPSProxyAuth` also passed.
- Synthetic database and Docker endpoint overrides were separately rejected
  before preparation through the same sudo prefix.
- Live inspection confirmed locked images, IPv4 loopback ports, and no privileged
  containers. PostgreSQL retained its SELinux label and memory, CPU, and PID caps.
- The runner reported cleanup success. Neither the owned session's containers
  nor their previously observed IDs remained. Current-run JSONL, browser results,
  screenshots, and command evidence survived cleanup.
- The caller's account groups, socket mode `0660`, and host SELinux `Enforcing`
  state remained unchanged. Only verification subprocesses received the group.
- The map's retry description was qualified: duplicate-risk acknowledgement is
  required when the previous delivery outcome is uncertain.

Only verification-skill documentation changed. The coverage limits below and
the feature map's unverified behaviors still apply.

## Earlier recorded run

On 2026-11-05, `npm --prefix web run test:e2e` exited zero on Linux ARM64.
The checkout was based on `e31755b` with the doctor assertions subsequently
committed in `386062c`. This is a historical result, not a pass for later changes.

- Both HTTP browser cases passed without skipped or flaky cases.
- `TestReviewFlow` passed, including persisted report decisions and settings.
- `TestHTTPSProxyAuth` passed, covering login, cookie attributes, reload, and logout.
- Doctor assertions passed after HTTP login and HTTPS login and reload.
- The runner reported cleanup success; an exact project-name Docker query found
  no remaining containers. Current-run evidence remained available after cleanup.
- All five feature files received source review and live coverage through the
  owned runner. The feature index and local Markdown links were checked.

Raw logs, screenshots, HTML, and machine-specific evidence locations are private
run artifacts and are not published with this record.

## Reproduce

Follow the [launch, doctor, evidence, and cleanup procedure](SKILL.md) from the
repository root. Use the toolchain versions locked by the repository, Python 3,
a working local Unix-socket Docker context, Chromium system libraries, and the
free space required by [the contribution guide](../../../CONTRIBUTING.md).
Run without operational database, SMTP, or sensor settings.

The runner creates its own Testcontainers database and loopback HTTP and HTTPS
fixtures. Preserve each run's revision, working-tree changes, command, exit
status, and current-run artifacts. Verify cleanup before recording success.

## Limits

Coverage is defined by the [feature map](features/README.md), including its
explicitly unverified entry points and behaviors. Intercepted UI responses prove
UI behavior only; outbound job absence is verified independently in the owned DB. Cookie removal simulates
session expiry rather than testing elapsed time.

This run does not verify fresh-VM installation, systemd operation, public sensor
boundaries, real SMTP delivery, or Linux load behavior. Those require their own
procedures and evidence.

### Post-review overview correction

The stored historical fixture now returns to `needs_review`. A real-API assertion
compares overview counts with report-list membership. The follow-up HTTP and
HTTPS run passed with archived actions still disabled.
