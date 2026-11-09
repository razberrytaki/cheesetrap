# Contribute to cheesetrap

Describe the problem, expected behavior, verification, and remaining limits in a
small PR. Follow the [instructions for your change](AGENTS.md#scope-and-documents)
and use the [documentation map](docs/README.md) for product and operation guides.
Original contributions use the project's MIT license. Preserve imported
copyright and license notices in `THIRD_PARTY_NOTICES.md` and `third_party/notices.json`.
Use [private reporting](SECURITY.md) for vulnerabilities.

## Run the first checks

Use Go 1.27.3, Node 22.23.1, npm 10.9.8, and Python 3. `.nvmrc`, `go.mod`, and
`deploy/toolchain.lock.json` pin the tools. Start in the repository root of a fresh
checkout, in a development shell without production settings. Initial module and
npm downloads require network access.

```sh
npm --prefix web ci
go mod download
go mod verify
python3 -B scripts/test-python.py regression
go test ./... -count=1
go vet ./...
npm --prefix web run test -- --run
npm --prefix web run build
python3 -B scripts/check_links.py
```

These checks cover local fixtures, Python regressions, UI unit tests, and the
embedded UI build. Plain `go test ./...` does not start Docker. They do not prove
host firewall isolation, public sensor reachability, or production load capacity.

## Test a behavior change

1. Choose one observable behavior and run a failing test first. This is the
   Red step of test-driven development. It requires the intended assertion failure.
   Compilation errors and unavailable Docker do not establish that failure.
2. Write the minimum implementation that passes the test. This is the Green step.
   Use unit tests for business rules, Testcontainers integration tests for SQL,
   permissions, and transactions, and E2E
   tests for user journeys. Do not duplicate decision logic in tests.
3. Refactor while green, then rerun relevant checks. Test inputs and results rather
   than internal call order. Broaden verification when a shared contract changes.
4. Record the Red failure and Green commands and results in the PR.

For one Go test, use `go test ./internal/policy -run '^TestName$' -count=1` with a
real test name. For DB changes, use `scripts/test-integration.sh ./internal/store -run '^TestMigrationsAndRoles$'`. Run `scripts/test-integration.sh ./...` across
packages. The runner creates a temporary PostgreSQL with Testcontainers Go v0.44.0
and rejects external DB URLs. Preserve separate migration, API, collector, worker,
and domain database roles. Do not create a shared test database.

Integration tests require Docker Engine and a local Unix-socket context. The
runner pins PostgreSQL and Ryuk digests, binds all host ports to IPv4 loopback,
and limits PostgreSQL to 1 GiB memory and tmpfs, one CPU, and 128 PIDs. It cleans
up owned resources on completion, interruption, and parent exit. Ryuk assists after
abnormal exits. Missing Docker, skipped tests, empty selection, and cleanup failure
are failures. An unreachable selected endpoint must not fall back to another daemon.
Only the pinned Ryuk image uses `label=disable` for SELinux socket access. The
runner does not enable privileged mode or change PostgreSQL confinement, host
policy, or socket permissions. See the [release checks](docs/operations/release.md)
for the loopback, locked-image, and cleanup regression commands.

Each integration batch uses a unique Testcontainers session. The default `./...`
run gives the memory regression batch five minutes so its four-minute context can
report and clean up. Other batches retain three minutes and the same resource
limits. To select that test, use `scripts/test-integration.sh ./internal/reporting -run '^TestSecurityAggregateMemory$' -timeout 5m`. An explicit `-timeout` overrides
the batch default.

For isolated development verification, use `npm --prefix web run test:e2e`.
The runner prepares locked dependencies, Chromium, the UI, a temporary DB, and a
loopback API. It requires Docker, Compose, Python 3, Go, and Node/npm. It rejects
external DB and browser-target settings and cleans up only its own test stack.
It does not connect to an existing deployment.

For UI journeys, add assertions to the specs in `web/e2e/` or `web/e2e-https/` and
run the same command. Do not supply production DB, SMTP, credentials, or public
sensor addresses. Chromium, images, and dependencies can require network access
on first use.

Put integration-test `TMPDIR` on a filesystem below 90% usage with at least 10 GiB
free. A different directory on the same filesystem does not fix low capacity.
Use a sufficiently large isolated volume instead of weakening storage guards.

## Automated installation checks

```sh
python3 scripts/test_install.py
docker compose -f deploy/compose.yaml config --quiet
scripts/test-integration.sh ./tests/acceptance -run TestInstall
```

The integration runner creates isolated PostgreSQL 17.11 databases with random
role passwords and cleans up its own resources on success and failure. It accepts
no external DB URL. Acceptance uses its own database to avoid administrator and
collector-lease conflicts with other API or collector tests.
`TestInstall` checks the DB, DSN-file CLI roles, stopped-file rename recovery,
deduplication, login and event reads with the exact loopback browser origin, and
rendered Compose boundaries. Real public ingress, SSH tunnels, browser rendering,
and host filter counters need separate Linux verification.

## Preserve contracts and generated files

Preserve evidence IDs, hashes and counts, detection windows, late arrivals,
legacy and chunked data, immutable report revisions, atomic commits, legacy
approval and unknown-outcome records, and retention protection.

For SQL changes, run `scripts/generate-sql.sh`. For API changes, run
`go run ./cmd/cheesetrap api-schema --out api/openapi.json`,
`npm --prefix web run generate:api`, and `npm --prefix web run test:api`.
Commit generated source. The UI build regenerates `internal/ui/dist/`.
DB changes need forward migrations and tests for old data, permissions, failure
recovery, and backup restore. For docs, check affected links, commands, and release
metadata. See the [release procedure](docs/operations/release.md) for full automated
acceptance and pinned sensor-image tests.

## Update dependencies

Update dependency versions, checksums, image digests, and notices together.
Record the reason for the update. A Go upgrade must update `go.mod`, tool and image
locks, the Dockerfile, CI, the current installation docs, the Go license text,
and notice input hashes together.

Dependency PRs must pass the `Dependency vulnerabilities` CI job. Audit the full
npm lock graph without lifecycle scripts:

```sh
npm --prefix web audit --package-lock-only --ignore-scripts --audit-level=low
```

Check Go call paths on Linux AMD64 and ARM64 with govulncheck v1.9.0 in plain-text
mode, as described in the [release vulnerability gate](docs/operations/release.md#source-only-public-release).
For each new advisory, review the call path, platform, configuration, and fixed
version. Exit 0 in JSON output mode is not proof that no vulnerabilities exist.

## Keep evidence and secrets private

Public PRs contain sanitized summaries and the tested revision. Do not publish raw
JSONL, logs, operational IPs, recipients, credentials, or `.local` artifacts.
Automated acceptance reports process exit codes separately from report status.
Public diagnostics use only source-defined test names, files, lines, and fixed
error classes. They omit dynamic test names, error bodies, environment variables,
and raw artifacts. See the [diagnostic limits](docs/operations/release.md#public-diagnostics).

`.gitignore` excludes `.env`, keys, credentials, and `secrets/` in subdirectories.
Only public placeholders belong in `.env.example` and `.env.*.example`. Synthetic
JSONL, logs, and `testdata/` can remain tracked. Ignore rules cannot protect already
tracked files or `git add -f`, and CI runs after upload.

Before committing, install Gitleaks 8.30.1 and scan the staged diff with
`gitleaks git --config .gitleaks.toml --gitleaks-ignore-path .gitleaksignore --pre-commit --staged --ignore-gitleaks-allow --redact=100 --no-banner .`.
Before pushing, scan history with the same command, replacing `--pre-commit --staged`
with `--log-opts="--all"`. Run `python3 -B scripts/test-secret-scan.py` for scanner
policy regressions. These scans do not send source over the network. History scans
exclude uncommitted and untracked files. CI fetches full history and verifies the
scanner version and SHA-256. Findings and tool errors both fail, and CI does not
upload the report. Do not bypass findings with `gitleaks:allow`. Existing ignore
entries are limited to two reviewed false-positive fingerprints. Each names an
exact `path:rule:line`, or `commit:path:rule:line` when the finding exists only in
history. Do not exclude whole directories
or rules. Never register an exception for real credentials.

If you discover a real secret, first revoke and replace it, then stop publication.
If a history rewrite is needed, separately agree its scope and collaboration impact
with the maintainer before proceeding.

## Review API contract

Log in through the [management SSH tunnel](docs/operations/install.md)
using the configured Host and Origin. Read current versions with
`GET /api/v1/reports` and `GET /api/v1/settings`. A report's `version` sequences
review changes. `current_revision_id` identifies immutable content. A refresh request
or rejection can increment the version without changing the revision ID.

Contact selection, rejection, and refresh require `expected_version`,
`current_revision_id`, `Idempotency-Key`, the current session's `X-CSRF-Token`,
and the exact `Origin`. If a response is lost, retry with the same key and content.
Different content for the same key or a stale version with a new key returns 409.
After 409, reload, review, and use a new key. Failed requests are not cached as successes.

Lists default to 50 items and allow at most 200. Use the returned cursor with the
same filters. Report details do not embed all evidence. Page through each revision's
evidence and rule lists. JSON uses decimal strings for 64-bit sequence numbers,
versions, and total counts.

Refresh updates contact provenance and creates a revision when needed. A later
selection, rejection, or refresh prevents an earlier result from overwriting the
current report. Rejection is terminal in this review workflow. Worker startup and
periodic reconciliation recover missing or terminally failed refresh jobs from
durable requests.

Rule changes apply from the next ingestion sequence without redetecting old events.
Schedule changes apply after the current open calendar window. Reply-address
changes affect the next revision, never an existing revision. Preserve settings
versions and effective boundaries returned by the API.
