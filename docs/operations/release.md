# Reproduce a local release

This procedure rebuilds generated source, the embedded UI, the binary, and Docker
images from a selected Git revision. Pinned versions, checksums, and digests do not
guarantee bit-for-bit images. Record builder, platform, timestamp, and image-metadata
differences separately. Pinning does not replace registry and module-server trust,
supply-chain review, or vulnerability review. This procedure does not publish images,
deploy to production, or send reports.

## Actions roles and run names

| File and display name | Role |
| --- | --- |
| `ci.yml`, `CI - checks (auto/manual)` | Automatic master pushes and PR checks and manual checks on GitHub-hosted `ubuntu-24.04` runners. Run names include event and branch. |
| `arm64-image.yml`, `ARM64 image (manual)` | Manual only. Builds the ARM64 runtime image under QEMU on a GitHub-hosted x86_64 runner and runs the CLI smoke. A passing `ci.yml` run does not include this check. |

Automatic push runs apply only to master. PR and manual runs remain available.
Only a newer run with the same workflow, event, and PR number cancels an older run.
Master-push and manual runs use per-run groups and do not cancel each other.

`scripts/test-acceptance.py` owns SQL, OpenAPI, UI type generation, contract and
generated-diff checks, and the UI build. CI's `Check current automated result`
requires this evidence through `release-check.sh --acceptance-results`.
`Build pinned images` builds the AMD64 app image and pinned sensors.
`scripts/test-e2e.sh` remains an independent local runner. On failure, inspect
the relevant job, step log, and summary.

## Source-only public release

The initial release includes original MIT source and third-party material with
original licenses and copyrights. Image and binary builds below verify reproducibility.
They do not upload to a registry or publish distribution artifacts. Cowrie's JA4+
FoxIO conditions also apply to source installations.

At the selected public commit, require successful `Secret scan`,
`Dependency vulnerabilities`, and `automated` jobs. Follow the
[local scan and exception policy](../../CONTRIBUTING.md#keep-evidence-and-secrets-private).
The target is [razberrytaki/cheesetrap](https://github.com/razberrytaki/cheesetrap).
Dependency review and full candidate acceptance remain separate release gates.

`Dependency vulnerabilities` audits the npm lock graph without lifecycle scripts
and uses pinned govulncheck v1.9.0 for Linux AMD64 and ARM64 Go call paths. Plain-text
Go output propagates vulnerability detection as nonzero failure. Database lookup
errors also fail. Advisories judged unreachable still need separate review.
Passing does not establish that container OS or Python packages have no vulnerabilities.

## Tools and inputs

`deploy/toolchain.lock.json` pins Go 1.27.3, Node 22.23.1, npm 10.9.8, sqlc 1.31.1,
and Orval 8.46.0. `GOTOOLCHAIN=local` prevents automatic Go version changes.
Node matches `.nvmrc`. Python 3 standard library, Docker Compose, and BuildKit are
also required. Record host tools and OS. This is not a fully hermetic build.
Use the [supported deployment backend](reference-deployments.md).

`deploy/images.lock.json` pins Node, Go, Debian, PostgreSQL, and sensor base digests.
`sensors/images.lock` links engine source and patch hashes. Compose `:local`
app and web tags are local names built from this checkout, not selectors for a
remote latest image. Record actual image IDs. Floating `latest` and external
operational images without digests are prohibited.

## Build from a fresh checkout

Do not copy generated output or `node_modules` from another checkout. Set the
revision to the actual selected commit. Set `SOURCE_REPOSITORY` to an accessible
source repository, such as `https://github.com/razberrytaki/cheesetrap.git` or a local
repository path. This procedure never pushes.

```sh
# Set SOURCE_REPOSITORY and RELEASE_REVISION to the selected repository and commit.
git clone --no-local "$SOURCE_REPOSITORY" cheesetrap-release
cd cheesetrap-release
git checkout --detach "$RELEASE_REVISION"
export GOTOOLCHAIN=local GOENV=off GOWORK=off
test "$(go env GOVERSION)" = go1.27.3
test "$(node --version)" = v22.23.1
test "$(npm --version)" = 10.9.8
scripts/release-check.sh --metadata-only

# Initial setup requires package-server and registry access.
go mod download
go mod verify
npm --prefix web ci --no-audit --no-fund

# Generate SQL, OpenAPI, TypeScript, UI assets, and the binary in that order.
scripts/generate-sql.sh
go run ./cmd/cheesetrap api-schema --out api/openapi.json
npm --prefix web run generate:api
npm --prefix web run test:api
git diff --exit-code -- internal/store/db api/openapi.json web/src/api/schema.d.ts web/src/api/generated
test -z "$(git ls-files --others --exclude-standard -- internal/store/db api/openapi.json web/src/api/schema.d.ts web/src/api/generated)"
npm --prefix web run build
mkdir -p bin
CGO_ENABLED=0 go build -trimpath -buildvcs=false -tags=release -ldflags='-s -w' -o bin/cheesetrap ./cmd/cheesetrap

# Docker also builds the UI from locked dependencies and embeds it for release.
docker build -f deploy/Dockerfile -t cheesetrap:release-check .
docker build --target patched -t cheesetrap-web:release-check sensors/web
python3 -B scripts/test-python.py image --image cheesetrap-web:release-check
docker image inspect cheesetrap:release-check cheesetrap-web:release-check --format '{{.Id}}'
```

Go `-tags=release` fails without UI assets. Never deploy the non-release placeholder.
Local and Docker builds both use `-buildvcs=false`. Record the revision and source
hashes separately. The Docker context excludes secrets, raw logs, `.git`,
`node_modules`, and local binaries. Images include required license files.

## Automated checks and external verification

Integration and browser collection tests measure the real filesystem containing
temporary logs. With `TMPDIR` usage at or above 90% of available capacity, product
collection pauses and tests can time out. Install preflight also needs at least
10 GiB free. Use a dedicated test filesystem with enough space and pass it as
`TMPDIR`. Another directory on the same filesystem cannot fix capacity. Never
disable the 90% threshold or capacity checks. Record the filesystem, first failure,
and retry with fresh-checkout evidence.

Docker Desktop might not share a new mount automatically. Restore-test bind inputs
use a unique checkout directory under `.local/restore`, with only that directory
removed after the test. Local Docker must read the checkout path. No global Docker
setting change or existing service restart is required.

```sh
# Prepare Chromium and system libraries first. Network access is required.
(cd web && npx --no-install playwright install --with-deps chromium)
scripts/test-acceptance.sh --automated-only
# Use the actual path printed by the runner, not this placeholder.
scripts/release-check.sh --acceptance-results .local/acceptance/ACTUAL_RUN/results.json
```

CI uses the same tools and generators for fixture-based Go unit tests, vet, Python
regressions, isolated PostgreSQL integration, Chromium E2E, and UI tests and build.
Offline fixtures mean no production network or real SMTP, not that first-time
module, browser, and image downloads need no network. CI Linux and DB containers
do not replace real host-boundary acceptance.

`python3 -B scripts/test-python.py regression` runs files for runner behavior,
backup and restore, raw retention, capacity and performance calculations, operation
docs, and engine network policy, cleanup, and rotation. `--list` shows current
selection. Empty collection, required skips, failure, or a file exceeding 180
seconds fails. Installation Python tests remain indirectly invoked by Go acceptance.
The compatibility key `runner-tests` now covers the entire regression suite.

After building the sensor image, run the separate required image test. The runner
resolves the local tag to an image ID and prints it, mounts only necessary tests
read-only, and uses `--network none`, a read-only rootfs, temporary `/tmp`, and
`CHEESETRAP_REQUIRE_TWISTED_TESTS=1`. It runs request-evidence unit tests and then a direct
reactor script in another container. Each container has a default 120-second limit.
Failure, timeout, and interruption clean up only owned containers.
`PASS_PYTHON_IMAGE` and the image ID appear in CI logs. Match the candidate commit
to that workflow run. Image build or `PASS_AUTOMATED` alone does not prove this
check. Both gates must pass.

The Testcontainers boundary regression is `python3 -B scripts/test-testcontainers.py`.
CI's `Verify Testcontainers loopback ports and locked Ryuk image` checks actual
bindings, image, and cleanup. Go unit tests reject bypasses such as empty host
addresses and IPv6 wildcards. The same CI step tests an unreachable socket to
verify there is no daemon fallback. Sequential create and cleanup tests start the
next batch without waiting for the previous Ryuk to exit, proving session separation
and resource ownership. If startup or test failure coincides with cleanup failure,
the original error stays primary and public output adds a fixed sanitized category.

Network policy, engine, or input-boundary changes require fresh acceptance for the
affected boundary. Adding current source hashes to historical Linux evidence is
not a rerun. Historical finite load measurements do not guarantee unlimited operation
or a minimum hardware size. Use actual input and the [retention guide](retention.md)
to plan protected data, report copies, WAL, backup, and restore space.

## Public diagnostics

Automated acceptance prints `CI_CHECK` status per command and source-defined failed
test names, files, lines, and fixed categories. It reports process return codes
separately from report validity. It never publishes dynamic subtest names, runtime
error bodies, environment variables, or raw JSONL and logs. UI test identities use
verified `web/src/file.test.tsx::test@line` declarations, not runtime test names.
Only regular UI report files up to 8 MiB are read. Public `files`, `locations`, and
`tests` each contain at most 40 entries. If a Go timeout prevents terminal test
events, diagnostics identify unfinished tests from source in the failed package.
Keep raw reports and artifacts private.

## Check before deployment

`release-check.sh --metadata-only` checks required docs, the MIT grant, copied
notices, dependency input hashes, tool and image locks, and T01 to T13. It returns
`PASS_METADATA` only. `--acceptance-results` accepts only `PASS` or
`PASS_AUTOMATED` results matching the current Git revision, production source hashes,
all required automated commands, and automated T01 to T13 tests. Missing, failed,
skipped, or stale evidence fails.

The automated gate requires a clean checkout with no tracked or untracked changes.
At test start it must record `checkout_clean=true` and the SHA-256 of an empty tracked
diff. Running edited tests or an untracked runner and reverting afterward cannot
pass. Ordinary acceptance can run in a working checkout and records that state.
`PASS_AUTOMATED_GATE` proves neither current Linux retesting nor image-build success.
Result JSON is operator-owned evidence, not a cryptographic signature or fraud detector.

Review the gate, fresh-checkout image builds, Python image tests, and separately
scoped Linux and load evidence together. Never upload private `.local` logs,
addresses, or credentials to Git or CI artifacts. Include [MIT](../../LICENSE) and
[third-party terms](../../THIRD_PARTY_NOTICES.md), including Cowrie's vendored JA4+
FoxIO terms and upstream image redistribution obligations.

Apply the [installation](install.md), [retention](retention.md),
[backup and restore](backup-restore.md), and [upgrade](upgrade.md) guides.
Review restored drafts and evidence. This binary sends no email. Never run an old
worker alongside it.
