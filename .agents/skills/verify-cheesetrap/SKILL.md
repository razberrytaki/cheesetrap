---
name: verify-cheesetrap
description: Verify cheesetrap's React administration UI and persisted API behavior using its isolated Testcontainers and Playwright runner. Use after login, event investigation, report review or settings changes. Does not verify production deployment, public sensors, or real mail delivery.
---

# Verify cheesetrap

The maintained project skill lives in `.agents/skills/verify-cheesetrap/`.
Edit the canonical directory.

Use this procedure to verify the administration UI against an isolated database
and API. See [the validation record](validation.md) for the last recorded scope
and results; a past pass does not establish the state of another checkout.

Read [the feature map](features/README.md) and the relevant feature before running.
Run commands from the repository root. Follow `AGENTS.md`, `web/AGENTS.md`, and
`internal/AGENTS.md` when changing their respective areas.

## Launch

Use the existing owned fixture. Do not start a separate Compose DB or connect
Playwright to an arbitrary URL. This is a finite verification run, not a persistent
development server.

1. Use the versions in `deploy/toolchain.lock.json`, `go.mod`, and `.nvmrc`.
   Python 3, a local Unix-socket Docker context, and Chromium system libraries
   must be available. Run from a development shell without operational settings.
   The runner rejects supplied database URLs, test credentials, Playwright
   overrides, and Docker target overrides. Do not bypass that rejection.
2. Reserve this checkout for one run. DB ports and names are unique, but
   `web/node_modules`, `internal/ui/dist`, and evidence paths are shared.
   Do not run builds or other browser tests in this checkout concurrently.
3. Capture the command and its exit status in a new private evidence directory.

```bash
umask 077
mkdir -p .local
proof_dir=$(mktemp -d "$PWD/.local/verify-cheesetrap-XXXXXXXX")
git rev-parse HEAD > "$proof_dir/revision.txt"
git diff --stat > "$proof_dir/working-tree.txt"
printf '%s\n' 'npm --prefix web run test:e2e' > "$proof_dir/command.txt"
set -o pipefail
npm --prefix web run test:e2e 2>&1 | tee "$proof_dir/run.log"
run_status=$?
printf '%s\n' "$run_status" > "$proof_dir/exit-code.txt"
```

Use Bash without `errexit` for this block so failure still reaches evidence capture and cleanup.
The command accepts no targets or extra arguments. It runs `npm ci`, the UI
build, Chromium installation, and the Go tests `TestReviewFlow` and
`TestHTTPSProxyAuth` with integration and release build tags.

`scripts/test-integration.py` creates a bounded Testcontainers PostgreSQL,
initializes isolated roles and databases, and runs migrations. `TestReviewFlow`
loads synthetic captured events, runs collection through draft creation, creates
`review-admin` with a random password, and starts the embedded UI and real API on
an ephemeral IPv4 loopback port. It supplies the browser credentials and report
IDs. Never print or manually reuse those environment values.

Readiness requires the authenticated account menu and readable seeded events,
not merely the PostgreSQL startup message. The review spec asserts both before
mutating reports. The HTTPS test separately owns its TLS proxy and account.
Normal completion prints `PASS:` and `Cleaned isolated project` and exits zero.

## Check the test instance

There is no supported attach mode. The server exists only during its owning Go
test. The HTTP and HTTPS specs run these assertions after login; HTTPS repeats
them after reload. For a running browser journey, use this read-only check after login and
whenever the instance looks wrong, inside that existing Playwright test:

```ts
expect(new URL(page.url()).origin).toBe(process.env.CHEESETRAP_E2E_URL);
await expect(page.getByRole('button', {
  name: '\uacc4\uc815 \uba54\ub274: review-admin', exact: true,
})).toBeVisible();
expect((await page.request.get('/api/v1/auth/me')).status()).toBe(200);
```

Unicode escapes preserve the unchanged Korean accessible names.
The fixture creates the listener and passes its origin directly to its child.
The release-tagged test builds the current checkout with the freshly built UI.
Record the revision and dirty files because there is no live build-ID endpoint.
For the HTTPS spec, use `CHEESETRAP_E2E_HTTPS_URL` and `\uacc4\uc815 \uba54\ub274: admin` instead.
An expired session is a failed instance check, not permission to target another server.

Before launch, check `go version`, `node --version`, `npm --version`,
`docker context inspect`, and `docker info`. Inspect only non-secret output.
The context must use a local `unix://` socket. Missing tools, socket access,
Chromium libraries, or free space are infrastructure failures, not test passes.
Keep the storage guards and at least the free space required by `CONTRIBUTING.md`.
Host Docker access alone does not prove Ryuk can access its mounted socket.
The runner applies `label=disable` only to the locked Ryuk image, without enabling
privileged mode. PostgreSQL retains SELinux confinement. If access still fails,
report the infrastructure block. Do not disable host SELinux, relabel the shared
socket, or disable Ryuk to obtain a passing result.

### Temporary access to the local Docker socket

If the non-root caller cannot open `/var/run/docker.sock` because its group is
missing, an existing sudo authorization can grant that group to just the
verification process. Use this only when the selected context points to
`unix:///var/run/docker.sock` and the socket is owned by `root:docker` with mode
`0660`. Docker access grants control over the local daemon; this is not a
restricted Docker role.

In Bash, prepare a command prefix and repeat the instance check with it:

```bash
docker_access=(sudo -n -E --preserve-env=HOME,PATH,USER,LANG,TMPDIR --
  /usr/bin/setpriv --reuid="$(id -u)" --regid="$(id -g)"
  --groups="$(id -G | tr ' ' ','),$(stat -c %g /var/run/docker.sock)" --)
"${docker_access[@]}" id
"${docker_access[@]}" go version
"${docker_access[@]}" node --version
"${docker_access[@]}" npm --version
"${docker_access[@]}" docker context inspect --format '{{.Endpoints.docker.Host}}'
"${docker_access[@]}" docker info --format '{{.ServerVersion}}'
```

Require the original non-root UID, primary group, home, toolchain, and local
context. Stop if sudo or any instance check fails. `setpriv` adds the socket group
before running the command as the caller. It changes no account membership or
socket permissions. `-E` preserves inputs for the runner's environment rejection;
the explicit preserved variables also retain the caller's home and tool paths
under sudo policies that reset them. Do not remove rejected operational settings
through sudo filtering to obtain a pass.

In the Launch evidence block, record this prefix and replace only the npm command
with `"${docker_access[@]}" npm --prefix web run test:e2e`. Keep the exit-status
capture and evidence archive. Use the same prefix for exact-project Docker cleanup
checks. The existing runner still owns PostgreSQL, Ryuk, listeners, and cleanup;
do not run npm or the tests as root. No permanent group change, socket relabeling,
SELinux disablement, or Ryuk disablement is needed for this access method.

## Run feature checks

Run `npm --prefix web run test:e2e` for every feature in the map. The existing
specs are the executable recipes, and the map names their stable UI handles.
For additional assertions, edit the relevant spec and run the owned runner.
Do not invoke the Playwright CLI separately or invent a `dev` npm script.

The primary surface is the administration UI. Its secondary surface is the real
HTTP API, which the Go fixture uses to check authentication and persisted state.
CLI install, backup, restore, and production sensor behavior are outside this map.
Those require their operation-specific procedures and authorization.

## Evidence

Preserve the command, exit status, build revision, action assertions, screenshots,
and persisted results together. After the runner exits, archive its outputs before
another run can overwrite them:

```bash
for evidence_path in .local/e2e .local/design-review .local/https-browser; do
  if [ -d "$evidence_path" ]; then
    mkdir -p "$proof_dir/$(dirname "$evidence_path")"
    cp -a "$evidence_path" "$proof_dir/$evidence_path"
  fi
done
test -s "$proof_dir/run.log"
test -s "$proof_dir/exit-code.txt"
printf '%s\n' "$proof_dir"
```

The main outputs are `browser-results.json`, the run's
`cheesetrap-test-*.jsonl`, `browser/report.png`, report and settings screenshots,
and `.local/design-review` screenshots and HTML at widths 320, 390, and 1440.
The HTTPS config does not produce a screenshot automatically. Its assertions
and Go test result prove its authentication journey.

Only credit artifacts produced by the current run. Older files can survive a
failed launch. Match the project name in `run.log` to its JSONL and require the
current command's zero exit status and the expected browser results. A screenshot
alone proves neither the preceding action nor persistence.

Use the real UI controls for mutations. Require reload or a second read and the
Go fixture's DB assertions. The fixture checks persisted rejection and that
no delivery or SMTP-test job was queued. The draft-only browser journey checks
that sending navigation, actions and settings are absent. It also checks real
settings persistence and read-only archived legacy drafts. The Go fixture checks
the saved settings and unchanged legacy revision and evidence.

RDAP uses a mock at its transport boundary. The review spec also intercepts some
overview, settings, and IP responses for layout and race cases. Label those as
synthetic UI checks, never as backend persistence or real pagination proof.
The baseline review, rejection, settings save, and archived-draft journeys use the real API.
Browser requests outside the fixture origin are blocked and fail the specs.
This does not establish a system-wide network capture or production isolation.

Keep all raw logs, HTML, screenshots, and credentials private under `.local`.
Do not paste them into public output or commit them. Public reports follow
`CONTRIBUTING.md` and describe sanitized results only.

## Cleanup

The runner owns cleanup on success, failure, and SIGINT/SIGTERM. Let it finish.
Go closes its HTTP listeners, and the runner closes the Testcontainers lease and
removes its temporary directory. Require `Cleaned isolated project` after a DB
was started. An early preparation failure has no DB project to clean.

If interrupted, signal only the exact runner PID recorded by your execution tool.
Never use process-name kills, Docker prune, or a guessed container name. If cleanup
fails, inspect the exact project named by this run with `docker ps -a --filter
name=cheesetrap-test-...` using its full actual name. Resolve only that owned
resource before retrying. Do not infer ownership from a name prefix alone.

Keep `$proof_dir` and its archived evidence after cleanup. Dependencies and build
caches are reusable and need no destructive cleanup. Confirm `run.log`, the exit
status, and current-run proof artifacts still exist before reporting completion.

## Helpers

No new executable helper is needed. `scripts/test-e2e.sh` delegates to
`scripts/test-e2e.py`, which shares `scripts/test-integration.py` ownership and
cleanup. Invoke them through `npm --prefix web run test:e2e` as shown above.
Update the feature map and verification scope after user flows change.
