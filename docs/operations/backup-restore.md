# Back up and test an isolated restore

Use pinned source, tools, and images from the [release procedure](release.md).
Read the project MIT license and [third-party notices](../../THIRD_PARTY_NOTICES.md).

A backup cannot reveal mail accepted by SMTP after its snapshot. Treating restored
`queued` jobs as sendable can duplicate legacy delivery. Always restore first into
a new local PostgreSQL container. Never overwrite production or connect external
SMTP or sensors to a restore test.

## Back up

Use Python 3, a local Unix-socket Docker context, and administrative access to the
source PostgreSQL container. The tool uses that image's `pg_dump`. The current
locally verified combination is PostgreSQL 17.11, app schema 30, River module
v0.49.0, and River schema 8. Set `--app-version` to the running image's actual Git
commit. The checkout HEAD need not match the deployed image. Restore accepts app
schemas 14 to 30 and requires manifest and restored DB versions to match exactly.
Restoring an older schema does not replace migration before running the current binary.

### Prepare a shared administrative Bash session

Open Bash at the repository root. Set values from the deployment record.
`INSTALL_ROOT` is the root-owned mode-0700 installation directory.
`POSTGRES_CONTAINER` is the source DB container name. `DEPLOYED_GIT_COMMIT` is the
running image commit. `NEW_BACKUP_DIR` and `NEW_RESTORE_DIR` must be new absolute
paths whose parents are already restricted to root. `DEPLOYMENT_DOCKER_CONTEXT`
is the deployment's local context. Docker-group access does not grant access to
root-only files, so file operations also use sudo. Install sudo, Python 3, and the Docker CLI.

```bash
# ops: recovery-context
set -euo pipefail
: "${DEPLOYMENT_DOCKER_CONTEXT:?set deployment context}"
: "${INSTALL_ROOT:?set absolute install root}"
: "${POSTGRES_CONTAINER:?set source database container name}"
: "${DEPLOYED_GIT_COMMIT:?set deployed image commit}"
: "${NEW_BACKUP_DIR:?set new absolute backup directory}"
: "${NEW_RESTORE_DIR:?set new absolute restore directory}"
REPO_ROOT="$PWD"
LOCAL_DOCKER_ENDPOINT=$(env -u DOCKER_HOST -u DOCKER_CONTEXT docker \
  --context "$DEPLOYMENT_DOCKER_CONTEXT" context inspect "$DEPLOYMENT_DOCKER_CONTEXT" \
  --format '{{.Endpoints.docker.Host}}')
case "$LOCAL_DOCKER_ENDPOINT" in unix:///*) ;; *) echo 'local Unix socket required' >&2; exit 1;; esac
OPS_DOCKER_CONFIG=$(sudo mktemp -d /tmp/cheesetrap-ops-docker.XXXXXXXX)
sudo chmod 700 "$OPS_DOCKER_CONFIG"
ops_docker() {
  sudo env -u DOCKER_HOST -u DOCKER_CONTEXT DOCKER_CONFIG="$OPS_DOCKER_CONFIG" \
    docker --context ops-local "$@"
}
sudo env -u DOCKER_HOST -u DOCKER_CONTEXT DOCKER_CONFIG="$OPS_DOCKER_CONFIG" \
  docker context create ops-local --docker "host=$LOCAL_DOCKER_ENDPOINT"
sudo env -u DOCKER_HOST -u DOCKER_CONTEXT DOCKER_CONFIG="$OPS_DOCKER_CONFIG" \
  docker context use ops-local
ops_docker inspect --format '{{.Name}} {{.Config.Image}}' "$POSTGRES_CONTAINER"
```

Check the displayed DB identity against the deployment record. This private Docker
configuration does not change the user's or root's default context. The tools'
`docker_local()` rejects `DOCKER_HOST` and `DOCKER_CONTEXT` and checks the selected
context. Both scripts below must use the same `DOCKER_CONFIG` with those variables
unset. Prepare registry-authenticated images through a separate deployment procedure.

```bash
sudo env -u DOCKER_HOST -u DOCKER_CONTEXT DOCKER_CONFIG="$OPS_DOCKER_CONFIG" \
  "$REPO_ROOT/scripts/backup.sh" --container "$POSTGRES_CONTAINER" --database cheesetrap \
  --install-root "$INSTALL_ROOT" --output "$NEW_BACKUP_DIR" \
  --app-version "$DEPLOYED_GIT_COMMIT"
BACKUP_DIR="$NEW_BACKUP_DIR"
sudo stat "$BACKUP_DIR/manifest.json"
```

Only a new output directory is accepted. Directories use 0700 and files use 0600.
The full custom-format DB dump includes settings, rules, engine registrations,
queues, approvals, and legacy delivery history. The non-secret file allowlist
contains `install.json`, `compose.env`, Cowrie config and userdb, OpenCanary config,
the public certificate, and collector sources. These configs must not contain
credentials. Review custom settings against this contract before backup.
Symlinks are rejected. TLS `key.pem`, secrets, bootstrap SQL, SMTP files, and the
full environment are excluded. The manifest contains the commit, DB and River
versions, completion time, and file SHA-256 values, without URLs, passwords, email
addresses, or hostnames.

The DB dump is sensitive. It contains administrator password hashes, personal
data, and report content. Encrypt the backup, keep it in a separate restricted
store, and dispose of it under your retention policy. Checksums detect corruption,
not authenticity. Restore trusted backups only.

`pg_dump` provides a consistent DB snapshot but does not lock files with the DB.
Pause settings edits and migrations during backup. Before an upgrade, stop all apps
and sensor input first. Online backup completion is neither an SMTP acceptance
boundary nor the exact snapshot start. Raw sensor logs and state directories need
separate file backups if required.

Keep recovery secrets in a separately authorized encrypted secret store.
Never expose DB role credentials, legacy SMTP JSON, TLS private keys, lookup tokens,
or bootstrap data in stdout, shell arguments, or the ordinary manifest.
Restore tests create fresh DB credentials and need no old secrets. At production
cutover only, the responsible operator places required secrets in mode-0600 files
and verifies per-role ownership. Do not place SMTP secrets into the restore.

## Test a restore

Use the same administrative Bash session. To test an existing archive, set
`BACKUP_DIR` to its authorized root-only absolute path. Never widen archive permissions.

```bash
TARGET="cheesetrap-restore-$(openssl rand -hex 16)"
sudo env -u DOCKER_HOST -u DOCKER_CONTEXT DOCKER_CONFIG="$OPS_DOCKER_CONFIG" \
  "$REPO_ROOT/scripts/restore-check.sh" --backup "$BACKUP_DIR" --target "$TARGET" \
  --output "$NEW_RESTORE_DIR"
```

Targets require the shown prefix and 16 to 32 lowercase hex digits. Existing
containers, existing output directories, and arbitrary DB URLs are rejected.
The pinned PostgreSQL image creates a new container and volume and publishes only
an ephemeral loopback port. Production containers, volumes, and DBs are untouched.
Only the new output's `bootstrap-password` is mounted read-only with `ro,Z`.
On SELinux, Docker gives that file a container-private label. The output directory
stays 0700 and password file 0600. Archives and parent directories are not relabeled.
Host policy and container label isolation remain enabled.

On failure, the tool removes only containers and volumes it created. After every
review below is complete, remove the successful test container. Keep it if review
must continue. Treat the output directory as secret because it contains new credentials.

```bash
ops_docker rm -f -v "$TARGET"
```

This removes only the test container and anonymous volume. Manage root-only archive
and restore output through privileged file operations under the retention policy.
After operational review finishes, remove only the private context with
`sudo rm -r -- "$OPS_DOCKER_CONFIG"`.

Before app connections, restore sets `ALTER DATABASE cheesetrap SET
cheesetrap.delivery_disabled='true'`. This conservative marker protects old archives.
The current binary has neither report nor SMTP-test senders. Clearing the marker
does not enable delivery. Never attach an older worker. Collection, detection,
draft review, and cleanup queues still work.

Restore disables automatic approval and invalidates all approvals. Reports already
`sent`, `rejected`, or `closed_unconfirmed` in the snapshot retain terminal status.
For other reports, `sending` and existing `unknown` become `unknown`, existing
`held` stays `held`, and the rest become `needs_review`, with
`delivery_uncertain=true`. `cheesetrap.restore_review` preserves original status,
`post_backup_delivery_unknown`, and classification time. Restore never invents SMTP
acceptance. Active attempts and SMTP tests end with unknown `smtp_interrupted`.
Completed attempt outcomes remain. Pending contact refresh becomes superseded so
it cannot later overwrite restored review state. A snapshot's `sent` record proves
acceptance, not inbox delivery. Reports created after the snapshot are absent and
need separate comparison against external evidence.

Restored nonterminal reports and reports with legacy delivery attempts appear
read-only as `archived`. Compare external records before any external report,
because delivery may already have happened. Review restored drafts and evidence.
There is no delivery-resumption procedure. Legacy classifications and the DB hold
remain conservative archive handling. The binary sends no email regardless of
that hold. Never run old workers or mount SMTP secrets into the restore.

## Verify

```sh
scripts/test-integration.sh ./tests/acceptance -run TestRestoreDrafts
```

The isolated test checks evidence copies, revisions, content hashes, and secret
exclusion. It does not verify production recovery or Linux sensor isolation.
