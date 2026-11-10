# Upgrade and maintain River

Use pinned source, tools, and images from the [release procedure](release.md).
Read the project MIT license and [third-party notices](../../THIRD_PARTY_NOTICES.md).

The locally verified combination is PostgreSQL 17.11, app schema 31, River module
v0.49.0, and River schema 8. Record these versions and the deployed image Git commit
and digest. Check the new release's supported combination and schema compatibility,
then pass an isolated restore with the same combination. `restore-check.sh` accepts
app schemas 14 to 31 and requires the manifest to match the actual DB. Restoring
an old schema does not replace migrations before starting the latest app.
Unsupported combinations fail without a force-version bypass.

## Preserve installation identity across product renames

Existing installations keep their original project name, even if it contains an
old milestone name. Keep the original `compose.env`, `install.json`, install root,
PostgreSQL volume, sensor UUIDs, secrets, and external sensor network. Do not copy
identity fields from a new example. Run `install-prepare.py` only with
`--refresh-sources` during this upgrade. That mode updates only `archive_paths`
in the collector manifest. It preserves sensor UUIDs, endpoint mappings, secrets,
and installation configuration. Do not use
`down -v`, recreate the DB volume, or rename firewall resources during this upgrade.
The `ctm1-` sensor bridge prefix, derived `ctma-` API bridge, and `ctm1_` guard tables
remain compatible with existing installations.

1. Open the [administrative Bash session](backup-restore.md#prepare-a-shared-administrative-bash-session)
   from the deployed revision's repository root. Use a shell without exported
   Compose interpolation settings from another deployment. Set the existing project
   and external config path from your private deployment record. Record which
   services and raw-retention timer are active. Keep this shell and its private
   Docker context for all steps.
   Defer the backup guide's context cleanup until the upgrade review is complete.

```bash
: "${INSTALL_ROOT:?set existing install root}"
: "${COMPOSE_PROJECT_NAME:?set existing deployment project}"
: "${INSTALL_CONFIG:?set existing external install config path}"
ops_compose() {
  sudo env -u DOCKER_HOST -u DOCKER_CONTEXT DOCKER_CONFIG="$OPS_DOCKER_CONFIG" \
    INSTALL_ROOT="$INSTALL_ROOT" COMPOSE_PROJECT_NAME="$COMPOSE_PROJECT_NAME" \
    docker --context ops-local compose --env-file "$INSTALL_ROOT/compose.env" \
    --project-name "$COMPOSE_PROJECT_NAME" -f deploy/compose.yaml "$@"
}
ops_compose --profile worker ps -a
UPGRADE_PROOF_DIR=$(sudo mktemp -d /tmp/cheesetrap-upgrade.XXXXXXXX)
sudo chmod 700 "$UPGRADE_PROOF_DIR"
```

2. Compare the running DB's Compose labels and volume mount with the rendered
   configuration and compare `compose.env` with the shell project. The helper fails
   on a project, volume, or install-root mismatch. It records the DB volume's creation time and the external sensor
   network's actual Docker ID to detect replacement under the same names.
   Keep this evidence private.

```bash
upgrade_identity() {
	local pg_project pg_service pg_volume volume_project volume_key volume_created sensor_network network_id
	sudo grep -Fqx -- "COMPOSE_PROJECT_NAME=$COMPOSE_PROJECT_NAME" "$INSTALL_ROOT/compose.env" || return 1
	pg_project=$(ops_docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' "$POSTGRES_CONTAINER") || return 1
	pg_service=$(ops_docker inspect --format '{{index .Config.Labels "com.docker.compose.service"}}' "$POSTGRES_CONTAINER") || return 1
	test "$pg_project" = "$COMPOSE_PROJECT_NAME" || return 1
	test "$pg_service" = postgres || return 1
	pg_volume=$(ops_docker inspect --format '{{range .Mounts}}{{if eq .Destination "/var/lib/postgresql/data"}}{{.Name}}{{end}}{{end}}' "$POSTGRES_CONTAINER") || return 1
	test -n "$pg_volume" || return 1
	volume_project=$(ops_docker volume inspect --format '{{index .Labels "com.docker.compose.project"}}' "$pg_volume") || return 1
	test "$volume_project" = "$COMPOSE_PROJECT_NAME" || return 1
	volume_key=$(ops_docker volume inspect --format '{{index .Labels "com.docker.compose.volume"}}' "$pg_volume") || return 1
	test "$volume_key" = postgres-data || return 1
	volume_created=$(ops_docker volume inspect --format '{{.CreatedAt}}' "$pg_volume") || return 1
	test -n "$volume_created" || return 1
	sensor_network=$(set -o pipefail; ops_compose --profile worker config --format json | python3 -c '
import json, sys
from pathlib import Path
c = json.load(sys.stdin)
project, volume, root = sys.argv[1:]
assert c["name"] == project
assert c["volumes"]["postgres-data"]["name"] == volume
mounts = c["services"]["postgres"]["volumes"]
assert any(m["type"] == "volume" and m["source"] == "postgres-data" and m["target"] == "/var/lib/postgresql/data" for m in mounts)
assert any(m["type"] == "bind" and Path(m["source"]) == Path(root) / "secrets/bootstrap-password" for m in mounts)
assert c["networks"]["sensor"]["external"] is True
print(c["networks"]["sensor"]["name"])
' "$COMPOSE_PROJECT_NAME" "$pg_volume" "$INSTALL_ROOT") || return 1
	test -n "$sensor_network" || return 1
	network_id=$(ops_docker network inspect --format '{{.Id}}' "$sensor_network") || return 1
	test -n "$network_id" || return 1
	printf '%s\n' "$pg_project" "$pg_volume" "$INSTALL_ROOT" "$sensor_network" "$volume_created" "$network_id"
}
upgrade_sources() {
	sudo python3 -c '
import json, sys
from pathlib import Path
sources = json.loads((Path(sys.argv[1]) / "config/collector/sources.json").read_text())
identity = [{k: v for k, v in source.items() if k != "archive_paths"} for source in sources]
print(json.dumps(sorted(identity, key=lambda source: source["sensor_id"]), sort_keys=True))
' "$INSTALL_ROOT"
}
upgrade_files() {
	sudo bash -o pipefail -c 'cd "$1" && find install.json compose.env config secrets bootstrap -type f -exec sha256sum {} + | LC_ALL=C sort' sh "$INSTALL_ROOT"
}
upgrade_identity | sudo tee "$UPGRADE_PROOF_DIR/identity.before" >/dev/null
```

The DB mount must use the existing `<project>_postgres-data` engine volume.
Compose has no top-level project name and keeps the `postgres-data` key. With the
original env-file and explicit project, the new example names cannot select a new
DB volume. A failed comparison is a reason to investigate while services are stopped.

3. Stop the active raw-retention timer, all app roles, sensors, and any old worker
   processes on other hosts. Wait for active cleanup to finish, then record the
   installation file hashes.

```bash
ops_compose --profile worker stop api worker collector cowrie web
upgrade_files | sudo tee "$UPGRADE_PROOF_DIR/files.before.sha256" >/dev/null
upgrade_sources | sudo tee "$UPGRADE_PROOF_DIR/sources.before.json" >/dev/null
```

Back up the DB and configuration and pass an [isolated restore](backup-restore.md)
before continuing. Back up raw logs, sensor state, and secrets separately under
their existing access controls.

4. Switch this checkout to the selected pinned release. Keep the existing install
   root and env-file. Remove obsolete SMTP overrides as described below. Check the
   new Compose configuration against the running DB and saved identities before
   building both local images.

```bash
: "${RELEASE_REVISION:?set selected pinned release}"
git checkout --detach "$RELEASE_REVISION"
REPO_ROOT="$PWD"
upgrade_identity | sudo tee "$UPGRADE_PROOF_DIR/identity.candidate" >/dev/null
sudo cmp "$UPGRADE_PROOF_DIR/identity.before" "$UPGRADE_PROOF_DIR/identity.candidate"
ops_compose build api web
```

The new app and web tags end in `:local`. Their repositories still use the existing
project name. Cowrie's bind mount and the web build now use `sensors/`. Build both
images from the new checkout before any app or sensor resumes.

For installations that used `:m1`, the local `<project>:m1` and
`<project>-web:m1` images remain. Keep them until you accept the upgrade. An
approved rollback to the old checkout uses those images. Review DB compatibility
and the old worker's delivery behavior before any rollback. After you accept the
upgrade and no longer need these rollback images, remove only the exact old tags.
If Docker reports a container reference, review that stopped container before
removing it. Do not force removal or use a broad image prune.

```bash
ops_docker image rm "${COMPOSE_PROJECT_NAME}:m1" "${COMPOSE_PROJECT_NAME}-web:m1"
```

5. Apply forward migrations with the migration role. Recreate only previously
   active services after the host guard passes. Set `RESUME_SERVICES` to the recorded
   subset of `api collector cowrie web worker`. Keep PostgreSQL and its volume.
   First compare the installation files, then refresh collector archive paths.

```bash
ops_compose run --rm --no-deps migrate
upgrade_files | sudo tee "$UPGRADE_PROOF_DIR/files.after.sha256" >/dev/null
sudo cmp "$UPGRADE_PROOF_DIR/files.before.sha256" "$UPGRADE_PROOF_DIR/files.after.sha256"
sudo -n python3 scripts/install-prepare.py --refresh-sources \
	--config "$INSTALL_CONFIG" --output "$INSTALL_ROOT"
upgrade_sources | sudo tee "$UPGRADE_PROOF_DIR/sources.after.json" >/dev/null
sudo cmp "$UPGRADE_PROOF_DIR/sources.before.json" "$UPGRADE_PROOF_DIR/sources.after.json"
sudo -n python3 scripts/install-firewall.py check \
	--config "$INSTALL_CONFIG" --output "$INSTALL_ROOT"
: "${RESUME_SERVICES:?set previously active services}"
for service in $RESUME_SERVICES; do
	case "$service" in api|collector|cowrie|web|worker) ;; *) exit 1 ;; esac
done
for service in $RESUME_SERVICES; do
	ops_compose --profile worker up -d --no-deps --force-recreate "$service"
done
upgrade_identity | sudo tee "$UPGRADE_PROOF_DIR/identity.after" >/dev/null
sudo cmp "$UPGRADE_PROOF_DIR/identity.before" "$UPGRADE_PROOF_DIR/identity.after"
ops_compose --profile worker ps -a
```

The file comparison covers sensor UUIDs in the collector manifest, installation
configuration, TLS files, and secret bytes before the archive-path refresh. Refresh
preserves UUIDs and mappings while updating `archive_paths`. The second comparison
checks every manifest field except `archive_paths`, including `sensor_id` and
`endpoints`, before any service resumes. Verify API readiness and login, open a
pre-upgrade event and report revision, and check raw-to-event progress, checkpoints,
and worker queues. Resume only a previously active retention timer after these
checks. Preserve the private before-and-after evidence for recovery review.

On a mismatch or failed migration, keep apps and sensors stopped and investigate.
Do not run preparation without `--refresh-sources`, recreate volumes, or start an
older worker as a shortcut.
A rendered configuration comparison is not a live DB upgrade test.

## Switch to the draft-only binary

Use the administrative session and `ops_compose()` helper above. For a release
that also changes product names, follow the full identity-preservation procedure.

1. Use the [backup and restore administrative session](backup-restore.md) to confirm
   Docker context, project, and env-file. Stop API, worker, collector, sensors, and
   old processes on other hosts. Stop raw retention and wait for active cleanup to finish.
2. Back up DB and configuration and verify isolated restore. Preserve legacy
   delivery, approval, SMTP-test data, and secrets. Never mount those stored SMTP
   secrets into the new worker.
3. Replace Compose configuration. Remove `deploy/smtp.compose.yaml`, SMTP test
   addresses, and `CHEESETRAP_SMTP_SECRET_FILE`. Inspect other overrides too.
4. Apply forward migrations with the migration role. Check app schema 31 and River 8.
5. Recreate API and worker with the new binary only. Resume only previously running
   sensor and collector services after checking the installation manifest and host guard.

```bash
ops_compose run --rm --no-deps migrate
ops_compose --profile worker up -d --no-deps --force-recreate api worker
```

The draft-only change itself needs no new migration. Even legacy automatic approval
settings produce drafts only. Pending `deliver_report` and `smtp_test` River jobs
are neither consumed nor recovered. Legacy delivery reports appear as `archived`
without send or edit actions. Old workers can send legacy queued jobs, so do not
automatically roll back. On failure, keep all apps stopped, investigate, and choose
a forward fix.

## River REINDEX

Runtime workers set `ReindexerIndexNames: []string{}` to disable automatic REINDEX
only. Other River maintenance continues. Never grant ownership, MAINTAIN, or
superuser to the worker or API. The migration role owns River schemas and indexes.
That role or a separately authorized DBA performs maintenance.

Monitor DB size, index bloat, and locks. If needed, stop the worker for a maintenance
window. Check ownership, then use an autocommit psql connection. `CONCURRENTLY`
cannot run in a transaction block. A DBA must investigate invalid indexes after
failure. Check `indisvalid`, worker restart, and queue processing afterward.

```sql
SELECT c.relname, pg_get_userbyid(c.relowner) AS owner
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname='cheesetrap_river' AND c.relkind='i';
REINDEX TABLE CONCURRENTLY cheesetrap_river.river_job;
SELECT i.indexrelid::regclass, i.indisvalid
FROM pg_index i WHERE i.indrelid='cheesetrap_river.river_job'::regclass;
```

REINDEX is not part of automatic app startup or migration.

## Ingress and worker network changes

These deployment-boundary changes preserve schema 24, detections, evidence, and
legacy formats. Omitted ingress keys retain `/32`. Select `public_ipv4` explicitly
for a new production deployment. For an existing production identity, follow the
[ingress-policy change procedure](install.md#sensor-ingress-policy). Never flip a
test sensor's `is_test` to reclassify past data as production.

Recreate old workers to receive registry-lookup egress using the current base
Compose configuration. Remove SMTP overlays and related variables. Only workers
receive this egress. Never manually attach API, collector, sensors, or DB to it.

## Retention policy and event results, schemas 25 and 26

Update the app and host retention scripts together. Stop worker, collector, and API
under the standard procedure before migrations 25 and 26. Migration 25 makes cleanup
functions read validated policy, with defaults for missing old fields. Migration 26
builds a small evidence-history table from remaining report copies and events and
adds page-invalidation state. It never rewrites detection content, evidence copies,
immutable revisions, or hashes. Sources and legacy and chunked reads remain.

A shorter policy can affect preexisting data. Check purpose and backups before
reducing values. Unchanged settings retain defaults. Replayed successful PATCH
responses provide defaults for new fields. Restore recognizes schemas 14 to 31,
but current migrations are required before app use. Automatic downgrade is unsupported.
Check migration duration separately for a large production DB.

## Event detection reads, schema 27

Migration 27 changes only `event_detection_result` query order. It fixes the event's
actual legacy or chunk membership first, then reads linked references and detections.
Results, evidence sets, copies, revisions, retention history, and list snapshot
semantics remain. Migration 26 is not edited. Use the standard stop, backup,
migrate, and restore-check procedure. Ownership, permissions, function settings,
resource limits, and timeouts remain. Restore accepts schema 14 to 31 manifests
and requires current migrations before app use. Downgrade is unsupported.

## Streamed evidence and contact provenance, schemas 28 to 30

Use the standard stop, backup, and migration procedure. Migration 28 adds streaming
hashes, processing projections, and staging for new detections. Migration 29 adds
sealed report evidence parts. Migration 30 connects bounded retention cleanup.
Existing evidence, hashes, and revisions are not bulk-converted. Editing an old
revision applies parts only to its new revision.

Contact provenance remains draft review data. Large aggregations use DB workspace
and processing time instead of unbounded app memory. Monitor disk space and cursor
progress. Shutdown cancellation and storage guards remain. See the
[storage decision](../decisions/0002-streamed-evidence.md) for formats, compatibility,
and verification scope.

Legacy SMTP environment variables prevent startup with `smtp_configuration_removed`.

## Dated collection gaps, schema 31

Migration 31 preserves the cumulative gap summaries and backfills one dated
incident per summary with the legacy cause. Incidents retain their time ranges
and causes permanently. Sensor state reflects current collection health and
returns to active after a commit without a pending gap. New draft evidence
includes only incidents overlapping its report window. Existing revisions and
stored event quality flags stay unchanged. Raw-retention deletions remain possible
gaps; keep the receipt format and monotonic counters. Use the standard stopped
backup and forward-migration procedure. Restore accepts schema-31 manifests.
