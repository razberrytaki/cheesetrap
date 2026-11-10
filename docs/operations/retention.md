# Retention and storage operations

By default, normalized events remain for 30 days after ingestion. Terminal report
evidence copies, delivery records, and audit history remain for 180 days after the
last change. Completed River jobs remain for seven days. A DB trigger records each
report's last change. Earlier migrations initialized old reports to the migration
time. Policy changes do not reset that timestamp.

Only `sent`, `rejected`, and `closed_unconfirmed` reports are eligible for cleanup.
Review, preparation, sending, retry, failure, cancellation, and unresolved unknown
outcomes remain protected. Closing an unknown outcome without retransmission protects
it until the later of its immutable `retention_until` minimum of 180 days and the
current terminal-history period. Legacy states are retained for compatibility.
The current binary has no sender.

## Policy changes and effective boundaries

Change the `retention` object in settings or `PATCH /api/v1/settings` with the usual
expected version, idempotency key, and CSRF checks. The audit records the settings
version and policy values. Old settings with missing keys use the defined defaults.
Invalid stored values or failed reads never become arbitrary defaults used for deletion.

| Field | Default | Allowed range |
| --- | --- | --- |
| `raw_days` | 7 days | 1 to 365 days |
| `raw_bytes` | String `1073741824`, 1 GiB per sensor | String bytes `33554432` to `1099511627776` |
| `event_days` | 30 days | 1 to 3650 days |
| `history_days` | 180 days | 1 to 3650 days |
| `job_days` | 7 days | 1 to 365 days |

Send all fields when changing the object. The next DB cleanup call after commit
reads the new policy. An active call finishes its snapshot. Cleanup of detections
already marked `retiring` completes even if retention increases. Shorter periods
can make existing data eligible. Increasing a period does not restore deleted data.
Protection, unique attribution, copies, and legacy and chunked evidence proofs remain.

The host raw timer reads policy once from PostgreSQL and uses it for preview and
cleanup. A read or validation failure prevents preview, service stops, and deletion.
Changes during a call apply next time. The limit of 64 archives per sensor and
32 MiB or daily rotation remains. A high period or size setting can reach the
archive-count limit first. That requires operator review, not forced deletion.
Allowed policy ranges do not guarantee capacity or throughput.

The worker reconciles the `retention` queue each minute. While cleanup progresses,
it repeats short transactions with at most 1,000 rows per statement, yields 10 ms
after commit, and reacquires locks in the next transaction. After 20 seconds,
including storage measurement, it stops new calls and resumes after one second.
A call processes one terminal report. Child evidence, revisions, approvals, and
delivery records also use at most 1,000 rows per statement. Large reports lose
eligible children over several calls and the report last. SQL lock timeout is
one second and the call budget is five seconds. Only irreversible terminal states
allow this process. The worker has no direct DELETE permission on events or
immutable report data. Cleanup functions fix `search_path`, enforce retention,
and bound time by the real DB clock. API and collector cannot call them.

Events not yet processed by the detection cursor or not yet sealed remain protected. Detections
and evidence remain until aggregation completes and report evidence copies exist.
Copies remain visible after source events expire. `protected_events` and
`storage_backlog` show expired but protected events. For growing backlog, check
worker health, failed lookups, and pending review. Never weaken evidence protection
to recover disk space.

Chunk cleanup locks the detection cursor before the report draft lock.
Since migration 20, it drains existing `retiring` detections first without repeating
their evidence proof. For new candidates it counts actual shared-chunk members
and copies once per chunk, then sums by detection. A mismatch with the immutable
count, or any uncopied member, protects the detection. Legacy links receive the
same checks. Candidates are not truncated in a way that lets an early protected
detection block later eligible detections. Only completed aggregation with a copy
of every actual evidence member can become `retiring`. Such detections leave reads
and redetection retries without changing original counts, hashes, or explanations.
References drain in bounded batches, empty detections disappear, and shared chunks remain.

Unreferenced chunks become `retired` before their member links drain. Migration 21
reads members only under retired headers and deletes selected row locations within
the same SQL statement. It keeps `(chunk_id,event_id)` order and the 1,000-row
limit without persisting row locations. A later worker continues interrupted cleanup.
New detections never reuse a retiring chunk, even with identical evidence.
Legacy links drain too, without bulk conversion. For upgrades after an older
version partly drained links, migration 17 checks completed windows, remaining
copies, and expiration before inheriting `retiring`. Original counts, hashes,
and remaining links stay intact. `protected_events` includes expired events
protected by pending chunk foreign keys, so events can remain after their detection
disappears until cleanup completes.

Do not run an older binary that cannot read chunks against a DB containing chunks.
Use [isolated recovery](backup-restore.md). Throughput and chunk-width decisions
need separate load evidence.

The worker acquires cursor then draft locks in the same transaction within the
five-second call budget. If another task owns a row lock, it rolls back without
deletion, releases the connection, waits a cancellable 50 ms, and retries within
the 20-second job budget. At the budget boundary River snoozes it for one second.
`metadata.snoozes` counts deferrals, not completions or failures. Check
`retention_status.checked_at`, completion times, snoozes, and final queue state.
Missing singletons, permission or SQL errors, cancellation, execution failure,
and commit failure remain ordinary failures. Lock avoidance does not guarantee
fairness under sustained contention. Monitor continued retention completion.
The one-second SQL lock timeout, five-second call budget, and copy protections remain.

## Raw JSONL

The host operator owns raw deletion. The collector reads logs only. Preserve log
permissions and engine isolation, then run:

```sh
sudo -n python3 scripts/retain-raw-logs.py --output /absolute/install/root
```

Register a host timer to run this each minute. Record its exact unit name
and activation state for recovery. Set `RAW_TIMER` to that unit name when using
the recovery procedures. Leave it empty if you run cleanup manually without a timer.
The script first checks read-only whether work is needed. If needed, it stops collector, Cowrie, and web, verifies
the stops, and rotates by rename and recreate. It applies the configured period
and total managed JSONL size per sensor, deleting oldest archives first.
Rotation triggers include the first nonempty file, a 32 MiB or 24-hour boundary,
and total-size overflow. Age uses archive modification time. With seven-day
retention and daily rotation, the oldest event can remain about eight days.
This is neither per-event expiration nor a hard filesystem quota. Growth between
runs can temporarily exceed the configured size.

Failure after stopping can leave services stopped. A retry remembers only the
state at retry time, so it does not restart services stopped by an earlier failure.
Use explicit recovery below. Success resumes only container IDs running before
that call with `docker start`, without starting Compose dependencies. Removed
one-shot migration containers or another overlay's current rendering cannot block
collector resumption.

For legacy CD installations, `org.cheesetrap.cd-template` links each CD collector
to the full original Compose collector ID. The script discovers, stops, and
checks every exact ID, then resumes only previously running IDs. When
`/var/lib/cheesetrap-cd` exists, it holds the deployment `lock` from policy read
through resumption. A held lock fails before changes. Install this retention-script
version at the actual timer path before enabling a CD collector. The original
Compose collector remains the ownership reference. Do not delete it or change its label.

Before each deletion, the script atomically increments each sensor's monotonic
counter in `logs/.retention-loss.json`. The collector reads the receipt and
persists dated collection-gap incidents with the retention-cleanup cause for unseen counts. The host cannot prove which bytes
were unread, so every archive deletion is conservatively a possible gap.
A crash before actual deletion can record a gap without loss. Never delete the
receipt or reset counters. An invalid receipt prevents collector startup or continued collection.

### Resume after raw-retention failure

The manual Compose commands below apply to Compose installations. With a CD
collector, the Compose stop list does not prove all collectors stopped. Stop
deployment and retention, hold the same CD lock, and inspect full linked container
IDs, ownership labels, and running states. Resume only exact IDs recorded as running
before failure. Do not start the stopped original collector instead. Investigate
if the record is missing or uncertain.

First define the installation paths, `RAW_TIMER`, and `rdc` helper from
[resume after reboot](install.md#resume-after-reboot) in the same shell.
Set `RAW_TIMER` to your registered unit name or leave it empty if none is registered.
The recovery blocks run in subshells so failure leaves the SSH shell open.
Before registering a timer or running manual cleanup, record running collector
and sensor services and timer activation. For example, preserve
`rdc ps --status running --services collector cowrie web` output. Never infer the
original state from the stopped list after failure. Without a prior record,
confirm deployment or interruption records before starting anything.

1. Stop the actual raw timer and confirm any active run has finished. Inspect
   fixed error classes, Docker state, file ownership and permissions, archive
   names and counts, and deletion receipts. Never remove `.raw-retention.lock`
   or bypass the lock.

```sh
# Use the pre-failure record. Exclude services that were already stopped.
RAW_RESUME_SERVICES='collector cowrie web'
(
set -eu
if [ -n "$RAW_TIMER" ]; then
  sudo -n systemctl stop "$RAW_TIMER"
fi
rdc ps -a collector cowrie web
rdc stop collector cowrie web
)
```

2. Fix the established cause while stopped. Never force success by deleting
   archives, truncating active files, resetting receipts, or clearing gaps.
   The DB must be reachable so retry can read policy. External installations read
   policy with the pinned PostgreSQL client on `database_egress`, using the protected
   migration URL and CA. They do not require a bundled `postgres` container.
   After excluding another run and fixing the cause, retry. Retry also refreshes the manifest. The explicit refresh
   below validates paths again before resumption. Stop on any failed command.
   A successful retry does not start already stopped services. Start only recorded services.

```sh
(
set -eu
sudo -n python3 scripts/retain-raw-logs.py --output "$INSTALL_ROOT"
sudo -n python3 scripts/install-prepare.py --refresh-sources \
  --config "$INSTALL_CONFIG" --output "$INSTALL_ROOT"
sudo -n python3 scripts/install-firewall.py check \
  --config "$INSTALL_CONFIG" --output "$INSTALL_ROOT"
for service in $RAW_RESUME_SERVICES; do
  case "$service" in collector|cowrie|web) ;; *) exit 1 ;; esac
done
for service in $RAW_RESUME_SERVICES; do
  rdc start "$service"
done
rdc ps -a collector cowrie web
rdc logs --tail=50 collector cowrie web
)
```

3. If the guard check fails, keep sensors stopped and follow installation guard
   recovery first. After resumption, send authorized client input and compare raw
   logs, UI events, sensor observation times, and checkpoints. Preserve deletion
   receipts and existing gaps. Check originally running services and restart only
   a previously active timer named by `RAW_TIMER` with
   `sudo -n systemctl start "$RAW_TIMER"`. Leave an absent or previously inactive timer stopped.

New Cowrie settings disable TTY recording and separate text logs. Diagnostics use
stdout and Compose's two 5 MiB files. Existing settings are not overwritten.
Stop the engine, then apply `ttylog=false` and `[output_textlog] enabled=false`.
The script does not delete old `state/cowrie/lib/cowrie/tty` or unmanaged files.
Review and archive or remove those separately.

## Auxiliary logs and capacity planning

New web settings rotate `/var/tmp/opencanary.log` at 5 MiB with one backup,
separately from evidence JSONL. `events.jsonl` and its raw policy are unchanged.
The nominal auxiliary-log total is 10 MiB, but one large diagnostic record or an
already oversized file can temporarily exceed it. For existing installations,
stop web and set `logger.kwargs.handlers.file` to
`class=logging.handlers.RotatingFileHandler`, `maxBytes=5242880`, and `backupCount=1`.
Restart afterward. Never delete evidence or deletion receipts as part of that change.

Retention age is the minimum age for deletion eligibility. Inflow above cleanup
capacity or protected evidence extends actual retention. `held` and unresolved
`unknown` records have no automatic expiration, so an unreviewed report backlog
has no fixed maximum size. Budget each revision's complete evidence and rule
snapshot, retained WAL, backups, a simultaneous restore DB, temporary files, and
space for VACUUM reuse. Plan for usage at or below 80% and observe actual creation
and deletion. The 90% guard does not replace capacity planning.

## Disk guards and recovery

Bundled Compose mounts `/logs` and PostgreSQL data at `/storage/postgres` read-only in
collector and worker, with `CHEESETRAP_STORAGE_PATHS=/logs:/storage/postgres`.
Bundled measurement uses statfs capacity and never reads DB file contents. For a
custom deployment, set actual raw and DB filesystem paths separated by colons.
A standalone worker without storage paths or a database quota has no automatic
disk guard. Configure storage measurement in production.

For external PostgreSQL, the override measures `/logs` with statfs and sets
`CHEESETRAP_DATABASE_QUOTA_GIB` from the install config. The quota must be a positive
integer GiB value. An explicitly empty quota is invalid and fails closed.
Each sample queries `pg_database_size(current_database())` under the collector
or worker role. Database usage is size divided by quota, clamped to
100%. This budget does not enforce a provider allocation. `pg_database_size`
excludes WAL and other databases. Leave headroom for WAL, temporary work,
maintenance, backups, and provider limits. Monitor provider storage separately.

The highest filesystem or database usage controls the guard. Usage of 80% warns.
At 90%, collector new-file reads and detection, aggregation, draft, and contact jobs pause.
Retention cleanup continues. Durable jobs remain queued and resume on the next
poll or retry after recovery. Unmeasurable configured paths, invalid quotas, and
failed database-size queries also pause work and persist an unavailable sample.
UI observations older than two minutes show `stale`. Missing observations show
`unavailable`. Each task measures again immediately before work.

The guard records a dated collection-gap incident with the storage-restricted
cause. Incidents and cumulative gap counts remain permanently. Notes within ten
minutes of the latest incident extend its range and combine causes; later notes
start a new incident. Recovery or restart never resets counts or rewrites past
quality. Sensor state describes current health. A commit without a pending gap
returns the sensor to active. A draft includes an evidence sensor's incidents only
when they overlap its report window, including an incident ending at the window
start but excluding one starting at the window end. An overlapping incident holds
the draft for `collection_gap`; old incidents alone do not hold later drafts.
Every raw archive deletion remains a possible gap even if unread loss is unconfirmed.
Pre-upgrade gap summaries become dated incidents with the legacy cause. Last engine-log time is the server time when the
last record was read and committed, not the attacker-controlled event timestamp.
Collector observation time and sensor state appear separately.
`collection_lag_seconds` is time since the oldest collector observation among active
sensors. `detection_lag_seconds` is the wait for undetected events. An idle engine
without new input does not establish collector failure.

Status shows queue waiting time, contact lookup failures, draft review, and storage.
Legacy delivery queues are excluded from pending-work totals.

## Verify

```sh
scripts/test-integration.sh ./internal/retention -run TestRetention
go test ./internal/observability -count=1
python3 -m unittest discover -s scripts -p 'test_raw_retention.py'
```

Tests use fake time and capacity, small temporary files, and isolated PostgreSQL.
They do not fill a real disk or connect to production DBs, cloud accounts, or external SMTP.
