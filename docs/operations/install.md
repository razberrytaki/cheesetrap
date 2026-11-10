# Install on a single Linux server

Use a pinned source revision and tools from the [release procedure](release.md).
Read the project MIT license and the [third-party notices](../../THIRD_PARTY_NOTICES.md).

The host needs Linux, public IPv4, Docker Engine 28 or later with the Compose
plugin and iptables backend, Python 3, nftables, iptables, OpenSSL, and sudo. See the
[requirements and tested environments](reference-deployments.md).
Run commands from the checkout root in a management SSH session. The operator
account needs non-interactive sudo authorization for the privileged commands.
`sudo -n` fails instead of prompting for a password. Do not change Docker daemon
settings or stop existing services to install cheesetrap.
For an existing deployment, follow the [upgrade guide](upgrade.md).
Check the [resource limits and capacity](#resource-limits-and-capacity) before installation.

The API publishes only on `127.0.0.1:8080`. The bundled DB has no published port.
Host nftables `inet` and `bridge` filters block new sensor connections.
Compose networks alone cannot block DB, management SSH, metadata, or callbacks.
The optional worker runs detection, seals and repairs aggregation windows,
copies evidence, creates report drafts, and refreshes contacts. It does not send email.

## Preserve management SSH and prepare configuration

Keep your current SSH connection open. Verify a new management connection from
another terminal before changing ports. Defaults are management SSH 22, decoy SSH
2222, HTTP 18080, and HTTPS 18443. With the default `single_client` test policy,
restrict these three decoy ports in upstream firewalls to the same trusted client
IPv4 `/32`. Use your server's public IPv4 and the IPv4 address of the
client you will test from, as a `/32`.

To publish decoy SSH on host port 22, first move management SSH to another port yourself.
Add a separate management allow rule and listener without closing the current
connection. Run `sshd -t` and verify a new connection to the new port before removing
the old rule or listener. If that fails, restore only your changes through the
existing session. The installer does not change SSH settings, management ports,
or existing firewall chains.

For a load balancer with different external and host ports, use the
[reference deployment](reference-deployments.md#network-load-balancer-example).

`deploy/config.example.yaml` uses the JSON subset of YAML 1.2. The tools accept
JSON notation only so they can reject unknown keys, invalid values, and duplicate
keys without another YAML library. Replace documentation addresses with your
public IP and client `/32`. Choose unique project, network, bridge, and sensor
subnet values that do not overlap existing Docker networks or host routes.
`is_test: true` marks test input. Create a separate production identity with
`false` in a new deployment. Never change an existing sensor UUID or reclassify
historical events' test status.

```sh
mkdir -p .local
chmod 700 .local
cp deploy/config.example.yaml .local/install-config.yaml
chmod 600 .local/install-config.yaml
```

### Sensor ingress policy

`ingress_policy` is an installation setting separate from event test status.

| Value | Behavior |
| --- | --- |
| Omitted or `single_client` | Allow only `allowed_client_cidr`, a single IPv4 `/32`, on sensor ports. `is_test:false` alone does not expose sensors. |
| `public_ipv4` | Requires explicit selection and `is_test:false`. Accept IPv4 sources on the designated sensor TCP ports without a source restriction. |

Both policies require a valid `allowed_client_cidr` `/32`. Public mode still blocks
IPv6 sensor ingress, new sensor connections to the host, other sensors, management
networks or the internet, and new API egress. It does not widen management SSH,
API, or DB exposure. Upstream firewalls and other host rules can further restrict
reachability. The installer does not open them. Keep test deployments on `/32`.
For production, choose a separate deployment's policy and only the three sensor ports.

Omitting the policy key preserves the existing guard output and hash. To change
an existing production policy, stop and remove API and sensor containers, then
run `install-firewall.py remove` with the old config. Change only the ingress
policy in both the external config and installation `install.json`. Run `apply`
and `check` with the new config, then recreate containers. Keep raw files, volumes,
UUIDs, and secrets. `check` rejects config changes after application. `apply`
rejects attached API or sensor containers. Returning to `single_client` narrows
ingress without changing `is_test` or historical evidence. Use a new deployment
to move from a test identity to a production identity.

Set the [sensor ingress policy](#sensor-ingress-policy) when you edit the
config. Preparation stores it, and later steps reject a changed config.

```sh
# Set addresses, management port, ingress policy, and unique project/network/bridge/subnet in an editor.
INSTALL_CONFIG="$PWD/.local/install-config.yaml"
INSTALL_ROOT="$PWD/.local/install"
sudo -n python3 scripts/install-prepare.py --config "$INSTALL_CONFIG" --output "$INSTALL_ROOT"
```

Preparation accepts a new directory only. It never replaces existing UUIDs or DB
passwords on rerun. Investigate a partially prepared directory and retry with a
new name. Each app role gets a random DSN file and separate DB user. Runtime roles
never receive a superuser DSN. Bootstrap SQL, passwords, and DSNs use mode 0600.
The app UID is 10001. PostgreSQL bootstrap files use UID 999. The installation
root uses 0700, and Docker binds only each role's required files.
`compose.env` contains paths, ports, and network names, not secrets.
The example project is `cheesetrap-example` and its external sensor network is
`cheesetrap-example-sensor`. Compose builds `cheesetrap-example:local` and
`cheesetrap-example-web:local`. Custom project names change both image names.
Keep an existing installation's names and files through the
[upgrade procedure](upgrade.md#preserve-installation-identity-across-product-renames).

New installations exclusively create empty `cowrie.json` with UID/GID 999 and
`events.jsonl` with UID/GID 65534, both mode 0644. This distinguishes a normal
empty log before first input from missing raw data and permits collector UID
10001 to read it. Existing active files are never truncated.

Collector `/config` mounts only the operator-owned `config/collector` directory,
read-only. Sensors receive no manifest, DB or administrator secret, or Docker
socket. Fixed socket IPs and operator-verified configuration define public mappings.
`Forwarded` and `X-Forwarded-For` never establish the source.

Generate a decoy-only HTTPS key and certificate. Do not copy a business key or
certificate. The following certificate is for tests. Explicitly trust the test
certificate during input verification.

```sh
sudo -n openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
  -subj /CN=cheesetrap-decoy \
  -keyout "$INSTALL_ROOT/config/web/key.pem" \
  -out "$INSTALL_ROOT/config/web/cert.pem"
sudo -n chown 65534:65534 "$INSTALL_ROOT/config/web/key.pem" "$INSTALL_ROOT/config/web/cert.pem"
sudo -n chmod 600 "$INSTALL_ROOT/config/web/key.pem"
sudo -n chmod 644 "$INSTALL_ROOT/config/web/cert.pem"
```

For IP or DNS verification, include the actual target in the certificate SAN or
provide a trusted verification certificate. Do not disable certificate checks globally.

## Use external PostgreSQL

Omit `database` to keep the bundled PostgreSQL container. For an external database,
start with [the external example](../../deploy/config.external-db.example.yaml).
It uses placeholder values and does not identify a running service.

Prepare these prerequisites before starting the app:

1. Provision PostgreSQL 17 with a private IPv4 endpoint. The host must route to it.
   Use a direct endpoint or session-mode pooling. Migration uses a session advisory
   lock, and app pools set startup parameters. Transaction-mode pooling is unsupported.
2. Create database `cheesetrap`. The provider administrator must own it and have
   `CREATEROLE`. This account runs bootstrap SQL only. Runtime accounts remain restricted.
3. Install the provider CA bundle as a regular, non-symlink file readable by app
   UID 10001. Choose an absolute normalized path containing letters, digits,
   underscores, periods, hyphens, and slashes. Keep the CA file through upgrades.
4. Set `database.host`, `port`, `ca_file`, `quota_gib`, and `allowed_cidr` in the
   installation config. The host is a lowercase DNS name or private IPv4 literal.
   Preflight requires every resolved address to be inside `allowed_cidr`.
   The CIDR must be within `10/8`, `172.16/12`, `192.168/16`, or `100.64/10`,
   have prefix length at least 16, and not overlap the sensor subnet.
   Public endpoints, localhost, and the bundled hostname `postgres` are rejected.
5. Set a quota of 1 to 1,000,000 GiB below the provider's usable capacity.
   This is a collection guard budget, not a provider storage limit.
   Leave room for WAL, maintenance, backups, and other databases. See
   [disk guards and recovery](retention.md#disk-guards-and-recovery).

External mode requires Docker Compose 2.33.1 or newer for override tags and
explicit gateway selection. Preparation writes verified-TLS role URLs and a
mode-0600 `bootstrap/10-roles.sql`, without a bootstrap password. The SQL file
stays owned by the preparing operator rather than PostgreSQL UID 999.
Run it once against the empty database with `psql` as the provider administrator.
Use a protected service file or password prompt. Never put credentials in command
arguments or logs. With a locally configured `cheesetrap-provider-admin` service:

```sh
sudo -n psql 'service=cheesetrap-provider-admin' -X -v ON_ERROR_STOP=1 \
  --single-transaction -f "$INSTALL_ROOT/bootstrap/10-roles.sql"
```

The SQL temporarily grants the migration role to the administrator with `SET`
permission and no inheritance so PostgreSQL 16 and later can create schemas with
that owner. It explicitly switches to that role to set schema privileges, then
resets the role and revokes this membership. Do not rerun bootstrap over an
existing installation. Review and recover a failed transaction before retrying.

For every external-mode Compose command, use both files in this order. This
includes build, start, admin, migration, upgrade, and recovery commands:

```sh
dc() {
  sudo -n docker compose --env-file "$INSTALL_ROOT/compose.env" \
    -f deploy/compose.yaml -f deploy/compose.external-db.yaml "$@"
}
dc config --quiet
dc build api web
```

The override disables the bundled `postgres` service and removes its migration
dependency and data mounts. It mounts the CA into each app and measures `/logs`
alongside the database quota. Sensors stay on their sensor network.
The installation-owned `database_egress` network uses the `ctmd-` bridge prefix.
The host guard permits only the configured destination CIDR and TCP port on this
bridge, plus replies, and blocks new access from it to the host. Its identity and
attached containers receive the same checks as the API bridge.
Apply the host guard before starting app services. Provider firewall rules must
also allow the host's connection to the private endpoint. The installer does not
change provider rules or host routes.

API, migrate, collector, and admin use this bridge as their default gateway.
The worker keeps its existing registry-lookup gateway on `worker_egress`, which
also carries its database connections. Its outbound access remains broader than
the database-only bridge rules. Only app services join `database_egress`.
Role URLs require `sslmode=verify-full`, the mounted CA, and a five-second connect
timeout. The DB name remains `cheesetrap`. `check` validates files, DNS addresses,
and Compose rendering. It does not authenticate to the provider or verify routing.

External mode has not been verified against a provider database. App containers
may fail to resolve the database hostname when DNS queries leave through the
database-only bridge. Confirm that `migrate` connects on the first deployment.

For reboot and retention recovery, redefine `rdc` with the same two files before
running the recovery blocks. Skip bundled-only commands such as `dc exec postgres`
and PostgreSQL volume checks. Have the provider administrator perform database
administration through its own protected connection.

## Run preflight and build

```sh
sudo -n env SSH_CONNECTION="$SSH_CONNECTION" scripts/install-check.sh \
  --config "$INSTALL_CONFIG" --output "$INSTALL_ROOT"
docker compose -f deploy/compose.yaml config --quiet
sudo -n docker compose --env-file "$INSTALL_ROOT/compose.env" \
  -f deploy/compose.yaml build api web
```

Preflight checks Linux, the current SSH management port, IPv4 and ingress policy,
the fallback `/32`, port conflicts, minimum free space, secrets, TLS files, Compose
rendering, Docker version, and backend. Native Docker nftables backend, direct
routing, disabled firewall support, and unverified daemon options are unsupported.
Port checks target new installations and normally fail against an already running
deployment. Preflight does not verify a new external SSH connection or public reachability.

The app build runs locked `npm ci` and the UI build in pinned Node 22.23.1, then
Go 1.27.3 with `-tags=release` to embed real UI assets. All Go roles use the same
image. Sensor inputs pin Cowrie 3.1.2, OpenCanary 0.9.10, and their extensions.
Operational settings live in `deploy` without changing engine fixtures.
Cowrie's emulated command registry excludes download, DNS, and network commands.
SSH forwarding, SFTP, and telnet are disabled. Never reuse a public decoy password
as a management password.

## Create the sensor bridge and host guard

Use exact config values. These commands show defaults. For a separate deployment,
replace every name and subnet with unique values. Do not adopt an existing network.

```sh
sudo -n docker network create --driver bridge \
  --label com.cheesetrap.install=cheesetrap-example \
  --opt com.docker.network.bridge.name=ctm1-sensor \
  --subnet 172.30.91.0/24 --gateway 172.30.91.1 cheesetrap-example-sensor
sudo -n python3 scripts/install-firewall.py render \
  --config "$INSTALL_CONFIG" --output "$INSTALL_ROOT"
sudo -n python3 scripts/install-firewall.py apply \
  --config "$INSTALL_CONFIG" --output "$INSTALL_ROOT"
sudo -n python3 scripts/install-firewall.py check \
  --config "$INSTALL_CONFIG" --output "$INSTALL_ROOT"
```

The `ctm1` prefix is a fixed identifier for every installation, new or upgraded.
It is not a version. `sensor_network.bridge` must be `ctm1-` followed by 1 to 10
lowercase letters, digits, or hyphens, which keeps the API bridge name within
the 15-character Linux interface limit.

The guard owns only project-derived `ctm1_<hash>` tables. It first checks network
labels, driver, actual bridge, subnet, gateway, and disabled IPv6.
The API uses a separate bridge. Its name replaces the sensor bridge's `ctm1-`
prefix with `ctma-`. Preparation writes that name to `API_BRIDGE` in `compose.env`.
Before Docker creates the API network, preflight and guard application reject
an existing host interface with that name. The API network carries the same
ownership label as the sensor network. Apply and remove require no containers on
the sensor or API publishing network. Remove stopped containers if still attached.
The tool runs `nft -c` before installing both tables in one transaction and refuses
existing same-name tables or sensor containers.

- `inet prerouting -310` selects host-local destinations with `fib daddr type local`. It blocks sensor-port IPv6 and IPv4 outside the allowed `/32` in `single_client` mode. Ordinary forwarding for other containers is outside this ingress rule.
- Sensor bridge `inet input/forward -10` blocks new IP flows and permits only `ct direction reply` responses to incoming connections.
- API bridge `inet input/forward` also permits replies only. API-to-DB traffic uses the internal `management` Compose network.
- `bridge forward -10` blocks new IP flows to other containers on the same bridge without assuming `br_netfilter` is enabled.

Conntrack established state alone does not permit a sensor-originated connection.
The installer never
flushes Docker, VPN, or provider-owned tables, changes host routes, or changes
existing service rules. `check` compares current stateless rules with the saved
post-apply snapshot. Table existence alone does not pass. Containers are not VMs.

Start services only after checking the guard.

```sh
dc() { sudo -n docker compose --env-file "$INSTALL_ROOT/compose.env" -f deploy/compose.yaml "$@"; }
dc up -d api collector cowrie web
dc ps -a
curl --fail http://127.0.0.1:8080/api/v1/health/ready
dc run --rm admin
```

After DB initialization, the restricted migration account applies embedded
migrations before API and collector start. Inside its container only, the API uses
`CHEESETRAP_API_CONTAINER_LISTENER=true` and `0.0.0.0:8080`. Docker cannot publish a
container attached only to an internal network, so only the API also joins the
`api_host` bridge. DB, collector, and other roles do not join it. DB traffic uses
the internal `management` Compose network. Standalone CLI loopback restrictions remain.

Default browser Host and Origin checks require exactly `http://127.0.0.1:8080`.
Do not add wildcards. The optional `api_origin` sets one HTTPS origin in
`compose.env`, while host publication stays on loopback. Follow the
[HTTPS guide](https-access.md) for setup and migration. In HTTPS mode, loopback
health checks need the configured host in the `Host` header.

The admin command prompts on a terminal for a username and a hidden password.
Passwords must be 12 to 1024 bytes. Only one administrator can be created.
For automated input, place `username LF password LF` in a mode-0600 file and use
`dc run --rm -T admin < protected-file`, then handle the file under your retention
policy. Keep passwords out of CLI arguments, shell history, and public logs.

From a new terminal on your local machine, open the management SSH tunnel.
Replace `MANAGEMENT_PORT` with your management SSH port.

```sh
ssh -N -L 127.0.0.1:8080:127.0.0.1:8080 -p MANAGEMENT_PORT operator@management-host
```

Log in at `http://127.0.0.1:8080`. `localhost` or another port will not match the
configured origin. Send authorized SSH, HTTP, and HTTPS test input from an external
client. Compare the UI peer IP, public destination, time, service, and test status
with raw logs and the DB. Container startup or an HTTP 200 alone does not prove collection.

## Start the worker and upgrade an existing DB

New bootstrap creates `cheesetrap` and `cheesetrap_river` schemas owned by the
restricted migration account. `migrate` applies Goose and pinned official River
migrations. After success, start the worker.

```sh
dc --profile worker up -d worker
dc logs --tail=50 worker
```

The worker receives its own DB secret, without secrets for other roles.
At startup and each minute it repairs missing aggregation windows. A window becomes `ready` only after the detection
cursor reaches its seal boundary. Draft work then processes the oldest unfinished
window, one IP at a time, copying evidence and creating revisions. Window readiness
and completed draft creation are different states. Drafts remain `needs_review` or
`held` with reasons. No email is sent.

Authenticated management APIs handle schedules, reply addresses, repeat rules,
report reads, contact selection, rejection, and contact refresh. Refresh returns
202 after durable enqueue and needs a running worker. Automatic River REINDEX is
disabled because the worker has no index maintenance privileges. Follow the
[maintenance guide](upgrade.md#river-reindex).

For old DBs that already have the River schema, do not recreate it. Stop API and
worker, build the new image, and run `migrate`. Goose migration 8 introduced review
and settings versions and contact-refresh requests. API enqueue permissions follow
the official River migrations. Preserve existing schedules, reply addresses, and
immutable revisions.

```sh
dc stop api worker
dc build api
dc run --rm migrate
dc up -d --force-recreate api
dc --profile worker up -d --force-recreate worker
```

If migration fails, leave API and worker stopped. Keep volumes and never grant
schema ownership to runtime accounts. Goose Down deletes review, idempotency, and
settings history and can fail against newer states. It is not a production recovery
procedure. Recover an older app only with a matching DB backup and image.

Drafts without a reply address keep `reply_to_missing`. Registry lookup failure,
missing or ambiguous contacts, evidence-quality gaps, and evidence older than
72 hours also hold drafts without discarding evidence. The worker queries registries
through its dedicated `worker_egress` Compose network. It reaches the DB
through the internal `management` Compose network. Keep sensors on their sensor network. Add app database networking only through
the [external PostgreSQL override](#use-external-postgresql).

Only for an older installation that lacks the River schema, create it as follows.
Do not run this against a DB where it already exists.

```sh
dc stop collector
dc exec -T postgres psql -U postgres -d cheesetrap -v ON_ERROR_STOP=1 <<'SQL'
BEGIN;
CREATE SCHEMA cheesetrap_river AUTHORIZATION cheesetrap_migration;
REVOKE ALL ON SCHEMA cheesetrap_river FROM PUBLIC;
COMMIT;
SQL
dc build api
dc run --rm migrate
```

Resolve migration errors before starting the worker. Replace the old collector
image so new events receive an ingestion time at or after the end of already
sealed report windows, even if the DB clock moves backward. This prevents new
events from entering a sealed window. Refresh the manifest under the log
replacement contract below, run `dc up -d --force-recreate collector`, then start
the worker. Preserve volumes and never grant general runtime accounts database-wide
schema creation privileges.

For API clients and versioned mutations, see the [review API contract](../../CONTRIBUTING.md#review-api-contract).

## Operate drafts only

Review report content, immutable revisions, copied evidence, and registry contacts.
Contact selection and refresh can create revisions. Rejection preserves records.
Use drafts in an external tool for email. Do not use SMTP secrets, overlays, test
addresses, or automatic approval and sending settings. Legacy delivery reports
appear read-only as `archived`. See the [decision and data policy](../decisions/0003-report-drafts-only.md).

## Restart and replace logs

Collector recovery uses DB file generations, checkpoints, and one ownership lease.
Never use copytruncate. Raw JSONL lives in `logs/cowrie/cowrie.json` and
`logs/web/events.jsonl`, not container stdout. Docker stdout has a separate 5 MiB
limit with two files. It does not replace [raw and DB retention](retention.md).
Monitor disk space, archive counts, collection gaps, and stalled protected evidence.

Cowrie rotates daily to `cowrie.json.YYYY-MM-DD`, adding `_N` on collisions.
For web logs, stop the engine, rename to an unused `events.jsonl.N`, and write to
a new inode. Do not overwrite `.1`, copy and unlink the source inode, or move files
to another sensor's path. Preserve earlier raw files after tests.

Before every collector start or restart, refresh the explicit manifest
`archive_paths`. The collector never guesses globs dynamically. It uses
`restart: no` and does not restart after process exit or host reboot. Refresh before
`dc start collector` so daily Cowrie rotation does not leave a stale archive list.
The refresh atomically replaces the manifest in its configuration directory while
preserving UUIDs, public mappings, and test status.

```sh
sudo -n python3 scripts/install-prepare.py --refresh-sources \
  --config "$INSTALL_CONFIG" --output "$INSTALL_ROOT"
dc restart collector
```

Refresh accepts at most 64 archives per sensor and rejects symlinks, unexpected
names, and excess files. Failure preserves the old manifest without silently
dropping archives. Inspect checkpoints and preservation needs and complete explicit
archive handling. Refresh does not delete logs, clear gaps, or ignore unread bytes.

For controlled web rotation, use a new number if `.1` exists. Confirm the stopped
engine no longer writes the old file. After rename, exclusively create an empty
active file with the engine UID/GID and mode 0644, then refresh and start collector.
Use the same procedure with UID/GID 999 for manual Cowrie replacement.

```sh
dc stop web collector
sudo -n test ! -e "$INSTALL_ROOT/logs/web/events.jsonl.1"
sudo -n mv "$INSTALL_ROOT/logs/web/events.jsonl" "$INSTALL_ROOT/logs/web/events.jsonl.1"
sudo -n python3 - "$INSTALL_ROOT/logs/web/events.jsonl" <<'PYLOG'
import os
import sys
from pathlib import Path
path = Path(sys.argv[1])
with path.open('x'):
    pass
path.chmod(0o644)
os.chown(path, 65534, 65534)
PYLOG
sudo -n python3 scripts/install-prepare.py --refresh-sources \
  --config "$INSTALL_CONFIG" --output "$INSTALL_ROOT"
dc start web collector
```

After resumption, send authorized input and compare event counts, checkpoints,
and generations. Verify that the DB checkpoint reaches the final complete
JSONL line in the renamed file, with no duplicate or missing events.
If raw files were lost or overwritten, preserve the dated collection-gap history.
Sensor state describes current health and returns to active after a successful
commit without a pending gap. Drafts are held for collection gaps when an evidence
sensor's incident overlaps the report window. An empty UI does not prove there
were no past observations.

### Resume after reboot

API, collector, sensors, and the optional worker all use `restart: "no"`.
Only the DB restarts automatically. Record running services and worker use before
an interruption. Define this helper from the same deployment revision's repository
root and keep subsequent blocks in the same shell. Use recorded deployment paths.
Set `RAW_TIMER` to the exact timer unit you registered under [raw retention](retention.md#raw-jsonl),
or leave it empty if none is registered. Step 1 records whether it was active.
The recovery steps run in subshells so failure leaves the SSH shell open.
Stop on a failed block and investigate before proceeding, except for the guard
recovery described in step 2.

```sh
INSTALL_CONFIG=/absolute/path/to/install-config.yaml
INSTALL_ROOT=/absolute/install/root
RAW_TIMER=
rdc() {
  sudo -n env INSTALL_ROOT="$INSTALL_ROOT" docker compose \
    --env-file "$INSTALL_ROOT/compose.env" -f deploy/compose.yaml "$@"
}

rdc --profile worker ps -a
```

1. Keep the existing SSH session and verify a new connection in another terminal.
   Check Docker and the DB, then stop the actual raw-retention timer. The resume
   list below is an example. Keep only previously running services and include
   `worker` if the deployment used it.

```sh
RESUME_SERVICES='api collector cowrie web worker'
RAW_TIMER_WAS_ACTIVE=no
if [ -n "$RAW_TIMER" ] && sudo -n systemctl is-active --quiet "$RAW_TIMER"; then
  RAW_TIMER_WAS_ACTIVE=yes
fi
(
set -eu
if [ -n "$RAW_TIMER" ]; then
  sudo -n systemctl stop "$RAW_TIMER"
fi
rdc --profile worker stop api collector cowrie web worker
sudo -n python3 scripts/install-firewall.py check \
  --config "$INSTALL_CONFIG" --output "$INSTALL_ROOT"
)
```

2. If `check` succeeds, keep the guard and continue to step 3. Otherwise investigate
   without resuming. Do not overwrite a config, snapshot, or rule mismatch by
   reapplying. Use the next block only after confirming that reboot removed both
   owned tables. `apply` requires empty sensor and API network `Containers` lists.
   Stopping is insufficient if containers remain attached. Remove only this
   installation's stopped API and sensor containers. If other containers remain,
   investigate while stopped. Preserve DB volumes, raw files, secrets, and sensor network.

```sh
(
set -eu
rdc rm -f api cowrie web
sudo -n python3 scripts/install-firewall.py apply \
  --config "$INSTALL_CONFIG" --output "$INSTALL_ROOT"
sudo -n python3 scripts/install-firewall.py check \
  --config "$INSTALL_CONFIG" --output "$INSTALL_ROOT"
)
```

Never bypass failure with network disconnect or a global nftables flush. Investigate
remaining owned tables and use the removal procedure below without touching other services.

3. Confirm the DB is running and healthy and the same-version migration already
   succeeded. For a new version, use the [upgrade guide](upgrade.md). Refresh the
   manifest and check the guard before resuming recorded services. `--no-deps`
   avoids starting unrecorded apps and does not replace DB or migration prerequisites.
   Keep the worker profile and explicitly start the worker. Word splitting below
   is limited to fixed service names.

```sh
(
set -eu
sudo -n python3 scripts/install-prepare.py --refresh-sources \
  --config "$INSTALL_CONFIG" --output "$INSTALL_ROOT"
sudo -n python3 scripts/install-firewall.py check \
  --config "$INSTALL_CONFIG" --output "$INSTALL_ROOT"
for service in $RESUME_SERVICES; do
  case "$service" in api|collector|cowrie|web|worker) ;; *) exit 1 ;; esac
done
for service in $RESUME_SERVICES; do
  rdc --profile worker up -d --no-deps "$service"
done
rdc --profile worker ps -a
rdc --profile worker logs --tail=50 api collector worker cowrie web
)
```

Check API readiness and login, authorized sensor input, raw-to-event and checkpoint
progress, and worker queues and detection. Preserve earlier unknown outcomes and
gaps. Restart the raw-retention timer only if step 1 found it active. Leave an
absent or previously inactive timer stopped.

```sh
if [ "$RAW_TIMER_WAS_ACTIVE" = yes ]; then
  sudo -n systemctl start "$RAW_TIMER"
fi
```

## Recover and remove

Keep the current management connection open. Check a new SSH connection and
existing services. Never add `--volumes` to `down` when preserving DB data and raw logs.

```sh
dc down
sudo -n python3 scripts/install-firewall.py remove \
  --config "$INSTALL_CONFIG" --output "$INSTALL_ROOT"
sudo -n docker network rm cheesetrap-example-sensor
```

Removal requires empty sensor and API publishing networks and deletes only the
two tables with exact ownership comments. Other chains, tables, and routes stay
untouched. Never run sensors after removing their guard. A retry checks and removes
remaining owned tables. Separately verify new SSH access, existing containers,
ports and rules, and removal of this installation's containers, bridges, and tables.

For isolated installation regression tests, see the [contributor checks](../../CONTRIBUTING.md#automated-installation-checks).

## Review observations and reports

Log in through management SSH. The overview shows collection and detection status.
Filter events by source IP, service, type, test status, and ingestion time.
Distinguish observed and ingested times. IP details link saved registry information,
detections, and reports. Reloading a screen does not trigger an external registry lookup.

Filter reports by source IP and status. Review content, copied evidence, rules,
quality, and hold reasons. Select a contact, reject the current draft, or request
a refresh. Refresh acceptance and completion are separate states and require a
worker. Old revisions are read-only. On 409, reload and review current content.
For an unknown request outcome, retry identical content with the same idempotency key.

Settings cover the reply address, aggregation time zone and frequency, repeat-rule
thresholds, and retention. Check the settings version, effective ingestion sequence,
and current and pending schedules. Aggregation schedules define evidence windows,
not email transmission times. A settings change alone never rewrites existing
report copies. On a version conflict, reload settings and enter the change again.

## Resource limits and capacity

Container limits come from [Compose](../../deploy/compose.yaml). PostgreSQL settings
are defaults of the pinned PostgreSQL image. They are not minimum host sizes or
throughput guarantees.

| Component | Memory limit | CPU limit | Other defaults |
| --- | --- | --- | --- |
| PostgreSQL | 1 GiB | 1 | `shared_buffers=128MB`, `work_mem=4MB`, `maintenance_work_mem=64MB`, `max_connections=100` |
| Each Go role | 256 MiB | 1 | DB pool maximum 4, `GOMEMLIMIT=192MiB` |
| Each sensor | 256 MiB | 0.5 | 128 PIDs |

The five Go roles are `api`, `collector`, `worker`, `migrate`, and `admin`.
Their memory setting is a Go soft GC budget, not a process-wide hard cap.
GOGC retains its default. PostgreSQL and sensors do not use this budget.
The CLI and image do not embed it. Set an appropriate budget for custom containers.
The sum of container limits does not reserve host CPU or memory.

Evidence chunks contain at most 128 events. Raw retention defaults to seven days
and 1 GiB per sensor. Events default to 30 days, terminal report history to 180
days, and completed jobs to seven days. Web auxiliary logs rotate at 5 MiB with
one backup, separately from evidence JSONL. See [retention and capacity](retention.md).

`minimum_free_gib=10` checks free space before installation. It does not certify a
host size or retention capacity. Protected, uncopied, and unresolved data can
outlive its retention period. Plan for real input, report sizes, revisions, WAL,
backups, and restore space. Past finite load runs are not operating guarantees.
Observe OOM, PSI, reclaim, queues, and detection lag together. Memory-limit contact
alone does not establish a failure. Performance on other host sizes, architectures,
source distributions, and internet routes requires separate verification.

For existing deployments, use the [upgrade guide](upgrade.md), a maintenance window,
backup, and isolated restore. Recreate PostgreSQL to apply changed memory limits.
Existing web configuration is not overwritten. Stop the engine before applying
[auxiliary-log settings](retention.md#auxiliary-logs-and-capacity-planning).
Preserve DB volumes, raw files, UUIDs, and secrets.
