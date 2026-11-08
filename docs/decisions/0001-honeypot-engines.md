# ADR 0001: Use Cowrie and patched OpenCanary

Date 2026-10-18. Accepted. This decision selects observation engines for the Go
application's SSH, HTTP, and HTTPS sensors. Historical acceptance applies to its
recorded revision. Current operations follow the [installation guide](../operations/install.md).

## Decision

Use the restricted shell backend of Cowrie 3.1.2 for SSH and OpenCanary 0.9.10 with
Twisted 26.4.0 and request-evidence extensions for HTTP and HTTPS. Keep engines in
separate containers. The Go collector reads JSON Lines read-only and normalizes
records to common events. The product backend remains Go with a TypeScript UI.

The engine acceptance environment was Linux ARM64 with public IPv4. That evidence
does not establish AMD64 runtime or IPv6 support. Engine versions, source commits,
official image digests, and extension hashes are pinned in
[images.lock](../../sensors/images.lock).

| Role | Pinned input | Log contract |
| --- | --- | --- |
| SSH | Cowrie 3.1.2, source `56b2abb3b02fcb53980334f77daa0fe570f5e4be` | `var/log/cowrie/cowrie.json`, connection, authentication, session, and command JSONL |
| HTTP and HTTPS | OpenCanary 0.9.10, source `fb12e4fefbdb1b9acd1e5561a2614f827ab639ff`, Twisted 26.4.0 | Extended `/var/tmp/events.jsonl`, socket peer, method, URI, headers, body, limits, and unavailable-data reasons |
| Normalization | Go `internal/ingestion` | Schema 1, masking, quality, and trust boundaries in the [manifest](../../testdata/engines/manifest.json) |

Cowrie's official image digest is
`sha256:019726c8deef20729162cda492d9385917b579c9ace6368e47e7566cd2491ba1`.
OpenCanary's base digest is
`sha256:4e51338e3b6e349652b0604be656d9b8fc1cde2cd40409b2e956f1da3eb673a1`.
The historically tested derived ARM64 web image ID was
`sha256:71f370e058f7fdf7f9773a8b05aa76ec73c735d881a294998ffa56cc27a0b965`.
That local image ID is not a public registry manifest digest.

## Rationale and alternatives

Cowrie preserved connection, failed authentication, emulated-command sessions, and
original peers in public SSH acceptance. Restricted download, SFTP, forwarding,
and proxy configuration defined the initial defaults. The command registry loads
only the verified `base` commands. New emulated commands require fresh network
and file-handling verification.

Unmodified OpenCanary lacked evidence required by 38 HTTP and HTTPS cases.
Arbitrary paths, queries, bodies, malformed and interrupted requests had gaps,
and default access logs copied secret queries. Post-processing cannot recover
unrecorded data, so it was rejected.

The extension records evidence at existing Twisted parser boundaries and met the
same cases. It avoids a separate HTTP parser or new Go honeypot. Python engine
runtime and small logging extensions remain separate from the Go backend.
Further engine comparisons are unnecessary while required behavior holds.
Reconsider the choice if an update breaks it.

## Deployment, log, and collection contracts

- Sensors use a separate bridge from management and never host networking. Block new connections to DB, API, host management, metadata, callbacks, SMTP, and same-bridge peers. Allow responses to incoming connections only. Docker network declarations alone do not enforce this.
- Cowrie uses UID/GID 999 and web uses 65534, a read-only rootfs, all capabilities dropped, no-new-privileges, 0.5 CPU, 256 MiB, and 128 PIDs. A 4 MiB tmpfs over Cowrie `etc` covers its anonymous writable volume. Sensors write only log and state volumes. Never mount the Docker socket or SMTP or cloud credentials.
- Only transport fields establish the source. Verified deployment mappings supply public destinations. Request Host, Forwarded, XFF, and JSON fields cannot change trusted source or test status.
- Limits are 256 KiB per record, 16 KiB body, 8 KiB URI, and 16 KiB total headers. Raw size differs from masked string length. Record missing data, truncation, and parser limits as quality. Insufficient evidence cannot support operations that require it.
- The DB commit assigns `event_id`, `ingestion_seq`, and `ingested_at`. Engine time is `observed_at`. The collector assigns generation and byte position. Cowrie `eventid` is an event type. Raw hashes detect changes.
- Restrict permissions and retention for engine logs that can contain credentials. UI and reports use masked common events. Cowrie commands with quotes or backslashes mark masking limits and hold affected evidence, which can also exclude harmless commands.

## Rename rotation and reopen

Cowrie uses its own daily rename and reopen with `logtype=rotating`. External
active-file rename or an assumed SIGHUP reopen is not its contract. Web logging
opens and closes the file per event, so the next event recreates an externally
renamed active path. Copytruncate is excluded.

The collector tracks generations and offsets rather than filenames alone and
finishes renamed files. Date collisions, truncation, inode reuse, partial lines,
deletion before collection, interruption, and atomic DB commits need collector
verification. Logger-component acceptance alone does not prove lossless collection.
Current size and time enforcement is specified in [retention](../operations/retention.md).

## Patch and update procedure

The [Dockerfile](../../sensors/web/Dockerfile) starts from a pinned official
image. [apply_patch.py](../../sensors/web/apply_patch.py) first checks original
HTTP and HTTPS module SHA-256 values. The [constructor patch](../../sensors/web/patches/request-evidence.patch)
changes only two Site constructors. [request_evidence.py](../../sensors/web/request_evidence.py)
uses the existing parser for bounded input and suppresses duplicate raw content in
web and access logs. Other OpenCanary services stay disabled.

1. Review upstream and Twisted code, licenses, notices, and changed defaults.
   Never bypass hash failure or use fuzzy patches.
2. Record new original and patched module hashes, image ID, and build inputs.
   Distinguish local IDs from registry digests. Preserve successful fixtures until
   actual evidence exists for the new version.
3. Run Python boundary and parser tests, rotation probes, and Go masking and fixture
   checks. Repeat the same base-versus-patched input cases and public-peer isolation
   acceptance. Repeat Cowrie acceptance if its version or command scope changes.
4. Record required failures as `NO_GO` and unavailable environments as `BLOCKED`.
   Do not release a failed version. Return to the last verified version and update
   evidence provenance, samples, and this decision together.

There are no runtime automatic updates, floating `latest`, or arbitrary in-process
plugins. Separate engine distribution does not replace license review. Current
licensing and dependency obligations are in [third-party notices](../../THIRD_PARTY_NOTICES.md).
Engine acceptance alone does not authorize continuous public operation or abuse
report delivery. The current product is [draft-only](0003-report-drafts-only.md).
