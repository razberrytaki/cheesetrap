# Streamed evidence and contact trust

Decision date 2026-10-27. Schemas 28 to 30.

Per-input limits and bounded caches cannot prevent memory exhaustion if a worker
reads an entire aggregation before checking its size. Detection context, report
copies, revision validation, and DB `array_agg` share this risk. The chosen design
splits storage and reads to process the complete aggregation rather than holding
large reports or discarding evidence.

## Detection

Original events remain. `processing_events` projects only detection and report
fields, without bodies, headers, or credentials. The worker reads context in
128-event batches, applies existing Go rules, and stages matches in `detection_work`.
Under the processing-cursor lock it determines the window and actual evidence set.
Results, completion, and cursor commit atomically. Staging is cleared before commit.
Failure or cancellation rolls back the whole transaction.

Observed-time windows of plus or minus ten minutes, completed lower ingestion
sequences, all equal-time events, and the earliest eligible window containing the
trigger retain their meaning. PostgreSQL sorting and window calculations can spill
to disk under `work_mem=4MB`. A chunk holds at most 128 IDs in the same ingestion
sequence bucket. References attach in one SQL statement after creation without
repeated scans of all accumulated references.

New detections use `evidence_hash_scheme=sha256-chain-v2`. For sorted UUID bytes
`u1` through `un`, each 16 bytes, the hash is:

```
S0 = SHA256(UTF8("cheesetrap:evidence:sha256-chain-v2"))
Si = SHA256(S(i-1) || ui)
hash = hex(SHA256(Sn || uint64_big_endian(n)))
```

The DB lazily validates actual membership hash, count, duplicates, and bucket width
with the same constant-size state. Existing `sha256-json-v1` hashes and legacy and
chunked representations remain intact. Reprocessing also streams the v1 hash and
compares actual ID sets without duplicating or changing prior results.

## Report revisions

There is one report per IP and reporting window. All evidence and rules go into
`report_proof_parts`. The worker seals `report_proofs` before creating a revision.
A part holds at most 32 evidence items or one rule. Copies have no foreign keys to
source events or detections.

`sha256-parts-v1` binds each part's exact UTF-8 JSON bytes and order. Its initial
state is `SHA256(UTF8("cheesetrap:report:sha256-parts-v1"))`. Each part updates it
with `SHA256(previous_state || SHA256(part_bytes))`. Sealing checks contiguous part
sequence and item positions and complete counts. The revision content digest binds
the manifest scheme, both hashes, and both counts. Runtime roles cannot modify,
delete, or append sealed parts. A new revision must exactly match a sealed manifest
for the same report.

Old revision JSON and digests never change. Legacy validation traverses saved
arrays with a cursor to compute their original digest. Editing an old revision
copies its complete evidence into new parts and hashes the new revision only.
Reading a historical single JSONB value still incurs detoast cost. New aggregations
avoid creating such large single values.

The management API reads new parts and old arrays with the same pagination and
count contract. Cleanup preserves terminal status, age, uncertain-delivery, and
reference protection. It deletes owned copies before parts, each within the
configured batch limit. Restore must include all manifests and parts. Automatic
schema downgrade is unsupported.

## Draft content and contact provenance

Service lists are bounded to 256 KiB and rule summaries to 512 KiB. Overflow is
explicitly marked as an omitted summary. Evidence excerpts retain the 50-item and
32 KiB limits, and report bodies retain the 1 MiB limit. Full evidence and rule
copies are never reduced. Legacy signed mail bodies were not shortened afterward.
The [draft-only decision](0003-report-drafts-only.md) removes SMTP execution.

WHOIS is an unauthenticated TCP source. Its contacts require operator review.
The historical automatic-delivery policy required HTTPS RDAP provenance, an abuse
role, and address-range evidence bound to the exact selected email. Another
candidate's RDAP provenance could not authorize it. Legacy WHOIS auto-approvals
were rechecked before delivery. These are historical safety rules, not a current
sender or automatic-approval capability. Contact provenance remains visible for
manual draft review.

## Resources and verification scope

Bounded memory does not guarantee unlimited throughput or disk. Large aggregations
use more DB workspace and transaction time. Detection, draft creation, contact
refresh, and historical pre-delivery inspection removed fixed River execution
limits while retaining external lookup and historical SMTP network timeouts.
Cooperative yields between events, shutdown cancellation, and storage guards remain.
Cursor and draft locks span one aggregation. Observe operational throughput and free space.

Authenticated contact changes and historical approval and retry review use request
cancellation and shutdown signals instead of the ordinary ten-second API computation
limit. Authentication still has its existing budget. CSRF, body-size, and body-read
limits remain. Response writes are bounded to 15 seconds after computation.
Part reads fetch at most 32 parts and 1 MiB total at a time. If the first part exceeds
that size, it alone is read completely. Whole-report validation never approves a
partial result. Byte budgets also bound rule descriptions containing every allowed
path length without truncating the evidence or explanations.

`TestSecurityAggregateMemory` exercises real detection, draft creation, and revision
editing in a Linux 256 MiB cgroup with about 284 MiB of synthetic bodies and headers
passed through the normalizer. It does not verify public sensors, real SMTP,
production host firewalls, or infinite-input capacity. It also stores 32 rule
explanations of about 10.68 MiB each, produced by the real normalizer and detector,
and checks edits and complete traversal. This detects regressions where row-count
limits alone read too many large parts at once.
