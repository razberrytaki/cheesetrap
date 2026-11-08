# cheesetrap product contract

## Product scope

cheesetrap collects SSH, HTTP, and HTTPS decoy input on public IPv4 and supports
review of attack evidence and report drafts. A Go binary embeds the React
administration UI. It sends no email. Operators use reviewed drafts in external tools.

The product records observed source IPs and behavior from those IPs. It does not
identify a person. Drafts preserve network abuse contact provenance and lookup time.

## Supported environment and security boundary

- Public IPv4 on Linux with the Docker iptables backend. IPv6 sensors are unsupported.
- Management API and UI use loopback and SSH tunnels by default. Explicit HTTPS proxies retain exact Host and Origin checks, authentication, and CSRF.
- Host guards block sensor access to DB, API, management SSH, metadata, and new external connections.
- Attacker input is data. Credentials are masked and raw-data permissions remain separate.
- Production load, compromise isolation, and recovery require separately authorized verification environments.

## Operator workflow

1. Use the [installation procedure](operations/install.md) to prepare engines,
   secrets, and sensor identities. Choose the default test-client `/32` or an
   explicit production ingress policy and verify the host guard.
2. Collect events and inspect observation and ingestion times, gaps, quality,
   and detection evidence.
3. Generate drafts per IP when aggregation windows end. Time zone and frequency
   define evidence windows. Preserve late-arrival and unique-evidence attribution rules.
4. Review content, copied evidence, rules, and contact sources. Contact selection
   or refresh adds immutable revisions. Earlier revisions remain read-only.
5. Reject unwanted drafts. Use needed content and contacts in an external tool.

## Administration UI

| Screen | Behavior |
| --- | --- |
| Overview | Pending drafts, collection state, storage, and processing progress |
| Events | Time, service, IP, and detection filters, raw masking, and evidence |
| IP details | Event detections, registry contacts, and related drafts |
| Reports | Draft list, content, evidence, revisions, contact selection and refresh, and rejection |
| Settings | Reply-To, aggregation frequency and time zone, detection thresholds, and retention |

## Draft domain

`ReportDraft` exposes report ID, current revision ID and version, source IP, subject
and body, contacts, evidence count, and rule count. Review states are `held`,
`needs_review`, and `rejected`. Legacy delivery reports appear as read-only `archived`.

Revisions preserve content hashes and copied evidence. Failed or expired contact
lookups, ambiguous candidates, and incomplete or old evidence appear as hold reasons.
Review them before external communication. Reply-To is draft contact information,
not an SMTP account or permission to send.

## Excluded features

There is no SMTP setup or connection test, manual send or approval, automatic
approval, delivery scheduling, delivery limits, retries, delivery-history UI or API,
automatic report submission, or public mail relay. There is no separate outbox or
transport compatibility layer.

## Retention and upgrades

Defaults are seven days and 1 GiB per sensor for raw logs, 30 days for events and
eligible detections, 180 days for terminal report history, and seven days for
completed jobs. The [retention guide](operations/retention.md) defines protection,
80% storage warnings, and 90% guards.

Existing migrations, delivery records, and secrets remain. Legacy fields preserve
old revision hashes and safe forward upgrades. The current binary neither consumes
nor recreates old delivery jobs. Stop all old processes before upgrading. An old
worker running alongside the new binary can send legacy jobs.

[ADR 0003](decisions/0003-report-drafts-only.md) records the product decision and
alternatives. Historical plans and verification records apply only to their revisions.

## Completion criteria

- Collection, detection, and aggregation connect to draft creation and authenticated UI review.
- Contact selection, refresh, and rejection preserve revisions and audit records.
- Sending APIs and settings are rejected. Legacy queues cannot start delivery through this binary.
- Backup and isolated restore preserve evidence, immutable revisions, and hashes.
- Real Linux boundary and load results remain separate from local automated tests.
