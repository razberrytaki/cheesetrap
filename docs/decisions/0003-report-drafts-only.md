# 0003. Prepare report drafts without sending email

Cheesetrap prepares report drafts. The operator reviews evidence, contact sources,
subject and body, and handles any communication outside Cheesetrap.

## Domain and contracts

`ReportDraft` is the management API shape. It identifies a report, its current
immutable revision, copied evidence and registry contact information. Its review
states are `held`, `needs_review`, and `rejected`. Historical sending aggregates
are read-only `archived` drafts. The same classification covers any report with
`delivery_uncertain` or a persisted delivery attempt, even when its stored state
is `held` or `needs_review`. The API refuses contact changes, refresh and exclusion
for these records. The UI asks the operator to compare external records before
manual communication. This preserves uncertainty without restoring delivery history. A refresh or contact selection appends a revision
and preserves prior revisions and evidence. Exclusion preserves the record.

Remove approval, manual send, automatic approval, delivery scheduling, retries,
SMTP tests and configuration, delivery workers and delivery history UI and API.
Keep the aggregation calendar because it defines which evidence belongs to a draft.
It is not a delivery schedule.

## Upgrade and data policy

Do not edit old migrations or delete existing records and secrets. Legacy SQL
schema, permissions and signed payload fields remain for forward upgrades and
historical digest verification. They confer no sending capability in this binary.
Existing retention functions can still remove expired terminal history under the
established policy. Restore tooling retains its conservative legacy classification
and DB hold. Neither path transmits mail. No delivery queue
is consumed or repaired, and no SMTP transport exists. Stop all old binaries
before upgrading. Running an older worker against the DB can still send mail.
Legacy queued River jobs remain stored and cannot transmit under this binary.

Hiding UI actions or adding a send-disable setting was rejected because either
keeps the sending responsibility and makes stale settings dangerous. A new
outbox, compatibility transport or destructive cleanup migration is unnecessary.
