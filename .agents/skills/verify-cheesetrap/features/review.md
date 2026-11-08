# Report review

Administrators inspect a generated report, resolve its recipient, and reject it with a persisted decision.

## Sub-features

- `review-entry` reaches the report list and report detail.
- `review-queue` distinguishes zero pending reviews and synthetic nonzero counts.
- `review-evidence` expands evidence without exposing private input.
- `review-recipient` persists a selected contact.
- `review-reject` persists rejection and disables duplicate rejection.
- `review-archive` filters archived drafts, opens a list row, and keeps legacy evidence read only.
- `review-no-send` rejects removed sending endpoints and exposes no sending actions.

## Open the feature

- Open `/reports` or follow the overview's **Reports awaiting review** region link.
- Follow the report link from the source IP detail.
- Open a report's `/reports/{id}` URL using the fixture-supplied ID.

## Driving it with Playwright

UI label descriptions below are translated into English. The linked specs contain
the exact Korean accessible names. Unicode escapes in code preserve those names.

Preconditions:

- Use the report identified by `CHEESETRAP_E2E_REPORT` in the owned review spec.
  It has ambiguous contacts, ten evidence buttons, and a generated SSH report.

- **Entry.** The review spec opens `/reports` and asserts heading **Report list**.
  The overview region's keyboard link reaches `/reports?state=needs_review`.
  From IP detail, click `a[href="/reports/${id}"]` with the fixture ID.
  Require heading **Report review** and the generated description in `.report-body`.
- **Queue count.** On `/overview`, require the real fixture's zero count and
  **No reports await review.**. Intercepted variants check a nonzero count and a
  count beyond JavaScript's safe integer range before the keyboard list link.
  Those variants prove rendering, not persisted queue counts.
- **Evidence.** Open the evidence `summary` matching `/^\uc99d\uac70 ·/` under
  `.review-reference > details`. Click a button matching `/^\uc774\ubca4\ud2b8 #.* \uc99d\uac70 \ubcf4\uae30$/`.
  Require its evidence-detail region. Collapse it with the corresponding control.
- **Recipient.** Require no approval or sending button.
  Select `second@example.test` in the combobox matching `/^\uc5f0\ub77d\ucc98 \ud6c4\ubcf4/` and click
  **Save recipient**. Reload and require the saved address in the report metadata.
- **Reject.** Click **Reject draft**. Require `rejected`, reload, and require the same
  state with the rejection button disabled. The Go fixture independently checks
  persisted rejected reports after Playwright returns.

- **Archived legacy draft.** The draft-only spec follows the **Reports** navigation link,
  selects `archived` in **Report status**, applies the filter, and clicks the fixture row.
  Require the read-only notice and disabled recipient selection, recipient save,
  and rejection. Reload and require the same notice and disabled rejection.
  The real API rejects reject, refresh-contact, and select-contact with 409.
  The Go fixture checks unchanged revision bytes, current revision ID, and
  evidence rows after the browser returns. The legacy attempt is synthetic data
  in the isolated DB, attached to an engine-generated draft.
- **Removed sending operations.** The draft-only spec requires no sending
  navigation or actions. Authenticated requests to approve, cancel, retry,
  close-unconfirmed, SMTP-test, and deliveries return 404. No outbound job exists
  after all browser journeys.

## Limits

- A missing seeded report or contact is a failed precondition. Do not substitute
  a production report or fabricate a successful API response.
- The delayed snapshot in the recipient-save test exercises a UI race. The save
  and subsequent reload still use the real API.
- The archived report-list row is exercised with real API data. The active
  report still enters through the IP link and direct fixture URL.
- Report-list IP filtering, list pagination, registry contact
  relookup, and historical revision selection/return remain unverified.
- Rules, registry source, revision metadata, and evidence/rules pagination are
  additional detail controls not exercised by this browser journey.

## Overview count regression

The archived fixture retains a stored `needs_review` state after a historical
attempt. The draft-only journey compares the real overview held, needs-review
and archived counts with the corresponding real report lists. This checks API
consistency. Intercepted overview layout cases remain synthetic.
