# Event and IP investigation

Administrators filter collected events, inspect safe evidence, and follow source IPs to their detections.

## Sub-features

- `events-filter` preserves the chosen event type during refresh.
- `events-details` shows hostile input as text and hides private content.
- `events-empty` distinguishes an empty result from a loading state.
- `ip-investigation` links an event source to detections and reports.
- `collection-status` exposes the sensor comparison table to keyboard users.

## Open the feature

- Choose the **Events** navigation link to reach `/events`.
- Select the source-IP link in the event table to reach `/ips/1.1.1.1` in this fixture.
- Use **Collection status details** from the overview or events page for collection status.

## Driving it with Playwright

UI label descriptions below are translated into English. The linked specs contain
the exact Korean accessible names. Unicode escapes in code preserve those names.

Preconditions:

- The authenticated review fixture contains `cowrie.login.failed`, `web.request`,
  and a report for its synthetic source IP. Use `web/e2e/review.spec.ts`.

- **Filter.** Click `page.getByRole('link', { name: '\uc774\ubca4\ud2b8', exact: true })`.
  Select label **SSH failed login** in combobox **Event type**. Click **Apply filters**.
  Require `event_type=cowrie.login.failed` in the URL and matching table rows.
  Click **Refresh events** and require the same selection and URL.
- **Evidence result.** Select `evidence` in **Detection result** and apply. Require
  `detection_result=evidence` in the URL and **Included as detection evidence** in the first row.
- **Empty result.** Select `pending` in `page.getByLabel('\ud310\uc815 \uacb0\uacfc')` and apply.
  Require heading **No events match the filters.**. Click **Reset** to restore events.
- **Detail.** In the row containing `web.request`, click **View details**. The
  **Event details** complementary region shows the hostile HTML string in `pre`.
  Require no actual `img[src="x"]` node and no private canary in the body.
  Click **Collapse details** and require the region to disappear.
- **IP.** Click the first link named `1.1.1.1`. Require heading **IP details** and
  `SSH-REPEAT`. In the later intercepted ten-row case, focus the first
  **View details** button in **IP detection list** and press Enter. Require the detection
  detail heading and keyboard access to its evidence; closing returns focus to
  the opening button. Follow **Next detection**, then go back and require the first
  detection again. The report link opens the report-review feature.
- **Status.** Focus `page.getByText('\uc218\uc9d1 \uc0c1\ud0dc \uc0c1\uc138', { exact: true })` and press
  Enter. Require table **Collection status comparison by sensor** and keyboard access to its scroll region.

## Limits

- `1.1.1.1` is fixture data, not an authorized external test destination.
- The later ten-row IP pagination case intercepts API responses. It proves UI
  navigation and detection disclosure only, not real backend pagination.
- Other event filters and validation, real pagination, IP shortcut links, and
  nested status/registry disclosures remain unverified by this browser journey.
- The script captures action states with `checkDesign`. Preserve the current-run
  HTML and screenshots alongside its assertions.
