# cheesetrap administration UI for report review

On 2026-10-28, the user chose the report-review layout from option D and the graphite and gold colors from option A.
The UI copy remains Korean. The quoted labels below retain their exact text and include English explanations.

## Purpose and behavior contract

Operators continue reviewing pending report drafts and quickly identify collection exceptions.
The first screen shows the review count and collection gaps. Preserve existing URLs,
status details, refresh behavior, authentication, and draft review flows. cheesetrap sends no email.
Distinguish 0, unavailable data, and query failures. Display large numbers as strings.

## Appearance and tokens

The app token source is `tokens/cheesetrap.json`. Use `scripts/build-console-tokens.py` to generate `tokens.css`.
Use graphite `#15171b` for the background, `#1e2127` for panels, `#d8dce3` for body text, and gold `#e6c565`.
Keep the Korean system font and apply `tabular-nums` to numbers. Make no external font or image requests.
Use a fluid 48–80px font size for the review count, 30px main headings, 16px body text, and 14px secondary text.

## Layout and components

Place the overview below the top brand and navigation. Put review actions in a wide left panel
and collection status in a list on the right. Use a single column below 60rem.
Use a gold fill only for the review link. Use text and thin borders for other navigation.
Show event browsing and held reports as a continuous list of lower-page actions.
Use dark surfaces and 1px borders for depth. Do not use decorative shadows or lighting effects.

## Resend design reference

Use the Resend reference's 8px spacing unit, 16px panel corner radius,
14px navigation font, and 1px borders instead of shadows. Do not copy its colors, branding, or paid fonts.

## States and accessibility

Display a missing review count as **"확인 불가"**, meaning "Unavailable".
Display 0 as **"검토 대기 없음"**, meaning "No pending reviews".
Show errors with a refresh action that allows a retry. Keep status text visible during initial loading.
Preserve `focus-visible`, 44px touch targets, keyboard navigation, and native `details`.
Wrap long text. Stack actions and status vertically on narrow screens.

## Motion and prohibited changes

Use only brief color and border feedback, and respect `reduced-motion`.
Do not add charts, fake trends, automatic refresh, or new APIs.

## Verification criteria

Check 0, missing, large-number, error, and warning cases. Run the full UI tests and build, and E2E tests with synthetic fixtures.
Check actual screenshots at wide and narrow widths, and verify keyboard flows.

## Event workflow and shared account menu, 2026-10-30

Place the event heading and refresh action first, followed by collection status, filters, and the list.
Use one refresh action. Keep applied filters and update both the latest first page and collection status.
Keep existing content during refresh and show progress on the button. Report each failure in the affected area
and mark its results as stale. Allow another refresh through the same button.

Identify the account by username at the top right. Put the infrequently used logout action in the account dropdown.
Close the dropdown on Esc, an outside click, or focus leaving it. Preserve existing protections for login, permission expiry, and logout.
Remove duplicate path rows and keep existing back links on detail screens.
On narrow screens, put the brand and account on the first row and the main menu on the second.

Keep the existing Resend reference's 8px spacing unit, 14px navigation font, and 1px borders.
Make the refresh scope and account access clear without new images, fonts, or decorative effects.

## Administration details and settings layout, 2026-10-30

Use a dedicated 2-column field grid for settings, with 1 column on narrow screens.
Keep apply, delete, and protection guidance near the relevant input group. Place current and scheduled schedule details beside the schedule inputs.
Use a single settings save action.

Put one overview refresh action beside the main heading. On report details, use one button beside the main heading
to read the stored report status. Lock refresh while a change request is in progress.
Do not reuse earlier confirmation checks after refresh. Remove links from a detail screen to itself.

Keep the time, type, collection sequence number, quality, and truncation warnings in the report evidence summary.
Expand details for only the selected item. Clear the selection on page changes.
Preserve raw-data masking, revision pinning, and hold reasons.

## Report review actions and feedback, 2026-10-30

Place the report body beside recipient and rejection actions on wide screens.
On narrow screens, put the action area after the body. Place evidence, rules, raw registry data, and revision history below, expandable as needed.
Keep the body, recipients, and hold reasons visible in the default view.

**"수신자로 저장"**, meaning "Save as recipient", creates a new revision and does not send a report.
Show the result in the action area with the selected address and the next review action.
**"등록기관 연락처 다시 조회"**, meaning "Look up registry contacts again", requests a background lookup.
**"신고 상태 새로고침"**, meaning "Refresh report status", reads stored results. Distinguish request acceptance from completion.

Keep the existing screen and expanded sections during saves and refreshes.
Lock changes and rejection while reading the latest status and after a query failure. Mark information as stale after a failure.
