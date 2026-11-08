# Settings

Administrators configure retention, draft aggregation timing, reply contact, and detection rules.

## Sub-features

- `settings-entry` follows the **Settings** navigation link.
- `settings-save` persists event retention and Reply-To across reload.
- `settings-no-send` omits sending controls and rejects removed settings.
- `settings-layout` shows current and pending draft aggregation schedules.

## Driving it with Playwright

UI label descriptions below are translated into English. The linked specs contain
the exact Korean accessible names. Unicode escapes in code preserve those names.

Run the owned E2E command in [the canonical skill](../SKILL.md).
`web/e2e/draft-only.spec.ts` follows **Settings** from a report detail.
Require `Reply-To`, no automatic-approval checkbox, no sending-limit group,
and no SMTP button. Read the real settings API and require no sending fields.
PATCH requests with `automatic_mode` or `delivery_limits` must return 422.
The removed SMTP-test endpoint must return 404.

Fill **Event and detection retention in days** with `45` and `Reply-To` with the synthetic fixture
contact. Click **Save settings** and require the saved status. Reload and assert both
values. The Go fixture independently checks the persisted settings document.
The settings screenshot records this reloaded state.

`web/e2e/review.spec.ts` checks current and pending schedule layout. Its empty
pending-schedule response interception is synthetic layout evidence.

## Limits

The browser does not change aggregation timing, rule thresholds, or the other
retention fields. Unit and integration tests cover version conflicts and retry
recovery. Do not claim those cases as browser journeys. No SMTP configuration or
network send belongs in this verification.
