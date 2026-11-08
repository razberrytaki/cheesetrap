# Cheesetrap verification map

This map covers the administration UI using the owned Playwright fixture.
Read [the launch and evidence procedure](../SKILL.md) first.

## Baseline preconditions

- Start from a fresh runner-owned DB with migrated roles and synthetic events.
- Let the Go fixture provide the origin, account password, and report IDs.
- Use one runner per checkout. Evidence and generated UI paths are shared.
- The review fixture includes ambiguous contacts, reviewable drafts, and one legacy attempt
  attached to an engine-generated draft. Missing fixtures fail their journeys.

## Driving conventions

Every entry uses `npm --prefix web run test:e2e`. The runner executes both
`web/e2e/review.spec.ts` and `web/e2e/draft-only.spec.ts`, then the HTTPS suite.
Feature files identify the relevant part of that command, not independent tests.
Selectors below use Playwright's `page` inside those existing specs.

## Proof and skip reporting

Record the feature, entry point, command, result, and evidence directory.
Check all mapped entry points when claiming full feature coverage. A successful
direct URL does not prove its navigation link. Uncovered paths remain unverified.
Report missing preconditions as failures with their cause. Never remove an
assertion, skip a journey, or substitute intercepted API data to make it pass.

## Features

- [Authentication](authentication.md) covers login, persisted sessions, logout, and expiry.
- [Event investigation](investigation.md) covers event filtering, safe details, and IP navigation.
- [Report review](review.md) covers evidence, recipient selection, and persisted rejection.
- [Settings](settings.md) covers persisted retention and reply-contact saves, schedule layout, and absence of sending controls.
