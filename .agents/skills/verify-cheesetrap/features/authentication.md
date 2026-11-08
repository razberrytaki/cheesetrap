# Authentication

Administrators sign in before reading evidence and can end their session through the account menu.

## Sub-features

- `auth-login` reaches the authenticated administration UI.
- `auth-session` survives a reload over the owned HTTPS proxy.
- `auth-logout` revokes the session and returns to login.
- `auth-expiry` returns to login when a protected operation loses its session.

## Open the feature

- Open `/` or a protected page such as `/reports` while signed out.
- Open the account menu and choose **Log out**.

## Driving it with Playwright

UI label descriptions below are translated into English. The linked specs contain
the exact Korean accessible names. Unicode escapes in code preserve those names.

Preconditions:

- Run the launch command from `../SKILL.md`. The fixture supplies a fresh account.

- **Login.** In `web/e2e/review.spec.ts`, `page.goto('/')` shows **Administrator login**.
  Fill `page.getByLabel('\uad00\ub9ac\uc790 \uc774\ub984')` with `review-admin` and
  `page.getByLabel('\ube44\ubc00\ubc88\ud638', { exact: true })` with the fixture password.
  Click `page.getByRole('button', { name: '\ub85c\uadf8\uc778', exact: true })`.
  Require **account menu for review-admin**. Run the skill's read-only instance check here.
- **Protected entry.** `web/e2e/draft-only.spec.ts` starts at `/reports` and
  performs the same login. Preserve this entry point when editing the journey.
- **Session and logout.** Run the existing `web/e2e-https` suite through the same
  runner. Its `admin` account survives `page.reload()`. Click its account menu,
  then **Log out**. Require the login heading, GET `/api/v1/auth/me` returning 401,
  and removal of the session cookie.
- **Expiry.** The draft-only spec clears only its browser context's cookies before
  **Refresh report status**. Require the administrator-name field to reappear.

## Limits

- HTTP and HTTPS fixtures use different accounts and origins.
- Cookie removal simulates expiry. It does not prove elapsed-time expiry.
- HTTPS cookie assertions cover Secure, HttpOnly, SameSite Strict, and `/api/v1`.
- Never capture the password or cookie values. A login screenshot precedes credentials.
