# Frontend

Applies to the React and TypeScript UI and tests in `web/`. Run commands from the
repository root. The UI uses React, Vite, plain CSS, Vitest/Testing Library, and
Playwright. Install with `npm --prefix web ci` and follow `package-lock.json` and
`.nvmrc`. Use the [app design and token guide](../docs/design-kit.md).

## Screens and API boundaries

- Follow existing patterns in `src/features/`, shared UI in `src/features/shared/`, and styles in `src/styles.css`. Fit requested changes to the administration UI.
- Use `src/api/client.ts` for HTTP calls. Do not edit generated `src/api/schema.d.ts` or `src/api/generated/models.ts`. Generate Orval types with `npm --prefix web run generate:api` and check contracts with `npm --prefix web run test:api`. Run each `orval.fixtures.config.ts` project with its own `--project` invocation, as `test:api` does. For API changes, also follow [backend generation](../internal/AGENTS.md).
- Keep session cookies HttpOnly and CSRF tokens in client memory. Preserve epoch and cancellation handling so late responses cannot restore a previous session's screen.
- Distinguish loading, empty results, errors, and expired permissions. Stale queries, duplicate submissions, and report revision conflicts must not overwrite the current selection or review state.
- Render attacker input as text. Preserve raw-data masking and permissions. Never copy real evidence, addresses, or recipients into fixtures. Preserve keyboard access, accessible names, status announcements, and small-screen use.

## Verification and build

| Change | Command or check |
| --- | --- |
| Components, queries, state | `npm --prefix web run test -- --run src/features/<feature>/<name>.test.tsx` |
| Shared client or several screens | `npm --prefix web run test -- --run` |
| TypeScript or UI build | `npm --prefix web run build`, including `tsc --noEmit` |
| Browser journeys such as login, navigation, or draft review | `npm --prefix web run test:e2e` |
| Layout or CSS | Check relevant screens with synthetic data at narrow and wide widths and with the keyboard. |

Replace test-path placeholders with real files. Test user-visible outcomes and
failure states.
`package.json` has no `dev` or `lint` script. Do not document nonexistent commands.

E2E uses the runner's loopback API and test database. Do not point Playwright at an
arbitrary URL. Initial dependency and Chromium setup can require network access.
The build empties and regenerates `internal/ui/dist/`, so manual edits disappear.
The root `make build-release` connects the UI build to the Go release embed.
