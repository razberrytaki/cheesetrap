# Backend

Applies to Go code in `internal/` and to `cmd/`, `migrations/`, `api/`, and Go tests
linked from the root instructions. Run commands from the repository root.
Do not edit `internal/ui/dist/` by hand. The frontend build generates it.

## Implementation and data contracts

The backend uses Go, chi/Huma, pgx/PostgreSQL, Goose migrations, sqlc, and River.
Find CLI commands in `cmd/`, HTTP contracts in `internal/api/`, SQL sources in
`internal/store/queries/`, and schema changes in `migrations/`.
Follow existing domain package boundaries.

- Preserve evidence IDs, hashes and counts, detection windows, late arrivals, and legacy, chunked, and mixed data semantics.
- Preserve immutable report revisions, draft-to-recipient binding, atomic commits, and retention protection. Verify changes with relevant failure and race cases.
- Write forward DB migrations. Check old data, permissions, failure recovery, and backup restore effects. Do not use Goose Down as the default production recovery path.
- Regenerate SQL and API artifacts from their sources. Update clients and tests with any field, state, or error change consumed by the frontend.

## Generation and verification

| Change | Command or check |
| --- | --- |
| SQL queries or sqlc schema | `scripts/generate-sql.sh`. Inspect generated changes in `internal/store/db/`. |
| HTTP API contract | `go run ./cmd/cheesetrap api-schema --out api/openapi.json`, then `npm --prefix web run generate:api` |
| Go logic | `go test ./internal/<package> -count=1`. Run `gofmt` on changed Go files. |
| DB, transactions, migrations | `scripts/test-integration.sh ./internal/<package>`, or `scripts/test-integration.sh ./...` across packages |
| Backend-wide changes or releases | `go test ./... -count=1`, `go vet ./...`. Use relevant `go test -race` for concurrency changes. |

Replace `<package>` with the changed package. Unit tests use local fixtures.
The integration runner owns its test database and cleans up only its resources.
Run tests with production settings (such as DB URLs) unset in the test process.
Do not edit or delete the developer's environment files. Report missing Docker or
other prerequisites instead of testing against a production database.

For behavior changes, run a failing test, implement the minimum fix, then refactor.
Use unit tests for business rules, the existing Testcontainers runner for DB
contracts, and E2E tests for user journeys. Do not create a shared DB or Compose
stack for integration tests. Red requires the intended assertion failure,
not an environment or compilation failure.

For sensor or Python runner changes, select relevant tests and run
`python3 -B scripts/test-python.py regression`. Follow the contribution guide
for separate image, network, and full automated acceptance checks.
