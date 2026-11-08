# Third-party notices

cheesetrap's original code is MIT licensed. This does not change the licenses of
engines, patches based on upstream files, bundled libraries, container operating
systems or other third-party material.

[The notice inventory](third_party/notices.json) records versions, source URLs,
paths and SHA-256 hashes. [License texts](third_party/licenses/) are copied from
the selected sources without rewriting copyright notices. The application image
contains this file, project LICENSE and the inventory/texts under
`/usr/share/doc/cheesetrap`. Keep that directory with binary/image distributions.

## Engines and local changes

- Cowrie 3.1.2: pinned source `56b2abb3b02fcb53980334f77daa0fe570f5e4be`,
  [upstream](https://github.com/cowrie/cowrie/tree/56b2abb3b02fcb53980334f77daa0fe570f5e4be).
  Its general license is BSD-3-Clause. The modified
  `sensors/cowrie/commands.py` preserves the original copyright/SPDX
  attribution and restricts imports to emulated base commands. Its accompanying
  [BSD notice](sensors/cowrie/LICENSE-BSD-3-Clause.txt) still applies.
- Cowrie also includes vendored JA4+ code (`src/cowrie/vendor/ja4`, including
  `ja4ssh.py` and `ja4x.py`) under **FoxIO License 1.1**. Its
  [preserved terms](third_party/licenses/engines/cowrie-FoxIO-1.1.txt) include
  non-commercial use/distribution conditions and commercial licensing provisions.
  Do not describe the complete Cowrie image as solely BSD/MIT or assume the
  project MIT grant authorizes every use or redistribution of that image.
- OpenCanary 0.9.10: pinned source `fb12e4fefbdb1b9acd1e5561a2614f827ab639ff`,
  [upstream](https://github.com/thinkst/opencanary/tree/fb12e4fefbdb1b9acd1e5561a2614f827ab639ff),
  BSD-3-Clause, Copyright (c) 2018 Thinkst Applied Research. The local HTTP/HTTPS
  request-evidence patch lives in `sensors/web/patches/request-evidence.patch`;
  `apply_patch.py` checks expected upstream hashes before applying it. The original
  [license](third_party/licenses/engines/opencanary-LICENSE.txt) is retained.
  `request_evidence.py` is cheesetrap's added evidence module. The image retains
  the upstream Python/Twisted distribution and its dependency notices.

`sensors/images.lock` records engine source revisions, image digests and
patch hashes; `deploy/images.lock.json` records all operational base images.
These references freeze inputs, not grant extra license rights.

## Application dependencies

The notice inventory includes the Go application runtime module closure selected
by `go list -deps ./cmd/cheesetrap`: Huma, chi, pgx and supporting jackc modules,
goose, River and its driver/shared modules, interpolate, go-retry, tidwall JSON
libraries, multierr and golang.org/x libraries. It includes their actual license
and patent files, plus the Go runtime license. Exact selected versions
are in the inventory and `go.mod`/`go.sum`; notices must be refreshed when those
inputs change.

The UI includes React 19.3.1, React DOM 19.3.1 and scheduler 0.28.0 (MIT).
Their original Meta copyright notices and full licenses are bundled. Vite 8.3.4
also injects a modulepreload polyfill into the delivered JavaScript; although Vite
is declared as a devDependency, this helper is runtime code. Its complete
[upstream LICENSE.md](third_party/licenses/npm/vite-LICENSE.md), including the
Vite MIT grant and bundled-dependency notices, is retained in the inventory.
Tooling such as sqlc, TypeScript, Orval, Vitest and Playwright is used
during generation/build/tests. npm's full locked dependency graph includes upstream
license declarations; do not ship `node_modules` or tool caches as if they were
covered only by this runtime inventory.

The integration runner uses Testcontainers for Go v0.44.0 (MIT) and the Moby Docker
client. These are development tools and are not linked into the cheesetrap
application binary. Their pinned module versions and checksums are in
`go.mod`/`go.sum`; their license texts are included in the notice inventory.

Testcontainers' transitive `github.com/moby/go-archive` is pinned to v0.3.0 to
include the fix for [GO-2026-6253](https://pkg.go.dev/vuln/GO-2026-6253).

## Container and redistribution scope

Debian, PostgreSQL, Node/Go build images, Cowrie and OpenCanary contain further
OS/Python packages with their own licenses. Preserve their included metadata
(e.g. `/usr/share/doc/*/copyright`, Python `*.dist-info`/licenses) and upstream
source availability obligations when redistributing those images. The app's CA
bundle is copied from the pinned Go builder along with its Debian
`ca-certificates` copyright file; the runtime Debian image's package notices are
retained. This inventory is not a complete container SBOM or a blanket approval
to redistribute every upstream image. The local release process builds images;
it does not publish or relicense third-party images.
