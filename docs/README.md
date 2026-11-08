# cheesetrap documentation

Choose the document by its purpose and verified revision. Historical records do
not establish current behavior. This repository contains the executable
operational procedures and their source.

## Start by task

| Task | Documents |
| --- | --- |
| Install | [Linux installation](operations/install.md), [requirements and reference deployments](operations/reference-deployments.md) |
| Develop and verify | [Contributing and TDD](../CONTRIBUTING.md), [scoped instructions](../AGENTS.md), [generated API contract](../api/openapi.json) |
| Understand the product | [Product contract](cheesetrap-product-plan.md), [engine selection](decisions/0001-honeypot-engines.md), [evidence storage and contact trust](decisions/0002-streamed-evidence.md), [draft-only decision](decisions/0003-report-drafts-only.md) |
| Change the UI | [App design and tokens](design-kit.md), [frontend instructions](../web/AGENTS.md) |
| Prepare a release | [Release procedure](operations/release.md), [security boundary](../SECURITY.md) |

## Operate cheesetrap

| Task | Guide |
| --- | --- |
| Preserve management SSH, configure sensor ingress, and review drafts | [Install](operations/install.md) |
| Configure an HTTPS management URL, Tailscale Serve, or another proxy | [HTTPS access](operations/https-access.md) |
| Plan capacity and observe failures | [Retention](operations/retention.md) |
| Preserve drafts and evidence in an isolated restore | [Backup and restore](operations/backup-restore.md) |
| Upgrade and recover from failure | [Upgrade](operations/upgrade.md) |
| Reproduce generated code, binaries, and images with pinned tools | [Release](operations/release.md) |
