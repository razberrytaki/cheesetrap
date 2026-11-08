# cheesetrap

Self-hosted SSH, HTTP, and HTTPS decoys for public IPv4 servers. cheesetrap collects
attacker input and helps operators review evidence and abuse report drafts.
Cowrie and a patched OpenCanary provide the sensors. A Go backend and PostgreSQL
handle collection, detection, evidence retention, and draft review. The React
administration UI is embedded in the Go binary.

[Install cheesetrap](docs/operations/install.md) · [Contribute](CONTRIBUTING.md) · [Documentation](docs/README.md)

## Requirements

| Component | Requirement |
| --- | --- |
| Host | Linux with public IPv4. IPv6 sensors are unsupported. |
| Containers | Docker Engine 28 or later, the Compose plugin, and the iptables backend. |
| Isolation | Host nftables with `inet` and `bridge` filtering. Compose alone is insufficient. |

Follow the [installation guide](docs/operations/install.md) to preserve management
SSH access, prepare secrets and sensor identities, apply the host guard
that blocks sensor traffic with nftables rules, and create an administrator.
Start with one trusted test client IPv4 `/32`. Public sensor access requires an
explicit production ingress policy.

## Security boundary

The UI and API publish on loopback by default. Connect through an SSH tunnel or
an explicitly configured [HTTPS management proxy](docs/operations/https-access.md).
The host guard blocks sensors from the database, API, management SSH, metadata,
and new outbound connections. Containers do not provide VM isolation.

The UI offers an overview, event search, IP details, report drafts, and settings.
Review evidence, contact sources, and immutable revisions before using a draft
in an external tool. cheesetrap does not send email. It has no SMTP setup,
send actions, approval, scheduling, delivery retry, or delivery history UI.

## Tested environments

| Host | Scope |
| --- | --- |
| Ubuntu 24.04, native ARM64, Docker iptables backend | Reference environment. These are not minimum specifications or throughput guarantees. |

See [reference deployments](docs/operations/reference-deployments.md) for the
load-balancer example. Size storage for your input and review backlog with the
[retention guide](docs/operations/retention.md). A CI pass does not establish host
network isolation or production capacity.

## Operations and design

- [Build from pinned source and tools](docs/operations/release.md).
- [Back up and test an isolated restore](docs/operations/backup-restore.md).
- [Upgrade and recover from failure](docs/operations/upgrade.md).
- [Understand evidence storage](docs/decisions/0002-streamed-evidence.md) and the [draft-only decision](docs/decisions/0003-report-drafts-only.md).
- [Report a vulnerability and review security boundaries](SECURITY.md).

The source release includes original project code under [MIT](LICENSE) and
third-party material under its original licenses. Published container images,
binaries, and hosted services are outside this release's scope. Source builds
still carry third-party obligations. Read the [third-party notices](THIRD_PARTY_NOTICES.md),
including Cowrie's vendored JA4+ code under FoxIO 1.1. The project's MIT license
does not relicense the sensor images.
