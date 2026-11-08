# Security

The [requirements and tested environments](docs/operations/reference-deployments.md)
and [release procedure](docs/operations/release.md) define the supported scope.
There is no promised long-term security maintenance period for old tags or response
SLA. Upgrade to a pinned revision and image after verifying the fix. A pinned
digest does not establish that an image has no vulnerabilities.

## Report a vulnerability

Use [GitHub Private vulnerability reporting](https://github.com/razberrytaki/cheesetrap/security/advisories/new)
for [razberrytaki/cheesetrap](https://github.com/razberrytaki/cheesetrap).
If the form is unavailable, open an issue asking for a reporting route without
vulnerability details. No separate public security email address is designated.
Do not reproduce attacks against a production server.

Include the affected revision and image digest, impact, sanitized reproduction
steps, and expected and actual results. Keep secrets, operational addresses, raw
evidence, and report recipients out of public issues, PRs, and CI artifacts.

## Deployment boundary

- Keep the UI on `127.0.0.1:8080` by default. Use an SSH tunnel or an explicit [HTTPS management proxy](docs/operations/https-access.md). Restrict proxy access to the management network. Do not expose the API or DB directly. HTTPS retains exact Host and Origin checks, login, CSRF, and Secure cookies.
- Sensors support public IPv4 on Linux with the Docker iptables backend. IPv6 is unsupported.
- Host guards block new sensor egress and access to the DB, API, management SSH, and metadata. Neither Compose network separation nor containers provide complete isolation.
- Treat raw input as attacker-controlled data. Preserve UI masking, XSS defenses, and raw-evidence permissions. Do not mount the Docker socket, management secrets, or business keys into sensors.
- The binary has no mail sender or SMTP transport. Legacy delivery records, settings, and queues remain for compatibility but are not consumed. Stop every old worker before upgrading.

If you suspect a compromise, preserve evidence separately and stop collection and
the worker. Follow the [retention](docs/operations/retention.md),
[backup and restore](docs/operations/backup-restore.md), and
[upgrade](docs/operations/upgrade.md) procedures. Do not default to deleting the
existing DB or raw logs, or reverting state with Goose Down.
