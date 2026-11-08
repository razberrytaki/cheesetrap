# Requirements and reference deployments

## Requirements

| Component | Requirement |
| --- | --- |
| Host OS | Linux with host firewall access |
| Container runtime | Docker Engine 28 or later and the Docker Compose plugin |
| Docker firewall | iptables backend. Native Docker nftables backend, direct routing, and disabled firewall support are unsupported. |
| Host guard | nftables `inet` and `bridge` filtering. Compose network separation alone does not enforce isolation. |
| Sensor network | Public IPv4. IPv6 sensors are unsupported. |
| Installation tools | Python 3, iptables, OpenSSL, sudo with non-interactive authorization, and management SSH access |

These requirements are independent of a cloud provider. Container resource limits
and the installer's free-space check are not minimum host specifications.
The [installation guide](install.md) defines the guard, secrets, and startup order.
The [retention guide](retention.md) defines capacity planning and protected data.

## Tested environments

| OS and architecture | Docker backend | Meaning |
| --- | --- | --- |
| Ubuntu 24.04, native ARM64 | iptables | Recorded reference environment. No minimum-size or general throughput guarantee. |

## Network load balancer example

This reference uses an Oracle Cloud Network Load Balancer in front of an ARM64
host. Provider identifiers and address allocation are example-specific, not
installation requirements. Use [the NLB config](../../deploy/config.nlb.example.yaml)
when external ports differ from host-published ports. `public_ip` is the NLB's
public IPv4. `sensor_ports` are the host-published ports. Optional `load_balancer`
requires all three fields together. Omitting it preserves the existing guard behavior.

| Field | Meaning |
| --- | --- |
| `backend_ip` | RFC1918 private IPv4 for sensor publication. It must not overlap the sensor Docker subnet. |
| `public_ports` | External SSH, HTTP, and HTTPS ports recorded as evidence destinations. |
| `health_check_cidrs` | Provider-verified health-check source IPv4 `/32` entries. At most eight. Duplicates and broader CIDRs are rejected. Start empty if addresses are not yet known. |

The example maps NLB ports `22/80/443` to a secondary host private IP on
`2222/18080/18443`, then to sensor ports `2222/8080/8443`. Decoy SSH never uses
host port 22 here, so management SSH can stay on host port 22. Reach it through your
management SSH path, for example a VPN.
The NLB uses TCP listeners with **Preserve source IP** enabled,
source/destination preservation disabled, and PROXY protocol disabled.
HTTPS stays TCP so the sensor terminates TLS. The backend uses the host's private-IP
identifier. Confirm permissions, provider support, and source preservation in the target
environment. See the [Oracle backend API](https://docs.oracle.com/en-us/iaas/tools/python/latest/api/network_load_balancer/models/oci.network_load_balancer.models.CreateBackendDetails.html).

The secondary private IP has no public IP. Provider allocation, OS address
registration, and boot persistence are outside the installer. The guard rejects
sensor-port traffic to other local host addresses. API, DB, management SSH, and
sensor egress boundaries remain. This destination restriction also affects any
existing deployment using the same port on another address. Check before handing
over ports.

With source preservation, backend rules allow original client CIDRs rather than
the NLB address. Initially restrict both NLB and backend network security groups
to the test client's `/32`. On the backend, allow verified NLB private health-check
IPs as `/32` entries only on required sensor ports. A public NLB uses its private
IP for health checks. See the [Oracle description](https://docs.oracle.com/en-us/iaas/Content/ContEng/Tasks/contengconfiguringloadbalancersnetworkloadbalancers-subtopic.htm).
Compare successful checks with sensor connection records to verify the source.
The `single_client` host guard applies these same exceptions. Inspect any separate
live or persistent host rules left by earlier deployments. The installer does
not alter existing chains or provider rules. Changes to health-check addresses
require the same stop and guard reapplication procedure as other policy changes.

Start health checks with payload-free TCP connections. They prove a listener is
open, not valid SSH, HTTP, or TLS input. Cowrie can log these connections. SSH
repeat detection counts failed logins, but retention must include health-check
raw-log growth. Test the VIP from a separate authorized client, not the backend itself.

Before production use, verify external destination IP and ports, original source
IP preservation, blocked direct access through the host's public IP, and sensor
isolation. Verify a new connection through your management SSH path, for example
a VPN. Preserve test identities and raw files. Prepare production with new UUIDs. Retention, backup, and monitoring gates
apply with or without an NLB.
