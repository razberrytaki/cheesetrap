# Configure an HTTPS management address

The API listens on `127.0.0.1:8080` by default. The default installation uses an SSH
tunnel. You can instead use an HTTPS reverse proxy on the same host.
Tailscale Serve and other HTTPS proxies use the same app settings.

Configure certificates, DNS, the proxy, and tailnet ACLs yourself. Restrict proxy
access to a trusted management network. An HTTPS origin does not grant access.
Administrator login, sessions, CSRF, and draft mutation protections remain active.

## App and installation settings

| Setting | Default | Meaning |
| --- | --- | --- |
| `CHEESETRAP_API_LISTEN` | `127.0.0.1:8080` | Internal HTTP listener. An HTTPS origin does not change it. |
| `CHEESETRAP_API_ORIGIN` | `http://` plus the listener address when omitted | One exact browser origin, including scheme, host, and optional port. |
| Installation `api_origin` | `http://127.0.0.1:8080` | Validated and written as `CHEESETRAP_API_ORIGIN` in `compose.env`. Existing configs can omit it. |

For a direct binary, use a separate [DB secret file](install.md).
Pass the origin only to the `api` role.

```sh
CHEESETRAP_API_LISTEN=127.0.0.1:8080 \
CHEESETRAP_API_ORIGIN=https://dashboard.example.com \
CHEESETRAP_DATABASE_URL_FILE=/absolute/private/api-url \
./bin/cheesetrap api
```

For a new Docker installation, copy the [HTTPS example](../../deploy/config.https.example.yaml)
and set `api_origin` and the remaining values for your environment. Use the
[default example](../../deploy/config.example.yaml) for SSH-tunnel access.
Never rerun `install-prepare.py` over an existing installation directory.
Add this property inside the installation JSON object.

```json
"api_origin": "https://dashboard.example.com"
```

Follow the [installation order](install.md) for preparation, guards, and the
administrator. Generated `compose.env` includes this value.

```dotenv
CHEESETRAP_API_ORIGIN=https://dashboard.example.com
```

Compose passes it only to the API. The container still listens on `0.0.0.0:8080`
with `CHEESETRAP_API_CONTAINER_LISTENER=true`, while host publication stays on
`127.0.0.1:8080`. DB and sensor networks stay unchanged. For direct Compose use,
pass the same variable through `--env-file`. Unset stale shell exports first
because exported values take precedence over the file.

## Accepted origins

| Input | Result |
| --- | --- |
| `http://127.0.0.1:8080` | SSH tunnel |
| `https://dashboard.example.com` | Custom HTTPS domain |
| `https://node.tail-example.ts.net:8443` | Tailnet HTTPS with an explicit port |
| `https://192.0.2.10` | HTTPS IP with a trusted certificate that includes the IP SAN |
| `http://192.0.2.10:8080` | Rejected. HTTP requires a literal loopback IP. |

Use lowercase ASCII hostnames or canonical IP notation. Enter internationalized
domains as lowercase punycode. Default ports `:443` for HTTPS and `:80` for HTTP
are omitted after normalization. Ports must be 1 to 65535 without leading zeros.
Trailing `/`, subpaths, queries, fragments, user credentials, wildcards, lists,
trailing dots, abbreviated or hexadecimal IPv4, IPv4-mapped IPv6, and zone IDs
are rejected. Subpath deployments are unsupported. An invalid origin stops the
API with `api_origin_invalid`.

## Connect the proxy

The browser connects by HTTPS to the proxy, which forwards HTTP to
`127.0.0.1:8080`. Preserve the original **Host and Origin** and forward all paths
from the root. The app matches `Host` exactly against the configured origin's host
and port. Mutations require the exact `Origin` and session-bound CSRF cookie and header.

`Forwarded`, `X-Forwarded-Host`, `X-Forwarded-Proto`, and Tailscale identity headers
do not establish authentication or an allowed origin. Never overwrite `Origin`
with a constant or synthesize CSRF headers. In HTTPS mode, session and CSRF cookies
use `Secure`, `HttpOnly`, and `SameSite=Strict` on issue, rotation, and deletion.
Do not create an HTTP bypass.

For Tailscale Serve, set `api_origin` to the node's actual MagicDNS HTTPS address.
Check existing Serve configuration, port conflicts, and tailnet rules, then run:

```sh
tailscale serve --bg --https=443 http://127.0.0.1:8080
tailscale serve status
```

If HTTPS certificates are not ready, complete the account setup requested by the
CLI. Its displayed address must match `api_origin`. Tailnet access rules apply.
Do not use public Funnel for this deployment. See the
[Tailscale Serve guide](https://tailscale.com/docs/features/tailscale-serve) and
[CLI reference](https://tailscale.com/docs/reference/tailscale-cli/serve).

For nginx, add this to your prepared HTTPS server. Configure the certificate,
HTTPS listener, and management-network access restriction in the server block.

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $http_host;
}
```

nginx can otherwise use the upstream Host. This setting preserves the original
host and port. Do not rewrite Origin. See [proxy_set_header](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_set_header).
This example assumes a host process. A separate container's `127.0.0.1` is not the
host, so the example cannot be copied unchanged into a proxy container.

## Switch an existing installation and revert

1. Use the [upgrade guide](upgrade.md) for an HTTPS-capable version. Keep recovery
   copies of the old image and config. Prepare the same-host proxy, certificate,
   and access restrictions.
2. Set `api_origin` in existing `install.json` and `CHEESETRAP_API_ORIGIN` in
   `compose.env` to the same address. Add omitted keys. Do not change sensor addresses.
3. Check the existing guard, then recreate only the API. With the installation
   guide's `dc` helper, run `dc config --quiet`, then `dc up -d --no-deps api`.
   API restart rotates CSRF. Open a fresh browser session and log in.
4. Verify login, reload, and logout at the chosen HTTPS address. Local health and
   external proxy access are different checks. Browser access through the old
   `http://127.0.0.1:8080` origin correctly returns 403 while HTTPS is selected.
5. To revert, restore both values to `http://127.0.0.1:8080`, recreate only the API,
   and log in through the SSH tunnel. Stop only the relevant proxy route.
   Do not recreate the DB, evidence, or secrets.

Local health checks do not need the public network. Supply the configured host
and non-default port in `Host`, for example:

```sh
curl --fail -H 'Host: dashboard.example.com' \
  http://127.0.0.1:8080/api/v1/health/ready
```

This check does not verify the proxy certificate, ACL, or external reachability.
Other monitors also need the same Host. Health paths retain Host checks.

## Verification scope

Go configuration and the Python installer share accepted and rejected cases in
`testdata/api-origins.json`. The integration runner owns Testcontainers PostgreSQL,
an HTTP backend, and a loopback HTTPS proxy with a temporary certificate. It checks
login, CSRF, cookies, and logout. `npm --prefix web run test:e2e` covers both the
HTTP journey and Chromium HTTPS login, reload, and logout. These checks do not
verify a real Tailscale account, production proxy, or Linux firewall.
