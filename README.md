# knet-ca

> [!WARNING]
> **knet-ca was built with AI (Claude by Anthropic).** The code has not been independently reviewed or security-audited.
> A certificate authority is security-critical: whoever controls it can impersonate any service on your network.
> Intended for home labs and learning – **not for production use**. Use at your own risk; no warranty of any kind.
> Review the code before you trust it, restrict access to the web UI and keep the root key offline.
> Provided as-is, issues and PRs may not be answered."

Your own certificate authority for the home lab – **one container**, no step-ca, no database server.
Servers get certificates automatically via **ACME** (certbot, acme.sh, Caddy, Traefik, Proxmox …); everything else is done in the **web UI**.

```
 certbot · acme.sh · Caddy · Traefik           Browser (admin)
            │ ACME :9443 → 9000                    │ :8443
            ▼                                      ▼
 ┌─────────────────────────────────────────────────────────┐
 │ knet-ca: ACME server · PKI (root + intermediate) · UI   │
 │          SQLite + keys in the /data volume              │
 └─────────────────────────────────────────────────────────┘
            ▲ :8080 (HTTP) root certificate · CRL · bootstrap script
```

## Features

- **ACME server** (RFC 8555): `http-01`, `dns-01` (incl. wildcards), `tls-alpn-01`, DNS names and IP addresses, revocation, key rollover
- **Readable errors**: when a validation fails, the client and the UI show the actual reason ("name does not resolve", "port 80 refused", "wrong content – is another server answering?")
- **Name constraints**: the CA can only issue certificates for *your* domains – browsers reject anything else, even if correctly signed
- **Web UI**: certificate list, downloads, sign CSRs, generate key + certificate (incl. `.p12`), revocation, ACME accounts & log
- **Endpoint monitoring**: checks that a service actually serves the renewed certificate
- **Setup page** with a one-liner for Linux servers, instructions for Windows/macOS/Linux/iOS/Android/Firefox/Java and snippets for ACME clients
- ntfy expiry warnings, audit log, Prometheus `/metrics`
- Access control: IP allowlist, optional login via **Authentik/OIDC** or forward auth

> The web UI is currently in German.

## Quick start

```bash
git clone <repo-url> knet-ca && cd knet-ca
./setup.sh          # creates .env
nano .env           # at least CA_NAME, CA_HOSTNAME, PERMITTED_DOMAINS, ALLOWED_NETWORKS
docker compose up -d --build
docker compose logs ca   # shows URLs and the root fingerprint
```

👉 **Step-by-step guide with checks: [docs/installation.md](docs/installation.md)**

## Where to place it in your network

Put the CA in your **internal server/admin network, not in the DMZ**. The CA is the most valuable system in your network (whoever controls it can impersonate every internal service), and ACME needs connections in both directions:

| From | To | Port | Purpose |
|---|---|---|---|
| Servers (incl. DMZ) | CA | `ACME_PORT` (e.g. 9443) | ACME |
| Servers (incl. DMZ) | CA | 8080 | Root certificate, bootstrap, CRL |
| CA | Servers | 80 / 443 | Challenge validation |
| Admin PC only | CA | 8443 | Web UI |

For a DMZ this means **one** rule "DMZ net → CA, ports ACME + 8080" – instead of placing the CA in the DMZ and opening access from there into your internal network.

## Important notes

- **`CA_NAME`, `PERMITTED_DOMAINS`, `PERMITTED_IP_RANGES`, `CA_KEY_TYPE`** only apply on first start. Domains can be changed later with `renew-intermediate` (the root stays the same).
- **Always run `certbot renew --dry-run` with `--server <ACME URL>`** – without it, certbot's dry run tests against Let's Encrypt staging and fails on internal names (NXDOMAIN). The most reliable test is `certbot renew --force-renewal`.
- **Take the root key offline** once everything works – see [installation, step 10](docs/installation.md#10-backup--take-the-root-key-offline).
- The `knet-ca-data` volume contains the CA keys. **Store backups (`./backup.sh`) securely.**

## Configuration

All options are documented in [`.env.example`](.env.example). The most important ones:

| Variable | Meaning |
|---|---|
| `CA_HOSTNAME` | DNS name of the CA (A record pointing to the Docker host) |
| `PERMITTED_DOMAINS` / `PERMITTED_IP_RANGES` | allowed names (name constraints) |
| `ACME_PORT`, `WEBUI_PORT`, `PUBLIC_HTTP_PORT` | ports on the host (fixed 9000/8443/8080 inside the container) |
| `ACME_CERT_DAYS`, `MANUAL_DEFAULT_DAYS`, `MANUAL_MAX_DAYS` | lifetimes (90 / 365 / max. 825 days) |
| `ACME_ALLOWED_NETWORKS` | who may use ACME |
| `ACME_TRUSTED_NETWORKS` | escape hatch: issue **without** challenge for these networks |
| `ALLOWED_NETWORKS`, `AUTH_MODE` | access to the UI (`none` · `oidc` · `proxy`) |
| `DNS_SERVERS` | DNS for dns-01 (default: container DNS) |
| `NTFY_URL`, `METRICS_TOKEN` | notifications, Prometheus |

## Command line

```bash
docker compose exec ca python -m app.cli info                 # fingerprint, lifetimes, constraints
docker compose exec ca python -m app.cli renew-intermediate   # new intermediate (needs the root key)
docker compose exec ca python -m app.cli revoke <serial> [reason]
```

## Project layout

```
app/server.py      runs ACME (9000), UI (8443) and HTTP (8080) in one process
app/pki.py         root/intermediate, issuance, revocation, CRL
app/acme.py        ACME server         app/jose.py        JWS/JWK (RS*, PS*, ES*, EdDSA)
app/validation.py  challenge checks    app/dnsclient.py   TXT resolver for dns-01
app/main.py        web UI              app/auth.py        allowlist, CSRF, OIDC, forward auth
app/tasks.py       monitoring, ntfy, own TLS certificate (hot reload)
```

Without Docker: `pip install -r requirements.txt && DATA_DIR=/tmp/ca CA_HOSTNAME=ca.home.arpa PERMITTED_DOMAINS=home.arpa python -m app.server`
