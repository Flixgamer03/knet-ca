# Step-by-step installation

Every step ends with a **✅ check**. Only continue once it passes.
Example values: domain `home.arpa`, CA at `ca.home.arpa` on `192.168.1.10`, internal network `192.168.1.0/24`, DMZ `192.168.50.0/24`. Replace them with yours.

1. [Prepare the Docker host](#1-prepare-the-docker-host)
2. [DNS record](#2-dns-record)
3. [Files & `.env`](#3-files--env)
4. [Start](#4-start)
5. [Root CA on the admin PC](#5-root-ca-on-the-admin-pc)
6. [Firewall (DMZ only)](#6-firewall-dmz-only)
7. [Prepare a server](#7-prepare-a-server)
8. [First certificate (certbot + nginx)](#8-first-certificate-certbot--nginx)
9. [Secure the web UI](#9-secure-the-web-ui)
10. [Backup & take the root key offline](#10-backup--take-the-root-key-offline)

---

## 1. Prepare the Docker host

A Linux VM or LXC in the internal network with a static IP, Docker and Compose v2 (`curl -fsSL https://get.docker.com | sudo sh`).

✅ `docker compose version` shows v2 or newer · `ss -tlnp | grep -E ':(9000|8443|8080)\b'` prints nothing.

- **Port already in use?** (e.g. 9000 by Portainer or MinIO) – no problem, just set `ACME_PORT=9443` or similar in step 3.
- **Proxmox LXC:** if containers fail with "permission denied/apparmor", enable **Nesting** and **keyctl** under *Options → Features*.

## 2. DNS record

On your **internal** DNS (OPNsense/pfSense Unbound *Host Overrides*, Pi-hole *Local DNS*, AdGuard *DNS rewrites*): `ca.home.arpa → 192.168.1.10`.

✅ `getent hosts ca.home.arpa` on the host **and** `docker run --rm alpine nslookup <some-server>.home.arpa` (the CA validates from inside the container!).
If the container cannot resolve internal names → add `dns:` with your DNS server to `docker-compose.yml`.

## 3. Files & `.env`

```bash
git clone <repo-url> knet-ca && cd knet-ca && ./setup.sh && nano .env
```

```ini
CA_NAME=My CA                        # appears in every certificate – choose carefully
CA_HOSTNAME=ca.home.arpa
CA_EXTRA_NAMES=192.168.1.10          # optional: CA also reachable by IP
PERMITTED_DOMAINS=home.arpa          # only this domain (incl. subdomains)
PERMITTED_IP_RANGES=192.168.1.0/24,192.168.50.0/24
ACME_PORT=9443                       # 9000 if free
ACME_ALLOWED_NETWORKS=192.168.1.0/24,192.168.50.0/24
ALLOWED_NETWORKS=192.168.1.0/24      # narrowed down in step 9
AUTH_MODE=none
```

> `CA_NAME`, `PERMITTED_*` and `CA_KEY_TYPE` are baked in on first start.
> If you use a **public domain** internally (e.g. `example.com`), `PERMITTED_DOMAINS=example.com` also allows the CA to issue your public names – this only affects devices that trust your root CA. A subdomain such as `internal.example.com` is cleaner if possible.

✅ `docker compose config --quiet && echo OK` · `docker compose config | grep -E 'published|target'` shows your ports → 9000/8443/8080.

## 4. Start

```bash
docker compose up -d --build
```

✅ After ~30 s:
- `docker compose ps` → `Up … (healthy)`
- `docker compose logs ca | tail -12` → ACME directory, web UI, **root SHA256 (write it down!)**, allowed names
- TLS chain: `curl -s http://ca.home.arpa:8080/public/root_ca.crt -o /tmp/root.crt && curl --cacert /tmp/root.crt https://ca.home.arpa:9443/acme/directory` → JSON without errors
- From another machine: `curl http://ca.home.arpa:8080/` → info text. Works only locally → host firewall: `sudo firewall-cmd --permanent --add-port={9443,8443,8080}/tcp && sudo firewall-cmd --reload`

## 5. Root CA on the admin PC

Download the file and **compare the fingerprint with the log**:

| System | Installation |
|---|---|
| Windows | download `http://ca.home.arpa:8080/public/root_ca.cer` · check: `certutil -hashfile <file> SHA256` (= fingerprint) · admin PowerShell: `Import-Certificate -FilePath <file> -CertStoreLocation Cert:\LocalMachine\Root` |
| macOS | `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain root.crt` |
| Arch/CachyOS/Manjaro | `sudo trust anchor --store root.crt` |
| Fedora/RHEL | `sudo cp root.crt /etc/pki/ca-trust/source/anchors/ && sudo update-ca-trust` |
| Debian/Ubuntu | `sudo cp root.crt /usr/local/share/ca-certificates/my-ca.crt && sudo update-ca-certificates` |

Check on Linux/macOS: `openssl x509 -in root.crt -noout -fingerprint -sha256`. Import into Firefox separately if needed (*Settings → Certificates → Authorities*), then restart the browser.

✅ `https://ca.home.arpa:8443` loads **without a warning**, issuer "… Intermediate CA", bottom left shows "Angemeldet: lokal (<your IP>)".

## 6. Firewall (DMZ only)

Servers in the same network as the CA need no rules. For a DMZ (example: OPNsense):

1. *Firewall → Aliases*: `CA_HOST` (type Host(s), content `192.168.1.10` + **Enter**), `CA_PORTS` (type Port(s), `9443` and `8080`) → **Apply**
2. *Firewall → Rules → DMZ*: Pass · TCP · source `DMZ net` · destination `CA_HOST` · port `CA_PORTS` – **above** any block rules → **Apply changes**
3. Check that the internal network may reach the DMZ on ports 80/443 – otherwise add *LAN: `CA_HOST` → `DMZ net`, ports 80, 443*
4. The DMZ must reach the internal DNS. Do **not** open port 8443.

✅ On a DMZ server: `curl http://ca.home.arpa:8080/` → info text · `curl -sk https://ca.home.arpa:9443/acme/directory` → JSON · `curl -sk -m5 https://ca.home.arpa:8443/` → **fails**.
Watch live: *Firewall → Log Files → Live View*, filtered on the CA IP.

## 7. Prepare a server

On the server (works from the DMZ too – only uses ports 8080/9443). Insert the fingerprint from step 4:

```bash
curl -fsS http://ca.home.arpa:8080/public/root_ca.crt -o /tmp/ca-root.crt
openssl x509 -in /tmp/ca-root.crt -noout -fingerprint -sha256       # must match exactly!
curl -fsS --cacert /tmp/ca-root.crt https://ca.home.arpa:9443/public/bootstrap.sh | sudo sh
```

The script installs the root CA (Debian/Ubuntu/RHEL/Fedora/Alpine/Arch) and makes sure certbot's renewal timer trusts it. The ready-made one-liner with the fingerprint filled in is also on the *Einrichtung* (setup) page of the UI.

Install certbot: Debian/Ubuntu `apt install certbot python3-certbot-nginx` · RHEL/CentOS `dnf install epel-release && dnf install certbot python3-certbot-nginx`.

✅ `curl https://ca.home.arpa:9443/health` → `ok` (without `-k`) · `python3 -c "import requests; print(requests.get('https://ca.home.arpa:9443/health').text)"` → `ok` · the CA resolves the server: `docker compose exec ca getent hosts <server>.home.arpa`.

## 8. First certificate (certbot + nginx)

certbot reads the **entire** nginx configuration and edits the file whose `server_name` matches (`sudo nginx -T | grep -E "^# configuration file|server_name"` shows which one). Back it up first: `sudo cp -a /etc/nginx /etc/nginx.bak`.

```bash
sudo certbot --nginx --server https://ca.home.arpa:9443/acme/directory \
  -d app.home.arpa -m admin@home.arpa --agree-tos --no-eff-email --redirect
sudo systemctl enable --now certbot-renew.timer   # Debian/Ubuntu: certbot.timer
```

If certbot should not touch your config: use `certbot certonly --nginx … --deploy-hook "systemctl reload nginx"` and add `ssl_certificate /etc/letsencrypt/live/<name>/fullchain.pem;` / `ssl_certificate_key …/privkey.pem;` yourself.

✅
- `sudo certbot certificates` → "VALID: 89 days"
- Browser: `https://app.home.arpa` without a warning
- UI: certificate with source ACME, *ACME → Protokoll* (log) shows `http-01` and `finalize` OK
- **Test renewal:** `sudo certbot renew --force-renewal` (real renewal) or `sudo certbot renew --dry-run --server https://ca.home.arpa:9443/acme/directory`
  ⚠️ `--dry-run` **without** `--server` tests against Let's Encrypt staging → "NXDOMAIN", even though everything is fine.
- UI *Endpunkte* (endpoints): add `app.home.arpa:443` → status OK; after a renewal, "Prüfen" (check) shows the new certificate (nginx was reloaded)

If something fails: UI *ACME → Protokoll → Nur Fehler* (errors only) shows the reason.

## 9. Secure the web UI

**At minimum:** admin PC only (static IP/DHCP reservation!) → `.env`: `ALLOWED_NETWORKS=192.168.1.20/32`, then `docker compose up -d`.

**Optional Authentik (OIDC):** *Applications → Create with Provider → OAuth2/OpenID*, client type *Confidential*, redirect URI `https://ca.home.arpa:8443/auth/callback`. In `.env`:

```ini
AUTH_MODE=oidc
OIDC_ISSUER=https://auth.home.arpa/application/o/<slug>/
OIDC_CLIENT_ID=…
OIDC_CLIENT_SECRET=…
OIDC_ALLOWED_GROUPS=ca-admins
OIDC_CA_BUNDLE=/data/ca/root_ca.crt     # only if Authentik uses a certificate from this CA
```

Alternatively forward auth via a proxy outpost: `AUTH_MODE=proxy`, `TRUSTED_PROXIES=<proxy IP>`.
Locked out? Reset `.env` (`AUTH_MODE=none`, your IP in `ALLOWED_NETWORKS`) and run `docker compose up -d`.

✅ The UI loads from the admin PC (after login, if enabled); other devices get "Zugriff … nicht erlaubt" (access denied). ACME (`:9443/health`) and the root download (`:8080`) keep working everywhere.

## 10. Backup & take the root key offline

```bash
./backup.sh                       # → backups/knet-ca-<time>.tar.gz + .env (contains CA keys!)
docker compose cp ca:/data/ca/root_ca.key ./root_ca.key   # store offline (password manager, USB stick)
docker compose exec ca rm /data/ca/root_ca.key && rm ./root_ca.key
```

The root key is only needed for `renew-intermediate` (copy it back temporarily: `docker compose cp ./root_ca.key ca:/data/ca/`).

**Restore:**
```bash
docker volume create knet-ca-data
docker run --rm -v knet-ca-data:/data -v "$PWD/backups:/b" alpine sh -c \
  "tar xzf /b/knet-ca-<time>.tar.gz -C /data && mv /data/backup.sqlite /data/ca.sqlite && chown -R 1000:1000 /data"
cp backups/knet-ca-<time>.env .env && docker compose up -d
```

✅ `docker compose exec ca python -m app.cli info` → "Root-Schlüssel ist offline" (root key is offline), the backup file is stored off the host.
