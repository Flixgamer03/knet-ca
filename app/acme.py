"""ACME-Server nach RFC 8555 (+ RFC 8737 tls-alpn-01, RFC 8738 IP-Identifier)."""
from __future__ import annotations

import ipaddress
import json
import logging
import re
import secrets
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

from . import validation as V
from .auth import client_ip, ip_allowed
from .certs import get_sans, common_name
from .db import dumps, iso, parse_iso, utcnow
from .jose import SUPPORTED_ALGS, JoseError, b64d, parse_flattened, public_jwk, thumbprint, verify, jwk_to_key
from .pki import IssueError, spki_sha256

log = logging.getLogger("knet-ca.acme")

ERR = "urn:ietf:params:acme:error:"
ORDER_LIFETIME = timedelta(days=7)
AUTHZ_LIFETIME = timedelta(days=7)
REVOKE_REASONS = {0, 1, 3, 4, 5, 9}
DNS_LABEL = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")


class Problem(Exception):
    def __init__(self, kind: str, detail: str, status: int = 400, headers: dict | None = None):
        super().__init__(detail)
        self.kind, self.detail, self.status, self.headers = kind, detail, status, headers or {}


def new_id(n: int = 16) -> str:
    return secrets.token_urlsafe(n)


class Nonces:
    def __init__(self, ttl: int = 3600, max_size: int = 20000):
        self.ttl, self.max_size = ttl, max_size
        self._d: dict[str, float] = {}
        self._lock = threading.Lock()

    def issue(self) -> str:
        n = secrets.token_urlsafe(24)
        now = time.time()
        with self._lock:
            if len(self._d) >= self.max_size:
                for k in [k for k, exp in self._d.items() if exp < now] or list(self._d)[: self.max_size // 2]:
                    self._d.pop(k, None)
            self._d[n] = now + self.ttl
        return n

    def consume(self, n) -> bool:
        if not isinstance(n, str):
            return False
        with self._lock:
            exp = self._d.pop(n, None)
        return exp is not None and exp > time.time()


def _norm_url(u: str) -> tuple:
    p = urllib.parse.urlsplit(u)
    port = p.port or (443 if p.scheme == "https" else 80)
    return (p.scheme.lower(), (p.hostname or "").lower(), port, p.path.rstrip("/") or "/")


def normalize_identifier(ident) -> tuple[str, str, bool]:
    """-> (typ, wert ohne '*.', wildcard)"""
    if not isinstance(ident, dict):
        raise Problem("malformed", "Identifier muss ein Objekt sein")
    typ, val = ident.get("type"), ident.get("value")
    if not isinstance(val, str) or not val:
        raise Problem("malformed", "Identifier ohne Wert")
    val = val.strip().lower().rstrip(".")
    if typ == "ip":
        try:
            return "ip", str(ipaddress.ip_address(val)), False
        except ValueError:
            raise Problem("rejectedIdentifier", f"'{val}' ist keine gültige IP-Adresse")
    if typ != "dns":
        raise Problem("unsupportedIdentifier", f"Identifier-Typ '{typ}' wird nicht unterstützt (dns, ip)")
    wildcard = val.startswith("*.")
    base = val[2:] if wildcard else val
    try:
        ipaddress.ip_address(base)
        raise Problem("rejectedIdentifier", f"'{val}' ist eine IP-Adresse – bitte Typ 'ip' verwenden")
    except ValueError:
        pass
    labels = base.split(".")
    if "*" in base or len(base) > 253 or not all(DNS_LABEL.match(l) for l in labels):
        raise Problem("rejectedIdentifier", f"'{val}' ist kein gültiger DNS-Name")
    return "dns", base, wildcard


class AcmeServer:
    def __init__(self, state):
        self.state = state
        self.cfg, self.db, self.pki = state.cfg, state.db, state.pki
        self.nonces = Nonces()
        self.pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix="acme-validate")

    # --- URLs ---------------------------------------------------------------------------------
    def base(self, request: Request) -> str:
        u = request.url
        return f"{u.scheme}://{u.netloc}"

    def url(self, request: Request, *parts: str) -> str:
        return self.base(request) + "/acme/" + "/".join(parts)

    # --- Antworten ------------------------------------------------------------------------------
    def _headers(self, request: Request, extra: dict | None = None) -> dict:
        h = {"Replay-Nonce": self.nonces.issue(), "Cache-Control": "no-store",
             "Link": f'<{self.url(request, "directory")}>;rel="index"'}
        if extra:
            h.update(extra)
        return h

    def json(self, request: Request, obj, status: int = 200, location: str | None = None,
             headers: dict | None = None) -> Response:
        h = self._headers(request, headers)
        if location:
            h["Location"] = location
        return Response(dumps(obj), status_code=status, media_type="application/json", headers=h)

    def problem(self, request: Request, p: Problem) -> Response:
        body = {"type": ERR + p.kind, "detail": p.detail, "status": p.status}
        h = self._headers(request, p.headers)
        return Response(dumps(body), status_code=p.status, media_type="application/problem+json", headers=h)

    # --- JWS -------------------------------------------------------------------------------------
    async def verify(self, request: Request, need: str = "kid") -> dict:
        """need: 'kid' (Account), 'jwk' (neuer Schlüssel) oder 'any'."""
        body = await request.body()
        try:
            prot, p64, pay64, sig = parse_flattened(body)
        except JoseError as e:
            raise Problem(e.kind, str(e))
        alg = prot.get("alg")
        if alg not in SUPPORTED_ALGS:
            raise Problem("badSignatureAlgorithm", f"Algorithmus {alg!r} nicht unterstützt",
                          headers={})
        if not self.nonces.consume(prot.get("nonce")):
            raise Problem("badNonce", "Nonce ungültig oder bereits verwendet – bitte neue Nonce holen")
        if not isinstance(prot.get("url"), str) or _norm_url(prot["url"]) != _norm_url(str(request.url)):
            raise Problem("unauthorized", f"'url' im JWS ({prot.get('url')}) passt nicht zur Request-URL "
                                          f"({request.url})")
        has_jwk, has_kid = "jwk" in prot, "kid" in prot
        if has_jwk == has_kid:
            raise Problem("malformed", "JWS braucht genau eines von 'jwk' oder 'kid'")
        if need == "kid" and not has_kid:
            raise Problem("malformed", "Diese Anfrage muss mit 'kid' (Account-URL) signiert werden")
        if need == "jwk" and not has_jwk:
            raise Problem("malformed", "Diese Anfrage muss mit 'jwk' signiert werden")
        account = None
        if has_kid:
            m = re.search(r"/acme/acct/([A-Za-z0-9_-]+)$", str(prot["kid"]))
            account = self.db.one("SELECT * FROM acme_accounts WHERE id = ?", (m.group(1),)) if m else None
            if account is None:
                raise Problem("accountDoesNotExist", "Account existiert nicht", 400)
            if account["status"] != "valid":
                raise Problem("unauthorized", f"Account ist {account['status']}", 403)
            jwk = json.loads(account["jwk"])
        else:
            jwk = prot["jwk"]
            try:
                jwk_to_key(jwk)
                tp = thumbprint(jwk)
            except JoseError as e:
                raise Problem(e.kind, str(e))
            account = self.db.one("SELECT * FROM acme_accounts WHERE thumbprint = ?", (tp,))
        try:
            verify(alg, jwk, f"{p64}.{pay64}".encode(), sig)
        except JoseError as e:
            raise Problem(e.kind if e.kind != "malformed" else "malformed", f"JWS-Prüfung fehlgeschlagen: {e}")
        if pay64 == "":
            payload = None  # POST-as-GET
        else:
            try:
                payload = json.loads(b64d(pay64))
            except ValueError:
                raise Problem("malformed", "Payload ist kein JSON")
        if account is not None:
            self.db.run("UPDATE acme_accounts SET last_seen = ? WHERE id = ?", (iso(utcnow()), account["id"]))
        return {"protected": prot, "payload": payload, "jwk": jwk, "account": account, "alg": alg,
                "ip": request.state.client_ip}

    # --- Objekte -> JSON -------------------------------------------------------------------------
    def account_json(self, request: Request, a: dict) -> dict:
        return {"status": a["status"], "contact": json.loads(a["contact"]),
                "orders": self.url(request, "acct", a["id"], "orders")}

    def challenge_json(self, request: Request, c: dict) -> dict:
        o = {"type": c["type"], "url": self.url(request, "chall", c["id"]), "status": c["status"],
             "token": c["token"]}
        if c["validated"]:
            o["validated"] = c["validated"]
        if c["error"]:
            o["error"] = json.loads(c["error"])
        return o

    def authz_json(self, request: Request, a: dict) -> dict:
        chs = self.db.all("SELECT * FROM acme_challenges WHERE authz_id = ? ORDER BY rowid", (a["id"],))
        if a["status"] == "valid":
            chs = [c for c in chs if c["status"] == "valid"] or chs
        o = {"identifier": {"type": a["id_type"], "value": a["id_value"]}, "status": a["status"],
             "expires": a["expires"], "challenges": [self.challenge_json(request, c) for c in chs]}
        if a["wildcard"]:
            o["wildcard"] = True
        return o

    def refresh_order(self, order: dict) -> dict:
        if order["status"] in ("valid", "invalid"):
            return order
        now = utcnow()
        authz = self.db.all("SELECT * FROM acme_authz WHERE order_id = ?", (order["id"],))
        status = order["status"]
        if parse_iso(order["expires"]) < now:
            status = "invalid"
        elif any(a["status"] in ("invalid", "deactivated", "revoked", "expired") for a in authz):
            status = "invalid"
        elif status == "pending" and authz and all(a["status"] == "valid" for a in authz):
            status = "ready"
        if status != order["status"]:
            self.db.run("UPDATE acme_orders SET status = ? WHERE id = ?", (status, order["id"]))
            order = dict(order, status=status)
        return order

    def order_json(self, request: Request, o: dict) -> dict:
        authz = self.db.all("SELECT id FROM acme_authz WHERE order_id = ? ORDER BY rowid", (o["id"],))
        j = {"status": o["status"], "expires": o["expires"], "identifiers": json.loads(o["identifiers"]),
             "authorizations": [self.url(request, "authz", a["id"]) for a in authz],
             "finalize": self.url(request, "order", o["id"], "finalize")}
        if o["cert_serial"]:
            j["certificate"] = self.url(request, "cert", o["cert_serial"])
        if o["error"]:
            j["error"] = json.loads(o["error"])
        return j

    def _owned(self, table: str, obj_id: str, account: dict) -> dict:
        row = self.db.one(f"SELECT * FROM {table} WHERE id = ?", (obj_id,))
        if row is None:
            raise Problem("malformed", "Objekt nicht gefunden", 404)
        if row["account_id"] != account["id"]:
            raise Problem("unauthorized", "Objekt gehört zu einem anderen Account", 403)
        return row

    # --- Endpunkte --------------------------------------------------------------------------------
    async def directory(self, request: Request) -> Response:
        d = {
            "newNonce": self.url(request, "new-nonce"),
            "newAccount": self.url(request, "new-account"),
            "newOrder": self.url(request, "new-order"),
            "revokeCert": self.url(request, "revoke-cert"),
            "keyChange": self.url(request, "key-change"),
            "meta": {"website": self.cfg.webui_public_url, "externalAccountRequired": False},
        }
        return Response(dumps(d), media_type="application/json",
                        headers={"Cache-Control": "public, max-age=60"})

    async def new_nonce(self, request: Request) -> Response:
        status = 200 if request.method == "HEAD" else 204
        return Response(status_code=status, headers=self._headers(request))

    async def new_account(self, request: Request) -> Response:
        ctx = await self.verify(request, need="jwk")
        p = ctx["payload"] or {}
        if not isinstance(p, dict):
            raise Problem("malformed", "Payload muss ein Objekt sein")
        if ctx["account"] is not None:
            a = ctx["account"]
            return self.json(request, self.account_json(request, a), 200, location=self.url(request, "acct", a["id"]))
        if p.get("onlyReturnExisting"):
            raise Problem("accountDoesNotExist", "Kein Account für diesen Schlüssel")
        contact = _check_contact(p.get("contact", []))
        acc_id = new_id(12)
        self.db.run("INSERT INTO acme_accounts (id, thumbprint, jwk, contact, status, created, ip, last_seen) "
                    "VALUES (?,?,?,?,?,?,?,?)",
                    (acc_id, thumbprint(ctx["jwk"]), dumps(public_jwk(ctx["jwk"])), dumps(contact), "valid",
                     iso(utcnow()), ctx["ip"], iso(utcnow())))
        self.db.acme_event("account", True, f"Neuer Account ({', '.join(contact) or 'ohne Kontakt'}, "
                                            f"{ctx['alg']})", account_id=acc_id, ip=ctx["ip"])
        a = self.db.one("SELECT * FROM acme_accounts WHERE id = ?", (acc_id,))
        return self.json(request, self.account_json(request, a), 201, location=self.url(request, "acct", acc_id))

    async def account(self, request: Request) -> Response:
        ctx = await self.verify(request)
        a = ctx["account"]
        if a["id"] != request.path_params["id"]:
            raise Problem("unauthorized", "Falscher Account", 403)
        p = ctx["payload"]
        if isinstance(p, dict):
            if "contact" in p:
                self.db.run("UPDATE acme_accounts SET contact = ? WHERE id = ?",
                            (dumps(_check_contact(p["contact"])), a["id"]))
            if p.get("status") == "deactivated":
                self.db.run("UPDATE acme_accounts SET status = 'deactivated' WHERE id = ?", (a["id"],))
                self.db.acme_event("account", True, "Account deaktiviert", account_id=a["id"], ip=ctx["ip"])
            elif "status" in p and p["status"] != "valid":
                raise Problem("malformed", "Nur status=deactivated ist erlaubt")
        a = self.db.one("SELECT * FROM acme_accounts WHERE id = ?", (a["id"],))
        return self.json(request, self.account_json(request, a), location=self.url(request, "acct", a["id"]))

    async def account_orders(self, request: Request) -> Response:
        ctx = await self.verify(request)
        if ctx["account"]["id"] != request.path_params["id"]:
            raise Problem("unauthorized", "Falscher Account", 403)
        rows = self.db.all("SELECT id FROM acme_orders WHERE account_id = ? ORDER BY created DESC LIMIT 200",
                           (ctx["account"]["id"],))
        return self.json(request, {"orders": [self.url(request, "order", r["id"]) for r in rows]})

    async def new_order(self, request: Request) -> Response:
        ctx = await self.verify(request)
        a, p = ctx["account"], ctx["payload"]
        if not isinstance(p, dict) or not isinstance(p.get("identifiers"), list) or not p["identifiers"]:
            raise Problem("malformed", "identifiers fehlt")
        if len(p["identifiers"]) > 100:
            raise Problem("rejectedIdentifier", "Maximal 100 Namen pro Auftrag")
        idents, seen = [], set()
        for raw in p["identifiers"]:
            typ, val, wc = normalize_identifier(raw)
            full = f"*.{val}" if wc else val
            if (typ, full) in seen:
                continue
            seen.add((typ, full))
            idents.append((typ, val, wc, full))
        bad = self.pki.constraints.check([f for _, _, _, f in idents])
        if bad:
            msg = (f"Nicht erlaubt: {', '.join(bad)}. Diese CA stellt nur Zertifikate für "
                   f"{', '.join(self.pki.constraints.dns) or '(alles)'} aus.")
            self.db.acme_event("order", False, msg, account_id=a["id"], identifier=", ".join(bad), ip=ctx["ip"])
            raise Problem("rejectedIdentifier", msg)
        now = utcnow()
        oid = new_id()
        with self.db.tx() as c:
            c.execute("INSERT INTO acme_orders (id, account_id, status, identifiers, expires, created, ip) "
                      "VALUES (?,?,?,?,?,?,?)",
                      (oid, a["id"], "pending", dumps([{"type": t, "value": f} for t, _, _, f in idents]),
                       iso(now + ORDER_LIFETIME), iso(now), ctx["ip"]))
            for typ, val, wc, _ in idents:
                zid = new_id()
                c.execute("INSERT INTO acme_authz (id, order_id, account_id, id_type, id_value, wildcard, status, "
                          "expires) VALUES (?,?,?,?,?,?,?,?)",
                          (zid, oid, a["id"], typ, val, 1 if wc else 0, "pending", iso(now + AUTHZ_LIFETIME)))
                types = ["dns-01"] if wc else (["http-01", "tls-alpn-01"] if typ == "ip"
                                               else ["http-01", "dns-01", "tls-alpn-01"])
                for t in types:
                    c.execute("INSERT INTO acme_challenges (id, authz_id, type, token, status) VALUES (?,?,?,?,?)",
                              (new_id(), zid, t, secrets.token_urlsafe(32), "pending"))
        self.db.acme_event("order", True, "Neuer Auftrag: " + ", ".join(f for _, _, _, f in idents),
                           account_id=a["id"], order_id=oid, ip=ctx["ip"])
        o = self.db.one("SELECT * FROM acme_orders WHERE id = ?", (oid,))
        return self.json(request, self.order_json(request, o), 201, location=self.url(request, "order", oid))

    async def order(self, request: Request) -> Response:
        ctx = await self.verify(request)
        o = self.refresh_order(self._owned("acme_orders", request.path_params["id"], ctx["account"]))
        headers = {"Retry-After": "2"} if o["status"] in ("pending", "processing") else None
        return self.json(request, self.order_json(request, o), headers=headers)

    async def authz(self, request: Request) -> Response:
        ctx = await self.verify(request)
        z = self._owned("acme_authz", request.path_params["id"], ctx["account"])
        p = ctx["payload"]
        if isinstance(p, dict) and p.get("status") == "deactivated":
            self.db.run("UPDATE acme_authz SET status = 'deactivated' WHERE id = ?", (z["id"],))
            z = self.db.one("SELECT * FROM acme_authz WHERE id = ?", (z["id"],))
        elif z["status"] == "pending" and parse_iso(z["expires"]) < utcnow():
            self.db.run("UPDATE acme_authz SET status = 'expired' WHERE id = ?", (z["id"],))
            z = dict(z, status="expired")
        headers = {"Retry-After": "2"} if z["status"] == "pending" else None
        return self.json(request, self.authz_json(request, z), headers=headers)

    async def challenge(self, request: Request) -> Response:
        ctx = await self.verify(request)
        ch = self.db.one("SELECT * FROM acme_challenges WHERE id = ?", (request.path_params["id"],))
        if ch is None:
            raise Problem("malformed", "Challenge nicht gefunden", 404)
        z = self._owned("acme_authz", ch["authz_id"], ctx["account"])
        if isinstance(ctx["payload"], dict) and ch["status"] == "pending" and z["status"] == "pending":
            self.db.run("UPDATE acme_challenges SET status = 'processing' WHERE id = ? AND status = 'pending'",
                        (ch["id"],))
            ch = dict(ch, status="processing")
            self.pool.submit(self._validate, ch["id"], ctx["ip"], ctx["account"])
        headers = {"Link": f'<{self.url(request, "authz", z["id"])}>;rel="up"'}
        if ch["status"] == "processing":
            headers["Retry-After"] = "2"
        resp = self.json(request, self.challenge_json(request, ch), headers=headers)
        # Link-Header zusammenführen (index + up)
        resp.headers["Link"] = (f'<{self.url(request, "directory")}>;rel="index", '
                                f'<{self.url(request, "authz", z["id"])}>;rel="up"')
        return resp

    def _validate(self, chall_id: str, ip: str, account: dict) -> None:
        ch = self.db.one("SELECT * FROM acme_challenges WHERE id = ?", (chall_id,))
        z = self.db.one("SELECT * FROM acme_authz WHERE id = ?", (ch["authz_id"],))
        ident = ("*." if z["wildcard"] else "") + z["id_value"]
        keyauth = V.key_authorization(ch["token"], thumbprint(json.loads(account["jwk"])))
        cfg = self.cfg
        try:
            if cfg.acme_trusted_networks and ip_allowed(ip, cfg.acme_trusted_networks):
                detail = f"Prüfung übersprungen – Client {ip} ist in ACME_TRUSTED_NETWORKS"
            elif ch["type"] == "http-01":
                detail = V.run_with_retries(lambda: V.validate_http01(z["id_value"], ch["token"], keyauth,
                                                                      cfg.http01_port), 3, 2)
            elif ch["type"] == "dns-01":
                detail = V.run_with_retries(lambda: V.validate_dns01(z["id_value"], keyauth, cfg.dns_servers),
                                            6, 5)
            elif ch["type"] == "tls-alpn-01":
                detail = V.run_with_retries(lambda: V.validate_tlsalpn01(z["id_value"], keyauth,
                                                                         cfg.tlsalpn01_port), 3, 2)
            else:
                raise V.ValidationError("malformed", f"Unbekannter Challenge-Typ {ch['type']}")
            with self.db.tx() as c:
                c.execute("UPDATE acme_challenges SET status = 'valid', validated = ? WHERE id = ?",
                          (iso(utcnow()), chall_id))
                c.execute("UPDATE acme_authz SET status = 'valid' WHERE id = ? AND status = 'pending'", (z["id"],))
            self.db.acme_event(ch["type"], True, detail, account_id=account["id"], order_id=z["order_id"],
                               identifier=ident, ip=ip)
        except V.ValidationError as e:
            err = {"type": ERR + e.kind, "detail": f"{ch['type']} für {ident}: {e}", "status": 403}
            with self.db.tx() as c:
                c.execute("UPDATE acme_challenges SET status = 'invalid', error = ? WHERE id = ?",
                          (dumps(err), chall_id))
                c.execute("UPDATE acme_authz SET status = 'invalid' WHERE id = ?", (z["id"],))
            self.db.acme_event(ch["type"], False, str(e), account_id=account["id"], order_id=z["order_id"],
                               identifier=ident, ip=ip)
        except Exception as e:  # pragma: no cover - unerwartet
            log.exception("Validierung fehlgeschlagen")
            err = {"type": ERR + "serverInternal", "detail": f"Interner Fehler: {e}", "status": 500}
            self.db.run("UPDATE acme_challenges SET status = 'invalid', error = ? WHERE id = ?",
                        (dumps(err), chall_id))
            self.db.run("UPDATE acme_authz SET status = 'invalid' WHERE id = ?", (z["id"],))
        o = self.db.one("SELECT * FROM acme_orders WHERE id = ?", (z["order_id"],))
        if o:
            self.refresh_order(o)

    async def finalize(self, request: Request) -> Response:
        ctx = await self.verify(request)
        o = self.refresh_order(self._owned("acme_orders", request.path_params["id"], ctx["account"]))
        if o["status"] != "ready":
            raise Problem("orderNotReady", f"Auftrag ist '{o['status']}', nicht 'ready' – erst alle "
                                           f"Challenges erfüllen", 403)
        p = ctx["payload"]
        if not isinstance(p, dict) or not isinstance(p.get("csr"), str):
            raise Problem("malformed", "csr fehlt")
        try:
            csr = x509.load_der_x509_csr(b64d(p["csr"]))
        except (ValueError, JoseError) as e:
            raise Problem("badCSR", f"CSR nicht lesbar: {e}")
        if not csr.is_signature_valid:
            raise Problem("badCSR", "Signatur des CSR ungültig")
        want = [i["value"] for i in json.loads(o["identifiers"])]
        have = {s.lower() for s in get_sans(csr) if not s.startswith(("email:", "uri:"))}
        cn = common_name(csr.subject).lower()
        if cn:
            have.add(cn)
        norm = set()
        for h in have:
            try:
                norm.add(str(ipaddress.ip_address(h)))
            except ValueError:
                norm.add(h.rstrip("."))
        if norm != set(want):
            raise Problem("badCSR", f"Namen im CSR ({', '.join(sorted(norm))}) passen nicht zum Auftrag "
                                    f"({', '.join(want)})")
        if spki_sha256(csr.public_key()) == spki_sha256(jwk_to_key(ctx["jwk"])):
            raise Problem("badCSR", "Der Zertifikatsschlüssel darf nicht der Account-Schlüssel sein")
        acct = ctx["account"]
        contact = ", ".join(c.replace("mailto:", "") for c in json.loads(acct["contact"])) or f"Account {acct['id']}"
        try:
            cert = await run_in_threadpool(
                self.pki.issue_csr, csr, want, self.cfg.acme_cert_days, source="acme",
                requester=f"{contact} @ {ctx['ip']}", acme_account=acct["id"], order_id=o["id"],
                max_days=self.cfg.acme_cert_days)
        except IssueError as e:
            self.db.acme_event("finalize", False, str(e), account_id=acct["id"], order_id=o["id"], ip=ctx["ip"])
            raise Problem("badCSR", str(e))
        serial = format(cert.serial_number, "x")
        self.db.run("UPDATE acme_orders SET status = 'valid', cert_serial = ? WHERE id = ?", (serial, o["id"]))
        self.db.acme_event("finalize", True, f"Zertifikat {serial[:12]}… für {', '.join(want)} ausgestellt",
                           account_id=acct["id"], order_id=o["id"], ip=ctx["ip"])
        o = self.db.one("SELECT * FROM acme_orders WHERE id = ?", (o["id"],))
        return self.json(request, self.order_json(request, o), location=self.url(request, "order", o["id"]))

    async def certificate(self, request: Request) -> Response:
        ctx = await self.verify(request)
        row = self.db.one("SELECT pem, acme_account FROM certs WHERE serial = ?", (request.path_params["serial"],))
        if row is None:
            raise Problem("malformed", "Zertifikat nicht gefunden", 404)
        if row["acme_account"] != ctx["account"]["id"]:
            raise Problem("unauthorized", "Zertifikat gehört zu einem anderen Account", 403)
        body = row["pem"].strip() + "\n" + self.pki.chain_pem().strip() + "\n"
        return Response(body, media_type="application/pem-certificate-chain", headers=self._headers(request))

    async def revoke_cert(self, request: Request) -> Response:
        ctx = await self.verify(request, need="any")
        p = ctx["payload"]
        if not isinstance(p, dict) or not isinstance(p.get("certificate"), str):
            raise Problem("malformed", "certificate fehlt")
        try:
            cert = x509.load_der_x509_certificate(b64d(p["certificate"]))
        except (ValueError, JoseError):
            raise Problem("malformed", "Zertifikat nicht lesbar")
        reason = p.get("reason", 0)
        if not isinstance(reason, int) or reason not in REVOKE_REASONS:
            raise Problem("badRevocationReason", f"Widerrufsgrund {reason} nicht erlaubt (0,1,3,4,5,9)")
        serial = format(cert.serial_number, "x")
        row = self.db.one("SELECT * FROM certs WHERE serial = ?", (serial,))
        if row is None or x509.load_pem_x509_certificate(row["pem"].encode()) != cert:
            raise Problem("malformed", "Zertifikat wurde nicht von dieser CA ausgestellt", 404)
        allowed = False
        if "kid" in ctx["protected"] and ctx["account"] and row["acme_account"] == ctx["account"]["id"]:
            allowed = True
        if "jwk" in ctx["protected"]:
            try:
                allowed = allowed or spki_sha256(jwk_to_key(ctx["jwk"])) == spki_sha256(cert.public_key())
            except JoseError:
                pass
        if not allowed:
            raise Problem("unauthorized", "Nur der Account, der das Zertifikat bestellt hat, oder der "
                                          "Zertifikatsschlüssel darf widerrufen", 403)
        if row["revoked_at"]:
            raise Problem("alreadyRevoked", "Zertifikat ist bereits widerrufen")
        self.pki.revoke(serial, reason, "per ACME")
        self.db.acme_event("revoke", True, f"Zertifikat {serial[:12]}… widerrufen (Grund {reason})",
                           account_id=(ctx["account"] or {}).get("id"), ip=ctx["ip"])
        return Response(status_code=200, headers=self._headers(request))

    async def key_change(self, request: Request) -> Response:
        ctx = await self.verify(request)
        acct = ctx["account"]
        inner_obj = ctx["payload"]
        if not isinstance(inner_obj, dict):
            raise Problem("malformed", "Payload muss eine innere JWS sein")
        try:
            prot, p64, pay64, sig = parse_flattened(json.dumps(inner_obj).encode())
        except JoseError as e:
            raise Problem("malformed", f"Innere JWS: {e}")
        if "jwk" not in prot or "kid" in prot:
            raise Problem("malformed", "Innere JWS muss mit dem neuen Schlüssel (jwk) signiert sein")
        if _norm_url(str(prot.get("url", ""))) != _norm_url(str(request.url)):
            raise Problem("malformed", "url der inneren JWS passt nicht")
        try:
            verify(prot.get("alg"), prot["jwk"], f"{p64}.{pay64}".encode(), sig)
            inner = json.loads(b64d(pay64))
            new_tp = thumbprint(prot["jwk"])
            old_tp = thumbprint(inner.get("oldKey", {}))
        except (JoseError, ValueError, AttributeError) as e:
            raise Problem("malformed", f"Innere JWS ungültig: {e}")
        if str(inner.get("account")) != str(ctx["protected"]["kid"]):
            raise Problem("malformed", "account in der inneren JWS passt nicht zum kid")
        if old_tp != acct["thumbprint"]:
            raise Problem("malformed", "oldKey ist nicht der aktuelle Account-Schlüssel")
        other = self.db.one("SELECT id FROM acme_accounts WHERE thumbprint = ?", (new_tp,))
        if other:
            raise Problem("malformed", "Neuer Schlüssel gehört bereits zu einem Account", 409,
                          headers={"Location": self.url(request, "acct", other["id"])})
        self.db.run("UPDATE acme_accounts SET jwk = ?, thumbprint = ? WHERE id = ?",
                    (dumps(public_jwk(prot["jwk"])), new_tp, acct["id"]))
        self.db.acme_event("account", True, "Account-Schlüssel gewechselt", account_id=acct["id"], ip=ctx["ip"])
        a = self.db.one("SELECT * FROM acme_accounts WHERE id = ?", (acct["id"],))
        return self.json(request, self.account_json(request, a), location=self.url(request, "acct", a["id"]))

    async def not_get(self, request: Request) -> Response:
        return self.problem(request, Problem("malformed", "Bitte POST-as-GET verwenden (RFC 8555 §6.3)", 405))


def _check_contact(contact) -> list[str]:
    if contact is None:
        return []
    if not isinstance(contact, list) or not all(isinstance(c, str) for c in contact):
        raise Problem("invalidContact", "contact muss eine Liste von Strings sein")
    for c in contact:
        if not c.startswith("mailto:") or "@" not in c or len(c) > 320:
            raise Problem("invalidContact", f"Ungültiger Kontakt '{c}' (erwartet mailto:…)")
    return contact[:10]


def create_acme_app(state, extra_routes: list | None = None) -> Starlette:
    srv = AcmeServer(state)
    state.acme = srv

    def wrap(fn):
        async def handler(request: Request) -> Response:
            request.state.client_ip = client_ip(request, state.cfg.trusted_proxies)
            if not ip_allowed(request.state.client_ip, state.cfg.acme_allowed_networks):
                return srv.problem(request, Problem(
                    "unauthorized", f"ACME-Zugriff von {request.state.client_ip} ist nicht erlaubt "
                                    f"(ACME_ALLOWED_NETWORKS)", 403))
            try:
                return await fn(request)
            except Problem as p:
                if p.kind not in ("badNonce",):
                    log.info("ACME %s %s -> %s: %s", request.method, request.url.path, p.kind, p.detail)
                return srv.problem(request, p)
            except Exception as e:
                log.exception("ACME-Fehler")
                return srv.problem(request, Problem("serverInternal", f"Interner Fehler: {e}", 500))
        return handler

    P = ["POST"]
    routes = [
        Route("/acme/directory", wrap(srv.directory), methods=["GET"]),
        Route("/acme/acme/directory", wrap(srv.directory), methods=["GET"]),   # Pfad wie bei step-ca
        Route("/directory", wrap(srv.directory), methods=["GET"]),
        Route("/acme/new-nonce", wrap(srv.new_nonce), methods=["GET", "HEAD"]),
        Route("/acme/new-account", wrap(srv.new_account), methods=P),
        Route("/acme/new-order", wrap(srv.new_order), methods=P),
        Route("/acme/revoke-cert", wrap(srv.revoke_cert), methods=P),
        Route("/acme/key-change", wrap(srv.key_change), methods=P),
        Route("/acme/acct/{id}", wrap(srv.account), methods=P),
        Route("/acme/acct/{id}/orders", wrap(srv.account_orders), methods=P),
        Route("/acme/order/{id}", wrap(srv.order), methods=P),
        Route("/acme/order/{id}/finalize", wrap(srv.finalize), methods=P),
        Route("/acme/authz/{id}", wrap(srv.authz), methods=P),
        Route("/acme/chall/{id}", wrap(srv.challenge), methods=P),
        Route("/acme/cert/{serial}", wrap(srv.certificate), methods=P),
    ]
    for path in ("/acme/order/{id}", "/acme/authz/{id}", "/acme/chall/{id}", "/acme/cert/{serial}"):
        routes.append(Route(path, wrap(srv.not_get), methods=["GET"]))
    routes += extra_routes or []
    return Starlette(routes=routes)
