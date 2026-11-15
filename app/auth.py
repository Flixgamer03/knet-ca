"""Zugriffskontrolle für die Web-GUI.

Immer aktiv: IP-Allowlist (ALLOWED_NETWORKS) und CSRF-Schutz für POST-Requests.
Dazu ein Login-Modus (AUTH_MODE):
  none   – kein Login, nur die IP-Allowlist
  oidc   – Login per OpenID Connect (z. B. Authentik), optional auf Gruppen beschränkt
  proxy  – Reverse-Proxy mit Forward-Auth (z. B. Authentik-Outpost) setzt Header
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import secrets
import ssl
import time
import urllib.parse
import urllib.request

from starlette.concurrency import run_in_threadpool
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response

PUBLIC_PREFIXES = ("/public/", "/static/", "/healthz", "/health", "/metrics", "/crl", "/1.0/crl", "/roots.pem")


def client_ip(request: Request, trusted_proxies: list) -> str:
    peer = request.client.host if request.client else "0.0.0.0"
    try:
        peer_ip = ipaddress.ip_address(peer)
    except ValueError:
        return peer
    if trusted_proxies and any(peer_ip in n for n in trusted_proxies):
        xff = request.headers.get("x-forwarded-for", "")
        hops = [h.strip() for h in xff.split(",") if h.strip()]
        # von rechts nach links: erster Eintrag, der kein vertrauenswürdiger Proxy ist
        for hop in reversed(hops):
            try:
                ip = ipaddress.ip_address(hop)
            except ValueError:
                break
            if not any(ip in n for n in trusted_proxies):
                return str(ip)
        if hops:
            return hops[0]
    return str(peer_ip)


def ip_allowed(ip: str, networks: list) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return any(addr in n for n in networks)


def csrf_token(request: Request) -> str:
    tok = request.session.get("csrf")
    if not tok:
        tok = secrets.token_urlsafe(32)
        request.session["csrf"] = tok
    return tok


def _forbidden(msg: str, status: int = 403) -> HTMLResponse:
    return HTMLResponse(
        f"<!doctype html><meta charset=utf-8><title>Kein Zugriff</title>"
        f"<body style='font-family:system-ui;padding:3rem;max-width:40rem'>"
        f"<h1>Kein Zugriff</h1><p>{msg}</p></body>", status_code=status)


class CSRFError(Exception):
    pass


async def checked_form(request: Request):
    """Formular lesen und CSRF-Token prüfen (für alle POST-Handler)."""
    form = await request.form()
    sent = str(form.get("csrf", ""))
    if not sent or not secrets.compare_digest(sent, request.session.get("csrf", "")):
        raise CSRFError()
    return form


class AccessMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, cfg):
        super().__init__(app)
        self.cfg = cfg

    async def dispatch(self, request: Request, call_next) -> Response:
        cfg = self.cfg
        path = request.url.path
        ip = client_ip(request, cfg.trusted_proxies)
        request.state.client_ip = ip
        request.state.user = None

        if path.startswith(PUBLIC_PREFIXES):
            return await call_next(request)

        if not ip_allowed(ip, cfg.allowed_networks):
            return _forbidden(f"Zugriff von {ip} ist nicht erlaubt (ALLOWED_NETWORKS).")

        if cfg.auth_mode == "none":
            request.state.user = {"name": f"lokal ({ip})", "groups": []}
        elif cfg.auth_mode == "proxy":
            peer = request.client.host if request.client else ""
            if not ip_allowed(peer, cfg.trusted_proxies):
                return _forbidden("Direktzugriff nicht erlaubt – bitte über den Reverse-Proxy aufrufen.")
            name = request.headers.get(cfg.proxy_user_header)
            if not name:
                return _forbidden(f"Header {cfg.proxy_user_header} fehlt – läuft der Zugriff über den Proxy?", 401)
            groups = [g for g in request.headers.get(cfg.proxy_groups_header, "").split("|") if g]
            request.state.user = {"name": name, "groups": groups}
        else:  # oidc
            if path.startswith("/auth/"):
                return await call_next(request)
            user = request.session.get("user")
            if not user or user.get("exp", 0) < time.time():
                request.session.pop("user", None)
                if request.method == "GET":
                    request.session["next"] = str(request.url.path) + (f"?{request.url.query}" if request.url.query else "")
                return RedirectResponse("/auth/login", status_code=303)
            request.state.user = user

        return await call_next(request)


# --- OIDC (Authorization Code Flow mit PKCE, nur Standardbibliothek) ---------------------

class OIDCClient:
    def __init__(self, cfg):
        self.cfg = cfg
        self._meta: dict | None = None
        self._meta_ts = 0.0
        self._ctx = ssl.create_default_context(cafile=cfg.oidc_ca_bundle or None)

    def _get_json(self, url: str, headers: dict | None = None, data: bytes | None = None) -> dict:
        req = urllib.request.Request(url, data=data, headers={"Accept": "application/json", **(headers or {})})
        with urllib.request.urlopen(req, timeout=15, context=self._ctx) as r:
            return json.loads(r.read())

    def metadata(self) -> dict:
        if self._meta is None or time.time() - self._meta_ts > 3600:
            url = self.cfg.oidc_issuer.rstrip("/") + "/.well-known/openid-configuration"
            self._meta = self._get_json(url)
            self._meta_ts = time.time()
        return self._meta

    @property
    def redirect_uri(self) -> str:
        return f"{self.cfg.webui_public_url}/auth/callback"

    def authorize_url(self, session: dict) -> str:
        meta = self.metadata()
        state, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
        verifier = secrets.token_urlsafe(64)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        session["oidc"] = {"state": state, "nonce": nonce, "verifier": verifier, "ts": time.time()}
        q = {
            "response_type": "code", "client_id": self.cfg.oidc_client_id, "redirect_uri": self.redirect_uri,
            "scope": self.cfg.oidc_scopes, "state": state, "nonce": nonce,
            "code_challenge": challenge, "code_challenge_method": "S256",
        }
        return meta["authorization_endpoint"] + "?" + urllib.parse.urlencode(q)

    def finish(self, session: dict, params: dict) -> dict:
        pending = session.pop("oidc", None)
        if not pending or time.time() - pending["ts"] > 600:
            raise PermissionError("Login-Sitzung abgelaufen – bitte erneut anmelden.")
        if params.get("error"):
            raise PermissionError(f"Login abgelehnt: {params.get('error_description') or params['error']}")
        if not secrets.compare_digest(params.get("state", ""), pending["state"]):
            raise PermissionError("Ungültiger state-Parameter.")
        meta = self.metadata()
        body = urllib.parse.urlencode({
            "grant_type": "authorization_code", "code": params.get("code", ""),
            "redirect_uri": self.redirect_uri, "code_verifier": pending["verifier"],
            "client_id": self.cfg.oidc_client_id, "client_secret": self.cfg.oidc_client_secret,
        }).encode()
        tok = self._get_json(meta["token_endpoint"], {"Content-Type": "application/x-www-form-urlencoded"}, body)
        claims = _jwt_claims(tok.get("id_token", ""))
        # Das ID-Token kommt direkt per TLS vom Token-Endpunkt (OIDC Core 3.1.3.7, Punkt 6),
        # daher genügen hier die Claim-Prüfungen.
        if claims.get("iss", "").rstrip("/") != meta.get("issuer", "").rstrip("/"):
            raise PermissionError("ID-Token: falscher Issuer.")
        aud = claims.get("aud")
        if self.cfg.oidc_client_id not in (aud if isinstance(aud, list) else [aud]):
            raise PermissionError("ID-Token: falsche Audience.")
        if claims.get("nonce") != pending["nonce"]:
            raise PermissionError("ID-Token: falsche Nonce.")
        if claims.get("exp", 0) < time.time() - 60:
            raise PermissionError("ID-Token abgelaufen.")
        info = dict(claims)
        if meta.get("userinfo_endpoint") and tok.get("access_token"):
            try:
                info.update(self._get_json(meta["userinfo_endpoint"],
                                           {"Authorization": f"Bearer {tok['access_token']}"}))
            except Exception:
                pass
        groups = info.get("groups") or []
        if isinstance(groups, str):
            groups = [groups]
        allowed = self.cfg.oidc_allowed_groups
        if allowed and not set(allowed) & set(groups):
            raise PermissionError("Dein Konto ist nicht in einer der erlaubten Gruppen: " + ", ".join(allowed))
        name = info.get("preferred_username") or info.get("email") or info.get("sub")
        return {"name": name, "email": info.get("email", ""), "groups": groups,
                "exp": time.time() + 12 * 3600, "id_token": tok.get("id_token", "")}

    def logout_url(self, id_token: str) -> str | None:
        try:
            end = self.metadata().get("end_session_endpoint")
        except Exception:
            return None
        if not end:
            return None
        q = {"post_logout_redirect_uri": self.cfg.webui_public_url + "/"}
        if id_token:
            q["id_token_hint"] = id_token
        return end + "?" + urllib.parse.urlencode(q)


def _jwt_claims(token: str) -> dict:
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception as e:
        raise PermissionError("Kein gültiges ID-Token erhalten.") from e


def oidc_routes(cfg):
    from starlette.routing import Route
    client = OIDCClient(cfg)

    async def login(request: Request):
        try:
            url = await run_in_threadpool(client.authorize_url, request.session)
        except Exception as e:
            return PlainTextResponse(f"OIDC-Provider nicht erreichbar: {e}", status_code=502)
        return RedirectResponse(url, status_code=303)

    async def callback(request: Request):
        try:
            user = await run_in_threadpool(client.finish, request.session, dict(request.query_params))
        except PermissionError as e:
            return _forbidden(f"{e} <p><a href='/auth/login'>Erneut anmelden</a></p>")
        except Exception as e:
            return PlainTextResponse(f"Fehler beim Login: {e}", status_code=502)
        user.pop("id_token", None)  # nicht im Cookie speichern (Größe)
        request.session["user"] = user
        request.app.state.db.audit(user["name"], request.state.client_ip, "login")
        nxt = request.session.pop("next", "/")
        if not nxt.startswith("/") or nxt.startswith("//"):
            nxt = "/"
        return RedirectResponse(nxt, status_code=303)

    async def logout(request: Request):
        request.session.clear()
        url = await run_in_threadpool(client.logout_url, "")
        return RedirectResponse(url or "/", status_code=303)

    return [Route("/auth/login", login), Route("/auth/callback", callback), Route("/auth/logout", logout)]
