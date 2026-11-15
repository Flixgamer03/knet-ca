"""Hintergrundaufgaben: Endpunkt-Prüfung, Ablauf-Benachrichtigungen, eigenes TLS-Zertifikat."""
from __future__ import annotations

import logging
import socket
import ssl
import threading
import time
import urllib.request
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .certs import common_name, get_sans
from .db import iso, utcnow


def utcnow_iso() -> str:
    return iso(utcnow())

log = logging.getLogger("knet-ca")


# --- Endpunkte ---------------------------------------------------------------------------

def fetch_endpoint_cert(host: str, port: int, timeout: float = 8.0) -> x509.Certificate:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
    if not der:
        raise ValueError("Kein Zertifikat erhalten")
    return x509.load_der_x509_certificate(der)


def host_matches(host: str, san: str) -> bool:
    host, san = host.lower().rstrip("."), san.lower().rstrip(".")
    if san.startswith("*."):
        return "." in host and host.split(".", 1)[1] == san[2:]
    return host == san


def check_endpoint(app_state, ep: dict) -> dict:
    cfg, db, store = app_state.cfg, app_state.db, app_state.store
    fields: dict = {"last_checked": utcnow_iso()}
    try:
        cert = fetch_endpoint_cert(ep["host"], int(ep["port"]))
    except Exception as e:
        fields.update(status="error", error=f"{type(e).__name__}: {e}"[:400])
        db.update_endpoint(ep["id"], **fields)
        return fields
    inter = store.intermediate()
    ours = False
    if inter is not None:
        try:
            cert.verify_directly_issued_by(inter)
            ours = True
        except Exception:
            ours = False
    sans = get_sans(cert)
    host_ok = any(host_matches(ep["host"], s) for s in sans)
    problems = []
    days_left = (cert.not_valid_after_utc - datetime.now(timezone.utc)).days
    if days_left < 0:
        problems.append("abgelaufen")
    elif days_left < cfg.expiry_warn_days:
        problems.append(f"läuft in {days_left} Tagen ab")
    if not ours:
        problems.append("nicht von dieser CA")
    if not host_ok:
        problems.append("Hostname nicht im Zertifikat")
    fields.update(
        status="error" if days_left < 0 else ("warn" if problems else "ok"),
        serial=str(cert.serial_number), subject=common_name(cert.subject) or cert.subject.rfc4514_string(),
        issuer=common_name(cert.issuer) or cert.issuer.rfc4514_string(),
        not_after=cert.not_valid_after_utc.isoformat(timespec="seconds"), ours=1 if ours else 0,
        error=", ".join(problems),
    )
    db.update_endpoint(ep["id"], **fields)
    return fields


def check_all_endpoints(app_state) -> None:
    for ep in app_state.db.endpoints():
        try:
            check_endpoint(app_state, ep)
        except Exception:
            log.exception("Endpunkt-Prüfung fehlgeschlagen: %s", ep)


# --- Benachrichtigungen ---------------------------------------------------------------------

def send_ntfy(cfg, title: str, message: str, priority: str = "default", tags: str = "lock") -> None:
    if not cfg.ntfy_url:
        raise RuntimeError("NTFY_URL ist nicht gesetzt.")
    headers = {"Title": title.encode("utf-8").decode("latin-1", "replace"), "Priority": priority, "Tags": tags,
               "Content-Type": "text/plain; charset=utf-8"}
    if cfg.ntfy_token:
        headers["Authorization"] = f"Bearer {cfg.ntfy_token}"
    req = urllib.request.Request(cfg.ntfy_url, data=message.encode("utf-8"), headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=15) as r:
        r.read()


def expiry_report(app_state) -> list[str]:
    cfg = app_state.cfg
    lines = []
    for c in app_state.store.all():
        if c.superseded_by or c.is_ca:
            continue
        st = c.status(cfg.expiry_warn_days)
        if st == "expiring":
            lines.append(f"• {c.display_name}: läuft in {c.days_left} Tagen ab ({c.via})")
        elif st == "expired" and c.not_after > datetime.now(timezone.utc) - timedelta(days=7):
            lines.append(f"• {c.display_name}: seit {-c.days_left} Tagen abgelaufen ({c.via})")
    for ep in app_state.db.endpoints():
        if ep["status"] in ("warn", "error"):
            lines.append(f"• Endpunkt {ep['host']}:{ep['port']}: {ep['error'] or ep['status']}")
    return lines


def notify_expiring(app_state) -> int:
    if not app_state.cfg.ntfy_url:
        return 0
    lines = expiry_report(app_state)
    if lines:
        send_ntfy(app_state.cfg, f"{app_state.cfg.ca_name}: {len(lines)} Zertifikat(e) brauchen Aufmerksamkeit",
                  "\n".join(lines) + f"\n\n{app_state.cfg.webui_public_url}", priority="high", tags="warning,lock")
    return len(lines)


# --- Eigenes TLS-Zertifikat (ACME-Port und Web-GUI) -------------------------------------------

def ensure_server_cert(state) -> bool:
    """Stellt ein gültiges Server-Zertifikat sicher. True, wenn neu ausgestellt."""
    cfg, pki = state.cfg, state.pki
    want = cfg.server_names
    if cfg.tls_cert_path.exists() and cfg.tls_key_path.exists():
        try:
            cur = x509.load_pem_x509_certificate(cfg.tls_cert_path.read_bytes())
            life = cur.not_valid_after_utc - cur.not_valid_before_utc
            left = cur.not_valid_after_utc - datetime.now(timezone.utc)
            if left > life / 3 and sorted(get_sans(cur)) == sorted(want) and cur.issuer == pki.intermediate.subject:
                cur.verify_directly_issued_by(pki.intermediate)
                return False
        except Exception:
            pass
    key = ec.generate_private_key(ec.SECP256R1())
    cert = pki.issue(key.public_key(), want, 90, source="system", requester="CA-Server", max_days=90)
    cfg.tls_cert_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_key = cfg.tls_key_path.with_name(cfg.tls_key_path.name + ".tmp")
    tmp_key.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    tmp_key.chmod(0o600)
    tmp_crt = cfg.tls_cert_path.with_name(cfg.tls_cert_path.name + ".tmp")
    tmp_crt.write_bytes(cert.public_bytes(serialization.Encoding.PEM) +
                        pki.intermediate.public_bytes(serialization.Encoding.PEM))
    tmp_key.replace(cfg.tls_key_path)
    tmp_crt.replace(cfg.tls_cert_path)
    log.info("Server-Zertifikat ausgestellt (%s)", ", ".join(want))
    return True


# --- Scheduler ------------------------------------------------------------------------------

def start_background(app_state, ssl_ctxs=()) -> None:
    cfg = app_state.cfg

    def loop():
        time.sleep(30)
        last_notify = 0.0
        last_endpoints = 0.0
        while True:
            t = time.time()
            try:
                if t - last_endpoints >= cfg.endpoint_check_hours * 3600:
                    check_all_endpoints(app_state)
                    last_endpoints = t
                if t - last_notify >= 24 * 3600:
                    n = notify_expiring(app_state)
                    if n:
                        log.info("Benachrichtigung gesendet (%d Einträge)", n)
                    last_notify = t
                if ensure_server_cert(app_state):
                    for ctx in ssl_ctxs:
                        ctx.load_cert_chain(str(cfg.tls_cert_path), str(cfg.tls_key_path))
                    log.info("Neues TLS-Zertifikat geladen")
            except Exception:
                log.exception("Hintergrundaufgabe fehlgeschlagen")
            time.sleep(600)

    threading.Thread(target=loop, name="background", daemon=True).start()
