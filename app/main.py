"""Web-GUI für die knet-ca (Starlette)."""
from __future__ import annotations

import base64
import json
import ipaddress
import logging
import re
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.middleware import Middleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse, RedirectResponse, Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates

from . import tasks
from .auth import AccessMiddleware, CSRFError, checked_form, csrf_token, oidc_routes
from .certs import (REVOCATION_REASONS, STATUS_LABELS, CertStore, Constraints, analyze_csr, common_name,
                    fingerprint_sha256, fmt_fp, get_sans, key_description, pem, sha256_hex, split_pem, eku_list)
from .config import get_config
from .db import Database, parse_iso
from .pki import PKI, IssueError

log = logging.getLogger("knet-ca")
BASE = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE / "templates"))
templates.env.filters["fp"] = fmt_fp
templates.env.filters["dt"] = lambda d: d.astimezone().strftime("%d.%m.%Y %H:%M") if d else ""
templates.env.filters["d"] = lambda d: d.astimezone().strftime("%d.%m.%Y") if d else ""
templates.env.filters["isodt"] = lambda s: (datetime.fromisoformat(s).astimezone().strftime("%d.%m.%Y %H:%M")
                                           if s else "")
templates.env.globals["STATUS_LABELS"] = STATUS_LABELS
templates.env.globals["REASONS"] = REVOCATION_REASONS

VALIDITY_CHOICES = [30, 90, 180, 365, 730, 825]


class State:
    """Gemeinsamer Zustand (Konfiguration, DB, CA)."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.db = Database(cfg.db_path)
        self.pki = PKI(cfg, self.db)
        self.store = CertStore(self.db, self.pki)
        self.acme = None

    def root(self) -> x509.Certificate:
        return self.pki.root

    def constraints(self) -> Constraints:
        return self.pki.constraints

    def user(self, request) -> str:
        return (request.state.user or {}).get("name", "?")


def st(request: Request) -> State:
    return request.app.state.ca


def render(request: Request, template: str, status_code: int = 200, headers: dict | None = None, **ctx) -> Response:
    s = st(request)
    ctx.update(cfg=s.cfg, user=request.state.user, csrf=csrf_token(request), path=request.url.path,
               auth_mode=s.cfg.auth_mode)
    return templates.TemplateResponse(request, template, ctx, status_code=status_code, headers=headers)


def audit(request: Request, action: str, serial: str | None = None, details: str = "") -> None:
    user = (request.state.user or {}).get("name", "?")
    try:
        st(request).db.audit(user, request.state.client_ip, action, serial, details)
    except Exception:
        log.exception("Audit-Eintrag fehlgeschlagen")


def safe_name(s: str) -> str:
    s = s.replace("*", "wildcard")
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s).strip("_") or "zertifikat"


def clamp_days(cfg, raw) -> int:
    try:
        d = int(raw)
    except (TypeError, ValueError):
        d = cfg.manual_default_days
    return max(1, min(d, cfg.manual_max_days))


def validity_choices(cfg) -> list[int]:
    ch = sorted(set([d for d in VALIDITY_CHOICES if d <= cfg.manual_max_days] + [cfg.manual_default_days]))
    return ch


# --- Übersicht ------------------------------------------------------------------------------------

async def dashboard(request: Request):
    s = st(request)
    certs = await run_in_threadpool(s.store.all)
    warn = s.cfg.expiry_warn_days
    current = [c for c in certs if not c.superseded_by and not c.is_ca]
    counts = {k: 0 for k in STATUS_LABELS}
    for c in current:
        counts[c.status(warn)] += 1
    attention = sorted([c for c in current if c.status(warn) in ("expiring", "expired")
                        and c.days_left > -30], key=lambda c: c.not_after)
    endpoints = await run_in_threadpool(s.db.endpoints)
    ep_problems = [e for e in endpoints if e["status"] in ("warn", "error")]
    inter = s.store.intermediate()
    return render(request, "dashboard.html", counts=counts, attention=attention, recent=certs[:8],
                  total=len(certs), current_total=len(current), endpoints=endpoints, ep_problems=ep_problems,
                  root=s.root(), inter=inter, constraints=s.constraints(), warn=warn,
                  fingerprint=fingerprint_sha256(s.root()))


# --- Zertifikate ------------------------------------------------------------------------------------

async def cert_list(request: Request):
    s = st(request)
    q = (request.query_params.get("q") or "").strip().lower()
    status = request.query_params.get("status", "")
    via = request.query_params.get("via", "")
    show_all = request.query_params.get("all") == "1"
    warn = s.cfg.expiry_warn_days
    certs = await run_in_threadpool(s.store.all)
    out = []
    for c in certs:
        if not show_all and c.superseded_by:
            continue
        if status and c.status(warn) != status:
            continue
        if via == "acme" and c.via != "ACME":
            continue
        if via == "manual" and c.via == "ACME":
            continue
        if q and q not in " ".join([c.cn, c.serial, c.serial_hex.replace(":", ""), *c.sans]).lower():
            continue
        out.append(c)
    sort = request.query_params.get("sort", "issued")
    if sort == "expiry":
        out.sort(key=lambda c: c.not_after)
    elif sort == "name":
        out.sort(key=lambda c: c.display_name.lower())
    return render(request, "certs.html", certs=out, q=q, status=status, via=via, show_all=show_all,
                  sort=sort, warn=warn, total=len(certs))


async def cert_detail(request: Request):
    s = st(request)
    serial = request.path_params["serial"]
    c = await run_in_threadpool(s.store.get, serial)
    if c is None:
        return render(request, "error.html", status_code=404, title="Nicht gefunden",
                      message=f"Kein Zertifikat mit Seriennummer {serial}.")
    inter = s.store.intermediate()
    history = [x for x in await run_in_threadpool(s.store.all)
               if x.serial != c.serial and sorted(x.sans) == sorted(c.sans) and x.sans]
    return render(request, "cert_detail.html", c=c, pem_text=pem(c.cert),
                  chain_text=pem(inter) if inter else "", warn=s.cfg.expiry_warn_days, ekus=eku_list(c.cert),
                  history=history[:20], new=request.query_params.get("new") == "1",
                  revoke_error=request.query_params.get("error"))


async def cert_download(request: Request):
    s = st(request)
    serial, kind = request.path_params["serial"], request.path_params["kind"]
    c = await run_in_threadpool(s.store.get, serial)
    if c is None:
        return PlainTextResponse("Nicht gefunden", status_code=404)
    inter = s.store.intermediate()
    name = safe_name(c.display_name)
    leaf_pem = pem(c.cert)
    inter_pem = pem(inter) if inter else ""
    if kind == "cert":
        body, fn, mt = leaf_pem, f"{name}.crt", "application/x-pem-file"
    elif kind == "fullchain":
        body, fn, mt = leaf_pem + inter_pem, f"{name}.fullchain.pem", "application/x-pem-file"
    elif kind == "chain":
        body, fn, mt = inter_pem, f"{name}.chain.pem", "application/x-pem-file"
    elif kind == "der":
        body, fn, mt = c.cert.public_bytes(serialization.Encoding.DER), f"{name}.cer", "application/pkix-cert"
    else:
        return PlainTextResponse("Unbekannter Typ", status_code=404)
    return Response(body, media_type=mt, headers={"Content-Disposition": f'attachment; filename="{fn}"'})


async def cert_revoke(request: Request):
    s = st(request)
    serial = request.path_params["serial"]
    form = await checked_form(request)
    try:
        code = int(form.get("reason_code", "0"))
    except ValueError:
        code = 0
    if code not in REVOCATION_REASONS:
        code = 0
    reason = str(form.get("reason", ""))[:200]
    if form.get("confirm") != "yes":
        return RedirectResponse(f"/certs/{serial}?error=Bitte+Widerruf+bestätigen", status_code=303)
    try:
        await run_in_threadpool(s.pki.revoke, serial, code, reason)
    except IssueError as e:
        return RedirectResponse(f"/certs/{serial}?error=" + _q(str(e)), status_code=303)
    audit(request, "revoke", serial, f"{REVOCATION_REASONS[code]}{': ' + reason if reason else ''}")
    return RedirectResponse(f"/certs/{serial}", status_code=303)


def _q(s: str) -> str:
    from urllib.parse import quote_plus
    return quote_plus(s[:500])


# --- CSR signieren ---------------------------------------------------------------------------------

async def sign_form(request: Request):
    return render(request, "sign.html", step="upload", choices=validity_choices(st(request).cfg))


async def sign_preview(request: Request):
    s = st(request)
    form = await checked_form(request)
    data = b""
    up = form.get("csr_file")
    if up is not None and hasattr(up, "read"):
        data = await up.read()
    if not data.strip():
        data = str(form.get("csr_text", "")).encode()
    if not data.strip():
        return render(request, "sign.html", step="upload", error="Bitte einen CSR hochladen oder einfügen.",
                      choices=validity_choices(s.cfg))
    try:
        info = analyze_csr(data, s.constraints())
    except ValueError as e:
        return render(request, "sign.html", step="upload", error=f"Konnte den CSR nicht lesen: {e}",
                      choices=validity_choices(s.cfg))
    return render(request, "sign.html", step="preview", info=info, choices=validity_choices(s.cfg))


async def sign_issue(request: Request):
    s = st(request)
    form = await checked_form(request)
    csr_pem = str(form.get("csr_pem", ""))
    days = clamp_days(s.cfg, form.get("days"))
    try:
        info = analyze_csr(csr_pem.encode(), s.constraints())
    except ValueError as e:
        return render(request, "sign.html", step="upload", error=str(e), choices=validity_choices(s.cfg))
    if info.errors:
        return render(request, "sign.html", step="preview", info=info, choices=validity_choices(s.cfg))
    names = [n for n in info.sans if not n.startswith(("email:", "uri:"))]
    try:
        cert = await run_in_threadpool(lambda: s.pki.issue_csr(info.csr, names, days, source="webui",
                                                               requester=s.user(request)))
    except IssueError as e:
        return render(request, "sign.html", step="preview", info=info, choices=validity_choices(s.cfg),
                      error=f"Signieren abgelehnt: {e}")
    serial = format(cert.serial_number, "x")
    audit(request, "sign-csr", serial, f"{', '.join(info.sans)} · {days} Tage")
    return RedirectResponse(f"/certs/{serial}?new=1", status_code=303)


# --- Schlüssel + Zertifikat erzeugen ------------------------------------------------------------------

KEY_TYPES = {
    "ec256": ("EC P-256 (empfohlen)", lambda: ec.generate_private_key(ec.SECP256R1())),
    "ec384": ("EC P-384", lambda: ec.generate_private_key(ec.SECP384R1())),
    "rsa2048": ("RSA 2048 (maximale Kompatibilität)", lambda: rsa.generate_private_key(65537, 2048)),
    "rsa3072": ("RSA 3072", lambda: rsa.generate_private_key(65537, 3072)),
    "rsa4096": ("RSA 4096", lambda: rsa.generate_private_key(65537, 4096)),
}


def parse_names(cn: str, raw: str) -> list[str]:
    names = []
    for part in re.split(r"[\s,;]+", raw or ""):
        part = part.strip().lower().rstrip(".")
        if part and part not in names:
            names.append(part)
    cn = cn.strip().lower()
    if cn:
        names = [cn] + [n for n in names if n != cn]
    return names


def build_csr(key, cn: str, names: list[str], org: str = ""):
    gn = []
    for n in names:
        try:
            gn.append(x509.IPAddress(ipaddress.ip_address(n)))
        except ValueError:
            if not re.fullmatch(r"(\*\.)?[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)*", n):
                raise ValueError(f"Ungültiger Name: {n}")
            gn.append(x509.DNSName(n))
    attrs = [x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, cn)]
    if org:
        attrs.append(x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, org))
    return (x509.CertificateSigningRequestBuilder().subject_name(x509.Name(attrs))
            .add_extension(x509.SubjectAlternativeName(gn), critical=False).sign(key, hashes.SHA256()))


async def generate_form(request: Request):
    cfg = st(request).cfg
    return render(request, "generate.html", key_types=KEY_TYPES, choices=validity_choices(cfg), form={},
                  default_days=cfg.manual_default_days, constraints=st(request).constraints())


async def generate_issue(request: Request):
    s = st(request)
    form = await checked_form(request)
    f = {k: str(v) for k, v in form.items() if k != "csrf"}
    cn = f.get("cn", "").strip().lower()
    names = parse_names(cn, f.get("sans", ""))
    days = clamp_days(s.cfg, f.get("days"))
    kt = f.get("key_type", "ec256")
    p12_pw = f.get("p12_password", "")

    def fail(msg):
        return render(request, "generate.html", key_types=KEY_TYPES, choices=validity_choices(s.cfg), form=f,
                      error=msg, default_days=days, constraints=s.constraints())

    if not cn:
        return fail("Bitte einen Hostnamen (Common Name) angeben.")
    if kt not in KEY_TYPES:
        return fail("Unbekannter Schlüsseltyp.")
    key = await run_in_threadpool(KEY_TYPES[kt][1])
    try:
        csr = build_csr(key, cn, names, f.get("org", "").strip())
    except ValueError as e:
        return fail(str(e))
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
    info = analyze_csr(csr_pem.encode(), s.constraints())
    if info.errors:
        return fail(" ".join(info.errors))
    try:
        leaf = await run_in_threadpool(lambda: s.pki.issue(key.public_key(), names, days, source="webui",
                                                           requester=s.user(request)))
    except IssueError as e:
        return fail(f"Signieren abgelehnt: {e}")
    inter = s.store.intermediate()
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()).decode()
    p12_b64 = ""
    if p12_pw:
        if f.get("p12_legacy") == "1":
            enc = (serialization.PrivateFormat.PKCS12.encryption_builder().kdf_rounds(50000)
                   .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC).hmac_hash(hashes.SHA1())
                   .build(p12_pw.encode()))
        else:
            enc = serialization.BestAvailableEncryption(p12_pw.encode())
        p12 = pkcs12.serialize_key_and_certificates(cn.encode(), key, leaf, [inter] if inter else None, enc)
        p12_b64 = base64.b64encode(p12).decode()
    audit(request, "generate", format(leaf.serial_number, "x"), f"{', '.join(names)} · {KEY_TYPES[kt][0]} · {days} Tage")
    return render(request, "generate_result.html", headers={"Cache-Control": "no-store"},
                  serial=format(leaf.serial_number, "x"), name=safe_name(cn), key_pem=key_pem, cert_pem=pem(leaf),
                  fullchain_pem=pem(leaf) + (pem(inter) if inter else ""), p12_b64=p12_b64, names=names,
                  not_after=leaf.not_valid_after_utc)


# --- Endpunkte ---------------------------------------------------------------------------------------

async def endpoints_page(request: Request):
    s = st(request)
    eps = await run_in_threadpool(s.db.endpoints)
    return render(request, "endpoints.html", endpoints=eps, prefill=request.query_params.get("host", ""))


async def endpoint_add(request: Request):
    s = st(request)
    form = await checked_form(request)
    host = str(form.get("host", "")).strip().lower()
    label = str(form.get("label", "")).strip()[:100]
    try:
        port = int(form.get("port") or 443)
    except ValueError:
        port = 443
    if ":" in host and host.count(":") == 1:
        host, p = host.split(":")
        port = int(p) if p.isdigit() else port
    if not host or not re.fullmatch(r"[a-z0-9._-]+|[0-9a-f:]+", host) or not (0 < port < 65536):
        return RedirectResponse("/endpoints", status_code=303)
    await run_in_threadpool(s.db.add_endpoint, host, port, label)
    eps = [e for e in await run_in_threadpool(s.db.endpoints) if e["host"] == host and e["port"] == port]
    if eps:
        await run_in_threadpool(tasks.check_endpoint, s, eps[-1])
    audit(request, "endpoint-add", None, f"{host}:{port}")
    return RedirectResponse("/endpoints", status_code=303)


async def endpoint_action(request: Request):
    s = st(request)
    await checked_form(request)
    ep_id, action = int(request.path_params["id"]), request.path_params["action"]
    ep = await run_in_threadpool(s.db.endpoint, ep_id)
    if ep is not None:
        if action == "check":
            await run_in_threadpool(tasks.check_endpoint, s, ep)
        elif action == "delete":
            await run_in_threadpool(s.db.delete_endpoint, ep_id)
            audit(request, "endpoint-delete", None, f"{ep['host']}:{ep['port']}")
    return RedirectResponse("/endpoints", status_code=303)


async def endpoints_check_all(request: Request):
    await checked_form(request)
    await run_in_threadpool(tasks.check_all_endpoints, st(request))
    return RedirectResponse("/endpoints", status_code=303)


# --- Vertrauen / Einrichtung ---------------------------------------------------------------------------

async def trust_page(request: Request):
    s = st(request)
    root = s.root()
    root_file = s.cfg.root_path.read_bytes()
    return render(request, "trust.html", root=root, fingerprint=fingerprint_sha256(root),
                  file_sha=sha256_hex(root_file), inter=s.store.intermediate(), constraints=s.constraints(),
                  base=safe_name(s.cfg.ca_name))


# --- Werkzeuge -------------------------------------------------------------------------------------------

def decode_blocks(data: bytes, s: State) -> list[dict]:
    inter = s.store.intermediate()
    root = s.root()
    out = []
    blocks = split_pem(data)
    if not blocks and data.strip():
        blocks = [("?", data)]
    for label, block in blocks:
        item: dict = {"label": label}
        try:
            if label == "CERTIFICATE":
                c = x509.load_pem_x509_certificate(block)
                ours = "nein"
                for issuer, txt in ((inter, "ja (Intermediate dieser CA)"), (root, "ja (Root dieser CA)")):
                    if issuer is None:
                        continue
                    try:
                        c.verify_directly_issued_by(issuer)
                        ours = txt
                        break
                    except Exception:
                        pass
                if c.fingerprint(hashes.SHA256()) == root.fingerprint(hashes.SHA256()):
                    ours = "das ist die Root-CA"
                item.update(kind="Zertifikat", cn=common_name(c.subject), subject=c.subject.rfc4514_string(),
                            issuer=c.issuer.rfc4514_string(), sans=get_sans(c), not_before=c.not_valid_before_utc,
                            not_after=c.not_valid_after_utc, key=key_description(c.public_key()),
                            serial=str(c.serial_number), fingerprint=fingerprint_sha256(c), ours=ours,
                            ekus=eku_list(c))
            elif "CERTIFICATE REQUEST" in label:
                info = analyze_csr(block, s.constraints())
                item.update(kind="CSR", cn=info.cn, subject=info.subject, sans=info.sans, key=info.key,
                            warnings=info.warnings, errors=info.errors)
            elif "PRIVATE KEY" in label:
                item.update(kind="Privater Schlüssel",
                            note="Wird nicht angezeigt. Private Schlüssel gehören nicht in Formulare – auch nicht hier.")
                if "ENCRYPTED" not in label:
                    try:
                        k = serialization.load_pem_private_key(block, None)
                        item["key"] = key_description(k.public_key())
                    except Exception:
                        pass
            else:
                item.update(kind=label, note="Typ wird nicht ausgewertet.")
        except Exception as e:
            item.update(kind=label, error=str(e))
        out.append(item)
    return out


async def tools_page(request: Request):
    return render(request, "tools.html", results=None, text="")


async def tools_decode(request: Request):
    s = st(request)
    form = await checked_form(request)
    text = str(form.get("text", ""))
    up = form.get("file")
    data = text.encode()
    if up is not None and hasattr(up, "read"):
        fdata = await up.read()
        if fdata.strip():
            data = fdata
            if b"-----BEGIN" not in fdata:
                # DER: Zertifikat oder CSR?
                try:
                    data = x509.load_der_x509_certificate(fdata).public_bytes(serialization.Encoding.PEM)
                except ValueError:
                    try:
                        data = x509.load_der_x509_csr(fdata).public_bytes(serialization.Encoding.PEM)
                    except ValueError:
                        pass
    results = await run_in_threadpool(decode_blocks, data, s)
    return render(request, "tools.html", results=results, text=text if "PRIVATE KEY" not in text else "")


async def tools_notify(request: Request):
    s = st(request)
    await checked_form(request)
    try:
        lines = await run_in_threadpool(tasks.expiry_report, s)
        await run_in_threadpool(tasks.send_ntfy, s.cfg, f"{s.cfg.ca_name}: Testbenachrichtigung",
                                "Die Benachrichtigungen funktionieren.\n\nAktueller Stand:\n" +
                                ("\n".join(lines) if lines else "Alles in Ordnung."))
        msg, ok = "Testbenachrichtigung gesendet.", True
    except Exception as e:
        msg, ok = f"Senden fehlgeschlagen: {e}", False
    return render(request, "tools.html", results=None, text="", notify_msg=msg, notify_ok=ok)


# --- Protokoll ---------------------------------------------------------------------------------------------

async def audit_page(request: Request):
    entries = await run_in_threadpool(st(request).db.audit_entries, 500)
    return render(request, "audit.html", entries=entries)


# --- Öffentliche Endpunkte (auf allen Ports) ---------------------------------------------------

def public_routes(state: "State") -> list:
    cfg = state.cfg
    base = safe_name(cfg.ca_name)

    def dl(body, mt, fn):
        return Response(body, media_type=mt, headers={"Content-Disposition": f'attachment; filename="{fn}"'})

    async def public_file(request: Request):
        name = request.path_params["name"]
        pki = state.pki
        root_pem = pem(pki.root).encode()
        inter_pem = pem(pki.intermediate).encode()
        if name == "root_ca.crt":
            return dl(root_pem, "application/x-pem-file", f"{base}-root.crt")
        if name == "root_ca.cer":
            return dl(pki.root.public_bytes(serialization.Encoding.DER), "application/pkix-cert", f"{base}-root.cer")
        if name == "intermediate_ca.crt":
            return dl(inter_pem, "application/x-pem-file", f"{base}-intermediate.crt")
        if name == "intermediate_ca.der":
            return Response(pki.intermediate.public_bytes(serialization.Encoding.DER), media_type="application/pkix-cert")
        if name == "ca_chain.pem":
            return dl(inter_pem + root_pem, "application/x-pem-file", f"{base}-chain.pem")
        if name == "bootstrap.sh":
            body = templates.get_template("bootstrap.sh.j2").render(cfg=cfg, root_pem=root_pem.decode().strip(),
                                                                     base=base)
            return Response(body, media_type="text/x-shellscript")
        return PlainTextResponse("Nicht gefunden", status_code=404)

    async def crl(request: Request):
        der = await run_in_threadpool(state.pki.crl_der)
        return Response(der, media_type="application/pkix-crl")

    async def roots_pem(request: Request):
        return Response(pem(state.pki.root), media_type="application/x-pem-file")

    async def health(request: Request):
        return PlainTextResponse("ok")

    async def index(request: Request):
        return PlainTextResponse(f"{cfg.ca_name}\n\nACME-Directory: {cfg.acme_directory}\n"
                                 f"Root-CA:        {cfg.public_http_url or cfg.ca_public_url}/public/root_ca.crt\n"
                                 f"Web-GUI:        {cfg.webui_public_url}\n")

    return [
        Route("/public/{name:str}", public_file),
        Route("/crl", crl), Route("/1.0/crl", crl),
        Route("/roots.pem", roots_pem),
        Route("/health", health), Route("/healthz", health),
        Route("/", index),
    ]


async def metrics(request: Request):
    s = st(request)
    if not s.cfg.metrics_token:
        return PlainTextResponse("Nicht aktiviert (METRICS_TOKEN)", status_code=404)
    if request.headers.get("authorization", "") != f"Bearer {s.cfg.metrics_token}":
        return PlainTextResponse("Unauthorized", status_code=401)
    certs = await run_in_threadpool(s.store.all)
    warn = s.cfg.expiry_warn_days
    lines = ["# HELP knet_ca_certificates Anzahl aktueller Zertifikate nach Status",
             "# TYPE knet_ca_certificates gauge"]
    counts = {k: 0 for k in STATUS_LABELS}
    current = [c for c in certs if not c.superseded_by and not c.is_ca]
    for c in current:
        counts[c.status(warn)] += 1
    for k, v in counts.items():
        lines.append(f'knet_ca_certificates{{status="{k}"}} {v}')
    lines += ["# HELP knet_ca_certificate_expiry_seconds Ablaufzeitpunkt (Unix) je aktuellem Zertifikat",
              "# TYPE knet_ca_certificate_expiry_seconds gauge"]
    for c in current:
        if c.revoked is None:
            name = c.display_name.replace('"', "")
            lines.append(f'knet_ca_certificate_expiry_seconds{{name="{name}",serial="{c.serial}",'
                         f'via="{c.via}"}} {int(c.not_after.timestamp())}')
    eps = await run_in_threadpool(s.db.endpoints)
    lines += ["# HELP knet_ca_endpoint_expiry_seconds Ablaufzeitpunkt (Unix) des ausgelieferten Zertifikats",
              "# TYPE knet_ca_endpoint_expiry_seconds gauge"]
    for e in eps:
        if e["not_after"]:
            ts = int(datetime.fromisoformat(e["not_after"]).timestamp())
            lines.append(f'knet_ca_endpoint_expiry_seconds{{endpoint="{e["host"]}:{e["port"]}"}} {ts}')
    return PlainTextResponse("\n".join(lines) + "\n")


# --- ACME-Übersicht -------------------------------------------------------------------------------------------

async def acme_page(request: Request):
    s = st(request)
    only_errors = request.query_params.get("errors") == "1"

    def load():
        accounts = s.db.all("SELECT a.*, (SELECT COUNT(*) FROM certs c WHERE c.acme_account = a.id) AS certs, "
                            "(SELECT COUNT(*) FROM acme_orders o WHERE o.account_id = a.id) AS orders "
                            "FROM acme_accounts a ORDER BY last_seen DESC")
        q = "SELECT * FROM acme_events " + ("WHERE ok = 0 " if only_errors else "") + "ORDER BY id DESC LIMIT 300"
        events = s.db.all(q)
        for a in accounts:
            a["contact_list"] = [c.replace("mailto:", "") for c in json.loads(a["contact"])]
        return accounts, events
    accounts, events = await run_in_threadpool(load)
    acc_names = {a["id"]: (", ".join(a["contact_list"]) or a["id"]) for a in accounts}
    return render(request, "acme.html", accounts=accounts, events=events, acc_names=acc_names,
                  only_errors=only_errors)


async def acme_account_action(request: Request):
    s = st(request)
    await checked_form(request)
    acc_id, action = request.path_params["id"], request.path_params["action"]
    if action == "deactivate":
        s.db.run("UPDATE acme_accounts SET status = 'deactivated' WHERE id = ?", (acc_id,))
        audit(request, "acme-account-deactivate", None, acc_id)
    elif action == "activate":
        s.db.run("UPDATE acme_accounts SET status = 'valid' WHERE id = ?", (acc_id,))
        audit(request, "acme-account-activate", None, acc_id)
    return RedirectResponse("/acme", status_code=303)


# --- App ---------------------------------------------------------------------------------------------------

def create_gui_app(state: State) -> Starlette:
    cfg = state.cfg
    routes = [
        Route("/", dashboard),
        Route("/certs", cert_list),
        Route("/certs/{serial:str}", cert_detail),
        Route("/certs/{serial:str}/download/{kind:str}", cert_download),
        Route("/certs/{serial:str}/revoke", cert_revoke, methods=["POST"]),
        Route("/sign", sign_form),
        Route("/sign/preview", sign_preview, methods=["POST"]),
        Route("/sign/issue", sign_issue, methods=["POST"]),
        Route("/generate", generate_form),
        Route("/generate", generate_issue, methods=["POST"]),
        Route("/acme", acme_page),
        Route("/acme/accounts/{id:str}/{action:str}", acme_account_action, methods=["POST"]),
        Route("/endpoints", endpoints_page),
        Route("/endpoints/add", endpoint_add, methods=["POST"]),
        Route("/endpoints/check-all", endpoints_check_all, methods=["POST"]),
        Route("/endpoints/{id:int}/{action:str}", endpoint_action, methods=["POST"]),
        Route("/trust", trust_page),
        Route("/tools", tools_page),
        Route("/tools/decode", tools_decode, methods=["POST"]),
        Route("/tools/notify", tools_notify, methods=["POST"]),
        Route("/audit", audit_page),
        Route("/metrics", metrics),
        Mount("/static", StaticFiles(directory=str(BASE / "static")), name="static"),
    ] + [r for r in public_routes(state) if r.path != "/"]
    if cfg.auth_mode == "oidc":
        routes += oidc_routes(cfg)
    middleware = [
        Middleware(SessionMiddleware, secret_key=cfg.session_secret, session_cookie="knet_ca",
                   max_age=12 * 3600, same_site="lax", https_only=cfg.webui_public_url.startswith("https")),
        Middleware(AccessMiddleware, cfg=cfg),
    ]

    async def csrf_error(request, exc):
        return render(request, "error.html", status_code=400, title="Sitzung abgelaufen",
                      message="Ungültiges oder fehlendes CSRF-Token. Bitte die Seite neu laden und erneut versuchen.")

    app = Starlette(routes=routes, middleware=middleware, exception_handlers={CSRFError: csrf_error})
    app.state.ca = state
    app.state.db = state.db
    return app
