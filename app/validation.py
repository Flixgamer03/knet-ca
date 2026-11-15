"""Prüfung der ACME-Challenges (http-01, dns-01, tls-alpn-01) mit verständlichen Fehlermeldungen."""
from __future__ import annotations

import hashlib
import http.client
import ipaddress
import socket
import ssl
import time
import urllib.parse

from cryptography import x509
from cryptography.x509.oid import ObjectIdentifier

from . import dnsclient
from .jose import b64e

ACME_IDENTIFIER_OID = ObjectIdentifier("1.3.6.1.5.5.7.1.31")


class ValidationError(Exception):
    def __init__(self, kind: str, detail: str):
        super().__init__(detail)
        self.kind = kind  # ACME-Fehlertyp: connection, dns, incorrectResponse, tls, unauthorized


def key_authorization(token: str, thumb: str) -> str:
    return f"{token}.{thumb}"


def _resolve(host: str, port: int) -> list[tuple]:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise ValidationError("dns", f"'{host}' lässt sich nicht auflösen ({e.strerror}). Hat der Name einen "
                                     f"DNS-Eintrag, den auch die CA sieht? (ggf. DNS_SERVERS / dns: setzen)")
    # IPv4 zuerst – im Heimnetz die zuverlässigere Wahl
    infos.sort(key=lambda i: 0 if i[0] == socket.AF_INET else 1)
    return infos


def _fmt_addr(sockaddr) -> str:
    ip, port = sockaddr[0], sockaddr[1]
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


# --- http-01 ---------------------------------------------------------------------------------

def validate_http01(identifier: str, token: str, keyauth: str, port: int = 80, timeout: float = 10.0) -> str:
    host = identifier
    path = f"/.well-known/acme-challenge/{token}"
    scheme, cur_host, cur_port = "http", host, port
    tried = []
    for _redirect in range(10):
        infos = _resolve(cur_host, cur_port)
        last_err = None
        resp_info = None
        for family, _, _, _, sockaddr in infos:
            addr = _fmt_addr(sockaddr)
            try:
                conn = http.client.HTTPConnection(sockaddr[0], sockaddr[1], timeout=timeout)
                raw = socket.create_connection(sockaddr[:2], timeout=timeout)
                if scheme == "https":
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    raw = ctx.wrap_socket(raw, server_hostname=None if _is_ip(cur_host) else cur_host)
                conn.sock = raw
                conn.putrequest("GET", path, skip_host=True, skip_accept_encoding=True)
                conn.putheader("Host", cur_host if cur_port in (80, 443) else f"{cur_host}:{cur_port}")
                conn.putheader("User-Agent", "knet-ca-validator/1.0")
                conn.putheader("Accept", "*/*")
                conn.endheaders()
                r = conn.getresponse()
                body = r.read(8192)
                resp_info = (addr, r.status, r.getheader("Location"), body)
                conn.close()
                break
            except (OSError, http.client.HTTPException, ssl.SSLError) as e:
                last_err = f"{addr}: {_err_text(e)}"
                tried.append(last_err)
                continue
        if resp_info is None:
            raise ValidationError("connection", f"Keine Verbindung zu {scheme}://{cur_host}:{cur_port}{path} – "
                                                f"{'; '.join(tried)}. Läuft der ACME-Client (z. B. certbot "
                                                f"--standalone) und ist Port {cur_port} aus Sicht der CA erreichbar?")
        addr, status, location, body = resp_info
        if status in (301, 302, 303, 307, 308) and location:
            nxt = urllib.parse.urljoin(f"{scheme}://{cur_host}:{cur_port}{path}", location)
            u = urllib.parse.urlsplit(nxt)
            if u.scheme not in ("http", "https"):
                raise ValidationError("connection", f"Ungültige Weiterleitung nach {location}")
            scheme, cur_host = u.scheme, u.hostname or cur_host
            cur_port = u.port or (443 if u.scheme == "https" else 80)
            path = u.path + (f"?{u.query}" if u.query else "")
            continue
        if status != 200:
            raise ValidationError("unauthorized", f"{addr} antwortete mit HTTP {status} für {path}. "
                                                  f"Liegt die Challenge-Datei am richtigen Ort (Webroot)?")
        got = body.decode("utf-8", "replace").strip()
        if got != keyauth:
            snippet = got[:120].replace("\n", " ")
            raise ValidationError("incorrectResponse", f"{addr} lieferte falschen Inhalt: '{snippet}' "
                                                       f"(erwartet: '{keyauth[:20]}…'). Antwortet evtl. ein "
                                                       f"anderer Server/Container auf Port {cur_port}?")
        return f"OK: {addr} lieferte die richtige Antwort"
    raise ValidationError("connection", "Zu viele Weiterleitungen")


# --- dns-01 ----------------------------------------------------------------------------------

def validate_dns01(identifier: str, keyauth: str, servers: list[str] | None = None) -> str:
    name = f"_acme-challenge.{identifier}"
    expected = b64e(hashlib.sha256(keyauth.encode()).digest())
    try:
        values = dnsclient.query_txt(name, servers or None)
    except dnsclient.DNSError as e:
        raise ValidationError("dns", f"DNS-Abfrage für {name} fehlgeschlagen: {e}")
    if expected in [v.strip() for v in values]:
        return f"OK: TXT-Eintrag {name} gefunden"
    if not values:
        raise ValidationError("unauthorized", f"Kein TXT-Eintrag unter {name} gefunden (erwartet: {expected}). "
                                              f"Schon propagiert? Fragt die CA den richtigen DNS-Server?")
    raise ValidationError("incorrectResponse", f"TXT {name} enthält {values}, erwartet wurde {expected}.")


# --- tls-alpn-01 -------------------------------------------------------------------------------

def validate_tlsalpn01(identifier: str, keyauth: str, port: int = 443, timeout: float = 10.0) -> str:
    expected = hashlib.sha256(keyauth.encode()).digest()
    is_ip = _is_ip(identifier)
    sni = ipaddress.ip_address(identifier).reverse_pointer if is_ip else identifier
    infos = _resolve(identifier, port)
    errors = []
    for family, _, _, _, sockaddr in infos:
        addr = _fmt_addr(sockaddr)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_alpn_protocols(["acme-tls/1"])
        try:
            with socket.create_connection(sockaddr[:2], timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=sni) as tls:
                    proto = tls.selected_alpn_protocol()
                    der = tls.getpeercert(binary_form=True)
        except (OSError, ssl.SSLError) as e:
            errors.append(f"{addr}: {_err_text(e)}")
            continue
        if proto != "acme-tls/1":
            raise ValidationError("tls", f"{addr} hat das ALPN-Protokoll acme-tls/1 nicht ausgehandelt "
                                         f"(bekam: {proto}). Läuft dort ein ACME-Client im tls-alpn-Modus?")
        cert = x509.load_der_x509_certificate(der)
        try:
            sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        except x509.ExtensionNotFound:
            raise ValidationError("unauthorized", "Challenge-Zertifikat ohne SAN")
        names = [str(n.value) for n in sans]
        if names != [str(ipaddress.ip_address(identifier)) if is_ip else identifier]:
            raise ValidationError("unauthorized", f"Challenge-Zertifikat enthält {names}, erwartet {identifier}")
        try:
            ext = cert.extensions.get_extension_for_oid(ACME_IDENTIFIER_OID)
        except x509.ExtensionNotFound:
            raise ValidationError("unauthorized", "Challenge-Zertifikat ohne acmeIdentifier-Erweiterung")
        if not ext.critical:
            raise ValidationError("unauthorized", "acmeIdentifier-Erweiterung muss kritisch sein")
        raw_val = ext.value.value
        if raw_val != b"\x04\x20" + expected:
            raise ValidationError("incorrectResponse", "acmeIdentifier enthält einen falschen Wert")
        return f"OK: {addr} präsentierte das richtige Challenge-Zertifikat"
    raise ValidationError("connection", f"Keine TLS-Verbindung zu {identifier}:{port} – {'; '.join(errors)}")


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _err_text(e: Exception) -> str:
    if isinstance(e, ConnectionRefusedError):
        return "Verbindung abgelehnt (nichts lauscht auf dem Port)"
    if isinstance(e, (socket.timeout, TimeoutError)):
        return "Zeitüberschreitung (Firewall?)"
    if isinstance(e, OSError) and e.errno == 113:
        return "Host nicht erreichbar"
    return f"{type(e).__name__}: {e}"


def run_with_retries(fn, attempts: int, delay: float):
    last = None
    for i in range(attempts):
        try:
            return fn()
        except ValidationError as e:
            last = e
            if i < attempts - 1:
                time.sleep(delay)
    raise last
