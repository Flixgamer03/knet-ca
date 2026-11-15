"""Zertifikate & CSRs parsen, Status berechnen, Name Constraints prüfen."""
from __future__ import annotations

import hashlib
import ipaddress
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

REVOCATION_REASONS = {
    0: "Nicht angegeben",
    1: "Schlüssel kompromittiert",
    3: "Zugehörigkeit geändert",
    4: "Ersetzt",
    5: "Außer Betrieb genommen",
    9: "Berechtigung entzogen",
}

STATUS_LABELS = {
    "valid": "Gültig",
    "expiring": "Läuft bald ab",
    "expired": "Abgelaufen",
    "revoked": "Widerrufen",
}


def now() -> datetime:
    return datetime.now(timezone.utc)


def key_description(pub) -> str:
    if isinstance(pub, rsa.RSAPublicKey):
        return f"RSA {pub.key_size}"
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return {"secp256r1": "EC P-256", "secp384r1": "EC P-384", "secp521r1": "EC P-521"}.get(
            pub.curve.name, f"EC {pub.curve.name}")
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return "Ed25519"
    if isinstance(pub, ed448.Ed448PublicKey):
        return "Ed448"
    if isinstance(pub, dsa.DSAPublicKey):
        return f"DSA {pub.key_size}"
    return type(pub).__name__


def key_warnings(pub) -> list[str]:
    w = []
    if isinstance(pub, rsa.RSAPublicKey) and pub.key_size < 2048:
        w.append(f"Schwacher RSA-Schlüssel ({pub.key_size} Bit) – mindestens 2048 Bit verwenden.")
    if isinstance(pub, dsa.DSAPublicKey):
        w.append("DSA-Schlüssel werden von modernen Clients nicht mehr unterstützt.")
    return w


def get_sans(ext_owner) -> list[str]:
    try:
        ext = ext_owner.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return []
    out: list[str] = []
    for n in ext:
        if isinstance(n, x509.DNSName):
            out.append(n.value)
        elif isinstance(n, x509.IPAddress):
            out.append(str(n.value))
        elif isinstance(n, x509.RFC822Name):
            out.append(f"email:{n.value}")
        elif isinstance(n, x509.UniformResourceIdentifier):
            out.append(f"uri:{n.value}")
        else:
            out.append(str(n.value))
    return out


def common_name(name: x509.Name) -> str:
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(attrs[0].value) if attrs else ""


def fingerprint_sha256(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def fmt_fp(hexstr: str) -> str:
    return ":".join(hexstr[i:i + 2] for i in range(0, len(hexstr), 2)).upper()


def pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def eku_list(cert: x509.Certificate) -> list[str]:
    try:
        ekus = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        return []
    names = {ExtendedKeyUsageOID.SERVER_AUTH: "TLS-Server", ExtendedKeyUsageOID.CLIENT_AUTH: "TLS-Client",
             ExtendedKeyUsageOID.CODE_SIGNING: "Code-Signatur", ExtendedKeyUsageOID.EMAIL_PROTECTION: "E-Mail"}
    return [names.get(e, e.dotted_string) for e in ekus]


# --- Name Constraints --------------------------------------------------------------

@dataclass
class Constraints:
    dns: list[str] = field(default_factory=list)
    ip: list = field(default_factory=list)

    @property
    def active(self) -> bool:
        return bool(self.dns or self.ip)

    def permits_dns(self, name: str) -> bool:
        return not self.dns or any(dns_permitted(name, d) for d in self.dns)

    @classmethod
    def from_cert(cls, cert: x509.Certificate | None) -> "Constraints":
        if cert is None:
            return cls()
        try:
            nc = cert.extensions.get_extension_for_class(x509.NameConstraints).value
        except x509.ExtensionNotFound:
            return cls()
        c = cls()
        for st in nc.permitted_subtrees or []:
            if isinstance(st, x509.DNSName):
                c.dns.append(st.value)
            elif isinstance(st, x509.IPAddress):
                c.ip.append(st.value)
        return c

    def check(self, sans: list[str]) -> list[str]:
        """Liefert die SANs, die außerhalb der Constraints liegen."""
        bad = []
        for s in sans:
            if s.startswith(("email:", "uri:")):
                continue
            try:
                ip = ipaddress.ip_address(s)
            except ValueError:
                if self.dns and not any(dns_permitted(s, d) for d in self.dns):
                    bad.append(s)
                continue
            if self.ip and not any(ip in net for net in self.ip if net.version == ip.version):
                bad.append(s)
        return bad


def dns_permitted(name: str, constraint: str) -> bool:
    name, c = name.lower().rstrip("."), constraint.lower().rstrip(".")
    if name.startswith("*."):
        name = name[2:]
    if c.startswith("."):
        return name.endswith(c)
    return name == c or name.endswith("." + c)


# --- Zertifikatsinfos ----------------------------------------------------------------

@dataclass
class CertInfo:
    row: dict
    cert: x509.Certificate
    superseded_by: str | None = None

    @property
    def serial(self) -> str:
        return self.row["serial"]

    @property
    def serial_hex(self) -> str:
        h = self.serial if len(self.serial) % 2 == 0 else "0" + self.serial
        return ":".join(h[i:i + 2] for i in range(0, len(h), 2))

    @property
    def cn(self) -> str:
        return common_name(self.cert.subject)

    @property
    def subject(self) -> str:
        return self.cert.subject.rfc4514_string()

    @property
    def issuer(self) -> str:
        return self.cert.issuer.rfc4514_string()

    @property
    def sans(self) -> list[str]:
        return get_sans(self.cert)

    @property
    def display_name(self) -> str:
        return self.cn or (self.sans[0] if self.sans else self.serial)

    @property
    def not_before(self) -> datetime:
        return self.cert.not_valid_before_utc

    @property
    def not_after(self) -> datetime:
        return self.cert.not_valid_after_utc

    @property
    def key(self) -> str:
        return self.row.get("key_desc") or key_description(self.cert.public_key())

    @property
    def fingerprint(self) -> str:
        return fingerprint_sha256(self.cert)

    @property
    def days_left(self) -> int:
        return int((self.not_after - now()).total_seconds() / 86400)

    @property
    def lifetime_days(self) -> int:
        return max(1, (self.not_after - self.not_before).days)

    @property
    def is_ca(self) -> bool:
        return False

    @property
    def source(self) -> str:
        return self.row.get("source", "")

    @property
    def via(self) -> str:
        src = self.source
        if src == "acme":
            return "ACME"
        if src == "system":
            return "System"
        req = self.row.get("requester") or ""
        return f"Web-GUI ({req})" if req else "Web-GUI"

    @property
    def revoked(self) -> dict | None:
        if not self.row.get("revoked_at"):
            return None
        return {"ReasonCode": self.row.get("revoke_reason") or 0, "Reason": self.row.get("revoke_note") or "",
                "RevokedAt": self.row["revoked_at"]}

    def status(self, warn_days: int) -> str:
        if self.revoked is not None:
            return "revoked"
        n = now()
        if self.not_after < n:
            return "expired"
        if self.not_after - n < timedelta(days=warn_days):
            return "expiring"
        return "valid"

    @property
    def revoked_reason(self) -> str:
        if self.revoked is None:
            return ""
        code = self.revoked.get("ReasonCode", 0)
        txt = self.revoked.get("Reason") or ""
        label = REVOCATION_REASONS.get(code, f"Code {code}")
        return f"{label}{' – ' + txt if txt else ''}"

    @property
    def revoked_at(self) -> str:
        return (self.revoked or {}).get("RevokedAt", "")


class CertStore:
    """Liest ausgestellte Zertifikate aus der eigenen Datenbank (mit Parse-Cache)."""

    def __init__(self, db, pki):
        self.db = db
        self.pki = pki
        self._cache: dict[str, x509.Certificate] = {}
        self._lock = threading.Lock()

    def _info(self, row: dict) -> CertInfo:
        with self._lock:
            c = self._cache.get(row["serial"])
        if c is None:
            c = x509.load_pem_x509_certificate(row["pem"].encode())
            with self._lock:
                self._cache[row["serial"]] = c
        return CertInfo(row=row, cert=c)

    def all(self) -> list[CertInfo]:
        out = [self._info(r) for r in self.db.all("SELECT * FROM certs")]
        mark_superseded(out)
        out.sort(key=lambda c: c.not_before, reverse=True)
        return out

    def get(self, serial: str) -> CertInfo | None:
        serial = serial.lower().replace(":", "")
        for c in self.all():
            if c.serial == serial:
                return c
        return None

    def intermediate(self) -> x509.Certificate | None:
        return self.pki.intermediate


def mark_superseded(certs: list[CertInfo]) -> None:
    """Ein Zertifikat gilt als 'ersetzt', wenn es ein neueres, nicht widerrufenes
    Zertifikat mit denselben Namen gibt (typisch: ACME-Erneuerungen)."""
    def key(c):
        return tuple(sorted(set(n.lower() for n in c.sans) or {c.cn.lower()}))
    latest: dict[tuple, CertInfo] = {}
    for c in certs:
        if c.revoked is not None:
            continue
        cur = latest.get(key(c))
        if cur is None or c.not_before > cur.not_before:
            latest[key(c)] = c
    for c in certs:
        cur = latest.get(key(c))
        if cur is not None and cur is not c and cur.not_before >= c.not_before:
            c.superseded_by = cur.serial


# --- PEM-Eingaben parsen ---------------------------------------------------------------

def split_pem(data: bytes) -> list[tuple[str, bytes]]:
    """Zerlegt beliebigen PEM-Text in (Typ, Block)-Paare."""
    out = []
    text = data.decode("utf-8", errors="replace")
    pos = 0
    while True:
        start = text.find("-----BEGIN ", pos)
        if start < 0:
            break
        end_label = text.find("-----", start + 11)
        label = text[start + 11:end_label]
        end_marker = f"-----END {label}-----"
        end = text.find(end_marker, end_label)
        if end < 0:
            break
        block = text[start:end + len(end_marker)] + "\n"
        out.append((label, block.encode()))
        pos = end + len(end_marker)
    return out


def load_csr(data: bytes) -> x509.CertificateSigningRequest:
    data = data.strip()
    if b"-----BEGIN" in data:
        for label, block in split_pem(data):
            if "CERTIFICATE REQUEST" in label:
                return x509.load_pem_x509_csr(block)
        raise ValueError("Kein 'CERTIFICATE REQUEST'-Block gefunden.")
    return x509.load_der_x509_csr(data)


@dataclass
class CsrInfo:
    csr: x509.CertificateSigningRequest
    pem: str
    cn: str
    subject: str
    sans: list[str]
    key: str
    signature_ok: bool
    warnings: list[str]
    errors: list[str]


def analyze_csr(data: bytes, constraints: Constraints) -> CsrInfo:
    csr = load_csr(data)
    sans = get_sans(csr)
    cn = common_name(csr.subject)
    pub = csr.public_key()
    warnings = key_warnings(pub)
    errors = []
    sig_ok = csr.is_signature_valid
    if not sig_ok:
        errors.append("Die Signatur des CSR ist ungültig.")
    if not sans:
        errors.append("Der CSR enthält keine Subject Alternative Names. Browser ignorieren den Common Name – "
                      "bitte CSR mit SAN erzeugen oder 'Neues Zertifikat' nutzen.")
    elif cn and cn.lower() not in [s.lower() for s in sans]:
        warnings.append(f"Der Common Name '{cn}' ist nicht in den SANs enthalten.")
    bad = constraints.check(sans) if constraints.active else []
    if bad:
        errors.append("Diese Namen liegen außerhalb der erlaubten Domains/Netze der CA: " + ", ".join(bad))
    if any(s.startswith("*.") for s in sans):
        warnings.append("Wildcard-Zertifikat – gilt nur für eine Subdomain-Ebene.")
    pem_text = csr.public_bytes(serialization.Encoding.PEM).decode()
    return CsrInfo(csr=csr, pem=pem_text, cn=cn, subject=csr.subject.rfc4514_string(), sans=sans,
                   key=key_description(pub), signature_ok=sig_ok, warnings=warnings, errors=errors)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
