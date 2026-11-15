"""Die eigentliche CA: Root/Intermediate anlegen, Zertifikate ausstellen, widerrufen, CRL."""
from __future__ import annotations

import hashlib
import ipaddress
import logging
import os
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .certs import Constraints, key_description, key_warnings
from .db import Database, dumps, iso, utcnow

log = logging.getLogger("knet-ca")

PRIVATE_RANGES = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8",
                  "fc00::/7", "::1/128"]
REASON_FLAGS = {1: x509.ReasonFlags.key_compromise, 3: x509.ReasonFlags.affiliation_changed,
                4: x509.ReasonFlags.superseded, 5: x509.ReasonFlags.cessation_of_operation,
                9: x509.ReasonFlags.privilege_withdrawn, 0: x509.ReasonFlags.unspecified}


class IssueError(Exception):
    pass


def _write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    tmp.replace(path)


def _write_public(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    tmp.replace(path)


def _key_pem(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def _cert_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def spki_sha256(pub) -> str:
    der = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def random_serial() -> int:
    # 159 Bit, positiv, nie 0
    return int.from_bytes(os.urandom(20), "big") >> 1 | 1


def general_name(n: str) -> x509.GeneralName:
    try:
        return x509.IPAddress(ipaddress.ip_address(n))
    except ValueError:
        return x509.DNSName(n)


class PKI:
    def __init__(self, cfg, db: Database):
        self.cfg, self.db = cfg, db
        self.dir = cfg.ca_dir
        self.root_crt_p = self.dir / "root_ca.crt"
        self.root_key_p = self.dir / "root_ca.key"
        self.int_crt_p = self.dir / "intermediate_ca.crt"
        self.int_key_p = self.dir / "intermediate_ca.key"
        self._lock = threading.Lock()
        self._crl_cache: tuple[datetime, bytes] | None = None
        if not self.int_crt_p.exists():
            self.create()
        self.load()

    # --- Aufbau -------------------------------------------------------------------------------
    def _new_key(self, strong: bool):
        if self.cfg.ca_key_type == "rsa":
            return rsa.generate_private_key(65537, 4096 if strong else 3072)
        return ec.generate_private_key(ec.SECP384R1() if strong else ec.SECP256R1())

    def _hash(self, key):
        if isinstance(key, ec.EllipticCurvePrivateKey) and key.curve.key_size >= 384:
            return hashes.SHA384()
        return hashes.SHA256()

    def create(self) -> None:
        cfg = self.cfg
        log.info("Erzeuge neue CA '%s' …", cfg.ca_name)
        now = utcnow()
        root_key = self._new_key(strong=True)
        root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{cfg.ca_name} Root CA"),
                               x509.NameAttribute(NameOID.ORGANIZATION_NAME, cfg.ca_name)])
        root = (x509.CertificateBuilder().subject_name(root_name).issuer_name(root_name)
                .public_key(root_key.public_key()).serial_number(random_serial())
                .not_valid_before(now - timedelta(minutes=5))
                .not_valid_after(now + timedelta(days=365 * cfg.root_years))
                .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
                .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()), critical=False)
                .sign(root_key, self._hash(root_key)))
        _write_private(self.root_key_p, _key_pem(root_key))
        _write_public(self.root_crt_p, _cert_pem(root))
        self.create_intermediate(root, root_key)
        log.info("CA erstellt. Root-Fingerprint: %s", root.fingerprint(hashes.SHA256()).hex())

    def name_constraints(self) -> x509.NameConstraints | None:
        domains = [d.lower().strip(".") for d in self.cfg.permitted_domains]
        if not domains:
            return None
        ranges = self.cfg.permitted_ip_ranges or PRIVATE_RANGES
        permitted: list[x509.GeneralName] = [x509.DNSName(d) for d in domains]
        permitted += [x509.IPAddress(ipaddress.ip_network(r, strict=False)) for r in ranges]
        return x509.NameConstraints(permitted_subtrees=permitted, excluded_subtrees=None)

    def create_intermediate(self, root: x509.Certificate, root_key) -> None:
        cfg = self.cfg
        domains = [d.lower().strip(".") for d in cfg.permitted_domains]
        for n in cfg.server_names:
            if domains and not Constraints(dns=domains).permits_dns(n) and not _is_ip(n):
                raise SystemExit(f"'{n}' (CA_HOSTNAME/WEBUI_HOSTNAME) liegt nicht in PERMITTED_DOMAINS {domains}.")
        now = utcnow()
        key = self._new_key(strong=False)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{cfg.ca_name} Intermediate CA"),
                          x509.NameAttribute(NameOID.ORGANIZATION_NAME, cfg.ca_name)])
        not_after = min(now + timedelta(days=365 * cfg.intermediate_years), root.not_valid_after_utc)
        b = (x509.CertificateBuilder().subject_name(name).issuer_name(root.subject)
             .public_key(key.public_key()).serial_number(random_serial())
             .not_valid_before(now - timedelta(minutes=5)).not_valid_after(not_after)
             .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
             .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True)
             .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
             .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root.public_key()), critical=False))
        nc = self.name_constraints()
        if nc is not None:
            b = b.add_extension(nc, critical=True)
            log.info("Intermediate mit Name Constraints: %s", ", ".join(domains))
        else:
            log.warning("PERMITTED_DOMAINS ist leer – Intermediate ohne Name Constraints!")
        cert = b.sign(root_key, self._hash(root_key))
        _write_private(self.int_key_p, _key_pem(key))
        _write_public(self.int_crt_p, _cert_pem(cert))

    def load(self) -> None:
        self.root = x509.load_pem_x509_certificate(self.root_crt_p.read_bytes())
        self.intermediate = x509.load_pem_x509_certificate(self.int_crt_p.read_bytes())
        self.int_key = serialization.load_pem_private_key(self.int_key_p.read_bytes(), None)
        self.constraints = Constraints.from_cert(self.intermediate)
        self._crl_cache = None

    @property
    def root_key_present(self) -> bool:
        return self.root_key_p.exists()

    def chain_pem(self) -> str:
        return _cert_pem(self.intermediate).decode()

    # --- Ausstellen -----------------------------------------------------------------------------
    def issue(self, public_key, names: list[str], days: int, source: str, requester: str,
              acme_account: str | None = None, order_id: str | None = None,
              max_days: int | None = None) -> x509.Certificate:
        names = _normalize_names(names)
        if not names:
            raise IssueError("Keine Namen angegeben.")
        if isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            raise IssueError("Ed25519/Ed448-Schlüssel werden von Browsern für TLS nicht unterstützt.")
        if not isinstance(public_key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
            raise IssueError(f"Schlüsseltyp {key_description(public_key)} wird nicht unterstützt.")
        warn = key_warnings(public_key)
        if isinstance(public_key, rsa.RSAPublicKey) and public_key.key_size < 2048:
            raise IssueError(warn[0])
        if spki_sha256(public_key) == spki_sha256(self.int_key.public_key()):
            raise IssueError("Der Schlüssel der CA darf nicht für ein Zertifikat verwendet werden.")
        bad = self.constraints.check(names)
        if bad:
            raise IssueError("Diese Namen liegen außerhalb der erlaubten Domains/Netze der CA: " + ", ".join(bad))
        days = max(1, min(int(days), max_days or self.cfg.manual_max_days))

        now = utcnow()
        not_before = now - timedelta(minutes=1)
        not_after = min(not_before + timedelta(days=days), self.intermediate.not_valid_after_utc)
        cn = next((n for n in names if not _is_ip(n)), names[0])
        ku_enc = isinstance(public_key, rsa.RSAPublicKey)
        b = (x509.CertificateBuilder()
             .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn[:64])]))
             .issuer_name(self.intermediate.subject).public_key(public_key)
             .serial_number(random_serial()).not_valid_before(not_before).not_valid_after(not_after)
             .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
             .add_extension(x509.KeyUsage(True, False, ku_enc, False, False, False, False, False, False), critical=True)
             .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH,
                                                   ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
             .add_extension(x509.SubjectAlternativeName([general_name(n) for n in names]), critical=False)
             .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
             .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.int_key.public_key()),
                            critical=False))
        if self.cfg.public_http_url:
            b = b.add_extension(x509.AuthorityInformationAccess([x509.AccessDescription(
                x509.oid.AuthorityInformationAccessOID.CA_ISSUERS,
                x509.UniformResourceIdentifier(f"{self.cfg.public_http_url}/public/intermediate_ca.der"))]),
                critical=False)
            if self.cfg.crl_in_certs:
                b = b.add_extension(x509.CRLDistributionPoints([x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(f"{self.cfg.public_http_url}/crl")],
                    relative_name=None, reasons=None, crl_issuer=None)]), critical=False)
        with self._lock:
            cert = b.sign(self.int_key, self._hash(self.int_key))
        self.db.run(
            "INSERT INTO certs (serial, cn, sans, not_before, not_after, pem, source, requester, acme_account, "
            "order_id, key_desc, spki_sha256, created) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (format(cert.serial_number, "x"), cn, dumps(names), iso(cert.not_valid_before_utc),
             iso(cert.not_valid_after_utc), _cert_pem(cert).decode(), source, requester, acme_account, order_id,
             key_description(public_key), spki_sha256(public_key), iso(now)))
        log.info("Zertifikat ausgestellt: %s (%s, %s Tage, %s)", ", ".join(names), source, days, requester)
        return cert

    def issue_csr(self, csr: x509.CertificateSigningRequest, names: list[str], days: int, **kw) -> x509.Certificate:
        if not csr.is_signature_valid:
            raise IssueError("Die Signatur des CSR ist ungültig.")
        return self.issue(csr.public_key(), names, days, **kw)

    # --- Widerruf & CRL --------------------------------------------------------------------------
    def revoke(self, serial_hex: str, reason: int = 0, note: str = "") -> None:
        if reason not in REASON_FLAGS:
            raise IssueError("Ungültiger Widerrufsgrund.")
        row = self.db.one("SELECT revoked_at FROM certs WHERE serial = ?", (serial_hex,))
        if row is None:
            raise IssueError("Zertifikat nicht gefunden.")
        if row["revoked_at"]:
            raise IssueError("Das Zertifikat ist bereits widerrufen.")
        self.db.run("UPDATE certs SET revoked_at = ?, revoke_reason = ?, revoke_note = ? WHERE serial = ?",
                    (iso(utcnow()), reason, note[:200], serial_hex))
        self._crl_cache = None
        log.info("Zertifikat %s widerrufen (Grund %s)", serial_hex, reason)

    def crl_der(self) -> bytes:
        now = utcnow()
        if self._crl_cache and now - self._crl_cache[0] < timedelta(hours=1):
            return self._crl_cache[1]
        num = int(self.db.get_kv("crl_number") or "0") + 1
        self.db.set_kv("crl_number", str(num))
        b = (x509.CertificateRevocationListBuilder().issuer_name(self.intermediate.subject)
             .last_update(now - timedelta(minutes=5)).next_update(now + timedelta(days=7))
             .add_extension(x509.CRLNumber(num), critical=False)
             .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.int_key.public_key()),
                            critical=False))
        rows = self.db.all("SELECT serial, revoked_at, revoke_reason FROM certs WHERE revoked_at IS NOT NULL "
                           "AND not_after > ?", (iso(now - timedelta(days=1)),))
        from .db import parse_iso
        for r in rows:
            rb = (x509.RevokedCertificateBuilder().serial_number(int(r["serial"], 16))
                  .revocation_date(parse_iso(r["revoked_at"])))
            if r["revoke_reason"]:
                rb = rb.add_extension(x509.CRLReason(REASON_FLAGS.get(r["revoke_reason"],
                                                                      x509.ReasonFlags.unspecified)), critical=False)
            b = b.add_revoked_certificate(rb.build())
        with self._lock:
            crl = b.sign(self.int_key, self._hash(self.int_key))
        der = crl.public_bytes(serialization.Encoding.DER)
        self._crl_cache = (now, der)
        return der

    # --- Neues Intermediate (z. B. nach Ablauf oder Änderung der Constraints) ----------------------
    def renew_intermediate(self) -> None:
        if not self.root_key_present:
            raise IssueError(f"Root-Schlüssel fehlt ({self.root_key_p}) – erst wieder einspielen.")
        root_key = serialization.load_pem_private_key(self.root_key_p.read_bytes(), None)
        ts = utcnow().strftime("%Y%m%d-%H%M%S")
        self.int_crt_p.replace(self.dir / f"intermediate_ca.{ts}.crt.old")
        self.int_key_p.replace(self.dir / f"intermediate_ca.{ts}.key.old")
        self.create_intermediate(self.root, root_key)
        self.load()


def _is_ip(n: str) -> bool:
    try:
        ipaddress.ip_address(n)
        return True
    except ValueError:
        return False


def _normalize_names(names: list[str]) -> list[str]:
    out: list[str] = []
    for n in names:
        n = n.strip().lower().rstrip(".")
        if _is_ip(n):
            n = str(ipaddress.ip_address(n))
        if n and n not in out:
            out.append(n)
    return out
