"""Minimale JOSE-Implementierung für ACME (RFC 7515/7517/7638): JWK laden, Thumbprint, JWS prüfen."""
from __future__ import annotations

import base64
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature


class JoseError(Exception):
    def __init__(self, detail: str, kind: str = "malformed"):
        super().__init__(detail)
        self.kind = kind


def b64d(s: str) -> bytes:
    if not isinstance(s, str):
        raise JoseError("base64url-String erwartet")
    if "=" in s or "+" in s or "/" in s:
        # RFC 7515: base64url ohne Padding – tolerant entfernen wir Padding
        s = s.rstrip("=")
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except (ValueError, TypeError) as e:
        raise JoseError(f"Ungültiges base64url: {e}")


def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _int(s: str) -> int:
    return int.from_bytes(b64d(s), "big")


CURVES = {"P-256": (ec.SECP256R1, 32, "ES256", hashes.SHA256),
          "P-384": (ec.SECP384R1, 48, "ES384", hashes.SHA384),
          "P-521": (ec.SECP521R1, 66, "ES512", hashes.SHA512)}


def jwk_to_key(jwk: dict):
    if not isinstance(jwk, dict):
        raise JoseError("jwk muss ein Objekt sein")
    kty = jwk.get("kty")
    try:
        if kty == "RSA":
            key = rsa.RSAPublicNumbers(_int(jwk["e"]), _int(jwk["n"])).public_key()
            if key.key_size < 2048:
                raise JoseError("RSA-Accountschlüssel muss mindestens 2048 Bit haben", "badPublicKey")
            return key
        if kty == "EC":
            crv = jwk.get("crv")
            if crv not in CURVES:
                raise JoseError(f"Kurve {crv} nicht unterstützt", "badPublicKey")
            return ec.EllipticCurvePublicNumbers(_int(jwk["x"]), _int(jwk["y"]), CURVES[crv][0]()).public_key()
        if kty == "OKP" and jwk.get("crv") == "Ed25519":
            return ed25519.Ed25519PublicKey.from_public_bytes(b64d(jwk["x"]))
    except JoseError:
        raise
    except (KeyError, ValueError, TypeError) as e:
        raise JoseError(f"Ungültiger JWK: {e}", "badPublicKey")
    raise JoseError(f"Schlüsseltyp {kty} nicht unterstützt", "badPublicKey")


def public_jwk(jwk: dict) -> dict:
    """Nur die öffentlichen Pflichtfelder (für Speicherung & Thumbprint)."""
    kty = jwk.get("kty")
    if kty == "RSA":
        return {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}
    if kty == "EC":
        return {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]}
    if kty == "OKP":
        return {"crv": jwk["crv"], "kty": "OKP", "x": jwk["x"]}
    raise JoseError(f"Schlüsseltyp {kty} nicht unterstützt", "badPublicKey")


def thumbprint(jwk: dict) -> str:
    pub = public_jwk(jwk)
    return b64e(hashlib.sha256(json.dumps(pub, sort_keys=True, separators=(",", ":")).encode()).digest())


RSA_ALGS = {"RS256": hashes.SHA256, "RS384": hashes.SHA384, "RS512": hashes.SHA512}
PSS_ALGS = {"PS256": hashes.SHA256, "PS384": hashes.SHA384, "PS512": hashes.SHA512}
EC_ALGS = {v[2]: k for k, v in CURVES.items()}
SUPPORTED_ALGS = sorted([*RSA_ALGS, *PSS_ALGS, *EC_ALGS, "EdDSA"])


def verify(alg: str, jwk: dict, signing_input: bytes, signature: bytes) -> None:
    key = jwk_to_key(jwk)
    try:
        if alg in RSA_ALGS and isinstance(key, rsa.RSAPublicKey):
            key.verify(signature, signing_input, padding.PKCS1v15(), RSA_ALGS[alg]())
        elif alg in PSS_ALGS and isinstance(key, rsa.RSAPublicKey):
            h = PSS_ALGS[alg]
            key.verify(signature, signing_input, padding.PSS(padding.MGF1(h()), h.digest_size), h())
        elif alg in EC_ALGS and isinstance(key, ec.EllipticCurvePublicKey):
            crv = EC_ALGS[alg]
            if jwk.get("crv") != crv:
                raise JoseError(f"{alg} passt nicht zur Kurve {jwk.get('crv')}", "badSignatureAlgorithm")
            size = CURVES[crv][1]
            if len(signature) != 2 * size:
                raise JoseError("Falsche Länge der EC-Signatur")
            r, s = int.from_bytes(signature[:size], "big"), int.from_bytes(signature[size:], "big")
            key.verify(encode_dss_signature(r, s), signing_input, ec.ECDSA(CURVES[crv][3]()))
        elif alg == "EdDSA" and isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(signature, signing_input)
        else:
            raise JoseError(f"Algorithmus {alg} passt nicht zum Schlüssel oder wird nicht unterstützt "
                            f"(unterstützt: {', '.join(SUPPORTED_ALGS)})", "badSignatureAlgorithm")
    except InvalidSignature:
        raise JoseError("Signatur ungültig")


def parse_flattened(body: bytes) -> tuple[dict, str, str, bytes]:
    """JWS in Flattened-JSON-Serialisierung zerlegen -> (protected, protected64, payload64, signature)."""
    try:
        obj = json.loads(body)
    except ValueError:
        raise JoseError("Request-Body ist kein JSON")
    if not isinstance(obj, dict) or "signatures" in obj:
        raise JoseError("JWS muss in der Flattened-JSON-Serialisierung gesendet werden")
    if "header" in obj:
        raise JoseError("Ungeschützte JWS-Header sind nicht erlaubt")
    for f in ("protected", "payload", "signature"):
        if f not in obj or not isinstance(obj[f], str):
            raise JoseError(f"JWS-Feld '{f}' fehlt")
    try:
        protected = json.loads(b64d(obj["protected"]))
    except ValueError:
        raise JoseError("Protected-Header ist kein JSON")
    if not isinstance(protected, dict):
        raise JoseError("Protected-Header muss ein Objekt sein")
    return protected, obj["protected"], obj["payload"], b64d(obj["signature"])
