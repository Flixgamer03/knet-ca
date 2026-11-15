"""Verwaltung auf der Kommandozeile:

    docker compose exec ca python -m app.cli info
    docker compose exec ca python -m app.cli renew-intermediate    # braucht den Root-Schlüssel
    docker compose exec ca python -m app.cli revoke <serial> [grund]
"""
from __future__ import annotations

import sys

from cryptography.hazmat.primitives import hashes

from .config import get_config
from .db import Database
from .pki import PKI


def main(argv: list[str]) -> int:
    cfg = get_config()
    db = Database(cfg.db_path)
    pki = PKI(cfg, db)
    cmd = argv[0] if argv else "info"
    if cmd == "info":
        print(f"Root:          {pki.root.subject.rfc4514_string()}  (bis {pki.root.not_valid_after_utc:%Y-%m-%d})")
        print(f"Root-SHA256:   {pki.root.fingerprint(hashes.SHA256()).hex()}")
        print(f"Intermediate:  {pki.intermediate.subject.rfc4514_string()}  (bis {pki.intermediate.not_valid_after_utc:%Y-%m-%d})")
        print(f"Constraints:   {', '.join(pki.constraints.dns + [str(n) for n in pki.constraints.ip]) or 'keine'}")
        print(f"Root-Schlüssel {'liegt im Volume' if pki.root_key_present else 'ist offline (nicht im Volume)'}")
        n = db.one("SELECT COUNT(*) AS n FROM certs")["n"]
        print(f"Zertifikate:   {n}")
        print(f"ACME:          {cfg.acme_directory}")
        return 0
    if cmd == "renew-intermediate":
        pki.renew_intermediate()
        print("Neues Intermediate erstellt (Constraints aus PERMITTED_DOMAINS). Container neu starten: "
              "docker compose restart ca")
        return 0
    if cmd == "revoke" and len(argv) >= 2:
        pki.revoke(argv[1].lower().replace(":", ""), int(argv[2]) if len(argv) > 2 else 0, "per CLI")
        print("Widerrufen.")
        return 0
    print(__doc__)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
