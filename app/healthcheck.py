"""Docker-Healthcheck: fragt /health des ACME-Ports ab."""
import os
import ssl
import sys
import urllib.request

port = os.environ.get("ACME_PORT", "9000")
ctx = ssl._create_unverified_context()  # nur lokal; das Zertifikat lautet auf den Hostnamen
try:
    with urllib.request.urlopen(f"https://127.0.0.1:{port}/health", timeout=5, context=ctx) as r:
        sys.exit(0 if r.status == 200 else 1)
except Exception:
    sys.exit(1)
