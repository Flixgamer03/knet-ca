"""Startet alles in einem Prozess:
  * ACME-Server (HTTPS, Standard 9000) – öffentlich für deine Server
  * Web-GUI (HTTPS, Standard 8443)   – geschützt durch ALLOWED_NETWORKS / Login
  * Öffentlicher HTTP-Port (Standard 8080) – Root-CA, CRL, Bootstrap-Skript
Das eigene Server-Zertifikat stellt sich die CA selbst aus und erneuert es ohne Neustart."""
from __future__ import annotations

import logging
import threading

import uvicorn
from starlette.applications import Starlette

from . import tasks
from .acme import create_acme_app
from .config import get_config
from .main import State, create_gui_app, public_routes

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("knet-ca")


def _uv(app, port: int, tls: bool, cfg) -> uvicorn.Config:
    kw = {"ssl_certfile": str(cfg.tls_cert_path), "ssl_keyfile": str(cfg.tls_key_path)} if tls else {}
    c = uvicorn.Config(app, host="0.0.0.0", port=port, proxy_headers=False, server_header=False,
                       log_level="warning", timeout_keep_alive=30, **kw)
    c.load()
    return c


def main() -> None:
    cfg = get_config()
    state = State(cfg)
    tasks.ensure_server_cert(state)

    acme_app = create_acme_app(state, extra_routes=public_routes(state))
    gui_app = create_gui_app(state)

    ssl_ctxs = []
    acme_cfg = _uv(acme_app, cfg.acme_port, True, cfg)
    ssl_ctxs.append(acme_cfg.ssl)
    threading.Thread(target=uvicorn.Server(acme_cfg).run, name="acme", daemon=True).start()

    if cfg.public_http_port:
        pub_cfg = _uv(Starlette(routes=public_routes(state)), cfg.public_http_port, False, cfg)
        threading.Thread(target=uvicorn.Server(pub_cfg).run, name="public-http", daemon=True).start()

    gui_cfg = _uv(gui_app, cfg.webui_port, cfg.webui_tls, cfg)
    if gui_cfg.ssl:
        ssl_ctxs.append(gui_cfg.ssl)
    tasks.start_background(state, ssl_ctxs)

    fp = state.pki.root.fingerprint(__import__("cryptography.hazmat.primitives.hashes",
                                               fromlist=["SHA256"]).SHA256()).hex()
    log.info("──────────────────────────────────────────────────────────────")
    log.info("%s läuft", cfg.ca_name)
    log.info("ACME-Directory : %s", cfg.acme_directory)
    log.info("Web-GUI        : %s (Login: %s)", cfg.webui_public_url, cfg.auth_mode)
    if cfg.public_http_url:
        log.info("Root-CA (HTTP) : %s/public/root_ca.crt", cfg.public_http_url)
    log.info("Root-SHA256    : %s", fp)
    if state.pki.constraints.active:
        log.info("Erlaubte Namen : %s", ", ".join(state.pki.constraints.dns + [str(n) for n in state.pki.constraints.ip]))
    log.info("──────────────────────────────────────────────────────────────")
    uvicorn.Server(gui_cfg).run()


if __name__ == "__main__":
    main()
