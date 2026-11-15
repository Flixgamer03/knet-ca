"""SQLite-Speicher für Zertifikate, ACME-Objekte, Protokoll und Endpunkte."""
from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(s: str | None) -> datetime | None:
    if not s:
        return None
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


SCHEMA = """
CREATE TABLE IF NOT EXISTS certs (
    serial TEXT PRIMARY KEY, cn TEXT, sans TEXT NOT NULL, not_before TEXT NOT NULL, not_after TEXT NOT NULL,
    pem TEXT NOT NULL, source TEXT NOT NULL, requester TEXT, acme_account TEXT, order_id TEXT,
    key_desc TEXT, spki_sha256 TEXT, created TEXT NOT NULL,
    revoked_at TEXT, revoke_reason INTEGER, revoke_note TEXT);
CREATE INDEX IF NOT EXISTS certs_not_after ON certs(not_after);
CREATE TABLE IF NOT EXISTS acme_accounts (
    id TEXT PRIMARY KEY, thumbprint TEXT UNIQUE NOT NULL, jwk TEXT NOT NULL, contact TEXT NOT NULL,
    status TEXT NOT NULL, created TEXT NOT NULL, ip TEXT, last_seen TEXT);
CREATE TABLE IF NOT EXISTS acme_orders (
    id TEXT PRIMARY KEY, account_id TEXT NOT NULL, status TEXT NOT NULL, identifiers TEXT NOT NULL,
    expires TEXT NOT NULL, created TEXT NOT NULL, cert_serial TEXT, error TEXT, ip TEXT);
CREATE INDEX IF NOT EXISTS orders_account ON acme_orders(account_id);
CREATE TABLE IF NOT EXISTS acme_authz (
    id TEXT PRIMARY KEY, order_id TEXT NOT NULL, account_id TEXT NOT NULL, id_type TEXT NOT NULL,
    id_value TEXT NOT NULL, wildcard INTEGER NOT NULL, status TEXT NOT NULL, expires TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS authz_order ON acme_authz(order_id);
CREATE TABLE IF NOT EXISTS acme_challenges (
    id TEXT PRIMARY KEY, authz_id TEXT NOT NULL, type TEXT NOT NULL, token TEXT NOT NULL,
    status TEXT NOT NULL, validated TEXT, error TEXT);
CREATE INDEX IF NOT EXISTS chall_authz ON acme_challenges(authz_id);
CREATE TABLE IF NOT EXISTS acme_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, account_id TEXT, order_id TEXT,
    identifier TEXT, kind TEXT NOT NULL, ok INTEGER NOT NULL, detail TEXT, ip TEXT);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, username TEXT, ip TEXT, action TEXT NOT NULL,
    serial TEXT, details TEXT);
CREATE TABLE IF NOT EXISTS endpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT, host TEXT NOT NULL, port INTEGER NOT NULL, label TEXT,
    last_checked TEXT, status TEXT, serial TEXT, subject TEXT, issuer TEXT, not_after TEXT, ours INTEGER,
    error TEXT, created TEXT);
CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT);
"""


class Database:
    def __init__(self, path: Path):
        self.path = str(path)
        self._lock = threading.RLock()
        with self._conn() as c:
            c.execute("PRAGMA journal_mode=WAL")
            c.executescript(SCHEMA)

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            conn = sqlite3.connect(self.path, timeout=30)
            conn.row_factory = sqlite3.Row
            try:
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        """Mehrere Statements atomar ausführen."""
        with self._conn() as c:
            yield c

    def all(self, sql: str, params: tuple = ()) -> list[dict]:
        with self._conn() as c:
            return [dict(r) for r in c.execute(sql, params).fetchall()]

    def one(self, sql: str, params: tuple = ()) -> dict | None:
        with self._conn() as c:
            r = c.execute(sql, params).fetchone()
            return dict(r) if r else None

    def run(self, sql: str, params: tuple = ()) -> int:
        with self._conn() as c:
            cur = c.execute(sql, params)
            return cur.rowcount

    # --- kv --------------------------------------------------------------------------
    def get_kv(self, k: str) -> str | None:
        r = self.one("SELECT v FROM kv WHERE k = ?", (k,))
        return r["v"] if r else None

    def set_kv(self, k: str, v: str) -> None:
        self.run("INSERT INTO kv (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v", (k, v))

    # --- Audit -------------------------------------------------------------------------
    def audit(self, username: str, ip: str, action: str, serial: str | None = None, details: str = "") -> None:
        self.run("INSERT INTO audit (ts, username, ip, action, serial, details) VALUES (?,?,?,?,?,?)",
                 (iso(utcnow()), username, ip, action, serial, details))

    def audit_entries(self, limit: int = 500) -> list[dict]:
        return self.all("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,))

    # --- ACME-Ereignisse (Diagnose) ------------------------------------------------------
    def acme_event(self, kind: str, ok: bool, detail: str = "", account_id: str | None = None,
                   order_id: str | None = None, identifier: str | None = None, ip: str | None = None) -> None:
        self.run("INSERT INTO acme_events (ts, account_id, order_id, identifier, kind, ok, detail, ip) "
                 "VALUES (?,?,?,?,?,?,?,?)",
                 (iso(utcnow()), account_id, order_id, identifier, kind, 1 if ok else 0, detail[:2000], ip))
        # Tabelle klein halten
        self.run("DELETE FROM acme_events WHERE id < (SELECT MAX(id) - 5000 FROM acme_events)")

    # --- Endpunkte -------------------------------------------------------------------------
    def endpoints(self) -> list[dict]:
        return self.all("SELECT * FROM endpoints ORDER BY host, port")

    def endpoint(self, ep_id: int) -> dict | None:
        return self.one("SELECT * FROM endpoints WHERE id = ?", (ep_id,))

    def add_endpoint(self, host: str, port: int, label: str) -> int:
        with self._conn() as c:
            cur = c.execute("INSERT INTO endpoints (host, port, label, created) VALUES (?,?,?,?)",
                            (host, port, label, iso(utcnow())))
            return cur.lastrowid

    def delete_endpoint(self, ep_id: int) -> None:
        self.run("DELETE FROM endpoints WHERE id = ?", (ep_id,))

    def update_endpoint(self, ep_id: int, **fields: Any) -> None:
        allowed = {"last_checked", "status", "serial", "subject", "issuer", "not_after", "ours", "error"}
        cols = [k for k in fields if k in allowed]
        if not cols:
            return
        self.run(f"UPDATE endpoints SET {', '.join(c + ' = ?' for c in cols)} WHERE id = ?",
                 tuple(fields[c] for c in cols) + (ep_id,))


def dumps(o: Any) -> str:
    return json.dumps(o, separators=(",", ":"))
