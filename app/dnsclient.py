"""Kleiner DNS-Client für TXT-Abfragen (dns-01), ohne externe Abhängigkeiten."""
from __future__ import annotations

import os
import random
import socket
import struct
from pathlib import Path

TYPE_TXT, TYPE_CNAME = 16, 5
RCODES = {1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


class DNSError(Exception):
    pass


def system_servers() -> list[str]:
    servers = []
    try:
        for line in Path("/etc/resolv.conf").read_text().splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "nameserver":
                servers.append(parts[1])
    except OSError:
        pass
    return servers or ["127.0.0.1"]


def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("idna") if label else b""
        if not raw or len(raw) > 63:
            raise DNSError(f"Ungültiger DNS-Name: {name}")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def _read_name(msg: bytes, off: int) -> tuple[str, int]:
    labels, jumped, end, hops = [], False, off, 0
    while True:
        if off >= len(msg):
            raise DNSError("Abgeschnittene DNS-Antwort")
        n = msg[off]
        if n & 0xC0 == 0xC0:
            ptr = ((n & 0x3F) << 8) | msg[off + 1]
            if not jumped:
                end = off + 2
            jumped, off, hops = True, ptr, hops + 1
            if hops > 50:
                raise DNSError("Kompressionsschleife in DNS-Antwort")
            continue
        if n == 0:
            if not jumped:
                end = off + 1
            break
        labels.append(msg[off + 1:off + 1 + n].decode("ascii", "replace"))
        off += 1 + n
    return ".".join(labels), end


def _query(name: str, qtype: int, server: str, port: int, timeout: float) -> bytes:
    qid = random.randint(0, 0xFFFF)
    packet = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + _encode_name(name) + struct.pack(">HH", qtype, 1)
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(packet, (server, port))
        while True:
            data, _ = s.recvfrom(65535)
            if len(data) >= 2 and struct.unpack(">H", data[:2])[0] == qid:
                break
    flags = struct.unpack(">H", data[2:4])[0]
    if flags & 0x0200:  # TC -> per TCP wiederholen
        with socket.create_connection((server, port), timeout=timeout) as s:
            s.sendall(struct.pack(">H", len(packet)) + packet)
            ln = struct.unpack(">H", _recv_exact(s, 2))[0]
            data = _recv_exact(s, ln)
    return data


def _recv_exact(s, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise DNSError("Verbindung zum DNS-Server abgebrochen")
        buf += chunk
    return buf


def _parse(data: bytes) -> tuple[int, list[tuple[str, int, bytes]]]:
    _, flags, qd, an, _, _ = struct.unpack(">HHHHHH", data[:12])
    off = 12
    for _ in range(qd):
        _, off = _read_name(data, off)
        off += 4
    answers = []
    for _ in range(an):
        rname, off = _read_name(data, off)
        rtype, _, _, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        answers.append((rname, rtype, data[off:off + rdlen]))
        off += rdlen
    return flags & 0x000F, answers


def query_txt(name: str, servers: list[str] | None = None, timeout: float = 4.0) -> list[str]:
    """Liefert alle TXT-Werte für name (CNAME-Ketten löst der rekursive Resolver auf)."""
    servers = servers or system_servers()
    last_err: Exception | None = None
    for srv in servers:
        host, port = srv, 53
        if srv.count(":") == 1:  # host:port (IPv4)
            host, p = srv.split(":")
            port = int(p)
        try:
            rcode, answers = _parse(_query(name, TYPE_TXT, host, port, timeout))
        except (OSError, DNSError, struct.error) as e:
            last_err = e
            continue
        if rcode == 3:
            return []
        if rcode != 0:
            last_err = DNSError(f"{RCODES.get(rcode, rcode)} von {srv}")
            continue
        out = []
        for _, rtype, rdata in answers:
            if rtype != TYPE_TXT:
                continue
            i, parts = 0, []
            while i < len(rdata):
                ln = rdata[i]
                parts.append(rdata[i + 1:i + 1 + ln].decode("utf-8", "replace"))
                i += 1 + ln
            out.append("".join(parts))
        return out
    raise DNSError(f"Kein DNS-Server erreichbar ({', '.join(servers)}): {last_err}")


if __name__ == "__main__":  # python -m app.dnsclient _acme-challenge.example.com
    import sys
    print(query_txt(sys.argv[1], os.environ.get("DNS_SERVERS", "").split(",") if os.environ.get("DNS_SERVERS") else None))
