"""Zentrale Konfiguration – alles kommt aus Umgebungsvariablen (siehe .env.example)."""
from __future__ import annotations

import ipaddress
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path


def env(name: str, default: str | None = None) -> str | None:
    v = os.environ.get(name)
    if v is None or v.strip() == "":
        return default
    return v.strip()


def env_bool(name: str, default: bool) -> bool:
    v = env(name)
    if v is None:
        return default
    return v.lower() in ("1", "true", "yes", "on", "ja")


def env_int(name: str, default: int) -> int:
    v = env(name)
    return int(v) if v is not None else default


def env_list(name: str, default: str = "") -> list[str]:
    v = env(name, default) or ""
    return [x.strip() for x in v.replace(";", ",").split(",") if x.strip()]


def parse_networks(items: list[str]) -> list:
    return [ipaddress.ip_network(i, strict=False) for i in items]


PRIVATE_NETS = "127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7,100.64.0.0/10"


@dataclass
class Config:
    # --- CA -----------------------------------------------------------------------
    ca_name: str = field(default_factory=lambda: env("CA_NAME", "Homelab CA"))
    ca_hostname: str = field(default_factory=lambda: env("CA_HOSTNAME", "ca.home.lan"))
    ca_extra_names: list = field(default_factory=lambda: env_list("CA_EXTRA_NAMES"))
    ca_key_type: str = field(default_factory=lambda: (env("CA_KEY_TYPE", "ec") or "ec").lower())
    root_years: int = field(default_factory=lambda: env_int("ROOT_VALIDITY_YEARS", 20))
    intermediate_years: int = field(default_factory=lambda: env_int("INTERMEDIATE_VALIDITY_YEARS", 10))
    permitted_domains: list = field(default_factory=lambda: env_list("PERMITTED_DOMAINS"))
    permitted_ip_ranges: list = field(default_factory=lambda: env_list("PERMITTED_IP_RANGES"))
    data_dir: Path = field(default_factory=lambda: Path(env("DATA_DIR", "/data")))

    # --- Ports & URLs -----------------------------------------------------------------
    acme_port: int = field(default_factory=lambda: env_int("ACME_PORT", 9000))
    webui_port: int = field(default_factory=lambda: env_int("WEBUI_PORT", 8443))
    public_http_port: int = field(default_factory=lambda: env_int("PUBLIC_HTTP_PORT", 8080))
    # Externe Ports (falls Docker andere Ports nach außen mappt)
    acme_public_port: int = field(default_factory=lambda: env_int("ACME_PUBLIC_PORT", 0))
    webui_public_port: int = field(default_factory=lambda: env_int("WEBUI_PUBLIC_PORT", 0))
    public_http_public_port: int = field(default_factory=lambda: env_int("PUBLIC_HTTP_PUBLIC_PORT", 0))
    webui_hostname: str = field(default_factory=lambda: env("WEBUI_HOSTNAME", ""))
    webui_tls: bool = field(default_factory=lambda: env_bool("WEBUI_TLS", True))
    webui_public_url: str = field(default_factory=lambda: env("WEBUI_PUBLIC_URL", ""))

    # --- Laufzeiten -------------------------------------------------------------------
    acme_cert_days: int = field(default_factory=lambda: env_int("ACME_CERT_DAYS", 90))
    manual_default_days: int = field(default_factory=lambda: env_int("MANUAL_DEFAULT_DAYS", 365))
    manual_max_days: int = field(default_factory=lambda: env_int("MANUAL_MAX_DAYS", 825))

    # --- ACME ------------------------------------------------------------------------
    acme_allowed_networks: list = field(default_factory=lambda: parse_networks(env_list("ACME_ALLOWED_NETWORKS", PRIVATE_NETS)))
    acme_trusted_networks: list = field(default_factory=lambda: parse_networks(env_list("ACME_TRUSTED_NETWORKS", "")))
    http01_port: int = field(default_factory=lambda: env_int("HTTP01_PORT", 80))
    tlsalpn01_port: int = field(default_factory=lambda: env_int("TLSALPN01_PORT", 443))
    dns_servers: list = field(default_factory=lambda: env_list("DNS_SERVERS"))
    crl_in_certs: bool = field(default_factory=lambda: env_bool("CRL_IN_CERTS", False))

    # --- Zugriff auf die Web-GUI ---------------------------------------------------------
    auth_mode: str = field(default_factory=lambda: (env("AUTH_MODE", "none") or "none").lower())
    allowed_networks: list = field(default_factory=lambda: parse_networks(env_list("ALLOWED_NETWORKS", PRIVATE_NETS)))
    trusted_proxies: list = field(default_factory=lambda: parse_networks(env_list("TRUSTED_PROXIES")))
    proxy_user_header: str = field(default_factory=lambda: env("PROXY_USER_HEADER", "X-authentik-username"))
    proxy_groups_header: str = field(default_factory=lambda: env("PROXY_GROUPS_HEADER", "X-authentik-groups"))
    oidc_issuer: str = field(default_factory=lambda: env("OIDC_ISSUER", ""))
    oidc_client_id: str = field(default_factory=lambda: env("OIDC_CLIENT_ID", ""))
    oidc_client_secret: str = field(default_factory=lambda: env("OIDC_CLIENT_SECRET", ""))
    oidc_scopes: str = field(default_factory=lambda: env("OIDC_SCOPES", "openid profile email"))
    oidc_allowed_groups: list = field(default_factory=lambda: env_list("OIDC_ALLOWED_GROUPS"))
    oidc_ca_bundle: str = field(default_factory=lambda: env("OIDC_CA_BUNDLE", ""))
    session_secret: str = field(default_factory=lambda: env("SESSION_SECRET", ""))

    # --- Monitoring ------------------------------------------------------------------------
    expiry_warn_days: int = field(default_factory=lambda: env_int("EXPIRY_WARN_DAYS", 14))
    ntfy_url: str = field(default_factory=lambda: env("NTFY_URL", ""))
    ntfy_token: str = field(default_factory=lambda: env("NTFY_TOKEN", ""))
    endpoint_check_hours: int = field(default_factory=lambda: env_int("ENDPOINT_CHECK_HOURS", 6))
    metrics_token: str = field(default_factory=lambda: env("METRICS_TOKEN", ""))

    def __post_init__(self) -> None:
        if not self.webui_hostname:
            self.webui_hostname = self.ca_hostname
        self.acme_public_port = self.acme_public_port or self.acme_port
        self.webui_public_port = self.webui_public_port or self.webui_port
        self.public_http_public_port = self.public_http_public_port or self.public_http_port
        if not self.webui_public_url:
            scheme = "https" if self.webui_tls else "http"
            self.webui_public_url = f"{scheme}://{self.webui_hostname}:{self.webui_public_port}"
        self.webui_public_url = self.webui_public_url.rstrip("/")
        if self.ca_key_type not in ("ec", "rsa"):
            raise SystemExit("CA_KEY_TYPE muss 'ec' oder 'rsa' sein")
        if self.auth_mode not in ("none", "oidc", "proxy"):
            raise SystemExit(f"AUTH_MODE muss none, oidc oder proxy sein (ist: {self.auth_mode})")
        if self.auth_mode == "oidc" and not (self.oidc_issuer and self.oidc_client_id and self.oidc_client_secret):
            raise SystemExit("AUTH_MODE=oidc braucht OIDC_ISSUER, OIDC_CLIENT_ID und OIDC_CLIENT_SECRET")
        if self.auth_mode == "proxy" and not self.trusted_proxies:
            raise SystemExit("AUTH_MODE=proxy braucht TRUSTED_PROXIES (IP/Netz des Reverse-Proxys)")
        self.data_dir.mkdir(parents=True, exist_ok=True)
        if not self.session_secret:
            self.session_secret = self._persistent_secret("session_secret")

    # --- Pfade & URLs -----------------------------------------------------------------------
    @property
    def ca_dir(self) -> Path:
        return self.data_dir / "ca"

    @property
    def root_path(self) -> Path:
        return self.ca_dir / "root_ca.crt"

    @property
    def intermediate_path(self) -> Path:
        return self.ca_dir / "intermediate_ca.crt"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "ca.sqlite"

    @property
    def tls_cert_path(self) -> Path:
        return self.data_dir / "tls" / "server.crt"

    @property
    def tls_key_path(self) -> Path:
        return self.data_dir / "tls" / "server.key"

    @property
    def ca_public_url(self) -> str:
        return f"https://{self.ca_hostname}:{self.acme_public_port}"

    @property
    def public_http_url(self) -> str:
        if not self.public_http_port:
            return ""
        return f"http://{self.ca_hostname}:{self.public_http_public_port}"

    @property
    def acme_directory(self) -> str:
        return f"{self.ca_public_url}/acme/directory"

    @property
    def server_names(self) -> list[str]:
        names = [self.ca_hostname]
        for n in [self.webui_hostname, *self.ca_extra_names]:
            if n and n not in names:
                names.append(n)
        return names

    def _persistent_secret(self, name: str) -> str:
        p = self.data_dir / "secrets" / name
        if p.exists():
            return p.read_text().strip()
        p.parent.mkdir(parents=True, exist_ok=True)
        s = secrets.token_urlsafe(48)
        p.write_text(s)
        p.chmod(0o600)
        return s


_config: Config | None = None


def get_config() -> Config:
    global _config
    if _config is None:
        _config = Config()
    return _config
