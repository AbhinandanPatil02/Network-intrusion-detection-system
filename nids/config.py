"""Runtime configuration.

Every setting can be supplied as an environment variable (prefix ``NIDS_``) or
overridden from the command line (see ``application.py --help``). Defaults are
chosen to be safe: bind to localhost, authentication on, debug off.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _env(name: str, default=None):
    return os.environ.get(f"NIDS_{name}", default)


def _env_bool(name: str, default: bool) -> bool:
    val = _env(name)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}


def _env_float(name: str, default: float) -> float:
    try:
        return float(_env(name, default))
    except (TypeError, ValueError):
        return default


def _env_list(name: str) -> list[str]:
    raw = _env(name, "") or ""
    return [x.strip() for x in raw.split(",") if x.strip()]


@dataclass
class Config:
    # --- Web server -------------------------------------------------------
    host: str = field(default_factory=lambda: _env("HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: int(_env("PORT", "5000")))
    auth_enabled: bool = field(default_factory=lambda: _env_bool("AUTH", True))
    admin_user: str = field(default_factory=lambda: _env("ADMIN_USER", "admin"))
    admin_password: str | None = field(default_factory=lambda: _env("ADMIN_PASSWORD"))

    # --- Capture ----------------------------------------------------------
    interface: str | None = field(default_factory=lambda: _env("INTERFACE"))
    bpf_filter: str = field(default_factory=lambda: _env("BPF", "ip and (tcp or udp)"))
    capture_enabled: bool = field(default_factory=lambda: _env_bool("CAPTURE", True))
    pcap_file: str | None = field(default_factory=lambda: _env("PCAP"))

    # --- Flow assembly ----------------------------------------------------
    idle_timeout: float = field(default_factory=lambda: _env_float("IDLE_TIMEOUT", 60.0))
    active_timeout: float = field(default_factory=lambda: _env_float("ACTIVE_TIMEOUT", 600.0))
    max_active_flows: int = field(default_factory=lambda: int(_env("MAX_FLOWS", "100000")))
    max_packets_per_flow: int = field(default_factory=lambda: int(_env("MAX_PACKETS_PER_FLOW", "20000")))

    # --- Detection --------------------------------------------------------
    alert_min_confidence: float = field(default_factory=lambda: _env_float("ALERT_MIN_CONFIDENCE", 0.6))
    anomaly_alerts: bool = field(default_factory=lambda: _env_bool("ANOMALY_ALERTS", True))
    anomaly_percentile: float = field(default_factory=lambda: _env_float("ANOMALY_PERCENTILE", 99.5))
    anomaly_warmup: int = field(default_factory=lambda: int(_env("ANOMALY_WARMUP", "200")))
    alert_dedup_window: float = field(default_factory=lambda: _env_float("ALERT_DEDUP_WINDOW", 300.0))
    scan_detection: bool = field(default_factory=lambda: _env_bool("SCAN_DETECTION", True))
    scan_window: float = field(default_factory=lambda: _env_float("SCAN_WINDOW", 60.0))
    scan_port_threshold: int = field(default_factory=lambda: int(_env("SCAN_PORT_THRESHOLD", "25")))
    scan_host_threshold: int = field(default_factory=lambda: int(_env("SCAN_HOST_THRESHOLD", "20")))
    allowlist: list[str] = field(default_factory=lambda: _env_list("ALLOWLIST"))
    blocklist: list[str] = field(default_factory=lambda: _env_list("BLOCKLIST"))

    # --- Enrichment & integrations ----------------------------------------
    geoip_enabled: bool = field(default_factory=lambda: _env_bool("GEOIP", True))
    ipinfo_token: str | None = field(default_factory=lambda: _env("IPINFO_TOKEN"))
    webhook_url: str | None = field(default_factory=lambda: _env("WEBHOOK_URL"))
    webhook_min_severity: str = field(default_factory=lambda: _env("WEBHOOK_MIN_SEVERITY", "high"))

    # --- Storage ----------------------------------------------------------
    data_dir: Path = field(default_factory=lambda: Path(_env("DATA_DIR", str(BASE_DIR / "data"))))
    models_dir: Path = field(default_factory=lambda: Path(_env("MODELS_DIR", str(BASE_DIR / "models"))))
    retention_days: float = field(default_factory=lambda: _env_float("RETENTION_DAYS", 30.0))
    max_upload_mb: int = field(default_factory=lambda: int(_env("MAX_UPLOAD_MB", "200")))

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        (self.data_dir / "uploads").mkdir(exist_ok=True)

    @property
    def db_path(self) -> Path:
        return self.data_dir / "nids.sqlite3"

    @property
    def alert_log_path(self) -> Path:
        return self.data_dir / "alerts.jsonl"

    def public_dict(self) -> dict:
        """Configuration safe to show in the UI (no secrets)."""
        return {
            "host": self.host,
            "port": self.port,
            "auth_enabled": self.auth_enabled,
            "interface": self.interface or "default",
            "bpf_filter": self.bpf_filter,
            "capture_enabled": self.capture_enabled,
            "idle_timeout": self.idle_timeout,
            "active_timeout": self.active_timeout,
            "max_active_flows": self.max_active_flows,
            "alert_min_confidence": self.alert_min_confidence,
            "anomaly_alerts": self.anomaly_alerts,
            "anomaly_percentile": self.anomaly_percentile,
            "alert_dedup_window": self.alert_dedup_window,
            "scan_detection": self.scan_detection,
            "scan_window": self.scan_window,
            "scan_port_threshold": self.scan_port_threshold,
            "scan_host_threshold": self.scan_host_threshold,
            "allowlist": self.allowlist,
            "blocklist": self.blocklist,
            "geoip_enabled": self.geoip_enabled,
            "webhook_configured": bool(self.webhook_url),
            "retention_days": self.retention_days,
        }
