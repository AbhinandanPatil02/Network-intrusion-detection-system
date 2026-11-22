"""Alert pipeline: correlation/deduplication, SIEM log, webhook notifications."""
from __future__ import annotations

import ipaddress
import json
import logging
import queue
import threading
import time
import urllib.request
from datetime import datetime, timezone

from .detector import severity_rank
from .features import THREAT_INTEL

log = logging.getLogger(__name__)


def _parse_networks(items):
    nets = []
    for item in items:
        try:
            nets.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            log.warning("Ignoring invalid network in list: %r", item)
    return nets


def _in(ip: str, nets) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in nets)


class AlertManager:
    def __init__(self, cfg, storage):
        self.cfg = cfg
        self.storage = storage
        self.allow = _parse_networks(cfg.allowlist)
        self.block = _parse_networks(cfg.blocklist)
        self._log_lock = threading.Lock()
        self._webhook_q: queue.Queue = queue.Queue(maxsize=1000)
        if cfg.webhook_url:
            threading.Thread(target=self._webhook_worker, name="webhook", daemon=True).start()

    def evaluate(self, flow: dict) -> dict | None:
        """Create or update an alert for a classified flow. Returns the alert event, if any."""
        src, dst = flow["src"], flow["dst"]
        if _in(src, self.allow) and _in(dst, self.allow):
            return None

        category, severity, risk = None, flow["severity"], flow["risk"]
        if _in(src, self.block) or _in(dst, self.block):
            category, severity, risk = "Threat-intel match", "critical", max(risk, 95.0)
        elif flow["verdict"] == "malicious":
            category = flow["label"]
        elif self.cfg.anomaly_alerts and flow.get("is_anomaly") and (flow.get("anomaly_score") or 0) >= 1.25:
            category = "Anomaly"
            severity = severity if severity_rank(severity) >= severity_rank("low") else "low"
        if not category:
            return None
        if _in(src, self.allow) or _in(dst, self.allow):
            # Allow-listed endpoints only alert on high-confidence, high-severity events.
            if severity_rank(severity) < severity_rank("high"):
                return None

        now = flow["ts_end"]
        existing = self.storage.find_recent_alert(category, src, dst, now - self.cfg.alert_dedup_window)
        if existing:
            if severity_rank(severity) < severity_rank(existing["severity"]):
                severity = existing["severity"]
            self.storage.bump_alert(existing["id"], now, risk, severity, flow["id"], flow["confidence"])
            alert = self.storage.get_alert(existing["id"])
            alert["is_new"] = False
        else:
            alert_id = self.storage.insert_alert({
                "first_seen": now, "last_seen": now, "severity": severity, "category": category,
                "src": src, "dst": dst, "dport": flow["dport"], "proto": flow["proto"], "count": 1,
                "max_risk": risk, "confidence": flow["confidence"], "flow_id": flow["id"], "status": "open",
            })
            alert = self.storage.get_alert(alert_id)
            alert["is_new"] = True

        alert["intel"] = THREAT_INTEL.get(category, THREAT_INTEL["Anomaly"])
        self._siem_log(alert, flow)
        if alert["is_new"] and self.cfg.webhook_url and \
                severity_rank(severity) >= severity_rank(self.cfg.webhook_min_severity):
            try:
                self._webhook_q.put_nowait(alert)
            except queue.Full:
                pass
        return alert

    def _siem_log(self, alert: dict, flow: dict) -> None:
        """Append an ECS-flavoured JSON line, ready for Filebeat / Splunk / Sentinel ingestion."""
        event = {
            "@timestamp": datetime.fromtimestamp(flow["ts_end"], tz=timezone.utc).isoformat(),
            "event": {"kind": "alert", "category": ["network", "intrusion_detection"],
                      "severity": severity_rank(alert["severity"]), "action": "new" if alert["is_new"] else "update"},
            "rule": {"name": alert["category"], "id": alert["id"]},
            "threat": {"tactic": {"name": alert["intel"]["tactic"]}, "technique": {"name": alert["intel"]["technique"]}},
            "source": {"ip": flow["src"], "port": flow["sport"], "geo": {"country_iso_code": flow.get("src_country")}},
            "destination": {"ip": flow["dst"], "port": flow["dport"], "geo": {"country_iso_code": flow.get("dst_country")}},
            "network": {"transport": (flow["proto"] or "").lower(), "packets": flow["packets"], "bytes": flow["bytes"]},
            "process": {"name": flow.get("process") or None, "pid": flow.get("pid")},
            "nids": {"flow_id": flow["id"], "alert_id": alert["id"], "risk": flow["risk"],
                     "confidence": flow["confidence"], "label": flow["label"],
                     "anomaly_score": flow.get("anomaly_score"), "occurrences": alert["count"]},
        }
        line = json.dumps(event, default=str)
        with self._log_lock:
            with open(self.cfg.alert_log_path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")

    def _webhook_worker(self):
        while True:
            alert = self._webhook_q.get()
            text = (f"[{alert['severity'].upper()}] {alert['category']} — {alert['src']} → "
                    f"{alert['dst']}:{alert['dport']} ({alert['proto']}), risk {alert['max_risk']:.0f}")
            body = json.dumps({"text": text, "content": text, "alert": {
                k: alert[k] for k in ("id", "severity", "category", "src", "dst", "dport", "proto", "max_risk")
            }}).encode()
            req = urllib.request.Request(self.cfg.webhook_url, data=body,
                                         headers={"Content-Type": "application/json"}, method="POST")
            try:
                urllib.request.urlopen(req, timeout=5).close()
            except Exception as exc:
                log.warning("Webhook delivery failed: %s", exc)
            time.sleep(0.2)
