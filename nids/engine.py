"""Capture -> flow assembly -> analysis -> storage/alerts -> live UI pipeline."""
from __future__ import annotations

import logging
import queue
import threading
import time
import traceback
import uuid
from collections import Counter, deque
from pathlib import Path

from flow.Flow import Flow
from flow.PacketInfo import PacketInfo

from .alerts import AlertManager
from .correlation import ScanDetector
from .detector import Detector, risk_to_severity
from .enrichment import GeoResolver, ProcessMap
from .features import THREAT_INTEL, WELL_KNOWN_PORTS
from .storage import Storage

log = logging.getLogger(__name__)

TIMELINE_BUCKET = 10        # seconds
TIMELINE_BUCKETS = 180      # 30 minutes


def parse_packet(p) -> PacketInfo:
    """Build a PacketInfo; raises AttributeError for non IPv4 TCP/UDP packets."""
    pkt = PacketInfo()
    pkt.setDest(p)
    pkt.setSrc(p)
    pkt.setSrcPort(p)
    pkt.setDestPort(p)
    pkt.setProtocol(p)
    if not pkt.getProtocol():
        raise AttributeError("not TCP/UDP")
    pkt.setTimestamp(p)
    pkt.setPSHFlag(p)
    pkt.setFINFlag(p)
    pkt.setSYNFlag(p)
    pkt.setACKFlag(p)
    pkt.setURGFlag(p)
    pkt.setRSTFlag(p)
    pkt.setPayloadBytes(p)
    pkt.setHeaderBytes(p)
    pkt.setPacketSize(p)
    pkt.setWinBytes(p)
    pkt.setFwdID()
    pkt.setBwdID()
    pkt.timestamp = float(pkt.timestamp)
    return pkt


class FlowTable:
    """Bidirectional flow table with FIN/RST, idle, active and capacity expiry."""

    def __init__(self, engine: "Engine", source: str):
        self.engine = engine
        self.cfg = engine.cfg
        self.source = source
        self.flows: dict[str, Flow] = {}
        self.lock = threading.Lock()
        self.packets = 0
        self.last_packet_ts = 0.0
        self.job: dict | None = None

    def _finish(self, key: str, reason: str):
        flow = self.flows.pop(key, None)
        if flow is not None:
            self.engine.submit(flow, reason, self.source, self.job)

    def add(self, p) -> None:
        try:
            pkt = parse_packet(p)
        except (AttributeError, IndexError, TypeError):
            return
        pid, pname = self.engine.processes.lookup(pkt.getSrcPort(), pkt.getDestPort())
        pkt.setProcess(pid, pname)

        with self.lock:
            self.packets += 1
            self.last_packet_ts = pkt.getTimestamp()
            fwd, bwd = pkt.getFwdID(), pkt.getBwdID()
            if fwd in self.flows:
                key, direction = fwd, "fwd"
            elif bwd in self.flows:
                key, direction = bwd, "bwd"
            else:
                if len(self.flows) >= self.cfg.max_active_flows:
                    oldest = min(self.flows, key=lambda k: self.flows[k].getFlowLastSeen())
                    self._finish(oldest, "capacity")
                self.flows[fwd] = Flow(pkt)
                return

            flow = self.flows[key]
            if pkt.getTimestamp() - flow.getFlowLastSeen() > self.cfg.idle_timeout:
                self._finish(key, "idle")
                self.flows[fwd] = Flow(pkt)
                return

            flow.new(pkt, direction)
            if pkt.getFINFlag() or pkt.getRSTFlag():
                self._finish(key, "fin/rst")
            elif pkt.getTimestamp() - flow.getFlowStartTime() > self.cfg.active_timeout:
                self._finish(key, "active-timeout")
            elif flow.packet_count >= self.cfg.max_packets_per_flow:
                self._finish(key, "packet-cap")

    def sweep(self, now: float) -> None:
        with self.lock:
            expired = [k for k, f in self.flows.items()
                       if now - f.getFlowLastSeen() > self.cfg.idle_timeout
                       or now - f.getFlowStartTime() > self.cfg.active_timeout]
            for k in expired:
                self._finish(k, "idle")

    def flush(self, reason="shutdown") -> None:
        with self.lock:
            for k in list(self.flows):
                self._finish(k, reason)

    def __len__(self):
        return len(self.flows)


class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.started = time.time()
        self.flows_total = 0
        self.verdicts = Counter()
        self.labels = Counter()
        self.protocols = Counter()
        self.top_src = Counter()
        self.top_threat_src = Counter()
        self.top_dports = Counter()
        self.bytes_total = 0
        self.timeline: dict[int, list[int]] = {}
        self.dropped = 0
        self.anomalies = 0
        self.offline_packets = 0
        self._pps_samples: deque[tuple[float, int]] = deque(maxlen=10)

    def seed(self, rows):
        for r in rows:
            self.flows_total += r["n"]
            self.verdicts[r["verdict"]] += r["n"]
            self.labels[r["label"]] += r["n"]

    def record(self, flow: dict):
        with self.lock:
            self.flows_total += 1
            self.verdicts[flow["verdict"]] += 1
            self.labels[flow["label"]] += 1
            self.protocols[flow["proto"]] += 1
            self.top_src[flow["src"]] += 1
            if flow["verdict"] != "benign":
                self.top_threat_src[flow["src"]] += 1
            self.top_dports[flow["dport"]] += 1
            self.bytes_total += flow["bytes"] or 0
            if flow.get("is_anomaly"):
                self.anomalies += 1
            bucket = int(time.time() // TIMELINE_BUCKET) * TIMELINE_BUCKET
            slot = self.timeline.setdefault(bucket, [0, 0, 0])
            slot[{"benign": 0, "suspicious": 1, "malicious": 2}[flow["verdict"]]] += 1
            if len(self.timeline) > TIMELINE_BUCKETS + 10:
                for k in sorted(self.timeline)[:-TIMELINE_BUCKETS]:
                    del self.timeline[k]
            for c in (self.top_src, self.top_threat_src, self.top_dports):
                if len(c) > 20000:
                    keep = c.most_common(2000)
                    c.clear()
                    c.update(dict(keep))

    def snapshot(self, packets_total: int) -> dict:
        now = time.time()
        with self.lock:
            self._pps_samples.append((now, packets_total))
            pps = 0.0
            if len(self._pps_samples) >= 2:
                (t0, p0), (t1, p1) = self._pps_samples[0], self._pps_samples[-1]
                pps = (p1 - p0) / max(t1 - t0, 1e-6)
            end = int(now // TIMELINE_BUCKET) * TIMELINE_BUCKET
            timeline = []
            for i in range(TIMELINE_BUCKETS - 1, -1, -1):
                b = end - i * TIMELINE_BUCKET
                timeline.append([b] + self.timeline.get(b, [0, 0, 0]))
            return {
                "uptime": now - self.started,
                "flows_total": self.flows_total,
                "verdicts": dict(self.verdicts),
                "labels": dict(self.labels),
                "protocols": dict(self.protocols),
                "bytes_total": self.bytes_total,
                "pps": round(pps, 1),
                "dropped": self.dropped,
                "anomalies": self.anomalies,
                "top_src": self.top_src.most_common(8),
                "top_threat_src": self.top_threat_src.most_common(8),
                "top_dports": [[p, n, WELL_KNOWN_PORTS.get(p, "")] for p, n in self.top_dports.most_common(8)],
                "timeline": timeline,
                "timeline_bucket": TIMELINE_BUCKET,
            }


class Engine:
    def __init__(self, cfg, socketio=None):
        self.cfg = cfg
        self.socketio = socketio
        self.storage = Storage(cfg.db_path)
        self.detector = Detector(cfg.models_dir, cfg)
        self.alerts = AlertManager(cfg, self.storage)
        self.processes = ProcessMap()
        self.geo = GeoResolver(cfg.geoip_enabled, cfg.ipinfo_token)
        self.scans = ScanDetector(cfg.scan_window, cfg.scan_port_threshold, cfg.scan_host_threshold)
        self.stats = Stats()
        self.stats.seed(self.storage.totals())
        self.stats.top_src.update(dict(self.storage.top_counts("src")))
        self.stats.top_dports.update(dict(self.storage.top_counts("dport")))
        self.stats.top_threat_src.update(dict(self.storage.top_counts("src", "WHERE verdict != 'benign'")))

        self.live = FlowTable(self, "live")
        self.capture_state = {"status": "stopped", "interface": cfg.interface or "default", "error": None}
        self._sniffer = None
        self.jobs: dict[str, dict] = {}

        self._q: queue.Queue = queue.Queue(maxsize=20000)
        self._pending_flows: deque[dict] = deque(maxlen=200)
        self._pending_alerts: dict[int, dict] = {}
        self._pending_lock = threading.Lock()
        self._stop = threading.Event()

    # ------------------------------------------------------------ lifecycle
    def start(self):
        self.processes.start()
        self.geo.start()
        for target, name in ((self._analysis_worker, "analysis"), (self._housekeeping, "housekeeping"),
                             (self._broadcaster, "broadcaster")):
            threading.Thread(target=target, name=name, daemon=True).start()
        if self.cfg.capture_enabled:
            self.start_capture()
        if self.cfg.pcap_file:
            self.analyze_pcap(Path(self.cfg.pcap_file), Path(self.cfg.pcap_file).name)

    def stop(self):
        self.stop_capture()
        self.live.flush()
        deadline = time.time() + 5
        while not self._q.empty() and time.time() < deadline:
            time.sleep(0.1)
        self._stop.set()
        self.processes.stop()

    def start_capture(self) -> dict:
        if self._sniffer is not None:
            return self.capture_state
        try:
            from scapy.sendrecv import AsyncSniffer

            kwargs = {"prn": self.live.add, "store": False}
            if self.cfg.interface:
                kwargs["iface"] = self.cfg.interface
            if self.cfg.bpf_filter:
                kwargs["filter"] = self.cfg.bpf_filter
            sniffer = AsyncSniffer(**kwargs)
            sniffer.start()
            time.sleep(0.5)
            if not getattr(sniffer, "running", True) and getattr(sniffer, "exception", None):
                raise sniffer.exception
            self._sniffer = sniffer
            self.capture_state.update(status="running", error=None, since=time.time())
            log.info("Live capture started on %s (filter=%r)", self.cfg.interface or "default interface",
                     self.cfg.bpf_filter)
        except Exception as exc:  # missing Npcap/libpcap, permissions, bad iface...
            self._sniffer = None
            msg = str(exc) or exc.__class__.__name__
            self.capture_state.update(status="error", error=msg)
            log.error("Live capture failed: %s — run as Administrator/root and ensure Npcap/libpcap is installed",
                      msg)
        return self.capture_state

    def stop_capture(self) -> dict:
        sniffer, self._sniffer = self._sniffer, None
        if sniffer is not None:
            try:
                sniffer.stop()
            except Exception:
                pass
            self.live.flush("capture-stopped")
        self.capture_state.update(status="stopped")
        return self.capture_state

    # ---------------------------------------------------------- PCAP replay
    def analyze_pcap(self, path: Path, name: str) -> str:
        job_id = uuid.uuid4().hex[:10]
        job = {"id": job_id, "name": name, "status": "queued", "packets": 0, "flows": 0, "threats": 0,
               "started": time.time(), "finished": None, "error": None}
        self.jobs[job_id] = job
        threading.Thread(target=self._pcap_worker, args=(path, job), name=f"pcap-{job_id}", daemon=True).start()
        return job_id

    def _pcap_worker(self, path: Path, job: dict):
        from scapy.utils import PcapReader

        table = FlowTable(self, f"pcap:{job['name']}")
        table.job = job
        job["status"] = "running"
        try:
            with PcapReader(str(path)) as reader:
                for i, pkt in enumerate(reader):
                    table.add(pkt)
                    if i % 2000 == 0:
                        table.sweep(table.last_packet_ts)
                        job["packets"] = table.packets
            table.flush("end-of-capture")
            job["packets"] = table.packets
            job["status"] = "analyzing"
            while self._q.unfinished_tasks and not self._stop.is_set():
                time.sleep(0.2)
            job["status"] = "completed"
        except Exception as exc:
            job["status"] = "failed"
            job["error"] = str(exc)
            log.exception("PCAP analysis failed")
        finally:
            with self.stats.lock:
                self.stats.offline_packets += table.packets
            self.scans.drop(table.source)
        job["finished"] = time.time()

    # ------------------------------------------------------------- analysis
    def submit(self, flow: Flow, reason: str, source: str, job: dict | None = None):
        if job is not None:
            self._q.put((flow, reason, source, job))  # offline replay: apply back-pressure, never drop
            return
        try:
            self._q.put_nowait((flow, reason, source, None))
        except queue.Full:
            with self.stats.lock:
                self.stats.dropped += 1

    def _analysis_worker(self):
        while not self._stop.is_set():
            try:
                flow, reason, source, job = self._q.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self._analyze(flow, reason, source, job)
            except Exception:
                traceback.print_exc()
            finally:
                self._q.task_done()

    def _analyze(self, flow: Flow, reason: str, source: str, job: dict | None):
        raw = flow.terminated()
        x, v = self.detector.analyze(raw, learn=(source == "live"))
        src, sport, dst, dport, proto, t_start, t_end, pname, pid = raw[39:48]
        rec = {
            "ts_start": flow.getFlowStartTime(), "ts_end": flow.getFlowLastSeen(),
            "src": src, "sport": int(sport), "dst": dst, "dport": int(dport), "proto": proto,
            "duration_ms": round(float(x[0]) / 1000.0, 3),
            "packets": int(flow.packet_count),
            "bytes": int(sum(p.getPacketSize() for p in flow.packetInfos)),
            "process": pname or "", "pid": pid,
            "label": v.label, "confidence": v.confidence, "attack_prob": v.attack_prob,
            "anomaly_score": v.anomaly_score, "risk": v.risk, "severity": v.severity, "verdict": v.verdict,
            "src_country": self.geo.country(src), "dst_country": self.geo.country(dst),
            "source": source, "end_reason": reason, "detection": None,
            "probs": v.probs, "features": [round(float(f), 6) for f in x],
        }
        if self.cfg.scan_detection and rec["verdict"] != "malicious":
            hit = self.scans.observe(source, rec["ts_end"], src, dst, rec["dport"], rec["packets"], rec["bytes"])
            if hit:
                # The model saw this flow alone; correlation across flows shows reconnaissance.
                rec["label"], rec["verdict"] = "Probe", "malicious"
                rec["risk"] = max(rec["risk"], min(90.0, 70.0 + hit.count / 10.0))
                rec["severity"] = risk_to_severity(rec["risk"])
                rec["detection"] = hit.describe()
        rec["id"] = self.storage.insert_flow(rec)
        rec["is_anomaly"] = v.is_anomaly
        self.stats.record(rec)

        alert = self.alerts.evaluate(rec)
        if job is not None:
            job["flows"] += 1
            if rec["verdict"] != "benign":
                job["threats"] += 1

        light = {k: rec[k] for k in ("id", "ts_start", "ts_end", "src", "sport", "dst", "dport", "proto",
                                     "duration_ms", "packets", "bytes", "process", "pid", "label", "confidence",
                                     "risk", "severity", "verdict", "anomaly_score", "src_country",
                                     "dst_country", "source", "detection")}
        with self._pending_lock:
            self._pending_flows.append(light)
            if alert:
                alert = {k: val for k, val in alert.items() if k != "intel"}
                self._pending_alerts[alert["id"]] = alert

    # ------------------------------------------------------- live updates
    def summary(self) -> dict:
        snap = self.stats.snapshot(self.live.packets)
        snap.update({
            "active_flows": len(self.live),
            "packets_total": self.live.packets + self.stats.offline_packets,
            "packets_live": self.live.packets,
            "queue_depth": self._q.qsize(),
            "capture": dict(self.capture_state),
            "alerts": self.storage.alert_counts(),
            "baseline": self.detector.baseline_status(),
            "jobs": sorted(self.jobs.values(), key=lambda j: -j["started"])[:10],
        })
        return snap

    def _broadcaster(self):
        while not self._stop.wait(1.0):
            if self.socketio is None:
                continue
            with self._pending_lock:
                flows = list(self._pending_flows)
                self._pending_flows.clear()
                alerts = list(self._pending_alerts.values())
                self._pending_alerts.clear()
            try:
                self.socketio.emit("tick", {"summary": self.summary(), "flows": flows, "alerts": alerts},
                                   namespace="/live")
            except Exception:
                log.exception("broadcast failed")

    def _housekeeping(self):
        last_prune = 0.0
        while not self._stop.wait(5.0):
            self.live.sweep(time.time())
            if time.time() - last_prune > 3600:
                last_prune = time.time()
                try:
                    n = self.storage.prune(self.cfg.retention_days)
                    if n:
                        log.info("Retention: pruned %d flows older than %s days", n, self.cfg.retention_days)
                except Exception:
                    log.exception("prune failed")

    # ------------------------------------------------------------- detail
    def flow_detail(self, flow_id: int) -> dict | None:
        rec = self.storage.get_flow(flow_id)
        if not rec:
            return None
        feats = rec["features"]
        from .features import FEATURE_KEYS, FEATURE_LABELS

        rec["feature_table"] = [{"key": k, "label": lbl, "value": feats[i] if i < len(feats) else None}
                                for i, (k, lbl) in enumerate(zip(FEATURE_KEYS, FEATURE_LABELS))]
        rec["explanation"] = self.detector.explain(feats)
        rec["reconstruction"] = self.detector.reconstruction_report(feats)
        rec["intel"] = THREAT_INTEL.get(rec["label"], THREAT_INTEL["Anomaly"])
        if rec["label"] == "Benign" and rec["verdict"] == "suspicious" and (rec["anomaly_score"] or 0) > 1:
            rec["intel"] = THREAT_INTEL["Anomaly"]
        rec["src_country"] = rec["src_country"] or self.geo.country(rec["src"])
        rec["dst_country"] = rec["dst_country"] or self.geo.country(rec["dst"])
        return rec
