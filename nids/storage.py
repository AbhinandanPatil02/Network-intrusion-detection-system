"""SQLite persistence for flows and alerts (WAL mode, thread-safe)."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS flows (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_start      REAL NOT NULL,
    ts_end        REAL NOT NULL,
    src           TEXT NOT NULL,
    sport         INTEGER,
    dst           TEXT NOT NULL,
    dport         INTEGER,
    proto         TEXT,
    duration_ms   REAL,
    packets       INTEGER,
    bytes         INTEGER,
    process       TEXT,
    pid           INTEGER,
    label         TEXT,
    confidence    REAL,
    attack_prob   REAL,
    anomaly_score REAL,
    risk          REAL,
    severity      TEXT,
    verdict       TEXT,
    src_country   TEXT,
    dst_country   TEXT,
    source        TEXT,
    end_reason    TEXT,
    probs         TEXT,
    features      TEXT
);
CREATE INDEX IF NOT EXISTS ix_flows_ts      ON flows(ts_end);
CREATE INDEX IF NOT EXISTS ix_flows_verdict ON flows(verdict);
CREATE INDEX IF NOT EXISTS ix_flows_src     ON flows(src);

CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    first_seen  REAL NOT NULL,
    last_seen   REAL NOT NULL,
    severity    TEXT NOT NULL,
    category    TEXT NOT NULL,
    src         TEXT,
    dst         TEXT,
    dport       INTEGER,
    proto       TEXT,
    count       INTEGER NOT NULL DEFAULT 1,
    max_risk    REAL,
    confidence  REAL,
    flow_id     INTEGER,
    status      TEXT NOT NULL DEFAULT 'open',
    note        TEXT,
    updated_by  TEXT,
    updated_at  REAL
);
CREATE INDEX IF NOT EXISTS ix_alerts_status ON alerts(status, last_seen);
"""

FLOW_COLS = [
    "id", "ts_start", "ts_end", "src", "sport", "dst", "dport", "proto", "duration_ms", "packets", "bytes",
    "process", "pid", "label", "confidence", "attack_prob", "anomaly_score", "risk", "severity", "verdict",
    "src_country", "dst_country", "source", "end_reason", "detection",
]


class Storage:
    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(SCHEMA)
        self._migrate()

    def _migrate(self):
        cols = {r[1] for r in self._conn.execute("PRAGMA table_info(flows)")}
        if "ingested_at" not in cols:
            # Retention must key on ingestion time, not packet time — otherwise flows from an
            # older forensic PCAP would be pruned the moment they are stored.
            self._conn.execute("ALTER TABLE flows ADD COLUMN ingested_at REAL")
            self._conn.execute("UPDATE flows SET ingested_at = ts_end WHERE ingested_at IS NULL")
        self._conn.execute("CREATE INDEX IF NOT EXISTS ix_flows_ingested ON flows(ingested_at)")
        if "detection" not in cols:
            # Non-model detections (e.g. cross-flow scan correlation) that overrode the classifier.
            self._conn.execute("ALTER TABLE flows ADD COLUMN detection TEXT")

    def close(self):
        with self._lock:
            self._conn.close()

    # ---------------------------------------------------------------- flows
    def insert_flow(self, rec: dict) -> int:
        cols = [c for c in FLOW_COLS if c != "id"] + ["ingested_at", "probs", "features"]
        vals = [rec.get(c) for c in cols[:-3]] + [time.time(), json.dumps(rec.get("probs")),
                                                  json.dumps(rec.get("features"))]
        sql = f"INSERT INTO flows ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})"
        with self._lock:
            cur = self._conn.execute(sql, vals)
            return int(cur.lastrowid)

    def get_flow(self, flow_id: int) -> dict | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM flows WHERE id=?", (flow_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["probs"] = json.loads(d["probs"] or "{}")
        d["features"] = json.loads(d["features"] or "[]")
        return d

    def _flow_filters(self, q=None, verdict=None, label=None, since=None, src=None, source=None):
        where, args = [], []
        if source:
            where.append("source=?")
            args.append(source)
        if verdict:
            where.append("verdict=?")
            args.append(verdict)
        if label:
            where.append("label=?")
            args.append(label)
        if since:
            where.append("ts_end>=?")
            args.append(float(since))
        if src:
            where.append("(src=? OR dst=?)")
            args += [src, src]
        if q:
            like = f"%{q}%"
            where.append("(src LIKE ? OR dst LIKE ? OR process LIKE ? OR label LIKE ? OR CAST(dport AS TEXT)=? "
                         "OR CAST(sport AS TEXT)=? OR proto LIKE ?)")
            args += [like, like, like, like, q, q, like]
        return (" WHERE " + " AND ".join(where)) if where else "", args

    def list_flows(self, limit=50, offset=0, **filters) -> tuple[list[dict], int]:
        clause, args = self._flow_filters(**filters)
        with self._lock:
            total = self._conn.execute(f"SELECT COUNT(*) FROM flows{clause}", args).fetchone()[0]
            rows = self._conn.execute(
                f"SELECT {','.join(FLOW_COLS)} FROM flows{clause} ORDER BY id DESC LIMIT ? OFFSET ?",
                args + [int(limit), int(offset)],
            ).fetchall()
        return [dict(r) for r in rows], int(total)

    def iter_flows_csv(self, **filters):
        clause, args = self._flow_filters(**filters)
        with self._lock:
            rows = self._conn.execute(
                f"SELECT {','.join(FLOW_COLS)} FROM flows{clause} ORDER BY id DESC LIMIT 1000000", args
            ).fetchall()
        yield FLOW_COLS
        for r in rows:
            yield list(r)

    def top_counts(self, column: str, where: str = "", limit: int = 2000) -> list[tuple]:
        assert column in {"src", "dport"}
        with self._lock:
            return [tuple(r) for r in self._conn.execute(
                f"SELECT {column}, COUNT(*) n FROM flows {where} GROUP BY {column} ORDER BY n DESC LIMIT ?", (limit,))]

    def totals(self) -> dict:
        with self._lock:
            rows = self._conn.execute("SELECT label, verdict, COUNT(*) n FROM flows GROUP BY label, verdict").fetchall()
        return [dict(r) for r in rows]

    # --------------------------------------------------------------- alerts
    def find_recent_alert(self, category, src, dst, since) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM alerts WHERE category=? AND src=? AND dst=? AND last_seen>=? AND status!='resolved' "
                "ORDER BY id DESC LIMIT 1",
                (category, src, dst, since),
            ).fetchone()
        return dict(row) if row else None

    def insert_alert(self, a: dict) -> int:
        cols = ["first_seen", "last_seen", "severity", "category", "src", "dst", "dport", "proto",
                "count", "max_risk", "confidence", "flow_id", "status"]
        with self._lock:
            cur = self._conn.execute(
                f"INSERT INTO alerts ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})",
                [a.get(c) for c in cols],
            )
            return int(cur.lastrowid)

    def bump_alert(self, alert_id, last_seen, risk, severity, flow_id, confidence):
        with self._lock:
            self._conn.execute(
                "UPDATE alerts SET count=count+1, last_seen=?, max_risk=MAX(max_risk, ?), severity=?, flow_id=?, "
                "confidence=MAX(confidence, ?) WHERE id=?",
                (last_seen, risk, severity, flow_id, confidence, alert_id),
            )

    def get_alert(self, alert_id) -> dict | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
        return dict(row) if row else None

    def list_alerts(self, status=None, limit=100, offset=0, severity=None) -> tuple[list[dict], int]:
        where, args = [], []
        if status and status != "all":
            where.append("status=?")
            args.append(status)
        if severity:
            where.append("severity=?")
            args.append(severity)
        clause = (" WHERE " + " AND ".join(where)) if where else ""
        with self._lock:
            total = self._conn.execute(f"SELECT COUNT(*) FROM alerts{clause}", args).fetchone()[0]
            rows = self._conn.execute(
                f"SELECT * FROM alerts{clause} ORDER BY last_seen DESC LIMIT ? OFFSET ?",
                args + [int(limit), int(offset)],
            ).fetchall()
        return [dict(r) for r in rows], int(total)

    def update_alert_status(self, alert_id, status, user, note=None) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "UPDATE alerts SET status=?, updated_by=?, updated_at=?, note=COALESCE(?, note) WHERE id=?",
                (status, user, time.time(), note, alert_id),
            )
            return cur.rowcount > 0

    def alert_counts(self) -> dict:
        with self._lock:
            rows = self._conn.execute(
                "SELECT status, severity, COUNT(*) n FROM alerts GROUP BY status, severity").fetchall()
        out = {"open": 0, "acknowledged": 0, "resolved": 0, "open_by_severity": {}}
        for r in rows:
            out[r["status"]] = out.get(r["status"], 0) + r["n"]
            if r["status"] == "open":
                out["open_by_severity"][r["severity"]] = r["n"]
        return out

    def iter_alerts_csv(self):
        with self._lock:
            rows = self._conn.execute("SELECT * FROM alerts ORDER BY id DESC").fetchall()
        if rows:
            yield list(rows[0].keys())
        for r in rows:
            yield list(r)

    # ----------------------------------------------------------- retention
    def prune(self, older_than_days: float) -> int:
        cutoff = time.time() - older_than_days * 86400
        with self._lock:
            n = self._conn.execute("DELETE FROM flows WHERE ingested_at < ?", (cutoff,)).rowcount
            self._conn.execute("DELETE FROM alerts WHERE status='resolved' AND COALESCE(updated_at, last_seen) < ?",
                               (cutoff,))
        return n
