"""Cross-flow correlation: reconnaissance that is invisible flow-by-flow.

The classifier judges every flow in isolation, so a SYN scan — hundreds of
one-packet flows, each individually unremarkable — sails through as Benign.
This module tracks, per source address, the distinct destination ports and
hosts it has touched inside a sliding time window and flags:

* **vertical port scans** — one source probing many ports on one host;
* **horizontal sweeps**   — one source probing one port across many hosts.

Time is taken from the flows themselves, so PCAP replay behaves like live
capture. Each source (live capture or a PCAP job) gets its own tracker.
"""
from __future__ import annotations

import threading
from collections import OrderedDict, deque
from dataclasses import dataclass


@dataclass
class ScanHit:
    kind: str        # "port-scan" | "host-sweep"
    count: int       # distinct ports (port-scan) or hosts (host-sweep)
    window: float

    def describe(self) -> str:
        if self.kind == "port-scan":
            return f"Port scan: {self.count} distinct ports on one host within {self.window:.0f}s"
        return f"Host sweep: {self.count} distinct hosts on one port within {self.window:.0f}s"


class _SourceState:
    __slots__ = ("events",)

    def __init__(self):
        self.events: deque[tuple[float, str, int]] = deque()  # (ts, dst, dport)


class ScanDetector:
    """Sliding-window fan-out detector keyed by source IP."""

    def __init__(self, window: float = 60.0, port_threshold: int = 25, host_threshold: int = 20,
                 max_sources: int = 50000, max_events_per_source: int = 5000):
        self.window = window
        self.port_threshold = port_threshold
        self.host_threshold = host_threshold
        self.max_sources = max_sources
        self.max_events = max_events_per_source
        self._lock = threading.Lock()
        self._trackers: dict[str, OrderedDict[str, _SourceState]] = {}

    def observe(self, tracker: str, ts: float, src: str, dst: str, dport: int,
                packets: int, bytes_: int) -> ScanHit | None:
        # Only short, small flows count as probes; a real session to many ports
        # (e.g. a browser) carries data and is not reconnaissance.
        if packets > 4 or bytes_ > 1024 or dport is None:
            return None
        with self._lock:
            sources = self._trackers.setdefault(tracker, OrderedDict())
            st = sources.get(src)
            if st is None:
                st = sources[src] = _SourceState()
                if len(sources) > self.max_sources:
                    sources.popitem(last=False)
            else:
                sources.move_to_end(src)

            ev = st.events
            ev.append((ts, dst, int(dport)))
            cutoff = ts - self.window
            while ev and ev[0][0] < cutoff:
                ev.popleft()
            while len(ev) > self.max_events:
                ev.popleft()

            ports = len({p for _, d, p in ev if d == dst})
            if ports >= self.port_threshold:
                return ScanHit("port-scan", ports, self.window)
            hosts = len({d for _, d, p in ev if p == dport})
            if hosts >= self.host_threshold:
                return ScanHit("host-sweep", hosts, self.window)
        return None

    def drop(self, tracker: str) -> None:
        """Forget a finished PCAP job's state."""
        with self._lock:
            self._trackers.pop(tracker, None)
