"""Flow enrichment: local process attribution and IP geolocation.

Both lookups are cached and run off the packet path — the original code called
``psutil.net_connections()`` twice per packet and ipinfo.io synchronously per
flow, which throttled capture to a crawl under any real load.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import queue
import threading
import time
import urllib.request
from collections import OrderedDict

import psutil

log = logging.getLogger(__name__)


class ProcessMap:
    """Port -> (pid, process name) map, refreshed in the background."""

    def __init__(self, refresh_seconds: float = 3.0):
        self.refresh_seconds = refresh_seconds
        self._ports: dict[int, tuple[int | None, str]] = {}
        self._names: dict[int, str] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self.available = True
        self._thread = threading.Thread(target=self._run, name="process-map", daemon=True)

    def start(self):
        self._refresh()
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _name(self, pid: int | None) -> str:
        if not pid:
            return ""
        if pid not in self._names:
            try:
                self._names[pid] = psutil.Process(pid).name()
            except (psutil.Error, OSError):
                self._names[pid] = ""
        return self._names[pid]

    def _refresh(self):
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError) as exc:
            if self.available:
                log.warning("Process attribution unavailable: %s", exc)
            self.available = False
            return
        ports: dict[int, tuple[int | None, str]] = {}
        for c in conns:
            if c.laddr and c.pid:
                ports[c.laddr.port] = (c.pid, self._name(c.pid))
        if len(self._names) > 5000:
            self._names.clear()
        with self._lock:
            self._ports = ports

    def _run(self):
        while not self._stop.wait(self.refresh_seconds):
            self._refresh()

    def lookup(self, sport: int, dport: int) -> tuple[int | None, str]:
        with self._lock:
            return self._ports.get(sport) or self._ports.get(dport) or (None, "")


def is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_global


class GeoResolver:
    """Asynchronous, cached country lookups via ipinfo.io (optional)."""

    def __init__(self, enabled: bool, token: str | None = None, max_cache: int = 20000):
        self.enabled = enabled
        self.token = token
        self.max_cache = max_cache
        self._cache: OrderedDict[str, str | None] = OrderedDict()
        self._pending: set[str] = set()
        self._q: queue.Queue[str] = queue.Queue(maxsize=5000)
        self._lock = threading.Lock()
        self._backoff_until = 0.0
        self._thread = threading.Thread(target=self._run, name="geoip", daemon=True)

    def start(self):
        if self.enabled:
            self._thread.start()

    def country(self, ip: str) -> str | None:
        """Return the cached country code ('LAN' for private), queueing a lookup if unknown."""
        if not is_public(ip):
            return "LAN"
        if not self.enabled:
            return None
        with self._lock:
            if ip in self._cache:
                self._cache.move_to_end(ip)
                return self._cache[ip]
            if ip in self._pending:
                return None
            self._pending.add(ip)
        try:
            self._q.put_nowait(ip)
        except queue.Full:
            with self._lock:
                self._pending.discard(ip)
        return None

    def _fetch(self, ip: str) -> str | None:
        url = f"https://ipinfo.io/{ip}/json"
        if self.token:
            url += f"?token={self.token}"
        req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "sentinel-nids"})
        with urllib.request.urlopen(req, timeout=4) as res:
            data = json.load(res)
        country = data.get("country")
        return country.upper() if isinstance(country, str) and len(country) == 2 else None

    def _run(self):
        while True:
            ip = self._q.get()
            wait = self._backoff_until - time.time()
            if wait > 0:
                time.sleep(wait)
            try:
                result = self._fetch(ip)
            except urllib.error.HTTPError as exc:
                result = None
                if exc.code == 429:
                    self._backoff_until = time.time() + 60
                    log.warning("ipinfo.io rate limit hit; backing off 60s")
            except Exception:
                result = None
            with self._lock:
                self._pending.discard(ip)
                self._cache[ip] = result
                while len(self._cache) > self.max_cache:
                    self._cache.popitem(last=False)
