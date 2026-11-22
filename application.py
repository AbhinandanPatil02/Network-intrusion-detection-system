"""Sentinel NIDS — entry point.

Examples
--------
    python application.py                          # live capture on the default interface
    python application.py --iface "Wi-Fi"          # pick an interface (see --list-interfaces)
    python application.py --pcap capture.pcap     # offline / forensic analysis of a capture
    python application.py --no-capture             # console only (analyse uploaded PCAPs)
    python application.py --set-password           # change the admin password

Every option can also be set via environment variables (NIDS_*); see README.md.
Live capture needs Administrator/root rights and Npcap (Windows) or libpcap.
"""
from __future__ import annotations

import argparse
import getpass
import logging
import signal
import sys
import warnings

from nids import __version__
from nids.config import Config


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Sentinel NIDS — ML network intrusion detection")
    p.add_argument("--host", help="bind address (default 127.0.0.1; use 0.0.0.0 to expose on the LAN)")
    p.add_argument("--port", type=int, help="web console port (default 5000)")
    p.add_argument("--iface", help="capture interface name")
    p.add_argument("--bpf", help='BPF capture filter (default "ip and (tcp or udp)")')
    p.add_argument("--pcap", help="analyse a pcap/pcapng file at startup")
    p.add_argument("--no-capture", action="store_true", help="do not start live capture")
    p.add_argument("--no-auth", action="store_true", help="disable login (local development only)")
    p.add_argument("--no-geoip", action="store_true", help="disable ipinfo.io country lookups")
    p.add_argument("--data-dir", help="directory for database, logs and uploads")
    p.add_argument("--list-interfaces", action="store_true", help="list capture interfaces and exit")
    p.add_argument("--set-password", action="store_true", help="set the admin password and exit")
    p.add_argument("--debug", action="store_true", help="verbose logging")
    p.add_argument("--version", action="version", version=f"Sentinel NIDS {__version__}")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s", datefmt="%H:%M:%S")
    for noisy in ("werkzeug", "engineio", "socketio", "scapy.runtime"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    warnings.filterwarnings("ignore", category=UserWarning)

    cfg = Config()
    if args.host: cfg.host = args.host
    if args.port: cfg.port = args.port
    if args.iface: cfg.interface = args.iface
    if args.bpf is not None: cfg.bpf_filter = args.bpf
    if args.pcap: cfg.pcap_file = args.pcap
    if args.no_capture: cfg.capture_enabled = False
    if args.no_auth: cfg.auth_enabled = False
    if args.no_geoip: cfg.geoip_enabled = False
    if args.data_dir:
        from pathlib import Path
        cfg.data_dir = Path(args.data_dir)
    cfg.ensure_dirs()

    if args.list_interfaces:
        from nids.web import list_interfaces
        for i in list_interfaces():
            print(f"{i['name']:<40} {i['ip']:<16} {i['description']}")
        return 0

    if args.set_password:
        from nids.web import set_password
        user = input(f"Username [{cfg.admin_user}]: ").strip() or cfg.admin_user
        pw = getpass.getpass("New password (min 10 chars): ")
        if len(pw) < 10 or pw != getpass.getpass("Repeat: "):
            print("Passwords do not match or are too short.")
            return 1
        set_password(cfg, user, pw)
        print("Password updated.")
        return 0

    from nids.engine import Engine
    from nids.web import create_app

    log = logging.getLogger("nids")
    if cfg.host not in ("127.0.0.1", "localhost") and not cfg.auth_enabled:
        log.error("Refusing to expose the console on %s without authentication.", cfg.host)
        return 2

    app, socketio, engine = create_app(cfg, lambda sio: Engine(cfg, sio))
    engine.start()

    def shutdown(*_):
        log.info("Shutting down — flushing active flows…")
        engine.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    log.info("Sentinel NIDS %s console: http://%s:%d/", __version__,
             "127.0.0.1" if cfg.host == "0.0.0.0" else cfg.host, cfg.port)
    socketio.run(app, host=cfg.host, port=cfg.port, debug=False, use_reloader=False,
                 allow_unsafe_werkzeug=True, log_output=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
