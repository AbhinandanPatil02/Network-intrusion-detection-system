"""Flask web console + REST API + Socket.IO live channel."""
from __future__ import annotations

import csv
import io
import json
import logging
import secrets
import time
from collections import defaultdict, deque
from functools import wraps

from flask import (Flask, Response, abort, jsonify, redirect, render_template, request, session,
                   stream_with_context, url_for)
from flask_socketio import SocketIO, disconnect
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from . import __version__
from .features import FEATURE_LABELS, THREAT_INTEL

log = logging.getLogger(__name__)

ALLOWED_CAPTURE_EXT = {".pcap", ".pcapng", ".cap"}


# ---------------------------------------------------------------- credentials
def load_secret_key(cfg) -> str:
    path = cfg.data_dir / "secret.key"
    if path.exists():
        return path.read_text().strip()
    key = secrets.token_hex(32)
    path.write_text(key)
    return key


def set_password(cfg, user: str, password: str) -> None:
    path = cfg.data_dir / "credentials.json"
    path.write_text(json.dumps({"user": user, "hash": generate_password_hash(password)}))
    initial = cfg.data_dir / "INITIAL_ADMIN_PASSWORD.txt"
    if initial.exists():
        initial.unlink()


def load_credentials(cfg) -> tuple[str, str]:
    """Return (user, password_hash). Generates a random admin password on first run."""
    if cfg.admin_password:
        return cfg.admin_user, generate_password_hash(cfg.admin_password)
    path = cfg.data_dir / "credentials.json"
    if path.exists():
        data = json.loads(path.read_text())
        return data["user"], data["hash"]
    password = secrets.token_urlsafe(12)
    set_password(cfg, cfg.admin_user, password)
    (cfg.data_dir / "INITIAL_ADMIN_PASSWORD.txt").write_text(
        f"user: {cfg.admin_user}\npassword: {password}\n"
        "Change it with: python application.py --set-password\n")
    log.warning("=" * 64)
    log.warning(" First run — generated admin credentials")
    log.warning("   user:     %s", cfg.admin_user)
    log.warning("   password: %s", password)
    log.warning(" (also saved to %s)", cfg.data_dir / "INITIAL_ADMIN_PASSWORD.txt")
    log.warning("=" * 64)
    return cfg.admin_user, generate_password_hash(password)


# ------------------------------------------------------------------- factory
def create_app(cfg, engine_factory):
    app = Flask(__name__, template_folder="../templates", static_folder="../static")
    app.config.update(
        SECRET_KEY=load_secret_key(cfg),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        MAX_CONTENT_LENGTH=cfg.max_upload_mb * 1024 * 1024,
        JSON_SORT_KEYS=False,
    )
    socketio = SocketIO(app, async_mode="threading", logger=False, engineio_logger=False,
                        cors_allowed_origins=None)
    engine = engine_factory(socketio)
    admin_user, admin_hash = load_credentials(cfg) if cfg.auth_enabled else ("analyst", "")
    failed_logins: dict[str, deque] = defaultdict(lambda: deque(maxlen=10))

    # -------------------------------------------------------------- helpers
    def logged_in() -> bool:
        return not cfg.auth_enabled or bool(session.get("user"))

    def csrf_token() -> str:
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(24)
        return session["csrf"]

    def login_required(view):
        @wraps(view)
        def wrapper(*a, **kw):
            if not logged_in():
                if request.path.startswith("/api/"):
                    return jsonify(error="authentication required"), 401
                return redirect(url_for("login", next=request.path))
            if request.method in ("POST", "PUT", "PATCH", "DELETE"):
                token = request.headers.get("X-CSRF-Token") or request.form.get("csrf")
                if not token or not secrets.compare_digest(token, session.get("csrf", "")):
                    return jsonify(error="invalid CSRF token"), 403
            return view(*a, **kw)
        return wrapper

    @app.context_processor
    def inject():
        return {"csrf_token": csrf_token, "version": __version__,
                "current_user": session.get("user") or ("analyst" if not cfg.auth_enabled else None),
                "auth_enabled": cfg.auth_enabled}

    @app.after_request
    def security_headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self' ws: wss:; frame-ancestors 'none'")
        return resp

    # --------------------------------------------------------------- pages
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if not cfg.auth_enabled:
            return redirect(url_for("index"))
        error = None
        if request.method == "POST":
            ip = request.remote_addr or "?"
            attempts = failed_logins[ip]
            recent = [t for t in attempts if time.time() - t < 300]
            if len(recent) >= 5:
                error = "Too many failed attempts. Try again in a few minutes."
            elif (secrets.compare_digest(request.form.get("username", ""), admin_user)
                  and check_password_hash(admin_hash, request.form.get("password", ""))):
                session.clear()
                session["user"] = admin_user
                session.permanent = True
                log.info("Login success for %s from %s", admin_user, ip)
                nxt = request.args.get("next", "/")
                return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else "/")
            else:
                attempts.append(time.time())
                log.warning("Login failure from %s", ip)
                error = "Invalid username or password."
        return render_template("login.html", error=error)

    @app.route("/logout", methods=["POST"])
    @login_required
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.route("/")
    @login_required
    def index():
        return render_template("dashboard.html", classes=engine.detector.classes, max_upload_mb=cfg.max_upload_mb)

    @app.route("/flow-detail")
    def legacy_flow_detail():
        return redirect(f"/#flow/{request.args.get('flow_id', '')}")

    # ----------------------------------------------------------------- API
    @app.get("/api/health")
    def health():
        return jsonify(status="ok", version=__version__, capture=engine.capture_state["status"])

    @app.get("/api/summary")
    @login_required
    def api_summary():
        return jsonify(engine.summary())

    @app.get("/api/flows")
    @login_required
    def api_flows():
        args = request.args
        limit = min(max(args.get("limit", 50, type=int), 1), 500)
        flows, total = engine.storage.list_flows(
            limit=limit, offset=max(args.get("offset", 0, type=int), 0),
            q=(args.get("q") or "").strip() or None, verdict=args.get("verdict") or None,
            label=args.get("label") or None, src=args.get("ip") or None,
            source=args.get("source") or None)
        return jsonify(flows=flows, total=total)

    @app.get("/api/flows/<int:flow_id>")
    @login_required
    def api_flow(flow_id):
        rec = engine.flow_detail(flow_id)
        if not rec:
            abort(404)
        return jsonify(rec)

    @app.get("/api/alerts")
    @login_required
    def api_alerts():
        alerts, total = engine.storage.list_alerts(
            status=request.args.get("status", "open"), severity=request.args.get("severity") or None,
            limit=min(request.args.get("limit", 100, type=int), 500),
            offset=request.args.get("offset", 0, type=int))
        for a in alerts:
            a["intel"] = THREAT_INTEL.get(a["category"], THREAT_INTEL["Anomaly"])
        return jsonify(alerts=alerts, total=total)

    @app.post("/api/alerts/<int:alert_id>")
    @login_required
    def api_alert_update(alert_id):
        body = request.get_json(silent=True) or {}
        status = body.get("status")
        if status not in {"open", "acknowledged", "resolved"}:
            return jsonify(error="status must be open|acknowledged|resolved"), 400
        note = (body.get("note") or "")[:1000] or None
        if not engine.storage.update_alert_status(alert_id, status, session.get("user", "analyst"), note):
            abort(404)
        log.info("Alert %s -> %s by %s", alert_id, status, session.get("user"))
        return jsonify(engine.storage.get_alert(alert_id))

    @app.post("/api/capture")
    @login_required
    def api_capture():
        action = (request.get_json(silent=True) or {}).get("action")
        if action == "start":
            return jsonify(engine.start_capture())
        if action == "stop":
            return jsonify(engine.stop_capture())
        return jsonify(error="action must be start|stop"), 400

    @app.post("/api/pcap")
    @login_required
    def api_pcap_upload():
        f = request.files.get("file")
        if not f or not f.filename:
            return jsonify(error="no file uploaded"), 400
        name = secure_filename(f.filename)
        ext = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
        if ext not in ALLOWED_CAPTURE_EXT:
            return jsonify(error="only .pcap, .pcapng and .cap files are accepted"), 400
        dest = cfg.data_dir / "uploads" / f"{int(time.time())}_{name}"
        f.save(dest)
        job_id = engine.analyze_pcap(dest, name)
        return jsonify(job=engine.jobs[job_id]), 202

    @app.get("/api/jobs")
    @login_required
    def api_jobs():
        return jsonify(jobs=sorted(engine.jobs.values(), key=lambda j: -j["started"]))

    @app.get("/api/system")
    @login_required
    def api_system():
        d = engine.detector
        return jsonify(
            version=__version__,
            config=cfg.public_dict(),
            capture=engine.capture_state,
            model={"type": type(d.classifier).__name__, "classes": d.classes,
                   "n_estimators": getattr(d.classifier, "n_estimators", None),
                   "features": len(FEATURE_LABELS), "autoencoder_layers": len(d.autoencoder.layers),
                   "global_importance": d.global_importance[:12]},
            baseline=d.baseline_status(),
            process_attribution=engine.processes.available,
        )

    @app.get("/api/interfaces")
    @login_required
    def api_interfaces():
        return jsonify(interfaces=list_interfaces())

    def _csv_response(rows, filename):
        def gen():
            buf = io.StringIO()
            w = csv.writer(buf)
            for row in rows:
                w.writerow(row)
                yield buf.getvalue()
                buf.seek(0)
                buf.truncate(0)
        return Response(stream_with_context(gen()), mimetype="text/csv",
                        headers={"Content-Disposition": f"attachment; filename={filename}"})

    @app.get("/api/export/flows.csv")
    @login_required
    def export_flows():
        return _csv_response(engine.storage.iter_flows_csv(
            verdict=request.args.get("verdict") or None, q=request.args.get("q") or None,
            label=request.args.get("label") or None, src=request.args.get("ip") or None,
            source=request.args.get("source") or None),
            f"flows_{time.strftime('%Y%m%d_%H%M%S')}.csv")

    @app.get("/api/export/alerts.csv")
    @login_required
    def export_alerts():
        return _csv_response(engine.storage.iter_alerts_csv(), f"alerts_{time.strftime('%Y%m%d_%H%M%S')}.csv")

    @app.errorhandler(413)
    def too_large(_):
        return jsonify(error=f"file exceeds {cfg.max_upload_mb} MB limit"), 413

    # ----------------------------------------------------------- socket.io
    @socketio.on("connect", namespace="/live")
    def ws_connect(auth=None):
        if not logged_in():
            disconnect()
            return False
        socketio.emit("tick", {"summary": engine.summary(), "flows": [], "alerts": []},
                      namespace="/live", to=request.sid)

    return app, socketio, engine


def list_interfaces() -> list[dict]:
    try:
        from scapy.all import conf

        out = []
        for iface in conf.ifaces.values():
            out.append({"name": getattr(iface, "name", str(iface)),
                        "description": getattr(iface, "description", ""),
                        "ip": getattr(iface, "ip", "") or "",
                        "mac": getattr(iface, "mac", "") or ""})
        return out
    except Exception as exc:
        return [{"name": "error", "description": str(exc), "ip": "", "mac": ""}]
