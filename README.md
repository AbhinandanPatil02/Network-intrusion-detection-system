# Sentinel NIDS — Network Intrusion Detection System

Real-time, ML-driven network intrusion detection. Sentinel captures traffic (live or from a PCAP), assembles packets into bidirectional **flows**, extracts 39 CIC-IDS2017-style flow features, and runs a **hybrid detector** on each completed flow:

- **Classification**: a Random Forest predicts one of eight classes: Benign, Botnet, DDoS, DoS, FTP-Patator, SSH-Patator, Probe, Web Attack.
- **Anomaly detection**: an autoencoder trained on benign traffic scores how unusual each flow is. The threshold **self-calibrates** to your network from the flows the classifier considers benign.
- **Explainability**: a LIME-style local surrogate shows which features drove each verdict, next to a per-feature reconstruction-error breakdown.

Results go to SQLite, a SIEM-friendly JSON alert log and an optional webhook. They also stream live to an authenticated web console.

---

## Features

- **Live capture** on any interface with a configurable BPF filter, plus **offline PCAP analysis** (from the CLI or by uploading in the console).
- **Scan detection across connections**: port scans and host sweeps are spread over many tiny connections that each look harmless, so the per-connection model misses them. A sliding-window tracker per source address catches them; those connections are relabelled Probe, and the model's own verdict stays visible.
- **Alert correlation and deduplication**: repeated hits from the same source/destination/category are folded into one alert with an occurrence count. Alerts can be acknowledged or resolved.
- **Risk scoring and severity** (low / medium / high / critical), with MITRE ATT&CK tactic/technique and recommendations for each attack family.
- **Allowlist / blocklist** for IPs and CIDRs.
- **Enrichment**: the local process that owns each flow (psutil, cached and off the packet path) and the country of each IP (ipinfo.io, cached, rate-limit aware, can be turned off).
- **Web console**: live dashboard, traffic timeline, flow feed, alert queue, flow drill-down drawer, PCAP jobs, system and config view, CSV export, audible alerts for critical events.
- **Security defaults**: binds to localhost, login required, CSRF protection, generated secret key and admin password. It refuses to expose an unauthenticated console beyond localhost.
- **No TensorFlow at runtime**: the Keras autoencoder is evaluated in pure NumPy straight from its HDF5 file.
- **Retention**: flows older than `NIDS_RETENTION_DAYS` are pruned automatically.

---

## Architecture

```
 capture (scapy: live iface / PCAP)
        │ packets
        ▼
 flow assembly ── flow/Flow.py, FlowFeature.py, PacketInfo.py
        │ completed flows (idle / active timeout, FIN/RST)
        ▼
 enrichment ── process owner (psutil), GeoIP (ipinfo.io)
        ▼
 detector ── Random Forest  +  NumPy autoencoder (adaptive threshold)  +  surrogate explainer
        ▼
 correlation ── per-source scan detection (port scan / host sweep)
        ▼
 alerts ── correlation/dedup → SQLite · data/alerts.jsonl · webhook
        ▼
 web console ── Flask REST API + Socket.IO (/live namespace)
```

| Module | Responsibility |
|---|---|
| `application.py` | CLI entry point: parses options, starts the engine and the web server |
| `nids/config.py` | All settings (`NIDS_*` env vars, with CLI overrides) |
| `nids/engine.py` | Capture → flows → analysis → storage/alerts → live UI pipeline; PCAP jobs; retention |
| `nids/detector.py` | Random Forest, NumPy autoencoder, adaptive baseline, explanations |
| `nids/features.py` | The 39 feature definitions (order must match the models), threat intel, port names |
| `nids/enrichment.py` | Process attribution and GeoIP lookups |
| `nids/correlation.py` | Scan detection across connections (port scans, host sweeps) |
| `nids/alerts.py` | Alert correlation, JSONL SIEM log, webhook worker |
| `nids/storage.py` | SQLite (WAL) persistence for flows and alerts |
| `nids/web.py` | Flask app, auth, CSRF, REST API, Socket.IO |
| `flow/` | Packet parsing and per-flow feature computation |
| `templates/`, `static/` | Console UI (vanilla JS, Chart.js and Socket.IO vendored, so it works offline) |

---

## Requirements

- **Python 3.10 or 3.11.** `scikit-learn` is pinned to 1.2.0 because the bundled Random Forest was pickled with that version, and 1.2.0 has no wheels for newer Pythons.
- **Packet capture driver**: [Npcap](https://npcap.com/) on Windows (install with "WinPcap API-compatible mode"), libpcap on Linux/macOS.
- **Administrator / root** rights for live capture. PCAP analysis does not need them.
- Model files in `models/`:

| File | Purpose |
|---|---|
| `model.pkl` | Random Forest classifier |
| `scaler.pkl` | Feature scaler for the classifier (optional) |
| `autoencoder_39ft.hdf5` | Keras autoencoder weights (read with h5py) |
| `preprocess_pipeline_AE_39ft.save` | Preprocessing pipeline for the autoencoder |

---

## Installation

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux / macOS
source .venv/bin/activate

pip install -r requirements.txt
```

---

## Running

```bash
python application.py                         # live capture on the default interface
python application.py --list-interfaces       # show capture interfaces
python application.py --iface "Wi-Fi"         # capture on a specific interface
python application.py --pcap capture.pcap     # analyse a capture at startup
python application.py --no-capture            # console only (analyse uploaded PCAPs)
python application.py --set-password          # change the admin password
python application.py --help                  # all options
```

Then open **http://127.0.0.1:5000/**.

**First login:** on first start an admin password is generated. It is printed to the console and written to `data/INITIAL_ADMIN_PASSWORD.txt`. Sign in as `admin`, then change it with `--set-password` and delete that file. You can also set `NIDS_ADMIN_PASSWORD` before the first start.

**Anomaly warm-up:** the autoencoder threshold calibrates from the first `NIDS_ANOMALY_WARMUP` (default 200) benign flows. Until then only classifier verdicts raise alerts. The dashboard shows the calibration status.

---

## Configuration

Every setting is an environment variable. The most common ones also have CLI flags.

| Variable | Default | Description |
|---|---|---|
| `NIDS_HOST` / `--host` | `127.0.0.1` | Bind address. Using `0.0.0.0` requires auth to be on |
| `NIDS_PORT` / `--port` | `5000` | Console port |
| `NIDS_AUTH` / `--no-auth` | `true` | Require login |
| `NIDS_ADMIN_USER` | `admin` | Admin username |
| `NIDS_ADMIN_PASSWORD` | *(generated)* | Initial admin password |
| `NIDS_INTERFACE` / `--iface` | *(default)* | Capture interface |
| `NIDS_BPF` / `--bpf` | `ip and (tcp or udp)` | BPF capture filter |
| `NIDS_CAPTURE` / `--no-capture` | `true` | Start live capture |
| `NIDS_PCAP` / `--pcap` | | PCAP to analyse at startup |
| `NIDS_IDLE_TIMEOUT` | `60` | Seconds of inactivity before a flow is closed |
| `NIDS_ACTIVE_TIMEOUT` | `600` | Maximum flow lifetime in seconds |
| `NIDS_MAX_FLOWS` | `100000` | Maximum number of concurrently tracked flows |
| `NIDS_MAX_PACKETS_PER_FLOW` | `20000` | Packets per flow before it is force-closed |
| `NIDS_ALERT_MIN_CONFIDENCE` | `0.6` | Minimum classifier confidence that raises an alert |
| `NIDS_ANOMALY_ALERTS` | `true` | Raise alerts for autoencoder anomalies |
| `NIDS_ANOMALY_PERCENTILE` | `99.5` | Baseline percentile used as the anomaly threshold |
| `NIDS_ANOMALY_WARMUP` | `200` | Benign flows needed to calibrate the threshold |
| `NIDS_ALERT_DEDUP_WINDOW` | `300` | Seconds within which repeat hits merge into one alert |
| `NIDS_SCAN_DETECTION` | `true` | Detect scans across connections |
| `NIDS_SCAN_WINDOW` | `60` | Sliding window for scan detection, in seconds |
| `NIDS_SCAN_PORT_THRESHOLD` | `25` | Distinct ports on one host that count as a port scan |
| `NIDS_SCAN_HOST_THRESHOLD` | `20` | Distinct hosts on one port that count as a host sweep |
| `NIDS_ALLOWLIST` / `NIDS_BLOCKLIST` | | Comma-separated IPs/CIDRs |
| `NIDS_GEOIP` / `--no-geoip` | `true` | ipinfo.io country lookups |
| `NIDS_IPINFO_TOKEN` | | Optional ipinfo.io token (higher rate limit) |
| `NIDS_WEBHOOK_URL` | | POST alerts as JSON (Slack/Discord/Teams-compatible `text`/`content`) |
| `NIDS_WEBHOOK_MIN_SEVERITY` | `high` | Lowest severity sent to the webhook |
| `NIDS_DATA_DIR` / `--data-dir` | `./data` | Database, logs, uploads, secrets |
| `NIDS_MODELS_DIR` | `./models` | Model artifacts |
| `NIDS_RETENTION_DAYS` | `30` | Prune flows (and resolved alerts) older than this |
| `NIDS_MAX_UPLOAD_MB` | `200` | Maximum PCAP upload size |

---

## Outputs

| Path | Contents |
|---|---|
| `data/nids.sqlite3` | All flows (features, verdicts, enrichment) and alerts |
| `data/alerts.jsonl` | One JSON event per alert, ECS-like fields, ready for a SIEM (Splunk, Elastic, Wazuh…) |
| `data/uploads/` | Uploaded PCAPs |
| `data/secret.key`, `data/credentials.json` | Session key and hashed admin credentials. Keep these private |

`data/` is gitignored. The console also exports flows and alerts as CSV (`/api/export/flows.csv`, `/api/export/alerts.csv`).

---

## REST API

All endpoints except `/api/health` require a logged-in session. State-changing requests need the `X-CSRF-Token` header; its value is in the `csrf-token` meta tag of the dashboard.

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/health` | Liveness check |
| GET | `/api/summary` | Counters, capture status, baseline, timeline |
| GET | `/api/flows` | Paged flow list (filterable) |
| GET | `/api/flows/<id>` | Flow detail with feature table, explanation, reconstruction report, threat intel |
| GET | `/api/alerts` | Alert list |
| POST | `/api/alerts/<id>` | Acknowledge or resolve an alert |
| POST | `/api/capture` | Start or stop live capture |
| POST | `/api/pcap` | Upload a PCAP (`file` form field) for analysis |
| GET | `/api/jobs` | PCAP job status |
| GET | `/api/system`, `/api/interfaces` | Host and interface info |

Live updates are pushed on the Socket.IO namespace `/live` (`tick` events).

---

## Limitations

- **Model generalisation**: the models were trained on CIC-IDS2017. Real networks differ, so expect some false positives and negatives. The adaptive anomaly baseline helps, but verdicts are not ground truth.
- **Flow-based detection**: the model judges each flow on its own. Scan detection covers port scans and host sweeps. Other attacks spread over many flows, such as slow scans longer than `NIDS_SCAN_WINDOW` or distributed sources, can still go unnoticed. The first probes of a scan, before the threshold is reached, stay labelled Benign.
- **Explanations** come from a local surrogate model. They approximate the classifier's behaviour around one flow and do not prove causation.
- **Visibility**: only traffic the capturing host can see is analysed. Use a SPAN/mirror port or a TAP to monitor a whole network.
- **Transport security**: the console speaks plain HTTP. Put it behind a TLS reverse proxy before exposing it beyond localhost.

---

## Troubleshooting

| Issue | Fix |
|---|---|
| No packets / permission denied | Run as Administrator (Windows) or with `sudo` / `cap_net_raw` (Linux) |
| No interfaces listed | Install Npcap (Windows) or libpcap; check `--list-interfaces` |
| `scikit-learn==1.2.0` fails to install | Use Python 3.10 or 3.11 |
| Model files not found | Put the files listed above in `models/`, or set `NIDS_MODELS_DIR` |
| Countries always blank | Check outbound HTTPS, set `NIDS_IPINFO_TOKEN`, or turn GeoIP off with `--no-geoip` |
| Forgot the admin password | `python application.py --set-password` |
| "Refusing to expose the console…" | You used `--host 0.0.0.0` with `--no-auth`. Turn auth back on |
