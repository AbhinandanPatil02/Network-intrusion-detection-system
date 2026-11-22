"""Lightweight HTTP target to absorb the flood during NIDS testing.

Run this FIRST, then point ddos_test.py at this machine's Wi-Fi IP so the
packets cross the network your NIDS is sniffing.

    python tools/target_server.py            # listens on 0.0.0.0:8000
    python tools/target_server.py 9000       # custom port

Reachable from this PC or other devices on the hotspot at <wifi-ip>:<port>.
"""
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8000


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):  # silence per-request console spam
        pass


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"Target server listening on http://0.0.0.0:{PORT}")
    print("Reachable over Wi-Fi at <your-wifi-ip>:%d  (e.g. 172.24.77.76:%d)" % (PORT, PORT))
    print("Press Ctrl+C to stop.")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
