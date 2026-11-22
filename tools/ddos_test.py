"""GET-request flood for testing your OWN NIDS on your OWN local network.

Authorized self-testing only: point it at a machine you control (here, the
PC running Sentinel NIDS, or its target_server.py) on your own hotspot.

    python tools/ddos_test.py 172.24.77.76 8000 30
    python tools/ddos_test.py <target-ip> <port> <seconds> [threads]

Each request uses a fresh TCP connection, so the NIDS sees many short flows
from one source -- the pattern its scan/flood correlation is built to catch.
"""
import socket
import sys
import threading
import time

TARGET = sys.argv[1] if len(sys.argv) > 1 else "172.24.77.76"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8000
SECONDS = int(sys.argv[3]) if len(sys.argv) > 3 else 30
THREADS = int(sys.argv[4]) if len(sys.argv) > 4 else 200

stop_at = time.time() + SECONDS
sent = 0
errors = 0
lock = threading.Lock()

REQUEST = (
    "GET /?{} HTTP/1.1\r\n"
    f"Host: {TARGET}\r\n"
    "User-Agent: nids-ddos-test\r\n"
    "Connection: close\r\n\r\n"
)


def worker():
    global sent, errors
    while time.time() < stop_at:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((TARGET, PORT))
            s.sendall(REQUEST.format(time.time_ns()).encode())
            try:
                s.recv(256)
            except Exception:
                pass
            s.close()
            with lock:
                sent += 1
        except Exception:
            with lock:
                errors += 1


def progress():
    while time.time() < stop_at:
        time.sleep(2)
        with lock:
            print(f"  sent={sent}  errors={errors}  elapsed={int(SECONDS - (stop_at - time.time()))}s")


if __name__ == "__main__":
    print(f"Flooding {TARGET}:{PORT} for {SECONDS}s with {THREADS} threads...")
    threading.Thread(target=progress, daemon=True).start()
    ts = [threading.Thread(target=worker, daemon=True) for _ in range(THREADS)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    print(f"Done. ~{sent} requests sent, {errors} connection errors.")
