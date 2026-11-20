"""Referee console: follows router logs, receives station reports and serves a live dashboard.

    python -m lanshield.console -c config.json --log /var/log/dnsmasq.log --log /var/log/flows.csv
Then open http://<this machine>:8080 on the referee laptop.
"""
from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .netmon import NetworkDetector
from .rules import BAD, INFO, SEVERITY_RANK, Alert, Rules
from .station import evaluate

DASHBOARD = Path(__file__).with_name("dashboard.html")
STATION_STALE_S = 180   # no report for this long -> station shown as "no report"


class State:
    """All alerts and station status, shared between the log followers and the web server."""

    def __init__(self, rules: Rules, log_path: str | None = None):
        self.rules = rules
        self.lock = threading.Lock()
        self.alerts: list[dict] = []
        self.keys: dict[tuple, int] = {}      # alert key -> index in self.alerts
        self.last_report: dict[str, dict] = {}
        self.log_file = open(log_path, "a", encoding="utf-8") if log_path else None
        # One detector shared by every log follower, so a lookup seen in the DNS log
        # explains a connection seen in the flow log.
        self.detector = NetworkDetector(rules)
        self.det_lock = threading.Lock()
        self.add(Alert(INFO, "system", "all", f"Monitoring started for {rules.event}.", "system"))

    def add(self, alert: Alert) -> None:
        with self.lock:
            k = alert.key()
            if k in self.keys:                       # repeat: bump the count instead of a new row
                a = self.alerts[self.keys[k]]
                a["count"] += 1
                a["last_ts"] = alert.ts
                if a["status"] == "resolved":        # it came back after being cleared
                    a["status"] = "open"
                return
            d = alert.to_dict()
            d.update(id=len(self.alerts) + 1, count=1, last_ts=alert.ts,
                     status="open" if alert.severity != INFO else "info", note="")
            self.keys[k] = len(self.alerts)
            self.alerts.append(d)
            if self.log_file:                        # evidence trail for disputes
                self.log_file.write(json.dumps(d) + "\n")
                self.log_file.flush()

    def report(self, rep: dict) -> int:
        st = rep.get("station") or "unknown"
        found = evaluate(rep, self.rules)
        with self.lock:
            self.last_report[st] = {"ts": time.time(), "account": rep.get("account", ""),
                                    "hostname": rep.get("hostname", ""), "os": rep.get("os", ""),
                                    "programs": len(rep.get("processes", [])), "usb": len(rep.get("usb", []))}
        for a in found:
            self.add(a)
        if not found:
            self.add(Alert(INFO, "station_check", st, f"{st} passed the station check.", "station",
                           {"indicator": "pass"}))
        return len(found)

    def resolve(self, alert_id: int, note: str) -> bool:
        with self.lock:
            for a in self.alerts:
                if a["id"] == alert_id:
                    a["status"], a["note"], a["resolved_ts"] = "resolved", note, time.time()
                    if self.log_file:
                        self.log_file.write(json.dumps({"resolved": alert_id, "note": note, "ts": time.time()}) + "\n")
                        self.log_file.flush()
                    return True
        return False

    def snapshot(self) -> dict:
        now = time.time()
        with self.lock:
            stations = []
            for ip, info in self.rules.stations.items():
                sid = info["id"]
                open_alerts = [a for a in self.alerts if a["station"] == sid and a["status"] == "open"]
                worst = max((SEVERITY_RANK[a["severity"]] for a in open_alerts), default=0)
                rep = self.last_report.get(sid)
                stations.append({
                    "id": sid, "ip": ip, "team": info.get("team", ""), "player": info.get("player", ""),
                    "state": {0: "ok", 1: "warn", 2: "bad"}[worst],
                    "open": len(open_alerts),
                    "report_age": round(now - rep["ts"]) if rep else None,
                    "stale": (not rep) or now - rep["ts"] > STATION_STALE_S,
                    "account": rep["account"] if rep else "",
                })
            return {
                "event": self.rules.event, "now": now, "stations": stations,
                "alerts": list(reversed(self.alerts[-300:])),
                "open_bad": sum(a["status"] == "open" and a["severity"] == BAD for a in self.alerts),
                "open_warn": sum(a["status"] == "open" and a["severity"] != BAD for a in self.alerts),
            }


def follow(path: str, state: State, from_start: bool, stop: threading.Event) -> None:
    """Tail a log file like `tail -F`, feeding each new line to the network detector."""
    pos, inode = None, None
    while not stop.is_set():
        try:
            p = Path(path)
            st = p.stat()
            if inode != st.st_ino or (pos is not None and st.st_size < pos):   # new or rotated file
                inode, pos = st.st_ino, 0 if (from_start or pos is not None) else st.st_size
            with p.open(encoding="utf-8", errors="replace") as f:
                f.seek(pos)
                for line in f:
                    if not line.endswith("\n"):        # half-written line: read it next time
                        break
                    pos += len(line.encode("utf-8"))
                    with state.det_lock:
                        found = state.detector.feed(line)
                    for a in found:
                        state.add(a)
        except FileNotFoundError:
            pass
        with state.det_lock:
            found = state.detector.flush()
        for a in found:
            state.add(a)
        stop.wait(0.5)


def make_handler(state: State):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):  # keep the terminal quiet
            pass

        def _send(self, code: int, body: bytes, ctype: str = "application/json"):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _json_body(self) -> dict:
            n = int(self.headers.get("Content-Length") or 0)
            if n > 5_000_000:
                raise ValueError("too large")
            return json.loads(self.rfile.read(n) or b"{}")

        def do_GET(self):
            if self.path in ("/", "/index.html"):
                self._send(200, DASHBOARD.read_bytes(), "text/html; charset=utf-8")
            elif self.path == "/api/state":
                self._send(200, json.dumps(state.snapshot()).encode())
            else:
                self._send(404, b'{"error":"not found"}')

        def do_POST(self):
            try:
                body = self._json_body()
            except (ValueError, json.JSONDecodeError):
                return self._send(400, b'{"error":"bad json"}')
            if self.path == "/api/report":
                n = state.report(body)
                self._send(200, json.dumps({"alerts": n}).encode())
            elif self.path == "/api/resolve":
                ok = state.resolve(int(body.get("id", 0)), str(body.get("note", ""))[:500])
                self._send(200 if ok else 404, json.dumps({"ok": ok}).encode())
            else:
                self._send(404, b'{"error":"not found"}')

    return Handler


def main(argv=None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Run the LANShield referee console.")
    ap.add_argument("-c", "--config", default="config.json")
    ap.add_argument("--log", action="append", default=[], help="router log to follow (repeatable)")
    ap.add_argument("--from-start", action="store_true", help="read logs from the beginning, not just new lines")
    ap.add_argument("--evidence", default="evidence.jsonl", help="file that keeps every alert for disputes")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args(argv)

    state = State(Rules.load(args.config), args.evidence)
    stop = threading.Event()
    for path in args.log:
        threading.Thread(target=follow, args=(path, state, args.from_start, stop), daemon=True).start()
    srv = ThreadingHTTPServer((args.host, args.port), make_handler(state))
    print(f"LANShield console for {state.rules.event}: http://localhost:{args.port}  (Ctrl+C to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        srv.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
