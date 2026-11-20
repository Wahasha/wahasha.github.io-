"""Tests for the LANShield anti-cheat prototype. Run from the anticheat folder:

    python -m unittest -v
"""
import json
import os
import tempfile
import threading
import time
import unittest
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from lanshield import simulate
from lanshield.console import State, follow, make_handler
from lanshield.netmon import NetworkDetector, scan_lines
from lanshield.rules import BAD, WARN, Rules
from lanshield.station import evaluate

ROOT = Path(__file__).resolve().parents[1]
RULES = Rules.load(ROOT / "config.example.json")


def found(alerts):
    """{(station, category, severity)} for easy comparison."""
    return {(a.station, a.category, a.severity) for a in alerts}


class SimulatedMatch(unittest.TestCase):
    """The full simulated match: every planted attempt caught, nothing else flagged."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        simulate.write_samples(cls.tmp.name)
        d = Path(cls.tmp.name)
        lines = (d / "dnsmasq.log").read_text().splitlines() + (d / "flows.csv").read_text().splitlines()
        cls.net = scan_lines(RULES, lines)
        cls.reports = {p.stem: json.loads(p.read_text()) for p in (d / "stations").glob("*.json")}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_network_catches_every_planted_attempt_and_nothing_else(self):
        self.assertEqual(found(self.net), {
            ("P02", "vpn", BAD),              # NordVPN lookup + WireGuard port
            ("P04", "remote_access", BAD),    # AnyDesk lookup + port 7070
            ("P05", "remote_access", BAD),    # TeamViewer
            ("P06", "cheat", BAD),            # cheat forum
            ("P07", "direct_ip", WARN),       # connection with no DNS lookup
            ("P08", "dns_bypass", BAD),       # DNS-over-TLS to Cloudflare
            ("P09", "unknown_domain", WARN),  # TikTok: not on the approved list
        })

    def test_clean_background_traffic_raises_nothing(self):
        flagged = {a.station for a in self.net}
        for clean in ["P01", "P03", "P10"]:
            self.assertNotIn(clean, flagged)

    def test_spectator_wifi_is_ignored(self):
        self.assertNotIn("unknown", {a.station for a in self.net})
        self.assertFalse(any(a.evidence.get("src_ip", "").startswith("10.30.") for a in self.net))

    def test_station_checks(self):
        expected = {
            "P01": set(), "P02": set(), "P04": set(), "P07": set(), "P09": set(),
            "P03": {("P03", "cheat_tool", BAD), ("P03", "usb", BAD)},
            "P05": {("P05", "macro_tool", BAD)},
            "P06": {("P06", "vpn", BAD)},
            "P08": {("P08", "account_mismatch", BAD)},
            "P10": {("P10", "usb", WARN), ("P10", "vpn", WARN)},
        }
        for sid, want in expected.items():
            with self.subTest(station=sid):
                self.assertEqual(found(evaluate(self.reports[sid], RULES)), want)


class NetworkRules(unittest.TestCase):
    def feed(self, *lines):
        det = NetworkDetector(RULES)
        out = []
        for l in lines:
            out += det.feed(l, now=0)
        return out + det.flush(now=float("inf"))

    def test_subdomains_match_but_lookalikes_do_not(self):
        self.assertEqual(found(self.feed("dnsmasq[1]: query[A] eu-12.api.nordvpn.com from 10.20.1.11")),
                         {("P01", "vpn", BAD)})
        self.assertEqual(found(self.feed("dnsmasq[1]: query[A] notnordvpn.com from 10.20.1.11")),
                         {("P01", "unknown_domain", WARN)})

    def test_allowed_domains_and_reverse_lookups_are_quiet(self):
        self.assertEqual(self.feed("dnsmasq[1]: query[AAAA] eu.edge.riotgames.com from 10.20.1.11",
                                   "dnsmasq[1]: query[PTR] 4.3.2.1.in-addr.arpa from 10.20.1.11"), [])

    def test_conntrack_format(self):
        line = ("[NEW] udp      17 30 src=10.20.1.13 dst=89.40.12.7 sport=50211 dport=51820 [UNREPLIED] "
                "src=89.40.12.7 dst=192.168.0.2 sport=51820 dport=50211")
        self.assertEqual(found(self.feed(line)), {("P03", "vpn", BAD)})

    def test_connection_to_ip_learned_from_dns(self):
        alerts = self.feed("dnsmasq[1]: reply router7.teamviewer.com is 37.252.230.1",
                           "1700000000,10.20.1.14,37.252.230.1,443,tcp")
        self.assertEqual(found(alerts), {("P04", "remote_access", BAD)})

    def test_connection_logged_before_its_dns_answer_is_not_flagged(self):
        det = NetworkDetector(RULES)
        self.assertEqual(det.feed("1700000000,10.20.1.14,20.42.65.85,443,tcp", now=100), [])
        self.assertEqual(det.feed("dnsmasq[1]: reply settings-win.data.microsoft.com is 20.42.65.85", now=101), [])
        self.assertEqual(det.flush(now=200), [])
        # ...but one that is never explained is flagged once the grace time has passed
        det.feed("1700000000,10.20.1.14,185.199.110.42,9443,tcp", now=300)
        self.assertEqual(det.flush(now=302), [])
        self.assertEqual(found(det.flush(now=306)), {("P04", "direct_ip", WARN)})
        # and a late answer that names a blocked service upgrades it to serious
        det.feed("1700000000,10.20.1.15,89.40.1.1,443,tcp", now=400)
        self.assertEqual(found(det.feed("dnsmasq[1]: reply x.protonvpn.com is 89.40.1.1", now=401)),
                         {("P05", "vpn", BAD)})

    def test_direct_ip_on_game_port_is_fine_but_odd_port_is_flagged(self):
        self.assertEqual(self.feed("1700000000,10.20.1.14,104.160.141.3,7000,udp"), [])
        self.assertEqual(found(self.feed("1700000000,10.20.1.14,104.160.141.3,6667,tcp")),
                         {("P04", "direct_ip", WARN)})

    def test_local_traffic_and_unknown_sources_ignored(self):
        self.assertEqual(self.feed("1700000000,10.20.1.14,10.20.0.2,3389,tcp",       # RDP inside the LAN
                                   "1700000000,10.99.0.5,89.40.12.7,51820,udp"), [])  # not a station

    def test_garbage_lines_do_not_crash(self):
        self.assertEqual(self.feed("", "# comment", "timestamp,src_ip,dst_ip,dst_port,proto",
                                   "complete nonsense ,,,", "dnsmasq[1]: query[A]"), [])


class StationRules(unittest.TestCase):
    def rep(self, **kw):
        base = {"station": "P01", "account": "jsmith", "processes": [], "usb": [], "adapters": []}
        base.update(kw)
        return found(evaluate(base, RULES))

    def test_short_names_need_a_word_start(self):
        # "ahk" must not match inside other names
        self.assertEqual(self.rep(processes=["Shakti.exe", "chakra_helper.exe", "Bahkup.exe"]), set())
        self.assertEqual(self.rep(processes=["ahk_helper.exe"]), {("P01", "macro_tool", BAD)})

    def test_approved_and_hub_devices_are_quiet(self):
        self.assertEqual(self.rep(usb=[{"id": "045e:0b12", "name": "Xbox controller"},
                                       {"id": "1d6b:0002", "name": "root hub"},
                                       {"id": "abcd:1234", "name": "USB2.0 Hub"}]), set())

    def test_linux_and_mac_tunnel_names(self):
        self.assertEqual(self.rep(adapters=["eth0", "lo", "wg0"]), {("P01", "vpn", BAD)})
        self.assertEqual(self.rep(adapters=["en0", "utun3"]), set())   # macOS system tunnels
        self.assertEqual(self.rep(adapters=["en0", "tailscale0"]), {("P01", "vpn", BAD)})

    def test_account_check_is_case_insensitive_and_optional(self):
        self.assertEqual(self.rep(account="JSmith"), set())
        self.assertEqual(self.rep(account=""), set())


class Console(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = State(RULES, os.path.join(self.tmp.name, "evidence.jsonl"))

    def tearDown(self):
        self.state.log_file.close()
        self.tmp.cleanup()

    def test_repeats_are_counted_not_duplicated_and_reopen_after_resolve(self):
        rep = simulate.station_report("P05")
        self.state.report(rep)
        self.state.report(rep)
        macro = [a for a in self.state.alerts if a["category"] == "macro_tool"]
        self.assertEqual(len(macro), 1)
        self.assertEqual(macro[0]["count"], 2)
        self.assertTrue(self.state.resolve(macro[0]["id"], "AHK used by teacher, removed"))
        snap = self.state.snapshot()
        self.assertEqual(next(s for s in snap["stations"] if s["id"] == "P05")["state"], "ok")
        self.state.report(rep)                       # it is back: must reopen
        self.assertEqual(macro[0]["status"], "open")

    def test_evidence_file_keeps_alerts_and_rulings(self):
        self.state.report(simulate.station_report("P03"))
        first = next(a for a in self.state.alerts if a["station"] == "P03")
        self.state.resolve(first["id"], "Cronus confiscated")
        lines = [json.loads(l) for l in Path(self.tmp.name, "evidence.jsonl").read_text().splitlines()]
        self.assertTrue(any(l.get("category") == "usb" for l in lines))
        self.assertTrue(any(l.get("note") == "Cronus confiscated" for l in lines))

    def test_follow_picks_up_new_lines_and_rotated_files(self):
        log = Path(self.tmp.name, "dnsmasq.log")
        log.write_text("old line before monitoring\n")
        stop = threading.Event()
        t = threading.Thread(target=follow, args=(str(log), self.state, False, stop), daemon=True)
        t.start()
        time.sleep(0.7)
        with log.open("a") as f:
            f.write("dnsmasq[1]: query[A] anydesk.com from 10.20.1.22\n")
        time.sleep(1.2)
        log.unlink()                                  # log rotation: file replaced
        log.write_text("dnsmasq[1]: query[A] mpgh.net from 10.20.1.23\n")
        time.sleep(1.5)
        stop.set()
        got = {(a["station"], a["category"]) for a in self.state.alerts}
        self.assertIn(("P07", "remote_access"), got)
        self.assertIn(("P08", "cheat"), got)

    def test_http_api_end_to_end(self):
        srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.state))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{srv.server_address[1]}"
        try:
            def post(path, body):
                req = urllib.request.Request(base + path, data=json.dumps(body).encode(),
                                             headers={"Content-Type": "application/json"}, method="POST")
                with urllib.request.urlopen(req) as r:
                    return json.loads(r.read())

            self.assertEqual(post("/api/report", simulate.station_report("P08"))["alerts"], 1)
            with urllib.request.urlopen(base + "/api/state") as r:
                snap = json.loads(r.read())
            p08 = next(s for s in snap["stations"] if s["id"] == "P08")
            self.assertEqual((p08["state"], p08["account"], p08["stale"]), ("bad", "proplayer99", False))
            aid = next(a["id"] for a in snap["alerts"] if a["category"] == "account_mismatch")
            self.assertTrue(post("/api/resolve", {"id": aid, "note": "Sub approved by TO"})["ok"])
            with urllib.request.urlopen(base + "/") as r:
                self.assertIn(b"LANShield Console", r.read())
        finally:
            srv.shutdown()
            srv.server_close()


if __name__ == "__main__":
    unittest.main()
