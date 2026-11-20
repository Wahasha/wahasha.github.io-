"""Simulated tournament for testing: normal game traffic plus planted cheating attempts.

    python -m lanshield.simulate --samples samples          # write static sample logs and reports
    python -m lanshield.simulate --live run --console http://localhost:8080 --speed 2
        (then point the console at run/dnsmasq.log and run/flows.csv)
"""
from __future__ import annotations

import json
import random
import time
from datetime import datetime
from pathlib import Path

# Public-looking addresses for game, CDN and service endpoints.
GAME_SERVERS = ["104.160.141.3", "104.160.131.3", "35.172.44.10", "3.120.77.41"]
RESOLVE = {
    "auth.riotgames.com": "104.160.156.15", "valorant-content.riotcdn.net": "151.101.2.133",
    "account-public-service-prod.ol.epicgames.com": "54.172.18.9", "rocketleague.com": "23.45.12.80",
    "settings-win.data.microsoft.com": "20.42.65.85", "cdn.discordapp.com": "162.159.130.233",
    "playvs.com": "76.76.21.21", "api.nordvpn.com": "104.17.49.74", "www.unknowncheats.me": "172.67.69.10",
    "anydesk.com": "75.2.47.111", "boot.net.anydesk.com": "195.181.174.176", "cloudflare-dns.com": "104.16.248.249",
    "www.tiktok.com": "23.53.40.45", "router15.teamviewer.com": "37.252.231.66", "www.legionfarm.com": "104.21.8.77",
}
NORMAL_DOMAINS = list(RESOLVE)[:7]

IP = {f"P{i:02d}": ip for i, ip in enumerate(
    ["10.20.1.11", "10.20.1.12", "10.20.1.13", "10.20.1.14", "10.20.1.15",
     "10.20.1.21", "10.20.1.22", "10.20.1.23", "10.20.1.24", "10.20.1.25"], start=1)}

# (seconds into match, what, details). "dns" = lookup + reply, "flow" = connection, "report" = station check.
PLANTED = [
    (8,  "dns",  ("P02", "api.nordvpn.com")),
    (9,  "flow", ("P02", "104.17.49.74", 51820, "udp")),
    (14, "report", "P03"),                                  # Cheat Engine + Cronus Zen
    (20, "dns",  ("P04", "boot.net.anydesk.com")),
    (21, "flow", ("P04", "195.181.174.176", 7070, "tcp")),
    (26, "dns",  ("P06", "www.unknowncheats.me")),
    (30, "flow", ("P07", "185.199.110.42", 9443, "tcp")),   # straight to an IP, no DNS
    (34, "dns",  ("P08", "cloudflare-dns.com")),
    (35, "flow", ("P08", "104.16.248.249", 853, "tcp")),
    (38, "report", "P08"),                                  # wrong account signed in
    (42, "dns",  ("P09", "www.tiktok.com")),
    (46, "report", "P05"),                                  # AutoHotkey macro
    (48, "dns",  ("P05", "router15.teamviewer.com")),
    (49, "flow", ("P05", "37.252.231.66", 443, "tcp")),
    (52, "report", "P10"),                                  # unknown USB + VPN adapter switched off
    (55, "dns",  ("guest", "api.nordvpn.com")),             # spectator Wi-Fi: must be ignored
    (58, "report", "P06"),                                  # NordLynx adapter up
]

CLEAN_WINDOWS = ["System", "smss.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe", "svchost.exe",
                 "explorer.exe", "dwm.exe", "RuntimeBroker.exe", "SearchHost.exe", "MsMpEng.exe",
                 "RiotClientServices.exe", "VALORANT-Win64-Shipping.exe", "vgtray.exe", "Discord.exe",
                 "EpicGamesLauncher.exe", "RocketLeague.exe", "chakra_helper.exe", "Shakti.exe"]
CLEAN_USB = [{"id": "046d:c08b", "name": "G502 HERO Gaming Mouse"}, {"id": "1532:0241", "name": "Razer BlackWidow"},
             {"id": "0951:16a4", "name": "HyperX Cloud"}, {"id": "05e3:0610", "name": "Generic USB Hub"}]
CLEAN_ADAPTERS = ["Ethernet | Intel(R) Ethernet Connection I219-V | Up",
                  "Bluetooth Network Connection | Bluetooth Device (PAN) | Disconnected"]


def station_report(sid: str) -> dict:
    players = {"P01": "jsmith", "P02": "alee", "P03": "mgarcia", "P04": "tnguyen", "P05": "kpatel",
               "P06": "rbrown", "P07": "cwilson", "P08": "dkim", "P09": "elopez", "P10": "fdavis"}
    rep = {"station": sid, "account": players[sid], "hostname": f"ESPORTS-{sid}", "os": "Windows 11",
           "ts": time.time(), "processes": list(CLEAN_WINDOWS), "usb": list(CLEAN_USB),
           "adapters": list(CLEAN_ADAPTERS)}
    if sid == "P03":
        rep["processes"] += ["cheatengine-x86_64-SSE4-AVX2.exe"]
        rep["usb"] += [{"id": "2508:0032", "name": "Cronus Zen"}]
    elif sid == "P05":
        rep["processes"] += ["AutoHotkey64.exe"]
    elif sid == "P06":
        rep["adapters"] += ["NordLynx | NordLynx Tunnel | Up"]
    elif sid == "P08":
        rep["account"] = "proplayer99"
    elif sid == "P10":
        rep["usb"] += [{"id": "1a2c:2124", "name": "USB Keyboard"}]
        rep["adapters"] += ["WireGuard Tunnel | WireGuard Tunnel | Disconnected"]
    return rep


def _stamp(t: float) -> str:
    return datetime.fromtimestamp(t).strftime("%b %d %H:%M:%S")


def dns_lines(t: float, src: str, domain: str) -> list[str]:
    ip = RESOLVE.get(domain, "93.184.216.34")
    return [f"{_stamp(t)} dnsmasq[812]: query[A] {domain} from {src}",
            f"{_stamp(t)} dnsmasq[812]: forwarded {domain} to 1.1.1.1",
            f"{_stamp(t)} dnsmasq[812]: reply {domain} is {ip}"]


def flow_line(t: float, src: str, dst: str, port: int, proto: str) -> str:
    return f"{int(t)},{src},{dst},{port},{proto}"


def background(t: float, rng: random.Random) -> tuple[list[str], list[str]]:
    """One second of normal traffic from a random station."""
    sid = rng.choice(list(IP))
    src = IP[sid]
    if rng.random() < 0.5:
        d = rng.choice(NORMAL_DOMAINS)
        return dns_lines(t, src, d), [flow_line(t, src, RESOLVE[d], 443, "tcp")]
    return [], [flow_line(t, src, rng.choice(GAME_SERVERS), rng.choice([7000, 7500, 8180, 5100]), "udp")]


def build(start: float, seconds: int = 60, seed: int = 7):
    """Return (timeline of (t, kind, payload)) for a whole simulated match."""
    rng = random.Random(seed)
    out = []
    for s in range(seconds):
        dns, flows = background(start + s, rng)
        out += [(s, "dns_line", l) for l in dns] + [(s, "flow_line", l) for l in flows]
    for s, kind, what in PLANTED:
        t = start + s
        if kind == "dns":
            sid, domain = what
            src = IP.get(sid, "10.30.0.57")
            out += [(s + 0.5, "dns_line", l) for l in dns_lines(t, src, domain)]
        elif kind == "flow":
            sid, dst, port, proto = what
            out.append((s + 0.5, "flow_line", flow_line(t, IP[sid], dst, port, proto)))
        else:
            out.append((s + 0.5, "report", what))
    # P01, P02, P04, P07, P09: clean station checks at the start
    out += [(1 + i * 0.3, "report", sid) for i, sid in enumerate(["P01", "P02", "P04", "P07", "P09"])]
    return sorted(out, key=lambda x: x[0])


def write_samples(folder: str) -> None:
    root = Path(folder)
    (root / "stations").mkdir(parents=True, exist_ok=True)
    start = datetime(2026, 11, 21, 10, 0, 0).timestamp()
    dns, flows = [], ["timestamp,src_ip,dst_ip,dst_port,proto"]
    for _, kind, payload in build(start):
        if kind == "dns_line":
            dns.append(payload)
        elif kind == "flow_line":
            flows.append(payload)
    (root / "dnsmasq.log").write_text("\n".join(dns) + "\n")
    (root / "flows.csv").write_text("\n".join(flows) + "\n")
    for sid in IP:
        (root / "stations" / f"{sid}.json").write_text(json.dumps(station_report(sid), indent=2) + "\n")
    print(f"Wrote {len(dns)} DNS lines, {len(flows) - 1} flows and {len(IP)} station reports to {root}/")


def run_live(folder: str, console: str, speed: float, loop: bool) -> None:
    import urllib.request

    root = Path(folder)
    root.mkdir(parents=True, exist_ok=True)
    dns_f = open(root / "dnsmasq.log", "a", buffering=1)
    flow_f = open(root / "flows.csv", "a", buffering=1)
    while True:
        t0 = time.time()
        for s, kind, payload in build(t0, seed=int(t0)):
            delay = t0 + s / speed - time.time()
            if delay > 0:
                time.sleep(delay)
            if kind == "dns_line":
                dns_f.write(payload + "\n")
            elif kind == "flow_line":
                flow_f.write(payload + "\n")
            else:
                req = urllib.request.Request(console.rstrip("/") + "/api/report",
                                             data=json.dumps(station_report(payload)).encode(),
                                             headers={"Content-Type": "application/json"}, method="POST")
                try:
                    urllib.request.urlopen(req, timeout=5).close()
                except OSError as e:
                    print("console not reachable:", e)
        if not loop:
            break


def main(argv=None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Generate a simulated match with planted cheating attempts.")
    ap.add_argument("--samples", help="write static sample files to this folder")
    ap.add_argument("--live", help="write log lines into this folder in real time")
    ap.add_argument("--console", default="http://localhost:8080", help="console to send station reports to")
    ap.add_argument("--speed", type=float, default=1.0, help="2 = twice as fast as real time")
    ap.add_argument("--loop", action="store_true", help="keep replaying the match")
    args = ap.parse_args(argv)
    if args.samples:
        write_samples(args.samples)
    if args.live:
        run_live(args.live, args.console, args.speed, args.loop)
    if not (args.samples or args.live):
        ap.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
