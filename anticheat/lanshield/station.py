"""Station check: snapshot a player PC (programs, USB devices, network adapters) and judge it.

Run on each tournament PC before a match, or every minute with --watch:
    python -m lanshield.station --station P03 --account mgarcia --console http://10.20.0.2:8080
"""
from __future__ import annotations

import json
import platform
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

from .rules import BAD, WARN, Alert, Rules

VPN_ADAPTER_HINTS = ["tap-windows", "tap0901", "wintun", "wireguard", "nordlynx", "openvpn", "protonvpn",
                     "expressvpn", "surfshark", "windscribe", "mullvad", "zerotier", "tailscale",
                     "hamachi", "radmin vpn", "softether"]
VPN_ADAPTER_NAME = re.compile(r"^(tun|tap|wg|utun\d{2,}|ppp|zt|tailscale)", re.I)
ROOT_HUBS = {"1d6b:0001", "1d6b:0002", "1d6b:0003"}


def _run(cmd: list[str]) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=30).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


# ---- collection (one function per OS) ---------------------------------
def collect_processes() -> list[str]:
    if sys.platform == "win32":
        out = _run(["tasklist", "/fo", "csv", "/nh"])
        names = [line.split('","')[0].strip('"') for line in out.splitlines() if line.startswith('"')]
    elif sys.platform == "darwin":
        names = _run(["ps", "-axco", "comm="]).splitlines()
    else:
        names = _run(["ps", "-eo", "comm="]).splitlines()
    return sorted({n.strip() for n in names if n.strip()}, key=str.lower)


def collect_usb() -> list[dict]:
    devices = []
    if sys.platform == "win32":
        ps = ("Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -like 'USB\\VID_*' } | "
              "Select-Object InstanceId, FriendlyName | ConvertTo-Json -Compress")
        try:
            items = json.loads(_run(["powershell", "-NoProfile", "-Command", ps]) or "[]")
        except json.JSONDecodeError:
            items = []
        for it in items if isinstance(items, list) else [items]:
            m = re.search(r"VID_([0-9A-F]{4})&PID_([0-9A-F]{4})", it.get("InstanceId", ""), re.I)
            if m:
                devices.append({"id": f"{m[1]}:{m[2]}".lower(), "name": it.get("FriendlyName") or ""})
    elif sys.platform == "darwin":
        try:
            data = json.loads(_run(["system_profiler", "SPUSBDataType", "-json"]) or "{}")
        except json.JSONDecodeError:
            data = {}

        def walk(nodes):
            for n in nodes or []:
                v, p = n.get("vendor_id", ""), n.get("product_id", "")
                mv, mp = re.search(r"0x([0-9a-f]{4})", v, re.I), re.search(r"0x([0-9a-f]{4})", p, re.I)
                if mv and mp:
                    devices.append({"id": f"{mv[1]}:{mp[1]}".lower(), "name": n.get("_name", "")})
                walk(n.get("_items"))
        walk(data.get("SPUSBDataType"))
    else:
        for d in Path("/sys/bus/usb/devices").glob("*"):
            v, p = d / "idVendor", d / "idProduct"
            if v.exists() and p.exists():
                name = (d / "product").read_text(errors="replace").strip() if (d / "product").exists() else ""
                devices.append({"id": f"{v.read_text().strip()}:{p.read_text().strip()}".lower(), "name": name})
    return devices


def collect_adapters() -> list[str]:
    if sys.platform == "win32":
        ps = "Get-NetAdapter | ForEach-Object { $_.Name + ' | ' + $_.InterfaceDescription + ' | ' + $_.Status }"
        return [l.strip() for l in _run(["powershell", "-NoProfile", "-Command", ps]).splitlines() if l.strip()]
    if sys.platform == "darwin":
        return [l.split(":")[0] for l in _run(["ifconfig"]).splitlines() if l and not l[0].isspace()]
    return sorted(p.name for p in Path("/sys/class/net").glob("*"))


def snapshot(station: str, account: str = "") -> dict:
    return {
        "station": station,
        "account": account,
        "hostname": socket.gethostname(),
        "os": f"{platform.system()} {platform.release()}",
        "ts": time.time(),
        "processes": collect_processes(),
        "usb": collect_usb(),
        "adapters": collect_adapters(),
    }


# ---- evaluation --------------------------------------------------------
def evaluate(report: dict, rules: Rules) -> list[Alert]:
    st = report.get("station", "unknown")
    alerts: list[Alert] = []

    def add(sev, cat, msg, indicator, **ev):
        alerts.append(Alert(sev, cat, st, msg, "station", dict(indicator=indicator, **ev)))

    # Programs
    for proc in report.get("processes", []):
        low = proc.lower()
        if low in rules.approved_processes:
            continue
        for cat, needles in rules.suspicious_processes.items():
            hit = next((n for n in needles if re.search(r"(?<![a-z0-9])" + re.escape(n), low)), None)
            if hit:
                label = cat.replace("_", " ")
                add(BAD, cat, f"{st} is running {proc}, a {label}.", low, process=proc)
                break

    # USB devices
    for dev in report.get("usb", []):
        did, name = dev.get("id", "").lower(), dev.get("name", "")
        if did in rules.approved_usb or did in ROOT_HUBS or "hub" in name.lower():
            continue
        if did in rules.suspicious_usb:
            add(BAD, "usb", f"{st} has a {rules.suspicious_usb[did]} plugged in ({did}).", did, device=name)
        else:
            add(WARN, "usb", f"{st} has an unapproved USB device: {name or 'unnamed device'} ({did}). "
                             f"Check it by hand.", did, device=name)

    # Network adapters (VPN / virtual LAN tunnels)
    for ad in report.get("adapters", []):
        low = ad.lower()
        first = ad.split(" | ")[0]
        if any(h in low for h in VPN_ADAPTER_HINTS) or VPN_ADAPTER_NAME.match(first):
            if " | disconnected" in low or " | disabled" in low:
                add(WARN, "vpn", f"{st} has a VPN adapter installed but switched off: {first}.", low)
            else:
                add(BAD, "vpn", f"{st} has an active VPN or tunnel adapter: {ad}.", low)

    # Who is playing
    expected = rules.station_by_id.get(st, {}).get("player")
    account = (report.get("account") or "").strip()
    if expected and account and account.lower() != expected.lower():
        add(BAD, "account_mismatch",
            f"{st} is signed in as '{account}' but the registered player is '{expected}'.",
            f"account:{account.lower()}", account=account, expected=expected)
    return alerts


def main(argv=None) -> int:
    import argparse
    import urllib.request

    ap = argparse.ArgumentParser(description="Check a player PC for unapproved software and devices.")
    ap.add_argument("--station", required=True, help="station ID, e.g. P03")
    ap.add_argument("--account", default="", help="in-game account the player signed in with")
    ap.add_argument("--console", help="console URL to send the report to, e.g. http://10.20.0.2:8080")
    ap.add_argument("-c", "--config", help="judge the report locally with this config")
    ap.add_argument("--out", help="also save the raw report to this JSON file")
    ap.add_argument("--from-file", help="judge a saved report instead of this PC")
    ap.add_argument("--watch", type=int, metavar="SECONDS", help="repeat every N seconds")
    args = ap.parse_args(argv)

    while True:
        report = json.load(open(args.from_file)) if args.from_file else snapshot(args.station, args.account)
        if args.out:
            Path(args.out).write_text(json.dumps(report, indent=2))
        if args.console:
            req = urllib.request.Request(args.console.rstrip("/") + "/api/report", data=json.dumps(report).encode(),
                                         headers={"Content-Type": "application/json"}, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=10) as r:
                    print(f"Sent report for {args.station}: {r.status}")
            except OSError as e:
                print(f"Could not reach console: {e}", file=sys.stderr)
        worst = 0
        if args.config:
            alerts = evaluate(report, Rules.load(args.config))
            for a in alerts:
                print(f"[{a.severity.upper():4}] {a.category:16} {a.message}")
            print(f"{len(report['processes'])} programs, {len(report['usb'])} USB devices, "
                  f"{len(report['adapters'])} adapters checked. {len(alerts)} alert(s).")
            worst = 1 if any(a.severity == BAD for a in alerts) else 0
        if not args.watch or args.from_file:
            return worst
        time.sleep(args.watch)


if __name__ == "__main__":
    raise SystemExit(main())
