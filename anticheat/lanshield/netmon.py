"""Network monitor: reads DNS and connection logs from the event router and flags cheating signals.

Supported inputs (auto-detected per line):
  * dnsmasq / Pi-hole query log      "... dnsmasq[812]: query[A] api.nordvpn.com from 10.20.1.12"
                                     "... dnsmasq[812]: reply api.nordvpn.com is 185.12.3.4"
  * Linux conntrack events           "[NEW] udp 17 30 src=10.20.1.12 dst=185.12.3.4 sport=50211 dport=51820 ..."
  * CSV flow log                     "timestamp,src_ip,dst_ip,dst_port,proto"
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass

from .rules import BAD, WARN, Alert, Rules, is_private_ip

# category -> (one of them, several of them)
CATEGORY_TEXT = {
    "vpn": ("a VPN service", "VPN services"),
    "remote_access": ("a remote-access tool", "remote-access tools"),
    "cheat": ("a known cheat website", "cheat websites"),
    "account_sharing": ("an account boosting or sharing service", "account boosting services"),
    "dns_bypass": ("an encrypted DNS service, which can hide lookups from monitoring",
                   "encrypted DNS services (these can hide lookups from monitoring)"),
}


def one(cat: str) -> str:
    return CATEGORY_TEXT.get(cat, ("a " + cat, cat))[0]


def many(cat: str) -> str:
    return CATEGORY_TEXT.get(cat, ("a " + cat, cat))[1]

_DNS_QUERY = re.compile(r"query\[(?P<qtype>\w+)\]\s+(?P<domain>\S+)\s+from\s+(?P<src>[0-9a-fA-F:.]+)")
_DNS_REPLY = re.compile(r"(?:reply|cached|forwarded)\s+(?P<domain>\S+)\s+is\s+(?P<ip>[0-9a-fA-F:.]+)")
_CONNTRACK = re.compile(r"\b(?P<proto>tcp|udp)\b.*?\bsrc=(?P<src>\S+)\s+dst=(?P<dst>\S+)\s+sport=\d+\s+dport=(?P<dport>\d+)")
_SKIP_QTYPES = {"PTR", "SRV", "TXT", "SOA"}


@dataclass
class Flow:
    src: str
    dst: str
    dport: int
    proto: str


def parse_flow(line: str) -> Flow | None:
    m = _CONNTRACK.search(line)
    if m:
        return Flow(m["src"], m["dst"], int(m["dport"]), m["proto"])
    parts = [p.strip() for p in line.split(",")]
    if len(parts) >= 5 and parts[3].isdigit():
        _, src, dst, dport, proto = parts[:5]
        return Flow(src, dst, int(dport), proto.lower())
    return None


class NetworkDetector:
    def __init__(self, rules: Rules):
        self.rules = rules
        self.resolved: dict[str, str] = {}   # ip -> domain, learned from DNS replies
        # Connections with no DNS lookup yet. DNS and connection logs are written separately,
        # so the lookup can show up a moment after the connection: wait before flagging.
        self.grace_s = rules.cfg.get("direct_ip_grace_s", 5)
        self.pending: list[tuple[float, Flow, str]] = []

    def feed(self, line: str, now: float | None = None) -> list[Alert]:
        line = line.strip()
        out: list[Alert] = []
        if line and not line.startswith("#") and not line.lower().startswith("timestamp,"):
            m = _DNS_REPLY.search(line)
            q = None if m else _DNS_QUERY.search(line)
            if m:
                self.resolved[m["ip"]] = m["domain"].lower()
            elif q:
                out += self._on_dns(q["src"], q["domain"], q["qtype"].upper())
            else:
                flow = parse_flow(line)
                if flow:
                    out += self._on_flow(flow, now)
        return out + self.flush(now)

    def flush(self, now: float | None = None) -> list[Alert]:
        """Settle waiting connections: explained by a lookup since, or still unexplained after the grace time."""
        now = time.time() if now is None else now
        out, keep = [], []
        for deadline, f, station in self.pending:
            if f.dst in self.resolved:
                out += self._resolved_flow(f, station)
            elif deadline <= now:
                out.append(Alert(WARN, "direct_ip", station,
                                 f"{station} connected straight to {f.dst} on {f.proto.upper()} {f.dport} "
                                 f"without a DNS lookup. This can mean a hard-coded VPN or cheat server.",
                                 "flow", {"indicator": f"{f.dst}:{f.proto}/{f.dport}", "dst_ip": f.dst, "src_ip": f.src}))
            else:
                keep.append((deadline, f, station))
        self.pending = keep
        return out

    # ---- DNS -----------------------------------------------------------
    def _on_dns(self, src: str, domain: str, qtype: str) -> list[Alert]:
        station = self.rules.station_for_ip(src)
        if not station or qtype in _SKIP_QTYPES:
            return []
        domain = domain.lower().rstrip(".")
        cat = self.rules.blocked_category(domain)
        if cat:
            return [Alert(BAD, cat, station,
                          f"{station} looked up {domain}, {one(cat)}.",
                          "dns", {"indicator": domain, "src_ip": src})]
        if self.rules.flag_unknown_domains and not self.rules.is_allowed_domain(domain):
            return [Alert(WARN, "unknown_domain", station,
                          f"{station} looked up {domain}, which is not on the approved list.",
                          "dns", {"indicator": domain, "src_ip": src})]
        return []

    # ---- connections ---------------------------------------------------
    def _on_flow(self, f: Flow, now: float | None = None) -> list[Alert]:
        station = self.rules.station_for_ip(f.src)
        if not station or is_private_ip(f.dst):
            return []
        cat = self.rules.port_category(f.proto, f.dport)
        if cat:
            return [Alert(BAD, cat, station,
                          f"{station} connected to {f.dst} on {f.proto.upper()} port {f.dport}, "
                          f"a port used by {many(cat)}.",
                          "flow", {"indicator": f"{f.proto}/{f.dport}", "dst_ip": f.dst, "src_ip": f.src})]
        if f.dst in self.resolved:
            return self._resolved_flow(f, station)
        if self.rules.flag_direct_ip and (f.proto, f.dport) not in self.rules.direct_ip_ok:
            self.pending.append(((time.time() if now is None else now) + self.grace_s, f, station))
        return []

    def _resolved_flow(self, f: Flow, station: str) -> list[Alert]:
        domain = self.resolved[f.dst]
        cat = self.rules.blocked_category(domain)
        if cat:
            return [Alert(BAD, cat, station,
                          f"{station} connected to {domain} ({f.dst}), {one(cat)}.",
                          "flow", {"indicator": domain, "dst_ip": f.dst, "src_ip": f.src})]
        return []


def scan_lines(rules: Rules, lines) -> list[Alert]:
    """Run every line through one detector and return de-duplicated alerts in order.

    DNS replies are learned first, so connections can be matched to the names they were
    looked up by even when the DNS log and connection log are separate files."""
    lines = list(lines)
    det, seen, out = NetworkDetector(rules), set(), []
    for line in lines:
        m = _DNS_REPLY.search(line)
        if m:
            det.resolved[m["ip"]] = m["domain"].lower()
    found = [a for line in lines for a in det.feed(line, now=0)]
    found += det.flush(now=float("inf"))       # whole file is in hand: nothing more to wait for
    for a in found:
        if a.key() not in seen:
            seen.add(a.key())
            out.append(a)
    return out


def main(argv=None) -> int:
    import argparse
    import json
    import sys

    ap = argparse.ArgumentParser(description="Scan router DNS/connection logs for cheating signals.")
    ap.add_argument("logs", nargs="+", help="dnsmasq, conntrack or CSV flow log files ('-' for stdin)")
    ap.add_argument("-c", "--config", default="config.json")
    ap.add_argument("--json", action="store_true", help="print alerts as JSON lines")
    args = ap.parse_args(argv)

    rules = Rules.load(args.config)
    lines = []
    for p in args.logs:
        lines.extend(sys.stdin if p == "-" else open(p, encoding="utf-8", errors="replace"))
    alerts = scan_lines(rules, lines)
    for a in alerts:
        if args.json:
            print(json.dumps(a.to_dict()))
        else:
            print(f"[{a.severity.upper():4}] {a.station:7} {a.category:15} {a.message}")
    print(f"\n{len(alerts)} alert(s): "
          f"{sum(a.severity == BAD for a in alerts)} serious, {sum(a.severity == WARN for a in alerts)} to check.",
          file=sys.stderr)
    return 1 if any(a.severity == BAD for a in alerts) else 0


if __name__ == "__main__":
    raise SystemExit(main())
