"""Event rules: stations, allow and block lists, and the alert type everything returns."""
from __future__ import annotations

import ipaddress
import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

# Severity levels, lowest to highest.
INFO, WARN, BAD = "info", "warn", "bad"
SEVERITY_RANK = {INFO: 0, WARN: 1, BAD: 2}


@dataclass
class Alert:
    severity: str            # info | warn | bad
    category: str            # vpn, remote_access, cheat, unknown_domain, usb, ...
    station: str             # station ID such as "P03", or "unknown"
    message: str             # plain-language text for the referee
    source: str              # dns | flow | station | system
    evidence: dict = field(default_factory=dict)
    ts: float = field(default_factory=time.time)

    def key(self) -> tuple:
        """Identity used to avoid repeating the same alert over and over."""
        return (self.station, self.category, self.evidence.get("indicator", self.message))

    def to_dict(self) -> dict:
        return asdict(self)


def _norm_domain(d: str) -> str:
    return d.strip().lower().rstrip(".")


class Rules:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.event = cfg.get("event", "Esports event")
        self.stations = {ip: dict(info) for ip, info in cfg.get("stations", {}).items()}
        self.station_by_id = {info["id"]: dict(info, ip=ip) for ip, info in self.stations.items()}
        self.allowed = {_norm_domain(d) for d in cfg.get("allowed_domains", [])}
        self.blocked = {
            _norm_domain(d): cat
            for cat, domains in cfg.get("blocked_domains", {}).items()
            for d in domains
        }
        self.blocked_ports = {
            (proto.lower(), int(port)): cat
            for cat, protos in cfg.get("blocked_ports", {}).items()
            for proto, ports in protos.items()
            for port in ports
        }
        self.flag_unknown_domains = cfg.get("flag_unknown_domains", True)
        self.flag_direct_ip = cfg.get("flag_direct_ip", True)
        self.direct_ip_ok = {
            (proto.lower(), int(port))
            for proto, ports in cfg.get("direct_ip_ok_ports", {}).items()
            for port in ports
        }
        self.approved_processes = {p.lower() for p in cfg.get("approved_processes", [])}
        self.suspicious_processes = {
            cat: [s.lower() for s in names]
            for cat, names in cfg.get("suspicious_processes", {}).items()
        }
        self.approved_usb = {k.lower(): v for k, v in cfg.get("approved_usb", {}).items()}
        self.suspicious_usb = {k.lower(): v for k, v in cfg.get("suspicious_usb", {}).items()}
        self.ping_warn_ms = cfg.get("ping_warn_ms", 60)

    @classmethod
    def load(cls, path: str | Path) -> "Rules":
        with open(path, encoding="utf-8") as f:
            return cls(json.load(f))

    # ---- lookups -------------------------------------------------------
    def station_for_ip(self, ip: str) -> str | None:
        info = self.stations.get(ip)
        return info["id"] if info else None

    @staticmethod
    def _suffixes(domain: str):
        """sub.cdn.example.com -> sub.cdn.example.com, cdn.example.com, example.com"""
        parts = _norm_domain(domain).split(".")
        for i in range(len(parts) - 1):
            yield ".".join(parts[i:])

    def blocked_category(self, domain: str) -> str | None:
        for s in self._suffixes(domain):
            if s in self.blocked:
                return self.blocked[s]
        return None

    def is_allowed_domain(self, domain: str) -> bool:
        return any(s in self.allowed for s in self._suffixes(domain))

    def port_category(self, proto: str, port: int) -> str | None:
        return self.blocked_ports.get((proto.lower(), int(port)))


def is_private_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_private or a.is_loopback or a.is_link_local or a.is_multicast
