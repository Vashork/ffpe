"""
DNS/IP resolver with optional fallback via fw_objects.csv.

- Pass 1: DNS
- Pass 2: fw_objects.csv (optional)

Produces display format: name[ip] (or name[ref]).
"""

from __future__ import annotations

import csv
import ipaddress
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple


@dataclass(frozen=True)
class ResolveResult:
    """Resolved token representation."""
    display: str


class FwObjectsLookup:
    """
    Loads fw_objects.csv/tsv with columns:
        "Имя объекта", "ip", "mask"

    Supports:
    - find_name_for_ip(ip) -> object name by IP-in-network (most specific wins)
    - find_ref_for_name(name) -> reference string by exact object name (case-insensitive)
      host -> "10.1.1.4"
      net  -> "10.20.99.0/24"
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._networks: List[Tuple[ipaddress._BaseNetwork, str]] = []
        self._name_to_ref: Dict[str, str] = {}

    @staticmethod
    def _mask_to_prefix(mask_str: str) -> int:
        return ipaddress.IPv4Network(f"0.0.0.0/{mask_str}").prefixlen

    @staticmethod
    def _normalize_name(name: str) -> str:
        return name.strip().lower()

    def load(self) -> None:
        """Load CSV/TSV and build networks list and name->ref map."""
        if not self.path.exists():
            raise FileNotFoundError(f"fw_objects file not found: {self.path}")

        with self.path.open("r", encoding="utf-8-sig", newline="") as f:
            sample = f.read(4096)
            f.seek(0)

            try:
                dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
            except csv.Error:
                dialect = csv.excel
                dialect.delimiter = "\t"

            reader = csv.DictReader(f, dialect=dialect)
            required = {"Имя объекта", "ip", "mask"}
            if not reader.fieldnames or not required.issubset(set(reader.fieldnames)):
                raise ValueError(
                    "fw_objects must contain columns: "
                    + ", ".join(sorted(required))
                    + f". Found: {reader.fieldnames}"
                )

            networks: List[Tuple[ipaddress._BaseNetwork, str]] = []
            name_to_ref: Dict[str, str] = {}

            for row in reader:
                name_raw = (row.get("Имя объекта") or "").strip()
                ip_str = (row.get("ip") or "").strip()
                mask_str = (row.get("mask") or "").strip()

                if not name_raw or not ip_str:
                    continue

                try:
                    ip_obj = ipaddress.ip_address(ip_str)
                except ValueError:
                    continue

                if not mask_str:
                    prefix = 32 if isinstance(ip_obj, ipaddress.IPv4Address) else 128
                else:
                    try:
                        prefix = self._mask_to_prefix(mask_str)
                    except Exception:
                        continue

                try:
                    network = ipaddress.ip_network(f"{ip_str}/{prefix}", strict=False)
                except ValueError:
                    continue

                name_norm = self._normalize_name(name_raw)

                if (network.version == 4 and network.prefixlen == 32) or (
                        network.version == 6 and network.prefixlen == 128
                ):
                    name_to_ref[name_norm] = ip_str
                else:
                    name_to_ref.setdefault(
                        name_norm,
                        f"{network.network_address}/{network.prefixlen}",
                    )

                networks.append((network, name_raw))

            networks.sort(key=lambda x: x[0].prefixlen, reverse=True)
            self._networks = networks
            self._name_to_ref = name_to_ref

    def find_name_for_ip(self, ip_str: str) -> Optional[str]:
        """IP -> object name by IP-in-network."""
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return None

        for network, name in self._networks:
            if network.version != ip_obj.version:
                continue
            if ip_obj in network:
                return name
        return None

    def find_ref_for_name(self, name: str) -> Optional[str]:
        """Exact name (case-insensitive) -> ref (ip or cidr)."""
        return self._name_to_ref.get(self._normalize_name(name))


class DnsResolver:
    """DNS resolver with caching and optional fw_objects fallback."""

    def __init__(self, timeout: float = 3.0, fw_objects: Optional[FwObjectsLookup] = None) -> None:
        self.timeout = timeout
        socket.setdefaulttimeout(self.timeout)
        self.fw_objects = fw_objects
        self._ip_to_name: Dict[str, Optional[str]] = {}
        self._name_to_ip: Dict[str, Optional[str]] = {}

    @staticmethod
    def is_ip(value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def _dns_ptr(self, ip_str: str) -> Optional[str]:
        if ip_str in self._ip_to_name:
            return self._ip_to_name[ip_str]
        try:
            hostname, _, _ = socket.gethostbyaddr(ip_str)
            self._ip_to_name[ip_str] = hostname
            return hostname
        except (socket.herror, socket.gaierror, TimeoutError, OSError):
            self._ip_to_name[ip_str] = None
            return None

    def _dns_a(self, name: str) -> Optional[str]:
        if name in self._name_to_ip:
            return self._name_to_ip[name]
        try:
            _, _, ips = socket.gethostbyname_ex(name)
            ip_value = ips[0] if ips else None
            self._name_to_ip[name] = ip_value
            return ip_value
        except (socket.gaierror, TimeoutError, OSError):
            self._name_to_ip[name] = None
            return None

    def resolve_token(self, token: str) -> ResolveResult:
        """
        Resolve token to name[ip] (or name[ref]) with 2-pass logic.

        Args:
            token (str): IP or hostname string.

        Returns:
            ResolveResult: display-ready representation.
        """
        cleaned = token.strip()
        if not cleaned:
            return ResolveResult(display="")

        if self.is_ip(cleaned):
            hostname = self._dns_ptr(cleaned)
            if hostname:
                return ResolveResult(display=f"{hostname}[{cleaned}]")

            if self.fw_objects:
                obj_name = self.fw_objects.find_name_for_ip(cleaned)
                if obj_name:
                    return ResolveResult(display=f"{obj_name}[{cleaned}]")

            return ResolveResult(display=f"?[{cleaned}]")

        ip_value = self._dns_a(cleaned)
        if ip_value:
            return ResolveResult(display=f"{cleaned}[{ip_value}]")

        if self.fw_objects:
            fw_ref = self.fw_objects.find_ref_for_name(cleaned)
            if fw_ref:
                return ResolveResult(display=f"{cleaned}[{fw_ref}]")

        return ResolveResult(display=f"{cleaned}[?]")


def split_tokens(value: str) -> List[str]:
    """Split comma-separated cell string into tokens."""
    return [t.strip() for t in value.split(",") if t.strip()]


def resolve_cell(value: str, resolver: DnsResolver) -> str:
    """Resolve a comma-separated cell string and return resolved string."""
    tokens = split_tokens(value)
    resolved = [resolver.resolve_token(t).display for t in tokens]
    return ", ".join(resolved)
