#!/usr/bin/env python3
"""
Export FortiGate services and service-groups with ports to CSV.

- Fetch custom services: /cmdb/firewall.service/custom
- Fetch service groups: /cmdb/firewall.service/group
- Normalize ports:
  "88 464" -> "88/tcp 464/tcp" (and similarly for udp/udplite/sctp)
  "7000-7009" -> "7000/tcp 7001/tcp ... 7009/tcp"
- Save 2 CSV files:
  - firewall_services_custom.csv
  - firewall_service_groups_with_ports.csv

Config is loaded strictly from .env in project root.
"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
import warnings

from urllib3.exceptions import InsecureRequestWarning

warnings.simplefilter("ignore", InsecureRequestWarning)

# -----------------------------
# .env parsing (no os.environ)
# -----------------------------
def parse_dotenv(path: str) -> Dict[str, str]:
    """Parse simple KEY=VALUE .env file."""
    data: Dict[str, str] = {}
    with open(path, "r", encoding="utf-8") as f:
        for line_no, raw in enumerate(f, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                raise ValueError(f"Malformed .env line {line_no}: {raw!r}")
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()
            if not key:
                raise ValueError(f"Empty key in .env line {line_no}")
            if (value.startswith('"') and value.endswith('"')) or (
                value.startswith("'") and value.endswith("'")
            ):
                value = value[1:-1]
            data[key] = value
    return data


def to_bool(value: Optional[str], default: bool) -> bool:
    if value is None or value == "":
        return default
    return value.strip().lower() in ("1", "true", "yes", "y", "on")


def to_int(value: Optional[str], default: int) -> int:
    if value is None or value == "":
        return default
    return int(value)


def to_str(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    v = value.strip()
    return v if v else None


# -----------------------------
# HTTP client
# -----------------------------
class FortiGateClient:
    """Minimal FortiGate REST API client (token auth)."""

    def __init__(self, base_url: str, token: str, verify_tls: bool, timeout: int) -> None:
        self.base_url = base_url.rstrip("/")
        self.verify_tls = verify_tls
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        )

    def get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """GET request, returns parsed JSON."""
        url = f"{self.base_url}{path}"
        try:
            resp = self.session.get(
                url, params=params or {}, timeout=self.timeout, verify=self.verify_tls
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise RuntimeError(f"HTTP request failed for {url}: {exc}") from exc

        try:
            return resp.json()
        except json.JSONDecodeError as exc:
            snippet = resp.text[:500] if resp.text else ""
            raise RuntimeError(f"Invalid JSON response from {url}: {exc}. Body: {snippet}") from exc


def extract_results(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return payload['results'] safely."""
    results = payload.get("results", [])
    if isinstance(results, list):
        return results
    return []


# -----------------------------
# Port normalization
# -----------------------------
def expand_port_tokens(ports: str, proto_tag: str) -> List[str]:
    """
    Expand FortiGate port string into tokens with transport.

    Examples:
      "88 464" -> ["88/tcp", "464/tcp"]
      "7000-7002" -> ["7000/tcp", "7001/tcp", "7002/tcp"]

    Args:
        ports (str): Raw portrange string (space-separated tokens).
        proto_tag (str): tcp/udp/udplite/sctp.

    Returns:
        List[str]: Expanded tokens with suffix "/<proto_tag>".
    """
    if not ports or not ports.strip():
        return []

    out: List[str] = []
    tokens = [t for t in ports.split() if t.strip()]

    for t in tokens:
        if "-" in t:
            parts = t.split("-", 1)
            if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                start = int(parts[0])
                end = int(parts[1])
                if start <= end:
                    out.extend([f"{p}/{proto_tag}" for p in range(start, end + 1)])
                    continue

        if t.isdigit():
            out.append(f"{t}/{proto_tag}")
        else:
            # Keep unknown tokens, still attach proto tag for clarity
            out.append(f"{t}/{proto_tag}")

    return out


def safe_get(obj: Dict[str, Any], key: str) -> str:
    """Get key from dict and normalize to str; handles missing keys."""
    val = obj.get(key, "")
    return str(val) if val is not None else ""


# -----------------------------
# Data models
# -----------------------------
@dataclass(frozen=True)
class ServicePorts:
    protocol: str
    tcp_ports: str
    udp_ports: str
    udplite_ports: str
    sctp_ports: str


# -----------------------------
# Exporters
# -----------------------------
def ensure_dir(path: str) -> None:
    Path(path).mkdir(parents=True, exist_ok=True)


def write_csv(path: Path, rows: List[Dict[str, Any]], fieldnames: List[str]) -> None:
    """Write CSV with UTF-8 and header."""
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


# -----------------------------
# Main logic
# -----------------------------
def build_services_map(services: List[Dict[str, Any]]) -> Dict[str, ServicePorts]:
    """Build name -> ServicePorts map from custom services list."""
    svc_map: Dict[str, ServicePorts] = {}

    for s in services:
        name = safe_get(s, "name")
        protocol = safe_get(s, "protocol")

        tcp = " ".join(expand_port_tokens(safe_get(s, "tcp-portrange"), "tcp"))
        udp = " ".join(expand_port_tokens(safe_get(s, "udp-portrange"), "udp"))
        udpl = " ".join(expand_port_tokens(safe_get(s, "udplite-portrange"), "udplite"))
        sctp = " ".join(expand_port_tokens(safe_get(s, "sctp-portrange"), "sctp"))

        svc_map[name] = ServicePorts(
            protocol=protocol,
            tcp_ports=tcp,
            udp_ports=udp,
            udplite_ports=udpl,
            sctp_ports=sctp,
        )

    return svc_map


def export_custom_services_csv(
    services: List[Dict[str, Any]],
    output_path: Path,
) -> None:
    """Export custom services with normalized ports to CSV."""
    rows: List[Dict[str, Any]] = []
    for s in services:
        name = safe_get(s, "name")
        protocol = safe_get(s, "protocol")

        row = {
            "name": name,
            "protocol": protocol,
            "tcp_ports": " ".join(expand_port_tokens(safe_get(s, "tcp-portrange"), "tcp")),
            "udp_ports": " ".join(expand_port_tokens(safe_get(s, "udp-portrange"), "udp")),
            "udplite_ports": " ".join(
                expand_port_tokens(safe_get(s, "udplite-portrange"), "udplite")
            ),
            "sctp_ports": " ".join(expand_port_tokens(safe_get(s, "sctp-portrange"), "sctp")),
        }
        rows.append(row)

    fieldnames = ["name", "protocol", "tcp_ports", "udp_ports", "udplite_ports", "sctp_ports"]
    write_csv(output_path, rows, fieldnames)


def export_service_groups_with_ports_csv(
    groups: List[Dict[str, Any]],
    svc_map: Dict[str, ServicePorts],
    output_path: Path,
) -> None:
    """Export service groups with ports (joined from svc_map)."""
    rows: List[Dict[str, Any]] = []

    for g in groups:
        group_name = safe_get(g, "name")
        members = g.get("member", []) or []

        if not isinstance(members, list):
            continue

        for m in members:
            member_name = ""
            if isinstance(m, dict):
                member_name = safe_get(m, "name")
            else:
                member_name = str(m)

            svc = svc_map.get(member_name)
            rows.append(
                {
                    "group_name": group_name,
                    "member_name": member_name,
                    "protocol": svc.protocol if svc else "",
                    "tcp_ports": svc.tcp_ports if svc else "",
                    "udp_ports": svc.udp_ports if svc else "",
                    "udplite_ports": svc.udplite_ports if svc else "",
                    "sctp_ports": svc.sctp_ports if svc else "",
                    "note": "" if svc else "not_found_in_custom_services",
                }
            )

    fieldnames = [
        "group_name",
        "member_name",
        "protocol",
        "tcp_ports",
        "udp_ports",
        "udplite_ports",
        "sctp_ports",
        "note",
    ]
    write_csv(output_path, rows, fieldnames)


def main() -> int:
    try:
        env = parse_dotenv(".env")

        token = to_str(env.get("FGT_API_TOKEN"))
        base_url = to_str(env.get("FGT_API_BASE_URL"))
        vdom = to_str(env.get("FGT_VDOM"))
        verify_tls = to_bool(env.get("FGT_VERIFY_TLS"), True)
        timeout = to_int(env.get("FGT_TIMEOUT_SECONDS"), 20)

        if not token:
            raise RuntimeError("Missing required .env variable: FGT_API_TOKEN")
        if not base_url:
            raise RuntimeError("Missing required .env variable: FGT_API_BASE_URL")
        if not vdom:
            raise RuntimeError("Missing required .env variable: FGT_VDOM")

        output_dir = to_str(env.get("OUTPUT_DIR")) or "./output"
        ensure_dir(output_dir)

        services_csv_name = to_str(env.get("SERVICES_CUSTOM_CSV")) or "firewall_services_custom.csv"
        groups_csv_name = (
            to_str(env.get("SERVICE_GROUPS_WITH_PORTS_CSV"))
            or "firewall_service_groups_with_ports.csv"
        )

        client = FortiGateClient(base_url=base_url, token=token, verify_tls=verify_tls, timeout=timeout)

        params = {"vdom": vdom}

        # --- Custom services ---
        svc_payload = client.get("/cmdb/firewall.service/custom", params=params)
        services = extract_results(svc_payload)
        if not services:
            print("No custom services returned.")
        else:
            services_csv = Path(output_dir) / services_csv_name
            export_custom_services_csv(services, services_csv)
            print(f"Custom services CSV: {services_csv}")

        # --- Service groups ---
        grp_payload = client.get("/cmdb/firewall.service/group", params=params)
        groups = extract_results(grp_payload)
        if not groups:
            print("No service groups returned.")
        else:
            svc_map = build_services_map(services)
            groups_csv = Path(output_dir) / groups_csv_name
            export_service_groups_with_ports_csv(groups, svc_map, groups_csv)
            print(f"Service groups CSV: {groups_csv}")

        return 0

    except Exception as exc:
        print(f"Error: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
