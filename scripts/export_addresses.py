#!/usr/bin/env python3
"""
Export FortiGate address objects to CSV.

- Fetch address objects: /cmdb/firewall/address
- Handle variability:
  - subnet may exist (ipmask)
  - fqdn may exist (fqdn type)
- Convert subnet "IP MASK" -> CIDR (e.g. 10.0.0.0 255.255.255.0 -> 10.0.0.0/24)
- Save CSV to OUTPUT_DIR.

Config is loaded strictly from .env in project root.
"""

from __future__ import annotations

import csv
import json
import warnings
import ipaddress
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
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
                url,
                params=params or {},
                timeout=self.timeout,
                verify=self.verify_tls,
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise RuntimeError(f"HTTP request failed for {url}: {exc}") from exc

        try:
            return resp.json()
        except json.JSONDecodeError as exc:
            snippet = resp.text[:500] if resp.text else ""
            raise RuntimeError(
                f"Invalid JSON response from {url}: {exc}. Body: {snippet}"
            ) from exc


def extract_results(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return payload['results'] safely."""
    results = payload.get("results", [])
    if isinstance(results, list):
        return results
    return []


def ensure_dir(path: str) -> None:
    """Create directory if missing."""
    Path(path).mkdir(parents=True, exist_ok=True)


def safe_get(obj: Dict[str, Any], key: str) -> str:
    """Get key from dict and normalize to str; handles missing keys."""
    val = obj.get(key, "")
    return str(val) if val is not None else ""


def subnet_to_cidr(subnet: str) -> str:
    """
    Convert FortiGate subnet string "IP MASK" to CIDR notation.

    Example:
        "10.20.108.0 255.255.254.0" -> "10.20.108.0/23"
    """
    if not subnet:
        return ""

    parts = subnet.split()
    if len(parts) != 2:
        return ""

    ip, mask = parts
    try:
        net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
        return str(net)
    except ValueError:
        return ""


def write_csv(path: Path, rows: List[Dict[str, Any]], fieldnames: List[str]) -> None:
    """Write CSV with UTF-8 and header."""
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def export_addresses_csv(addresses: List[Dict[str, Any]], output_path: Path) -> None:
    """
    Export address objects to CSV.

    Fields:
      - name
      - type
      - subnet
      - cidr
      - fqdn
      - interface
      - associated_interface
      - comment
      - uuid
    """
    rows: List[Dict[str, Any]] = []
    for a in addresses:
        subnet = safe_get(a, "subnet")
        rows.append(
            {
                "name": safe_get(a, "name"),
                "type": safe_get(a, "type"),
                "subnet": subnet,
                "cidr": subnet_to_cidr(subnet),
                "fqdn": safe_get(a, "fqdn"),
                "interface": safe_get(a, "interface"),
                "associated_interface": safe_get(a, "associated-interface"),
                "comment": safe_get(a, "comment"),
                "uuid": safe_get(a, "uuid"),
            }
        )

    fieldnames = [
        "name",
        "type",
        "subnet",
        "cidr",
        "fqdn",
        "interface",
        "associated_interface",
        "comment",
        "uuid",
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

        addresses_csv_name = to_str(env.get("ADDRESSES_CSV")) or "firewall_addresses.csv"
        output_path = Path(output_dir) / addresses_csv_name

        client = FortiGateClient(
            base_url=base_url,
            token=token,
            verify_tls=verify_tls,
            timeout=timeout,
        )

        payload = client.get("/cmdb/firewall/address", params={"vdom": vdom})
        addresses = extract_results(payload)

        if not addresses:
            print("No address objects returned.")
            return 0

        export_addresses_csv(addresses, output_path)
        print(f"Addresses CSV: {output_path}")
        return 0

    except Exception as exc:
        print(f"Error: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
