#!/usr/bin/env python3
"""
Post-process CSV: resolve firewall service names into name(ports).

Reads settings from .env (project root).

Input CSV:
  - PORTS_RESOLVE_INPUT_CSV if set
  - otherwise:
      - if PORTS_RESOLVE_INTERACTIVE=true -> ask user to select CSV from OUTPUT_DIR
      - else -> newest *.csv from OUTPUT_DIR (excluding truth tables)

Service tables:
  - PORTS_SERVICES_CSV -> firewall_services_custom.csv
  - PORTS_SERVICE_GROUPS_CSV -> firewall_service_groups_with_ports.csv (optional)

Columns to resolve:
  - PORTS_RESOLVE_COLUMNS (comma-separated)
    Example: PORTS_RESOLVE_COLUMNS=service,services

Writes output CSV to OUTPUT_DIR with suffix PORTS_RESOLVE_OUTPUT_SUFFIX (default: _ports).

Also:
  - supports large CSV fields (RPC)
  - compresses sequential ports: 4001/tcp 4002/tcp 4003/tcp -> 4001-4003/tcp
"""

from __future__ import annotations

import csv
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set

from dotenv import load_dotenv

load_dotenv(".env")

# allow very large CSV fields (RPC ranges etc.)
try:
    csv.field_size_limit(sys.maxsize)
except OverflowError:
    csv.field_size_limit(10_000_000)

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _parse_columns(value: str | None) -> List[str]:
    if not value:
        raise ValueError("PORTS_RESOLVE_COLUMNS is empty. Example: PORTS_RESOLVE_COLUMNS=service")
    cols = [c.strip() for c in value.split(",") if c.strip()]
    if not cols:
        raise ValueError("PORTS_RESOLVE_COLUMNS is empty. Example: PORTS_RESOLVE_COLUMNS=service")
    return cols


def _split_tokens(cell: str) -> List[str]:
    # comma-separated tokens (same as resolve_name.py)
    return [t.strip() for t in cell.split(",") if t.strip()]


def compress_ports(port_tokens: List[str]) -> List[str]:
    """
    Compress sequential numeric ports per proto:
      ["4001/tcp","4002/tcp","4003/tcp","53/udp","4010/tcp"]
    -> ["4001-4003/tcp","4010/tcp","53/udp"]
    """
    by_proto: Dict[str, List[int]] = {}
    passthrough: List[str] = []

    for tok in port_tokens:
        tok = tok.strip()
        if not tok:
            continue
        if "/" not in tok:
            passthrough.append(tok)
            continue

        port_part, proto = tok.rsplit("/", 1)
        if port_part.isdigit():
            by_proto.setdefault(proto, []).append(int(port_part))
        else:
            passthrough.append(tok)

    out: List[str] = []

    for proto, ports in by_proto.items():
        ports = sorted(set(ports))
        i = 0
        while i < len(ports):
            start = ports[i]
            end = start
            while i + 1 < len(ports) and ports[i + 1] == end + 1:
                i += 1
                end = ports[i]
            if start == end:
                out.append(f"{start}/{proto}")
            else:
                out.append(f"{start}-{end}/{proto}")
            i += 1

    out.extend(passthrough)

    def _sort_key(t: str):
        if "/" in t:
            pp, pr = t.rsplit("/", 1)
            first = pp.split("-", 1)[0]
            return (pr, int(first) if first.isdigit() else 10**12, t)
        return ("~", 10**12, t)

    return sorted(out, key=_sort_key)


def _join_ports(parts: List[str]) -> str:
    tokens: List[str] = []
    for p in parts:
        if not p:
            continue
        for t in str(p).split():
            if t:
                tokens.append(t)

    seen: Set[str] = set()
    uniq: List[str] = []
    for t in tokens:
        if t not in seen:
            seen.add(t)
            uniq.append(t)

    compressed = compress_ports(uniq)
    return " ".join(compressed)


def load_services_table(path: Path) -> Dict[str, str]:
    """name -> ports_string"""
    if not path.exists():
        raise FileNotFoundError(f"Services CSV not found: {path}")

    m: Dict[str, str] = {}
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        r = csv.DictReader(f)
        if not r.fieldnames:
            return m

        required = {"name", "tcp_ports", "udp_ports", "udplite_ports", "sctp_ports"}
        if not required.issubset(set(r.fieldnames)):
            raise ValueError(f"Services CSV must contain columns {sorted(required)}. Found: {r.fieldnames}")

        for row in r:
            name = (row.get("name") or "").strip()
            if not name:
                continue
            ports = _join_ports(
                [
                    row.get("tcp_ports") or "",
                    row.get("udp_ports") or "",
                    row.get("udplite_ports") or "",
                    row.get("sctp_ports") or "",
                    ]
            )
            m[name] = ports

    return m


def load_groups_table(path: Path) -> Dict[str, str]:
    """group_name -> ports_string aggregated from member rows"""
    if not path.exists():
        raise FileNotFoundError(f"Service groups CSV not found: {path}")

    tmp: Dict[str, List[str]] = {}
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        r = csv.DictReader(f)
        if not r.fieldnames:
            return {}

        required = {"group_name", "tcp_ports", "udp_ports", "udplite_ports", "sctp_ports"}
        if not required.issubset(set(r.fieldnames)):
            raise ValueError(f"Groups CSV must contain columns {sorted(required)}. Found: {r.fieldnames}")

        for row in r:
            g = (row.get("group_name") or "").strip()
            if not g:
                continue
            ports = _join_ports(
                [
                    row.get("tcp_ports") or "",
                    row.get("udp_ports") or "",
                    row.get("udplite_ports") or "",
                    row.get("sctp_ports") or "",
                    ]
            )
            if ports:
                tmp.setdefault(g, []).append(ports)

    out: Dict[str, str] = {}
    for g, chunks in tmp.items():
        out[g] = _join_ports(chunks)
    return out


def resolve_service_token(token: str, svc_map: Dict[str, str], grp_map: Dict[str, str]) -> str:
    ports = svc_map.get(token)
    if ports is not None:
        return f"{token}({ports})" if ports else f"{token}()"

    gports = grp_map.get(token)
    if gports is not None:
        return f"{token}({gports})" if gports else f"{token}()"

    return token


def _list_csv_candidates(output_dir: str) -> List[Path]:
    out = Path(output_dir)
    if not out.exists():
        return []

    # exclude truth tables so we don't accidentally "resolve" them
    exclude = {
        "firewall_services_custom.csv",
        "firewall_service_groups_with_ports.csv",
    }

    candidates = sorted(out.glob("*.csv"), key=lambda p: p.stat().st_mtime, reverse=True)
    return [p for p in candidates if p.is_file() and p.name not in exclude]


def _select_csv_interactive(output_dir: str) -> Path:
    candidates = _list_csv_candidates(output_dir)
    if not candidates:
        raise FileNotFoundError(f"No CSV files found in output dir: {output_dir}")

    print(f"\nAvailable CSV files in {output_dir}:\n")
    for i, p in enumerate(candidates, start=1):
        ts = datetime.fromtimestamp(p.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{i}] {p.name}    {ts}")

    try:
        while True:
            s = input(f"\nSelect file to resolve ports (1-{len(candidates)}): ").strip()
            if not s:
                continue
            if s.isdigit():
                idx = int(s)
                if 1 <= idx <= len(candidates):
                    return candidates[idx - 1]
            print("Invalid selection. Please enter a number from the list.")
    except (KeyboardInterrupt, EOFError):
        print("\nCancelled.")
        raise SystemExit(0)


def _pick_input_csv(output_dir: str, explicit: str | None, interactive: bool) -> Path:
    if explicit:
        p = Path(explicit)
        if not p.exists():
            raise FileNotFoundError(f"Input CSV not found: {p}")
        return p

    if interactive:
        return _select_csv_interactive(output_dir)

    candidates = _list_csv_candidates(output_dir)
    if not candidates:
        raise FileNotFoundError(f"No CSV files found in output dir: {output_dir}")
    return candidates[0]


def main() -> int:
    if os.getenv("PORTS_RESOLVE_ENABLED", "false").lower() != "true":
        print("Ports resolve disabled (PORTS_RESOLVE_ENABLED=false).")
        return 0

    output_dir = os.getenv("OUTPUT_DIR", "./output")
    interactive = os.getenv("PORTS_RESOLVE_INTERACTIVE", "false").lower() == "true"

    input_csv_env = os.getenv("PORTS_RESOLVE_INPUT_CSV")
    suffix = os.getenv("PORTS_RESOLVE_OUTPUT_SUFFIX") or "_ports"
    columns_to_resolve = _parse_columns(os.getenv("PORTS_RESOLVE_COLUMNS"))

    services_csv_path = os.getenv("PORTS_SERVICES_CSV")
    if not services_csv_path:
        raise RuntimeError("Missing required .env variable: PORTS_SERVICES_CSV")

    groups_csv_path = os.getenv("PORTS_SERVICE_GROUPS_CSV")

    services_csv = Path(services_csv_path)
    groups_csv: Optional[Path] = Path(groups_csv_path) if groups_csv_path else None

    svc_map = load_services_table(services_csv)
    grp_map: Dict[str, str] = load_groups_table(groups_csv) if groups_csv else {}

    input_csv = _pick_input_csv(output_dir, input_csv_env, interactive)

    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    out_name = f"{input_csv.stem}{suffix}{input_csv.suffix}"
    out_path = out_dir / out_name

    with input_csv.open("r", encoding="utf-8", newline="") as fin:
        reader = csv.DictReader(fin)
        if not reader.fieldnames:
            raise ValueError("CSV has no header row.")

        missing = [c for c in columns_to_resolve if c not in reader.fieldnames]
        if missing:
            raise ValueError(f"Columns not found in CSV header: {missing}. Header: {reader.fieldnames}")

        rows: List[Dict[str, str]] = []
        for row in reader:
            for col in columns_to_resolve:
                cell = (row.get(col) or "").strip()
                if not cell:
                    continue
                tokens = _split_tokens(cell)
                resolved = [resolve_service_token(t, svc_map, grp_map) for t in tokens]
                row[col] = ", ".join(resolved)
            rows.append(row)

    with out_path.open("w", encoding="utf-8", newline="") as fout:
        writer = csv.DictWriter(fout, fieldnames=reader.fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Ports-resolved CSV written: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
