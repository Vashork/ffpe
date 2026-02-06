#!/usr/bin/env python3
"""
Post-process CSV: resolve firewall service names into name(ports).

Reads settings from .env (project root).

Input CSV:
  - PORTS_RESOLVE_INPUT_CSV if set
  - otherwise the newest *.csv from OUTPUT_DIR

Service tables:
  - PORTS_SERVICES_CSV -> firewall_services_custom.csv
  - PORTS_SERVICE_GROUPS_CSV -> firewall_service_groups_with_ports.csv (optional)

Columns to resolve:
  - PORTS_RESOLVE_COLUMNS (comma-separated)
    Example: PORTS_RESOLVE_COLUMNS=service,services

Writes output CSV to OUTPUT_DIR with suffix PORTS_RESOLVE_OUTPUT_SUFFIX (default: _ports).
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fgpol.config import load_config


def _pick_input_csv(output_dir: str, explicit: str | None) -> Path:
    if explicit:
        p = Path(explicit)
        if not p.exists():
            raise FileNotFoundError(f"Input CSV not found: {p}")
        return p

    out = Path(output_dir)
    candidates = sorted(out.glob("*.csv"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not candidates:
        raise FileNotFoundError(f"No CSV files found in output dir: {out}")
    return candidates[0]


def _parse_columns(value: str | None) -> List[str]:
    if not value:
        raise ValueError("PORTS_RESOLVE_COLUMNS is empty. Example: PORTS_RESOLVE_COLUMNS=service")
    cols = [c.strip() for c in value.split(",") if c.strip()]
    if not cols:
        raise ValueError("PORTS_RESOLVE_COLUMNS is empty. Example: PORTS_RESOLVE_COLUMNS=service")
    return cols


def _split_tokens(cell: str) -> List[str]:
    return [t.strip() for t in cell.split(",") if t.strip()]


def _join_ports(parts: List[str]) -> str:
    tokens: List[str] = []
    for p in parts:
        if not p:
            continue
        for t in str(p).split():
            if t:
                tokens.append(t)

    seen: Set[str] = set()
    out: List[str] = []
    for t in tokens:
        if t not in seen:
            seen.add(t)
            out.append(t)

    return " ".join(out)


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
            ports = _join_ports([
                row.get("tcp_ports") or "",
                row.get("udp_ports") or "",
                row.get("udplite_ports") or "",
                row.get("sctp_ports") or "",
            ])
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
            ports = _join_ports([
                row.get("tcp_ports") or "",
                row.get("udp_ports") or "",
                row.get("udplite_ports") or "",
                row.get("sctp_ports") or "",
            ])
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


def main() -> int:
    cfg = load_config(".env")

    if not cfg.ports_resolve_enabled:
        print("Ports resolve disabled (PORTS_RESOLVE_ENABLED=false).")
        return 0

    if not cfg.ports_services_csv:
        raise RuntimeError("Missing required .env variable: PORTS_SERVICES_CSV")

    services_csv = Path(cfg.ports_services_csv)
    groups_csv: Optional[Path] = Path(cfg.ports_service_groups_csv) if cfg.ports_service_groups_csv else None

    svc_map = load_services_table(services_csv)
    grp_map: Dict[str, str] = load_groups_table(groups_csv) if groups_csv else {}

    input_csv = _pick_input_csv(cfg.output_dir, cfg.ports_resolve_input_csv)
    suffix = cfg.ports_resolve_output_suffix or "_ports"
    columns_to_resolve = _parse_columns(cfg.ports_resolve_columns)

    out_dir = Path(cfg.output_dir)
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
