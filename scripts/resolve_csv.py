#!/usr/bin/env python3
"""
Post-process CSV: resolve selected columns into name[ip] inplace.

Reads settings from .env (project root).
Input CSV:
  - RESOLVE_INPUT_CSV if set
  - otherwise the newest *.csv from OUTPUT_DIR

Writes output CSV to OUTPUT_DIR with suffix RESOLVE_OUTPUT_SUFFIX.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import csv
import os
from pathlib import Path
from typing import Dict, List

from fgpol.config import load_config
from fgpol.resolver import DnsResolver, FwObjectsLookup, resolve_cell


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


def _parse_columns(value: str) -> List[str]:
    cols = [c.strip() for c in value.split(",") if c.strip()]
    if not cols:
        raise ValueError("RESOLVE_COLUMNS is empty. Example: RESOLVE_COLUMNS=srcaddr,dstaddr")
    return cols


def main() -> int:
    cfg = load_config(".env")

    # Read resolve-specific options from cfg via raw .env keys:
    # We'll store them in config.py in the next step (см. ниже).
    # Пока — читаем напрямую из cfg через его "filters/show_flags" нельзя,
    # поэтому ожидается, что ты добавишь поля в AppConfig (я могу сделать патч).
    # Здесь предполагаем, что эти поля уже добавлены:
    if not cfg.resolve_enabled:
        print("Resolve disabled (RESOLVE_ENABLED=false).")
        return 0

    input_csv = _pick_input_csv(cfg.output_dir, cfg.resolve_input_csv)
    suffix = cfg.resolve_output_suffix or "_resolved"
    columns_to_resolve = _parse_columns(cfg.resolve_columns)
    timeout = cfg.resolve_dns_timeout

    fw_lookup = None
    if cfg.resolve_fw_objects_path:
        path = Path(cfg.resolve_fw_objects_path)
        if path.exists():
            fw_lookup = FwObjectsLookup(path)
            fw_lookup.load()

    resolver = DnsResolver(timeout=timeout, fw_objects=fw_lookup)

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
                val = (row.get(col) or "").strip()
                if val:
                    row[col] = resolve_cell(val, resolver)
            rows.append(row)

    with out_path.open("w", encoding="utf-8", newline="") as fout:
        writer = csv.DictWriter(fout, fieldnames=reader.fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Resolved CSV written: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
