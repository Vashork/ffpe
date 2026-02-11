#!/usr/bin/env python3
"""
Post-process CSV: resolve selected columns into name[ip] inplace.

Reads settings from .env (project root).
Input CSV:
  - RESOLVE_INPUT_CSV if set
  - otherwise:
      - if RESOLVE_INTERACTIVE=true -> ask user to select CSV from OUTPUT_DIR
      - else -> newest *.csv from OUTPUT_DIR

Writes output CSV to OUTPUT_DIR with suffix RESOLVE_OUTPUT_SUFFIX.

Extra:
  RESOLVE_DISPLAY_MODE=full|ip
    full: keep name[ip]
    ip: write only ip from brackets (fallback to original token if unknown)
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import csv
import os
import re
import threading
import time
from datetime import datetime
from typing import Dict, List

from dotenv import load_dotenv

from fgpol.config import load_config
from fgpol.resolver import DnsResolver, FwObjectsLookup, resolve_cell

# Make sure .env vars are available via os.getenv (load_config does not export them)
load_dotenv(".env")


class Spinner:
    """Clean one-line spinner; avoids line wrapping by truncation."""

    def __init__(self, message: str = "Resolving") -> None:
        self.message = message
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._current = ""
        self._thread: threading.Thread | None = None

    def set_current(self, text: str) -> None:
        text = text.replace("\r", " ").replace("\n", " ")
        with self._lock:
            self._current = text

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1.0)
        self._clear_line()

    @staticmethod
    def _term_width() -> int:
        try:
            import shutil

            return shutil.get_terminal_size(fallback=(120, 24)).columns
        except Exception:
            return 120

    def _clear_line(self) -> None:
        width = self._term_width()
        print("\r" + (" " * width) + "\r", end="", flush=True)

    def _render(self, line: str) -> None:
        width = self._term_width()
        if width > 2 and len(line) >= width:
            line = line[: max(0, width - 2)] + "…"
        print("\r" + (" " * width), end="", flush=True)
        print("\r" + line, end="", flush=True)

    def _run(self) -> None:
        frames = ["\\", "|", "/", "-"]
        i = 0
        while not self._stop.is_set():
            with self._lock:
                cur = self._current
            tail = f" — {cur}" if cur else ""
            self._render(f"{self.message} [{frames[i % len(frames)]}]{tail}")
            i += 1
            time.sleep(0.12)


def _list_csv_candidates(output_dir: str) -> List[Path]:
    out = Path(output_dir)
    if not out.exists():
        return []
    candidates = sorted(out.glob("*.csv"), key=lambda p: p.stat().st_mtime, reverse=True)
    return [p for p in candidates if p.is_file()]


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
            s = input(f"\nSelect file to resolve names (1-{len(candidates)}): ").strip()
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


def _parse_columns(value: str) -> List[str]:
    cols = [c.strip() for c in value.split(",") if c.strip()]
    if not cols:
        raise ValueError("RESOLVE_COLUMNS is empty. Example: RESOLVE_COLUMNS=srcaddr,dstaddr")
    return cols


_BRACKET_RE = re.compile(r"\[(.*?)\]")


def _to_ip_only(resolved_token: str, original_token: str) -> str:
    m = _BRACKET_RE.search(resolved_token)
    if not m:
        return original_token
    inner = (m.group(1) or "").strip()
    if not inner or inner == "?":
        return original_token
    return inner


def _apply_display_mode(original_cell: str, resolved_cell: str, mode: str) -> str:
    mode = (mode or "full").lower()
    if mode != "ip":
        return resolved_cell

    orig_tokens = [t.strip() for t in original_cell.split(",") if t.strip()]
    res_tokens = [t.strip() for t in resolved_cell.split(",") if t.strip()]

    out: List[str] = []
    for i, rt in enumerate(res_tokens):
        ot = orig_tokens[i] if i < len(orig_tokens) else rt
        out.append(_to_ip_only(rt, ot))

    if len(orig_tokens) > len(res_tokens):
        out.extend(orig_tokens[len(res_tokens) :])

    return ", ".join(out)


def main() -> int:
    cfg = load_config(".env")

    if not cfg.resolve_enabled:
        print("Resolve disabled (RESOLVE_ENABLED=false).")
        return 0

    interactive = os.getenv("RESOLVE_INTERACTIVE", "false").lower() == "true"
    display_mode = os.getenv("RESOLVE_DISPLAY_MODE", "full")

    input_csv = _pick_input_csv(cfg.output_dir, cfg.resolve_input_csv, interactive)
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

    spinner = Spinner("Resolving")
    spinner.start()
    try:
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
                        short = val if len(val) <= 80 else (val[:80] + "…")
                        spinner.set_current(f"{col}={short}")

                        resolved = resolve_cell(val, resolver)
                        row[col] = _apply_display_mode(val, resolved, display_mode)
                rows.append(row)
    finally:
        spinner.stop()

    with out_path.open("w", encoding="utf-8", newline="") as fout:
        writer = csv.DictWriter(fout, fieldnames=reader.fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Resolved CSV written: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
