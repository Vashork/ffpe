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
import threading
import time
from typing import Dict, List

from fgpol.config import load_config
from fgpol.resolver import DnsResolver, FwObjectsLookup, resolve_cell


import os
import shutil
import sys
import threading
import time


class Spinner:
    """Clean one-line spinner; handles long lines (no wrapping) and clears properly."""

    def __init__(self, message: str = "Resolving") -> None:
        self.message = message
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._current = ""
        self._thread: threading.Thread | None = None
        self._last_lines = 1

        # Enable ANSI on Windows terminals that support it
        self._ansi = sys.stdout.isatty() and os.environ.get("TERM", "") != "dumb"

    def set_current(self, text: str) -> None:
        # make it single-line
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
        self._clear_rendered_lines()

    def _term_width(self) -> int:
        try:
            return shutil.get_terminal_size(fallback=(120, 24)).columns
        except Exception:
            return 120

    def _clear_rendered_lines(self) -> None:
        width = self._term_width()

        if self._ansi:
            # Clear all previously occupied lines and return to the top line
            for _ in range(self._last_lines):
                sys.stdout.write("\r\x1b[2K")  # clear current line
                sys.stdout.write("\x1b[1A")    # cursor up
            sys.stdout.write("\r\x1b[2K")      # clear the line we're on
            sys.stdout.write("\r")
            sys.stdout.flush()
        else:
            # best-effort: clear only current line
            sys.stdout.write("\r" + (" " * width) + "\r")
            sys.stdout.flush()

        self._last_lines = 1

    def _render(self, line: str) -> None:
        width = self._term_width()

        # Truncate to avoid wrapping (reserve 1 char)
        if width > 2 and len(line) >= width:
            line = line[: max(0, width - 2)] + "…"

        # Compute how many terminal lines it would occupy *without truncation*:
        # (we keep truncation anyway; this is for clearing safety)
        self._last_lines = 1

        if self._ansi:
            sys.stdout.write("\r\x1b[2K")  # clear line
            sys.stdout.write("\r" + line)
            sys.stdout.flush()
        else:
            sys.stdout.write("\r" + (" " * width) + "\r")
            sys.stdout.write(line)
            sys.stdout.flush()

    def _run(self) -> None:
        frames = ["\\", "|", "/", "-"]
        i = 0
        while not self._stop.is_set():
            with self._lock:
                cur = self._current

            tail = f" — {cur}" if cur else ""
            line = f"{self.message} [{frames[i % len(frames)]}]{tail}"
            self._render(line)

            i += 1
            time.sleep(0.12)



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
                        spinner.set_current(f"{col}={val}")
                        row[col] = resolve_cell(val, resolver)
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
