"""
Export helpers (CSV).
"""

from __future__ import annotations

import csv
import os
from datetime import datetime
from typing import Dict, List, Tuple, Any

from fgpol.fields import render_value


def ensure_output_dir(path: str) -> None:
    """
    Ensure output directory exists.

    Args:
        path (str): Output directory path.
    """
    os.makedirs(path, exist_ok=True)


def export_csv(
        rows: List[Dict[str, Any]],
        columns: List[Tuple[str, str]],
        output_dir: str,
        filename: str | None = None,
) -> str:
    """
    Export policies to CSV file.

    Args:
        rows (List[Dict]): Firewall policies.
        columns (List[Tuple[str, str]]): (header, key) pairs.
        output_dir (str): Output directory.
        filename (str | None): CSV filename. Auto-generated if None.

    Returns:
        str: Full path to written CSV file.
    """
    if not filename:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"firewall_policies_{ts}.csv"

    path = os.path.join(output_dir, filename)

    headers = [h for h, _ in columns]
    keys = [k for _, k in columns]

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)

        for row in rows:
            writer.writerow([render_value(row, key) for key in keys])

    return path
