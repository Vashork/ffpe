"""
Console table rendering.
"""

from __future__ import annotations

from typing import Dict, List, Tuple

from fgpol.fields import render_value


def print_table(rows: List[Dict], columns: List[Tuple[str, str]], max_width: int = 80) -> None:
    """
    Print rows as an adaptive console table.

    Args:
        rows (List[Dict]): Policy dicts.
        columns (List[Tuple[str, str]]): (header, key) columns.
        max_width (int): Maximum width of a column before clipping.
    """
    headers = [h for h, _ in columns]
    keys = [k for _, k in columns]

    matrix: List[List[str]] = [[render_value(r, k) for k in keys] for r in rows]

    widths: List[int] = []
    for i, header in enumerate(headers):
        w = len(header)
        for row in matrix:
            w = max(w, len(row[i]))
        widths.append(min(w, max_width))

    def clip(text: str, width: int) -> str:
        if len(text) <= width:
            return text
        if width <= 1:
            return text[:width]
        return text[: width - 1] + "…"

    header_line = " | ".join(clip(headers[i], widths[i]).ljust(widths[i]) for i in range(len(headers)))
    sep_line = "-+-".join("-" * widths[i] for i in range(len(headers)))

    print(header_line)
    print(sep_line)

    for row in matrix:
        line = " | ".join(clip(row[i], widths[i]).ljust(widths[i]) for i in range(len(headers)))
        print(line)
