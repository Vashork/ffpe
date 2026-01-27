"""
Output columns and value formatting (variative via SHOW_* flags).
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Tuple

from fgpol.filters import as_name_list


def join_names(value: Any, sep: str = ",") -> str:
    """
    Join name-like values into a readable string.

    Args:
        value (Any): Field value (list/dict/str).
        sep (str): Separator.

    Returns:
        str: Joined string.
    """
    return sep.join(as_name_list(value))


def compute_columns(show_flags: Dict[str, bool]) -> List[Tuple[str, str]]:
    """
    Compute output columns based on SHOW_* flags.

    Args:
        show_flags (Dict[str, bool]): Dict of flags controlling output.

    Returns:
        List[Tuple[str, str]]: List of (header, field_key) in order.
    """
    cols: List[Tuple[str, str]] = []

    if show_flags.get("policyid", True):
        cols.append(("policyid", "policyid"))
    if show_flags.get("name", True):
        cols.append(("name", "name"))

    if show_flags.get("srcintf", True):
        cols.append(("srcintf", "srcintf"))
    if show_flags.get("dstintf", True):
        cols.append(("dstintf", "dstintf"))

    if show_flags.get("srcaddr", True):
        cols.append(("srcaddr", "srcaddr"))
    if show_flags.get("dstaddr", True):
        cols.append(("dstaddr", "dstaddr"))
    if show_flags.get("service", True):
        cols.append(("service", "service"))

    if show_flags.get("action", True):
        cols.append(("action", "action"))
    if show_flags.get("status", True):
        cols.append(("status", "status"))
    if show_flags.get("schedule", False):
        cols.append(("schedule", "schedule"))
    if show_flags.get("logtraffic", False):
        cols.append(("logtraffic", "logtraffic"))

    return cols


def render_value(policy: Dict[str, Any], key: str) -> str:
    """
    Render a policy field into a readable string.

    Args:
        policy (Dict[str, Any]): Firewall policy object.
        key (str): Field key.

    Returns:
        str: Rendered value.
    """
    if key in ("srcintf", "dstintf", "srcaddr", "dstaddr", "service"):
        return join_names(policy.get(key))

    if key == "policyid":
        return str(policy.get("policyid", policy.get("id", "")))

    value = policy.get(key, "")
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)
