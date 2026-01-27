"""
Client-side policy filtering.
"""

from __future__ import annotations

from typing import Any, Dict, List


def as_name_list(value: Any) -> List[str]:
    """
    Convert FortiOS list/object values to list of names (strings).

    Args:
        value (Any): A value that may be:
            - list of {"name": "..."} dicts
            - list of strings
            - dict with "name"
            - string
            - other scalars

    Returns:
        List[str]: Normalized list of names/values.
    """
    if value is None:
        return []
    if isinstance(value, list):
        out: List[str] = []
        for item in value:
            if isinstance(item, dict) and "name" in item:
                out.append(str(item["name"]))
            elif isinstance(item, str):
                out.append(item)
            else:
                out.append(str(item))
        return out
    if isinstance(value, dict):
        if "name" in value:
            return [str(value["name"])]
        return [str(value)]
    if isinstance(value, str):
        return [value]
    return [str(value)]


def match_filter_str(needle: str | None, hay_value: Any) -> bool:
    """
    Match a string filter against scalar or list-like FortiOS fields.

    Args:
        needle (str | None): Filter value. If None, match is always True.
        hay_value (Any): Policy field value.

    Returns:
        bool: True if matches, else False.
    """
    if needle is None:
        return True

    hay_list = as_name_list(hay_value)
    if hay_list:
        return needle in hay_list

    return str(hay_value) == needle


def apply_filters(policies: List[Dict[str, Any]], flt: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Apply client-side filters to firewall policies.

    Args:
        policies (List[Dict[str, Any]]): Policies from FortiOS.
        flt (Dict[str, Any]): Filter criteria (values may be None).

    Returns:
        List[Dict[str, Any]]: Filtered policies.
    """
    out: List[Dict[str, Any]] = []
    for policy in policies:
        if not match_filter_str(flt.get("srcintf"), policy.get("srcintf", [])):
            continue
        if not match_filter_str(flt.get("dstintf"), policy.get("dstintf", [])):
            continue
        if not match_filter_str(flt.get("action"), policy.get("action", "")):
            continue
        if not match_filter_str(flt.get("status"), policy.get("status", "")):
            continue
        if not match_filter_str(flt.get("name"), policy.get("name", "")):
            continue

        policy_id = policy.get("policyid", policy.get("id", ""))
        want_id = flt.get("policyid")
        if want_id is not None and str(policy_id) != str(want_id):
            continue

        if not match_filter_str(flt.get("srcaddr"), policy.get("srcaddr", [])):
            continue
        if not match_filter_str(flt.get("dstaddr"), policy.get("dstaddr", [])):
            continue
        if not match_filter_str(flt.get("service"), policy.get("service", [])):
            continue

        out.append(policy)

    return out
