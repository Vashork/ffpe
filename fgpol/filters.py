"""
Client-side policy filtering.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


LIST_FIELDS = {"srcintf", "dstintf", "srcaddr", "dstaddr", "service"}


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


def parse_csv_list(value: Optional[str]) -> List[str]:
    """
    Parse comma-separated list from config.

    Args:
        value (Optional[str]): "A,B,C" or None.

    Returns:
        List[str]: ["A", "B", "C"]
    """
    if not value:
        return []
    return [x.strip() for x in value.split(",") if x.strip()]


def match_filter_str(needle: Optional[str], hay_value: Any) -> bool:
    """
    Exact/contains match for a single value.

    - For list-like fields: True if needle is contained in the list.
    - For scalar fields: True if equals.

    Args:
        needle (Optional[str]): Filter value. If None, match is always True.
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


def match_in(allowed: List[str], hay_value: Any) -> bool:
    """
    Inclusion filter (IN).

    For list-like fields: True if ANY element is in allowed.
    For scalar fields: True if scalar equals any allowed value.

    Args:
        allowed (List[str]): Allowed values list.
        hay_value (Any): Policy field value.

    Returns:
        bool: True if policy passes inclusion, else False.
    """
    if not allowed:
        return True

    hay_list = as_name_list(hay_value)
    if hay_list:
        return any(item in allowed for item in hay_list)

    return str(hay_value) in allowed


def match_not_in(excluded: List[str], hay_value: Any) -> bool:
    """
    Exclusion filter (NOT IN).

    For list-like fields: False if ANY element is in excluded.
    For scalar fields: False if scalar equals any excluded value.

    Args:
        excluded (List[str]): Excluded values list.
        hay_value (Any): Policy field value.

    Returns:
        bool: True if policy passes exclusion, else False.
    """
    if not excluded:
        return True

    hay_list = as_name_list(hay_value)
    if hay_list:
        return not any(item in excluded for item in hay_list)

    return str(hay_value) not in excluded


def _get_field_value(policy: Dict[str, Any], field: str) -> Any:
    """
    Get field value from policy with proper defaults.
    """
    if field in LIST_FIELDS:
        return policy.get(field, [])
    return policy.get(field, "")


def apply_filters(policies: List[Dict[str, Any]], flt: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Apply client-side filters to firewall policies.

    Supported:
      - exact:   <field> (e.g. srcintf, status, action, name, srcaddr...)
      - IN:      <field>_in       (comma-separated)
      - NOT IN:  <field>_not_in   (comma-separated)

    Fields typically used:
      srcintf, dstintf, action, status, name, policyid, srcaddr, dstaddr, service

    Notes:
      - policyid is handled separately (exact match)
      - IN/NOT IN for list-like fields checks membership against each element.

    Args:
        policies (List[Dict[str, Any]]): Policies from FortiOS.
        flt (Dict[str, Any]): Filter criteria.

    Returns:
        List[Dict[str, Any]]: Filtered policies.
    """
    # Pre-parse IN/NOT IN lists once
    list_keys = [
        "srcintf", "dstintf", "action", "status", "name", "srcaddr", "dstaddr", "service"
    ]
    allowed_map = {k: parse_csv_list(flt.get(f"{k}_in")) for k in list_keys}
    excluded_map = {k: parse_csv_list(flt.get(f"{k}_not_in")) for k in list_keys}

    out: List[Dict[str, Any]] = []
    for policy in policies:
        # --- Exact/single-value filters (as before) ---
        for key in list_keys:
            if not match_filter_str(flt.get(key), _get_field_value(policy, key)):
                break
        else:
            # --- IN filters ---
            for key in list_keys:
                if not match_in(allowed_map[key], _get_field_value(policy, key)):
                    break
            else:
                # --- NOT IN filters ---
                for key in list_keys:
                    if not match_not_in(excluded_map[key], _get_field_value(policy, key)):
                        break
                else:
                    # --- policyid exact match ---
                    policy_id = policy.get("policyid", policy.get("id", ""))
                    want_id = flt.get("policyid")
                    if want_id is not None and str(policy_id) != str(want_id):
                        continue

                    out.append(policy)

    return out
