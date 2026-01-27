"""
FortiOS response helpers.
"""

from __future__ import annotations

from typing import Any, Dict, List


def extract_results(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extract policy list from FortiOS response.

    FortiOS commonly returns:
        {"results": [ ... ], ...}

    Args:
        payload (Dict[str, Any]): JSON response.

    Returns:
        List[Dict[str, Any]]: List of policy objects.
    """
    if not isinstance(payload, dict):
        return []

    results = payload.get("results")
    if isinstance(results, list):
        return results

    alt = payload.get("result")
    if isinstance(alt, list):
        return alt

    if isinstance(results, dict):
        return [results]

    return []
