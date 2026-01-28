"""
Configuration loader and .env parser.

All configuration is loaded strictly from a .env file in project root.
No environment variables are read directly.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional


def parse_dotenv(path: str) -> Dict[str, str]:
    data: Dict[str, str] = {}
    with open(path, "r", encoding="utf-8") as f:
        for line_no, raw in enumerate(f, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if "=" not in line:
                raise ValueError(f"Malformed .env line {line_no}: {raw!r}")

            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()

            if not key:
                raise ValueError(f"Empty key in .env line {line_no}")

            if (value.startswith('"') and value.endswith('"')) or (
                    value.startswith("'") and value.endswith("'")
            ):
                value = value[1:-1]

            data[key] = value

    return data


def to_bool(value: Optional[str], default: bool) -> bool:
    if value is None or value == "":
        return default
    return value.strip().lower() in ("1", "true", "yes", "y", "on")


def to_int(value: Optional[str], default: int) -> int:
    if value is None or value == "":
        return default
    return int(value)


def to_str(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    v = value.strip()
    return v if v else None


@dataclass(frozen=True)
class AppConfig:
    token: str
    base_url: str
    vdom: Optional[str]
    verify_tls: bool
    timeout_seconds: int
    server_filter: Optional[str]
    output_dir: str
    output_max_col_width: int
    filters: Dict[str, Any]
    show_flags: Dict[str, bool]
    export_csv: bool
    csv_filename: str | None
    print_console: bool

    # DEBUG
    debug: bool
    debug_response_keys: bool
    debug_results_type: bool

    def to_query_params(self) -> Dict[str, Any]:
        params: Dict[str, Any] = {"limit": 1000, "skip": 0}
        if self.vdom:
            params["vdom"] = self.vdom
        if self.server_filter:
            params["filter"] = self.server_filter
        return params


def load_config(dotenv_path: str) -> AppConfig:
    data = parse_dotenv(dotenv_path)

    token = to_str(data.get("FGT_API_TOKEN"))
    base_url = to_str(data.get("FGT_API_BASE_URL"))

    if not token:
        raise RuntimeError("Missing required .env variable: FGT_API_TOKEN")
    if not base_url:
        raise RuntimeError("Missing required .env variable: FGT_API_BASE_URL")

    verify_tls = to_bool(data.get("FGT_VERIFY_TLS"), True)

    try:
        timeout_seconds = to_int(data.get("FGT_TIMEOUT_SECONDS"), 20)
        output_max_col_width = to_int(data.get("OUTPUT_MAX_COL_WIDTH"), 80)
    except ValueError as exc:
        raise RuntimeError(f"Invalid integer value in .env: {exc}") from exc

    filters = {
        "srcintf": to_str(data.get("FILTER_SRCINTF")),
        "dstintf": to_str(data.get("FILTER_DSTINTF")),
        "action": to_str(data.get("FILTER_ACTION")),
        "status": to_str(data.get("FILTER_STATUS")),
        "name": to_str(data.get("FILTER_NAME")),
        "policyid": to_str(data.get("FILTER_POLICYID")),
        "srcaddr": to_str(data.get("FILTER_SRCADDR")),
        "dstaddr": to_str(data.get("FILTER_DSTADDR")),
        "service": to_str(data.get("FILTER_SERVICE")),
        "dstintf_not_in": to_str(data.get("FILTER_DSTINTF_NOT_IN")),
        "status_not_in": to_str(data.get("FILTER_STATUS_NOT_IN")),
        # IN lists
        "srcintf_in": to_str(data.get("FILTER_SRCINTF_IN")),
        "dstintf_in": to_str(data.get("FILTER_DSTINTF_IN")),
        "action_in": to_str(data.get("FILTER_ACTION_IN")),
        "status_in": to_str(data.get("FILTER_STATUS_IN")),
        "name_in": to_str(data.get("FILTER_NAME_IN")),
        "srcaddr_in": to_str(data.get("FILTER_SRCADDR_IN")),
        "dstaddr_in": to_str(data.get("FILTER_DSTADDR_IN")),
        "service_in": to_str(data.get("FILTER_SERVICE_IN")),
        # NOT IN lists
        "srcintf_not_in": to_str(data.get("FILTER_SRCINTF_NOT_IN")),
        "dstintf_not_in": to_str(data.get("FILTER_DSTINTF_NOT_IN")),
        "action_not_in": to_str(data.get("FILTER_ACTION_NOT_IN")),
        "status_not_in": to_str(data.get("FILTER_STATUS_NOT_IN")),
        "name_not_in": to_str(data.get("FILTER_NAME_NOT_IN")),
        "srcaddr_not_in": to_str(data.get("FILTER_SRCADDR_NOT_IN")),
        "dstaddr_not_in": to_str(data.get("FILTER_DSTADDR_NOT_IN")),
        "service_not_in": to_str(data.get("FILTER_SERVICE_NOT_IN")),
    }

    show_flags = {
        "policyid": to_bool(data.get("SHOW_POLICYID"), True),
        "name": to_bool(data.get("SHOW_NAME"), True),
        "srcintf": to_bool(data.get("SHOW_SRCINTF"), True),
        "dstintf": to_bool(data.get("SHOW_DSTINTF"), True),
        "srcaddr": to_bool(data.get("SHOW_SRCADDR"), True),
        "dstaddr": to_bool(data.get("SHOW_DSTADDR"), True),
        "service": to_bool(data.get("SHOW_SERVICE"), True),
        "action": to_bool(data.get("SHOW_ACTION"), True),
        "status": to_bool(data.get("SHOW_STATUS"), True),
        "schedule": to_bool(data.get("SHOW_SCHEDULE"), False),
        "logtraffic": to_bool(data.get("SHOW_LOGTRAFFIC"), False),
    }

    return AppConfig(
        token=token,
        base_url=base_url.rstrip("/"),
        vdom=to_str(data.get("FGT_VDOM")),
        verify_tls=verify_tls,
        timeout_seconds=timeout_seconds,
        server_filter=to_str(data.get("FGT_SERVER_FILTER")),
        output_dir=to_str(data.get("OUTPUT_DIR")) or "./output",
        output_max_col_width=output_max_col_width,
        filters=filters,
        show_flags=show_flags,
        debug=to_bool(data.get("DEBUG"), False),
        debug_response_keys=to_bool(data.get("DEBUG_RESPONSE_KEYS"), True),
        debug_results_type=to_bool(data.get("DEBUG_RESULTS_TYPE"), True),
        export_csv=to_bool(data.get("EXPORT_CSV"), True),
        csv_filename=to_str(data.get("CSV_FILENAME")),
        print_console=to_bool(data.get("PRINT_CONSOLE"), False),
    )
