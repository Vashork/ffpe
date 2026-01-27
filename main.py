#!/usr/bin/env python3
"""
Entrypoint for fetching and exporting FortiGate firewall policies.
"""

from fgpol.config import load_config
from fgpol.client import FortiGateClient
from fgpol.fortios import extract_results
from fgpol.filters import apply_filters
from fgpol.fields import compute_columns
from fgpol.table import print_table
from fgpol.exporters import ensure_output_dir, export_csv


def main() -> int:
    try:
        cfg = load_config(".env")
        ensure_output_dir(cfg.output_dir)

        client = FortiGateClient(
            base_url=cfg.base_url,
            token=cfg.token,
            verify_tls=cfg.verify_tls,
            timeout=cfg.timeout_seconds,
        )

        payload = client.get(
            "/cmdb/firewall/policy",
            params=cfg.to_query_params(),
            debug=cfg.debug,
        )

        policies = extract_results(payload)
        if not policies:
            print("No policies returned.")
            return 0

        filtered = apply_filters(policies, cfg.filters)
        columns = compute_columns(cfg.show_flags)

        if not filtered:
            print("No policies matched filters.")
            return 0

        # --- CSV export ---
        if cfg.export_csv:
            csv_path = export_csv(
                rows=filtered,
                columns=columns,
                output_dir=cfg.output_dir,
                filename=cfg.csv_filename,
            )
            print(f"CSV exported: {csv_path}")

        # --- Optional console output ---
        if cfg.print_console:
            print_table(filtered, columns, max_width=cfg.output_max_col_width)

        return 0

    except Exception as exc:
        print(f"Error: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
