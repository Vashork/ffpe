"""
FortiGate REST API client using requests.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning


class FortiGateClient:
    def __init__(self, base_url: str, token: str, verify_tls: bool, timeout: int) -> None:
        self.base_url = base_url.rstrip("/")
        self.verify_tls = verify_tls
        self.timeout = timeout

        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
            }
        )

        if not self.verify_tls:
            requests.packages.urllib3.disable_warnings(
                category=InsecureRequestWarning
            )

    def get(
            self,
            path: str,
            params: Optional[Dict[str, Any]] = None,
            debug: bool = False,
    ) -> Dict[str, Any]:
        url = f"{self.base_url}{path}"
        params = params or {}

        if debug:
            req = requests.Request("GET", url, params=params)
            prepped = self.session.prepare_request(req)
            print(f"[DEBUG] GET {prepped.url}")
            print(f"[DEBUG] TLS verify = {self.verify_tls}")

        try:
            resp = self.session.get(
                url,
                params=params,
                timeout=self.timeout,
                verify=self.verify_tls,
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise RuntimeError(f"HTTP request failed for {url}: {exc}") from exc

        if debug:
            print(f"[DEBUG] HTTP {resp.status_code}")
            print(f"[DEBUG] Content-Type: {resp.headers.get('Content-Type')}")

        try:
            return resp.json()
        except json.JSONDecodeError as exc:
            snippet = resp.text[:800] if resp.text else ""
            raise RuntimeError(
                f"Invalid JSON response from {url}: {exc}. Body: {snippet}"
            ) from exc
