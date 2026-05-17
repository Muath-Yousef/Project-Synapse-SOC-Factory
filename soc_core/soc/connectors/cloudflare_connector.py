"""
CloudflareConnector — Firewall rule management via Cloudflare API.
Inherits from BaseConnector for standardized mock/retry/health behavior.
"""

import os
import logging
import requests
from typing import Any, Dict

from dotenv import load_dotenv
from soc.connectors.base_connector import BaseConnector, ConnectorResult

logger = logging.getLogger(__name__)


class CloudflareConnector(BaseConnector):
    """
    Manages Cloudflare firewall rules via Zone-level API.

    Note: Free tier is limited to 5 active rules.
    Configured via: CF_API_TOKEN, CF_ZONE_ID.
    Falls back to MOCK mode when credentials are missing.
    """

    CONNECTOR_NAME = "CloudflareConnector"
    CF_API = "https://api.cloudflare.com/client/v4"
    MAX_RETRIES = 3

    def __init__(self):
        load_dotenv()
        self.token = os.getenv("CF_API_TOKEN", "")
        self.zone_id = os.getenv("CF_ZONE_ID", "")
        self._headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }
        super().__init__()   # triggers _is_configured() → mock detection

    def _is_configured(self) -> bool:
        return bool(
            self.token
            and self.zone_id
            and self.token not in ("your_cf_api_token_here", "")
        )

    def _build_payload(self, **kwargs) -> Dict[str, Any]:
        """Accepts: ip, reason, mode."""
        return {
            "ip": kwargs.get("ip", ""),
            "reason": kwargs.get("reason", "SOCRoot auto-block")[:100],
            "mode": kwargs.get("mode", "block"),
        }

    def _send_impl(self, payload: Dict[str, Any]) -> ConnectorResult:
        """Create a Cloudflare firewall access rule."""
        ip = payload["ip"]
        reason = payload["reason"]
        mode = payload["mode"]

        endpoint = (
            f"{self.CF_API}/zones/{self.zone_id}/firewall/access_rules/rules"
        )
        body = {
            "mode": mode,
            "configuration": {"target": "ip", "value": ip},
            "notes": reason,
        }
        response = requests.post(
            endpoint, headers=self._headers, json=body, timeout=10
        )
        response.raise_for_status()
        data = response.json()

        logger.info(
            f"[CloudflareConnector] IP {ip} {mode}ed | Reason: {reason}"
        )
        return ConnectorResult(
            success=True, status="blocked",
            data={"ip": ip, "mode": mode, "cf_response": data},
        )

    def health_check(self) -> Dict[str, Any]:
        """Override: verify zone ID is reachable."""
        base = super().health_check()
        if self._mock:
            return base
        try:
            url = f"{self.CF_API}/zones/{self.zone_id}"
            resp = requests.get(url, headers=self._headers, timeout=5)
            resp.raise_for_status()
            base["zone_status"] = "reachable"
            base["zone_name"] = resp.json().get("result", {}).get("name", "unknown")
        except Exception as e:
            base["zone_status"] = "error"
            base["zone_error"] = str(e)
        return base

    # ── Legacy shim — keeps existing SOAR callers working ────────────────────
    def block_ip(self, ip: str, reason: str) -> dict:
        """
        Backwards-compatible wrapper for SOAR action callers.
        Prefer using send(ip=..., reason=...) directly.
        """
        result = self.send(ip=ip, reason=reason, mode="block")
        return result.to_dict()
