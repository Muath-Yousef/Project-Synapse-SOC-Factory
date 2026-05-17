"""
TelegramConnector — Multi-channel Telegram alert delivery for SOCRoot.
Inherits from BaseConnector for standardized mock/retry/health behavior.
"""

import os
import logging
import requests
from datetime import datetime
from typing import Any, Dict

from dotenv import load_dotenv
from soc.connectors.base_connector import BaseConnector, ConnectorResult

logger = logging.getLogger(__name__)


class TelegramConnector(BaseConnector):
    """
    Sends alerts to multiple Telegram channels based on alert type.

    Channels:
        findings  → TELEGRAM_CHAT_ID_FINDINGS
        actions   → TELEGRAM_CHAT_ID_ACTIONS
        failures  → TELEGRAM_CHAT_ID_FAILURES

    Falls back to MOCK mode when TELEGRAM_BOT_TOKEN or all channels are missing.
    """

    CONNECTOR_NAME = "TelegramConnector"
    MAX_RETRIES = 3

    def __init__(self):
        load_dotenv()
        self.bot_token = os.getenv("TELEGRAM_BOT_TOKEN", "")
        self.channels = {
            "findings": os.getenv("TELEGRAM_CHAT_ID_FINDINGS", ""),
            "actions": os.getenv("TELEGRAM_CHAT_ID_ACTIONS", ""),
            "failures": os.getenv("TELEGRAM_CHAT_ID_FAILURES", ""),
        }
        super().__init__()   # triggers _is_configured() → mock detection
        channels_set = [k for k, v in self.channels.items() if v]
        logger.info(
            f"[TG-INIT] {datetime.now().isoformat()} | "
            f"Token: {'SET' if self.bot_token else 'MISSING'} | "
            f"Channels configured: {channels_set}"
        )

    def _is_configured(self) -> bool:
        return bool(
            self.bot_token
            and self.bot_token not in ("your_bot_token", "")
            and any(self.channels.values())
        )

    def _build_payload(self, **kwargs) -> Dict[str, Any]:
        """Accepts: message, channel."""
        channel = kwargs.get("channel", "findings")
        chat_id = self.channels.get(channel) or self.channels.get("findings", "")
        return {
            "message": kwargs.get("message", ""),
            "channel": channel,
            "chat_id": chat_id,
        }

    def _send_impl(self, payload: Dict[str, Any]) -> ConnectorResult:
        """POST the message to the Telegram Bot API."""
        message = payload["message"]
        channel = payload["channel"]
        chat_id = payload["chat_id"]
        ts = datetime.now().isoformat()

        if not chat_id:
            logger.warning(
                f"[TG-SKIP] {ts} | Channel '{channel}' has no chat_id configured"
            )
            return ConnectorResult(
                success=True, status="skipped",
                data={"reason": f"channel '{channel}' not configured"},
            )

        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        response = requests.post(
            url,
            json={"chat_id": chat_id, "text": message, "parse_mode": "HTML"},
            timeout=10,
        )
        response.raise_for_status()

        logger.info(
            f"[TG-OK] {datetime.now().isoformat()} | Channel: {channel} | "
            f"Status: {response.status_code}"
        )
        return ConnectorResult(
            success=True, status="sent",
            data={"channel": channel, "chat_id": chat_id[:6] + "..."},
        )

    def health_check(self) -> Dict[str, Any]:
        """Override: include channel configuration status."""
        base = super().health_check()
        base["channels"] = {k: bool(v) for k, v in self.channels.items()}
        return base

    # ── Legacy shim — keeps existing callers working ──────────────────────────
    def send(self, message: str = "", channel: str = "findings", **kwargs) -> bool:
        """
        Backwards-compatible shim: send(message, channel) → bool.
        Internal base.send() is called with kwargs; this wraps it.
        """
        result = super().send(message=message, channel=channel)
        if not result.success and not result.mock:
            # Attempt failure notification (best-effort, no recursion)
            self._notify_failure(f"Telegram send failed for #{channel}: {result.error}")
        return result.success or result.mock

    def _notify_failure(self, error_msg: str):
        """Best-effort failure notification to the failures channel."""
        fail_chat = self.channels.get("failures", "")
        if not fail_chat or not self.bot_token:
            return
        try:
            requests.post(
                f"https://api.telegram.org/bot{self.bot_token}/sendMessage",
                json={
                    "chat_id": fail_chat,
                    "text": (
                        f"⚠️ SYSTEM FAILURE\n{error_msg}\n"
                        f"Time: {datetime.now().isoformat()}"
                    ),
                },
                timeout=5,
            )
        except Exception:
            pass  # Last resort — don't recurse
