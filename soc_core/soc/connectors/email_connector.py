"""
EmailConnector — SMTP email delivery for SOCRoot reports and alerts.
Inherits from BaseConnector for standardized mock/retry/health behavior.
"""

import smtplib
import os
import logging
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any, Dict

from soc.connectors.base_connector import BaseConnector, ConnectorResult

logger = logging.getLogger(__name__)


class EmailConnector(BaseConnector):
    """
    Sends reports and alerts via SMTP.
    Configured via: SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, SMTP_FROM.
    Falls back to MOCK mode when credentials are missing.
    """

    CONNECTOR_NAME = "EmailConnector"
    MAX_RETRIES = 2      # SMTP failures rarely recover on retry

    def __init__(self):
        self.host = os.getenv("SMTP_HOST", "")
        self.port = int(os.getenv("SMTP_PORT", "587"))
        self.user = os.getenv("SMTP_USER", "")
        self.password = os.getenv("SMTP_PASSWORD", "")
        self.from_addr = os.getenv("SMTP_FROM", self.user)
        super().__init__()   # triggers mock detection via _is_configured()

    def _is_configured(self) -> bool:
        return bool(self.host and self.user and self.password)

    def _build_payload(self, **kwargs) -> Dict[str, Any]:
        """Accepts: to, subject, body, attachment_path."""
        return {
            "to": kwargs.get("to", ""),
            "subject": kwargs.get("subject", ""),
            "body": kwargs.get("body", ""),
            "attachment_path": kwargs.get("attachment_path"),
        }

    def _send_impl(self, payload: Dict[str, Any]) -> ConnectorResult:
        """Build and dispatch the SMTP email."""
        to = payload["to"]
        subject = payload["subject"]
        body = payload["body"]
        attachment_path = payload.get("attachment_path")

        msg = MIMEMultipart()
        msg["From"] = self.from_addr
        msg["To"] = to
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        if attachment_path and Path(attachment_path).exists():
            with open(attachment_path, "rb") as f:
                part = MIMEBase("application", "octet-stream")
                part.set_payload(f.read())
            encoders.encode_base64(part)
            part.add_header(
                "Content-Disposition",
                f"attachment; filename={Path(attachment_path).name}",
            )
            msg.attach(part)

        with smtplib.SMTP(self.host, self.port) as server:
            server.starttls()
            server.login(self.user, self.password)
            server.send_message(msg)

        logger.info(f"[EmailConnector] Report sent → {to} | Subject: {subject}")
        return ConnectorResult(
            success=True, status="sent", data={"to": to, "subject": subject}
        )

    # ── Legacy shim — keeps existing callers working ──────────────────────────
    def send_report(
        self,
        to: str,
        subject: str,
        body: str,
        attachment_path: str = None,
    ) -> dict:
        """
        Backwards-compatible wrapper for main_orchestrator.py callers.
        Prefer using send(to=..., subject=..., body=...) directly.
        """
        result = self.send(
            to=to, subject=subject, body=body, attachment_path=attachment_path
        )
        return result.to_dict()
