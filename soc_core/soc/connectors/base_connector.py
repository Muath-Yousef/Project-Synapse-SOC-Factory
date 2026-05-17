"""
BaseConnector — Abstract base class for all SOCRoot output connectors.

Provides shared infrastructure for:
  - Mock mode detection (when credentials are missing)
  - Structured send() interface with retry logic
  - Health check interface
  - Standardized result dict format

All connectors must inherit from this class and implement:
  - _send_impl(payload: dict) -> dict
  - _build_payload(**kwargs) -> dict
  - _is_configured() -> bool

Usage:
    class EmailConnector(BaseConnector):
        def _is_configured(self): ...
        def _send_impl(self, payload): ...
        def _build_payload(self, **kwargs): ...
"""

import logging
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class ConnectorResult:
    """Standardized result wrapper for all connector operations."""

    def __init__(
        self,
        success: bool,
        status: str,
        mock: bool = False,
        error: Optional[str] = None,
        data: Optional[Dict] = None,
    ):
        self.success = success
        self.status = status       # "sent" | "mock" | "error" | "blocked" | ...
        self.mock = mock
        self.error = error
        self.data = data or {}

    def to_dict(self) -> Dict[str, Any]:
        result = {"success": self.success, "status": self.status, "mock": self.mock}
        if self.error:
            result["error"] = self.error
        if self.data:
            result.update(self.data)
        return result

    def __bool__(self):
        return self.success

    def __repr__(self):
        return f"ConnectorResult(status={self.status!r}, mock={self.mock}, error={self.error!r})"


class BaseConnector(ABC):
    """
    Abstract base for all SOCRoot connectors (Email, Telegram, Cloudflare).

    Subclasses implement _is_configured(), _build_payload(), and _send_impl().
    This base class handles: mock mode, retry logic, and logging.
    """

    # Subclasses can override these defaults
    MAX_RETRIES: int = 3
    RETRY_BACKOFF: float = 2.0    # seconds between retries
    CONNECTOR_NAME: str = "BaseConnector"

    def __init__(self):
        self._mock = not self._is_configured()
        if self._mock:
            logger.info(
                f"[{self.CONNECTOR_NAME}] MOCK mode — credentials not configured"
            )

    @abstractmethod
    def _is_configured(self) -> bool:
        """Return True if this connector has all required credentials."""

    @abstractmethod
    def _build_payload(self, **kwargs) -> Dict[str, Any]:
        """Build the provider-specific payload dict from caller arguments."""

    @abstractmethod
    def _send_impl(self, payload: Dict[str, Any]) -> ConnectorResult:
        """
        Execute the actual send operation.
        Must return a ConnectorResult.
        Should raise exceptions on failure (base class handles retry).
        """

    def send(self, **kwargs) -> ConnectorResult:
        """
        Public send interface with mock detection, retry logic, and logging.
        Passes all kwargs to _build_payload() then calls _send_impl().
        """
        payload = self._build_payload(**kwargs)

        if self._mock:
            logger.info(
                f"[{self.CONNECTOR_NAME}][MOCK] send() called — "
                f"payload keys: {list(payload.keys())}"
            )
            return ConnectorResult(
                success=True, status="mock", mock=True,
                data={"payload_preview": {k: str(v)[:80] for k, v in payload.items()}},
            )

        last_error: Optional[Exception] = None
        for attempt in range(1, self.MAX_RETRIES + 1):
            try:
                result = self._send_impl(payload)
                logger.info(
                    f"[{self.CONNECTOR_NAME}] send() succeeded on attempt {attempt}"
                )
                return result
            except Exception as exc:
                last_error = exc
                wait = self.RETRY_BACKOFF * attempt
                logger.warning(
                    f"[{self.CONNECTOR_NAME}] send() attempt {attempt}/{self.MAX_RETRIES} "
                    f"failed: {exc}. Retrying in {wait}s..."
                )
                if attempt < self.MAX_RETRIES:
                    time.sleep(wait)

        logger.error(
            f"[{self.CONNECTOR_NAME}] send() failed after {self.MAX_RETRIES} attempts. "
            f"Last error: {last_error}"
        )
        return ConnectorResult(
            success=False, status="error", error=str(last_error)
        )

    def health_check(self) -> Dict[str, Any]:
        """
        Non-destructive health check.
        Subclasses can override for provider-specific checks.
        Default implementation just reports mock/live state.
        """
        return {
            "connector": self.CONNECTOR_NAME,
            "configured": not self._mock,
            "mock_mode": self._mock,
            "max_retries": self.MAX_RETRIES,
        }
