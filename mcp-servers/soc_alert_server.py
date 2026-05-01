"""
SOC Alert MCP Server
====================
Exposes Wazuh/SIEM alert ingestion as MCP tools callable by the agentic engine.
Provides: ingest_alert, list_active_alerts, get_alert_detail, dismiss_alert
"""
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastmcp import FastMCP

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("soc-alert-server")

mcp = FastMCP("soc-alert-server")

# In-memory store (replace with Redis/DB in production)
_alerts: Dict[str, Dict] = {}

SEVERITY_MAP = {
    range(1, 4):  "low",
    range(4, 7):  "medium",
    range(7, 10): "high",
    range(10, 16): "critical",
}


def _classify(level: int) -> str:
    for r, sev in SEVERITY_MAP.items():
        if level in r:
            return sev
    return "unknown"


@mcp.tool()
async def ingest_alert(
    rule_id: str,
    rule_level: int,
    description: str,
    agent_id: str,
    agent_name: str,
    src_ip: Optional[str] = None,
    user: Optional[str] = None,
    raw_data: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Ingest a security alert from Wazuh or any SIEM.
    Returns alert_id and severity classification.
    """
    alert_id = str(uuid.uuid4())[:8].upper()
    severity = _classify(rule_level)

    alert = {
        "alert_id": alert_id,
        "rule_id": rule_id,
        "rule_level": rule_level,
        "severity": severity,
        "description": description,
        "agent": {"id": agent_id, "name": agent_name},
        "src_ip": src_ip,
        "user": user,
        "raw_data": raw_data,
        "status": "open",
        "ingested_at": datetime.now(timezone.utc).isoformat(),
    }
    _alerts[alert_id] = alert

    logger.info(f"[INGEST] {alert_id} | {severity.upper()} | {description[:60]}")
    return {"alert_id": alert_id, "severity": severity, "status": "accepted"}


@mcp.tool()
async def list_active_alerts(
    severity_filter: Optional[str] = None,
    limit: int = 20,
) -> List[Dict[str, Any]]:
    """
    List all open alerts, optionally filtered by severity (low/medium/high/critical).
    """
    alerts = [a for a in _alerts.values() if a["status"] == "open"]
    if severity_filter:
        alerts = [a for a in alerts if a["severity"] == severity_filter.lower()]
    alerts.sort(key=lambda x: x["rule_level"], reverse=True)
    return alerts[:limit]


@mcp.tool()
async def get_alert_detail(alert_id: str) -> Dict[str, Any]:
    """
    Get full detail for a specific alert by ID.
    """
    alert = _alerts.get(alert_id.upper())
    if not alert:
        return {"error": f"Alert {alert_id} not found"}
    return alert


@mcp.tool()
async def dismiss_alert(alert_id: str, reason: str = "false_positive") -> Dict[str, Any]:
    """
    Dismiss an alert with a reason. Updates status to 'dismissed'.
    """
    alert = _alerts.get(alert_id.upper())
    if not alert:
        return {"error": f"Alert {alert_id} not found"}
    alert["status"] = "dismissed"
    alert["dismissed_reason"] = reason
    alert["dismissed_at"] = datetime.now(timezone.utc).isoformat()
    logger.info(f"[DISMISS] {alert_id} — reason: {reason}")
    return {"alert_id": alert_id, "status": "dismissed"}


if __name__ == "__main__":
    mcp.run(transport="stdio")
