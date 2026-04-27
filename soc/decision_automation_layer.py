"""
Decision Automation Layer (DAL)
3-tier alert triage: auto-close, auto-remediate, human escalation.
Reduces human alert review time at scale.
"""

import logging
import os
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Callable, Optional

logger = logging.getLogger(__name__)

SOAR_DRY_RUN = os.getenv("SOAR_DRY_RUN", "true").lower() == "true"


class Tier(IntEnum):
    AUTO_CLOSE = 1       # Benign — log only, no notification
    AUTO_REMEDIATE = 2   # Known pattern — execute playbook + notify
    HUMAN_ESCALATE = 3   # Novel/critical — immediate human review


@dataclass
class AlertDecision:
    tier: Tier
    action: str                          # "auto_close" | "auto_remediate" | "escalate_human"
    reason: str
    notify_telegram: bool
    confidence_used: float
    severity_used: str
    dry_run_blocked: bool = False        # True if Tier 2 blocked by DRY_RUN


# ─────────────────────────────────────────────
# Known Benign Patterns
# Populate from first 30 days of real alerts
# Each pattern: (name, predicate(alert) -> bool)
# ─────────────────────────────────────────────

ADMIN_IPS: set[str] = set(os.getenv("ADMIN_IPS", "").split(",")) - {""}
KNOWN_SCANNER_IPS: set[str] = set(os.getenv("SCANNER_IPS", "").split(",")) - {""}

KNOWN_BENIGN_PATTERNS: dict[str, Callable[[dict], bool]] = {
    "scheduled_vuln_scan": lambda a: a.get("data", {}).get("srcip", "") in KNOWN_SCANNER_IPS,
    "health_check_ping": lambda a: "health check" in str(a.get("rule", {}).get("description", "")).lower(),
    "admin_ssh_known_ip": lambda a: (
        str(a.get("rule", {}).get("id")) == "5712"
        and a.get("data", {}).get("srcip", "") in ADMIN_IPS
    ),
    "wazuh_agent_heartbeat": lambda a: "wazuh" in str(a.get("agent", {}).get("name", "")).lower(),
}


def is_known_benign(alert: dict) -> tuple[bool, str]:
    """Check if alert matches any known benign pattern. Returns (matched, pattern_name)."""
    for pattern_name, predicate in KNOWN_BENIGN_PATTERNS.items():
        try:
            if predicate(alert):
                return True, pattern_name
        except Exception:
            continue
    return False, ""


def extract_alert_fields(alert: dict) -> tuple[float, str, bool, bool]:
    """
    Extract normalized fields from alert dict.
    Returns: (confidence, severity, is_critical_asset, is_novel_pattern)
    """
    confidence = float(alert.get("confidence", 0.5))
    severity = alert.get("severity", alert.get("rule", {}).get("level_label", "medium")).lower()
    is_critical_asset = bool(alert.get("critical_asset", False))
    is_novel_pattern = bool(alert.get("novel_pattern", False))
    return confidence, severity, is_critical_asset, is_novel_pattern


def classify_alert(alert: dict, dry_run: Optional[bool] = None) -> AlertDecision:
    """
    Classify alert into DAL tier.

    Tier 1 (Auto-Close):
        confidence >= 0.90 AND severity in {info, low} AND known benign pattern

    Tier 2 (Auto-Remediate):
        confidence >= 0.75 AND severity in {medium, high} AND NOT critical_asset AND NOT novel

    Tier 3 (Human Escalate):
        everything else, including all critical_asset and novel_pattern
    """
    if dry_run is None:
        dry_run = SOAR_DRY_RUN

    confidence, severity, is_critical_asset, is_novel_pattern = extract_alert_fields(alert)
    benign, benign_pattern = is_known_benign(alert)

    # Override rules — ABSOLUTE (see SAFETY_RULES.md)
    if is_critical_asset:
        return AlertDecision(
            tier=Tier.HUMAN_ESCALATE,
            action="escalate_human",
            reason="critical_asset override — always Tier 3",
            notify_telegram=True,
            confidence_used=confidence,
            severity_used=severity,
        )

    if is_novel_pattern:
        return AlertDecision(
            tier=Tier.HUMAN_ESCALATE,
            action="escalate_human",
            reason="novel_pattern override — always Tier 3",
            notify_telegram=True,
            confidence_used=confidence,
            severity_used=severity,
        )

    # Tier 1: Auto-Close
    if confidence >= 0.90 and severity in {"info", "low"} and benign:
        return AlertDecision(
            tier=Tier.AUTO_CLOSE,
            action="auto_close",
            reason=f"Tier 1: confidence={confidence:.2f}, severity={severity}, pattern={benign_pattern}",
            notify_telegram=False,
            confidence_used=confidence,
            severity_used=severity,
        )

    # Tier 2: Auto-Remediate
    if confidence >= 0.75 and severity in {"medium", "high"}:
        blocked = dry_run
        return AlertDecision(
            tier=Tier.AUTO_REMEDIATE,
            action="auto_remediate",
            reason=f"Tier 2: confidence={confidence:.2f}, severity={severity}",
            notify_telegram=True,
            confidence_used=confidence,
            severity_used=severity,
            dry_run_blocked=blocked,
        )

    # Tier 3: Human Escalation
    return AlertDecision(
        tier=Tier.HUMAN_ESCALATE,
        action="escalate_human",
        reason=f"Tier 3: confidence={confidence:.2f} < 0.75 or severity={severity} not classified",
        notify_telegram=True,
        confidence_used=confidence,
        severity_used=severity,
    )
