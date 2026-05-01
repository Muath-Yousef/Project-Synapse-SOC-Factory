"""
Wazuh Evidence Bridge — converts Wazuh JSON alerts to EvidenceRecords
Maps Wazuh rule IDs to NCA ECC 2.0 controls.
"""

from datetime import datetime, timezone
from typing import Optional

from soc.evidence_store import EvidenceRecord, EvidenceStore, hash_raw_log

# ─────────────────────────────────────────────
# NCA ECC 2.0 Control Mapping
# Wazuh rule_id (int) → (control_id, framework)
# Expand to full 114 controls as intelligence grows
# ─────────────────────────────────────────────
NCA_WAZUH_MAP: dict[int, tuple[str, str]] = {
    # SSH / Access Control
    5701: ("NCA-2.4.1", "NCA_ECC_2.0"),  # SSH login failure
    5710: ("NCA-3.1.1", "NCA_ECC_2.0"),  # SSH brute force
    5712: ("NCA-3.1.1", "NCA_ECC_2.0"),  # SSH login after multiple failures
    5716: ("NCA-2.4.1", "NCA_ECC_2.0"),  # SSH login error
    5720: ("NCA-3.1.1", "NCA_ECC_2.0"),  # Multiple authentication failures
    5760: ("NCA-3.1.1", "NCA_ECC_2.0"),  # SSH authentication failure

    # Web Attacks
    31101: ("NCA-2.3.1", "NCA_ECC_2.0"),  # SQL injection
    31103: ("NCA-2.3.1", "NCA_ECC_2.0"),  # XSS
    31104: ("NCA-2.3.1", "NCA_ECC_2.0"),  # Path traversal
    31151: ("NCA-2.3.1", "NCA_ECC_2.0"),  # Command injection

    # Network Security
    100002: ("NCA-2.1.3", "NCA_ECC_2.0"),  # Cleartext HTTP
    80100: ("NCA-2.2.1", "NCA_ECC_2.0"),   # Port scan
    80101: ("NCA-2.2.1", "NCA_ECC_2.0"),   # Port scan high volume

    # Malware
    87003: ("NCA-2.5.1", "NCA_ECC_2.0"),  # Malware detected
    510: ("NCA-2.5.1", "NCA_ECC_2.0"),    # Rootkit detection
    511: ("NCA-2.5.1", "NCA_ECC_2.0"),    # Rootkit evidence

    # System Integrity
    550: ("NCA-3.2.1", "NCA_ECC_2.0"),   # Integrity check failed
    553: ("NCA-3.2.1", "NCA_ECC_2.0"),   # File modified
    554: ("NCA-3.2.1", "NCA_ECC_2.0"),   # File added to system

    # Email Security
    200100: ("NCA-3.4.1", "NCA_ECC_2.0"),  # Missing SPF
    200101: ("NCA-3.4.1", "NCA_ECC_2.0"),  # Missing DMARC
    200102: ("NCA-3.4.1", "NCA_ECC_2.0"),  # Missing DKIM

    # Vulnerability / Patch
    23001: ("NCA-2.2.1", "NCA_ECC_2.0"),  # Outdated software
    23002: ("NCA-2.2.1", "NCA_ECC_2.0"),  # Critical CVE detected
}

SEVERITY_MAP: dict[str, str] = {
    "critical": "FAIL",
    "high": "FAIL",
    "medium": "PARTIAL",
    "low": "PARTIAL",
    "info": "PASS",
}


def extract_rule_id(alert: dict) -> Optional[int]:
    """Extract Wazuh rule ID from alert JSON."""
    try:
        rule_id = alert.get("rule", {}).get("id")
        if rule_id is not None:
            return int(rule_id)
    except (ValueError, TypeError):
        pass
    return None


def extract_severity(alert: dict) -> str:
    """Extract severity from Wazuh alert level (1-15 → severity string)."""
    level = alert.get("rule", {}).get("level", 0)
    try:
        level = int(level)
    except (ValueError, TypeError):
        return "info"

    if level >= 13:
        return "critical"
    elif level >= 10:
        return "high"
    elif level >= 7:
        return "medium"
    elif level >= 4:
        return "low"
    return "info"


def build_finding_summary(alert: dict, control_id: str) -> str:
    """
    Build audit-facing finding summary in non-technical language.
    Must be understandable by auditors, not just engineers.
    """
    description = alert.get("rule", {}).get("description", "Security event detected")
    agent = alert.get("agent", {}).get("name", "unknown host")
    src_ip = alert.get("data", {}).get("srcip", "")

    summary = f"[{control_id}] {description} on {agent}"
    if src_ip:
        summary += f" from {src_ip}"
    return summary


def wazuh_alert_to_evidence(
    alert: dict,
    client_id: str,
    scan_id: str,
    store: EvidenceStore,
) -> Optional[EvidenceRecord]:
    """
    Convert Wazuh JSON alert to EvidenceRecord and append to chain.

    Returns:
        EvidenceRecord if rule is mapped to NCA control, None if unmapped.
    """
    rule_id = extract_rule_id(alert)

    if rule_id is None or rule_id not in NCA_WAZUH_MAP:
        # Unmapped rule — do not create evidence record
        return None

    control_id, framework = NCA_WAZUH_MAP[rule_id]
    severity = extract_severity(alert)
    status = SEVERITY_MAP.get(severity, "PARTIAL")

    # External anchor — Wazuh internal alert ID
    event_id = alert.get("id") or alert.get("_id") or f"{scan_id}_{rule_id}_{datetime.now(timezone.utc).timestamp()}"

    raw_log_content = str(alert)  # Full alert JSON as string for hashing

    record = EvidenceRecord(
        control_id=control_id,
        framework=framework,
        client_id=client_id,
        scan_id=scan_id,
        status=status,
        finding_summary=build_finding_summary(alert, control_id),
        source="wazuh",
        event_id=str(event_id),
        raw_log_hash=hash_raw_log(raw_log_content),
        timestamp=datetime.now(timezone.utc).isoformat(),
        origin="remote",
    )

    return store.append(record)


def process_wazuh_alert_batch(
    alerts: list[dict],
    client_id: str,
    scan_id: str,
    store: EvidenceStore,
) -> dict:
    """
    Process a batch of Wazuh alerts. Returns summary statistics.
    """
    mapped = 0
    skipped = 0

    for alert in alerts:
        result = wazuh_alert_to_evidence(alert, client_id, scan_id, store)
        if result is not None:
            mapped += 1
        else:
            skipped += 1

    return {
        "total": len(alerts),
        "mapped_to_nca": mapped,
        "skipped_unmapped": skipped,
        "client_id": client_id,
        "scan_id": scan_id,
    }
