"""
SOAR Evidence Bridge — every SOAR action generates an EvidenceRecord.
Closes the security-action-to-compliance-evidence loop.
"""

import os
import json
import urllib.request
from datetime import datetime, timezone
from typing import Optional

from soc.evidence_store import EvidenceRecord, EvidenceStore, hash_raw_log

SOAR_DRY_RUN = os.getenv("SOAR_DRY_RUN", "true").lower() == "true"

# ─────────────────────────────────────────────
# SOAR Action → Framework Control Mapping
# ─────────────────────────────────────────────
SOAR_ACTION_CONTROL_MAP: dict[str, dict] = {
    "cloudflare_block_ip": {
        "nca_control": "NCA-2.3.1",
        "iso_control": "A.8.20",
        "framework": "NCA_ECC_2.0",
        "finding_summary_template": "Malicious IP {ip} blocked via Cloudflare WAF rule {rule_id}",
    },
    "cloudflare_under_attack_mode": {
        "nca_control": "NCA-2.3.2",
        "iso_control": "A.8.20",
        "framework": "NCA_ECC_2.0",
        "finding_summary_template": "Cloudflare Under Attack Mode activated for zone {zone_id}",
    },
    "patch_advisory_sent": {
        "nca_control": "NCA-2.2.1",
        "iso_control": "A.8.8",
        "framework": "NCA_ECC_2.0",
        "finding_summary_template": "Patch advisory sent for CVE {cve_id} on {host}",
    },
    "email_security_enforced": {
        "nca_control": "NCA-3.4.1",
        "iso_control": "A.8.20",
        "framework": "NCA_ECC_2.0",
        "finding_summary_template": "Email security policy enforced: {action} for {domain}",
    },
    "account_locked": {
        "nca_control": "NCA-2.4.1",
        "iso_control": "A.8.3",
        "framework": "NCA_ECC_2.0",
        "finding_summary_template": "Account {account} locked after {attempts} failed attempts",
    },
}


class SafetyGuard:
    """
    ABSOLUTE safety constraints on SOAR actions.
    These rules cannot be overridden by any configuration.
    """

    # RFC1918 ranges — NEVER block
    RFC1918_PREFIXES = (
        "10.", "172.16.", "172.17.", "172.18.", "172.19.",
        "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
        "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
        "172.30.", "172.31.", "192.168.",
    )

    # Cloudflare CDN IP ranges — NEVER block
    CLOUDFLARE_PREFIXES = (
        "103.21.244.", "103.22.200.", "103.31.4.", "104.16.",
        "104.17.", "104.18.", "104.19.", "108.162.", "141.101.",
        "162.158.", "172.64.", "172.65.", "172.66.", "172.67.",
        "173.245.", "188.114.", "190.93.", "197.234.", "198.41.",
    )

    @classmethod
    def is_safe_to_block(cls, ip: str, client_whitelist: set[str]) -> tuple[bool, str]:
        """
        Returns (safe, reason). Safe=False means DO NOT BLOCK.
        """
        # RFC1918 check
        for prefix in cls.RFC1918_PREFIXES:
            if ip.startswith(prefix):
                return False, f"RFC1918 address — internal IP, never block: {ip}"

        # Cloudflare CDN check
        for prefix in cls.CLOUDFLARE_PREFIXES:
            if ip.startswith(prefix):
                return False, f"Cloudflare CDN IP — never block: {ip}"

        # Client whitelist check
        if ip in client_whitelist:
            return False, f"Client whitelisted IP — never block: {ip}"

        return True, "Safe to block"

    @classmethod
    def validate_soar_action(
        cls, action: str, params: dict, client_whitelist: set[str]
    ) -> tuple[bool, str]:
        """Validate any SOAR action before execution."""

        # DNS findings — notify only, never block
        if params.get("source") == "dns_finding":
            return False, "DNS findings are NOTIFY_ONLY — never execute block"

        # Malware — escalate to human, never auto-block
        if params.get("alert_type") in {"malware", "ransomware"}:
            return False, "Malware/ransomware findings require human escalation"

        # IP block safety check
        if action == "cloudflare_block_ip":
            ip = params.get("ip", "")
            return cls.is_safe_to_block(ip, client_whitelist)

        return True, "Action validated"


def execute_soar_action_with_evidence(
    action: str,
    params: dict,
    client_id: str,
    scan_id: str,
    store: EvidenceStore,
    client_whitelist: Optional[set[str]] = None,
) -> Optional[EvidenceRecord]:
    """
    Execute SOAR action (if DRY_RUN=false and SafetyGuard passes).
    Always generates EvidenceRecord regardless of DRY_RUN status.
    """
    if client_whitelist is None:
        client_whitelist = set()

    # SafetyGuard check — ALWAYS runs, even in dry run
    safe, safety_reason = SafetyGuard.validate_soar_action(action, params, client_whitelist)
    if not safe:
        print(f"🛡️ SafetyGuard BLOCKED: {action} — {safety_reason}")
        return None

    # Get control mapping
    control_map = SOAR_ACTION_CONTROL_MAP.get(action)
    if not control_map:
        print(f"⚠️ No control mapping for action: {action}")
        return None

    # Build finding summary from template
    try:
        finding_summary = control_map["finding_summary_template"].format(**params)
    except KeyError:
        finding_summary = f"SOAR action executed: {action}"

    # Execute (only if DRY_RUN=false)
    external_anchor = None
    if not SOAR_DRY_RUN:
        external_anchor = _execute_action(action, params)
        print(f"✅ SOAR action executed: {action} — anchor: {external_anchor}")
    else:
        print(f"🔵 DRY RUN: Would execute {action} with params: {params}")
        external_anchor = f"DRY_RUN_{action}_{datetime.now(timezone.utc).timestamp()}"

    # Always generate evidence record
    record = EvidenceRecord(
        control_id=control_map["nca_control"],
        framework=control_map["framework"],
        client_id=client_id,
        scan_id=scan_id,
        status="PASS" if not SOAR_DRY_RUN else "PARTIAL",
        finding_summary=finding_summary + (" [DRY RUN]" if SOAR_DRY_RUN else ""),
        source="cloudflare" if "cloudflare" in action else "soar",
        event_id=str(external_anchor or f"{action}_{scan_id}"),
        raw_log_hash=hash_raw_log(str(params)),
        timestamp=datetime.now(timezone.utc).isoformat(),
        origin="remote",
    )

    return store.append(record)


def _execute_action(action: str, params: dict) -> Optional[str]:
    """
    Execute actual SOAR action against live systems.
    Returns external anchor ID from the action.
    """
    cf_token = os.getenv("CF_API_TOKEN")
    cf_zone = os.getenv("CF_ZONE_ID")

    if action == "cloudflare_block_ip":
        ip = params.get("ip")
        if not ip or not cf_token or not cf_zone:
            return None

        payload = json.dumps({
            "mode": "block",
            "configuration": {"target": "ip", "value": ip},
            "notes": f"SOC Root automated block — scan {params.get('scan_id', 'N/A')}",
        }).encode()

        req = urllib.request.Request(
            f"https://api.cloudflare.com/client/v4/zones/{cf_zone}/firewall/access_rules/rules",
            data=payload,
            headers={
                "Authorization": f"Bearer {cf_token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )

        with urllib.request.urlopen(req) as resp:
            result = json.loads(resp.read())
            if result.get("success"):
                return result.get("result", {}).get("id")

    elif action == "cloudflare_under_attack_mode":
        zone_id = params.get("zone_id") or cf_zone
        if not zone_id or not cf_token:
            return None

        payload = json.dumps({
            "value": "under_attack",
        }).encode()

        req = urllib.request.Request(
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/settings/security_level",
            data=payload,
            headers={
                "Authorization": f"Bearer {cf_token}",
                "Content-Type": "application/json",
            },
            method="PATCH",
        )

        with urllib.request.urlopen(req) as resp:
            result = json.loads(resp.read())
            if result.get("success"):
                return f"under_attack_mode_{zone_id}"

    return None
