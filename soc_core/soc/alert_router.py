from dataclasses import dataclass
from typing import List, Optional, Dict, Any
import logging
import os
from soc.playbooks.base_playbook import ActionType
from soc.decision_automation_layer import classify_alert, Tier, AlertDecision, SOAR_DRY_RUN
from soc.audit_log import log_dal_decision

logger = logging.getLogger(__name__)

@dataclass
class AlertContext:
    client_id: str
    target_ip: str
    finding_type: str       # "cleartext_http" | "default_ssh" | "cve"
    severity: str           # "critical" | "high" | "medium" | "low"
    cve_id: Optional[str]   # None إذا لم يكن CVE
    source_tool: str        # "nmap" | "nuclei" | "aggregated"
    raw_finding: dict

class AlertRouter:
    """
    Routing logic:
    - Critical + web-facing → auto-block + notify
    - High CVE              → notify + patch advisory
    - Medium infra          → notify only + ticket
    - Low                   → log only
    
    Failure mode: إذا فشل الـ Cloudflare API،
    يجب أن يُسجّل الـ failure ويُرسل Telegram alert
    بدلاً من الصمت — silent failure في SOAR أخطر من الـ finding نفسه.
    """

    ROUTING_TABLE = {
        ("critical", "cleartext_http")   : [ActionType.BLOCK_IP, ActionType.ESCALATE_HUMAN],
        ("critical", "cve")              : [ActionType.BLOCK_IP, ActionType.NOTIFY_ONLY],
        ("high",     "cve")              : [ActionType.NOTIFY_ONLY, ActionType.PATCH_ADVISORY],
        ("high",     "default_ssh")      : [ActionType.NOTIFY_ONLY],
        ("medium",   "default_ssh")      : [ActionType.NOTIFY_ONLY],
        ("high",     "dns_dmarc")        : [ActionType.NOTIFY_ONLY, ActionType.PATCH_ADVISORY],
        ("medium",   "dns_dmarc")        : [ActionType.NOTIFY_ONLY],
        ("low",      "dns_dmarc")        : [ActionType.NOTIFY_ONLY],
        ("high",     "dns_spf")          : [ActionType.NOTIFY_ONLY, ActionType.PATCH_ADVISORY],
        ("medium",   "dns_spf")          : [ActionType.NOTIFY_ONLY],
        ("low",      "dns_spf")          : [ActionType.NOTIFY_ONLY],
        ("high",     "dns_missing_dkim") : [ActionType.NOTIFY_ONLY, ActionType.PATCH_ADVISORY],
        ("medium",   "dns_missing_dkim") : [ActionType.NOTIFY_ONLY],
        ("low",      "dns_missing_dkim") : [ActionType.NOTIFY_ONLY],
        ("high",     "ip_reputation")    : [ActionType.NOTIFY_ONLY],
        ("medium",   "ip_reputation")    : [ActionType.NOTIFY_ONLY],
        # Phase 22: DNS finding variants from DNSTool
        ("high",     "dns_spf_missing")       : [ActionType.NOTIFY_ONLY, ActionType.PATCH_ADVISORY],
        ("medium",   "dns_spf_missing")       : [ActionType.NOTIFY_ONLY],
        ("low",      "dns_spf_missing")       : [ActionType.NOTIFY_ONLY],
        ("high",     "dns_dmarc_missing")     : [ActionType.NOTIFY_ONLY, ActionType.PATCH_ADVISORY],
        ("medium",   "dns_dmarc_missing")     : [ActionType.NOTIFY_ONLY],
        ("low",      "dns_dmarc_missing")     : [ActionType.NOTIFY_ONLY],
        ("high",     "dns_dkim_not_found")    : [ActionType.NOTIFY_ONLY, ActionType.PATCH_ADVISORY],
        ("medium",   "dns_dkim_not_found")    : [ActionType.NOTIFY_ONLY],
        ("low",      "dns_dkim_not_found")    : [ActionType.NOTIFY_ONLY],
        ("high",     "dns_bimi_missing")      : [ActionType.NOTIFY_ONLY],
        ("medium",   "dns_bimi_missing")      : [ActionType.NOTIFY_ONLY],
        ("low",      "dns_bimi_missing")      : [ActionType.NOTIFY_ONLY],
        ("info",     "dns_bimi_missing")      : [ActionType.NOTIFY_ONLY],
        ("high",     "cleartext_http")        : [ActionType.NOTIFY_ONLY, ActionType.PATCH_ADVISORY],
        ("medium",   "cleartext_http")        : [ActionType.NOTIFY_ONLY],
        ("low",      "cleartext_http")        : [ActionType.NOTIFY_ONLY],
        ("critical", "malware")              : [ActionType.ESCALATE_HUMAN],
        ("high",     "malware")              : [ActionType.ESCALATE_HUMAN],
        ("critical", "data_exfiltration")    : [ActionType.BLOCK_IP, ActionType.ESCALATE_HUMAN],
        ("high",     "data_exfiltration")    : [ActionType.BLOCK_IP, ActionType.ESCALATE_HUMAN],
        ("critical", "ransomware_precursor") : [ActionType.ESCALATE_HUMAN],
        ("high",     "ransomware_precursor") : [ActionType.ESCALATE_HUMAN],
    }

    def get_playbooks(self, client_name: str, config: Dict[str, Any], finding_type: str) -> List:
        """
        Returns instances of playbooks relevant to the finding_type.
        Late imports used to break circular dependencies.
        """
        # Late imports to ensure no cycle with AlertRouter
        from soc.playbooks.web_attack_playbook import WebAttackPlaybook
        from soc.playbooks.hardening_playbook import HardeningPlaybook
        from soc.playbooks.phishing_playbook import PhishingPlaybook

        playbooks = []
        if "web" in finding_type or "http" in finding_type:
            playbooks.append(WebAttackPlaybook(client_name, config))
        if "ssh" in finding_type or "service" in finding_type:
            playbooks.append(HardeningPlaybook(client_name, config))
        if "dns" in finding_type or "reputation" in finding_type:
            playbooks.append(PhishingPlaybook(client_name, config))
            
        return playbooks

    def route(self, alert: AlertContext) -> List[ActionType]:
        key = (alert.severity.lower(), alert.finding_type.lower())
        
        # Enrich with GeoIP for external IPs
        geo_info = self._enrich_geoip(alert.target_ip)
        if geo_info:
            logger.info(f"[Router] GeoIP for {alert.target_ip}: {geo_info.get('country_name')} ({geo_info.get('org')})")
            alert.raw_finding["geoip"] = geo_info

        actions = self.ROUTING_TABLE.get(key)
        if not actions:
            logger.warning(f"[Router] No rule for {key} — defaulting to NOTIFY_ONLY")
            actions = [ActionType.NOTIFY_ONLY]
        logger.info(f"[Router] {alert.client_id} | {key} → {actions}")
        return actions

    def _enrich_geoip(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Enriches the alert with geographic data.
        Returns None for internal/private IPs.
        Returns a dict (possibly with empty fields if API fails) for external IPs.
        Uses ipapi.co as primary, ip-api.com as fallback.
        """
        import ipaddress, requests
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback:
                return None
        except ValueError:
            pass  # Not a valid IP, treat as external

        # Primary: ipapi.co (free tier)
        try:
            r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5)
            if r.status_code == 200:
                data = r.json()
                if not data.get("error"):
                    return {
                        "country": data.get("country_code"),
                        "country_name": data.get("country_name"),
                        "city": data.get("city"),
                        "org": data.get("org"),
                        "isp": data.get("isp")
                    }
        except Exception as e:
            logger.warning(f"[Router] GeoIP primary (ipapi.co) failed for {ip}: {e}")

        # Fallback: ip-api.com (free, no key)
        try:
            r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,org,isp", timeout=5)
            if r.status_code == 200:
                data = r.json()
                if data.get("status") == "success":
                    return {
                        "country": data.get("countryCode"),
                        "country_name": data.get("country"),
                        "city": data.get("city"),
                        "org": data.get("org"),
                        "isp": data.get("isp")
                    }
        except Exception as e:
            logger.error(f"[Router] GeoIP fallback (ip-api.com) failed for {ip}: {e}")

        logger.warning(f"[Router] GeoIP unavailable for {ip} — returning empty geo record")
        return {"country": None, "country_name": None, "city": None, "org": None, "isp": None}


# Stubs for functions called in route_alert_with_dal
def execute_playbook(alert: dict):
    logger.info(f"Executing playbook for alert {alert.get('id')}")

def send_telegram_notify(alert: dict, decision: AlertDecision, client_id: str):
    logger.info(f"Telegram Notification: Tier 2 alert {alert.get('id')} for {client_id}")

def send_telegram_immediate(alert: dict, decision: AlertDecision, client_id: str):
    logger.warning(f"Telegram IMMEDIATE Escalation: Tier 3 alert {alert.get('id')} for {client_id}")

def route_alert_with_dal(alert: dict, client_id: str) -> AlertDecision:
    """
    Main entry point: classify alert via DAL, route to appropriate action.
    All decisions are logged to audit_log for compliance evidence.
    """
    decision = classify_alert(alert, dry_run=SOAR_DRY_RUN)

    # Log to audit_log — every decision, regardless of tier
    log_dal_decision(
        client_id=client_id,
        alert_id=alert.get("id", "unknown"),
        tier=decision.tier.value,
        action=decision.action,
        reason=decision.reason,
        confidence=decision.confidence_used,
        severity=decision.severity_used,
    )

    if decision.tier == Tier.AUTO_CLOSE:
        logger.info(f"[DAL-T1] Auto-closed: {alert.get('id')} — {decision.reason}")
        return decision

    if decision.tier == Tier.AUTO_REMEDIATE:
        if decision.dry_run_blocked:
            logger.info(f"[DAL-T2-DRY] Would remediate but DRY_RUN=true: {alert.get('id')}")
        else:
            logger.info(f"[DAL-T2] Auto-remediating: {alert.get('id')}")
            execute_playbook(alert)  # existing function
        send_telegram_notify(alert, decision, client_id)
        return decision

    if decision.tier == Tier.HUMAN_ESCALATE:
        logger.warning(f"[DAL-T3] Human escalation required: {alert.get('id')} — {decision.reason}")
        send_telegram_immediate(alert, decision, client_id)
        queue_for_human_review(alert, client_id)
        return decision

    return decision


def queue_for_human_review(alert: dict, client_id: str):
    """Queue alert for human review within 2-hour SLA."""
    import json
    from pathlib import Path
    from datetime import datetime, timezone

    queue_file = Path(f"logs/dal/{client_id}_human_queue.jsonl")
    queue_file.parent.mkdir(parents=True, exist_ok=True)

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "client_id": client_id,
        "alert_id": alert.get("id"),
        "severity": alert.get("severity"),
        "description": alert.get("rule", {}).get("description", ""),
        "sla_deadline": "2 hours from timestamp",
        "reviewed": False,
    }

    with open(queue_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

