from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Dict, Any
import logging
from soc.playbooks.web_attack_playbook import WebAttackPlaybook
from soc.playbooks.hardening_playbook import HardeningPlaybook
from soc.playbooks.phishing_playbook import PhishingPlaybook

logger = logging.getLogger(__name__)

class ActionType(Enum):
    BLOCK_IP        = "block_ip"
    NOTIFY_ONLY     = "notify_only"
    PATCH_ADVISORY  = "patch_advisory"
    ESCALATE_HUMAN  = "escalate_human"

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
        ("critical", "cleartext_http") : [ActionType.BLOCK_IP, ActionType.ESCALATE_HUMAN],
        ("critical", "cve")            : [ActionType.BLOCK_IP, ActionType.NOTIFY_ONLY],
        ("high",     "cve")            : [ActionType.NOTIFY_ONLY, ActionType.PATCH_ADVISORY],
        ("high",     "default_ssh")    : [ActionType.NOTIFY_ONLY],
        ("medium",   "default_ssh")    : [ActionType.NOTIFY_ONLY],
        ("high",     "dns_spf_missing"): [ActionType.NOTIFY_ONLY],
        ("high",     "dns_dmarc_missing"): [ActionType.NOTIFY_ONLY],
        ("high",     "reputation_vt"): [ActionType.BLOCK_IP, ActionType.ESCALATE_HUMAN, ActionType.NOTIFY_ONLY],
    }

    def get_playbooks(self, client_name: str, config: Dict[str, Any], finding_type: str) -> List:
        """
        Returns instances of playbooks relevant to the finding_type.
        """
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
        actions = self.ROUTING_TABLE.get(key, [ActionType.NOTIFY_ONLY])
        logger.info(f"[Router] {alert.client_id} | {key} → {actions}")
        return actions
