from dataclasses import dataclass
from enum import Enum
from typing import List, Optional
import logging

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
    }

    def route(self, alert: AlertContext) -> List[ActionType]:
        key = (alert.severity.lower(), alert.finding_type.lower())
        actions = self.ROUTING_TABLE.get(key, [ActionType.NOTIFY_ONLY])
        logger.info(f"[Router] {alert.client_id} | {key} → {actions}")
        return actions
