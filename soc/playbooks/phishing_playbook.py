import logging
from typing import Dict, Any, List
from soc.playbooks.base_playbook import BasePlaybook, ActionType
from soc.connectors.telegram_connector import TelegramConnector

logger = logging.getLogger(__name__)

class PhishingPlaybook(BasePlaybook):
    """
    Playbook for handling Phishing alerts and Email Security findings.
    Part of Phase 12: managed SOC Operations.
    """

    def __init__(self, client_name: str, security_config: Dict[str, Any]):
        super().__init__(client_name, security_config)
        self.telegram = TelegramConnector()

    def execute(self, finding: Dict[str, Any]) -> List[ActionType]:
        """
        Executes phishing mitigation/advisory steps.
        """
        target = finding.get("target", "unknown")
        ftype = finding.get("type", "unknown")
        severity = finding.get("severity", "low")
        
        logger.info(f"[PhishingPlaybook] Executing for {target} -> {ftype}")
        
        actions = []
        
        if ftype in ["dns_spf_missing", "dns_dmarc_missing"]:
            # High Priority: Missing email security records
            self._notify_analyst(target, ftype, severity, "Domain vulnerable to spoofing. Missing SPF/DMARC.")
            actions.append(ActionType.NOTIFY_ONLY)
            # Future: Could add automated ticket creation here
            
        elif ftype == "reputation_vt" and severity in ["high", "critical"]:
            # High Priority: Malicious reputation found
            self._notify_analyst(target, ftype, severity, "IP/URL found in VirusTotal malicious database.")
            actions.append(ActionType.BLOCK_IP)
            actions.append(ActionType.ESCALATE_HUMAN)

        return actions

    def _notify_analyst(self, target: str, ftype: str, severity: str, details: str):
        msg = (
            f"🎣 *PLAYBOOK: PHISHING DETECTED*\n"
            f"Client: {self.client_name}\n"
            f"Target: `{target}`\n"
            f"Type: {ftype}\n"
            f"Severity: {severity.upper()}\n"
            f"Details: {details}\n"
            f"Action: Triage initiated."
        )
        self.telegram.send_notification(msg)
