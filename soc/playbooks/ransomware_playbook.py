from soc.playbooks.base_playbook import BasePlaybook
from soc.connectors.telegram_connector import TelegramConnector
from soc.audit_log import log_action
import logging

logger = logging.getLogger(__name__)

class RansomwarePlaybook(BasePlaybook):

    def __init__(self):
        self.tg = TelegramConnector()

    def execute(self, alert_context, dry_run: bool = True) -> dict:
        p0_message = (
            f"🔴 P0 RANSOMWARE PRECURSOR | Client: {alert_context.client_id}\n"
            f"Target: {alert_context.target_ip}\n"
            f"Indicator: {alert_context.finding_type}\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"IMMEDIATE ACTIONS REQUIRED:\n"
            f"1. Isolate affected system from network\n"
            f"2. Preserve disk image before any changes\n"
            f"3. Notify client emergency contact NOW\n"
            f"4. Do NOT reboot system\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"DRY_RUN: {dry_run}"
        )
        for channel in ["findings", "actions", "failures"]:
            try:
                self.tg.send(p0_message, channel=channel)
            except Exception as e:
                logger.critical(f"[RansomwarePlaybook] Telegram {channel} FAILED: {e}")

        log_action(alert_context.client_id, "P0_RANSOMWARE_ESCALATION", alert_context.target_ip, alert_context.finding_type, alert_context.severity, dry_run, {"status": "p0_escalated", "channels_notified": 3})
        return {"status": "p0_escalated", "action": "P0_RANSOMWARE_ESCALATION"}
