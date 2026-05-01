from soc.playbooks.base_playbook import BasePlaybook
from soc.connectors.telegram_connector import TelegramConnector
from soc.connectors.cloudflare_connector import CloudflareConnector
from soc.audit_log import log_action
import logging

logger = logging.getLogger(__name__)

class DataExfilPlaybook(BasePlaybook):

    def __init__(self):
        self.tg = TelegramConnector()
        self.cf = CloudflareConnector()

    def execute(self, alert_context, dry_run: bool = True) -> dict:
        result = {"status": "pending", "actions": []}
        try:
            if dry_run:
                logger.warning(f"[DRY-RUN] Would block {alert_context.target_ip} for data exfil")
                result["actions"].append(f"DRY_RUN_BLOCK: {alert_context.target_ip}")
            else:
                cf_resp = self.cf.block_ip(ip=alert_context.target_ip, reason=f"P1 Data Exfil | {alert_context.client_id}")
                result["actions"].append(f"CF_BLOCK: {cf_resp}")
        except Exception as e:
            logger.critical(f"[DataExfilPlaybook] Block FAILED: {e}")
            self.tg.send(f"🚨 P1 BLOCK FAILED for {alert_context.target_ip} | Manual action needed NOW", channel="failures")
            result["status"] = "partial_failure"
            return result

        self.tg.send(
            f"🚨 P1 DATA EXFILTRATION | Client: {alert_context.client_id}\n"
            f"IP: {alert_context.target_ip} — BLOCKED\n"
            f"Action required: Investigate immediately",
            channel="failures"
        )
        result["actions"].append("P1_ESCALATION_SENT")
        result["status"] = "success"
        log_action(alert_context.client_id, "DATA_EXFIL_BLOCK", alert_context.target_ip, alert_context.finding_type, alert_context.severity, dry_run, result)
        return result
