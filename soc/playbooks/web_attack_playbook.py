from soc.connectors.cloudflare_connector import CloudflareConnector
from soc.connectors.telegram_connector import TelegramConnector
import logging

logger = logging.getLogger(__name__)

class WebAttackPlaybook:
    """
    Triggered by: critical/high web-facing findings
    
    Execution order:
    1. Block IP at Cloudflare WAF (Firewall Rule)
    2. Notify analyst via Telegram
    3. Log action to audit trail
    
    Failure handling:
    - Cloudflare failure → escalate to human immediately
    - Telegram failure   → log locally, do NOT abort block
    """

    def __init__(self):
        self.cf = CloudflareConnector()
        self.tg = TelegramConnector()

    def execute(self, alert_context, dry_run: bool = True) -> dict:
        result = {"status": "pending", "actions_taken": []}

        if dry_run:
            logger.warning(f"[DRY-RUN] Would block {alert_context.target_ip} - no action taken")
            self.tg.send(f"🔵 DRY-RUN | Would block: {alert_context.target_ip}", channel="actions")
            return {"status": "dry_run", "would_block": alert_context.target_ip}

        # Step 1: Cloudflare Block
        try:
            cf_response = self.cf.block_ip(
                ip=alert_context.target_ip,
                reason=f"Synapse SOAR: {alert_context.finding_type} | {alert_context.client_id}"
            )
            result["actions_taken"].append(f"CF_BLOCK: {cf_response}")
            logger.info(f"[Playbook] Cloudflare block issued for {alert_context.target_ip}")
        except Exception as e:
            # CRITICAL: لا تصمت عند فشل الـ Block
            logger.critical(f"[Playbook] Cloudflare FAILED: {e}")
            self.tg.send(f"🚨 SOAR FAILURE: Cloudflare block failed for {alert_context.target_ip}. Manual intervention required.")
            result["status"] = "partial_failure"
            return result

        # Step 2: Telegram Notify
        try:
            self.tg.send(
                f"✅ SOAR Action | Client: {alert_context.client_id}\n"
                f"Finding: {alert_context.finding_type} ({alert_context.severity})\n"
                f"IP Blocked: {alert_context.target_ip}\n"
                f"Tool: {alert_context.source_tool}",
                channel="actions"
            )
            result["actions_taken"].append("TELEGRAM_NOTIFY: sent")
        except Exception as e:
            logger.warning(f"[Playbook] Telegram notify failed (non-critical): {e}")

        result["status"] = "success"
        return result
