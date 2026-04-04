import logging
from .base_playbook import BasePlaybook
from connectors.cloudflare_connector import CloudflareConnector
from connectors.telegram_connector import TelegramConnector

logger = logging.getLogger('web_attack_playbook')

class WebAttackPlaybook(BasePlaybook):
    def __init__(self):
        super().__init__("web_attack_playbook", trigger_rules=["sql", "sqli", "injection", "xss", "web"])
        self.cloudflare = CloudflareConnector()
        self.telegram = TelegramConnector()

    def execute(self, alert: dict):
        try:
            logger.info(f"[{self.name}] بدء التعامل مع هجوم ويب (Web Attack)")
            
            src_ip = alert.get("data", {}).get("srcip")
            if not src_ip:
                logger.warning(f"[{self.name}] لم يتم العثور على عنوان IP المهاجم في التنبيه.")
                return
            
            # Confidence for deterministic web attacks like SQLi/XSS is high
            confidence = 95
            
            # 1. Block at WAF Level via Cloudflare
            block_success = self.cloudflare.block_ip(src_ip)
            
            action_desc = f"🔴 تم حظر IP المهاجم ({src_ip}) عبر Cloudflare WAF" if block_success else f"⚠️ فشل حظر IP المهاجم ({src_ip}) عبر Cloudflare WAF"
            
            logger.info(f"[{self.name}] الحكم النهائي: malicious (ثقة: {confidence}%) → {action_desc}")
            
            # 2. Push Alert to Telegram
            msg = f"🔴 *تنبيه أمني — هجوم ويب حرج*\n" \
                  f"العميل: `{alert.get('agent', {}).get('name', 'N/A')}`\n" \
                  f"الجهاز: `{alert.get('agent', {}).get('ip', 'N/A')}`\n" \
                  f"التهديد: {alert.get('rule', {}).get('description', 'N/A')}\n" \
                  f"الإجراء: {action_desc}\n" \
                  f"الثقة: {confidence}%"
            
            self.telegram.send_message(msg)
            
        except Exception as e:
            logger.error(f"[{self.name}] حدث خطأ أثناء تنفيذ Playbook: {e}")
