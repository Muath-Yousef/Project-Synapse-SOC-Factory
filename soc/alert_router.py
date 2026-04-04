import logging

logger = logging.getLogger(__name__)

class AlertRouter:
    def __init__(self):
        self.playbooks = {}
        self._load_playbooks()

    def _load_playbooks(self):
        try:
            from playbooks.web_attack_playbook import WebAttackPlaybook
            self.playbooks["web_attack_playbook"] = WebAttackPlaybook()
            logger.info("🎯 Playbooks المسجلة: ['web_attack_playbook']")
        except Exception as e:
            logger.error(f"❌ فشل تحميل Playbooks: {e}")

    def route(self, alert: dict):
        try:
            logger.info("\n=======================================================")
            rule_id = alert.get("rule", {}).get("id", "N/A")
            level = alert.get("rule", {}).get("level", 0)
            desc = alert.get("rule", {}).get("description", "").lower()
            src_ip = alert.get("data", {}).get("srcip", "N/A")
            
            logger.info(f"📨 تنبيه جديد | ID:{rule_id} | Level:{level}")
            logger.info(f"   IP المهاجم: {src_ip}")
            logger.info(f"   الوصف: {desc}")
            
            if any(keyword in desc for keyword in ["sql", "sqli", "injection", "xss", "web"]):
                logger.info("🔄 توجيه لهجوم الويب...")
                if "web_attack_playbook" in self.playbooks:
                    self.playbooks["web_attack_playbook"].execute(alert)
            else:
                logger.warning("⚠️ لم يتم العثور على Playbook مناسب لهذا التنبيه.")
        except Exception as e:
            logger.error(f"❌ خطأ أثناء توجيه التنبيه: {e}")
