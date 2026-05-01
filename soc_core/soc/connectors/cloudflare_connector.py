import requests
import os
import logging
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

class CloudflareConnector:
    """
    يستخدم Cloudflare Firewall Rules API (Zone-level).
    الحد الأقصى للـ Free tier: 5 rules فقط.
    """

    CF_API   = "https://api.cloudflare.com/client/v4"
    
    def __init__(self):
        load_dotenv()
        self.token   = os.getenv("CF_API_TOKEN")
        self.zone_id = os.getenv("CF_ZONE_ID")
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }

    def block_ip(self, ip: str, reason: str) -> dict:
        if not self.token or not self.zone_id or self.token == "your_cf_api_token_here":
            logger.warning("[CF_CONNECTOR] API details missing. MOCKING block.")
            return {"success": True, "mock": True, "ip": ip, "reason": reason}

        endpoint = f"{self.CF_API}/zones/{self.zone_id}/firewall/access_rules/rules"
        payload = {
            "mode": "block",
            "configuration": {"target": "ip", "value": ip},
            "notes": reason[:100]  # Cloudflare يقبل 100 حرف فقط
        }
        response = requests.post(endpoint, headers=self.headers, json=payload, timeout=10)
        response.raise_for_status()  # يرمي Exception إذا فشل
        return response.json()
