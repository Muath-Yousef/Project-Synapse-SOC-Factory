import requests
import os
import logging
from datetime import datetime
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

class TelegramConnector:
    """
    Sends notifications to multiple Telegram channels based on alert type.
    Phase 29.2: Added explicit timestamped logging at every step.
    """
    def __init__(self):
        load_dotenv()
        self.bot_token = os.getenv("TELEGRAM_BOT_TOKEN")
        
        # Multi-channel setup
        self.channels = {
            "findings" : os.getenv("TELEGRAM_CHAT_ID_FINDINGS"),
            "actions"  : os.getenv("TELEGRAM_CHAT_ID_ACTIONS"),
            "failures" : os.getenv("TELEGRAM_CHAT_ID_FAILURES"),
        }
        
        # Log initialization state
        token_status = "SET" if (self.bot_token and self.bot_token != "your_bot_token") else "MISSING"
        channels_set = [k for k, v in self.channels.items() if v]
        logger.info(f"[TG-INIT] {datetime.now().isoformat()} | Token: {token_status} | Channels configured: {channels_set}")

    def send(self, message: str, channel: str = "findings") -> bool:
        ts = datetime.now().isoformat()
        
        # Resolve channel
        chat_id = self.channels.get(channel) or self.channels.get("findings")
        logger.info(f"[TG-SEND] {ts} | Channel: {channel} | Chat ID: {chat_id and chat_id[:6] + '...'}")
        
        if not self.bot_token or not chat_id or self.bot_token == "your_bot_token":
            logger.warning(f"[TG-MOCK] {ts} | Channel: {channel} | Reason: Missing credentials | Message: {message[:80]}...")
            return True

        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": message,
            "parse_mode": "HTML",
        }
        
        try:
            logger.info(f"[TG-API] {ts} | Sending to Telegram API...")
            response = requests.post(url, json=payload, timeout=10)
            response.raise_for_status()
            logger.info(f"[TG-OK] {datetime.now().isoformat()} | Channel: {channel} | Status: {response.status_code}")
            return True
        except Exception as e:
            logger.error(f"[TG-FAIL] {datetime.now().isoformat()} | Channel: {channel} | Error: {e}")
            # Send failure notification to failures channel if this wasn't already a failure channel message
            if channel != "failures":
                self._notify_failure(f"Telegram send failed for #{channel}: {str(e)[:100]}")
            raise e

    def _notify_failure(self, error_msg: str):
        """Attempt to send failure notification to the failures channel."""
        fail_chat = self.channels.get("failures")
        if not fail_chat or not self.bot_token:
            return
        try:
            url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
            requests.post(url, json={
                "chat_id": fail_chat,
                "text": f"⚠️ SYSTEM FAILURE\n{error_msg}\nTime: {datetime.now().isoformat()}"
            }, timeout=5)
        except Exception:
            pass  # Last resort — don't recurse
