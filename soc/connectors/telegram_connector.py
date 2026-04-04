import requests
import os
import logging
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

class TelegramConnector:
    """
    Sends notifications to multiple Telegram channels based on alert type.
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

    def send(self, message: str, channel: str = "findings") -> bool:
        # Fallback to findings if specific channel not provided
        chat_id = self.channels.get(channel) or self.channels.get("findings")
        
        if not self.bot_token or not chat_id or self.bot_token == "your_bot_token":
            logger.warning(f"[TELEGRAM_CONNECTOR] [{channel.upper()}] Mock send:\n{message}")
            return True

        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": message
        }
        
        try:
            response = requests.post(url, json=payload, timeout=10)
            response.raise_for_status()
            return True
        except Exception as e:
            logger.error(f"Failed to send Telegram message to {channel}: {e}")
            raise e
