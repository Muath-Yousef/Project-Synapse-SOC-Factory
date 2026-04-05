import smtplib, os, logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from pathlib import Path

logger = logging.getLogger(__name__)

class EmailConnector:
    def __init__(self):
        self.host = os.getenv("SMTP_HOST", "")
        self.port = int(os.getenv("SMTP_PORT", "587"))
        self.user = os.getenv("SMTP_USER", "")
        self.password = os.getenv("SMTP_PASSWORD", "")
        self.from_addr = os.getenv("SMTP_FROM", self.user)
        self._mock = not all([self.host, self.user, self.password])
        if self._mock:
            logger.info("[EmailConnector] MOCK mode — no SMTP credentials configured")

    def send_report(self, to: str, subject: str, body: str, attachment_path: str = None) -> dict:
        if self._mock:
            logger.info(f"[EMAIL_MOCK] To: {to} | Subject: {subject}")
            if attachment_path:
                logger.info(f"[EMAIL_MOCK] Attachment: {attachment_path}")
            return {"status": "mock", "to": to, "subject": subject}
        try:
            msg = MIMEMultipart()
            msg["From"] = self.from_addr
            msg["To"] = to
            msg["Subject"] = subject
            msg.attach(MIMEText(body, "plain"))
            if attachment_path and Path(attachment_path).exists():
                with open(attachment_path, "rb") as f:
                    part = MIMEBase("application", "octet-stream")
                    part.set_payload(f.read())
                encoders.encode_base64(part)
                part.add_header("Content-Disposition", f"attachment; filename={Path(attachment_path).name}")
                msg.attach(part)
            with smtplib.SMTP(self.host, self.port) as server:
                server.starttls()
                server.login(self.user, self.password)
                server.send_message(msg)
            logger.info(f"[EmailConnector] Report sent to {to}")
            return {"status": "sent", "to": to}
        except Exception as e:
            logger.error(f"[EmailConnector] Failed: {e}")
            return {"status": "error", "error": str(e)}
