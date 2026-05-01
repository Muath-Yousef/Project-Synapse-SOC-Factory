import json
import time
import logging
from pathlib import Path
from soc.connectors.telegram_connector import TelegramConnector

logger = logging.getLogger(__name__)

class HardeningPlaybook:
    """
    Playbook for non-blockable infrastructure findings (e.g., SSH on default port).
    Generates a local ticket and sends a hardening advisory checklist to the analyst.
    """

    SSH_CHECKLIST = [
        "Change SSH port from 22 to non-standard (e.g., 2222)",
        "Disable root login: PermitRootLogin no",
        "Enable key-based auth only: PasswordAuthentication no",
        "Implement fail2ban or equivalent brute-force protection",
        "Restrict SSH access by IP via AllowUsers or iptables",
    ]

    def __init__(self):
        self.tg = TelegramConnector()

    def execute(self, alert_context, dry_run: bool = True) -> dict:
        ticket = {
            "client_id" : alert_context.client_id,
            "finding"   : alert_context.finding_type,
            "severity"  : alert_context.severity,
            "checklist" : self.SSH_CHECKLIST,
            "dry_run"   : dry_run,
            "target_ip" : alert_context.target_ip,
            "timestamp" : int(time.time())
        }
        
        # Determine ticket path (absolute for reliability)
        project_root = Path(__file__).resolve().parent.parent.parent
        ticket_dir = project_root / "soc" / "tickets"
        ticket_dir.mkdir(parents=True, exist_ok=True)
        
        ticket_filename = f"{alert_context.client_id}_{int(time.time())}.json"
        ticket_path = ticket_dir / ticket_filename
        
        with open(ticket_path, "w") as f:
            f.write(json.dumps(ticket, indent=2))

        # Send Telegram Advisory
        status_msg = "[DRY-RUN] " if dry_run else ""
        self.tg.send(
            f"🔧 {status_msg}Hardening Advisory | {alert_context.client_id}\n"
            f"Finding: {alert_context.finding_type}\n"
            f"Target: {alert_context.target_ip}\n"
            f"Action Required: Review SSH hardening checklist\n"
            f"Ticket: {ticket_filename}",
            channel="actions"
        )
        
        logger.info(f"[Playbook] Hardening Advisory sent for {alert_context.finding_type} on {alert_context.target_ip}")
        
        return {"status": "advisory_sent", "ticket": str(ticket_path)}
