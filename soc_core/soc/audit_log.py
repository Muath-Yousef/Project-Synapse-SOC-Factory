import json
import logging
from datetime import datetime, timezone
from pathlib import Path

# Use absolute path relative to project root for the audit log
BASE_DIR = Path(__file__).resolve().parent.parent
AUDIT_FILE = BASE_DIR / "soc" / "audit" / "soar_actions.jsonl"

logger = logging.getLogger(__name__)

def log_action(client_id: str, action: str, target_ip: str,
               finding: str, severity: str, dry_run: bool, result: dict):
    """
    Logs every SOAR action to a JSONL audit trail.
    """
    try:
        AUDIT_FILE.parent.mkdir(parents=True, exist_ok=True)
        
        entry = {
            "timestamp"  : datetime.now(timezone.utc).isoformat(),
            "client_id"  : client_id,
            "action"     : action,
            "target_ip"  : target_ip,
            "finding"    : finding,
            "severity"   : severity,
            "dry_run"    : dry_run,
            "unblock_after_hours": 24, # Metadata only for future cleanup
            "cf_rule_id": result.get("cf_rule_id", None) if result else None,
            "result"     : result
        }
        
        with open(AUDIT_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
            
        logger.info(f"[Audit] Logged {action} for {target_ip} ({severity})")
    except Exception as e:
        logger.error(f"[Audit] Failed to log action: {e}")

def log_dal_decision(
    client_id: str,
    alert_id: str,
    tier: int,
    action: str,
    reason: str,
    confidence: float,
    severity: str,
):
    """Log DAL decision to a separate JSONL file for metrics."""
    try:
        log_file = BASE_DIR / "logs" / "dal" / "dal_decisions.jsonl"
        log_file.parent.mkdir(parents=True, exist_ok=True)
        
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "client_id": client_id,
            "alert_id": alert_id,
            "tier": tier,
            "action": action,
            "reason": reason,
            "confidence": confidence,
            "severity": severity,
        }
        
        with open(log_file, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        logger.error(f"[Audit] Failed to log DAL decision: {e}")
