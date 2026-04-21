#!/usr/bin/env python3
"""
Synapse Scheduler — Phase 30.1
================================
Reads client profiles, respects per-client scan_frequency tier,
logs to audit_log, and alerts Telegram on failures.

Deploy as systemd service (see deployment/synapse-scheduler.service).

Usage:
    python3 scheduler.py --mode weekly    # runs all clients due for weekly scan
    python3 scheduler.py --mode monthly   # runs all clients due for monthly scan
    python3 scheduler.py --run-now --client AsasEdu  # on-demand single client
"""
import os, yaml, logging, argparse, sys, json, time
sys.path.insert(0, '/media/kyrie/VMs1/Cybersecurity_Tools_Automation')
os.chdir('/media/kyrie/VMs1/Cybersecurity_Tools_Automation')
from pathlib import Path
from datetime import datetime
from dotenv import load_dotenv
load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("scheduler")

BASE_DIR = Path('/media/kyrie/VMs1/Cybersecurity_Tools_Automation')

# Tier → default frequency mapping
TIER_FREQUENCY = {
    "soc_lite":     "monthly",
    "soc_standard": "weekly",
    "soc_pro":      "weekly",
    "soc_grc":      "weekly",
}


def load_all_clients(profiles_dir: str = "knowledge/client_profiles") -> list:
    clients = []
    for yaml_file in Path(profiles_dir).glob("*.yaml"):
        if yaml_file.name.startswith("_"):
            continue  # skip templates
        try:
            with open(yaml_file) as f:
                data = yaml.safe_load(f)
                if data and "client_name" in data:
                    # Skip template placeholders
                    if str(data.get("client_name", "")).startswith("["):
                        continue
                    tier = data.get("service_tier", "soc_standard").lower()
                    freq = data.get("scan_frequency") or TIER_FREQUENCY.get(tier, "weekly")
                    clients.append({
                        "client_id":    data["client_name"],
                        "target":       data.get("primary_target", ""),
                        "contact_email":data.get("contact_email", ""),
                        "billing_email":data.get("billing_email", data.get("contact_email", "")),
                        "tier":         tier,
                        "frequency":    freq,
                        "notify_telegram": data.get("notification_channels", {}).get("telegram", True),
                        "notify_email":    data.get("notification_channels", {}).get("email", True),
                        "monthly_fee":  (data.get("billing") or {}).get("monthly_fee", 0),
                    })
        except Exception as e:
            logger.error(f"Failed to load {yaml_file}: {e}")
    return clients


def _notify_failure(client_id: str, error: str):
    """Send system failure alert to Telegram failures channel."""
    try:
        from soc.connectors.telegram_connector import TelegramConnector
        tg = TelegramConnector()
        tg.send(
            f"🚨 SCHEDULER FAILURE\n"
            f"Client: {client_id}\n"
            f"Time: {datetime.now().isoformat()}\n"
            f"Error: {error[:200]}",
            channel="failures"
        )
    except Exception as e:
        logger.error(f"[Scheduler] Telegram failure notification failed: {e}")


def _log_scheduler_run(client_id: str, status: str, duration_s: float):
    """Append run record to audit log."""
    try:
        from soc.audit_log import log_action
        log_action(
            client_id=client_id,
            action=f"SCHEDULED_SCAN_{status.upper()}",
            result=f"duration={duration_s:.1f}s",
            dry_run=False
        )
    except Exception:
        pass  # audit log failure should never block scans


def run_scheduled_scan(mode: str = "weekly", client_filter: str = None):
    logger.info(f"=== Synapse Scheduler: {mode.upper()} run at {datetime.now().isoformat()} ===")
    clients = load_all_clients()
    if not clients:
        logger.warning("No client profiles found in knowledge/client_profiles/")
        return

    # Filter by mode (frequency must match) or specific client
    if client_filter:
        clients = [c for c in clients if c["client_id"].lower() == client_filter.lower()]
    else:
        # soc_pro and soc_grc always run on weekly too
        clients = [c for c in clients if c["frequency"] == mode or
                   (mode == "weekly" and c["tier"] in ("soc_pro", "soc_grc"))]

    if not clients:
        logger.info(f"No clients due for {mode} scan.")
        return

    logger.info(f"Clients to scan ({len(clients)}): {[c['client_id'] for c in clients]}")

    from main_orchestrator import Orchestrator
    orch = Orchestrator()

    results = {"success": [], "failed": []}

    for client in clients:
        client_id = client["client_id"]
        target    = client["target"]
        if not target:
            logger.warning(f"[Scheduler] Skipping {client_id} — no primary_target")
            continue

        logger.info(f"[Scheduler] ▶ Starting scan: {client_id} → {target}")
        t0 = time.time()
        try:
            # Phase 30.1: pass report_type=both, email handled inside orchestrator
            orch.run_triage(
                target_ip=target,
                client_id=client_id,
                report_type="both"
            )
            duration = time.time() - t0
            logger.info(f"[Scheduler] ✅ Done: {client_id} ({duration:.1f}s)")
            _log_scheduler_run(client_id, "success", duration)
            results["success"].append(client_id)
        except Exception as e:
            duration = time.time() - t0
            logger.error(f"[Scheduler] ❌ Failed: {client_id} — {e}")
            _log_scheduler_run(client_id, "failed", duration)
            _notify_failure(client_id, str(e))
            results["failed"].append(client_id)

    # Summary
    logger.info(f"=== Scheduler run complete: {len(results['success'])} OK | {len(results['failed'])} FAILED ===")

    # Rule health report
    try:
        from soc.control_plane import ControlPlane
        cp = ControlPlane()
        rules = cp.get_rule_health()
        report_path = BASE_DIR / "reports" / "output" / f"rule_health_{int(time.time())}.json"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        with open(report_path, "w") as f:
            json.dump(rules, f, indent=2)
        logger.info(f"[Scheduler] Rule health report: {report_path}")
    except Exception as e:
        logger.error(f"[Scheduler] Rule health failed: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Synapse Scheduled Scanner")
    parser.add_argument("--mode", choices=["weekly", "monthly"], default="weekly",
                        help="Scan mode: weekly (default) or monthly")
    parser.add_argument("--run-now", action="store_true",
                        help="Run immediately regardless of frequency setting")
    parser.add_argument("--client", default=None,
                        help="Run for a single client only (on-demand)")
    args = parser.parse_args()

    mode = args.mode if not args.run_now else "weekly"
    run_scheduled_scan(mode=mode, client_filter=args.client)
