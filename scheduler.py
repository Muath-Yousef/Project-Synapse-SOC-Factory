#!/usr/bin/env python3
import os, yaml, logging, argparse, sys
sys.path.insert(0, '/media/kyrie/VMs1/Cybersecurity_Tools_Automation')
from pathlib import Path
from datetime import datetime
from dotenv import load_dotenv
load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("scheduler")

def load_all_clients(profiles_dir: str = "knowledge/client_profiles") -> list:
    clients = []
    for yaml_file in Path(profiles_dir).glob("*.yaml"):
        try:
            with open(yaml_file) as f:
                data = yaml.safe_load(f)
                if data and "client_name" in data:
                    clients.append({
                        "client_id": data["client_name"],
                        "target": data.get("primary_target", ""),
                        "contact_email": data.get("contact_email", ""),
                        "tech_stack_keywords": data.get("tech_stack_keywords", [])
                    })
        except Exception as e:
            logger.error(f"Failed to load {yaml_file}: {e}")
    return clients

def run_scheduled_scan(mode: str = "weekly"):
    logger.info(f"=== Synapse Scheduler: {mode.upper()} run at {datetime.now().isoformat()} ===")
    clients = load_all_clients()
    if not clients:
        logger.warning("No client profiles found in knowledge/client_profiles/")
        return

    from main_orchestrator import Orchestrator
    from soc.connectors.email_connector import EmailConnector
    orch = Orchestrator()
    email = EmailConnector()

    for client in clients:
        client_id = client["client_id"]
        target = client["target"]
        if not target:
            logger.warning(f"[Scheduler] Skipping {client_id} — no primary_target in profile")
            continue
        logger.info(f"[Scheduler] Starting scan: {client_id} — target: {target}")
        try:
            orch.run_triage(target_ip=target, client_id=client_id)
            logger.info(f"[Scheduler] Scan complete: {client_id}")
            if mode == "monthly" and client.get("contact_email"):
                reports = sorted(Path("reports/output").glob("*.md"))
                if reports:
                    email.send_report(
                        to=client["contact_email"],
                        subject=f"Monthly Security Report — {client_id} — {datetime.now().strftime('%B %Y')}",
                        body=f"Dear {client_id} team,\n\nPlease find attached your monthly security report.\n\nSynapse SOC",
                        attachment_path=str(reports[-1])
                    )
        except Exception as e:
            logger.error(f"[Scheduler] Failed for {client_id}: {e}")

    logger.info("=== Synapse Scheduler: Run complete ===")
    
    # Phase 24: Weekly Rule Health Report
    try:
        from soc.control_plane import ControlPlane
        cp = ControlPlane()
        rules = cp.get_rule_health()
        report_path = os.path.join(BASE_DIR, "reports/output", f"rule_health_{int(time.time())}.json")
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        with open(report_path, "w") as f:
            json.dump(rules, f, indent=2)
        logger.info(f"[Scheduler] Rule health report saved to {report_path}")
    except Exception as e:
        logger.error(f"[Scheduler] Failed to generate rule health report: {e}")
    
    import subprocess
    try:
        subprocess.run(
            'git add . && git commit -m "chore: Periodic full repo sync" && git push origin main',
            shell=True, cwd="/media/kyrie/VMs1/Cybersecurity_Tools_Automation",
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        logger.info("[Scheduler] Git sync complete.")
    except Exception as e:
        logger.error(f"[Scheduler] Git sync failed: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Synapse Scheduled Scanner")
    parser.add_argument("--mode", choices=["weekly", "monthly"], default="weekly")
    args = parser.parse_args()
    run_scheduled_scan(mode=args.mode)
