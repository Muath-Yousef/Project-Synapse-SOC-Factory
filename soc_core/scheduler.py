"""
Scheduler — production hardening for multi-client scan automation.
Phase 5 Deliverable 5.1
"""

import os
import sys
import argparse
import time
import logging
from datetime import datetime, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)

# ── Tier → Frequency Mapping ──────────────────────────────────────────────────
SCAN_FREQUENCIES = {
    "soc_lite": "monthly",
    "soc_standard": "weekly",      # Guard tier maps here
    "soc_pro": "weekly",
    "soc_grc": "weekly",           # Governance + Premium map here
}


def load_all_clients() -> list[dict]:
    """Load all client profiles from YAML files."""
    try:
        import yaml
    except ImportError:
        logger.error("[Scheduler] PyYAML not installed — pip install pyyaml")
        return []

    client_dir = Path("knowledge/client_profiles")
    clients = []
    if not client_dir.exists():
        return []

    for yaml_file in client_dir.glob("*.yaml"):
        try:
            with open(yaml_file, encoding="utf-8") as f:
                client = yaml.safe_load(f)
                if client:
                    # Map service_tier to tier if needed for test compatibility
                    if "service_tier" in client and "tier" not in client:
                        client["tier"] = client["service_tier"]
                    if "client_name" in client and "client_id" not in client:
                        client["client_id"] = client["client_name"].lower().replace(" ", "_")
                    clients.append(client)
        except Exception as e:
            logger.error(f"[Scheduler] Failed to load {yaml_file}: {e}")
            continue
    return clients


def get_scan_schedule(tier: str) -> str:
    return SCAN_FREQUENCIES.get(tier, "monthly")


def is_scan_due(last_scan_str: str, frequency: str, now: datetime) -> bool:
    if not last_scan_str:
        return True
    try:
        last_scan = datetime.fromisoformat(last_scan_str)
    except (ValueError, TypeError):
        return True

    delta = now - last_scan

    if frequency == "weekly":
        return delta.days >= 7
    else:  # monthly
        return delta.days >= 30


def run_client_scan(client_id: str, domain: str):
    """Trigger a scan for a specific client."""
    import subprocess
    project_root = Path(__file__).parent
    cmd = [
        sys.executable,
        str(project_root / "main_orchestrator.py"),
        "--client", client_id,
        "--domain", domain,
    ]
    logger.info(f"[Scheduler] Launching scan: {' '.join(cmd)}")
    try:
        subprocess.Popen(cmd, cwd=str(project_root))
    except FileNotFoundError:
        logger.warning(f"[Scheduler] main_orchestrator.py not found — scan skipped for {client_id}")


def run_scheduled_scans():
    """Run all due scans based on client tier schedule."""
    try:
        import yaml
    except ImportError:
        logger.error("[Scheduler] PyYAML not installed — pip install pyyaml")
        return

    client_dir = Path("knowledge/client_profiles")
    if not client_dir.exists():
        logger.warning(f"[Scheduler] Client profiles directory not found: {client_dir}")
        return

    now = datetime.now()
    scanned = 0
    skipped = 0

    for yaml_file in client_dir.glob("*.yaml"):
        try:
            with open(yaml_file, encoding="utf-8") as f:
                client = yaml.safe_load(f)
        except Exception as e:
            logger.error(f"[Scheduler] Failed to load {yaml_file}: {e}")
            continue

        client_id = client.get("client_id")
        domain = client.get("domain")
        tier = client.get("tier", "soc_standard")
        last_scan = client.get("last_scan_date")
        status = client.get("status", "active")

        if status != "active":
            logger.debug(f"[Scheduler] Skipping inactive client: {client_id}")
            skipped += 1
            continue

        frequency = get_scan_schedule(tier)

        if is_scan_due(last_scan, frequency, now):
            logger.info(f"[Scheduler] Scan due for {client_id} (tier: {tier}, freq: {frequency})")
            run_client_scan(client_id, domain)
            scanned += 1
        else:
            logger.debug(f"[Scheduler] {client_id}: not due yet")
            skipped += 1

    logger.info(f"[Scheduler] Cycle complete — {scanned} scans launched, {skipped} skipped")
    return scanned


def run_daemon(interval_seconds: int = 3600):
    """Run scheduler as daemon, checking every interval."""
    logger.info(f"[Scheduler] Starting daemon mode (interval: {interval_seconds}s)")
    while True:
        try:
            run_scheduled_scans()
        except Exception as e:
            logger.error(f"[Scheduler] Unexpected error in cycle: {e}")
        time.sleep(interval_seconds)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    parser = argparse.ArgumentParser(description="Synapse Scheduled Scanner")
    parser.add_argument("--daemon", action="store_true", help="Run as background daemon")
    parser.add_argument("--interval", type=int, default=3600, help="Daemon check interval (seconds)")
    parser.add_argument("--once", action="store_true", help="Run once and exit")
    args = parser.parse_args()

    if args.daemon:
        run_daemon(args.interval)
    else:
        run_scheduled_scans()
