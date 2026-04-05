#!/usr/bin/env python3
import sys, os, yaml, json
sys.path.insert(0, '/media/kyrie/VMs1/Cybersecurity_Tools_Automation')
os.chdir('/media/kyrie/VMs1/Cybersecurity_Tools_Automation')
from pathlib import Path
from datetime import datetime
from dotenv import load_dotenv
load_dotenv()

def load_clients():
    clients = []
    for f in Path("knowledge/client_profiles").glob("*.yaml"):
        with open(f) as fp:
            data = yaml.safe_load(fp)
            if data and "client_name" in data:
                clients.append(data)
    return clients

def get_recent_audit_actions(client_id, limit=5):
    audit_file = Path("soc/audit/soar_actions.jsonl")
    if not audit_file.exists():
        return []
    actions = []
    with open(audit_file) as f:
        for line in f:
            try:
                entry = json.loads(line)
                if entry.get("client_id", "").lower() == client_id.lower():
                    actions.append(entry)
            except Exception:
                continue
    return actions[-limit:]

def get_latest_report(client_id):
    reports = sorted(Path("reports/output").glob(f"*{client_id.lower()}*.md"))
    if not reports:
        reports = sorted(Path("reports/output").glob("*.md"))
    if reports:
        mtime = datetime.fromtimestamp(reports[-1].stat().st_mtime)
        return f"{reports[-1].name} ({mtime.strftime('%Y-%m-%d %H:%M')})"
    return "No reports yet"

def print_dashboard():
    clients = load_clients()
    width = 70
    print("\n" + "=" * width)
    print(f"  🛡️  SYNAPSE SOC FACTORY — Status Dashboard")
    print(f"  📅  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * width)
    if not clients:
        print("  ⚠️  No clients registered.")
        return
    print(f"\n  Registered Clients: {len(clients)}\n")
    for client in clients:
        name     = client.get("client_name", "Unknown")
        tier     = client.get("service_tier", "N/A")
        target   = client.get("primary_target", "N/A")
        industry = client.get("industry", "N/A")
        freq     = client.get("scan_frequency", "N/A")
        print(f"  ┌─ {name} [{tier.upper()}]")
        print(f"  │  Industry  : {industry}")
        print(f"  │  Target    : {target}")
        print(f"  │  Frequency : {freq}")
        print(f"  │  Last Rpt  : {get_latest_report(name)}")
        actions = get_recent_audit_actions(name)
        if actions:
            last = actions[-1]
            ts   = last.get("timestamp", "")[:16].replace("T", " ")
            act  = last.get("action", "")
            dry  = " [DRY]" if last.get("dry_run") else " [LIVE]"
            print(f"  │  Last SOAR : {act}{dry} @ {ts}")
        else:
            print(f"  │  Last SOAR : No actions recorded")
        blocks  = sum(1 for a in actions if "BLOCK" in a.get("action","") and "GUARD" not in a.get("action",""))
        guarded = sum(1 for a in actions if "GUARD" in a.get("action",""))
        print(f"  │  Actions   : {len(actions)} total | {blocks} blocks | {guarded} guarded")
        print(f"  └{'─' * (width - 4)}")
    print("\n" + "=" * width)
    print(f"  Tools: 8 | Playbooks: 6 | CI/CD: GitHub Actions")
    print("=" * width + "\n")

if __name__ == "__main__":
    print_dashboard()
