#!/usr/bin/env python3
"""
SYNAPSE SOC FACTORY — Operational Dashboard
Phase 29: Added Gemini API health check + revenue summary
"""
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
        if f.name.startswith("_"):
            continue  # skip templates
        with open(f) as fp:
            data = yaml.safe_load(fp)
            if data and "client_name" in data:
                # Skip template placeholder values
                if str(data.get("client_name", "")).startswith("["):
                    continue
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
    # Check for PDFs first, then markdown
    slug = client_id.lower()
    output_dir = Path("reports/output")
    if not output_dir.exists():
        return "No reports yet"
    for ext in ["pdf", "md"]:
        reports = sorted([f for f in output_dir.glob(f"*.{ext}") if slug in f.name.lower()])
        if reports:
            mtime = datetime.fromtimestamp(reports[-1].stat().st_mtime)
            return f"{reports[-1].name} ({mtime.strftime('%Y-%m-%d %H:%M')})"
    return "No reports yet"

def get_revenue_summary(clients):
    """Phase 30.3: Delegate to ContractManager for accurate billing data."""
    try:
        from onboarding.contract_manager import ContractManager
        cm = ContractManager()
        return cm.get_summary()
    except Exception:
        # Fallback: basic count from profile data
        mrr = sum(
            (c.get("billing") or {}).get("monthly_fee", 0) or 0
            for c in clients
        )
        return {"mrr": mrr, "active_paying": sum(1 for c in clients if (c.get("billing") or {}).get("monthly_fee", 0)),
                "pilots": 0, "overdue_invoices": 0, "expiring_soon": []}

def check_gemini_health():
    """Phase 29.3: API health check for dashboard."""
    try:
        from core.llm_manager import LLMManager
        llm = LLMManager()
        return llm.health_check()
    except Exception as e:
        return {"status": "error", "error": str(e)}

def check_telegram_health():
    """Quick Telegram bot verification."""
    bot_token = os.getenv("TELEGRAM_BOT_TOKEN", "")
    if not bot_token or bot_token == "your_bot_token":
        return {"status": "not_configured"}
    try:
        import requests
        r = requests.get(f"https://api.telegram.org/bot{bot_token}/getMe", timeout=5)
        if r.status_code == 200 and r.json().get("ok"):
            return {"status": "online", "bot": r.json()["result"]["username"]}
        return {"status": "error", "code": r.status_code}
    except Exception as e:
        return {"status": "error", "error": str(e)[:60]}

def display_dal_stats(client_id: str = "all"):
    """Display DAL statistics for dashboard."""
    from pathlib import Path
    import json
    from datetime import datetime, timezone, timedelta

    print("\n== DECISION AUTOMATION LAYER ==")

    # Load DAL audit log (last 24 hours)
    log_file = Path(f"logs/dal/dal_decisions.jsonl")
    if not log_file.exists():
        print("No DAL decisions logged yet.")
        return

    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    t1 = t2 = t3 = 0
    human_queue = []

    with open(log_file) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            ts = datetime.fromisoformat(entry.get("timestamp", "1970-01-01T00:00:00+00:00"))
            if ts < cutoff:
                continue
            tier = entry.get("tier")
            if tier == 1:
                t1 += 1
            elif tier == 2:
                t2 += 1
            elif tier == 3:
                t3 += 1
                human_queue.append(entry)

    print(f"Last 24h:")
    print(f"  Tier 1 (auto-closed):     {t1} alerts")
    print(f"  Tier 2 (auto-remediated): {t2} alerts")
    print(f"  Tier 3 (human queue):     {t3} alerts  ← {len(human_queue)} pending review")

    if human_queue:
        print("\nHuman Queue (review within 2 hours):")
        for item in human_queue[-5:]:  # Show last 5
            print(f"  [{item['timestamp'][:16]}] {item.get('severity', 'unknown').upper()} "
                  f"| {item.get('client_id', 'N/A')} | {item.get('reason', 'N/A')[:60]}")


def print_dashboard():
    clients = load_clients()
    width = 72
    print("\n" + "=" * width)
    print(f"  🛡️  SYNAPSE SOC FACTORY — Operational Dashboard")
    print(f"  📅  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * width)

    # ── System Health ──
    print(f"\n  {'─' * 30} SYSTEM HEALTH {'─' * 26}")
    
    gemini = check_gemini_health()
    gem_icon = "✅" if gemini.get("status") == "online" else "⚠️" if gemini.get("status") == "rate_limited" else "❌"
    gem_detail = gemini.get("model", gemini.get("reason", gemini.get("error", "unknown")))
    print(f"  {gem_icon} Gemini API : {gemini.get('status', 'unknown')} ({gem_detail})")
    
    tg = check_telegram_health()
    tg_icon = "✅" if tg.get("status") == "online" else "❌"
    tg_detail = f"@{tg['bot']}" if tg.get("bot") else tg.get("error", tg.get("status"))
    print(f"  {tg_icon} Telegram   : {tg.get('status', 'unknown')} ({tg_detail})")
    
    soar_mode = os.getenv("SOAR_DRY_RUN", "true")
    soar_icon = "🔒" if soar_mode.lower() == "true" else "🔥"
    print(f"  {soar_icon} SOAR Mode  : {'DRY RUN' if soar_mode.lower() == 'true' else 'LIVE'}")

    display_dal_stats()


    # ── Revenue ──
    rev = get_revenue_summary(clients)
    print(f"\n  {'─' * 30} REVENUE {'─' * 32}")
    print(f"  📊 Registered Clients : {len(clients)}")
    print(f"  💰 Paying Clients     : {rev.get('active_paying', 0)}")
    print(f"  🔵 Pilots/Demo        : {rev.get('pilots', 0)}")
    print(f"  💵 MRR                : JOD {rev.get('mrr', 0):,.0f}")
    if rev.get('overdue_invoices', 0):
        print(f"  🔴 Overdue Invoices   : {rev['overdue_invoices']}")
    for exp in rev.get('expiring_soon', []):
        print(f"  ⚠️  Expiring           : {exp['client']} — {exp['days_left']} days left")

    # ── Clients ──
    if not clients:
        print("\n  ⚠️  No clients registered.")
        print("=" * width + "\n")
        return
    
    print(f"\n  {'─' * 30} CLIENTS {'─' * 32}")
    for client in clients:
        name     = client.get("client_name", "Unknown")
        tier     = client.get("service_tier", "N/A")
        target   = client.get("primary_target", "N/A")
        industry = client.get("industry", "N/A")
        freq     = client.get("scan_frequency", "N/A")
        fee      = client.get("monthly_fee", 0)
        
        fee_str = f"JOD {fee}" if isinstance(fee, (int, float)) and fee > 0 else "pilot"
        
        print(f"\n  ┌─ {name} [{tier.upper()}] — {fee_str}")
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
    print(f"  Tools: 8 | Playbooks: 6 | Engine: Phase 29")
    print("=" * width + "\n")

if __name__ == "__main__":
    print_dashboard()
