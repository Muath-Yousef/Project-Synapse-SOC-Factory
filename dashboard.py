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
    """Calculate MRR and contract status from client profiles."""
    mrr = 0
    active = 0
    expiring_soon = 0
    for c in clients:
        fee = c.get("monthly_fee", 0)
        if isinstance(fee, (int, float)) and fee > 0:
            mrr += fee
            active += 1
        # Check contract expiry
        end = c.get("contract_end")
        if end:
            try:
                end_dt = datetime.fromisoformat(str(end))
                days_left = (end_dt - datetime.now()).days
                if 0 < days_left <= 30:
                    expiring_soon += 1
            except Exception:
                pass
    return {"mrr": mrr, "active_paying": active, "expiring_soon": expiring_soon}

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

    # ── Revenue ──
    rev = get_revenue_summary(clients)
    print(f"\n  {'─' * 30} REVENUE {'─' * 32}")
    print(f"  📊 Registered Clients : {len(clients)}")
    print(f"  💰 Paying Clients     : {rev['active_paying']}")
    print(f"  💵 MRR                : JOD {rev['mrr']:,.0f}")
    if rev['expiring_soon']:
        print(f"  ⚠️  Expiring (30 days) : {rev['expiring_soon']}")

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
