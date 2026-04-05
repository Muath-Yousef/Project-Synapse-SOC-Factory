#!/usr/bin/env python3
import os, sys, yaml, argparse, logging
from datetime import datetime
from pathlib import Path

# Setup path for root imports
sys.path.insert(0, '/media/kyrie/VMs1/Cybersecurity_Tools_Automation')
os.chdir('/media/kyrie/VMs1/Cybersecurity_Tools_Automation')

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ContractManager")

PROFILES_DIR = "knowledge/client_profiles"

class ContractManager:
    def __init__(self):
        self.profiles = self._load_profiles()

    def _load_profiles(self):
        profiles = []
        for f in os.listdir(PROFILES_DIR):
            if f.endswith(".yaml"):
                with open(os.path.join(PROFILES_DIR, f), 'r') as file:
                    try:
                        profiles.append(yaml.safe_load(file))
                    except Exception: pass
        return profiles

    def show_revenue(self):
        print("\n💰 [SOC Financial Status]")
        print("-" * 30)
        total_mrr = 0
        for p in self.profiles:
            billing = p.get("billing", {})
            fee = billing.get("monthly_fee", 0)
            total_mrr += fee
            print(f"- {p['client_name']:<15}: {fee:>6} {billing.get('currency', 'USD')}/mo")
        
        print("-" * 30)
        print(f"Total MRR: {total_mrr:>6} USD")
        print("-" * 30)

    def show_expiring(self, threshold_days=30):
        print(f"\n⚠️ [Expiring Contracts - Next {threshold_days} Days]")
        print("-" * 50)
        now = datetime.now()
        found = False
        for p in self.profiles:
            end_str = p.get("billing", {}).get("contract_end", "")
            if not end_str: continue
            
            end_date = datetime.strptime(end_str, "%Y-%m-%d")
            delta = (end_date - now).days
            
            if delta <= threshold_days:
                found = True
                status = "🔴 EXPIRED" if delta < 0 else f"🟡 {delta} days left"
                print(f"- {p['client_name']:<15} | End: {end_str} | Status: {status}")
        
        if not found:
            print("No contracts expiring soon. Business is stable.")
        print("-" * 50)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Synapse Contract & Revenue Manager")
    parser.add_argument("--revenue", action="store_true", help="Show Monthly Recurring Revenue (MRR)")
    parser.add_argument("--expiring", type=int, nargs="?", const=30, help="Show contracts expiring within N days (default 30)")
    
    args = parser.parse_args()
    manager = ContractManager()
    
    if args.revenue: manager.show_revenue()
    if args.expiring is not None: manager.show_expiring(args.expiring)
    if not any(vars(args).values()):
        parser.print_help()
