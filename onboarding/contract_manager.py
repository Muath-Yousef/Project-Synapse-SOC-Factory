"""
Contract Manager — financial tracking, invoice management, renewal alerts.
Phase 5 Deliverable 5.2
"""

import json
import os
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

CONTRACT_DIR = Path("knowledge/client_profiles")


class ContractManager:
    """
    Contract Manager — financial tracking, invoice management, renewal alerts.
    """
    def __init__(self, contract_dir=CONTRACT_DIR):
        self.contract_dir = Path(contract_dir)
        self.profiles = self.load_profiles()

    def load_profiles(self) -> list[dict]:
        """Load all client profiles."""
        if not YAML_AVAILABLE:
            raise ImportError("PyYAML required — pip install pyyaml")
        clients = []
        for yaml_file in self.contract_dir.glob("*.yaml"):
            try:
                with open(yaml_file, encoding="utf-8") as f:
                    client = yaml.safe_load(f)
                    if client:
                        clients.append(client)
            except Exception:
                continue
        return clients

    def calculate_mrr(self) -> float:
        """Calculate Monthly Recurring Revenue from all active clients."""
        return sum(
            float(c.get("billing", {}).get("monthly_fee", 0) if "billing" in c else c.get("monthly_fee", 0))
            for c in self.profiles
            if c.get("status", "active") == "active" or c.get("billing", {}).get("status") == "active"
        )

    def get_expiring_contracts(self, days_ahead: int = 30) -> list[dict]:
        """Find contracts expiring within N days."""
        now = datetime.now(timezone.utc)
        expiring = []

        for client in self.profiles:
            billing = client.get("billing", {})
            expiry_str = billing.get("contract_end") or client.get("contract_end")
            if not expiry_str:
                continue
            try:
                expiry = datetime.fromisoformat(expiry_str)
                if expiry.tzinfo is None:
                    expiry = expiry.replace(tzinfo=timezone.utc)
                days_to_expiry = (expiry - now).days
                if 0 <= days_to_expiry <= days_ahead:
                    expiring.append({
                        "client_id": client.get("client_id") or client.get("client_name", "unknown").lower().replace(" ", "_"),
                        "domain": client.get("domain"),
                        "expiry_date": expiry_str,
                        "days_remaining": days_to_expiry,
                        "monthly_fee": billing.get("monthly_fee") or client.get("monthly_fee", 0),
                    })
            except (ValueError, TypeError):
                continue

        return sorted(expiring, key=lambda x: x["days_remaining"])

    def get_overdue_invoices(self) -> list[dict]:
        """Find clients with overdue payment status."""
        return [
            c for c in self.profiles
            if c.get("billing", {}).get("payment_status") == "overdue" or c.get("payment_status") == "overdue"
        ]

    def generate_revenue_report(self) -> dict:
        """Complete revenue dashboard data."""
        active = [c for c in self.profiles if c.get("status", "active") == "active" or c.get("billing", {}).get("status") == "active"]
        mrr = self.calculate_mrr()
        expiring = self.get_expiring_contracts(30)
        overdue = self.get_overdue_invoices()

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "active_clients": len(active),
            "mrr_usd": mrr,
            "arr_usd": mrr * 12,
            "expiring_this_month": len(expiring),
            "overdue_invoices": len(overdue),
            "overdue_amount": sum(float(c.get("billing", {}).get("monthly_fee", 0) if "billing" in c else c.get("monthly_fee", 0)) for c in overdue),
            "clients_by_tier": {
                "soc_lite": sum(1 for c in active if c.get("service_tier") == "soc_lite" or c.get("tier") == "soc_lite"),
                "soc_standard": sum(1 for c in active if c.get("service_tier") == "soc_standard" or c.get("tier") == "soc_standard"),
                "soc_pro": sum(1 for c in active if c.get("service_tier") == "soc_pro" or c.get("tier") == "soc_pro"),
                "soc_grc": sum(1 for c in active if c.get("service_tier") == "soc_grc" or c.get("tier") == "soc_grc"),
            },
            "expiring_details": expiring,
            "overdue_details": [
                {"client_id": c.get("client_id") or c.get("client_name", "unknown").lower().replace(" ", "_"), "fee": c.get("billing", {}).get("monthly_fee") or c.get("monthly_fee")}
                for c in overdue
            ],
        }

    def send_renewal_alerts(self):
        """Send Telegram alerts for contracts expiring in 30 days."""
        expiring = self.get_expiring_contracts(30)
        if not expiring:
            print("✅ No contracts expiring in the next 30 days")
            return

        bot_token = os.getenv("TELEGRAM_BOT_TOKEN")
        chat_id = os.getenv("TELEGRAM_CHAT_ID_ACTIONS")

        if not bot_token or not chat_id:
            print("⚠️  Telegram credentials not set — TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID_ACTIONS")
            for contract in expiring:
                print(f"  ⚠️  {contract['client_id']} expires in {contract['days_remaining']} days (${contract['monthly_fee']}/mo)")
            return

        for contract in expiring:
            message = (
                f"⚠️ Contract Expiring Soon\n\n"
                f"Client: {contract['client_id']}\n"
                f"Domain: {contract['domain']}\n"
                f"Expires: {contract['expiry_date'][:10]}\n"
                f"Days remaining: {contract['days_remaining']}\n"
                f"MRR at risk: ${contract['monthly_fee']}/mo\n\n"
                f"Action: Initiate renewal conversation"
            )

            data = urllib.parse.urlencode({
                "chat_id": chat_id,
                "text": message,
            }).encode()

            req = urllib.request.Request(
                f"https://api.telegram.org/bot{bot_token}/sendMessage",
                data=data,
                method="POST",
            )
            try:
                urllib.request.urlopen(req)
                print(f"✅ Renewal alert sent for {contract['client_id']}")
            except Exception as e:
                print(f"❌ Failed to send alert for {contract['client_id']}: {e}")


# ── COMPATIBILITY WRAPPERS ──────────────────────────────────────────────────
def get_all_clients():
    return ContractManager().profiles

def calculate_mrr():
    return ContractManager().calculate_mrr()

def get_expiring_contracts(days_ahead=30):
    return ContractManager().get_expiring_contracts(days_ahead)

def get_overdue_invoices():
    return ContractManager().get_overdue_invoices()

def generate_revenue_report():
    return ContractManager().generate_revenue_report()

def send_renewal_alerts():
    ContractManager().send_renewal_alerts()


if __name__ == "__main__":
    report = generate_revenue_report()
    print("== SOC Root Revenue Dashboard ==")
    print(f"Active Clients: {report['active_clients']}")
    print(f"MRR:            ${report['mrr_usd']:,.0f}")
    print(f"ARR:            ${report['arr_usd']:,.0f}")
    print(f"Expiring 30d:   {report['expiring_this_month']}")
    print(f"Overdue:        {report['overdue_invoices']} (${report['overdue_amount']:,.0f})")
    print(f"\nBy Tier: {report['clients_by_tier']}")

