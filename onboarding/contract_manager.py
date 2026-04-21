#!/usr/bin/env python3
"""
Contract Manager — Phase 30.3
================================
Tracks payment status, contract expiry, invoice generation.
Integrated into dashboard.py revenue section.

Usage:
    python3 onboarding/contract_manager.py --status
    python3 onboarding/contract_manager.py --expiring 30
    python3 onboarding/contract_manager.py --overdue
    python3 onboarding/contract_manager.py --invoice --client AsasEdu
"""
import os, sys, yaml, argparse, logging
from datetime import datetime
from pathlib import Path

sys.path.insert(0, '/media/kyrie/VMs1/Cybersecurity_Tools_Automation')
os.chdir('/media/kyrie/VMs1/Cybersecurity_Tools_Automation')

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ContractManager")

PROFILES_DIR = Path("knowledge/client_profiles")
INVOICE_DIR  = Path("reports/invoices")


class ContractManager:
    def __init__(self):
        self.profiles = self._load_profiles()

    def _load_profiles(self):
        profiles = []
        for f in PROFILES_DIR.glob("*.yaml"):
            if f.name.startswith("_"):
                continue  # skip templates
            try:
                with open(f) as fp:
                    data = yaml.safe_load(fp)
                    if data and "client_name" in data:
                        profiles.append(data)
            except Exception:
                pass
        return profiles

    # ── Helpers ────────────────────────────────────────────────────────────
    def _billing(self, p: dict) -> dict:
        return p.get("billing") or {}

    def _parse_date(self, s: str):
        if not s:
            return None
        try:
            return datetime.fromisoformat(str(s))
        except Exception:
            return None

    def _days_left(self, p: dict) -> int | None:
        end = self._parse_date(self._billing(p).get("contract_end"))
        if not end:
            return None
        return (end - datetime.now()).days

    # ── Public methods ──────────────────────────────────────────────────────
    def get_mrr(self) -> float:
        """Total monthly recurring revenue in JOD."""
        return sum(
            self._billing(p).get("monthly_fee", 0) or 0
            for p in self.profiles
        )

    def get_summary(self) -> dict:
        """Full revenue + contract summary for dashboard."""
        mrr = 0
        active_paying = 0
        pilots = 0
        overdue = 0
        expiring_soon = []
        for p in self.profiles:
            b = self._billing(p)
            fee = b.get("monthly_fee", 0) or 0
            status = b.get("payment_status", "pending")
            days = self._days_left(p)
            if fee > 0:
                mrr += fee
                active_paying += 1
            else:
                pilots += 1
            if status == "overdue":
                overdue += 1
            if days is not None and 0 < days <= 30:
                expiring_soon.append({"client": p["client_name"], "days_left": days})
        return {
            "mrr": mrr,
            "active_paying": active_paying,
            "pilots": pilots,
            "overdue_invoices": overdue,
            "expiring_soon": expiring_soon,
        }

    def show_status(self):
        """Print full contract status table."""
        width = 70
        print("\n" + "=" * width)
        print("  💼  SYNAPSE — Contract & Revenue Status")
        print(f"  📅  {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        print("=" * width)
        summary = self.get_summary()
        print(f"\n  MRR          : JOD {summary['mrr']:,.0f}")
        print(f"  Paying       : {summary['active_paying']}")
        print(f"  Pilots       : {summary['pilots']}")
        print(f"  Overdue      : {summary['overdue_invoices']}")
        if summary["expiring_soon"]:
            print(f"  Expiring soon: {len(summary['expiring_soon'])}")

        print(f"\n  {'Client':<18} {'Tier':<14} {'Fee':>8} {'Status':<10} {'End Date':<12} {'Days'}")
        print("  " + "─" * 66)
        for p in self.profiles:
            b       = self._billing(p)
            fee     = b.get("monthly_fee", 0) or 0
            status  = b.get("payment_status", "pilot")
            end_str = str(b.get("contract_end", "—"))[:10]
            days    = self._days_left(p)
            days_s  = f"{days}d" if days is not None else "—"
            tier    = p.get("service_tier", "—")
            icon    = "⚠️" if (days is not None and 0 < days <= 30) else \
                      "🔴" if status == "overdue" else \
                      "✅" if fee > 0 else "🔵"
            print(f"  {icon} {p['client_name']:<16} {tier:<14} {fee:>6} JOD  {status:<10} {end_str:<12} {days_s}")
        print("=" * width + "\n")

    def show_expiring(self, threshold_days: int = 30):
        print(f"\n⚠️  Contracts expiring within {threshold_days} days:")
        found = False
        for p in self.profiles:
            days = self._days_left(p)
            if days is not None and days <= threshold_days:
                found = True
                label = "EXPIRED" if days < 0 else f"{days} days left"
                print(f"  - {p['client_name']}: {label}")
        if not found:
            print("  None — all contracts active.")

    def show_overdue(self):
        print("\n🔴 Overdue invoices:")
        found = False
        for p in self.profiles:
            if self._billing(p).get("payment_status") == "overdue":
                fee = self._billing(p).get("monthly_fee", 0) or 0
                print(f"  - {p['client_name']}: JOD {fee}")
                found = True
        if not found:
            print("  None — all payments current.")

    def generate_invoice(self, client_name: str) -> str:
        """Generate a simple text-based invoice PDF for a client."""
        profile = next((p for p in self.profiles
                        if p["client_name"].lower() == client_name.lower()), None)
        if not profile:
            raise ValueError(f"Client not found: {client_name}")

        b      = self._billing(profile)
        fee    = b.get("monthly_fee", 0) or 0
        month  = datetime.now().strftime("%B %Y")
        inv_no = f"INV-{datetime.now().strftime('%Y%m')}-{profile['client_name'][:4].upper()}"
        INVOICE_DIR.mkdir(parents=True, exist_ok=True)
        out_path = INVOICE_DIR / f"{inv_no}.pdf"

        try:
            from fpdf import FPDF
            pdf = FPDF()
            pdf.add_page()
            # Header
            pdf.set_font("Helvetica", "B", 20)
            pdf.set_text_color(26, 26, 46)
            pdf.cell(0, 12, "SYNAPSE SECURITY", align="C", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 11)
            pdf.set_text_color(127, 140, 141)
            pdf.cell(0, 8, "Managed Security Services", align="C", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(8)
            # Invoice meta
            pdf.set_font("Helvetica", "B", 14)
            pdf.set_text_color(26, 26, 46)
            pdf.cell(0, 10, f"Invoice: {inv_no}", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 11)
            pdf.set_text_color(51, 51, 51)
            pdf.cell(0, 7, f"Date: {datetime.now().strftime('%B %d, %Y')}", new_x="LMARGIN", new_y="NEXT")
            pdf.cell(0, 7, f"Period: {month}", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(8)
            # Bill to
            pdf.set_font("Helvetica", "B", 11)
            pdf.cell(0, 7, "Bill To:", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 11)
            pdf.cell(0, 7, profile.get("client_name", ""), new_x="LMARGIN", new_y="NEXT")
            pdf.cell(0, 7, profile.get("contact_email", ""), new_x="LMARGIN", new_y="NEXT")
            pdf.ln(8)
            # Service line
            pdf.set_fill_color(26, 26, 46)
            pdf.set_text_color(255, 255, 255)
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(100, 8, "Service", fill=True)
            pdf.cell(50, 8, "Tier", fill=True)
            pdf.cell(0, 8, "Amount (JOD)", fill=True, new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(51, 51, 51)
            pdf.set_font("Helvetica", "", 10)
            pdf.cell(100, 8, "Managed Security Service")
            pdf.cell(50, 8, profile.get("service_tier", "").upper())
            pdf.cell(0, 8, f"JOD {fee:,.0f}", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(6)
            # Total
            pdf.set_font("Helvetica", "B", 13)
            pdf.set_text_color(233, 69, 96)
            pdf.cell(0, 10, f"Total Due: JOD {fee:,.0f}", align="R", new_x="LMARGIN", new_y="NEXT")
            # Footer
            pdf.set_y(-30)
            pdf.set_font("Helvetica", "I", 8)
            pdf.set_text_color(127, 140, 141)
            pdf.cell(0, 5, "Thank you for trusting Synapse Security. Payment due within 14 days.", align="C")
            pdf.output(str(out_path))
            logger.info(f"[ContractManager] Invoice generated: {out_path}")
            return str(out_path)
        except Exception as e:
            # Fallback: plain text invoice
            txt_path = str(out_path).replace(".pdf", ".txt")
            with open(txt_path, "w") as f:
                f.write(f"SYNAPSE SECURITY — INVOICE\n{'='*40}\n")
                f.write(f"Invoice No : {inv_no}\n")
                f.write(f"Date       : {datetime.now().strftime('%Y-%m-%d')}\n")
                f.write(f"Period     : {month}\n")
                f.write(f"Client     : {profile.get('client_name')}\n")
                f.write(f"Service    : Managed Security ({profile.get('service_tier')})\n")
                f.write(f"Amount     : JOD {fee:,.0f}\n")
            logger.warning(f"PDF generation failed ({e}), saved text invoice: {txt_path}")
            return txt_path

    def alert_expiring(self, threshold_days: int = 30):
        """Send Telegram alert for contracts expiring soon."""
        expiring = [p for p in self.profiles
                    if (d := self._days_left(p)) is not None and 0 < d <= threshold_days]
        if not expiring:
            return
        try:
            from soc.connectors.telegram_connector import TelegramConnector
            tg = TelegramConnector()
            msg = f"⚠️ CONTRACT EXPIRY ALERT\n"
            for p in expiring:
                days = self._days_left(p)
                msg += f"  • {p['client_name']}: {days} days left\n"
            tg.send(msg, channel="actions")
        except Exception as e:
            logger.error(f"[ContractManager] Expiry alert failed: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Synapse Contract & Revenue Manager")
    parser.add_argument("--status",   action="store_true", help="Show full contract status table")
    parser.add_argument("--expiring", type=int, nargs="?", const=30,
                        help="Contracts expiring within N days (default 30)")
    parser.add_argument("--overdue",  action="store_true", help="Show overdue invoices")
    parser.add_argument("--invoice",  action="store_true", help="Generate invoice for client")
    parser.add_argument("--client",   default=None, help="Client name (required for --invoice)")
    parser.add_argument("--alert",    action="store_true", help="Send Telegram expiry alerts")

    args = parser.parse_args()
    manager = ContractManager()

    if args.status:   manager.show_status()
    if args.expiring is not None: manager.show_expiring(args.expiring)
    if args.overdue:  manager.show_overdue()
    if args.invoice:
        if not args.client:
            print("❌ --invoice requires --client <name>")
            sys.exit(1)
        path = manager.generate_invoice(args.client)
        print(f"✅ Invoice: {path}")
    if args.alert:    manager.alert_expiring()
    if not any(vars(args).values()):
        parser.print_help()
