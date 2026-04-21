"""
Client-Ready Executive Report Generator
========================================
Produces a business-oriented PDF from scan JSON data.
Does NOT modify or depend on report_generator.py.

Usage:
    python reports/client_report_generator.py \\
        --scan knowledge/history/asasedu_scan_1776718396.json \\
        --client "Asas Educational Platform" \\
        --domain asas4edu.net \\
        --output reports/output/asasEdu_executive_report_2026-04.pdf
"""

import json
import os
import sys
import argparse
import warnings
from datetime import datetime
from typing import Dict, Any, List

warnings.filterwarnings("ignore", category=DeprecationWarning, module="fpdf")
from fpdf import FPDF

# ---------------------------------------------------------------------------
# Color palette
# ---------------------------------------------------------------------------
CLR_HEADER  = (26, 26, 46)    # #1a1a2e  — dark navy
CLR_ACCENT  = (233, 69, 96)   # #e94560  — red accent
CLR_WHITE   = (255, 255, 255)
CLR_BODY    = (51, 51, 51)
CLR_MUTED   = (127, 140, 141)
CLR_BG_ROW  = (245, 245, 248)
CLR_GREEN   = (39, 174, 96)
CLR_ORANGE  = (211, 84, 0)
CLR_RED     = (192, 57, 43)
CLR_YELLOW  = (243, 156, 18)

# ---------------------------------------------------------------------------
# Finding-to-business mappings
# ---------------------------------------------------------------------------
FINDING_MAP = {
    "cleartext_http": {
        "risk": "Unencrypted website traffic",
        "severity": "Critical",
        "impact": "User data theft, legal liability",
        "priority": "P1 - Immediate",
        "phase": 1,
    },
    "dns_spf_missing": {
        "risk": "Email spoofing vulnerability (SPF)",
        "severity": "High",
        "impact": "Phishing attacks on clients/students",
        "priority": "P1 - Immediate",
        "phase": 1,
    },
    "dns_dmarc_missing": {
        "risk": "Email spoofing vulnerability (DMARC)",
        "severity": "High",
        "impact": "Phishing attacks on clients/students",
        "priority": "P1 - Immediate",
        "phase": 1,
    },
    "default_ssh": {
        "risk": "Exposed admin access (SSH)",
        "severity": "High",
        "impact": "Unauthorized server access",
        "priority": "P2 - This week",
        "phase": 2,
    },
    "dns_dkim_not_found": {
        "risk": "Missing email signatures (DKIM)",
        "severity": "Medium",
        "impact": "Spam delivery, trust issues",
        "priority": "P3 - This month",
        "phase": 2,
    },
    "dns_bimi_missing": {
        "risk": "Missing brand email indicator (BIMI)",
        "severity": "Info",
        "impact": "Reduced brand trust in email",
        "priority": "P4 - Improvement",
        "phase": 3,
    },
    "dns_mx": {
        "risk": "Mail routing configuration",
        "severity": "Info",
        "impact": "Informational — no direct risk",
        "priority": "N/A",
        "phase": 0,
    },
    "unknown": {
        "risk": "Unknown service exposed",
        "severity": "Low",
        "impact": "Expanded attack surface",
        "priority": "P3 - This month",
        "phase": 2,
    },
}

COMPLIANCE_MAP = [
    {
        "control": "NCA-2-1-3",
        "requirement": "Encryption in transit",
        "triggers": ["cleartext_http"],
        "status_pass": "PASS",
        "status_fail": "VIOLATION",
        "finding_text": "HTTP exposed without TLS",
    },
    {
        "control": "NCA-3-1-1",
        "requirement": "Access control",
        "triggers": ["default_ssh"],
        "status_pass": "PASS",
        "status_fail": "WARNING",
        "finding_text": "SSH on default port, publicly accessible",
    },
    {
        "control": "NCA-2-3-1",
        "requirement": "Email protection",
        "triggers": ["dns_spf_missing", "dns_dmarc_missing"],
        "status_pass": "PASS",
        "status_fail": "VIOLATION",
        "finding_text": "No SPF/DMARC records",
    },
]


# ============================================================================
# PDF Builder
# ============================================================================
class ClientReportPDF(FPDF):
    """Custom FPDF subclass with branded header/footer."""

    def __init__(self, client_name: str, domain: str):
        super().__init__()
        self.client_name = client_name
        self.domain = domain
        self.set_auto_page_break(auto=True, margin=30)

    # ----- footer on every page -----
    def footer(self):
        self.set_y(-20)
        self.set_font("helvetica", "I", 7)
        self.set_text_color(*CLR_MUTED)
        self.cell(
            0, 5,
            f"Confidential - Prepared exclusively for {self.client_name}"
            f" | Synapse Security | synapse.soc",
            align="C",
        )
        self.ln(4)
        self.cell(0, 5, f"Page {self.page_no()}/{{nb}}", align="C")

    # ----- helpers -----
    def _ew(self):
        """Effective writable width."""
        return self.w - self.l_margin - self.r_margin

    def _section_heading(self, number: int, title: str):
        """Render a numbered section heading with accent bar."""
        if self.get_y() > 240:
            self.add_page()
        self.set_font("helvetica", "B", 14)
        self.set_text_color(*CLR_HEADER)
        # accent bar
        self.set_fill_color(*CLR_ACCENT)
        self.rect(self.l_margin, self.get_y(), 3, 10, "F")
        self.set_x(self.l_margin + 6)
        self.cell(0, 10, f"{number}.  {title}", ln=True)
        self.ln(3)

    def _body_text(self, text: str, size: int = 10):
        self.set_font("helvetica", "", size)
        self.set_text_color(*CLR_BODY)
        self.set_x(self.l_margin)
        self.multi_cell(w=self._ew(), h=6, text=text)

    def _table_header(self, cols: List[str], widths: List[float]):
        self.set_font("helvetica", "B", 9)
        self.set_fill_color(*CLR_HEADER)
        self.set_text_color(*CLR_WHITE)
        for col, w in zip(cols, widths):
            self.cell(w, 8, col, border=0, fill=True, align="C")
        self.ln()
        self.set_text_color(*CLR_BODY)

    def _table_row(self, cells: List[str], widths: List[float], fill: bool = False):
        self.set_font("helvetica", "", 9)
        if fill:
            self.set_fill_color(*CLR_BG_ROW)
        h = 7
        x_start = self.get_x()
        max_lines = 1
        # multi-line height estimation
        for cell_text, w in zip(cells, widths):
            lines = self.multi_cell(w, h, cell_text, border=0, fill=fill,
                                     align="L", split_only=True)
            max_lines = max(max_lines, len(lines))
        row_h = max_lines * h
        # actually render
        self.set_x(x_start)
        y_before = self.get_y()
        for cell_text, w in zip(cells, widths):
            x_cur = self.get_x()
            self.multi_cell(w, h, cell_text, border=0, fill=fill, align="L")
            self.set_xy(x_cur + w, y_before)
        self.ln(row_h)


# ============================================================================
# Report Builder
# ============================================================================
class ClientReportGenerator:
    """Generates business-oriented executive PDF reports."""

    def __init__(self):
        pass

    def generate(
        self,
        scan_path: str,
        client_name: str,
        domain: str,
        output_path: str,
        ai_triage: str = "",
    ) -> str:
        with open(scan_path, "r") as f:
            scan_data = json.load(f)

        findings = scan_data.get("findings", [])
        finding_types = set(f.get("finding_type", "unknown") for f in findings)

        # Determine overall risk level
        severities = [f.get("severity", "low").lower() for f in findings]
        if "critical" in severities:
            risk_level = "CRITICAL"
            risk_explanation = "Multiple critical controls failing"
        elif severities.count("high") >= 2:
            risk_level = "HIGH"
            risk_explanation = "Several high-severity issues detected"
        elif "high" in severities:
            risk_level = "ELEVATED"
            risk_explanation = "High-severity issue requires attention"
        else:
            risk_level = "MODERATE"
            risk_explanation = "Issues found but manageable"

        actionable_count = sum(
            1 for f in findings
            if f.get("severity", "").lower() in ("critical", "high", "medium")
        )

        pdf = ClientReportPDF(client_name, domain)
        pdf.alias_nb_pages()

        # ====== SECTION 1: Cover Page ======
        self._cover_page(pdf, client_name, domain, risk_level, risk_explanation)

        # ====== SECTION 2: Executive Summary ======
        pdf.add_page()
        pdf._section_heading(1, "Executive Summary")
        summary = (
            f"This assessment evaluated the external security posture "
            f"of {domain}. We identified {actionable_count} issues requiring "
            f"immediate attention. Left unaddressed, these expose the "
            f"organization to data theft, brand impersonation, and "
            f"regulatory risk under the NCA Essential Cybersecurity "
            f"Controls framework."
        )
        pdf._body_text(summary)
        pdf.ln(6)

        # ====== SECTION 3: Risk Summary Table ======
        pdf._section_heading(2, "Risk Summary")
        self._risk_table(pdf, findings)
        pdf.ln(4)

        # ====== SECTION 4: Attack Scenario ======
        pdf._section_heading(3, "Realistic Attack Scenario")
        scenario = (
            f"A motivated attacker targeting {client_name} could first "
            f"intercept unencrypted user sessions on port 80 to harvest "
            f"credentials, then leverage the exposed SSH port to attempt "
            f"direct server access via brute-force. Simultaneously, the "
            f"attacker could launch phishing campaigns impersonating the "
            f"platform by exploiting the missing email security records "
            f"(SPF/DMARC) to target students and staff with convincing "
            f"fraudulent messages that appear to originate from "
            f"@{domain}."
        )
        pdf._body_text(scenario)
        pdf.ln(6)

        # ====== SECTION 5: Remediation Roadmap ======
        self._remediation_roadmap(pdf)

        # ====== SECTION 6: Compliance ======
        self._compliance_section(pdf, finding_types)

        # ====== SECTION 7: Methodology ======
        self._methodology_section(pdf, domain, scan_data)

        # ====== SECTION 8: About Synapse ======
        self._about_section(pdf)

        # Save
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        pdf.output(output_path)
        return output_path

    # ------------------------------------------------------------------
    # Section builders
    # ------------------------------------------------------------------
    def _cover_page(self, pdf: ClientReportPDF, client_name, domain, risk_level, risk_explanation):
        pdf.add_page()
        ew = pdf.w - pdf.l_margin - pdf.r_margin

        # Full-width dark header block
        pdf.set_fill_color(*CLR_HEADER)
        pdf.rect(0, 0, pdf.w, 120, "F")

        # Logo text
        pdf.set_y(30)
        pdf.set_font("helvetica", "B", 28)
        pdf.set_text_color(*CLR_WHITE)
        pdf.cell(0, 12, "SYNAPSE", align="C", ln=True)
        pdf.set_font("helvetica", "", 14)
        pdf.set_text_color(*CLR_ACCENT)
        pdf.cell(0, 8, "SECURITY", align="C", ln=True)

        # Divider line
        pdf.set_y(65)
        pdf.set_draw_color(*CLR_ACCENT)
        pdf.set_line_width(0.8)
        pdf.line(pdf.w * 0.3, 65, pdf.w * 0.7, 65)

        # Title
        pdf.set_y(75)
        pdf.set_font("helvetica", "B", 18)
        pdf.set_text_color(*CLR_WHITE)
        pdf.cell(0, 10, "Confidential Security Assessment", align="C", ln=True)

        # Risk badge
        pdf.set_y(135)
        badge_color = CLR_RED if risk_level == "CRITICAL" else CLR_ORANGE if risk_level in ("HIGH", "ELEVATED") else CLR_YELLOW
        pdf.set_fill_color(*badge_color)
        badge_w = 90
        badge_x = (pdf.w - badge_w) / 2
        pdf.set_xy(badge_x, 135)
        pdf.set_font("helvetica", "B", 16)
        pdf.set_text_color(*CLR_WHITE)
        pdf.cell(badge_w, 14, f"Risk Level: {risk_level}", align="C", fill=True, ln=True)
        pdf.set_x(badge_x)
        pdf.set_font("helvetica", "I", 10)
        pdf.set_text_color(*CLR_MUTED)
        pdf.cell(badge_w, 8, risk_explanation, align="C", ln=True)

        # Meta info
        pdf.set_y(175)
        pdf.set_font("helvetica", "", 12)
        pdf.set_text_color(*CLR_BODY)
        meta = [
            ("Prepared for:", client_name),
            ("Domain:", domain),
            ("Date:", datetime.now().strftime("%B %d, %Y")),
            ("Prepared by:", "Synapse Security Team"),
        ]
        for label, value in meta:
            pdf.set_x(pdf.l_margin + 20)
            pdf.set_font("helvetica", "", 11)
            pdf.cell(45, 9, label)
            pdf.set_font("helvetica", "B", 11)
            pdf.cell(0, 9, value, ln=True)

    def _risk_table(self, pdf: ClientReportPDF, findings):
        ew = pdf._ew()
        col_w = [ew * 0.30, ew * 0.15, ew * 0.32, ew * 0.23]
        pdf._table_header(["Risk", "Severity", "Business Impact", "Priority"], col_w)

        seen = set()
        row_idx = 0
        # Sort by severity order
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            findings,
            key=lambda x: sev_order.get(x.get("severity", "low").lower(), 5)
        )

        for f in sorted_findings:
            ft = f.get("finding_type", "unknown")
            if ft in seen:
                continue
            seen.add(ft)
            info = FINDING_MAP.get(ft, FINDING_MAP["unknown"])
            if info["priority"] == "N/A":
                continue  # skip purely informational
            sev = info["severity"]

            # Color the severity text
            pdf.set_font("helvetica", "", 9)
            fill = row_idx % 2 == 1
            if fill:
                pdf.set_fill_color(*CLR_BG_ROW)

            x_start = pdf.get_x()
            y_start = pdf.get_y()

            # Render each cell carefully
            cells = [info["risk"], sev, info["impact"], info["priority"]]

            # Calculate required row height
            max_h = 7
            for text, w in zip(cells, col_w):
                lines = pdf.multi_cell(w, 7, text, split_only=True)
                max_h = max(max_h, len(lines) * 7)

            # Draw background
            if fill:
                pdf.set_fill_color(*CLR_BG_ROW)
                pdf.rect(pdf.l_margin, y_start, ew, max_h, "F")

            # Render cells
            pdf.set_xy(x_start, y_start)
            for i, (text, w) in enumerate(zip(cells, col_w)):
                cx = pdf.l_margin + sum(col_w[:i])
                pdf.set_xy(cx, y_start)
                if i == 1:  # severity column — color it
                    if sev == "Critical":
                        pdf.set_text_color(*CLR_RED)
                    elif sev == "High":
                        pdf.set_text_color(*CLR_ORANGE)
                    elif sev == "Medium":
                        pdf.set_text_color(*CLR_YELLOW)
                    else:
                        pdf.set_text_color(*CLR_BODY)
                    pdf.set_font("helvetica", "B", 9)
                else:
                    pdf.set_text_color(*CLR_BODY)
                    pdf.set_font("helvetica", "", 9)
                pdf.multi_cell(w, 7, text)

            pdf.set_y(y_start + max_h)
            row_idx += 1

    def _remediation_roadmap(self, pdf: ClientReportPDF):
        pdf._section_heading(4, "Remediation Roadmap")
        ew = pdf._ew()

        phases = [
            {
                "title": "Phase 1 - Immediate (0-7 days)",
                "color": CLR_RED,
                "items": [
                    "Enable HTTPS and redirect all HTTP traffic",
                    "Add SPF record to prevent email spoofing",
                    "Add DMARC policy record",
                ],
            },
            {
                "title": "Phase 2 - Short-term (7-30 days)",
                "color": CLR_ORANGE,
                "items": [
                    "Restrict SSH access via firewall rules (whitelist IPs only)",
                    "Implement DKIM email signing",
                    "Enable security monitoring",
                ],
            },
            {
                "title": "Phase 3 - Hardening (30-90 days)",
                "color": CLR_YELLOW,
                "items": [
                    "Deploy WAF (Web Application Firewall)",
                    "Implement BIMI for brand trust",
                    "Establish monthly security review",
                ],
            },
        ]

        for phase in phases:
            if pdf.get_y() > 240:
                pdf.add_page()
            # Phase title with colored indicator
            pdf.set_fill_color(*phase["color"])
            pdf.rect(pdf.l_margin, pdf.get_y() + 1, 3, 7, "F")
            pdf.set_x(pdf.l_margin + 6)
            pdf.set_font("helvetica", "B", 11)
            pdf.set_text_color(*CLR_HEADER)
            pdf.cell(0, 9, phase["title"], ln=True)

            # Items
            pdf.set_font("helvetica", "", 10)
            pdf.set_text_color(*CLR_BODY)
            for item in phase["items"]:
                pdf.set_x(pdf.l_margin + 10)
                pdf.multi_cell(w=ew - 10, h=6, text=f"  {item}")
            pdf.ln(4)

    def _compliance_section(self, pdf: ClientReportPDF, finding_types: set):
        pdf._section_heading(5, "Compliance Status (NCA ECC 2.0)")
        ew = pdf._ew()
        col_w = [ew * 0.18, ew * 0.27, ew * 0.20, ew * 0.35]
        pdf._table_header(["Control", "Requirement", "Status", "Finding"], col_w)

        row_idx = 0
        for ctrl in COMPLIANCE_MAP:
            triggered = any(t in finding_types for t in ctrl["triggers"])
            status = ctrl["status_fail"] if triggered else ctrl["status_pass"]
            finding_text = ctrl["finding_text"] if triggered else "No issue detected"

            fill = row_idx % 2 == 1
            y_start = pdf.get_y()

            if fill:
                pdf.set_fill_color(*CLR_BG_ROW)
                pdf.rect(pdf.l_margin, y_start, ew, 8, "F")

            cells = [ctrl["control"], ctrl["requirement"], status, finding_text]
            for i, (text, w) in enumerate(zip(cells, col_w)):
                cx = pdf.l_margin + sum(col_w[:i])
                pdf.set_xy(cx, y_start)
                if i == 2:  # status column
                    if "VIOLATION" in status:
                        pdf.set_text_color(*CLR_RED)
                        pdf.set_font("helvetica", "B", 9)
                    elif "WARNING" in status:
                        pdf.set_text_color(*CLR_ORANGE)
                        pdf.set_font("helvetica", "B", 9)
                    else:
                        pdf.set_text_color(*CLR_GREEN)
                        pdf.set_font("helvetica", "B", 9)
                else:
                    pdf.set_text_color(*CLR_BODY)
                    pdf.set_font("helvetica", "", 9)
                pdf.multi_cell(w, 8, text)

            pdf.set_y(y_start + 8)
            row_idx += 1

        pdf.ln(4)

    def _methodology_section(self, pdf: ClientReportPDF, domain: str, scan_data: dict):
        pdf._section_heading(6, "Methodology and Scope")
        ew = pdf._ew()

        subdomains = scan_data.get("subdomains", [])
        sub_str = ", ".join(subdomains) if subdomains else "none discovered"

        items = [
            ("Assessment Type:", "External Passive Reconnaissance"),
            ("Scope:", f"{domain} and discovered subdomains ({sub_str})"),
            ("Tools:", "Port scanning, vulnerability templates, DNS analysis, subdomain enumeration"),
            ("Limitations:", "No authenticated testing. No internal network access."),
        ]

        for label, value in items:
            pdf.set_x(pdf.l_margin)
            pdf.set_font("helvetica", "B", 10)
            pdf.set_text_color(*CLR_HEADER)
            pdf.cell(40, 7, label)
            pdf.set_font("helvetica", "", 10)
            pdf.set_text_color(*CLR_BODY)
            pdf.multi_cell(w=ew - 40, h=7, text=value)
            pdf.ln(1)

        pdf.ln(3)
        pdf.set_x(pdf.l_margin)
        pdf.set_font("helvetica", "I", 9)
        pdf.set_text_color(*CLR_MUTED)
        pdf.multi_cell(
            w=ew, h=6,
            text="This assessment reflects the attacker's external view only. "
                 "Internal vulnerabilities, misconfigurations, or application-level "
                 "issues are not covered by this scope."
        )

    def _about_section(self, pdf: ClientReportPDF):
        pdf._section_heading(7, "About Synapse Security")
        pdf._body_text(
            "Synapse Security provides automated managed security services "
            "for SMBs. Our platform delivers continuous monitoring, "
            "vulnerability assessment, and compliance reporting - making "
            "enterprise-grade security accessible and affordable. We combine "
            "AI-powered threat analysis with expert human oversight to "
            "protect your digital assets around the clock."
        )


# ============================================================================
# CLI entry point
# ============================================================================
def main():
    parser = argparse.ArgumentParser(description="Generate client-ready executive PDF report")
    parser.add_argument("--scan", required=True, help="Path to scan JSON file")
    parser.add_argument("--client", default="Asas Educational Platform", help="Client display name")
    parser.add_argument("--domain", default="asas4edu.net", help="Primary domain")
    parser.add_argument("--output", default="reports/output/asasEdu_executive_report_2026-04.pdf",
                        help="Output PDF path")
    args = parser.parse_args()

    # Resolve paths relative to project root
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    scan_path = os.path.join(project_root, args.scan) if not os.path.isabs(args.scan) else args.scan
    output_path = os.path.join(project_root, args.output) if not os.path.isabs(args.output) else args.output

    gen = ClientReportGenerator()
    result = gen.generate(
        scan_path=scan_path,
        client_name=args.client,
        domain=args.domain,
        output_path=output_path,
    )
    print(f"PDF generated: {result}")


if __name__ == "__main__":
    main()
