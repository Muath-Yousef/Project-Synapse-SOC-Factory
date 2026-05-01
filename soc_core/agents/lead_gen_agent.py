"""
Lead Generation Agent — scores and qualifies leads from public data.
Pre-scans DNS only. Full scan only after lead confirms opt-in.

Phase 6 Deliverable 6.1
"""

import socket
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class Lead:
    domain: str
    company_name: str
    country: str
    industry: str
    employee_estimate: int
    email: str
    score: int = 0
    score_breakdown: dict = field(default_factory=dict)
    pre_scan_findings: list = field(default_factory=list)


def score_lead(lead: Lead) -> Lead:
    """
    Score lead 0-100. Minimum 50 to contact.
    Only uses passive DNS checks — no full scan without opt-in.
    """
    score = 0
    breakdown = {}

    # +20: website active
    try:
        socket.setdefaulttimeout(5)
        socket.gethostbyname(lead.domain)
        score += 20
        breakdown["website_active"] = 20
    except socket.error:
        breakdown["website_active"] = 0

    # +20: no HTTPS redirect (cleartext HTTP active)
    try:
        import urllib.request
        resp = urllib.request.urlopen(f"http://{lead.domain}", timeout=5)
        final_url = resp.url
        if not final_url.startswith("https://"):
            score += 20
            breakdown["no_https"] = 20
            lead.pre_scan_findings.append("No HTTPS redirect — cleartext HTTP active")
        else:
            breakdown["no_https"] = 0
    except Exception:
        breakdown["no_https"] = 0

    # +20: missing SPF or DMARC (passive DNS check)
    spf_missing = not _has_spf(lead.domain)
    dmarc_missing = not _has_dmarc(lead.domain)

    if spf_missing:
        score += 10
        breakdown["no_spf"] = 10
        lead.pre_scan_findings.append("Missing SPF record — email spoofing risk")
    else:
        breakdown["no_spf"] = 0

    if dmarc_missing:
        score += 10
        breakdown["no_dmarc"] = 10
        lead.pre_scan_findings.append("Missing DMARC record — phishing exposure")
    else:
        breakdown["no_dmarc"] = 0

    # +15: high-value industry
    high_value_industries = {"education", "finance", "healthcare", "legal", "insurance"}
    if lead.industry.lower() in high_value_industries:
        score += 15
        breakdown["high_value_industry"] = 15
    else:
        breakdown["high_value_industry"] = 0

    # +15: right employee size (SMB sweet spot)
    if 20 <= lead.employee_estimate <= 200:
        score += 15
        breakdown["right_size"] = 15
    else:
        breakdown["right_size"] = 0

    # +10: target market (Jordan, UAE, Saudi Arabia, Kuwait)
    if lead.country.lower() in {"jordan", "uae", "saudi arabia", "kuwait"}:
        score += 10
        breakdown["target_market"] = 10
    else:
        breakdown["target_market"] = 0

    # -30: government entity (out of scope)
    if any(lead.domain.endswith(suffix) for suffix in [".gov.jo", ".gov.ae", ".gov.sa"]):
        score -= 30
        breakdown["government_penalty"] = -30

    lead.score = max(0, score)
    lead.score_breakdown = breakdown
    return lead


def _has_spf(domain: str) -> bool:
    """Passive check: does domain have SPF TXT record?"""
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, "TXT")
        for r in answers:
            if "v=spf1" in str(r):
                return True
    except Exception:
        pass
    return False


def _has_dmarc(domain: str) -> bool:
    """Passive check: does domain have DMARC TXT record?"""
    try:
        import dns.resolver
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for r in answers:
            if "v=DMARC1" in str(r):
                return True
    except Exception:
        pass
    return False


def is_existing_client(domain: str) -> bool:
    """Check if domain is already a SOC Root client — never re-prospect clients."""
    try:
        import yaml
    except ImportError:
        return False

    client_dir = Path("knowledge/client_profiles")
    if not client_dir.exists():
        return False
    for yaml_file in client_dir.glob("*.yaml"):
        try:
            with open(yaml_file, encoding="utf-8") as f:
                client = yaml.safe_load(f)
                if client and client.get("domain", "").lower() == domain.lower():
                    return True
        except Exception:
            continue
    return False


def process_leads_batch(leads: list[Lead], min_score: int = 50) -> list[Lead]:
    """Score batch of leads, filter by minimum score, skip existing clients."""
    qualified = []
    for lead in leads:
        if is_existing_client(lead.domain):
            print(f"⏭️  Skip existing client: {lead.domain}")
            continue
        scored = score_lead(lead)
        if scored.score >= min_score:
            qualified.append(scored)
            findings_str = " | ".join(scored.pre_scan_findings) or "No immediate findings"
            print(f"✅ Qualified: {lead.domain} (score: {scored.score}) — {findings_str}")
        else:
            print(f"❌ Below threshold: {lead.domain} (score: {scored.score})")
    return sorted(qualified, key=lambda x: x.score, reverse=True)
