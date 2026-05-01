import dns.resolver
import logging
import json
from typing import Dict, List, Any
from tools.base_tool import BaseTool

logger = logging.getLogger(__name__)

class DNSTool(BaseTool):
    """
    Analyzes DNS records for security hygiene (SPF, DMARC, MX).
    Part of Phase 12: Email Security Retainer.
    """
    
    COMMON_DKIM_SELECTORS = [
        "google", "default", "mail", "k1", "k2",
        "selector1", "selector2", "dkim", "email",
        "zoho", "sendgrid", "mailchimp", "mandrill"
    ]

    EMAIL_PROVIDER_SELECTORS = {
        "google.com"       : ["google"],
        "googlemail.com"   : ["google"],
        "outlook.com"      : ["selector1", "selector2"],
        "hotmail.com"      : ["selector1", "selector2"],
        "sendgrid.net"     : ["s1", "s2", "smtpapi"],
        "mailgun.org"      : ["k1", "k2"],
        "amazonses.com"    : ["amazon"],
        "mimecast.com"     : ["mc1"],
        "proofpoint.com"   : ["pp1"],
    }

    def __init__(self):
        super().__init__("DNSTool")

    def get_description(self) -> str:
        return "Analyzes DNS records (SPF, DMARC, MX) for security compliance."

    def run(self, target: str) -> str:
        """
        Standard entry point for the orchestrator.
        """
        results = self.scan(target)
        return json.dumps(results, indent=2)

    def scan(self, target: str) -> Dict[str, Any]:
        """
        Queries SPF, DMARC, and MX records for a domain.
        """
        logger.info(f"[DNSTool] Analyzing security records for: {target}")
        
        # Clean target (strip http/https if present)
        domain = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
        
        results = {
            "target": domain,
            "status": "success",
            "findings": []
        }

        # 1. Check SPF
        spf_record = self._get_txt_record(domain, "v=spf1")
        if spf_record:
            results["findings"].append({
                "type": "dns_spf",
                "record": spf_record,
                "severity": "low" if "-all" in spf_record or "~all" in spf_record else "medium",
                "description": "SPF record found for domain."
            })
        else:
            results["findings"].append({
                "type": "dns_spf_missing",
                "severity": "high",
                "description": "Missing SPF record! Domain is vulnerable to spoofing."
            })

        # 2. Check DMARC
        dmarc_record = self._get_txt_record(f"_dmarc.{domain}", "v=DMARC1")
        if dmarc_record:
            policy = "none"
            if "p=reject" in dmarc_record: policy = "reject"
            elif "p=quarantine" in dmarc_record: policy = "quarantine"
            
            results["findings"].append({
                "type": "dns_dmarc",
                "record": dmarc_record,
                "policy": policy,
                "severity": "low" if policy in ["reject", "quarantine"] else "medium",
                "description": f"DMARC record found with policy: {policy}."
            })
        else:
            results["findings"].append({
                "type": "dns_dmarc_missing",
                "severity": "high",
                "description": "Missing DMARC record! High risk of unauthorized email usage."
            })

        # 3. Check MX
        mx_records = self._get_mx_records(domain)
        if mx_records:
            results["findings"].append({
                "type": "dns_mx",
                "records": mx_records,
                "severity": "info",
                "description": "Mail server records found."
            })

        # 4. Check DKIM (Selector Discovery)
        dkim_results = self.check_dkim(domain)
        if dkim_results["status"] == "found":
            for dkim in dkim_results["dkim_records"]:
                results["findings"].append({
                    "type": "dns_dkim",
                    "selector": dkim["selector"],
                    "record": dkim["record"],
                    "severity": "low",
                    "description": f"Verified DKIM selector found: {dkim['selector']}"
                })
        else:
            results["findings"].append({
                "type": "dns_dkim_not_found",
                "severity": "medium",
                "description": "No common DKIM selectors discovered. Manual verification recommended.",
                "note": dkim_results.get("note", "")
            })

        # 5. Check BIMI (Brand Identity)
        bimi_record = self._get_txt_record(f"default._bimi.{domain}", "v=BIMI1")
        if bimi_record:
            results["findings"].append({
                "type": "dns_bimi",
                "record": bimi_record,
                "severity": "low",
                "description": "BIMI record found for domain."
            })
        else:
            results["findings"].append({
                "type": "dns_bimi_missing",
                "severity": "info",
                "description": "BIMI record not found. Optional but recommended for brand identity."
            })

        # 6. Check for SMTP Open Relay (Security Critical)
        mx_hosts = [r.split()[-1].rstrip(".") for r in self._get_mx_records(domain)]
        for mx in mx_hosts[:2]: # Check top 2 MX servers
            if self._is_open_relay(mx):
                results["findings"].append({
                    "type": "smtp_open_relay",
                    "target": mx,
                    "severity": "critical",
                    "description": f"SMTP server {mx} appears to be an OPEN RELAY! High security risk."
                })
        
        return results

    def _is_open_relay(self, mx_host: str) -> bool:
        """
        Attempts a basic SMTP handshake to check for unauthenticated relaying.
        Very conservative check to avoid being flagged.
        """
        import smtplib, socket
        try:
            # We connect and try to RCPT TO an external address
            server = smtplib.SMTP(mx_host, 25, timeout=10)
            server.ehlo("synapse-soc.com")
            server.mail("test@synapse-soc.com")
            # This is the critical part: can we send to an external domain?
            code, msg = server.rcpt("synapse_relay_test@gmail.com")
            server.quit()
            
            # code 250 means OK, which indicates open relay
            return code == 250
        except Exception:
            return False

    def check_dkim(self, domain: str) -> dict:
        """
        DKIM Selector Discovery (Best-effort).
        Includes wildcard detection to prevent false positives from DNS spoofing.
        """
        # Provider-specific selectors first (higher accuracy)
        priority_selectors = self._detect_provider_selectors(domain)
        all_selectors = priority_selectors + [
            s for s in self.COMMON_DKIM_SELECTORS if s not in priority_selectors
        ]
        
        found_records = []  # List of results
        seen_content = {}   # To detect wildcards (content -> count)
        
        for selector in all_selectors:
            try:
                dkim_domain = f"{selector}._domainkey.{domain}"
                # Using a slightly longer lifetime for reliability
                answers = dns.resolver.resolve(dkim_domain, "TXT", lifetime=5)
                for rdata in answers:
                    txt = "".join([t.decode() if isinstance(t, bytes) else str(t) for t in rdata.strings])
                    
                    # Stricter validation: must have v=DKIM1 and a non-empty p= (unless revoked)
                    if "v=DKIM1" in txt and (" p=" in txt or ";p=" in txt):
                        # Track content to find wildcards later
                        seen_content[txt] = seen_content.get(txt, 0) + 1
                        
                        found_records.append({
                            "selector": selector,
                            "record": txt,
                            "key_type": "rsa" if "k=rsa" in txt else "unknown"
                        })
            except Exception:
                continue

        # Wildcard Detection: If many selectors return the exact same record, it's likely a wildcard DNS
        # and not a set of unique DKIM signatures.
        valid_findings = []
        for record in found_records:
            content = record["record"]
            # If the same record appears for 4+ selectors, it's probably a catch-all
            if seen_content[content] < 4:
                # Basic sanity check on p= length (usually 100+ chars for RSA)
                p_part = ""
                for part in content.split(";"):
                    if part.strip().startswith("p="):
                        p_part = part.partition("=")[2].strip()
                
                if len(p_part) > 10: # Real keys are long. Revoked or placeholders are short.
                    valid_findings.append(record)

        return {
            "status": "found" if valid_findings else "not_discovered",
            "selectors_checked": len(all_selectors),
            "dkim_records": valid_findings,
            "note": "Manual selector verification required if none found" if not valid_findings else ""
        }

    def _detect_provider_selectors(self, domain: str) -> list:
        """
        Reads MX records to infer the email provider and prioritize selectors.
        """
        provider_selectors = []
        try:
            mx_records = dns.resolver.resolve(domain, "MX", lifetime=5)
            for mx in mx_records:
                mx_host = str(mx.exchange).lower().rstrip(".")
                for provider, selectors in self.EMAIL_PROVIDER_SELECTORS.items():
                    if provider in mx_host:
                        provider_selectors.extend(selectors)
        except Exception:
            pass
        return list(dict.fromkeys(provider_selectors))  # dedup while maintaining order

    def _get_txt_record(self, domain: str, prefix: str) -> str:
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                txt = "".join([t.decode() if isinstance(t, bytes) else str(t) for t in rdata.strings])
                if txt.startswith(prefix):
                    return txt
        except Exception:
            return None
        return None

    def _get_mx_records(self, domain: str) -> List[str]:
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            return [f"{rdata.preference} {rdata.exchange}" for rdata in answers]
        except Exception:
            return []
