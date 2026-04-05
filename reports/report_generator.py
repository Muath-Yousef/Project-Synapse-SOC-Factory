import os
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

class ReportGenerator:
    """
    Generates intelligent and highly polished Markdown/PDF reports
    from the raw Orchestrator metrics and LLM triage verdicts.
    """
    def __init__(self, output_dir="reports/output"):
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        self.output_dir = os.path.join(base_dir, output_dir)
        os.makedirs(self.output_dir, exist_ok=True)

    def generate_markdown_report(self, target_ip: str, client_id: str, client_context: str, scan_data: Dict[str, Any], triage_verdict: str, delta_findings: Dict[str, Any] = None, compliance_results: Dict[str, Any] = None) -> str:
        logger.info(f"[ReportGenerator] Assembling Analytical report for [{client_id}] -> {target_ip}...")
        
        # 1. Formatting Security Posture Card
        score_md = ""
        if compliance_results:
            score = compliance_results.get("score", 0)
            grade = compliance_results.get("grade", "F")
            # Visual progress bar (roughly)
            bar = "█" * (score // 10) + "░" * (10 - (score // 10))
            score_md = f"""
## 1.1 Security Posture Score
| Metric | Value |
|--------|-------|
| **Score** | `{score}/100` |
| **Grade** | `{grade}` |
| **Status** | `[{bar}]` |

> [!TIP]
> This score is calculated based on weighted findings. A single Critical finding significantly impacts this metric.
"""

        # 2. Extract variables reliably
        targets = scan_data.get("targets", [])
        host_info = targets[0] if targets else {}
        open_ports = host_info.get("open_ports", [])
        
        # Formatting ports
        port_lines = []
        for p in open_ports:
            if isinstance(p, dict):
                port_num = p.get('port', 'Unknown')
                protocol = str(p.get('protocol', 'tcp')).upper()
                svc = p.get('service', 'Unknown')
                ver = p.get('version', '')
                line = f"- **Port {port_num}/{protocol}** \t— Service: `{svc}` " + (f"(Version: {ver})" if ver and ver != 'Unknown' else "")
            else:
                line = f"- {str(p)}"
            port_lines.append(line)
        ports_md = "\n".join(port_lines) if port_lines else "- No open ports discovered."
        
        # 3. Format vulnerabilities
        vulns = host_info.get("vulnerabilities", [])
        vuln_lines = []
        for v in vulns:
            sev = v.get("severity", "INFO")
            name = v.get("name", "Unknown")
            desc = v.get("description", "")
            vuln_lines.append(f"- **[{sev}]** {name} : {desc}")
        vulns_md = "\n".join(vuln_lines) if vuln_lines else "- No explicit remote vulnerabilities identified."

        # 4. Format Delta Analytics (Drift)
        delta_md = ""
        if delta_findings and any(delta_findings.values()):
            new_p = delta_findings.get("new_ports", [])
            new_v = delta_findings.get("new_vulnerabilities", [])
            new_s = delta_findings.get("new_subdomains", [])
            
            delta_lines = []
            if new_p: delta_lines.append("### 🆕 New Infrastructure Detected")
            for p in new_p: delta_lines.append(f"- Port `{p['port']}` ({p['service']}) discovered on {p['target']}")
            
            if new_v: delta_lines.append("### 🆕 New Vulnerabilities Detected")
            for v in new_v: delta_lines.append(f"- **[{v['severity']}]** {v.get('name')} ({v.get('vuln_id')})")
            
            if new_s: delta_lines.append("### 🆕 New Subdomains Discovered")
            for s in new_s: delta_lines.append(f"- {s}")
            
            delta_content = "\n".join(delta_lines)
            delta_md = f"""
---

## 2.2 Infrastructure Drift (Analysis since last scan)
{delta_content}

> [!IMPORTANT]
> Newly detected infrastructure usually represents the highest risk of unauthorized expansion.
"""
        else:
            delta_md = "\n---\n\n## 2.2 Infrastructure Drift\n- No changes detected since the previous automated audit."

        # 5. Format Reputation & Blacklists (Phase 20)
        reputation_md = ""
        blacklist_hits = [f for f in scan_data.get("findings", []) if f.get("finding_type") == "reputation_blacklist"]
        
        if blacklist_hits:
            hit = blacklist_hits[0]
            reputation_md = f"""
---

## 2.3 Global Reputation Analysis
> [!CAUTION]
> **Status: BLACKLISTED**
> This IP was found on {hit.get('hit_count')} global RBLs.
> **Impact:** High risk of email rejection and service blocking.
"""
        else:
            reputation_md = f"""
---

## 2.3 Global Reputation Analysis
> [!IMPORTANT]
> **Status: CLEAN**
> This IP is not listed on any major global blacklists (Spamhaus, Spamcop, etc.).
"""

        # 6. Format subdomains
        subdomains = scan_data.get("subdomains", [])
        subdomain_count = scan_data.get("subdomain_count", 0)
        subdomains_md = ""
        if subdomain_count > 0:
            subdomain_list = "\n".join([f"| {s} | Active |" for s in subdomains])
            subdomains_md = f"""
---

## 3. Attack Surface — Discovered Subdomains
| Subdomain | Status |
|-----------|--------|
{subdomain_list}
"""

        context_formatted = f"```yaml\n{str(client_context).strip()}\n```" if client_context != "No Context Found" else "_No context._"

        markdown = f"""# 🛡️ Synapse Security Report for [{client_id}]

## 1. Executive Summary
- **Target IP investigated:** `{target_ip}`
- **Report Status:** Finalized (Analytical Monitoring)

{score_md}

**Verdict from AI Triage Engine:**
> {triage_verdict.strip()}

---

## 2. Technical Details
### Discovery & Mapping
{ports_md}

### Vulnerabilities
{vulns_md}

{delta_md}

{subdomains_md}

---

## 4. Context Applied (Memory Layer)
{context_formatted}
"""
        return markdown

    def save_report(self, content: str, filename: str) -> str:
        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        logger.info(f"[ReportGenerator] Report physically saved to disk at: {filepath}")
        return filepath
