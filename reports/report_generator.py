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

    def generate_markdown_report(self, target_ip: str, client_id: str, client_context: str, scan_data: Dict[str, Any], triage_verdict: str) -> str:
        logger.info(f"[ReportGenerator] Assembling Markdown report for [{client_id}] -> {target_ip}...")
        
        # Extract variables reliably
        targets = scan_data.get("targets", [])
        host_info = targets[0] if targets else {}
        open_ports = host_info.get("open_ports", [])
        
        # Formatting ports for organized markdown
        port_lines = []
        for p in open_ports:
            # We cast to dict or handle the port struct accurately
            if isinstance(p, dict):
                port_num = p.get('port', 'Unknown')
                protocol = str(p.get('protocol', 'tcp')).upper()
                svc = getattr(p, 'service', p.get('service', 'Unknown'))
                ver = p.get('version', '')
                line = f"- **Port {port_num}/{protocol}** \t— Service: `{svc}` " + (f"(Version: {ver})" if ver and ver != 'Unknown' else "")
            else:
                line = f"- {str(p)}"
            port_lines.append(line)
            
        ports_md = "\n".join(port_lines) if port_lines else "- No open ports discovered on target."
        
        # Format vulnerabilities
        vulns = host_info.get("vulnerabilities", [])
        vuln_lines = []
        for v in vulns:
            sev = v.get("severity", "INFO")
            name = v.get("name", "Unknown")
            desc = v.get("description", "")
            vuln_lines.append(f"- **[{sev}]** {name} : {desc}")
        vulns_md = "\n".join(vuln_lines) if vuln_lines else "- No explicit remote vulnerabilities identified by template scanner."

        # Format subdomains (Phase 12.2 / 13)
        subdomains = scan_data.get("subdomains", [])
        subdomain_count = scan_data.get("subdomain_count", 0)
        subdomains_md = ""
        if subdomain_count > 0:
            subdomain_list = "\n".join([f"| {s} | Active |" for s in subdomains])
            subdomains_md = f"""
---

## 3. Attack Surface — Discovered Subdomains
The following subdomains were identified via passive reconnaissance (subfinder):

| Subdomain | Status |
|-----------|--------|
{subdomain_list}

> [!NOTE]
> Each subdomain represents an additional attack vector requiring individual assessment.
"""

        if not client_context or client_context == "No Context Found":
            context_formatted = "_No client infrastructure context located._"
        else:
            context_formatted = f"```yaml\n{str(client_context).strip()}\n```"

        markdown = f"""# 🛡️ Synapse Security Report for [{client_id}]

## 1. Executive Summary
- **Target IP investigated:** `{target_ip}`
- **Report Status:** Finalized (Automated AI Triage)

**Verdict from AI Triage Engine:**
> {triage_verdict.strip()}

---

## 2. Technical Details
### Discovery & Mapping
The following services were identified on the target infrastructure during the automated scan phase:
{ports_md}

### Vulnerabilities
The following template-based findings were detected:
{vulns_md}
{subdomains_md}
---

## 4. Context Applied (Memory Layer)
The Orchestrator actively analyzed the raw data against the following known infrastructure baseline parameters to filter false positives:
{context_formatted}
"""
        return markdown

    def save_report(self, content: str, filename: str) -> str:
        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        logger.info(f"[ReportGenerator] Report physically saved to disk at: {filepath}")
        return filepath
