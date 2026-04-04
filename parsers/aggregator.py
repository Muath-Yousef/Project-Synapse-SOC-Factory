import logging
import socket
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

def resolve_to_ip(target: str) -> str:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return target

class Aggregator:
    """
    Takes unified output from multiple tools (e.g. Nmap, Nuclei)
    and combines them into a single, cohesive "Target Summary" JSON payload 
    specifically optimized for LLM token efficiency and Context logic.
    """
    
    def __init__(self):
        # We will hold state per target IP
        self.targets_db = {}

    def ingest(self, parsed_data: Dict[str, Any]):
        """
        Ingests parsed output from a tool and merges it into the internal DB.
        """
        scanner = parsed_data.get("scanner", "unknown")
        
        # Currently handling Nmap payload integration
        if scanner == "nmap":
            for host in parsed_data.get("hosts", []):
                ip = host.get("ip")
                if not ip or ip == "Unknown":
                    continue
                
                # Initialize host record if it doesn't exist
                if ip not in self.targets_db:
                    self.targets_db[ip] = {
                        "ip": ip,
                        "status": host.get("status", "Unknown"),
                        "open_ports": [],
                        "vulnerabilities": [],
                        "dns_records": [],
                        "reputation_stats": {}
                    }
                
                # Merge port data
                for port in host.get("ports", []):
                    # Simple deduplication just in case
                    if port not in self.targets_db[ip]["open_ports"]:
                        self.targets_db[ip]["open_ports"].append(port)
                        
        elif "nuclei_findings" in parsed_data:
            for finding in parsed_data["nuclei_findings"]:
                ip = resolve_to_ip(finding.get("target", "Unknown"))
                if not ip or ip == "Unknown":
                    continue
                if ip not in self.targets_db:
                    self.targets_db[ip] = {
                        "ip": ip,
                        "status": "Unknown",
                        "open_ports": [],
                        "vulnerabilities": [],
                        "dns_records": [],
                        "reputation_stats": {}
                    }
                if "vulnerabilities" not in self.targets_db[ip]:
                    self.targets_db[ip]["vulnerabilities"] = []
                self.targets_db[ip]["vulnerabilities"].append({
                    "vuln_id": finding.get("vuln_id"),
                    "name": finding.get("vuln_name"),
                    "severity": finding.get("severity"),
                    "description": finding.get("description")
                })
                
        elif "dns_findings" in parsed_data or "findings" in parsed_data and any(f.get("type", "").startswith("dns") for f in parsed_data.get("findings", [])):
            # Support both direct key and flattened findings from DNSTool/VTTool
            findings_list = parsed_data.get("findings", [])
            target = parsed_data.get("target", "Unknown")
            ip = resolve_to_ip(target)
            
            if ip not in self.targets_db:
                self.targets_db[ip] = {"ip": ip, "status": "Unknown", "open_ports": [], "vulnerabilities": [], "dns_records": [], "reputation_stats": {}}
            
            for f in findings_list:
                if f.get("type", "").startswith("dns"):
                    self.targets_db[ip]["dns_records"].append(f)
                elif f.get("type", "").startswith("reputation"):
                    self.targets_db[ip]["reputation_stats"] = f
                        
    def filter_false_positives(self):
        """
        Placeholder logic. In the final system, this will query ChromaDB context
        to see if an open port or vulnerability is actually an expected business service.
        """
        logger.info("[Aggregator] Running False-Positive context filters (Mock)...")
        # No concrete filters for Phase 1

    def get_final_payload(self) -> Dict[str, Any]:
        """
        Returns the optimized Target Summary dictionary.
        """
        self.filter_false_positives()
        
        # Extract findings for easier SOAR consumption
        findings = []
        for ip, host in self.targets_db.items():
            for port in host.get("open_ports", []):
                # Simple logic to tag clearing HTTP and default SSH
                ftype = "unknown"
                severity = "low"
                if port.get("port") == 80:
                    ftype = "cleartext_http"
                    severity = "critical"
                elif port.get("port") == 22:
                    ftype = "default_ssh"
                    severity = "high"
                
                findings.append({
                    "target_ip": ip,
                    "finding_type": ftype,
                    "severity": severity,
                    "source": "nmap",
                    "port": port.get("port")
                })
            
            for vuln in host.get("vulnerabilities", []):
                findings.append({
                    "target_ip": ip,
                    "finding_type": "cve",
                    "severity": vuln.get("severity", "medium").lower(),
                    "source": "nuclei",
                    "vuln_id": vuln.get("vuln_id"),
                    "name": vuln.get("name")
                })

            for dns in host.get("dns_records", []):
                findings.append({
                    "target_ip": ip,
                    "finding_type": dns.get("type"),
                    "severity": dns.get("severity", "low").lower(),
                    "source": "dns_tool",
                    "description": dns.get("description")
                })

            rep = host.get("reputation_stats", {})
            if rep:
                findings.append({
                    "target_ip": ip,
                    "finding_type": rep.get("type"),
                    "severity": rep.get("severity", "low").lower(),
                    "source": "vt_tool",
                    "description": rep.get("description"),
                    "malicious_count": rep.get("malicious_count", 0)
                })

        return {
            "summary_type": "DataStandardization",
            "targets": list(self.targets_db.values()),
            "findings": findings
        }
