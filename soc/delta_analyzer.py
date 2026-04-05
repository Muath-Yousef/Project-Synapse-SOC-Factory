import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

class DeltaAnalyzer:
    """
    Compares two aggregated scan payloads to detect infrastructure drift,
    security regressions, and reconnaissance expansion.
    Part of Phase 19: Priority 2.
    """

    def analyze(self, old_scan: Dict[str, Any], new_scan: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Returns a dictionary of changes categorized by type.
        """
        deltas = {
            "new_ports": [],
            "closed_ports": [],
            "new_vulnerabilities": [],
            "resolved_vulnerabilities": [],
            "new_subdomains": [],
            "dns_changes": []
        }

        if not old_scan:
            return deltas # First scan, no delta possible

        # 1. Compare Ports/Services
        old_ports = self._extract_ports(old_scan)
        new_ports = self._extract_ports(new_scan)
        
        for ip_port, info in new_ports.items():
            if ip_port not in old_ports:
                deltas["new_ports"].append({"target": ip_port.split(":")[0], "port": ip_port.split(":")[1], "service": info.get("service")})
        
        for ip_port, info in old_ports.items():
            if ip_port not in new_ports:
                deltas["closed_ports"].append({"target": ip_port.split(":")[0], "port": ip_port.split(":")[1], "service": info.get("service")})

        # 2. Compare Vulnerabilities
        old_vulns = self._extract_vulns(old_scan)
        new_vulns = self._extract_vulns(new_scan)
        
        for vid, info in new_vulns.items():
            if vid not in old_vulns:
                deltas["new_vulnerabilities"].append(info)
        
        for vid, info in old_vulns.items():
            if vid not in new_vulns:
                deltas["resolved_vulnerabilities"].append(info)

        # 3. Compare Subdomains
        old_subs = set(old_scan.get("subdomains", []))
        new_subs = set(new_scan.get("subdomains", []))
        
        for sub in new_subs - old_subs:
            deltas["new_subdomains"].append(sub)

        return deltas

    def _extract_ports(self, scan: Dict[str, Any]) -> Dict[str, Dict]:
        ports = {}
        for target in scan.get("targets", []):
            ip = target.get("ip")
            for p in target.get("open_ports", []):
                key = f"{ip}:{p.get('port')}"
                ports[key] = p
        return ports

    def _extract_vulns(self, scan: Dict[str, Any]) -> Dict[str, Dict]:
        vulns = {}
        for target in scan.get("targets", []):
            for v in target.get("vulnerabilities", []):
                key = v.get("vuln_id", v.get("name"))
                vulns[key] = v
        return vulns
