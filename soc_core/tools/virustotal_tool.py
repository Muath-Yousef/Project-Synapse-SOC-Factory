import requests
import os
import logging
import json
from typing import Dict, Any
from tools.base_tool import BaseTool

logger = logging.getLogger(__name__)

class VirusTotalTool(BaseTool):
    """
    Checks IP/URL reputation using VirusTotal API (v3).
    Part of Phase 12: Managed SOC Operations.
    """

    def __init__(self):
        self.api_key = os.getenv("VT_API_KEY")
        self.base_url = "https://www.virustotal.com/api/v3"

    def get_description(self) -> str:
        return "Checks IP/URL reputation via VirusTotal API."

    def run(self, target: str) -> str:
        """
        Standard entry point for the orchestrator.
        Currently supports IP checks.
        """
        if not self.api_key:
            logger.warning("[VTTool] VT_API_KEY is missing. Skipping reputation check.")
            return json.dumps({"status": "skipped", "reason": "API key missing"}, indent=2)
            
        results = self.check_ip(target)
        return json.dumps(results, indent=2)

    def check_ip(self, ip: str) -> Dict[str, Any]:
        """
        Consults VT for the given IP address.
        """
        logger.info(f"[VTTool] Checking reputation for IP: {ip}")
        headers = { "x-apikey": self.api_key }
        
        try:
            response = requests.get(f"{self.base_url}/ip_addresses/{ip}", headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                
                severity = "low"
                if malicious > 3: severity = "critical"
                elif malicious > 0: severity = "high"
                elif suspicious > 0: severity = "medium"
                
                return {
                    "target": ip,
                    "status": "success",
                    "findings": [{
                        "type": "reputation_vt",
                        "malicious_count": malicious,
                        "suspicious_count": suspicious,
                        "severity": severity,
                        "description": f"VirusTotal found {malicious} malicious reports for this IP."
                    }]
                }
            elif response.status_code == 401:
                return {"status": "error", "reason": "Unauthorized (Invalid VT API Key)"}
            else:
                return {"status": "error", "reason": f"API Error: {response.status_code}"}
        except Exception as e:
            logger.error(f"[VTTool] Request failed: {e}")
            return {"status": "error", "reason": str(e)}
