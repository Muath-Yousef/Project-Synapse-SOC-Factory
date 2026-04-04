from tools.base_tool import BaseTool
import subprocess
import json
import os
import time
import ipaddress
import logging

logger = logging.getLogger(__name__)

class SubfinderTool(BaseTool):
    """
    Subfinder integration for passive subdomain reconnaissance.
    Standardized for Project Synapse SOC Factory.
    """

    def __init__(self):
        super().__init__("subfinder")

    def get_description(self):
        return "Passive subdomain enumeration. Use during reconnaissance on domain targets only. Do not use on raw IP addresses."

    def validate_input(self, target: str) -> bool:
        """
        Subfinder fails on raw IPs. This method enforces domain targets.
        """
        try:
            # Check if it's a valid IP
            ipaddress.ip_address(target.split(":")[0])
            return False  # IP rejected
        except ValueError:
            return True  # Domain accepted

    def run(self, target: str, arguments: str = "") -> dict:
        """
        Executes subfinder and returns standardized JSON.
        """
        # Clean target: remove protocol. subdomain.domain.com only.
        domain = target.replace("http://", "").replace("https://", "").split(":")[0].split("/")[-1]
        
        if not self.validate_input(domain):
            logger.error(f"[SubfinderTool] Target {domain} rejected: subfinder requires a domain, not an IP.")
            return {"status": "error", "error": "subfinder requires a domain, not an IP", "subdomains": [], "count": 0}

        output_file = f"/tmp/subfinder_{domain}_{int(time.time())}.json"
        # -silent to avoid banner, -json for parser
        command = ["subfinder", "-d", domain, "-silent", "-json", "-o", output_file, "-timeout", "30"]

        try:
            logger.info(f"[SubfinderTool] Starting passive reconnaissance for {domain}...")
            subprocess.run(command, capture_output=True, text=True, timeout=60)
            
            subdomains = []
            if os.path.exists(output_file):
                with open(output_file, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                entry = json.loads(line)
                                # Subfinder JSON can be line-delimited objects with 'host' key
                                subdomains.append(entry.get("host", entry) if isinstance(entry, dict) else str(entry))
                            except json.JSONDecodeError:
                                # Fallback for raw lines
                                if line:
                                    subdomains.append(line)
                os.remove(output_file)
            
            logger.info(f"[SubfinderTool] Completed. Found {len(subdomains)} subdomains.")
            return {
                "status": "success", 
                "target": domain, 
                "subdomains": subdomains, 
                "count": len(subdomains), 
                "source": "subfinder"
            }
        except subprocess.TimeoutExpired:
            logger.error(f"[SubfinderTool] Scan timed out for {domain}")
            return {"status": "timeout", "subdomains": [], "count": 0, "error": "Scan exceeded 60s"}
        except FileNotFoundError:
            logger.error("[SubfinderTool] subfinder binary not found in PATH")
            return {"status": "error", "subdomains": [], "count": 0, "error": "subfinder binary not found in PATH"}
