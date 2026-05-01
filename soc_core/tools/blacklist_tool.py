import socket
import logging
from typing import Dict, Any, List
from tools.base_tool import BaseTool

logger = logging.getLogger(__name__)

class BlacklistTool(BaseTool):
    """
    Checks if a target IP is blacklisted in major RBLs (Real-time Blackhole Lists).
    Uses DNS-based lookups for speed and cost-efficiency.
    """

    def __init__(self):
        super().__init__("Blacklist Checker")

    DEFAULT_RBLS = [
        "zen.spamhaus.org",
        "bl.spamcop.net",
        "b.barracudacentral.org",
        "dnsbl.sorbs.net",
        "spam.dnsbl.sorbs.net"
    ]

    def get_description(self):
        return "Checks if an IP is globally blacklisted (RBL). Essential for email deliverability and reputation auditing."

    def validate_input(self, target: str) -> bool:
        # Basic check if it's an IP. Domains should be resolved before calling this.
        try:
            socket.inet_aton(target.split(":")[0])
            return True
        except socket.error:
            return False

    def run(self, target: str, arguments: str = "") -> dict:
        host = target.split(":")[0]
        logger.info(f"[BlacklistTool] Auditing reputation for {host}...")
        
        # RBL lookup format: reversed_ip.rbl_domain
        # e.g., 1.2.3.4 -> 4.3.2.1.zen.spamhaus.org
        reversed_ip = ".".join(reversed(host.split(".")))
        
        hits = []
        for rbl in self.DEFAULT_RBLS:
            query = f"{reversed_ip}.{rbl}"
            try:
                # Any response (e.g., 127.0.0.2) means blacklisted
                socket.gethostbyname(query)
                hits.append(rbl)
                logger.warning(f"[BlacklistTool] HIT: {host} is blacklisted on {rbl}")
            except (socket.gaierror, socket.error):
                # gaierror means no record found (Clean)
                pass

        if hits:
            return {
                "status": "blacklisted",
                "target": host,
                "hit_count": len(hits),
                "rbls": hits,
                "finding_type": "reputation_blacklist",
                "severity": "high" if len(hits) > 1 else "medium",
                "description": f"IP is listed on {len(hits)} global blacklists: {', '.join(hits)}"
            }
        
        return {
            "status": "clean",
            "target": host,
            "hit_count": 0,
            "rbls": [],
            "finding_type": "reputation_clean",
            "severity": "info",
            "description": "IP is not listed on major global RBLs."
        }

if __name__ == "__main__":
    tool = BlacklistTool()
    # Test with a common test IP (127.0.0.2 is usually a hit in RBL test regimes)
    print(tool.run("127.0.0.2"))
