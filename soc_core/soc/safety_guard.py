import ipaddress
from typing import Union, List, Tuple

# Phase 1: Internal Protection
PROTECTED_RANGES = [
    "127.0.0.0/8",       # Loopback
    "10.0.0.0/8",        # RFC1918
    "172.16.0.0/12",     # RFC1918
    "192.168.0.0/16",    # RFC1918
    "169.254.0.0/16",    # Link-local
]

# Phase 13: CDN Protection (Prevents automated blocking of legitimate infrastructure)
CDN_RANGES = [
    # Cloudflare
    "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "104.16.0.0/13", "104.24.0.0/14", "108.162.192.0/18",
    "131.0.235.0/24", "141.101.64.0/18", "162.158.0.0/15",
    "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
    "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
    # Akamai broad range
    "23.0.0.0/12",
    # Fastly
    "151.101.0.0/16",
    # AWS CloudFront
    "13.32.0.0/15", "13.35.0.0/16", "52.84.0.0/15",
]

class SafetyGuard:
    def __init__(self, client_whitelist: List[str] = None):
        # Initialize internal ranges
        self.protected = [ipaddress.ip_network(r) for r in PROTECTED_RANGES]
        # Initialize CDN ranges
        self.cdn_networks = [ipaddress.ip_network(r) for r in CDN_RANGES]
        
        self.client_wl = []
        for ip in (client_whitelist or []):
            try:
                self.client_wl.append(ipaddress.ip_address(ip))
            except ValueError:
                continue

    def is_safe_to_block(self, ip: str) -> Tuple[bool, str]:
        """
        Safety check before SOAR execution.
        Returns: (True, "ok") or (False, "reason")
        """
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False, f"Invalid IP format: {ip}"

        # 1. Internal/RFC check
        for network in self.protected:
            if addr in network:
                return False, f"Protected RFC range: {network}"

        # 2. CDN infrastructure check (Phase 13)
        for network in self.cdn_networks:
            if addr in network:
                return False, "CDN infrastructure IP - not a threat actor"

        # 3. Client explicit whitelist
        if addr in self.client_wl:
            return False, f"Client whitelisted IP: {ip}"

        return True, "ok"
