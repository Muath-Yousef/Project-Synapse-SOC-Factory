import ipaddress
from typing import Union, List, Tuple

PROTECTED_RANGES = [
    "127.0.0.0/8",       # Loopback
    "10.0.0.0/8",        # RFC1918
    "172.16.0.0/12",     # RFC1918
    "192.168.0.0/16",    # RFC1918
    "169.254.0.0/16",    # Link-local
]

class SafetyGuard:
    def __init__(self, client_whitelist: List[str] = None):
        self.protected = [ipaddress.ip_network(r) for r in PROTECTED_RANGES]
        self.client_wl = []
        for ip in (client_whitelist or []):
            try:
                self.client_wl.append(ipaddress.ip_address(ip))
            except ValueError:
                continue

    def is_safe_to_block(self, ip: str) -> Tuple[bool, str]:
        """
        Returns: (True, "ok") or (False, "reason")
        The Orchestrator must check this before every Block.
        """
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False, f"Invalid IP format: {ip}"

        for network in self.protected:
            if addr in network:
                return False, f"Protected RFC range: {network}"

        if addr in self.client_wl:
            return False, f"Client whitelisted IP: {ip}"

        return True, "ok"
