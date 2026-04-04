from abc import ABC, abstractmethod
import socket
import logging

logger = logging.getLogger(__name__)

class BaseTool(ABC):
    """
    Abstract Base Class for all security tools.
    Enforces safe target validation and standard execution interfaces.
    """
    
    def __init__(self, name: str):
        self.name = name

    def validate_target(self, target: str) -> bool:
        """
        Validates the target against unsafe or internal testing IP addresses.
        Prevents accidental scanning of unauthorized local infrastructure.
        """
        forbidden_targets = ["127.0.0.1", "localhost", "0.0.0.0", "::1"]
        if target.lower() in forbidden_targets:
            logger.warning(f"[{self.name}] Target {target} is in the forbidden list.")
            return False
            
        # Basic check to avoid internal IP ranges if needed (simplified for phase 1)
        # We can expand this to block 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 later
        try:
            # Check if it's a resolvable domain or valid IP
            socket.gethostbyname(target)
            return True
        except socket.gaierror:
            logger.warning(f"[{self.name}] Target {target} is unresolvable.")
            return False

    @abstractmethod
    def run(self, target: str, **kwargs) -> str:
        """
        Executes the tool against the target.
        Returns the raw output (e.g., XML/JSON) as a string.
        """
        pass

    @abstractmethod
    def get_description(self) -> str:
        """Returns a brief description of the tool's purpose and output format."""
        pass
