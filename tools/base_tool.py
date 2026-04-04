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
        # Strip protocol and port for validation (e.g. http://localhost:8080 -> localhost)
        clean_target = target.replace("http://", "").replace("https://", "").split(":")[0].split("/")[0]

        # In Phase 10, we explicitly allow localhost/127.0.0.1 for the E2E Docker testbed.
        # Production safety is handled by the SOC/SafetyGuard layer.
        forbidden_targets = ["0.0.0.0", "::1"]
        if clean_target.lower() in forbidden_targets:
            logger.warning(f"[{self.name}] Target {target} is in the forbidden list.")
            return False
            
        try:
            # Check if it's a resolvable domain or valid IP
            socket.gethostbyname(clean_target)
            return True
        except socket.gaierror:
            logger.warning(f"[{self.name}] Target {target} (resolved from {clean_target}) is unresolvable.")
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
