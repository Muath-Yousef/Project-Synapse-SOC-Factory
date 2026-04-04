import subprocess
import logging
from tools.base_tool import BaseTool

logger = logging.getLogger(__name__)

class NmapTool(BaseTool):
    """
    Wrapper for the Nmap network scanner.
    Ensures safe execution and extracts output directly as XML.
    """
    
    def __init__(self):
        super().__init__("Nmap")

    def get_description(self) -> str:
        return "Network exploration tool and security / port scanner. Returns standard XML (-oX)."

    def run(self, target: str, profile: str = "quick") -> str:
        """
        Runs an Nmap scan against the target.
        Profiles:
        - quick: Fast scan of top ports (-F)
        - full: Service version detection (-sV -sC)
        """
        
        if not self.validate_target(target):
            raise ValueError(f"[{self.name}] Target {target} failed safety validation.")
            
        logger.info(f"[{self.name}] Initiating '{profile}' scan against {target}...")
        
        # Base command forcing XML output to stdout
        command = ["nmap", "-oX", "-"]
        
        if profile == "quick":
            command.extend(["-F", "-T4"])
        elif profile == "full":
            command.extend(["-sV", "-sC", "-T4"])
        else:
            logger.warning(f"[{self.name}] Unknown profile '{profile}', falling back to 'quick'.")
            command.extend(["-F", "-T4"])
            
        command.append(target)
        
        try:
            # Execute Nmap
            result = subprocess.run(
                command, 
                capture_output=True, 
                text=True, 
                check=True
            )
            logger.info(f"[{self.name}] Scan completed successfully.")
            return result.stdout
            
        except subprocess.CalledProcessError as e:
            logger.error(f"[{self.name}] Scan failed with error code {e.returncode}: {e.stderr}")
            raise
        except FileNotFoundError:
            logger.error(f"[{self.name}] The 'nmap' binary was not found in PATH.")
            raise RuntimeError("Nmap is not installed or accessible.")
