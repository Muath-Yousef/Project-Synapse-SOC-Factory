import logging
import subprocess
from tools.base_tool import BaseTool

logger = logging.getLogger(__name__)

class NiktoTool(BaseTool):
    """
    Auto-generated wrapper for nikto.
    Description: Web server vulnerability scanner
    """
    
    def __init__(self):
        # We pass the class name to the parent to set self.name
        super().__init__("NiktoTool")

    def get_description(self) -> str:
        return "Web server vulnerability scanner"

    def run(self, target: str, **kwargs) -> str:
        if not self.validate_target(target):
            raise ValueError(f"[{self.name}] Target {target} failed safety validation.")
            
        logger.info(f"[{self.name}] Initiating scan against {target}...")
        
        # Mocking an execution
        try:
            result = subprocess.run(
                ["echo", "Mock nikto output for " + target], 
                capture_output=True, 
                text=True, 
                check=True
            )
            logger.info(f"[{self.name}] Scan completed successfully.")
            return result.stdout
        except subprocess.CalledProcessError as e:
            logger.error(f"[{self.name}] Scan failed: {e.stderr}")
            raise
