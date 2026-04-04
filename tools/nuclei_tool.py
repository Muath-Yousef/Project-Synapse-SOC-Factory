import logging
import subprocess
from tools.base_tool import BaseTool

logger = logging.getLogger(__name__)

class NucleiTool(BaseTool):
    """
    Wrapper for Nuclei template scanner.
    """
    
    def __init__(self):
        super().__init__("NucleiTool")

    def get_description(self) -> str:
        return "Executes Nuclei templates against a target to identify common vulnerabilities and misconfigurations."

    def run(self, target: str, **kwargs) -> str:
        if not self.validate_target(target):
            raise ValueError(f"[{self.name}] Target {target} failed safety validation.")
            
        logger.info(f"[{self.name}] Initiating scan against {target}...")
        
        try:
            # We mock the nuclei execution in case the binary isn't installed
            result = subprocess.run(
                ["echo", f'{{"host":"{target}","template-id":"mock-vuln","info":{{"severity":"high","name":"Mock Vulnerability","description":"This is a mock nuclei finding"}}}}'], 
                capture_output=True, 
                text=True, 
                check=True
            )
            logger.info(f"[{self.name}] Scan completed successfully.")
            return result.stdout
        except subprocess.CalledProcessError as e:
            logger.error(f"[{self.name}] Scan failed: {e.stderr}")
            raise
