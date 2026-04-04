import logging
import subprocess
import json
import os
import time
from tools.base_tool import BaseTool

logger = logging.getLogger(__name__)

class NucleiTool(BaseTool):
    """
    Wrapper for real Nuclei template scanner.
    """
    
    def __init__(self):
        super().__init__("NucleiTool")

    def get_description(self) -> str:
        return "Executes Nuclei templates against a target to identify common vulnerabilities and misconfigurations."

    def run(self, target: str, templates: str = "exposures,vulnerabilities", **kwargs) -> dict:
        """
        Executes Nuclei with:
        - -json-export for structured output
        - -severity medium,high,critical to filter noise
        - -timeout to prevent hanging
        - -no-color for clean JSON
        """
        if not self.validate_target(target):
            raise ValueError(f"[{self.name}] Target {target} failed safety validation.")
            
        logger.info(f"[{self.name}] Initiating LIVE scan against {target}...")
        
        # Ensure target has protocol if missing (Nuclei requirement for web targets)
        if not target.startswith("http"):
            target = f"http://{target}"
            
        output_file = f"/tmp/nuclei_{target.replace('.', '_').replace(':', '_').replace('/', '_')}_{int(time.time())}.json"

        command = [
            "nuclei",
            "-u", target,
            "-t", templates,
            "-severity", "medium,high,critical",
            "-json-export", output_file,
            "-timeout", "10",
            "-no-color",
            "-silent"
        ]

        try:
            # We allow 120s for the scan
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            # Nuclei might exit with 0 even if it fails to start properly, 
            # so we check for the output file
            if os.path.exists(output_file):
                findings = []
                with open(output_file, 'r') as f:
                    for line in f:
                        if line.strip():
                            try:
                                findings.append(json.loads(line))
                            except json.JSONDecodeError:
                                continue
                
                os.remove(output_file) # Cleanup
                logger.info(f"[{self.name}] Scan completed. Findings found: {len(findings)}")
                return {
                    "status": "success",
                    "findings": findings,
                    "count": len(findings),
                    "raw_stdout": result.stdout
                }
            else:
                logger.warning(f"[{self.name}] No output file generated. Status: no_findings.")
                return {"status": "no_findings", "findings": [], "count": 0}

        except subprocess.TimeoutExpired:
            logger.error(f"[{self.name}] Scan timed out.")
            return {"status": "timeout", "findings": [], "error": "Scan exceeded 120s"}
        except FileNotFoundError:
            logger.error(f"[{self.name}] Nuclei binary not found in PATH.")
            return {"status": "error", "findings": [], "error": "nuclei binary not found"}
        except Exception as e:
            logger.error(f"[{self.name}] Unexpected error: {e}")
            return {"status": "error", "findings": [], "error": str(e)}
