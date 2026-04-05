#!/usr/bin/env python3
import subprocess
import json
import os
import logging
from typing import Dict, Any
from tools.base_tool import BaseTool

logger = logging.getLogger(__name__)

class TestSSLTool(BaseTool):
    """
    Wraps testssl.sh for deep TLS/SSL auditing.
    Part of Phase 18: Baseline Expansion.
    """

    def __init__(self):
        super().__init__("TestSSLTool")

    def get_description(self) -> str:
        return "Professional TLS/SSL auditor. Checks for Heartbleed, ROBOT, POODLE, and weak ciphers."

    def validate_input(self, target: str) -> bool:
        # testssl.sh handles IPs and domains
        return True

    def run(self, target: str, arguments: str = "") -> dict:
        """
        Runs testssl.sh --json-pretty against the target.
        """
        logger.info(f"[TestSSLTool] Auditing TLS for {target}")
        
        # Ensure we use the system binary
        cmd = ["testssl.sh", "--quiet", "--jsonfile-pretty", f"/tmp/testssl_{target}.json", target]
        
        try:
            # We use --jsonfile-pretty because stdout can be messy with ANSI
            subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            output_path = f"/tmp/testssl_{target}.json"
            if os.path.exists(output_path):
                with open(output_path, 'r') as f:
                    raw_results = json.load(f)
                
                # Cleanup
                os.remove(output_path)
                
                return self._parse_results(raw_results)
            else:
                return {"status": "error", "error": "testssl.sh failed to produce JSON output"}
                
        except subprocess.TimeoutExpired:
            return {"status": "error", "error": "testssl.sh timed out (5m limit)"}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def _parse_results(self, raw: list) -> dict:
        """
        Parses testssl.sh JSON array into a summarized finding format.
        """
        findings = []
        # testssl.sh returns a list of dictionaries
        for entry in raw:
            severity = entry.get("severity", "INFO")
            if severity in ["HIGH", "CRITICAL"]:
                findings.append({
                    "id": entry.get("id"),
                    "finding": entry.get("finding"),
                    "severity": severity.lower(),
                    "description": f"Vulnerability detected: {entry.get('id')}"
                })

        return {
            "status": "success",
            "findings_count": len(findings),
            "critical_vulnerabilities": findings
        }

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        tool = TestSSLTool()
        print(json.dumps(tool.run(sys.argv[1]), indent=2))
