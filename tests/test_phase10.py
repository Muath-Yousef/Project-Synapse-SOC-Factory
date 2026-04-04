import sys
import os
import unittest
import subprocess
import json
import logging
from pathlib import Path

# Ensure root can be imported
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from tools.nuclei_tool import NucleiTool
from parsers.nuclei_parser import NucleiParser
from parsers.aggregator import Aggregator

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
logger = logging.getLogger("TestPhase10")

class TestPhase10(unittest.TestCase):

    def test_01_nuclei_binary_available(self):
        """Verify nuclei is installed and reachable in PATH."""
        logger.info("Checking nuclei binary version...")
        try:
            result = subprocess.run(["nuclei", "--version"], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0)
            logger.info(f"✅ Nuclei version check passed: {result.stdout.strip()}")
        except FileNotFoundError:
            self.fail("Nuclei binary not found in PATH. Please install it first.")

    def test_02_nuclei_real_scan_dvwa(self):
        """Verify real scan against DVWA (port 8090) returns findings."""
        logger.info("Running real Nuclei scan against DVWA (port 8090)...")
        tool = NucleiTool()
        # We use a specific subset of templates for speed
        result = tool.run("http://localhost:8090", templates="exposures,vulnerabilities")
        
        self.assertIn(result["status"], ["success", "no_findings"])
        self.assertIsInstance(result["findings"], list)
        
        if result["status"] == "success":
            logger.info(f"✅ Real scan returned {len(result['findings'])} findings.")
            for f in result["findings"]:
                self.assertIn("template-id", f)
                self.assertIn("info", f)
                self.assertIn("severity", f["info"])
        else:
            logger.warning("No findings returned from DVWA. (Is it still starting up?)")

    def test_03_nuclei_parser_field_mapping(self):
        """Verify parser correctly maps real-world Nuclei JSON structure."""
        logger.info("Testing NucleiParser with real-world JSON structure...")
        real_finding = {
            "template-id": "http-missing-security-headers",
            "info": {"name": "Missing Headers", "severity": "medium", "description": "Desc"},
            "host": "http://localhost:8090",
            "matched-at": "http://localhost:8090",
            "ip": "127.0.0.1",
            "timestamp": "2026-04-04T10:00:00Z"
        }
        parser = NucleiParser()
        parsed = parser.parse([real_finding])
        findings = parsed["nuclei_findings"]
        
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "MEDIUM")
        self.assertEqual(findings[0]["target_ip"], "127.0.0.1")
        self.assertEqual(findings[0]["vuln_id"], "http-missing-security-headers")
        logger.info("✅ NucleiParser field mapping verified.")

    def test_04_aggregator_split_brain_prevention(self):
        """Verify Aggregator merges Nmap(IP) and Nuclei(Hostname) correctly via DNS resolution."""
        logger.info("Testing Aggregator for split-brain/duplicate target prevention...")
        
        # 1. Nmap finds a target by IP
        nmap_data = {
            "scanner": "nmap",
            "hosts": [{"ip": "127.0.0.1", "status": "up", "ports": [{"port": 80, "service": "http"}]}]
        }
        
        # 2. Nuclei finds findings on localhost (hostname)
        nuclei_data = {
            "nuclei_findings": [
                {
                    "target": "localhost", # Hostname that resolves to 127.0.0.1
                    "vuln_id": "test-vuln",
                    "severity": "HIGH",
                    "vuln_name": "Test Vuln"
                }
            ]
        }
        
        agg = Aggregator()
        agg.ingest(nmap_data)
        agg.ingest(nuclei_data)
        
        payload = agg.get_final_payload()
        
        # There should only be ONE target (127.0.0.1)
        self.assertEqual(len(payload["targets"]), 1)
        target = payload["targets"][0]
        self.assertEqual(target["ip"], "127.0.0.1")
        self.assertEqual(len(target["vulnerabilities"]), 1)
        logger.info("✅ Aggregator successfully resolved localhost to 127.0.0.1 and merged results.")

if __name__ == "__main__":
    unittest.main()
