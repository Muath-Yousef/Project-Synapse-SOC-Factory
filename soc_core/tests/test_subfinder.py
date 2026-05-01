import subprocess
import sys
import unittest
import os

# Ensure root can be imported
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, BASE_DIR)

from tools.subfinder_tool import SubfinderTool
from parsers.aggregator import Aggregator

class TestSubfinderTool(unittest.TestCase):

    def test_subfinder_binary_available(self):
        """Verify subfinder is installed and executable."""
        result = subprocess.run(["subfinder", "--version"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        print(f"✅ subfinder binary available: {result.stdout.strip()[:50]}")

    def test_subfinder_domain_scan(self):
        """E2E test against hackerone.com (Passive Recon)."""
        tool = SubfinderTool()
        result = tool.run("hackerone.com")
        self.assertEqual(result["status"], "success")
        self.assertGreater(result["count"], 0)
        self.assertIsInstance(result["subdomains"], list)
        print(f"✅ Subfinder found {result['count']} subdomains for hackerone.com")

    def test_subfinder_rejects_ip(self):
        """Verify that subfinder refuses to scan raw IPs."""
        tool = SubfinderTool()
        result = tool.run("192.168.1.1")
        self.assertEqual(result["status"], "error")
        self.assertIn("domain", result["error"].lower())
        print(f"✅ IP correctly rejected: {result['error']}")

    def test_aggregator_merges_subdomains(self):
        """Verify the aggregator can ingest and flatten subfinder results."""
        agg = Aggregator()
        mock_subfinder = {
            "status": "success", 
            "target": "test.com", 
            "subdomains": ["api.test.com", "mail.test.com"], 
            "count": 2, 
            "source": "subfinder"
        }
        agg.ingest(mock_subfinder)
        payload = agg.get_final_payload()
        
        self.assertIn("subdomains", payload)
        self.assertEqual(payload["subdomain_count"], 2)
        self.assertIn("api.test.com", payload["subdomains"])
        print(f"✅ Aggregator merged subdomains correctly")

if __name__ == "__main__":
    unittest.main(verbosity=2)
