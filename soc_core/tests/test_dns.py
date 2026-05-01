import unittest
import logging
import sys
import os
from unittest.mock import patch, MagicMock
import dns.resolver

# Ensure root can be imported
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from tools.dns_tool import DNSTool

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
logger = logging.getLogger("TestDNS")

class TestDNSTool(unittest.TestCase):
    def setUp(self):
        self.tool = DNSTool()

    def test_known_domain_google(self):
        """Verify DNSTool on google.com (should have SPF and DMARC)."""
        logger.info("[Test Case 1] Verifying Google.com DNS records...")
        results = self.tool.scan("google.com")
        
        self.assertEqual(results["status"], "success")
        self.assertTrue(any(f["type"] == "dns_spf" for f in results["findings"]))
        self.assertTrue(any(f["type"] == "dns_dmarc" for f in results["findings"]))
        self.assertTrue(any(f["type"] == "dns_mx" for f in results["findings"]))
        
        logger.info("✅ Case 1 Passed: google.com records found.")

    def test_missing_dmarc(self):
        """Verify DNSTool on a subdomain likely missing discrete DMARC (often inherits or is missing)."""
        # We can use a random long subdomain to test 'missing' behavior
        target = "nonexistent.subdomain.of.a.test.domain.com"
        logger.info(f"[Test Case 2] Verifying missing records on: {target}")
        results = self.tool.scan(target)
        
        spf_missing = any(f["type"] == "dns_spf_missing" for f in results["findings"])
        dmarc_missing = any(f["type"] == "dns_dmarc_missing" for f in results["findings"])
        
        self.assertTrue(spf_missing or dmarc_missing)
        logger.info("✅ Case 2 Passed: Correctly identified missing records.")

    @patch("dns.resolver.resolve")
    def test_dkim_discovery_google_mock(self, mock_resolve):
        """
        Mocked google.com DKIM discovery to ensure stable testing.
        """
        logger.info("[Test Case 3] Verifying Google.com DKIM discovery (Mocked)...")
        
        # Configure mock to return a valid DKIM record for 'google' selector
        def side_effect(qname, rtype, **kwargs):
            if str(qname).startswith("google._domainkey"):
                mock_answer = MagicMock()
                mock_rdata = MagicMock()
                # Simulate the p= key record (long string)
                mock_rdata.strings = [b"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv..."]
                mock_answer.__iter__.return_value = [mock_rdata]
                return mock_answer
            raise dns.resolver.NXDOMAIN()

        mock_resolve.side_effect = side_effect
        
        result = self.tool.check_dkim("google.com")
        self.assertEqual(result["status"], "found", f"Expected DKIM found for google.com, got: {result}")
        self.assertTrue(any(s["selector"] == "google" for s in result["dkim_records"]), "Expected 'google' selector in DKIM records")
        logger.info(f"✅ DKIM Discovery: found {len(result['dkim_records'])} selector(s)")

    def test_dkim_no_selector_returns_warning(self):
        """
        Domain without known DKIM should return warning, not crash.
        """
        logger.info("[Test Case 4] Verifying missing DKIM handling...")
        result = self.tool.check_dkim("example.com")
        self.assertIn("status", result)
        self.assertIn(result["status"], ["found", "not_discovered"])
        if result["status"] == "not_discovered":
            self.assertTrue(len(result.get("note", "")) > 0)
        logger.info(f"✅ DKIM Not Found handled gracefully: {result['status']}")

if __name__ == "__main__":
    unittest.main()
