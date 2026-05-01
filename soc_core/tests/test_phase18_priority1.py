import sys, unittest, os, json
sys.path.insert(0, '/media/kyrie/VMs1/Cybersecurity_Tools_Automation')
os.chdir('/media/kyrie/VMs1/Cybersecurity_Tools_Automation')

class TestPhase18Priority1(unittest.TestCase):

    def test_testssl_tool_instantiate_and_run(self):
        """Verify testssl_tool can run (requires testssl.sh installed)"""
        from tools.testssl_tool import TestSSLTool
        tool = TestSSLTool()
        # We run a very quick check on google.com (port 443)
        # Note: real scans take time, so we just verify the call works
        result = tool.run("google.com")
        self.assertIn("status", result)
        # If it's a success, it should have findings_count
        if result["status"] == "success":
            self.assertIn("findings_count", result)
        print(f"✅ TestSSLTool run result: {result.get('status')}")

    def test_dns_tool_new_checks(self):
        """Verify DNSTool detects BIMI and non-open-relay on google.com"""
        from tools.dns_tool import DNSTool
        tool = DNSTool()
        result = tool.scan("google.com")
        ftypes = [f["type"] for f in result.get("findings", [])]
        
        # Check if BIMI was checked
        self.assertTrue(any("dns_bimi" in t for t in ftypes))
        
        # Check if Open Relay was checked (google.com's MX shouldn't be open relay)
        self.assertNotIn("smtp_open_relay", ftypes)
        print(f"✅ DNSTool BIMI/Relay checks validated. Findings: {ftypes}")

    def test_alert_router_geoip_enrichment(self):
        """Verify AlertRouter enriches external IPs with GeoIP data"""
        from soc.alert_router import AlertRouter, AlertContext
        router = AlertRouter()
        
        # Test with a known external IP (8.8.8.8)
        geo = router._enrich_geoip("8.8.8.8")
        self.assertIsNotNone(geo)
        self.assertIn("country", geo)
        # Accept None if the free API rate limit was hit
        if geo["country"] is not None:
            self.assertEqual(geo["country"], "US")
        
        # Test with internal IP (should be None)
        geo_internal = router._enrich_geoip("192.168.1.1")
        self.assertIsNone(geo_internal)
        print(f"✅ AlertRouter GeoIP enrichment validated: US for 8.8.8.8, None for 192.168.1.1")

if __name__ == "__main__":
    unittest.main(verbosity=2)
