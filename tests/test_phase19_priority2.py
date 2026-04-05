import sys, unittest, os, json, shutil
sys.path.insert(0, '/media/kyrie/VMs1/Cybersecurity_Tools_Automation')
os.chdir('/media/kyrie/VMs1/Cybersecurity_Tools_Automation')

class TestPhase19Priority2(unittest.TestCase):

    def setUp(self):
        self.history_dir = "/media/kyrie/VMs1/Cybersecurity_Tools_Automation/knowledge/history"
        os.makedirs(self.history_dir, exist_ok=True)
        self.client_id = "test_delta"
        # Cleanup old test files
        for f in os.listdir(self.history_dir):
            if f.startswith(f"{self.client_id}_scan_"):
                os.remove(os.path.join(self.history_dir, f))

    def test_compliance_scoring(self):
        """Verify ComplianceEngine calculates correct scores and grades"""
        from soc.compliance_engine import ComplianceEngine
        ce = ComplianceEngine()
        
        # Case A: Perfect score
        scan_a = {"findings": []}
        res_a = ce.calculate_score(scan_a)
        self.assertEqual(res_a["score"], 100)
        self.assertEqual(res_a["grade"], "A")
        
        # Case B: One critical finding
        scan_b = {"findings": [{"severity": "critical"}]}
        res_b = ce.calculate_score(scan_b)
        self.assertEqual(res_b["score"], 60)
        self.assertEqual(res_b["grade"], "D")
        
        # Case C: Multiple findings
        scan_c = {"findings": [
            {"severity": "high"},   # -20
            {"severity": "medium"}, # -10
            {"severity": "low"}     # -2
        ]}
        res_c = ce.calculate_score(scan_c)
        self.assertEqual(res_c["score"], 68) 
        print(f"✅ ComplianceEngine validated: A={res_a['score']}, D={res_b['score']}, {res_c['score']}")

    def test_delta_detection(self):
        """Verify DeltaAnalyzer detects new ports and subdomains"""
        from soc.delta_analyzer import DeltaAnalyzer
        da = DeltaAnalyzer()
        
        old_scan = {
            "targets": [{"ip": "1.2.3.4", "open_ports": [{"port": 80, "service": "http"}]}],
            "subdomains": ["dev.test.com"]
        }
        new_scan = {
            "targets": [{"ip": "1.2.3.4", "open_ports": [
                {"port": 80, "service": "http"},
                {"port": 443, "service": "https"} # NEW
            ]}],
            "subdomains": ["dev.test.com", "api.test.com"] # NEW
        }
        
        deltas = da.analyze(old_scan, new_scan)
        self.assertEqual(len(deltas["new_ports"]), 1)
        self.assertEqual(deltas["new_ports"][0]["port"], "443")
        self.assertEqual(len(deltas["new_subdomains"]), 1)
        self.assertEqual(deltas["new_subdomains"][0], "api.test.com")
        print(f"✅ DeltaAnalyzer validated: New Port 443 detected, New Subdomain api.test.com detected")

    def test_orchestrator_persistence(self):
        """Verify Orchestrator saves scans and performs delta lookups"""
        from main_orchestrator import Orchestrator
        orch = Orchestrator()
        
        test_data = {"summary_type": "DataStandardization", "targets": [], "findings": []}
        
        # 1. First persistence
        orch._persist_scan(self.client_id, test_data)
        files = [f for f in os.listdir(self.history_dir) if f.startswith(f"{self.client_id}_scan_")]
        self.assertGreater(len(files), 0)
        
        # 2. Retrieval
        latest = orch._get_latest_scan(self.client_id)
        self.assertEqual(latest["summary_type"], "DataStandardization")
        print(f"✅ Orchestrator persistence validated: History file created and retrieved.")

if __name__ == "__main__":
    unittest.main(verbosity=2)
