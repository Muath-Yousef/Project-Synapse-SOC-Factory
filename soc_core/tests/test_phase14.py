import sys, unittest
sys.path.insert(0, '/media/kyrie/VMs1/Cybersecurity_Tools_Automation')

class TestPhase14(unittest.TestCase):

    def test_nvd_tool_instantiates(self):
        from tools.nvd_tool import NVDTool
        tool = NVDTool()
        self.assertIn("NVD", tool.get_description())
        print("✅ NVDTool instantiated")

    def test_nvd_query_returns_structure(self):
        from tools.nvd_tool import NVDTool
        tool = NVDTool()
        result = tool.run("Apache", "days=30")
        self.assertIn("status", result)
        self.assertIn("cves", result)
        self.assertIsInstance(result["cves"], list)
        print(f"✅ NVD query: status={result['status']}, count={result['cve_count']}")

    def test_malware_playbook_escalates(self):
        from soc.playbooks.malware_playbook import MalwarePlaybook
        from soc.alert_router import AlertContext
        alert = AlertContext("TestClient","1.2.3.4","malware","critical",None,"wazuh",{})
        result = MalwarePlaybook().execute(alert, dry_run=True)
        self.assertEqual(result["status"], "escalated")
        self.assertFalse(result["auto_close"])
        print("✅ MalwarePlaybook: escalated, auto_close=False")

    def test_data_exfil_playbook_executes(self):
        from soc.playbooks.data_exfil_playbook import DataExfilPlaybook
        from soc.alert_router import AlertContext
        alert = AlertContext("TestClient","5.6.7.8","data_exfiltration","critical",None,"wazuh",{})
        result = DataExfilPlaybook().execute(alert, dry_run=True)
        self.assertIn(result["status"], ["success", "partial_failure"])
        print(f"✅ DataExfilPlaybook: {result['status']}")

    def test_ransomware_playbook_p0(self):
        from soc.playbooks.ransomware_playbook import RansomwarePlaybook
        from soc.alert_router import AlertContext
        alert = AlertContext("TestClient","9.8.7.6","ransomware_precursor","critical",None,"wazuh",{})
        result = RansomwarePlaybook().execute(alert, dry_run=True)
        self.assertEqual(result["status"], "p0_escalated")
        print("✅ RansomwarePlaybook: P0 escalated")

    def test_malware_routing_never_blocks(self):
        from soc.alert_router import AlertRouter, AlertContext
        router = AlertRouter()
        for ftype in ["malware", "ransomware_precursor"]:
            alert = AlertContext("t","1.1.1.1",ftype,"critical",None,"wazuh",{})
            actions = [a.value for a in router.route(alert)]
            self.assertNotIn("block_ip", actions)
            self.assertIn("escalate_human", actions)
        print("✅ Malware/Ransomware correctly route to escalation-only")

if __name__ == "__main__":
    unittest.main(verbosity=2)
