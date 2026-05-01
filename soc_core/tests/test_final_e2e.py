#!/usr/bin/env python3
import sys, os, unittest, json
sys.path.insert(0, '/media/kyrie/VMs1/Cybersecurity_Tools_Automation')
os.chdir('/media/kyrie/VMs1/Cybersecurity_Tools_Automation')

class TestFinalE2E(unittest.TestCase):

    def test_01_all_tools_instantiate(self):
        from tools.nmap_tool import NmapTool
        from tools.nuclei_tool import NucleiTool
        from tools.dns_tool import DNSTool
        from tools.virustotal_tool import VirusTotalTool
        from tools.subfinder_tool import SubfinderTool
        from tools.nvd_tool import NVDTool
        tools = [NmapTool(), NucleiTool(), DNSTool(), VirusTotalTool(), SubfinderTool(), NVDTool()]
        for tool in tools:
            self.assertTrue(hasattr(tool, 'run'))
            self.assertTrue(hasattr(tool, 'get_description'))
            self.assertGreater(len(tool.get_description()), 10)
        print(f"✅ All 6 scanning tools instantiate correctly")

    def test_02_all_playbooks_instantiate(self):
        from soc.playbooks.web_attack_playbook import WebAttackPlaybook
        from soc.playbooks.hardening_playbook import HardeningPlaybook
        from soc.playbooks.phishing_playbook import PhishingPlaybook
        from soc.playbooks.malware_playbook import MalwarePlaybook
        from soc.playbooks.data_exfil_playbook import DataExfilPlaybook
        from soc.playbooks.ransomware_playbook import RansomwarePlaybook
        
        mock_config = {"risk_tolerance": "low"}
        playbooks = [
            WebAttackPlaybook(), 
            HardeningPlaybook(), 
            PhishingPlaybook("Test", mock_config),
            MalwarePlaybook(), 
            DataExfilPlaybook(), 
            RansomwarePlaybook()
        ]
        self.assertEqual(len(playbooks), 6)
        print(f"✅ All 6 playbooks instantiate correctly")

    def test_03_router_covers_all_finding_types(self):
        from soc.alert_router import AlertRouter, AlertContext
        router = AlertRouter()
        finding_types = [
            "cleartext_http", "cve", "default_ssh",
            "dns_dmarc", "dns_spf", "dns_missing_dkim",
            "malware", "data_exfiltration", "ransomware_precursor",
            "ip_reputation"
        ]
        for ftype in finding_types:
            alert = AlertContext("test","1.2.3.4",ftype,"high",None,"test",{})
            actions = router.route(alert)
            self.assertIsInstance(actions, list)
            self.assertGreater(len(actions), 0)
        print(f"✅ Router handles all {len(finding_types)} finding types")

    def test_04_safety_guard_protects_all_ranges(self):
        from soc.safety_guard import SafetyGuard
        guard = SafetyGuard(client_whitelist=["8.8.8.8"])
        test_cases = [
            ("192.168.1.1",   False, "RFC1918"),
            ("10.0.0.1",      False, "RFC1918"),
            ("127.0.0.1",     False, "Loopback"),
            ("104.18.36.214", False, "Cloudflare CDN"),
            ("172.67.0.1",    False, "Cloudflare CDN"),
            ("8.8.8.8",       False, "Client whitelist"),
            ("1.2.3.4",       True,  "External IP blockable"),
        ]
        for ip, expected_safe, label in test_cases:
            safe, reason = guard.is_safe_to_block(ip)
            self.assertEqual(safe, expected_safe, f"FAIL {ip} ({label}): safe={safe}, reason={reason}")
        print(f"✅ SafetyGuard handles all {len(test_cases)} IP categories correctly")

    def test_05_dns_tool_real_scan(self):
        from tools.dns_tool import DNSTool
        tool = DNSTool()
        result_json = tool.run("google.com")
        result = json.loads(result_json)
        self.assertIn("status", result)
        ftypes = [f["type"] for f in result.get("findings", [])]
        self.assertTrue(any("dns_spf" in t for t in ftypes))
        self.assertTrue(any("dns_dmarc" in t for t in ftypes))
        print(f"✅ DNS real scan: status={result['status']}, findings={len(result.get('findings',[]))}")

    def test_06_vector_store_isolation(self):
        from knowledge.vector_store import VectorStore
        # Ensure profiles are ingested for this run to avoid "not found" errors
        vs = VectorStore()
        vs.ingest_client_profile("knowledge/client_profiles/techco.yaml")
        vs.ingest_client_profile("knowledge/client_profiles/bankco.yaml")
        
        techco_r = vs.query_context("clients", "web server nginx", client_id="TechCo")
        bankco_r = vs.query_context("clients", "banking oracle", client_id="BankCo")
        self.assertIsInstance(techco_r, dict)
        self.assertIsInstance(bankco_r, dict)
        if techco_r.get("status") == "success":
            self.assertNotIn("bankco", str(techco_r).lower())
        print(f"✅ Vector isolation: TechCo={techco_r.get('status')}, BankCo={bankco_r.get('status')}")

    def test_07_audit_log_is_valid_jsonl(self):
        from pathlib import Path
        audit_file = Path("soc/audit/soar_actions.jsonl")
        if not audit_file.exists():
            self.skipTest("No audit log found")
        errors, total = 0, 0
        with open(audit_file) as f:
            for i, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue
                total += 1
                try:
                    entry = json.loads(line)
                    for field in ["timestamp", "client_id", "action", "target_ip"]:
                        self.assertIn(field, entry, f"Line {i+1} missing: {field}")
                except json.JSONDecodeError:
                    errors += 1
        self.assertEqual(errors, 0, f"{errors} invalid JSON lines in audit log")
        print(f"✅ Audit log: {total} valid entries, 0 JSON errors")

    def test_08_dashboard_shows_clean_clients(self):
        import subprocess
        result = subprocess.run(
            [sys.executable, "dashboard.py"],
            capture_output=True, text=True, timeout=15,
            cwd="/media/kyrie/VMs1/Cybersecurity_Tools_Automation"
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("TechCo", result.stdout)
        self.assertIn("BankCo", result.stdout)
        self.assertNotIn("TestCorp", result.stdout)
        self.assertNotIn("[N/A]", result.stdout)
        self.assertIn("SOC_STANDARD", result.stdout)
        print(f"✅ Dashboard: correct clients, no N/A tiers, no test artifacts")

if __name__ == "__main__":
    unittest.main(verbosity=2)
