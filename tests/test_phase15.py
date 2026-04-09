import sys, unittest
sys.path.insert(0, '/media/kyrie/VMs1/Cybersecurity_Tools_Automation')
import os
os.chdir('/media/kyrie/VMs1/Cybersecurity_Tools_Automation')

class TestPhase15(unittest.TestCase):

    def test_email_connector_mock_mode(self):
        from soc.connectors.email_connector import EmailConnector
        conn = EmailConnector()
        result = conn.send_report("test@example.com", "Test Subject", "Test body")
        self.assertIn(result["status"], ["mock", "sent"])
        print(f"✅ EmailConnector: {result['status']}")

    def test_email_with_attachment(self):
        from soc.connectors.email_connector import EmailConnector
        from pathlib import Path
        conn = EmailConnector()
        reports = sorted(Path("reports/output").glob("*.md"))
        if not reports:
            self.skipTest("No reports available")
        result = conn.send_report(
            "test@example.com", "Report Test", "Body",
            attachment_path=str(reports[-1])
        )
        self.assertIn(result["status"], ["mock", "sent"])
        print(f"✅ Email with attachment: {result['status']}")

    def test_scheduler_loads_clients(self):
        from scheduler import load_all_clients
        clients = load_all_clients()
        self.assertIsInstance(clients, list)
        self.assertGreater(len(clients), 0)
        self.assertIn("client_id", clients[0])
        print(f"✅ Scheduler loaded {len(clients)} client(s): {[c['client_id'] for c in clients]}")

    def test_techco_profile_has_required_fields(self):
        import yaml
        with open("knowledge/client_profiles/techco.yaml") as f:
            profile = yaml.safe_load(f)
        self.assertIn("primary_target", profile)
        self.assertIn("tech_stack_keywords", profile)
        self.assertIn("contact_email", profile)
        self.assertGreater(len(profile["tech_stack_keywords"]), 0)
        print(f"✅ TechCo profile complete: target={profile['primary_target']}, keywords={profile['tech_stack_keywords']}")

    def test_nvd_matcher_checks_client_stack(self):
        from tools.nvd_matcher import NVDMatcher
        matcher = NVDMatcher()
        result = matcher.check_client_stack("techco", days=30)
        self.assertIn(result["status"], ["success", "no_keywords", "error"])
        self.assertIn("cves", result)
        self.assertIn("total_cve_matches", result)
        print(f"✅ NVD Matcher: status={result['status']}, CVEs={result['total_cve_matches']}")

    def test_scheduler_cli_runs(self):
        import subprocess
        result = subprocess.run(
            [sys.executable, "scheduler.py", "--help"],
            capture_output=True, text=True, timeout=10,
            cwd="/media/kyrie/VMs1/Cybersecurity_Tools_Automation",
            env={**os.environ, "SOAR_DRY_RUN": "true"}
        )
        output = result.stdout + result.stderr
        self.assertIn("Synapse Scheduled Scanner", output)
        print(f"✅ Scheduler CLI ran: returncode={result.returncode}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
