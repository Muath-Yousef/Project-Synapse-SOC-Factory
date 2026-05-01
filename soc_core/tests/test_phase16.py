import sys, unittest, os
sys.path.insert(0, '/media/kyrie/VMs1/Cybersecurity_Tools_Automation')
os.chdir('/media/kyrie/VMs1/Cybersecurity_Tools_Automation')

class TestPhase16(unittest.TestCase):

    def test_onboarding_creates_profile(self):
        from onboarding.onboard_client import build_client_profile, save_profile
        import tempfile
        profile = build_client_profile("TestCorp","testcorp.com","sec@testcorp.com","Technology","soc_standard",["10.0.0.1"])
        self.assertEqual(profile["client_name"], "TestCorp")
        self.assertEqual(profile["service_tier"], "soc_standard")
        self.assertIn("Nginx", profile["tech_stack_keywords"])
        self.assertEqual(profile["whitelisted_ips"], ["10.0.0.1"])
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = save_profile(profile, profiles_dir=tmpdir)
            self.assertTrue(__import__("pathlib").Path(filepath).exists())
        print(f"✅ Profile structure valid (saved to temp dir, no production pollution)")

    def test_onboarding_tier_configs(self):
        from onboarding.onboard_client import TIER_CONFIGS
        for tier in ["soc_lite","soc_standard","soc_pro","soc_grc"]:
            self.assertIn(tier, TIER_CONFIGS)
            cfg = TIER_CONFIGS[tier]
            self.assertIn("log_cap_gb_day", cfg)
            self.assertIn("scan_frequency", cfg)
        print("✅ All 4 tier configs valid")

    def test_dashboard_loads_clients(self):
        from dashboard import load_clients
        clients = load_clients()
        self.assertIsInstance(clients, list)
        self.assertGreaterEqual(len(clients), 1)
        print(f"✅ Dashboard loaded {len(clients)} client(s)")

    def test_dashboard_runs_without_crash(self):
        import subprocess
        result = subprocess.run(
            [sys.executable, "dashboard.py"],
            capture_output=True, text=True, timeout=15,
            cwd="/media/kyrie/VMs1/Cybersecurity_Tools_Automation"
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("SYNAPSE SOC FACTORY", result.stdout)
        print("✅ Dashboard ran successfully")

    def test_cron_script_exists_and_valid(self):
        from pathlib import Path
        cron_script = Path("onboarding/setup_cron.sh")
        self.assertTrue(cron_script.exists())
        content = cron_script.read_text()
        self.assertIn("weekly", content)
        self.assertIn("monthly", content)
        self.assertIn("crontab", content)
        print("✅ Cron script valid")

    def test_onboarding_industry_stacks(self):
        from onboarding.onboard_client import INDUSTRY_TECH_STACKS
        for industry in ["Technology","Banking","Healthcare","E-commerce"]:
            self.assertIn(industry, INDUSTRY_TECH_STACKS)
            self.assertGreater(len(INDUSTRY_TECH_STACKS[industry]), 0)
        print(f"✅ Industry stacks: {list(INDUSTRY_TECH_STACKS.keys())}")

if __name__ == "__main__":
    unittest.main(verbosity=2)
