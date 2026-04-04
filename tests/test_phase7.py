import sys
import os
import logging
from unittest.mock import MagicMock

# Ensure root can be imported
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from main_orchestrator import Orchestrator
from soc.alert_router import ActionType

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')

def test_soar_safety_cases():
    print("="*60)
    print("Phase 7 Verification Test: Safety Guard & dry-run")
    print("="*60)
    
    # Instantiate Orchestrator
    # Note: We don't need real VectorStore for this specific unit test if we pass data directly
    orch = Orchestrator()
    
    client_profile = {
        "client_name": "TechCo",
        "security_profile": {
            "whitelisted_ips": ["8.8.8.8"]
        }
    }
    
    # Case 1: External IP -> Should reach DRY_RUN
    findings_external = {
        "findings": [{
            "target_ip": "1.2.3.4",
            "finding_type": "cleartext_http",
            "severity": "critical",
            "source": "nmap"
        }]
    }
    print("\n[CASE 1] External IP (1.2.3.4) - Expected: dry_run")
    orch.execute_soar_response(findings_external, client_profile)

    # Case 2: RFC1918 IP (Internal) -> Should be BLOCKED_BY_GUARD
    findings_internal = {
        "findings": [{
            "target_ip": "192.168.1.50",
            "finding_type": "cleartext_http",
            "severity": "critical",
            "source": "nmap"
        }]
    }
    print("\n[CASE 2] Internal RFC1918 IP (192.168.1.50) - Expected: blocked_by_guard")
    orch.execute_soar_response(findings_internal, client_profile)

    # Case 3: Whitelisted IP (Client) -> Should be BLOCKED_BY_GUARD
    findings_whitelisted = {
        "findings": [{
            "target_ip": "8.8.8.8",
            "finding_type": "cleartext_http",
            "severity": "critical",
            "source": "nmap"
        }]
    }
    print("\n[CASE 3] Whitelisted IP (8.8.8.8) - Expected: blocked_by_guard")
    orch.execute_soar_response(findings_whitelisted, client_profile)

    print("\n" + "="*60)
    print("Check soc/audit/soar_actions.jsonl for exact log entries.")
    print("="*60)

if __name__ == "__main__":
    test_soar_safety_cases()
