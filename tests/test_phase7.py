import sys
import os
import logging
from unittest.mock import MagicMock

# Ensure root can be imported
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from main_orchestrator import Orchestrator
from soc.alert_router import ActionType, AlertRouter, AlertContext

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
    print("\n[CASE 1] External IP (1.2.3.4) - Expected: dry_run")
    orch.control_plane.ingest_alert("TechCo", "1.2.3.4", "cleartext_http", "critical", "nmap", {"target_ip": "1.2.3.4"})

    # Case 2: RFC1918 IP (Internal) -> Should be BLOCKED_BY_GUARD
    print("\n[CASE 2] Internal RFC1918 IP (192.168.1.50) - Expected: blocked_by_guard")
    orch.control_plane.ingest_alert("TechCo", "192.168.1.50", "cleartext_http", "critical", "nmap", {"target_ip": "192.168.1.50"})

    # Case 3: Whitelisted IP (Client) -> Should be BLOCKED_BY_GUARD
    print("\n[CASE 3] Whitelisted IP (8.8.8.8) - Expected: blocked_by_guard")
    with orch.control_plane._conn() as conn:
        conn.execute("INSERT OR IGNORE INTO client_whitelist (client_id, ip, created_at) VALUES (?,?,?)", ("TechCo", "8.8.8.8", "timestamp"))
    orch.control_plane.ingest_alert("TechCo", "8.8.8.8", "cleartext_http", "critical", "nmap", {"target_ip": "8.8.8.8"})

    print("\n" + "="*60)
    print("Check soc/audit/soar_actions.jsonl for exact log entries.")
    print("="*60)

def test_cloudflare_ip_blocked_by_guard():
    """Cloudflare CDN IPs must never be blocked by SOAR"""
    print("\n[CASE 4] Cloudflare CDN IP (104.18.36.214) - Expected: protected")
    from soc.safety_guard import SafetyGuard
    guard = SafetyGuard()
    cloudflare_ips = ["104.18.36.214", "172.67.0.1", "162.158.100.1"]
    for ip in cloudflare_ips:
        safe, reason = guard.is_safe_to_block(ip)
        assert safe == False, f"Cloudflare IP {ip} should be protected"
        print(f"✅ CDN IP {ip} correctly protected: {reason}")

def test_dns_findings_never_trigger_block():
    """DNS configuration weaknesses must NEVER result in BLOCK_IP"""
    router = AlertRouter()
    dns_types = ["dns_dmarc", "dns_spf", "dns_missing_dkim"]
    severities = ["low", "medium", "high"]
    for ftype in dns_types:
        for severity in severities:
            alert = AlertContext(
                client_id="test", target_ip="1.2.3.4",
                finding_type=ftype, severity=severity,
                cve_id=None, source_tool="dns_tool", raw_finding={}
            )
            actions = router.route(alert)
            action_values = [a.value for a in actions]
            assert "block_ip" not in action_values, \
                f"FAIL: BLOCK_IP triggered for {ftype}/{severity}"
    print("✅ DNS findings correctly routed to advisory-only")

if __name__ == "__main__":
    test_soar_safety_cases()
    test_cloudflare_ip_blocked_by_guard()
    test_dns_findings_never_trigger_block()
