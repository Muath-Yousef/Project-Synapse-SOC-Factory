"""
Phase 4 Test Suite — SOAR Evidence Bridge
Tests SafetyGuard, evidence generation, and DRY_RUN behavior.
"""

import os
import sys
import json
import tempfile
import pytest

# Ensure project root is on path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def dry_run_env(monkeypatch, tmp_path):
    """Force DRY_RUN=true and isolated evidence root for all tests."""
    monkeypatch.setenv("SOAR_DRY_RUN", "true")
    monkeypatch.setenv("EVIDENCE_ROOT", str(tmp_path))


@pytest.fixture
def store(tmp_path):
    from soc.evidence_store import EvidenceStore
    return EvidenceStore("test_client")


@pytest.fixture
def bridge():
    """Re-import bridge after env is patched."""
    import importlib
    import soc.soar_evidence_bridge as b
    importlib.reload(b)
    return b


# ── SafetyGuard Tests ────────────────────────────────────────────────────────

class TestSafetyGuard:

    def test_rfc1918_blocked(self, bridge):
        """RFC1918 IPs must never be blocked."""
        sg = bridge.SafetyGuard
        for ip in ["10.0.0.1", "172.16.5.5", "192.168.1.100"]:
            safe, reason = sg.is_safe_to_block(ip, set())
            assert not safe, f"RFC1918 IP {ip} should be blocked from SOAR action"
            assert "RFC1918" in reason

    def test_cloudflare_cdn_blocked(self, bridge):
        """Cloudflare CDN IPs must never be blocked."""
        sg = bridge.SafetyGuard
        for ip in ["104.16.1.1", "172.64.0.1", "162.158.0.1"]:
            safe, reason = sg.is_safe_to_block(ip, set())
            assert not safe, f"Cloudflare IP {ip} should be protected"
            assert "Cloudflare" in reason

    def test_client_whitelist_respected(self, bridge):
        """Whitelisted client IPs must not be blocked."""
        sg = bridge.SafetyGuard
        whitelist = {"203.0.113.5", "198.51.100.10"}
        for ip in whitelist:
            safe, reason = sg.is_safe_to_block(ip, whitelist)
            assert not safe
            assert "whitelisted" in reason.lower()

    def test_public_ip_allowed(self, bridge):
        """Non-whitelisted public IPs should be allowed."""
        sg = bridge.SafetyGuard
        safe, reason = sg.is_safe_to_block("203.0.113.99", set())
        assert safe
        assert reason == "Safe to block"

    def test_dns_finding_notify_only(self, bridge):
        """DNS findings must never trigger block actions."""
        sg = bridge.SafetyGuard
        safe, reason = sg.validate_soar_action(
            "cloudflare_block_ip",
            {"source": "dns_finding", "ip": "1.2.3.4"},
            set(),
        )
        assert not safe
        assert "NOTIFY_ONLY" in reason

    def test_malware_escalated_to_human(self, bridge):
        """Malware/ransomware alerts must always escalate to human."""
        sg = bridge.SafetyGuard
        for alert_type in ["malware", "ransomware"]:
            safe, reason = sg.validate_soar_action(
                "cloudflare_block_ip",
                {"alert_type": alert_type, "ip": "5.6.7.8"},
                set(),
            )
            assert not safe
            assert "human escalation" in reason


# ── Evidence Bridge Tests ────────────────────────────────────────────────────

class TestSOAREvidenceBridge:

    def test_dry_run_generates_evidence(self, bridge, store):
        """DRY_RUN mode must still generate EvidenceRecord."""
        record = bridge.execute_soar_action_with_evidence(
            action="cloudflare_block_ip",
            params={"ip": "203.0.113.5", "rule_id": "rule_001"},
            client_id="test_client",
            scan_id="scan_001",
            store=store,
        )
        assert record is not None
        assert record.status == "PARTIAL"
        assert "[DRY RUN]" in record.finding_summary
        assert record.control_id == "NCA-2.3.1"
        assert record.framework == "NCA_ECC_2.0"

    def test_evidence_record_is_chained(self, bridge, store):
        """Multiple evidence records must form a valid hash chain."""
        # Write two records
        for ip in ["203.0.113.5", "203.0.113.6"]:
            bridge.execute_soar_action_with_evidence(
                action="cloudflare_block_ip",
                params={"ip": ip, "rule_id": "rule_001"},
                client_id="test_client",
                scan_id="scan_001",
                store=store,
            )

        # Verify chain integrity
        assert store.verify_chain()

    def test_safetyguard_blocks_before_evidence(self, bridge, store):
        """SafetyGuard-blocked actions must return None (no evidence)."""
        record = bridge.execute_soar_action_with_evidence(
            action="cloudflare_block_ip",
            params={"ip": "10.0.0.1", "rule_id": "test"},   # RFC1918
            client_id="test_client",
            scan_id="scan_001",
            store=store,
        )
        assert record is None

    def test_unknown_action_returns_none(self, bridge, store):
        """Unknown SOAR actions without mapping must return None."""
        record = bridge.execute_soar_action_with_evidence(
            action="mystery_action_xyz",
            params={"ip": "203.0.113.5"},
            client_id="test_client",
            scan_id="scan_001",
            store=store,
        )
        assert record is None

    def test_email_security_evidence(self, bridge, store):
        """Email security enforcement must generate correct evidence."""
        record = bridge.execute_soar_action_with_evidence(
            action="email_security_enforced",
            params={"action": "enforce_dmarc", "domain": "example.com"},
            client_id="test_client",
            scan_id="scan_002",
            store=store,
        )
        assert record is not None
        assert record.control_id == "NCA-3.4.1"
        assert "example.com" in record.finding_summary

    def test_patch_advisory_evidence(self, bridge, store):
        """Patch advisory action must generate correct NCA control evidence."""
        record = bridge.execute_soar_action_with_evidence(
            action="patch_advisory_sent",
            params={"cve_id": "CVE-2024-1234", "host": "webserver-01"},
            client_id="test_client",
            scan_id="scan_003",
            store=store,
        )
        assert record is not None
        assert record.control_id == "NCA-2.2.1"
        assert "CVE-2024-1234" in record.finding_summary
