"""
Tests for Phase 1 Evidence System
8 tests — all must pass before Phase 2 begins
"""

import json
import hashlib
import tempfile
import os
from pathlib import Path
from datetime import datetime, timezone

import pytest

# Override EVIDENCE_ROOT to use temp dir for tests
os.environ["EVIDENCE_ROOT"] = tempfile.mkdtemp()

from soc.evidence_store import EvidenceStore, EvidenceRecord, hash_raw_log, create_evidence_record
from soc.wazuh_evidence_bridge import wazuh_alert_to_evidence, extract_rule_id, NCA_WAZUH_MAP


# ─────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────

@pytest.fixture
def fresh_store():
    """Create a fresh EvidenceStore in temp directory for each test."""
    with tempfile.TemporaryDirectory() as tmpdir:
        os.environ["EVIDENCE_ROOT"] = tmpdir
        # Re-import to pick up env change
        from importlib import reload
        import soc.evidence_store
        reload(soc.evidence_store)
        from soc.evidence_store import EvidenceStore
        yield EvidenceStore("test_client")


@pytest.fixture
def sample_record_data():
    return {
        "control_id": "NCA-2.3.1",
        "framework": "NCA_ECC_2.0",
        "client_id": "test_client",
        "scan_id": "scan_test_001",
        "status": "FAIL",
        "finding_summary": "SQL injection attempt detected on web application",
        "source": "wazuh",
        "event_id": "wazuh_evt_12345",
        "raw_log_content": '{"rule": {"id": "31101", "level": 10}}',
    }


@pytest.fixture
def wazuh_ssh_alert():
    return {
        "id": "wazuh_alert_001",
        "rule": {
            "id": "5710",
            "level": 10,
            "description": "SSH brute force attack detected"
        },
        "agent": {"name": "web-server-01"},
        "data": {"srcip": "192.0.2.1"},
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


# ─────────────────────────────────────────────
# Test 1: Chain creation
# ─────────────────────────────────────────────

def test_append_creates_chain(fresh_store, sample_record_data):
    """First record has prev_hash=None, record_hash is computed."""
    record = create_evidence_record(**sample_record_data)
    # Use fresh_store directly
    appended = fresh_store.append(record)

    assert appended.prev_record_hash is None  # First record
    assert appended.record_hash is not None
    assert len(appended.record_hash) == 64  # SHA-256 hex = 64 chars

    # Second record should link to first
    record2 = create_evidence_record(
        **{**sample_record_data, "event_id": "wazuh_evt_12346"}
    )
    appended2 = fresh_store.append(record2)
    assert appended2.prev_record_hash == appended.record_hash


# ─────────────────────────────────────────────
# Test 2: Valid chain passes verification
# ─────────────────────────────────────────────

def test_verify_chain_passes_valid(fresh_store, sample_record_data):
    """Clean chain of 3 records must pass verify_chain()."""
    for i in range(3):
        record = create_evidence_record(
            **{**sample_record_data, "event_id": f"evt_{i}"}
        )
        fresh_store.append(record)

    assert fresh_store.verify_chain() is True


# ─────────────────────────────────────────────
# Test 3: Tampered chain fails verification
# ─────────────────────────────────────────────

def test_verify_chain_fails_tampered(fresh_store, sample_record_data):
    """Modifying a record in chain.jsonl must fail verify_chain()."""
    record = create_evidence_record(**sample_record_data)
    fresh_store.append(record)

    # Tamper with chain.jsonl
    with open(fresh_store.chain_file, "r") as f:
        content = f.read()

    tampered = content.replace("FAIL", "PASS")  # Change status post-hashing
    with open(fresh_store.chain_file, "w") as f:
        f.write(tampered)

    assert fresh_store.verify_chain() is False


# ─────────────────────────────────────────────
# Test 4: Wazuh bridge maps known rule
# ─────────────────────────────────────────────

def test_wazuh_bridge_maps_known_rule(fresh_store, wazuh_ssh_alert):
    """Rule 5710 must map to NCA-3.1.1."""
    result = wazuh_alert_to_evidence(
        alert=wazuh_ssh_alert,
        client_id="test_client",
        scan_id="scan_001",
        store=fresh_store,
    )

    assert result is not None
    assert result.control_id == "NCA-3.1.1"
    assert result.framework == "NCA_ECC_2.0"
    assert result.source == "wazuh"
    assert result.status == "FAIL"
    assert result.event_id == "wazuh_alert_001"


# ─────────────────────────────────────────────
# Test 5: Wazuh bridge skips unknown rule
# ─────────────────────────────────────────────

def test_wazuh_bridge_skips_unknown_rule(fresh_store):
    """Unmapped rule ID returns None — no evidence record created."""
    unknown_alert = {
        "id": "evt_999",
        "rule": {"id": "99999", "level": 5, "description": "Unknown event"},
        "agent": {"name": "host"},
        "data": {},
    }

    result = wazuh_alert_to_evidence(
        alert=unknown_alert,
        client_id="test_client",
        scan_id="scan_001",
        store=fresh_store,
    )

    assert result is None
    assert not fresh_store.chain_file.exists() or fresh_store.chain_file.stat().st_size == 0


# ─────────────────────────────────────────────
# Test 6: Audit export format stability (regression guard)
# ─────────────────────────────────────────────

def test_audit_export_format_stability(fresh_store, sample_record_data):
    """
    REGRESSION GUARD: export format must contain exact fields, never change.
    If this test fails, the evidence format has been modified — STOP BUILD.
    """
    record = create_evidence_record(**sample_record_data)
    fresh_store.append(record)

    package = fresh_store.get_audit_package()

    # Top-level package fields — FROZEN
    required_package_fields = {
        "client_id", "scan_id", "export_timestamp", "chain_integrity",
        "record_count", "records", "export_format_version"
    }
    assert required_package_fields.issubset(set(package.keys())), \
        f"Missing fields: {required_package_fields - set(package.keys())}"

    assert package["export_format_version"] == "1.0", \
        "Format version must remain '1.0' — frozen after Phase 1"

    # Per-record fields — FROZEN
    required_record_fields = {
        "control_id", "framework", "client_id", "scan_id", "status",
        "finding_summary", "source", "event_id", "raw_log_hash", "timestamp",
        "origin", "prev_record_hash", "record_hash", "raw_log_ref"
    }
    assert len(package["records"]) > 0
    actual_fields = set(package["records"][0].keys())
    assert required_record_fields == actual_fields, \
        f"Field mismatch. Extra: {actual_fields - required_record_fields}. Missing: {required_record_fields - actual_fields}"


# ─────────────────────────────────────────────
# Test 7: External anchor populated
# ─────────────────────────────────────────────

def test_evidence_external_anchor(fresh_store, wazuh_ssh_alert):
    """event_id must be populated from source system (external anchor)."""
    result = wazuh_alert_to_evidence(
        alert=wazuh_ssh_alert,
        client_id="test_client",
        scan_id="scan_001",
        store=fresh_store,
    )

    assert result is not None
    assert result.event_id != ""
    assert result.event_id is not None
    assert "wazuh_alert_001" in result.event_id  # Wazuh alert ID captured


# ─────────────────────────────────────────────
# Test 8: Hash computation is deterministic
# ─────────────────────────────────────────────

def test_hash_computation_deterministic():
    """Same EvidenceRecord must always produce the same hash."""
    record1 = EvidenceRecord(
        control_id="NCA-2.3.1",
        framework="NCA_ECC_2.0",
        client_id="client_a",
        scan_id="scan_001",
        status="FAIL",
        finding_summary="Test finding",
        source="wazuh",
        event_id="evt_001",
        raw_log_hash="abc123",
        timestamp="2026-04-27T10:00:00+00:00",
        origin="remote",
        prev_record_hash=None,
        raw_log_ref=None,
    )

    record2 = EvidenceRecord(
        control_id="NCA-2.3.1",
        framework="NCA_ECC_2.0",
        client_id="client_a",
        scan_id="scan_001",
        status="FAIL",
        finding_summary="Test finding",
        source="wazuh",
        event_id="evt_001",
        raw_log_hash="abc123",
        timestamp="2026-04-27T10:00:00+00:00",
        origin="remote",
        prev_record_hash=None,
        raw_log_ref=None,
    )

    assert record1.compute_hash() == record2.compute_hash()
