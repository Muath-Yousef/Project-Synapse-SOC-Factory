import pytest
import os
import sqlite3
from pathlib import Path
from soc.control_plane import ControlPlane

@pytest.fixture
def temp_cp(tmp_path):
    db_path = tmp_path / "test_cp.db"
    cp = ControlPlane(db_path=db_path)
    yield cp
    if db_path.exists():
        os.remove(db_path)

def test_ingest_alert_dedup(temp_cp):
    # Same finding today should return same alert_id and not duplicate
    id1 = temp_cp.ingest_alert("ClientA", "1.1.1.1", "cleartext_http", "high", "nmap", {"port": 80})
    id2 = temp_cp.ingest_alert("ClientA", "1.1.1.1", "cleartext_http", "high", "wazuh", {"port": 80})
    
    assert id1 == id2
    
    with temp_cp._conn() as conn:
        count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        assert count == 1

def test_state_machine_valid(temp_cp):
    alert_id = temp_cp.ingest_alert("ClientA", "1.1.1.1", "cve", "high", "nmap", {})
    alert = temp_cp._get_alert(alert_id)
    inc_id = alert["incident_id"]
    
    assert inc_id is not None
    assert temp_cp._get_incident_field(inc_id, "state") == "open"
    
    temp_cp.update_incident_state(inc_id, "investigating")
    assert temp_cp._get_incident_field(inc_id, "state") == "investigating"
    
    temp_cp.update_incident_state(inc_id, "contained")
    temp_cp.update_incident_state(inc_id, "closed")
    assert temp_cp._get_incident_field(inc_id, "state") == "closed"

def test_state_machine_invalid(temp_cp):
    alert_id = temp_cp.ingest_alert("ClientA", "1.1.1.1", "cve", "high", "nmap", {})
    inc_id = temp_cp._get_alert(alert_id)["incident_id"]
    
    with pytest.raises(ValueError, match="Invalid transition"):
        temp_cp.update_incident_state(inc_id, "closed")  # open straight to closed is invalid

def test_feedback_loop_fp(temp_cp):
    # Rule weight starts at 1.0 (from seed)
    rule = temp_cp._get_rule("malware", "critical")
    assert rule["weight"] == 1.0
    
    alert_id = temp_cp.ingest_alert("ClientB", "2.2.2.2", "malware", "critical", "wazuh", {})
    
    # Flag as FP
    temp_cp.flag_false_positive(alert_id)
    
    rule2 = temp_cp._get_rule("malware", "critical")
    assert rule2["weight"] == 0.9  # 1.0 - 0.1
    assert rule2["fp_count"] == 1

def test_grc_feedback(temp_cp):
    # Simulate GRC compliance failure
    temp_cp.grc_control_failed("ClientA", "CVE-2021-1234", "Auth Bypass", "cve")
    
    # Needs to elevate 'cve':'high' rule weight
    rule = temp_cp._get_rule("cve", "high")
    assert rule["weight"] == 1.05  # Seed is 1.0, TP delta is +0.05
    
    with temp_cp._conn() as conn:
        risk = conn.execute("SELECT * FROM grc_risk_events").fetchone()
        assert risk is not None
        assert "GRC→SOC" in risk["event"]

def test_incident_aggregation(temp_cp):
    # First alert creates incident
    id1 = temp_cp.ingest_alert("ClientC", "3.3.3.3", "default_ssh", "high", "nmap", {})
    inc1 = temp_cp._get_alert(id1)["incident_id"]
    
    # Second DIFFERENT alert type on same asset
    id2 = temp_cp.ingest_alert("ClientC", "3.3.3.3", "cleartext_http", "high", "nmap", {})
    inc2 = temp_cp._get_alert(id2)["incident_id"]
    
    # Should be different incidents
    assert inc1 != inc2
