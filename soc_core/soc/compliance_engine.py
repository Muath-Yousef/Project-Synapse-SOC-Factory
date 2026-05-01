import logging
from typing import Dict, Any
import json
from pathlib import Path
from soc.evidence_store import EvidenceRecord, EvidenceStore, hash_raw_log
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

class ComplianceEngine:
    """
    Calculates a Security Posture Score (0-100%) based on findings.
    Part of Phase 19: Priority 2.
    """

    WEIGHTS = {
        "critical": 40,
        "high": 20,
        "medium": 10,
        "low": 2,
        "info": 0
    }

    def calculate_score(self, scan_data: Dict[str, Any], client_id: str = "unknown") -> Dict[str, Any]:
        """
        Returns a score and a corresponding grade.
        Phase 24: Reports critical/high findings as GRC control failures to the Control Plane.
        """
        deductions = 0
        findings = scan_data.get("findings", [])
        
        # Initialize Control Plane for GRC cross-link
        try:
            from soc.control_plane import ControlPlane
            cp = ControlPlane()
        except ImportError:
            cp = None
            logger.warning("[GRC] ControlPlane not found — GRC to SOC feedback loop disabled.")

        for f in findings:
            severity = f.get("severity", "low").lower()
            finding_type = f.get("finding_type", "unknown")
            deductions += self.WEIGHTS.get(severity, 2)
            
            # GRC -> SOC Feedback Loop
            if cp and severity in ("critical", "high"):
                # Treat the vulnerability ID as the control ID (e.g. CVE-2021-1234 or "cleartext_http")
                control_id = f.get("vuln_id") or finding_type
                try:
                    cp.grc_control_failed(
                        client_id=client_id,
                        control_id=control_id,
                        control_name=f"Compliance Control for {finding_type}",
                        linked_finding_type=finding_type
                    )
                except Exception as e:
                    logger.error(f"[GRC] Failed to sync control failure to SOC: {e}")

        score = max(0, 100 - deductions)
        grade = self._get_grade(score)

        return {
            "score": score,
            "grade": grade,
            "deductions": deductions,
            "findings_count": len(findings)
        }

    def _get_grade(self, score: int) -> str:
        if score >= 90: return "A"
        if score >= 80: return "B"
        if score >= 70: return "C"
        if score >= 60: return "D"
        return "F"

def generate_evidence_from_finding(
    control_id: str,
    framework: str,
    client_id: str,
    scan_id: str,
    status: str,
    finding_summary: str,
    source: str,
    raw_finding_data: dict,
    store: EvidenceStore,
) -> EvidenceRecord:
    """
    Generate and append EvidenceRecord from compliance engine finding.
    Called after each control evaluation — ensures every finding has evidence.
    """
    event_id = f"{scan_id}_{control_id}_{source}"

    record = EvidenceRecord(
        control_id=control_id,
        framework=framework,
        client_id=client_id,
        scan_id=scan_id,
        status=status,
        finding_summary=finding_summary,
        source=source,
        event_id=event_id,
        raw_log_hash=hash_raw_log(str(raw_finding_data)),
        timestamp=datetime.now(timezone.utc).isoformat(),
        origin="remote",
    )

    return store.append(record)

def attach_evidence_references(
    compliance_report: dict,
    client_id: str,
    scan_id: str,
    store: EvidenceStore,
) -> dict:
    """
    Attach evidence record references to compliance report output.
    Auditor can verify each finding via chain.
    """
    for control in compliance_report.get("controls", []):
        control_id = control.get("control_id")
        if control_id:
            records = store.get_records_by_control(control_id)
            control["evidence_count"] = len(records)
            control["latest_evidence_hash"] = records[-1]["record_hash"][:16] if records else None
            control["evidence_chain_file"] = f"knowledge/evidence/{client_id}/chain.jsonl"

    return compliance_report


NCA_CONTROLS_PATH = Path("knowledge/compliance_frameworks/nca_controls.json")


def load_nca_controls() -> dict:
    """Load full NCA ECC 2.0 control database."""
    with open(NCA_CONTROLS_PATH, encoding="utf-8") as f:
        data = json.load(f)
    return data.get("controls", {})


def evaluate_all_nca_controls(
    scan_results: dict,
    client_id: str,
    scan_id: str,
) -> dict:
    """
    Evaluate client against all 114 NCA ECC 2.0 controls.

    For each control:
    - auto_detectable=True: evaluate from scan results
    - auto_detectable=False: flag as MANUAL_REQUIRED (client provides policy docs)

    Returns complete gap report with per-control status.
    """
    controls = load_nca_controls()
    gap_report = {
        "client_id": client_id,
        "scan_id": scan_id,
        "framework": "NCA_ECC_2.0",
        "total_controls": len(controls),
        "evaluated": 0,
        "passed": 0,
        "failed": 0,
        "partial": 0,
        "manual_required": 0,
        "compliance_score": 0.0,
        "grade": "F",
        "controls": [],
    }

    total_weight = 0
    earned_weight = 0

    for control_id, control_data in controls.items():
        auto_detectable = control_data.get("auto_detectable", False)
        severity_weight = abs(control_data.get("severity_weight", -10))

        if not auto_detectable:
            status = "MANUAL_REQUIRED"
            gap_report["manual_required"] += 1
            finding = f"Control {control_id} requires policy documentation from client"
        else:
            # Evaluate from scan results
            status, finding = evaluate_control_from_scan(
                control_id=control_id,
                control_data=control_data,
                scan_results=scan_results,
            )
            gap_report["evaluated"] += 1

            total_weight += severity_weight
            if status == "PASS":
                earned_weight += severity_weight
                gap_report["passed"] += 1
            elif status == "PARTIAL":
                earned_weight += severity_weight * 0.5
                gap_report["partial"] += 1
            else:
                gap_report["failed"] += 1

        control_entry = {
            "control_id": control_id,
            "domain": control_data.get("domain", ""),
            "title_en": control_data.get("title_en", ""),
            "title_ar": control_data.get("title_ar", ""),
            "status": status,
            "finding": finding,
            "remediation": control_data.get("remediation_summary", ""),
            "severity_weight": severity_weight,
            "auto_detectable": auto_detectable,
            "priority": get_remediation_priority(status, severity_weight),
        }
        gap_report["controls"].append(control_entry)

    # Calculate compliance score (automated controls only)
    if total_weight > 0:
        gap_report["compliance_score"] = round((earned_weight / total_weight) * 100, 1)

    gap_report["grade"] = score_to_grade(gap_report["compliance_score"])
    return gap_report


def evaluate_control_from_scan(
    control_id: str,
    control_data: dict,
    scan_results: dict,
) -> tuple[str, str]:
    """
    Evaluate a single control against scan results.
    Returns (status, finding_description).
    """
    wazuh_rule_ids = set(control_data.get("wazuh_rule_ids", []))
    scanner_tool = control_data.get("scanner_tool", "")

    triggered_rules = set(scan_results.get("triggered_wazuh_rules", []))
    scanner_findings = scan_results.get("scanner_findings", {}).get(control_id, {})

    if triggered_rules & wazuh_rule_ids:
        matched = triggered_rules & wazuh_rule_ids
        return "FAIL", f"Wazuh rules triggered: {matched} — control violated"

    if scanner_findings:
        severity = scanner_findings.get("severity", "medium")
        if severity in {"critical", "high"}:
            return "FAIL", scanner_findings.get("description", "Finding detected")
        return "PARTIAL", scanner_findings.get("description", "Partial compliance")

    return "PASS", "No violations detected in automated scan"


def get_remediation_priority(status: str, weight: int) -> str:
    if status == "FAIL" and weight >= 30:
        return "Critical"
    elif status == "FAIL":
        return "High"
    elif status == "PARTIAL":
        return "Medium"
    return "Low"


def score_to_grade(score: float) -> str:
    if score >= 90:
        return "A"
    elif score >= 80:
        return "B"
    elif score >= 70:
        return "C"
    elif score >= 60:
        return "D"
    return "F"


def build_manual_checklist(gap_report: dict) -> list[dict]:
    """Extract controls requiring manual client documentation."""
    return [
        {
            "control_id": c["control_id"],
            "title_en": c["title_en"],
            "title_ar": c["title_ar"],
            "action_required": "Provide policy documentation or evidence",
        }
        for c in gap_report["controls"]
        if c["status"] == "MANUAL_REQUIRED"
    ]
