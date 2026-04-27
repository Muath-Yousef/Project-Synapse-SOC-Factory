import logging
from typing import Dict, Any
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

