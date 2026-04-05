import logging
from typing import Dict, Any

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

    def calculate_score(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Returns a score and a corresponding grade.
        """
        deductions = 0
        findings = scan_data.get("findings", [])
        
        for f in findings:
            severity = f.get("severity", "low").lower()
            deductions += self.WEIGHTS.get(severity, 2)

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
