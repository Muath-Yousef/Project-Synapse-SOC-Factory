import json
import logging
from typing import Dict, Any, List, Union

logger = logging.getLogger(__name__)

class NucleiParser:
    """
    Parses output from Nuclei (JSONL format or List of dicts) into the standardized framework structure.
    """
    def parse(self, raw_data: Union[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        logger.info("[NucleiParser] Standardizing raw data...")
        parsed_results = []
        
        findings = []
        if isinstance(raw_data, str):
            # Nuclei returns JSONL string, so we parse line by line
            for line in raw_data.strip().split('\n'):
                if not line.strip():
                    continue
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError as e:
                    logger.warning(f"[NucleiParser] Failed to parse JSON line: {e}")
                    continue
        elif isinstance(raw_data, list):
            findings = raw_data
            
        for finding in findings:
            # Extract essential fields mapped to our standardized structure
            # Real Nuclei JSON uses info.severity as primary source
            info = finding.get("info", {})
            severity = info.get("severity", "info").lower()
            
            parsed_results.append({
                "target": finding.get("host", "Unknown"),
                "target_ip": finding.get("ip", "Unknown"),
                "vuln_id": finding.get("template-id", "Unknown"),
                "severity": severity.upper(),
                "vuln_name": info.get("name", "Unknown"),
                "description": info.get("description", "No description provided."),
                "matched_at": finding.get("matched-at", "Unknown"),
                "timestamp": finding.get("timestamp", "Unknown")
            })
                
        return {"nuclei_findings": parsed_results}
