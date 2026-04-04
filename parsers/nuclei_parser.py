import json
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

class NucleiParser:
    """
    Parses output from Nuclei (JSONL format) into the standardized framework structure.
    """
    def parse(self, raw_data: str) -> Dict[str, Any]:
        logger.info("[NucleiParser] Standardizing raw data...")
        parsed_results = []
        
        # Nuclei returns JSONL, so we parse line by line
        for line in raw_data.strip().split('\n'):
            if not line.strip():
                continue
            try:
                finding = json.loads(line)
                
                # Extract essential fields mapped to our standardized structure
                parsed_results.append({
                    "target": finding.get("host", "Unknown"),
                    "vuln_id": finding.get("template-id", "Unknown"),
                    "severity": finding.get("info", {}).get("severity", "info").upper(),
                    "vuln_name": finding.get("info", {}).get("name", "Unknown"),
                    "description": finding.get("info", {}).get("description", "No description provided.")
                })
            except json.JSONDecodeError as e:
                logger.warning(f"[NucleiParser] Failed to parse JSON line: {e}")
                continue
                
        return {"nuclei_findings": parsed_results}
