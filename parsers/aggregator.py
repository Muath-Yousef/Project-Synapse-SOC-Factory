import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class Aggregator:
    """
    Takes unified output from multiple tools (e.g. Nmap, Nuclei)
    and combines them into a single, cohesive "Target Summary" JSON payload 
    specifically optimized for LLM token efficiency and Context logic.
    """
    
    def __init__(self):
        # We will hold state per target IP
        self.targets_db = {}

    def ingest(self, parsed_data: Dict[str, Any]):
        """
        Ingests parsed output from a tool and merges it into the internal DB.
        """
        scanner = parsed_data.get("scanner", "unknown")
        
        # Currently handling Nmap payload integration
        if scanner == "nmap":
            for host in parsed_data.get("hosts", []):
                ip = host.get("ip")
                if not ip or ip == "Unknown":
                    continue
                
                # Initialize host record if it doesn't exist
                if ip not in self.targets_db:
                    self.targets_db[ip] = {
                        "ip": ip,
                        "status": host.get("status", "Unknown"),
                        "open_ports": [],
                        "vulnerabilities": []  # Placeholder for Nuclei integration
                    }
                
                # Merge port data
                for port in host.get("ports", []):
                    # Simple deduplication just in case
                    if port not in self.targets_db[ip]["open_ports"]:
                        self.targets_db[ip]["open_ports"].append(port)
                        
        # Future: elif scanner == "nuclei":
                        
    def filter_false_positives(self):
        """
        Placeholder logic. In the final system, this will query ChromaDB context
        to see if an open port or vulnerability is actually an expected business service.
        """
        logger.info("[Aggregator] Running False-Positive context filters (Mock)...")
        # No concrete filters for Phase 1

    def get_final_payload(self) -> Dict[str, Any]:
        """
        Returns the optimized Target Summary dictionary.
        """
        self.filter_false_positives()
        
        return {
            "summary_type": "DataStandardization",
            "targets": list(self.targets_db.values())
        }
