import yaml, logging
from pathlib import Path
from tools.nvd_tool import NVDTool

logger = logging.getLogger(__name__)

class NVDMatcher:
    def __init__(self):
        self.nvd = NVDTool()

    def check_client_stack(self, client_id: str, days: int = 7) -> dict:
        profile_path = Path(f"knowledge/client_profiles/{client_id.lower()}.yaml")
        if not profile_path.exists():
            return {"status": "error", "error": f"Profile not found: {profile_path}", "cves": [], "total_cve_matches": 0}
        with open(profile_path) as f:
            profile = yaml.safe_load(f)
        keywords = profile.get("tech_stack_keywords", [])
        if not keywords:
            return {"status": "no_keywords", "matches": [], "cves": [], "total_cve_matches": 0}
        all_cves = []
        for keyword in keywords:
            result = self.nvd.run(keyword, f"days={days}")
            if result["status"] == "success" and result["cve_count"] > 0:
                for cve in result["cves"]:
                    cve["matched_keyword"] = keyword
                    cve["client_id"] = client_id
                    all_cves.append(cve)
        return {
            "status": "success",
            "client_id": client_id,
            "keywords_checked": len(keywords),
            "total_cve_matches": len(all_cves),
            "cves": all_cves
        }
