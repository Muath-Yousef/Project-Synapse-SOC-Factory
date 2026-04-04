from tools.base_tool import BaseTool
import requests, os, logging
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

class NVDTool(BaseTool):
    
    def __init__(self):
        super().__init__("NVDTool")

    NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def get_description(self):
        return "Queries NVD for recent CVEs. Use for Zero-day monitoring and service-specific CVE lookups."

    def validate_input(self, target: str) -> bool:
        return True

    def run(self, target: str, arguments: str = "") -> dict:
        days = 7
        if "days=" in arguments:
            try:
                days = int(arguments.split("days=")[1].split()[0])
            except Exception:
                pass

        pub_start = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT00:00:00.000")
        pub_end = datetime.now(timezone.utc).strftime("%Y-%m-%dT23:59:59.999")
        params = {
            "keywordSearch": target,
            "pubStartDate": pub_start,
            "pubEndDate": pub_end,
            "cvssV3Severity": "HIGH",
            "resultsPerPage": 10,
        }
        api_key = os.getenv("NVD_API_KEY", "")
        headers = {"apiKey": api_key} if api_key else {}

        try:
            resp = requests.get(self.NVD_API, params=params, headers=headers, timeout=15)
            resp.raise_for_status()
            data = resp.json()
            cves = []
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")
                desc = ""
                for d in cve.get("descriptions", []):
                    if d.get("lang") == "en":
                        desc = d.get("value", "")[:200]
                        break
                metrics = cve.get("metrics", {})
                cvss_score = None
                severity = "UNKNOWN"
                for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if key in metrics and metrics[key]:
                        cvss_data = metrics[key][0].get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore")
                        severity = cvss_data.get("baseSeverity", "UNKNOWN")
                        break
                cves.append({
                    "cve_id": cve_id,
                    "description": desc,
                    "cvss_score": cvss_score,
                    "severity": severity,
                    "published": cve.get("published", ""),
                    "source": "nvd"
                })
            return {"status": "success", "target_keyword": target, "days_back": days, "cve_count": len(cves), "cves": cves}
        except requests.Timeout:
            return {"status": "timeout", "cves": [], "cve_count": 0, "error": "NVD API timeout"}
        except Exception as e:
            return {"status": "error", "cves": [], "cve_count": 0, "error": str(e)}
