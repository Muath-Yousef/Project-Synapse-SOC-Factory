from dataclasses import dataclass
from typing import List, Optional, Dict, Any
import logging
from soc.playbooks.base_playbook import ActionType

logger = logging.getLogger(__name__)

@dataclass
class AlertContext:
    client_id: str
    target_ip: str
    finding_type: str       # "cleartext_http" | "default_ssh" | "cve"
    severity: str           # "critical" | "high" | "medium" | "low"
    cve_id: Optional[str]   # None إذا لم يكن CVE
    source_tool: str        # "nmap" | "nuclei" | "aggregated"
    raw_finding: dict

class AlertRouter:
    """
    Routing logic:
    - Critical + web-facing → auto-block + notify
    - High CVE              → notify + patch advisory
    - Medium infra          → notify only + ticket
    - Low                   → log only
    
    Failure mode: إذا فشل الـ Cloudflare API،
    يجب أن يُسجّل الـ failure ويُرسل Telegram alert
    بدلاً من الصمت — silent failure في SOAR أخطر من الـ finding نفسه.
    """

    ROUTING_TABLE = {
        ("critical", "cleartext_http")   : [ActionType.BLOCK_IP, ActionType.ESCALATE_HUMAN],
        ("critical", "cve")              : [ActionType.BLOCK_IP, ActionType.NOTIFY_ONLY],
        ("high",     "cve")              : [ActionType.NOTIFY_ONLY, ActionType.PATCH_ADVISORY],
        ("high",     "default_ssh")      : [ActionType.NOTIFY_ONLY],
        ("medium",   "default_ssh")      : [ActionType.NOTIFY_ONLY],
        ("high",     "dns_dmarc")        : [ActionType.NOTIFY_ONLY, ActionType.PATCH_ADVISORY],
        ("medium",   "dns_dmarc")        : [ActionType.NOTIFY_ONLY],
        ("low",      "dns_dmarc")        : [ActionType.NOTIFY_ONLY],
        ("high",     "dns_spf")          : [ActionType.NOTIFY_ONLY, ActionType.PATCH_ADVISORY],
        ("medium",   "dns_spf")          : [ActionType.NOTIFY_ONLY],
        ("low",      "dns_spf")          : [ActionType.NOTIFY_ONLY],
        ("high",     "dns_missing_dkim") : [ActionType.NOTIFY_ONLY, ActionType.PATCH_ADVISORY],
        ("medium",   "dns_missing_dkim") : [ActionType.NOTIFY_ONLY],
        ("low",      "dns_missing_dkim") : [ActionType.NOTIFY_ONLY],
        ("high",     "ip_reputation")    : [ActionType.NOTIFY_ONLY],
        ("medium",   "ip_reputation")    : [ActionType.NOTIFY_ONLY],
        # Phase 22: DNS finding variants from DNSTool
        ("high",     "dns_spf_missing")       : [ActionType.NOTIFY_ONLY, ActionType.PATCH_ADVISORY],
        ("medium",   "dns_spf_missing")       : [ActionType.NOTIFY_ONLY],
        ("low",      "dns_spf_missing")       : [ActionType.NOTIFY_ONLY],
        ("high",     "dns_dmarc_missing")     : [ActionType.NOTIFY_ONLY, ActionType.PATCH_ADVISORY],
        ("medium",   "dns_dmarc_missing")     : [ActionType.NOTIFY_ONLY],
        ("low",      "dns_dmarc_missing")     : [ActionType.NOTIFY_ONLY],
        ("high",     "dns_dkim_not_found")    : [ActionType.NOTIFY_ONLY, ActionType.PATCH_ADVISORY],
        ("medium",   "dns_dkim_not_found")    : [ActionType.NOTIFY_ONLY],
        ("low",      "dns_dkim_not_found")    : [ActionType.NOTIFY_ONLY],
        ("high",     "dns_bimi_missing")      : [ActionType.NOTIFY_ONLY],
        ("medium",   "dns_bimi_missing")      : [ActionType.NOTIFY_ONLY],
        ("low",      "dns_bimi_missing")      : [ActionType.NOTIFY_ONLY],
        ("info",     "dns_bimi_missing")      : [ActionType.NOTIFY_ONLY],
        ("high",     "cleartext_http")        : [ActionType.NOTIFY_ONLY, ActionType.PATCH_ADVISORY],
        ("medium",   "cleartext_http")        : [ActionType.NOTIFY_ONLY],
        ("low",      "cleartext_http")        : [ActionType.NOTIFY_ONLY],
        ("critical", "malware")              : [ActionType.ESCALATE_HUMAN],
        ("high",     "malware")              : [ActionType.ESCALATE_HUMAN],
        ("critical", "data_exfiltration")    : [ActionType.BLOCK_IP, ActionType.ESCALATE_HUMAN],
        ("high",     "data_exfiltration")    : [ActionType.BLOCK_IP, ActionType.ESCALATE_HUMAN],
        ("critical", "ransomware_precursor") : [ActionType.ESCALATE_HUMAN],
        ("high",     "ransomware_precursor") : [ActionType.ESCALATE_HUMAN],
    }

    def get_playbooks(self, client_name: str, config: Dict[str, Any], finding_type: str) -> List:
        """
        Returns instances of playbooks relevant to the finding_type.
        Late imports used to break circular dependencies.
        """
        # Late imports to ensure no cycle with AlertRouter
        from soc.playbooks.web_attack_playbook import WebAttackPlaybook
        from soc.playbooks.hardening_playbook import HardeningPlaybook
        from soc.playbooks.phishing_playbook import PhishingPlaybook

        playbooks = []
        if "web" in finding_type or "http" in finding_type:
            playbooks.append(WebAttackPlaybook(client_name, config))
        if "ssh" in finding_type or "service" in finding_type:
            playbooks.append(HardeningPlaybook(client_name, config))
        if "dns" in finding_type or "reputation" in finding_type:
            playbooks.append(PhishingPlaybook(client_name, config))
            
        return playbooks

    def route(self, alert: AlertContext) -> List[ActionType]:
        key = (alert.severity.lower(), alert.finding_type.lower())
        
        # Enrich with GeoIP for external IPs
        geo_info = self._enrich_geoip(alert.target_ip)
        if geo_info:
            logger.info(f"[Router] GeoIP for {alert.target_ip}: {geo_info.get('country_name')} ({geo_info.get('org')})")
            alert.raw_finding["geoip"] = geo_info

        actions = self.ROUTING_TABLE.get(key)
        if not actions:
            logger.warning(f"[Router] No rule for {key} — defaulting to NOTIFY_ONLY")
            actions = [ActionType.NOTIFY_ONLY]
        logger.info(f"[Router] {alert.client_id} | {key} → {actions}")
        return actions

    def _enrich_geoip(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Enriches the alert with geographic data.
        Returns None for internal/private IPs.
        Returns a dict (possibly with empty fields if API fails) for external IPs.
        Uses ipapi.co as primary, ip-api.com as fallback.
        """
        import ipaddress, requests
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback:
                return None
        except ValueError:
            pass  # Not a valid IP, treat as external

        # Primary: ipapi.co (free tier)
        try:
            r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5)
            if r.status_code == 200:
                data = r.json()
                if not data.get("error"):
                    return {
                        "country": data.get("country_code"),
                        "country_name": data.get("country_name"),
                        "city": data.get("city"),
                        "org": data.get("org"),
                        "isp": data.get("isp")
                    }
        except Exception as e:
            logger.warning(f"[Router] GeoIP primary (ipapi.co) failed for {ip}: {e}")

        # Fallback: ip-api.com (free, no key)
        try:
            r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,org,isp", timeout=5)
            if r.status_code == 200:
                data = r.json()
                if data.get("status") == "success":
                    return {
                        "country": data.get("countryCode"),
                        "country_name": data.get("country"),
                        "city": data.get("city"),
                        "org": data.get("org"),
                        "isp": data.get("isp")
                    }
        except Exception as e:
            logger.error(f"[Router] GeoIP fallback (ip-api.com) failed for {ip}: {e}")

        # Both APIs failed — return empty dict so callers always get a dict for external IPs
        logger.warning(f"[Router] GeoIP unavailable for {ip} — returning empty geo record")
        return {"country": None, "country_name": None, "city": None, "org": None, "isp": None}
