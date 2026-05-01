"""
Correlation Engine — correlate events across Wazuh + Cloudflare + Okta.
Detects complex attack patterns that single-source analysis misses.

Phase 7 Deliverable 7.3
Build trigger: 5+ clients using all three data sources.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass
class CorrelatedEvent:
    event_id: str
    client_id: str
    pattern: str
    confidence: float
    sources: list[str]
    description: str
    affected_ips: list[str]
    timestamp: str
    recommended_tier: int


class CorrelationEngine:
    """
    Correlates Wazuh + Cloudflare + Okta events to detect complex threats.
    Time-window based correlation for multi-source attack pattern detection.
    """

    def __init__(self, client_id: str, time_window_seconds: int = 300):
        self.client_id = client_id
        self.time_window = time_window_seconds

    def correlate_credential_stuffing(
        self,
        wazuh_events: list[dict],
        cloudflare_events: list[dict],
    ) -> list[CorrelatedEvent]:
        """
        Detect credential stuffing:
        Wazuh: multiple SSH failures + Cloudflare: high request rate from same IP
        """
        correlated = []

        wazuh_ips: dict[str, int] = {}
        for evt in wazuh_events:
            if str(evt.get("rule", {}).get("id")) in {"5710", "5720", "5760"}:
                ip = evt.get("data", {}).get("srcip", "")
                if ip:
                    wazuh_ips[ip] = wazuh_ips.get(ip, 0) + 1

        cf_ips: dict[str, int] = {}
        for evt in cloudflare_events:
            ip = evt.get("ClientIP", "")
            if ip:
                cf_ips[ip] = cf_ips.get(ip, 0) + 1

        for ip in set(wazuh_ips.keys()) & set(cf_ips.keys()):
            if wazuh_ips[ip] >= 5 and cf_ips[ip] >= 100:
                correlated.append(CorrelatedEvent(
                    event_id=f"corr_cred_stuff_{ip}_{int(datetime.now().timestamp())}",
                    client_id=self.client_id,
                    pattern="credential_stuffing",
                    confidence=0.85,
                    sources=["wazuh", "cloudflare"],
                    description=(
                        f"Credential stuffing attack from {ip}: "
                        f"{wazuh_ips[ip]} SSH failures + {cf_ips[ip]} web requests"
                    ),
                    affected_ips=[ip],
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    recommended_tier=3,
                ))

        return correlated

    def correlate_data_exfiltration(
        self,
        wazuh_events: list[dict],
        cloudflare_events: list[dict],
    ) -> list[CorrelatedEvent]:
        """
        Detect data exfiltration:
        Wazuh: large file access from sensitive directory
        Cloudflare: spike in egress to unknown IP
        """
        correlated = []

        sensitive_paths = ["/etc/", "/home/", "/var/www/"]
        wazuh_file_events = [
            e for e in wazuh_events
            if str(e.get("rule", {}).get("id")) in {"553", "554", "550"}
            and any(path in str(e) for path in sensitive_paths)
        ]

        cf_spike_ips = [
            evt.get("ClientIP") for evt in cloudflare_events
            if evt.get("EdgeResponseBytes", 0) > 10_000_000  # 10MB+
        ]

        if wazuh_file_events and cf_spike_ips:
            correlated.append(CorrelatedEvent(
                event_id=f"corr_exfil_{int(datetime.now().timestamp())}",
                client_id=self.client_id,
                pattern="data_exfiltration",
                confidence=0.75,
                sources=["wazuh", "cloudflare"],
                description=(
                    f"Potential data exfiltration: {len(wazuh_file_events)} file events "
                    f"+ {len(cf_spike_ips)} high-egress connections"
                ),
                affected_ips=cf_spike_ips[:5],
                timestamp=datetime.now(timezone.utc).isoformat(),
                recommended_tier=3,
            ))

        return correlated

    def correlate_lateral_movement(
        self,
        wazuh_events: list[dict],
    ) -> list[CorrelatedEvent]:
        """
        Detect lateral movement:
        Wazuh: SSH login from internal IP → access to multiple hosts in time window.
        """
        correlated = []

        internal_ssh: dict[str, set] = {}
        for evt in wazuh_events:
            if str(evt.get("rule", {}).get("id")) in {"5715", "5501"}:
                srcip = evt.get("data", {}).get("srcip", "")
                dstip = evt.get("data", {}).get("dstip", "")
                if srcip.startswith(("10.", "172.16.", "192.168.")):
                    if srcip not in internal_ssh:
                        internal_ssh[srcip] = set()
                    if dstip:
                        internal_ssh[srcip].add(dstip)

        for srcip, targets in internal_ssh.items():
            if len(targets) >= 3:
                correlated.append(CorrelatedEvent(
                    event_id=f"corr_lateral_{srcip}_{int(datetime.now().timestamp())}",
                    client_id=self.client_id,
                    pattern="lateral_movement",
                    confidence=0.80,
                    sources=["wazuh"],
                    description=(
                        f"Lateral movement from {srcip}: "
                        f"SSH to {len(targets)} internal hosts"
                    ),
                    affected_ips=[srcip] + list(targets)[:5],
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    recommended_tier=3,
                ))

        return correlated
