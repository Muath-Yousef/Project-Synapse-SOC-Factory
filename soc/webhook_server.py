"""
soc/webhook_server.py — Wazuh SIEM webhook receiver (Phase 24)

All alerts now flow through ControlPlane for dedup, state tracking,
and feedback loop — never directly to AlertRouter.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, request, jsonify
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
logger = logging.getLogger('webhook_server')

# Lazy init to avoid import-time DB creation during tests
_control_plane = None

def _get_cp():
    global _control_plane
    if _control_plane is None:
        from soc.control_plane import ControlPlane
        _control_plane = ControlPlane()
    return _control_plane


def _map_wazuh_level_to_severity(level: int) -> str:
    if level >= 12: return "critical"
    if level >= 9:  return "high"
    if level >= 6:  return "medium"
    return "low"


def _map_wazuh_rule_to_finding_type(alert: dict) -> str:
    """Best-effort mapping from Wazuh rule groups to Synapse finding types."""
    groups = alert.get("rule", {}).get("groups", [])
    desc   = alert.get("rule", {}).get("description", "").lower()

    if "authentication_failed" in groups or "brute_force" in desc:
        return "default_ssh"
    if "web" in groups or "attack" in groups:
        return "cleartext_http"
    if "malware" in groups:
        return "malware"
    if "ids" in groups or "intrusion" in desc:
        return "cve"
    if "syscheck" in groups:
        return "data_exfiltration"
    return "cve"  # safe default — will be routed as NOTIFY_ONLY


@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok", "service": "synapse-webhook"}), 200


@app.route('/webhook/wazuh', methods=['POST'])
@app.route('/alert', methods=['POST'])
def wazuh_webhook():
    alert = request.json
    if not alert:
        return jsonify({"error": "empty payload"}), 400

    rule        = alert.get("rule", {})
    agent       = alert.get("agent", {})
    level       = rule.get("level", 3)
    client_id   = agent.get("name", "unknown")
    asset_ip    = agent.get("ip", "0.0.0.0")
    finding_type= _map_wazuh_rule_to_finding_type(alert)
    severity    = _map_wazuh_level_to_severity(level)

    try:
        cp = _get_cp()
        alert_id = cp.ingest_alert(
            client_id=client_id,
            asset_ip=asset_ip,
            finding_type=finding_type,
            severity=severity,
            source="wazuh",
            raw_finding=alert
        )
        return jsonify({
            "status": "received",
            "alert_id": alert_id,
            "wazuh_rule_id": rule.get("id")
        }), 200
    except Exception as e:
        logger.error(f"[Webhook] Failed to ingest alert: {e}")
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    logger.info("🚀 Synapse SOC Webhook — http://0.0.0.0:5000")
    app.run(host='0.0.0.0', port=5000)
