"""
SOC Playbook MCP Server
=======================
Exposes security playbooks as MCP tools — allowing the agentic engine
to select, execute, and track SOAR playbooks for each incident type.
Provides: list_playbooks, run_playbook, get_playbook_status
"""
import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastmcp import FastMCP

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("soc-playbook-server")

mcp = FastMCP("soc-playbook-server")

# Playbook registry — maps alert category to response steps
PLAYBOOK_REGISTRY: Dict[str, Dict] = {
    "ssh_brute_force": {
        "name": "SSH Brute Force Response",
        "severity": "high",
        "steps": [
            {"action": "ufw limit ssh",          "description": "Rate-limit SSH connections"},
            {"action": "ufw deny from {src_ip}", "description": "Block attacker IP"},
            {"action": "systemctl restart ssh",  "description": "Restart SSH service"},
            {"action": "notify_telegram",         "description": "Send alert to SOC channel"},
        ],
        "auto_execute": False,   # requires HITL
    },
    "malware_detected": {
        "name": "Malware Containment",
        "severity": "critical",
        "steps": [
            {"action": "isolate_host {agent_id}",    "description": "Network-isolate infected host"},
            {"action": "collect_artifacts {agent_id}", "description": "Collect forensic artifacts"},
            {"action": "notify_telegram",              "description": "Page on-call analyst"},
        ],
        "auto_execute": False,
    },
    "port_scan": {
        "name": "Port Scan Response",
        "severity": "medium",
        "steps": [
            {"action": "ufw deny from {src_ip}", "description": "Block scanning IP"},
            {"action": "log_event",               "description": "Record in evidence store"},
        ],
        "auto_execute": True,   # safe to auto-run
    },
    "web_attack": {
        "name": "Web Application Attack Response",
        "severity": "high",
        "steps": [
            {"action": "cf_block_ip {src_ip}",   "description": "Block IP at Cloudflare WAF"},
            {"action": "log_event",               "description": "Record in evidence store"},
            {"action": "notify_telegram",         "description": "Alert SOC channel"},
        ],
        "auto_execute": True,
    },
}

# Active playbook runs
_runs: Dict[str, Dict] = {}


@mcp.tool()
async def list_playbooks() -> List[Dict[str, Any]]:
    """
    List all available SOAR playbooks with their metadata.
    """
    return [
        {
            "playbook_id": pid,
            "name": pb["name"],
            "severity": pb["severity"],
            "steps_count": len(pb["steps"]),
            "auto_execute": pb["auto_execute"],
        }
        for pid, pb in PLAYBOOK_REGISTRY.items()
    ]


@mcp.tool()
async def run_playbook(
    playbook_id: str,
    alert_id: str,
    context: Optional[str] = "{}",
) -> Dict[str, Any]:
    """
    Trigger a playbook for a given alert. Substitutes {src_ip}, {agent_id}
    from context JSON. Returns run_id for status tracking.
    """
    import json

    pb = PLAYBOOK_REGISTRY.get(playbook_id)
    if not pb:
        return {"error": f"Playbook '{playbook_id}' not found. Available: {list(PLAYBOOK_REGISTRY)}"}

    ctx = {}
    try:
        ctx = json.loads(context)
    except Exception:
        pass

    run_id = str(uuid.uuid4())[:8].upper()
    run = {
        "run_id": run_id,
        "playbook_id": playbook_id,
        "alert_id": alert_id,
        "status": "running" if pb["auto_execute"] else "pending_approval",
        "steps": [
            {
                "action": s["action"].format(**ctx),
                "description": s["description"],
                "status": "queued",
            }
            for s in pb["steps"]
        ],
        "started_at": datetime.now(timezone.utc).isoformat(),
        "requires_approval": not pb["auto_execute"],
    }
    _runs[run_id] = run

    logger.info(f"[PLAYBOOK] Run {run_id} started for alert {alert_id} via {playbook_id}")
    return {
        "run_id": run_id,
        "status": run["status"],
        "steps_count": len(run["steps"]),
        "requires_approval": run["requires_approval"],
    }


@mcp.tool()
async def get_playbook_status(run_id: str) -> Dict[str, Any]:
    """
    Get the current execution status of a playbook run.
    """
    run = _runs.get(run_id.upper())
    if not run:
        return {"error": f"Run {run_id} not found"}
    return run


if __name__ == "__main__":
    mcp.run(transport="stdio")
