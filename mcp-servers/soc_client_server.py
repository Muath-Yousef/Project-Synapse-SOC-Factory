"""
SOC Client MCP Server
=====================
Exposes client management tools to the agentic engine:
- List clients and their risk profile
- Get scan history per client
- Trigger a new scan for a client
- Update client risk score
"""
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from fastmcp import FastMCP

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("soc-client-server")

mcp = FastMCP("soc-client-server")

# Resolve client profiles directory
_BASE = Path(__file__).parent.parent / "soc_core" / "knowledge" / "client_profiles"


def _load_clients() -> Dict[str, Dict]:
    clients = {}
    if not _BASE.exists():
        return clients
    for f in _BASE.glob("*.yaml"):
        if f.name.startswith("_"):
            continue
        try:
            data = yaml.safe_load(f.read_text())
            client_id = f.stem
            clients[client_id] = data or {}
        except Exception as e:
            logger.warning(f"Could not load {f.name}: {e}")
    return clients


@mcp.tool()
async def list_clients() -> List[Dict[str, Any]]:
    """
    Return all onboarded clients with their basic risk profile.
    """
    clients = _load_clients()
    result = []
    for cid, data in clients.items():
        result.append({
            "client_id": cid,
            "name": data.get("name", cid),
            "industry": data.get("industry", "unknown"),
            "risk_score": data.get("risk_score", "N/A"),
            "status": data.get("status", "active"),
            "last_scan": data.get("last_scan", "never"),
        })
    return result


@mcp.tool()
async def get_client_profile(client_id: str) -> Dict[str, Any]:
    """
    Get the full profile for a specific client including assets and compliance status.
    """
    clients = _load_clients()
    profile = clients.get(client_id)
    if not profile:
        return {"error": f"Client '{client_id}' not found", "available": list(clients.keys())}
    return {"client_id": client_id, **profile}


@mcp.tool()
async def get_client_scan_history(client_id: str, limit: int = 5) -> Dict[str, Any]:
    """
    Return the most recent scan results for a client from knowledge/history/.
    """
    history_dir = Path(__file__).parent.parent / "soc_core" / "knowledge" / "history"
    if not history_dir.exists():
        return {"error": "History directory not found"}

    scans = sorted(history_dir.glob(f"{client_id}_scan_*.json"), reverse=True)[:limit]
    if not scans:
        return {"client_id": client_id, "scans": [], "message": "No scan history found"}

    results = []
    for scan_file in scans:
        try:
            data = json.loads(scan_file.read_text())
            results.append({
                "scan_file": scan_file.name,
                "timestamp": data.get("timestamp", "unknown"),
                "findings_count": len(data.get("findings", [])),
                "critical_count": sum(
                    1 for f in data.get("findings", [])
                    if f.get("severity", "").lower() == "critical"
                ),
            })
        except Exception:
            continue

    return {"client_id": client_id, "scans": results}


@mcp.tool()
async def update_client_risk_score(
    client_id: str,
    new_score: int,
    reason: str = "Manual update",
) -> Dict[str, Any]:
    """
    Update a client's risk score (0-100). Writes back to the YAML profile.
    """
    if not (0 <= new_score <= 100):
        return {"error": "Risk score must be between 0 and 100"}

    profile_path = _BASE / f"{client_id}.yaml"
    if not profile_path.exists():
        return {"error": f"Client '{client_id}' profile not found"}

    data = yaml.safe_load(profile_path.read_text()) or {}
    old_score = data.get("risk_score", "N/A")
    data["risk_score"] = new_score
    data["risk_updated_at"] = datetime.now(timezone.utc).isoformat()
    data["risk_update_reason"] = reason

    profile_path.write_text(yaml.dump(data, default_flow_style=False))
    logger.info(f"[RISK] {client_id}: {old_score} → {new_score} ({reason})")
    return {
        "client_id": client_id,
        "old_score": old_score,
        "new_score": new_score,
        "updated_at": data["risk_updated_at"],
    }


if __name__ == "__main__":
    mcp.run(transport="stdio")
