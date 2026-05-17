import os
import yaml
from pathlib import Path
from typing import Dict, Any
from fastapi import WebSocket

class AgentManager:
    """Manages active remote agent WebSocket sessions and environment inventories."""
    
    # Class-level storage to persist active WebSocket sessions across requests
    active_connections: Dict[str, WebSocket] = {}

    def __init__(self, base_dir: str = "."):
        self.base_dir = Path(base_dir).resolve()
        self.inventories_dir = self.base_dir / "knowledge" / "agent_inventories"
        self.inventories_dir.mkdir(parents=True, exist_ok=True)

    async def register_connection(self, client_id: str, websocket: WebSocket):
        """Register a new active WebSocket session for a client agent."""
        self.active_connections[client_id] = websocket

    async def unregister_connection(self, client_id: str):
        """Unregister an active WebSocket session."""
        if client_id in self.active_connections:
            del self.active_connections[client_id]

    def is_agent_online(self, client_id: str) -> bool:
        """Check if the client's agent is currently connected."""
        return client_id in self.active_connections

    def save_inventory(self, client_id: str, inventory_data: Dict[str, Any]):
        """Save environment inventory gathered by the remote agent to a YAML file."""
        file_path = self.inventories_dir / f"{client_id}.yaml"
        with open(file_path, "w") as f:
            yaml.safe_dump(inventory_data, f, default_flow_style=False)

    def get_inventory(self, client_id: str) -> Dict[str, Any]:
        """Retrieve the environment inventory of a client's agent."""
        file_path = self.inventories_dir / f"{client_id}.yaml"
        if not file_path.is_file():
            return {}
        with open(file_path, "r") as f:
            return yaml.safe_load(f) or {}

    async def send_command(self, client_id: str, command: str) -> Dict[str, Any]:
        """Send a remote execution command to the connected client agent and await result."""
        websocket = self.active_connections.get(client_id)
        if not websocket:
            return {"status": "error", "message": "Agent offline or not connected"}

        try:
            # Send command request
            payload = {"action": "execute", "command": command}
            await websocket.send_json(payload)
            
            # Wait for response (bi-directional RPC over websocket)
            response = await websocket.receive_json()
            return response
        except Exception as e:
            await self.unregister_connection(client_id)
            return {"status": "error", "message": f"Failed to communicate with agent: {str(e)}"}
