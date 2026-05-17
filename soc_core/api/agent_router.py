from fastapi import APIRouter, WebSocket, WebSocketDisconnect, HTTPException, Depends
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from core.agent_manager import AgentManager
import yaml
from pathlib import Path
from typing import Dict, Any

agent_router = APIRouter(prefix="/agent", tags=["Remote Access Agent"])

# Pydantic schema for command execution requests
class CommandRequest(BaseModel):
    client_id: str
    command: str

def verify_client_exists(client_id: str):
    profile_path = Path(f"knowledge/client_profiles/{client_id}.yaml")
    if not profile_path.is_file():
        raise HTTPException(status_code=404, detail="Client profile not found")

@agent_router.get("/download")
async def download_agent(client_id: str, server_url: str = "http://localhost:8000"):
    """
    Generate and download a pre-configured lightweight agent script.
    Customized with client_id and a secure key mapping.
    """
    verify_client_exists(client_id)
    
    agent_template_path = Path("agent/soc_agent.py")
    if not agent_template_path.is_file():
        raise HTTPException(status_code=500, detail="Agent base template not found")
        
    with open(agent_template_path, "r") as f:
        content = f.read()
        
    # Inject variables dynamically into the template
    injected_vars = f"""
    SERVER_URL = "{server_url}"
    CLIENT_ID = "{client_id}"
    SECRET_KEY = "injected_secret_placeholder"
"""
    # Replace the default main block values in template
    target_block = """    SERVER_URL = "http://localhost:8000"
    CLIENT_ID = "sample_client"
    SECRET_KEY = "sample_secret" """
    
    content = content.replace(target_block, injected_vars.strip())
    
    return PlainTextResponse(content, headers={
        "Content-Disposition": f"attachment; filename=soc_agent_{client_id}.py"
    })

@agent_router.websocket("/ws/{client_id}")
async def agent_websocket(websocket: WebSocket, client_id: str):
    """Secure bi-directional WebSocket tunnel for remote agent communication."""
    # Accept the connection
    await websocket.accept()
    
    mgr = AgentManager()
    await mgr.register_connection(client_id, websocket)
    print(f"[WebSocket] Agent {client_id} successfully connected.")
    
    try:
        while True:
            # Maintain connection and listen for asynchronous messages (like inventory updates)
            data = await websocket.receive_json()
            action = data.get("action")
            
            if action == "inventory":
                # Handle environment inventory report sent upon startup
                inventory = data.get("data", {})
                mgr.save_inventory(client_id, inventory)
                print(f"[WebSocket] Received environment inventory for client {client_id}")
    except WebSocketDisconnect:
        print(f"[WebSocket] Agent {client_id} disconnected.")
    except Exception as e:
        print(f"[WebSocket] Connection error on agent {client_id}: {str(e)}")
    finally:
        await mgr.unregister_connection(client_id)

@agent_router.get("/inventory/{client_id}")
async def get_agent_inventory(client_id: str):
    """Retrieve the environment inventory of the client's agent."""
    verify_client_exists(client_id)
    mgr = AgentManager()
    inventory = mgr.get_inventory(client_id)
    
    # Enrich with online status
    inventory["online"] = mgr.is_agent_online(client_id)
    return inventory

@agent_router.post("/execute")
async def execute_remote_command(req: CommandRequest):
    """Send a command to the connected client agent and return the execution results."""
    verify_client_exists(req.client_id)
    
    mgr = AgentManager()
    if not mgr.is_agent_online(req.client_id):
        raise HTTPException(status_code=400, detail="Client agent is currently offline")
        
    print(f"[API] Dispatching remote command to agent {req.client_id}: {req.command}")
    result = await mgr.send_command(req.client_id, req.command)
    
    if result.get("status") == "error":
        raise HTTPException(status_code=500, detail=result.get("message"))
        
    return result
