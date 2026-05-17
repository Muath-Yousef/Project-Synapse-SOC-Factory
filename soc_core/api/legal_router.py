from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel
from core.legal_manager import LegalManager
import yaml
from pathlib import Path

legal_router = APIRouter(prefix="/legal", tags=["Legal & Compliance"])

def get_profile(client_id: str):
    profile_path = Path(f"knowledge/client_profiles/{client_id}.yaml")
    if not profile_path.is_file():
        raise HTTPException(status_code=404, detail="Client profile not found")
    with open(profile_path, "r") as f:
        return yaml.safe_load(f) or {}

@legal_router.get("/contract")
async def get_contract(client_id: str): # Usually we'd use Depends(get_current_client) but for brevity in this standalone router we'll just require client_id or pass it properly in app.py
    """Get the text of the Rules of Engagement contract for the client's domain."""
    profile = get_profile(client_id)
    domain = profile.get("domain")
    if not domain:
        raise HTTPException(status_code=400, detail="Domain not configured for this client.")
        
    mgr = LegalManager()
    contract_text = mgr.generate_roe(client_id, domain)
    return {"client_id": client_id, "domain": domain, "contract_text": contract_text}

class SignRequest(BaseModel):
    client_id: str
    domain: str

@legal_router.post("/sign")
async def sign_contract(req: SignRequest, request: Request):
    """Electronically sign the RoE and NDA (Clickwrap)."""
    # In a real scenario we use Depends(get_current_client) to ensure the client_id matches the token
    ip_address = request.client.host if request.client else "Unknown"
    user_agent = request.headers.get("user-agent", "Unknown")
    
    mgr = LegalManager()
    result = mgr.sign_contract(req.client_id, req.domain, ip_address, user_agent)
    
    if result.get("status") == "error":
        raise HTTPException(status_code=400, detail=result.get("message"))
        
    return result

@legal_router.get("/status")
async def get_legal_status(client_id: str):
    """Check if the client has signed the required legal documents."""
    profile = get_profile(client_id)
    domain = profile.get("domain")
    if not domain:
        raise HTTPException(status_code=400, detail="Domain not configured.")
        
    mgr = LegalManager()
    is_authorized = mgr.verify_authorization(client_id, domain)
    
    return {
        "client_id": client_id,
        "domain": domain,
        "is_authorized": is_authorized
    }
