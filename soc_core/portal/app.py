import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
import yaml
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from jose import JWTError, jwt

# FastAPI app
app = FastAPI(title="SOC Root Client Portal", version="1.0.0")

from api.billing_router import billing_router
app.include_router(billing_router)

from api.legal_router import legal_router
app.include_router(legal_router)

# Environment configuration
SECRET_KEY = os.getenv("PORTAL_SECRET_KEY", "change-me-in-production")
ALGORITHM = "HS256"
TOKEN_EXPIRE_MINUTES = 60

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

# CORS configuration (adjust origins as needed)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://socroot.com", "http://localhost:8000"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)

def create_access_token(client_id: str, expires_delta: timedelta = timedelta(minutes=TOKEN_EXPIRE_MINUTES)) -> str:
    expire = datetime.now(timezone.utc) + expires_delta
    payload = {"sub": client_id, "exp": expire, "type": "client"}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_client(token: str = Depends(oauth2_scheme)) -> str:
    """Validate JWT and extract client identifier."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        client_id: str = payload.get("sub")
        if client_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        return client_id
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

@app.post("/auth/login")
async def login(form: OAuth2PasswordRequestForm = Depends()):
    """Authenticate a client using client_id and API key stored in YAML profile."""
    profile_path = Path(f"knowledge/client_profiles/{form.username}.yaml")
    if not profile_path.is_file():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    with open(profile_path) as f:
        profile = yaml.safe_load(f)
    # The API key is stored as a SHA256 hash in the profile
    provided_hash = jwt.sha256(form.password.encode()).hexdigest() if hasattr(jwt, "sha256") else None
    # Fallback using hashlib if jwt.sha256 unavailable
    if provided_hash is None:
        import hashlib
        provided_hash = hashlib.sha256(form.password.encode()).hexdigest()
    if profile.get("portal_api_key_hash") != provided_hash:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    token = create_access_token(form.username)
    return {"access_token": token, "token_type": "bearer"}

async def require_active_subscription(client_id: str = Depends(get_current_client)) -> str:
    """Dependency to ensure the client has an active subscription."""
    profile_path = Path(f"knowledge/client_profiles/{client_id}.yaml")
    if not profile_path.is_file():
        raise HTTPException(status_code=404, detail="Client profile not found")
    with open(profile_path) as f:
        profile = yaml.safe_load(f)
        
    if profile.get("subscription_status") != "active":
        raise HTTPException(status_code=402, detail="Payment Required: Active subscription needed for this feature.")
    return client_id

async def require_legal_authorization(client_id: str = Depends(require_active_subscription)) -> str:
    """Dependency to ensure the client has signed the RoE/NDA for their domain."""
    from core.legal_manager import LegalManager
    profile_path = Path(f"knowledge/client_profiles/{client_id}.yaml")
    with open(profile_path) as f:
        profile = yaml.safe_load(f)
        
    domain = profile.get("domain")
    if not domain:
        raise HTTPException(status_code=400, detail="Domain not configured for client")
        
    mgr = LegalManager()
    if not mgr.verify_authorization(client_id, domain):
        raise HTTPException(status_code=403, detail="Forbidden: Legal Authorization (RoE/NDA) required before testing.")
        
    return client_id

@app.get("/dashboard")
async def get_dashboard(client_id: str = Depends(get_current_client)):
    """Return client specific dashboard data."""
    from soc.evidence_store import EvidenceStore
    store = EvidenceStore(client_id)
    chain_ok = store.verify_chain()
    profile_path = Path(f"knowledge/client_profiles/{client_id}.yaml")
    if not profile_path.is_file():
        raise HTTPException(status_code=404, detail="Client profile not found")
    with open(profile_path) as f:
        profile = yaml.safe_load(f)
    return {
        "client_id": client_id,
        "domain": profile.get("domain"),
        "tier": profile.get("tier"),
        "compliance_score": profile.get("last_compliance_score", 0),
        "last_scan": profile.get("last_scan_date"),
        "evidence_chain_integrity": "PASS" if chain_ok else "FAIL",
        "open_findings": profile.get("open_findings_count", 0),
    }

@app.get("/reports")
async def list_reports(client_id: str = Depends(get_current_client)):
    """List generated PDF reports for the client."""
    reports_dir = Path("reports")
    reports = []
    for file in reports_dir.glob(f"{client_id}_*.pdf"):
        stats = file.stat()
        reports.append({
            "filename": file.name,
            "size_kb": stats.st_size // 1024,
            "created": datetime.fromtimestamp(stats.st_mtime).isoformat(),
        })
    return {"client_id": client_id, "reports": sorted(reports, key=lambda x: x["created"], reverse=True)}

@app.get("/findings")
async def get_findings(client_id: str = Depends(get_current_client), severity: str | None = None, limit: int = 50):
    """Retrieve findings for the client, optionally filtered by severity."""
    from soc.evidence_store import EvidenceStore
    store = EvidenceStore(client_id)
    package = store.get_audit_package()
    records = package.get("records", [])
    if severity:
        records = [r for r in records if r.get("status", "").upper() == severity.upper()]
    return {"client_id": client_id, "total": len(records), "findings": records[:limit]}

@app.post("/scan/request")
async def request_scan(client_id: str = Depends(require_legal_authorization)):
    """Trigger an asynchronous scan for the client domain. Requires active subscription and signed RoE."""
    import subprocess
    from core.snapshot_manager import SnapshotManager
    
    # Take a safety snapshot BEFORE the scan
    snapshot_mgr = SnapshotManager()
    snapshot_result = snapshot_mgr.create_snapshot(client_id, trigger="auto_scan_prep")
    
    if snapshot_result.get("status") == "error":
        # Log it, but maybe we shouldn't block the scan if they have no evidence yet
        pass

    profile_path = Path(f"knowledge/client_profiles/{client_id}.yaml")
    if not profile_path.is_file():
        raise HTTPException(status_code=404, detail="Client profile not found")
    with open(profile_path) as f:
        profile = yaml.safe_load(f)
    domain = profile.get("domain")
    if not domain:
        raise HTTPException(status_code=400, detail="Domain not configured for client")
    # Launch the orchestrator asynchronously
    subprocess.Popen([
        "python3",
        "main_orchestrator.py",
        "--client",
        client_id,
        "--domain",
        domain,
        "--async",
    ])
    return {
        "message": f"Scan queued for {domain}", 
        "estimated_completion": "30 minutes", 
        "client_id": client_id,
        "pre_scan_snapshot": snapshot_result.get("snapshot_id")
    }

@app.post("/snapshots/create")
async def create_snapshot(client_id: str = Depends(get_current_client)):
    """Manually trigger a snapshot of the client's current evidence and profile."""
    from core.snapshot_manager import SnapshotManager
    snapshot_mgr = SnapshotManager()
    result = snapshot_mgr.create_snapshot(client_id, trigger="manual")
    if result.get("status") == "error":
        raise HTTPException(status_code=404, detail=result.get("message"))
    return result

@app.get("/snapshots")
async def list_snapshots(client_id: str = Depends(get_current_client)):
    """List all snapshots for the client."""
    from core.snapshot_manager import SnapshotManager
    snapshot_mgr = SnapshotManager()
    return {"client_id": client_id, "snapshots": snapshot_mgr.list_snapshots(client_id)}
