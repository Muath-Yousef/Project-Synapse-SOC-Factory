import secrets
import string
import time
import json
import os
from pathlib import Path

OTP_STORE_PATH = Path("/opt/synapse/data/otp_store.json")
# Local fallback
if not os.path.exists("/opt/synapse/data"):
    OTP_STORE_PATH = Path("/tmp/otp_store.json")

OTP_EXPIRY_SECONDS = 600  # 10 minutes

def generate_otp(length: int = 6) -> str:
    """Cryptographically secure numeric OTP."""
    return ''.join(secrets.choice(string.digits) for _ in range(length))

def store_otp(email: str, otp: str) -> None:
    store = _load_store()
    store[email] = {
        "otp": otp,
        "created_at": time.time(),
        "verified": False
    }
    _save_store(store)

def verify_otp(email: str, otp: str) -> bool:
    store = _load_store()
    entry = store.get(email)
    if not entry:
        return False
    if time.time() - entry["created_at"] > OTP_EXPIRY_SECONDS:
        del store[email]
        _save_store(store)
        return False
    if entry["otp"] != otp:
        return False
    # Mark as verified, delete from store
    del store[email]
    _save_store(store)
    return True

def _load_store() -> dict:
    if not OTP_STORE_PATH.exists():
        return {}
    with open(OTP_STORE_PATH) as f:
        return json.load(f)

def _save_store(store: dict) -> None:
    OTP_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OTP_STORE_PATH, 'w') as f:
        json.dump(store, f)
