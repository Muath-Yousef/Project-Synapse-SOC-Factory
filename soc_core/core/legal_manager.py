import os
import yaml
from datetime import datetime, timezone
from pathlib import Path

class LegalManager:
    """Manager to handle legal contracts, Rules of Engagement (RoE), and NDAs."""
    
    def __init__(self, base_dir: str = "."):
        self.base_dir = Path(base_dir).resolve()
        self.profiles_dir = self.base_dir / "knowledge" / "client_profiles"
        self.contracts_dir = self.base_dir / "knowledge" / "contracts"
        
        self.contracts_dir.mkdir(parents=True, exist_ok=True)

    def _get_profile_path(self, client_id: str) -> Path:
        return self.profiles_dir / f"{client_id}.yaml"

    def _load_profile(self, client_id: str) -> dict:
        profile_path = self._get_profile_path(client_id)
        if not profile_path.is_file():
            return {}
        with open(profile_path, "r") as f:
            return yaml.safe_load(f) or {}

    def _save_profile(self, client_id: str, profile_data: dict):
        profile_path = self._get_profile_path(client_id)
        with open(profile_path, "w") as f:
            yaml.safe_dump(profile_data, f, default_flow_style=False)

    def generate_roe(self, client_id: str, domain: str) -> str:
        """Generate the Rules of Engagement text for the given domain."""
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        roe_text = f"""
RULES OF ENGAGEMENT (RoE) & NON-DISCLOSURE AGREEMENT (NDA)
Date: {date_str}
Client ID: {client_id}
Authorized Domain: {domain}

1. AUTHORIZATION
The Client authorizes SOCRoot to perform security assessments, penetration testing, 
and vulnerability scanning exclusively against the Authorized Domain mentioned above.

2. SCOPE AND LIMITATIONS
The assessment is strictly limited to the Authorized Domain. SOCRoot will not intentionally 
target third-party services, out-of-scope subdomains, or physical infrastructure.

3. LIABILITY
SOCRoot operates under standard security assessment practices. The Client acknowledges that 
security testing carries inherent risks, including potential service disruptions. SOCRoot 
shall not be held liable for any direct or indirect damages, data loss, or business 
interruptions resulting from authorized testing activities.

4. CONFIDENTIALITY (NDA)
Both parties agree to treat all findings, vulnerability reports, and proprietary 
information exchanged during the assessment as strictly confidential.

By signing this document, the Client represents that they are the legal owner of the 
Authorized Domain or have explicit written permission from the owner to authorize this test.
"""
        return roe_text.strip()

    def sign_contract(self, client_id: str, domain: str, ip_address: str, user_agent: str) -> dict:
        """Sign the contract electronically (Clickwrap)."""
        profile = self._load_profile(client_id)
        if not profile:
            return {"status": "error", "message": "Client profile not found"}
            
        if profile.get("domain") != domain:
            return {"status": "error", "message": "Domain mismatch with profile configuration"}

        timestamp = datetime.now(timezone.utc).isoformat()
        
        # Save contract text
        roe_text = self.generate_roe(client_id, domain)
        contract_filename = f"{client_id}_{domain}_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}.txt"
        contract_path = self.contracts_dir / contract_filename
        with open(contract_path, "w") as f:
            f.write(roe_text)
            f.write(f"\n\n--- ELECTRONIC SIGNATURE ---\n")
            f.write(f"Signed By IP: {ip_address}\n")
            f.write(f"User Agent: {user_agent}\n")
            f.write(f"Timestamp: {timestamp}\n")

        # Update profile
        if "legal" not in profile:
            profile["legal"] = {}
        
        profile["legal"]["roe_signed"] = True
        profile["legal"]["roe_signed_at"] = timestamp
        profile["legal"]["roe_signed_ip"] = ip_address
        profile["legal"]["contract_file"] = contract_filename
        
        self._save_profile(client_id, profile)
        
        return {
            "status": "success", 
            "message": "Contract signed successfully",
            "contract_file": contract_filename
        }

    def verify_authorization(self, client_id: str, domain: str) -> bool:
        """Verify if the client has a valid, signed RoE for the requested domain."""
        profile = self._load_profile(client_id)
        if not profile:
            return False
            
        # Domain must match exactly what's in the profile
        if profile.get("domain") != domain:
            return False
            
        legal_data = profile.get("legal", {})
        if not legal_data.get("roe_signed"):
            return False
            
        return True
