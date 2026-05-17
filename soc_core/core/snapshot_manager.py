import os
import shutil
import zipfile
from datetime import datetime, timezone
from pathlib import Path

class SnapshotManager:
    """Manager to create and store system snapshots before critical operations."""
    
    def __init__(self, base_dir: str = "."):
        self.base_dir = Path(base_dir).resolve()
        self.snapshots_dir = self.base_dir / "backups" / "snapshots"
        self.profiles_dir = self.base_dir / "knowledge" / "client_profiles"
        self.evidence_dir = self.base_dir / "knowledge" / "evidence"
        
        # Ensure snapshot directory exists
        self.snapshots_dir.mkdir(parents=True, exist_ok=True)

    def create_snapshot(self, client_id: str, trigger: str = "auto") -> dict:
        """
        Creates a ZIP archive containing the client's current profile and evidence.
        trigger: 'auto' (e.g. before scan) or 'manual' (from portal)
        """
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        snapshot_filename = f"{client_id}_{timestamp}_{trigger}_snapshot.zip"
        snapshot_path = self.snapshots_dir / snapshot_filename
        
        profile_path = self.profiles_dir / f"{client_id}.yaml"
        client_evidence_dir = self.evidence_dir / client_id

        # We will collect all files to zip
        files_to_zip = []
        
        if profile_path.is_file():
            files_to_zip.append((profile_path, f"client_profiles/{profile_path.name}"))
            
        if client_evidence_dir.is_dir():
            for root, _, files in os.walk(client_evidence_dir):
                for file in files:
                    file_path = Path(root) / file
                    # Calculate relative path inside the zip
                    arcname = f"evidence/{file_path.relative_to(self.evidence_dir)}"
                    files_to_zip.append((file_path, arcname))

        if not files_to_zip:
            return {"status": "error", "message": "No data found to snapshot for this client."}

        # Create the zip file
        with zipfile.ZipFile(snapshot_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file_path, arcname in files_to_zip:
                zipf.write(file_path, arcname)
                
        snapshot_size = snapshot_path.stat().st_size
        
        return {
            "status": "success",
            "snapshot_id": snapshot_filename,
            "path": str(snapshot_path),
            "size_bytes": snapshot_size,
            "timestamp": timestamp,
            "trigger": trigger
        }

    def list_snapshots(self, client_id: str) -> list:
        """List all snapshots for a given client."""
        if not self.snapshots_dir.is_dir():
            return []
            
        snapshots = []
        for file in self.snapshots_dir.glob(f"{client_id}_*.zip"):
            stats = file.stat()
            snapshots.append({
                "snapshot_id": file.name,
                "size_bytes": stats.st_size,
                "created_at": datetime.fromtimestamp(stats.st_mtime, tz=timezone.utc).isoformat()
            })
            
        return sorted(snapshots, key=lambda x: x["created_at"], reverse=True)
