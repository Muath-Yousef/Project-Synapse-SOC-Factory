"""
SOC Root Evidence Store — Hash-Chained WORM Evidence System
Phase 1 Core Deliverable — Format FROZEN after first client record

WARNING: Do NOT modify field names, order, or hash computation after Phase 1 completion.
This is the audit continuity foundation. Changing format breaks all existing client chains.
"""

import hashlib
import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# Evidence storage root — all client chains live here
EVIDENCE_ROOT = Path(
    os.getenv("EVIDENCE_ROOT", "knowledge/evidence")
)


@dataclass
class EvidenceRecord:
    """
    Immutable evidence record — hash-chained for audit integrity.
    Field order is FROZEN — never reorder, rename, or add fields before record_hash.
    """
    # Core identification
    control_id: str                    # "NCA-2.3.1", "ISO-A.8.16"
    framework: str                     # "NCA_ECC_2.0", "ISO_27001"
    client_id: str
    scan_id: str
    status: str                        # "PASS" | "FAIL" | "PARTIAL"
    finding_summary: str               # audit-facing, non-technical language

    # Evidence sourcing
    source: str                        # "wazuh" | "cloudflare" | "dns_tool" | "nmap" | "nuclei"
    event_id: str                      # EXTERNAL ANCHOR — original system event ID

    # Integrity fields
    raw_log_hash: str                  # SHA-256 of raw log chunk
    timestamp: str                     # ISO 8601 UTC

    # Deployment mode — future-proof hook (Phase 5 hybrid deployment)
    origin: str = "remote"            # "remote" | "local_agent" | "air_gapped"

    # Chain fields — computed, do not set manually
    prev_record_hash: Optional[str] = None
    record_hash: Optional[str] = None

    # Hybrid mode reference — None until local agent deployed
    raw_log_ref: Optional[str] = None  # "local://client-host/logs/chunk_hash"

    def compute_hash(self) -> str:
        """
        Compute deterministic SHA-256 hash over all fields.
        Field serialization order matches dataclass definition order — FROZEN.
        """
        hash_payload = {
            "control_id": self.control_id,
            "framework": self.framework,
            "client_id": self.client_id,
            "scan_id": self.scan_id,
            "status": self.status,
            "finding_summary": self.finding_summary,
            "source": self.source,
            "event_id": self.event_id,
            "raw_log_hash": self.raw_log_hash,
            "timestamp": self.timestamp,
            "origin": self.origin,
            "prev_record_hash": self.prev_record_hash,
            "raw_log_ref": self.raw_log_ref,
        }
        # sort_keys=False — field order is locked to dict insertion order (Python 3.7+)
        serialized = json.dumps(hash_payload, ensure_ascii=False, separators=(",", ":"))
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict:
        """Serialize to dict for JSONL storage. Includes all fields."""
        return asdict(self)


class EvidenceStore:
    """
    Append-only hash-chained evidence store.
    One store per client. Storage: knowledge/evidence/{client_id}/chain.jsonl
    """

    def __init__(self, client_id: str):
        self.client_id = client_id
        self.store_dir = EVIDENCE_ROOT / client_id
        self.chain_file = self.store_dir / "chain.jsonl"
        self.store_dir.mkdir(parents=True, exist_ok=True)
        self._last_record_hash: Optional[str] = self._load_last_hash()

    def _load_last_hash(self) -> Optional[str]:
        """Load the hash of the last record in chain (for chaining new records)."""
        if not self.chain_file.exists():
            return None
        last_line = None
        with open(self.chain_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    last_line = line
        if last_line is None:
            return None
        last_record = json.loads(last_line)
        return last_record.get("record_hash")

    def append(self, record: EvidenceRecord) -> EvidenceRecord:
        """
        Append record to chain. WORM: no delete, no edit, ever.
        Sets prev_record_hash and record_hash before writing.
        """
        record.prev_record_hash = self._last_record_hash
        record.record_hash = record.compute_hash()

        # WORM append — open in append mode only
        with open(self.chain_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(record.to_dict(), ensure_ascii=False) + "\n")

        self._last_record_hash = record.record_hash
        return record

    def verify_chain(self) -> bool:
        """
        Verify integrity of entire chain.
        Returns True if chain is intact, False if any record is tampered.
        Called before every audit export — never skip.
        """
        if not self.chain_file.exists():
            return True  # Empty chain is valid

        records = []
        with open(self.chain_file, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append((line_num, json.loads(line)))
                except json.JSONDecodeError as e:
                    print(f"❌ Chain broken: invalid JSON at line {line_num}: {e}")
                    return False

        prev_hash = None
        for line_num, record_dict in records:
            # Reconstruct EvidenceRecord for hash verification
            stored_hash = record_dict.get("record_hash")
            stored_prev_hash = record_dict.get("prev_record_hash")

            # Verify prev_hash linkage
            if stored_prev_hash != prev_hash:
                print(f"❌ Chain broken at line {line_num}: prev_record_hash mismatch")
                print(f"   Expected: {prev_hash}")
                print(f"   Got:      {stored_prev_hash}")
                return False

            # Recompute hash to verify record integrity
            rec = EvidenceRecord(
                control_id=record_dict["control_id"],
                framework=record_dict["framework"],
                client_id=record_dict["client_id"],
                scan_id=record_dict["scan_id"],
                status=record_dict["status"],
                finding_summary=record_dict["finding_summary"],
                source=record_dict["source"],
                event_id=record_dict["event_id"],
                raw_log_hash=record_dict["raw_log_hash"],
                timestamp=record_dict["timestamp"],
                origin=record_dict.get("origin", "remote"),
                prev_record_hash=stored_prev_hash,
                raw_log_ref=record_dict.get("raw_log_ref"),
            )
            expected_hash = rec.compute_hash()

            if expected_hash != stored_hash:
                print(f"❌ Chain broken at line {line_num}: record_hash tampered")
                print(f"   Expected: {expected_hash}")
                print(f"   Got:      {stored_hash}")
                return False

            prev_hash = stored_hash

        return True

    def get_audit_package(self, scan_id: Optional[str] = None) -> dict:
        """
        Export audit-ready package. Runs verify_chain() first.
        Returns all records (or filtered by scan_id) + verification result.
        """
        integrity_ok = self.verify_chain()

        records = []
        if self.chain_file.exists():
            with open(self.chain_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        record = json.loads(line)
                        if scan_id is None or record.get("scan_id") == scan_id:
                            records.append(record)

        return {
            "client_id": self.client_id,
            "scan_id": scan_id,
            "export_timestamp": datetime.now(timezone.utc).isoformat(),
            "chain_integrity": "PASS" if integrity_ok else "FAIL",
            "record_count": len(records),
            "records": records,
            "export_format_version": "1.0",  # FROZEN — never change this
        }

    def get_records_by_control(self, control_id: str) -> list[dict]:
        """Return all evidence records for a specific control."""
        records = []
        if not self.chain_file.exists():
            return records
        with open(self.chain_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    record = json.loads(line)
                    if record.get("control_id") == control_id:
                        records.append(record)
        return records

    def get_latest_status(self, control_id: str) -> Optional[str]:
        """Return latest PASS/FAIL/PARTIAL for a control."""
        records = self.get_records_by_control(control_id)
        if not records:
            return None
        return records[-1].get("status")


def hash_raw_log(raw_log_content: str) -> str:
        """Compute SHA-256 hash of raw log content for external anchor."""
        return hashlib.sha256(raw_log_content.encode("utf-8")).hexdigest()


def create_evidence_record(
    client_id: str,
    scan_id: str,
    control_id: str,
    framework: str,
    status: str,
    finding_summary: str,
    source: str,
    event_id: str,
    raw_log_content: str,
    origin: str = "remote",
) -> EvidenceRecord:
    """Factory function: create EvidenceRecord from raw components."""
    return EvidenceRecord(
        control_id=control_id,
        framework=framework,
        client_id=client_id,
        scan_id=scan_id,
        status=status,
        finding_summary=finding_summary,
        source=source,
        event_id=event_id,
        raw_log_hash=hash_raw_log(raw_log_content),
        timestamp=datetime.now(timezone.utc).isoformat(),
        origin=origin,
    )
