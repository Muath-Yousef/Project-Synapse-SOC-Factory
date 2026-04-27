# Evidence Methodology Document
**Status:** FROZEN (Phase 1 Complete)
**Classification:** Internal / Auditor Facing

## 1. Objective
This document outlines the cryptographic evidence chaining methodology used within the SOC automation platform to ensure that compliance findings and security alerts are stored in a Write-Once-Read-Many (WORM) format. This guarantees non-repudiation and integrity for external IT auditors.

## 2. Core Architecture
The evidence system utilizes a linked-list cryptographic hashing mechanism (Hash Chain) over JSON Lines (JSONL).
- **Append-Only Store:** Evidence records are strictly appended to the chain.
- **Cryptographic Hash:** Each record computes its own `record_hash` using SHA-256.
- **Chain Link:** Each record stores the `record_hash` of the preceding record in its `prev_record_hash` field.
- **Root Node:** The first record in any chain has a `prev_record_hash` of `null`.

## 3. Data Schema (Frozen)
The schema for the `EvidenceRecord` is frozen. Modifying the fields, their order, or the hashing algorithm will break the evidence chain.

- `control_id` (string): The associated framework control ID (e.g., "NCA-2.3.1").
- `framework` (string): The compliance framework (e.g., "NCA_ECC_2.0").
- `client_id` (string): The unique identifier for the tenant/client.
- `scan_id` (string): The identifier for the execution run.
- `status` (string): "PASS", "FAIL", or "PARTIAL".
- `finding_summary` (string): Auditor-friendly explanation of the finding.
- `source` (string): Origin system of the event (e.g., "wazuh", "compliance_engine").
- `event_id` (string): The external anchor ID (e.g., Wazuh alert ID).
- `raw_log_hash` (string): SHA-256 hash of the raw log to decouple PII from the chain.
- `timestamp` (string): ISO 8601 UTC timestamp of record creation.
- `origin` (string): Environment origin (e.g., "remote").
- `prev_record_hash` (string | null): The SHA-256 hash of the previous record.
- `record_hash` (string): The SHA-256 hash of the current record.
- `raw_log_ref` (string | null): Reference URI to the raw log, if applicable.

## 4. Hash Computation
The hash is computed over a strictly deterministic JSON serialization of the record properties.

```python
hash_string = f"{control_id}|{framework}|{client_id}|{scan_id}|{status}|{finding_summary}|{source}|{event_id}|{raw_log_hash}|{timestamp}|{origin}|{prev_record_hash}"
record_hash = hashlib.sha256(hash_string.encode("utf-8")).hexdigest()
```

## 5. Auditor Verification Process
Auditors can verify the integrity of the evidence chain at any point by running:
```bash
python3 main_orchestrator.py --verify-evidence --client <CLIENT_ID>
```

Auditors can export a full audit package by running:
```bash
python3 main_orchestrator.py --export-evidence --client <CLIENT_ID>
```
The export will block automatically if the chain is broken.

## 6. Regulatory Mapping
The mappings for specific rules (e.g., Wazuh alerts to NCA ECC 2.0 controls) are detailed in `knowledge/compliance_frameworks/nca_controls.json`.
