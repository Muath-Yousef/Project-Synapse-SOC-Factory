# MSSP Scale Out Guide (Phase 7+)

## Architecture
The Synapse platform uses a hub-and-spoke model.
- **Control Plane (Hub):** Handles correlation, SOAR decisions, and LLM triage.
- **Nodes (Spokes):** Lightweight agents on Contabo/Hetzner nodes for individual client scans.

## Onboarding a New Client
1. Add the client profile to `onboarding/client_profiles.yaml`.
2. Ensure the client's network allows access from our dedicated scanner IPs.
3. The Scheduler will automatically pick up the new client on the next cycle.

## Scaling Nodes
- Deploy a new Ubuntu 22.04 node.
- Clone the repository and run `setup.sh` (or `setup_node.sh` when available).
- The node will connect to the central task queue.

## Correlation
The Correlation Engine (`soc/correlation_engine.py`) aggregates logs from Wazuh, Cloudflare, and Okta across the fleet. Make sure nodes are properly forwarding logs to the central SIEM.

## Model Routing
Tasks are routed to the most efficient LLM using `core/llm_router.py`.
- **DeepSeek:** Translation (Arabic)
- **Claude Sonnet:** High-confidence Threat Analysis
- **Gemini Flash:** Report writing and low-tier triage.
