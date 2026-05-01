# SOC ROOT — PROJECT INTELLIGENCE FILE
# Read this file completely before taking any action.

## North Star
Revenue-generating managed compliance + security service for MENA SMBs.
24 clients / 24 months / 60%+ gross margin.

## Identity
- Company: SOC Root (socroot.com)
- Stack: Python, Wazuh, Shuffle SOAR, TheHive, ChromaDB, Cloudflare WAF,
         Gemini 2.0 Flash, fpdf2, Ansible, Docker, Contabo VPS
- Repo: /media/kyrie/VMs1/Cybersecurity_Tools_Automation
- Branch convention: phase{N}-{description}

## Infrastructure
- Node A: 167.86.98.91 — Wazuh SIEM (SSH port 2222)
- Node B: 164.68.121.179 — SOAR/Webhook (SSH port 2222)
- Local: /media/kyrie/VMs1/Cybersecurity_Tools_Automation

## Current Phase
Phase 1 — Evidence System Foundation
Active client: AsasEdu (asas4edu.net)

## Safety Rules (NEVER VIOLATE)
1. SOAR_DRY_RUN=true always — never change without explicit owner text
2. Never block RFC1918, CDN IPs (Cloudflare/Akamai/Fastly/CloudFront)
3. Never scan domain not in client whitelist
4. Never commit .env or credentials
5. EvidenceRecord schema is FROZEN after first record — never change field names
6. Evidence chain.jsonl is APPEND-ONLY — no delete, no edit

## Scope Creep Rule
Before any code: state "Phase N, Deliverable X, in scope."
If cannot make this statement → output SCOPE FLAG → stop.

## Communication Format (end every response with this)
### Files Modified: [paths]
### Tests: [X/Y passing]
### Next Action: [what comes next]
### Flags: [any cost, scope, or safety flags]
