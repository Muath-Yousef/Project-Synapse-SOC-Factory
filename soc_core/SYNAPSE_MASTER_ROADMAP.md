# PROJECT SYNAPSE SOC FACTORY — MASTER ROADMAP
> **Version:** 1.0 — April 2026  
> **Authority:** This document is the single source of truth for all AI agents (including antigravity) executing on Project Synapse. No phase may be started without reading this document in full.  
> **Owner:** Muath Yousef — Kyrie Security Architect  
> **Classification:** INTERNAL — STRATEGIC

---

## PART 0: PROJECT IDENTITY & VISION

### 0.1 What This Project Is

Project Synapse SOC Factory is a **sovereign, AI-native MSSP (Managed Security Service Provider)** targeting SMBs in Jordan and the UAE. It delivers enterprise-grade cybersecurity through maximum automation — reducing human labor per client to under 2 hours/month while maintaining professional service quality.

### 0.2 The Final Product (Target State)

When complete, Project Synapse is a platform that:

1. **Receives a client domain or IP** → runs a full automated security lifecycle
2. **Monitors client infrastructure 24/7** → detects threats in real-time via SIEM
3. **Responds automatically** → SOAR playbooks execute without human intervention
4. **Reports professionally** → branded PDF delivered to client on schedule
5. **Upsells intelligently** → AI identifies new service opportunities from scan results
6. **Scales to 50+ clients** → without proportional increase in human effort

### 0.3 Business Model

| Package | Code Tier | Price | Target Client |
|---|---|---|---|
| Starter | soc_lite | JOD 690/year | Micro-business, basic website |
| Guard | soc_standard | JOD 590/month | SMB with active web presence |
| Governance | soc_pro | JOD 780/month | SMB needing compliance |
| Premium | soc_grc | JOD 1,250/month | Enterprise SMB, regulated sector |

**Break-even target:** 18–24 active clients by Month 22–24  
**Automation target:** 84% average across all services  
**Primary market:** Jordan (NCA ECC 2.0), UAE (PDPL, ADHICS)

### 0.4 Current State (April 2026)

```
✅ Phase 1–25: Core engine built and tested (60/60 tests green)
✅ Phase 23: Production infrastructure live — Contabo Node A + Node B
✅ Phase 26: Wazuh webhook tested and verified live
✅ Phase 27: UFW hardening — production secured
✅ Phase 28: First client (AsasEdu) onboarded and scanned
✅ Executive PDF report generated and client-ready
❌ First paid contract — NOT YET SIGNED
❌ Telegram → Full pipeline end-to-end with real AI — partial
❌ Client portal (web UI) — not built
❌ Automated upsell pipeline — not built
```

---

## PART 1: ARCHITECTURE OVERVIEW

### 1.1 Core Pipeline (Immutable Principle)

```
CLIENT INPUT
     ↓
[Onboarding] → client profile YAML created
     ↓
[Scanner Layer] → subfinder + nmap + nuclei + dns + testssl + virustotal + blacklist + nvd
     ↓
[Parser + Aggregator] → standardized JSON findings
     ↓
[RAG Layer] → ChromaDB context injection (frameworks: NCA, ISO 27001, MITRE ATT&CK)
     ↓
[AI Triage] → Gemini 2.0 Flash analysis (threat modeler perspective)
     ↓
[Compliance Engine] → Score 0–100, Grade A–F, NCA ECC 2.0 mapping
     ↓
[Delta Analyzer] → compare with historical baseline, detect new risks
     ↓
[SOAR Router] → alert_router → playbook execution → cloudflare/telegram/email actions
     ↓
[Report Generator] → Internal SOC report + Client Executive PDF
     ↓
[Email Delivery] → branded report to client
     ↓
[Scheduler] → stores baseline, schedules next scan (weekly/monthly)
```

### 1.2 Infrastructure (Production — April 2026)

```
Node A (Contabo VPS — 167.86.98.91)
  └── Wazuh 4.7.3 (Docker)
  └── Elasticsearch + Kibana
  └── UFW: ports 22, 1514, 514/UDP only

Node B (Contabo VPS — 164.68.121.179)
  └── webhook_server.py (port 5000 — Node A only)
  └── TheHive (port 9000)
  └── Shuffle SOAR (port 3001)
  └── UFW: port 5000 restricted to Node A IP only

Local Machine (/media/kyrie/VMs1/Cybersecurity_Tools_Automation)
  └── main_orchestrator.py (CLI brain)
  └── All scanning tools, agents, parsers
  └── ChromaDB vector store
  └── Report generators
```

### 1.3 AI Stack (Current + Target)

| Task | Current Model | Target Model | Trigger to Switch |
|---|---|---|---|
| Threat Analysis & Triage | Gemini 2.0 Flash | Claude Sonnet (via API) | First paid client |
| Report Writing | Gemini 2.0 Flash | Gemini 2.5 Flash | >5 clients active |
| Fast Classification/Routing | Gemini 2.0 Flash | Gemini Flash (keep) | Never change |
| Sensitive Data Processing | None (gap) | Local LLM (Ollama) | When client data sensitivity requires |
| Embeddings / RAG | ChromaDB default | text-embedding-3-small | >10 clients |

---

## PART 2: SERVICE CATALOG

### 2.1 Services Currently Available (Engine Ready)

| Service | Automation % | Tools Used | Human Time/Month |
|---|---|---|---|
| External Pentest / Assessment | 93% | subfinder, nmap, nuclei, nvd | 30 min |
| Email Security Audit | 94% | dns_tool (SPF/DKIM/DMARC/BIMI) | 20 min |
| TLS/SSL Audit | 91% | testssl | 15 min |
| Vulnerability Assessment | 92% | nuclei, nvd_matcher | 30 min |
| Reputation & Blacklist Check | 95% | virustotal, blacklist_tool | 10 min |
| SOC Alert Triage | 88% | Wazuh + alert_router + playbooks | per incident |
| Delta / Change Detection | 91% | delta_analyzer + history | 10 min |
| Monthly Reporting | 91% | report_generator + email | 15 min/client |
| Compliance Scoring (NCA) | 88% | compliance_engine | 20 min |

### 2.2 Services to Build (Roadmap)

| Service | Phase | Complexity | Revenue Impact |
|---|---|---|---|
| Client Web Portal | Phase 30 | Medium | High — self-service onboarding |
| Cloudflare WAF Management | Phase 31 | Low | High — recurring revenue |
| Automated Upsell Engine | Phase 32 | Medium | Very High |
| vCISO Monthly Reports | Phase 33 | High | Very High — premium tier |
| Dark Web Monitoring | Phase 34 | Medium | High |
| Phishing Simulation | Phase 35 | High | Medium |
| ISO 27001 Gap Assessment | Phase 36 | High | Premium tier |

---

## PART 3: COMPLETED PHASES (REFERENCE)

| Phase | Description | Status | Commit |
|---|---|---|---|
| 1–17 | Core engine: parsers, RAG, LLM, agents, SOAR, reporting, onboarding | ✅ | Various |
| 18 | TLS/SSL + GeoIP + BIMI + OpenRelay | ✅ | 07593f8 |
| 19 | Delta Analyzer + Compliance Scoring | ✅ | ddac540 |
| 20 | Blacklist RBL + Contract Manager | ✅ | 2606451 |
| 21 | Master E2E — 8/8 passing | ✅ | 45b8e9e |
| 22 | Router + GeoIP + Scheduler fixes | ✅ | 17816cc |
| 23 | Ansible deploy + TheHive/Shuffle Docker | ✅ | 189f1da |
| 24 | Control Plane Data Model | ✅ | — |
| 25 | Control Plane Hardening + SOAR Inline | ✅ | — |
| 26 | Wazuh webhook LIVE on Contabo VPS | ✅ | — |
| 27 | UFW Production Hardening | ✅ | — |
| 28 | AsasEdu — First client onboard + scan + report | ✅ | — |

---

## PART 4: ACTIVE ROADMAP

---

### PHASE 29 — REVENUE FOUNDATION
**Goal:** Convert AsasEdu from demo to paid contract. Fix remaining pipeline gaps.  
**Priority:** CRITICAL — nothing else starts until this phase is complete.  
**Owner:** Muath (sales) + antigravity (technical fixes)

#### 29.1 — Close AsasEdu Contract
```
Action items (Muath):
- Send executive PDF report to AsasEdu
- Schedule 30-minute call to walk through findings
- Present Guard package (JOD 590/month)
- Offer 3-month pilot at discounted rate if needed (JOD 350/month)
- Sign contract → trigger Hetzner provisioning OR use Contabo for first client

Success criteria:
- Signed contract (even verbal + written email confirmation)
- Payment method agreed
- Client domain added to production scheduler
```

#### 29.2 — Fix Telegram Full Pipeline (antigravity task)
```
Problem: Telegram alerts not consistently firing during Phase 27 testing.

Required fix:
1. Trace full path: Wazuh alert → webhook_server.py → alert_router.py → telegram_connector.py
2. Add explicit logging at each step with timestamp
3. Test with real SSH brute-force simulation (already documented in handoff)
4. Confirm all 3 channels receive correct alert types:
   - Findings channel: new vulnerabilities
   - Actions channel: SOAR actions taken
   - Failures channel: system errors
5. Fix any broken link in the chain
6. Document confirmed working state in SYNAPSE_AGENT_HANDOFF.md

Success criteria:
- SSH simulation → Telegram message within 30 seconds
- All 3 channels receiving correct alert types
```

#### 29.3 — Gemini API Stability (antigravity task)
```
Problem: Gemini 2.5 Flash returns 503 under load. Free tier = 15 RPM.

Required fix:
1. Implement exponential backoff with 3 retries in llm_manager.py
2. Primary: gemini-2.0-flash (stable, free tier)
3. Fallback 1: gemini-1.5-flash
4. Fallback 2: structured mock (clearly labeled in report as "Offline Analysis")
5. Never return empty triage — always return something
6. Add API health check to dashboard.py

Success criteria:
- 0 silent mock fallbacks in production scans
- Every failure is logged with reason
```

#### 29.4 — Report Pipeline Finalization (antigravity task)
```
Two reports now exist:
- reports/report_generator.py → Internal SOC report (for analysts)
- reports/client_report_generator.py → Executive client report (for business decision makers)

Required:
1. Both generators must read from same scan JSON
2. Add to main_orchestrator.py:
   --report-type [internal|executive|both]
   Default: both
3. Both PDFs saved to reports/output/ with consistent naming:
   {client}_{report_type}_{date}.pdf
4. Email connector sends executive report to client, internal to SOC inbox

Success criteria:
- Single command generates both reports
- Email delivers correct version to correct recipient
```

---

### PHASE 30 — CLIENT OPERATIONS FOUNDATION
**Goal:** Make the system operationally ready for 3–5 simultaneous clients.  
**Dependency:** Phase 29 complete (at least one paying client)

#### 30.1 — Scheduler Activation
```
Current state: scheduler.py exists but not running in production.

Required:
1. Deploy scheduler as systemd service on Node B
2. Configure per-client scan frequency from client YAML:
   soc_lite: monthly
   soc_standard: weekly
   soc_pro: weekly + on-demand
   soc_grc: weekly + on-demand + event-triggered
3. Scheduler logs to audit_log.py
4. Failed scans trigger Telegram Failures channel alert
5. scheduler status visible in dashboard.py

systemd service file:
[Unit]
Description=Synapse Scheduler
After=network.target

[Service]
WorkingDirectory=/opt/synapse
ExecStart=/opt/synapse/venv/bin/python3 scheduler.py
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
```

#### 30.2 — Client Profile Standardization
```
Every client YAML must contain:

client_id: [unique slug]
name: [display name]
domain: [primary domain]
tier: [soc_lite|soc_standard|soc_pro|soc_grc]
contact_email: [primary contact]
billing_email: [finance contact]
monthly_fee: [JOD amount]
contract_start: [ISO date]
contract_end: [ISO date]
scan_frequency: [weekly|monthly]
notification_channels:
  telegram: true
  email: true
targets:
  - domain: [domain]
  - ip: [optional additional IPs]
compliance_frameworks:
  - NCA_ECC_2.0
  - ISO_27001  # if applicable
notes: [any client-specific context]
```

#### 30.3 — Contract Manager Enhancement
```
Current state: contract_manager.py tracks dates only.

Required additions:
1. Payment status tracking (Paid / Overdue / Pending)
2. Auto-alert when contract within 30 days of expiry
3. Invoice generation (PDF, branded)
4. Revenue dashboard in dashboard.py:
   - Active clients count
   - Monthly recurring revenue (MRR) in JOD
   - Overdue invoices
   - Contracts expiring this month
```

#### 30.4 — SSH Security Hardening (Nodes)
```
Node A + Node B security improvements:
1. Change SSH port from 22 to 2222 on both nodes
2. Disable password authentication — key-only
3. Install fail2ban
4. Update UFW rules for new SSH port
5. Update production_inventory.ini with new port
6. Test Ansible connectivity after change
7. Document new SSH commands in SYNAPSE_AGENT_HANDOFF.md
```

---

### PHASE 31 — CLOUDFLARE WAF INTEGRATION
**Goal:** Activate Cloudflare WAF automation — the highest-value SOAR action.  
**Dependency:** Phase 30 + at least one client using Cloudflare

#### 31.1 — cloudflare_connector.py Activation
```
Current state: cloudflare_connector.py exists but CF_API_TOKEN not set in production.

Required:
1. Client onboarding must capture: CF_API_TOKEN, CF_ZONE_ID per client
2. Store per-client Cloudflare credentials in client YAML (encrypted)
3. SOAR_DRY_RUN=false only after Cloudflare test on isolated zone
4. Implement and test:
   - Block IP by zone
   - Enable "Under Attack" mode
   - Create WAF custom rule
   - Add IP to allowlist (for client whitelisting)
5. All Cloudflare actions logged to audit_log.py
6. Telegram Actions channel notified of every Cloudflare action

Test sequence (before live client):
1. Create test Cloudflare zone
2. Run simulation: data_exfiltration finding → BLOCK_IP → verify in CF dashboard
3. Run simulation: DDoS pattern → UNDER_ATTACK mode → verify
4. Confirm rollback works: unblock IP, disable protection
```

#### 31.2 — SOAR Flip to Live
```
Preconditions (ALL must be true before SOAR_DRY_RUN=false):
☐ Telegram all 3 channels confirmed working
☐ Cloudflare test completed successfully
☐ SafetyGuard tested with CDN IPs (must NOT block)
☐ RFC1918 ranges tested (must NOT block)
☐ Client whitelist tested (must NOT block)
☐ At least one human review cycle completed

Command:
sed -i 's/SOAR_DRY_RUN=true/SOAR_DRY_RUN=false/' /opt/synapse/.env
systemctl restart synapse-webhook
```

---

### PHASE 32 — AUTOMATED UPSELL ENGINE
**Goal:** Every scan automatically generates a tailored service proposal for the client.  
**Dependency:** Phase 30 complete + 2+ active clients for pattern data

#### 32.1 — Upsell Logic Rules
```python
# Rules engine in upsell_engine.py

UPSELL_RULES = {
    "cleartext_http": {
        "service": "Web Protection (Cloudflare WAF)",
        "package_upgrade": "Guard",
        "urgency": "immediate",
        "message": "Your website transmits data without encryption. 
                    Our Web Protection service resolves this in 24 hours."
    },
    "dns_spf_missing": {
        "service": "Email Security Retainer",
        "package_upgrade": "Guard",
        "urgency": "high",
        "message": "Your domain can be impersonated in phishing attacks.
                    Our Email Security service fixes this today."
    },
    "cve_critical": {
        "service": "Vulnerability Management",
        "package_upgrade": "Governance",
        "urgency": "critical",
        "message": "A critical CVE was detected on your infrastructure.
                    Immediate patching required — we can manage this for you."
    },
    "compliance_score_below_50": {
        "service": "GRC Gap Assessment + vCISO",
        "package_upgrade": "Premium",
        "urgency": "medium",
        "message": "Your NCA ECC 2.0 compliance score is below 50.
                    Our vCISO service provides a structured roadmap to compliance."
    }
}
```

#### 32.2 — Upsell Report Section
```
Add to client_report_generator.py:

Section 8: Recommended Next Steps (Synapse Services)
- Based on findings, recommend specific services
- Show estimated time to resolve with Synapse vs without
- Include pricing for recommended package upgrade
- CTA: "Contact us to activate these protections"

This section appears ONLY in the executive client report, never in the internal SOC report.
```

---

### PHASE 33 — CLIENT WEB PORTAL (MVP)
**Goal:** Clients can log in, view their security status, and download reports without Muath's involvement.  
**Dependency:** Phase 31 complete + 5+ active clients

#### 33.1 — Portal Architecture
```
Stack:
- Backend: FastAPI (Python — same ecosystem as project)
- Frontend: Simple HTML/CSS — no React for MVP
- Auth: JWT tokens, per-client credentials
- Hosting: Node B (add to docker-compose)
- Database: SQLite for MVP → PostgreSQL when >10 clients

Portal pages:
1. Login
2. Dashboard — security score, last scan date, open findings count
3. Reports — list of all reports, download PDF
4. Findings — filterable table of all findings with severity
5. Alerts — real-time SOC alerts for this client

Client data isolation:
- Every API endpoint filters by client_id from JWT
- ChromaDB already has STRICT client isolation — connect portal to same data
```

#### 33.2 — Portal API Endpoints
```python
POST /auth/login          → returns JWT
GET  /client/dashboard    → score, stats
GET  /client/reports      → list PDFs
GET  /client/reports/{id} → download PDF
GET  /client/findings     → paginated findings
GET  /client/alerts       → recent alerts
POST /client/scan/request → trigger on-demand scan (soc_pro+ only)
```

---

### PHASE 34 — KNOWLEDGE BASE EXPANSION
**Goal:** Load cybersecurity frameworks into ChromaDB to make AI analysis more accurate and authoritative.  
**Dependency:** Phase 29 complete (stable API)

#### 34.1 — Frameworks to Load
```
Priority 1 (load immediately):
- NCA ECC 2.0 (full Arabic + English text) → nca_controls.json (expand from current stub)
- OWASP Top 10 (2021) → owasp_top10.json
- MITRE ATT&CK (relevant tactics: Initial Access, Execution, Persistence) → mitre_attack.json

Priority 2 (after first 5 clients):
- ISO 27001:2022 Annex A controls
- UAE PDPL key articles
- ADHICS controls (for UAE healthcare clients)
- CIS Benchmarks (Linux + Apache + MySQL)

Priority 3 (when vCISO service active):
- NIST CSF 2.0
- PCI DSS v4.0 (if payment clients)
- SAMA Cybersecurity Framework (for Saudi expansion)
```

#### 34.2 — RAG Enhancement
```
Current: ChromaDB stores scan history only.
Target: ChromaDB stores frameworks + best practices + remediation playbooks.

When AI triage runs:
1. Query ChromaDB for relevant framework controls
2. Inject as context: "Based on NCA ECC 2.0 Section 2.1.3..."
3. Remediation recommendations pulled from known-good practices

Result: Reports cite specific framework articles, not generic advice.
This is the core differentiator vs generic security scanners.
```

---

### PHASE 35 — DARK WEB MONITORING
**Goal:** Add credential leak detection for client domains and email addresses.  
**Dependency:** Phase 30 complete

#### 35.1 — Implementation
```
Tools:
- HaveIBeenPwned API (free for domains, paid for real-time)
- LeakCheck API (paid — add to Paid Tool Upgrade Triggers)
- Custom: monitor paste sites via RSS/scraping

New tool file: tools/darkweb_tool.py

Scan additions:
- Check client domain for leaked credentials
- Check key email addresses (from client profile)
- Search for company name in breach databases

Report addition:
- New section: "Dark Web Exposure"
- Severity: Critical if active credentials found, High if historical

Upsell trigger:
- Any dark web finding → recommend "Dark Web Monitoring Retainer"
```

---

### PHASE 36 — MULTI-MODEL AI ROUTING
**Goal:** Use Claude for complex analysis, Gemini for speed, local LLM for sensitive data.  
**Dependency:** Phase 32 complete + revenue covers API costs

#### 36.1 — Model Routing Rules
```yaml
# policies/model_routing.yaml

rules:
  - condition: "sensitivity == critical OR contains_credentials == true"
    model: local_llm
    reason: "Sensitive data never leaves local environment"

  - condition: "task == threat_analysis AND severity == critical"
    model: claude_sonnet
    reason: "Highest accuracy for critical decisions"

  - condition: "task == report_writing"
    model: gemini_flash
    reason: "Cost-optimized for structured text generation"

  - condition: "task == classification OR task == routing"
    model: gemini_flash
    reason: "Fast, cheap, sufficient for classification"

  - condition: "default"
    model: gemini_flash
    reason: "Default to cheapest capable model"
```

#### 36.2 — Privacy Broker (from KYRIE architecture)
```python
# core/privacy_broker.py

class PrivacyBroker:
    """
    Mandatory intermediary before any external AI call.
    Sanitizes sensitive data, maps tokens, rehydrates after response.
    """
    
    PATTERNS = {
        "ip": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
        "credential": r"password[:\s]+\S+",
        "token": r"(api_key|token|secret)[:\s]+\S+",
        "client_name": None  # loaded from client profile per request
    }
    
    def sanitize(self, text: str, client_id: str) -> tuple[str, dict]:
        # Replace sensitive values with tokens
        # Return sanitized text + mapping dict
        pass
    
    def rehydrate(self, text: str, mapping: dict) -> str:
        # Restore original values in AI response
        pass
```

**Rule:** Privacy Broker is mandatory before ALL external AI calls from Phase 36 onward.

---

### PHASE 37 — SALES AUTOMATION
**Goal:** Automate the pre-sales process from lead to signed contract.  
**Dependency:** Phase 33 (web portal) complete

#### 37.1 — Lead Capture
```
Website form (add to Kyrie blueprint site):
- Company name, domain, contact email
- "Request free security scan" CTA

Triggers:
1. Automated free scan runs on submitted domain
2. Executive report generated
3. Personalized email sent with report + pricing
4. Muath notified via Telegram with lead summary

No human involvement until client responds to email.
```

#### 37.2 — Follow-up Sequence
```
Day 0: Report delivered via email
Day 3: Follow-up email — "Did you review the findings?"
Day 7: Second follow-up — case study or specific finding highlight
Day 14: Final email — limited-time offer if no response

All emails templated, personalized with actual findings from their scan.
```

---

## PART 5: ENGINEERING RULES (PERMANENT — NEVER VIOLATE)

### 5.1 Safety Rules
```
1. SOAR_DRY_RUN=true is the default. Change to false ONLY after:
   - Cloudflare test zone validated
   - SafetyGuard tested with CDN + RFC1918 + client whitelist
   - Human review of playbook logic completed

2. SafetyGuard NEVER blocks:
   - RFC1918 ranges (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
   - CDN IPs: Cloudflare, Akamai, Fastly, CloudFront
   - Client-defined whitelist in client YAML

3. DNS findings → NOTIFY_ONLY — NEVER BLOCK_IP
4. Malware and Ransomware → ESCALATE_HUMAN — NEVER auto-block
5. BLOCK_IP allowed ONLY for: cleartext_http (critical), cve (critical/high), data_exfiltration

6. Client data isolation: EVERY ChromaDB query MUST include client_id filter
   No cross-client data contamination is acceptable under any circumstance.

7. Privacy Broker (Phase 36+): ALL external AI calls MUST pass through sanitize()
   before sending. NEVER send raw client data to external APIs.
```

### 5.2 Code Standards
```
1. All tools inherit from BaseTool (tools/base_tool.py)
2. All inter-component communication via standardized JSON:
   {
     "client_id": str,
     "target": str,
     "findings": list,
     "severity": str,
     "timestamp": ISO8601,
     "scan_id": str,
     "tool": str
   }
3. All actions logged to audit_log.py with timestamp + actor + action + result
4. Every new module must have a test file in tests/
5. SYNAPSE_AGENT_HANDOFF.md must be updated at end of every phase
6. Git commit after every phase with standardized message:
   feat(phase{N}): {description}
```

### 5.3 AI Interaction Rules
```
1. LLM is a Threat Modeler — hostile perspective, NOT compliance checker
2. Mock fallback is acceptable ONLY if clearly labeled in report output
3. Never return empty analysis — structured mock is better than empty
4. Rate limiter (15 RPM) must be respected — never bypass
5. All prompts are deterministic (temperature=0.2, seed=42) for reproducible results
6. Model selection follows model_routing.yaml (Phase 36+) or defaults to gemini-2.0-flash
```

### 5.4 Report Standards
```
Two mandatory report types per client scan:

1. Internal SOC Report (report_generator.py output):
   - Full technical detail
   - Raw AI analysis
   - All findings including INFO level
   - Compliance score with calculation breakdown
   - Delta analysis
   - Audience: Muath / SOC analysts

2. Executive Client Report (client_report_generator.py output):
   - Non-technical language
   - Business impact framing
   - Attack scenario narrative
   - Remediation roadmap with phases
   - Compliance status table
   - Upsell section (from Phase 32)
   - NO score of 0/100 — use "Risk Level: CRITICAL" instead
   - NO internal findings codes — use plain names
   - Audience: Client decision maker (CEO/CTO/IT Manager)
```

---

## PART 6: PAID TOOL UPGRADE TRIGGERS

| Tool | Current | Trigger | Cost |
|---|---|---|---|
| Gemini Flash | Free 15 RPM | >3 simultaneous scans | ~$20/month |
| Claude Sonnet API | Not active | First paid client | ~$50/month at scale |
| VirusTotal | Free 500/day | >8 active clients | $200/month |
| Cloudflare WAF | Free tier | First client needing WAF | $20/month/zone |
| HaveIBeenPwned | Free (limited) | Phase 35 activation | $3.50/month |
| LeakCheck | Not active | Phase 35 activation | $50/month |
| Hetzner Node A | Contabo (current) | >10 clients OR Contabo performance issues | €20/month |
| Hetzner Node B | Contabo (current) | >10 clients OR Contabo performance issues | €15/month |
| PostgreSQL | SQLite (Phase 33) | >10 clients on portal | Included in server |

---

## PART 7: KNOWN ISSUES & TECHNICAL DEBT

### Active Issues
| Issue | Severity | Owner | Fix Phase |
|---|---|---|---|
| Telegram pipeline not consistently firing | High | antigravity | Phase 29.2 |
| Gemini 503 under load — no exponential backoff | High | antigravity | Phase 29.3 |
| cleartext_http high severity missing PATCH_ADVISORY in router | Low | antigravity | Phase 29 |
| testssl.sh binary path issue in tests | Low | antigravity | Phase 29 |
| BankCo profile has no real scan data | Low | — | When real client |
| SOAR_DRY_RUN still true in production | Medium | Muath | Phase 31.2 |
| No SSH key hardening on nodes | Medium | antigravity | Phase 30.4 |

### Fixed Issues (Reference)
- Router missing 5 DNS finding types → Phase 22 ✅
- GeoIP returning None → dual fallback → Phase 22 ✅
- Scheduler test timeout → Phase 22 ✅
- Wazuh webhook untested → Phase 26 ✅
- Report text truncation (fpdf2 multi_cell) → Phase 28 ✅
- Gemini API model name mismatch → Phase 28 ✅

---

## PART 8: AGENT INSTRUCTIONS (FOR ANTIGRAVITY AND ALL AI AGENTS)

### Before Starting Any Work
```
1. Read this document (SYNAPSE_MASTER_ROADMAP.md) completely
2. Read SYNAPSE_AGENT_HANDOFF.md for current state
3. Check git log for last 5 commits to understand recent changes
4. Run test suite to confirm baseline: python3 tests/test_final_e2e.py
5. Confirm Node A and Node B are reachable before any deployment task
```

### Phase Execution Protocol
```
1. Announce which phase you are starting and list all sub-tasks
2. Complete sub-tasks in order — do not skip
3. After each sub-task: run relevant tests, confirm success
4. If a sub-task fails: document the failure, propose fix, ask for confirmation before proceeding
5. After phase complete: update SYNAPSE_AGENT_HANDOFF.md
6. Commit with: git commit -m "feat(phase{N}): {description}"
7. Push to main: git push origin main
```

### What Never to Do
```
❌ Never start a new phase while a previous phase has failing tests
❌ Never commit .env or any file containing API keys
❌ Never set SOAR_DRY_RUN=false without explicit written confirmation from Muath
❌ Never delete client history files in knowledge/history/
❌ Never modify client YAML files without backup
❌ Never run nuclei or nmap on any domain not in the client whitelist
❌ Never add a new AI model without updating model_routing.yaml
❌ Never build a new feature outside of the defined phase roadmap without asking first
```

### Communication Format (to Muath)
```
After completing any work, report in this format:

## Phase {N} — {Name} — COMPLETE/PARTIAL/FAILED

### Done:
- [list of completed sub-tasks]

### Not Done:
- [list with reasons]

### Tests:
- [X/Y passing]

### Next Required Action:
- [what Muath needs to do, if anything]
- [what the next agent session should start with]

### Commit:
- [commit hash]
```

---

## PART 9: SUCCESS METRICS

### 30-Day Targets
- [ ] AsasEdu contract signed
- [ ] Telegram pipeline 100% reliable
- [ ] Scheduler running automatically on Node B
- [ ] 2nd client onboarded

### 90-Day Targets
- [ ] 5 paying clients
- [ ] MRR: JOD 1,500+
- [ ] SOAR_DRY_RUN=false in production
- [ ] Client portal MVP live
- [ ] Cloudflare WAF integration active

### 6-Month Targets
- [ ] 12 paying clients
- [ ] MRR: JOD 5,000+
- [ ] Dark web monitoring live
- [ ] Automated upsell generating leads
- [ ] Claude API integrated for critical analysis

### 12-Month Targets
- [ ] 24 paying clients (break-even)
- [ ] MRR: JOD 10,000+
- [ ] UAE market entry (2+ UAE clients)
- [ ] Multi-model AI routing live
- [ ] ISO 27001 service offered

---

*Document maintained by: Kyrie Security Architect*  
*Next review: After Phase 29 complete*  
*All AI agents must update Section "Completed Phases" after each phase.*

---

## PART 10: AUTOMATED MARKETING PIPELINE (KYRIE GROWTH ENGINE)

> **Philosophy:** Marketing is not a separate department. It is an automated system that feeds the SOC engine with qualified leads, builds brand trust at scale, and converts interest into revenue — with minimal human intervention.

---

### 10.1 Brand Identity (Foundation — Before Everything)

**Brand Name:** Synapse Security (or KYRIE Security — decide and commit)
**Brand Promise:** *"Enterprise-grade security, automated for businesses that can't afford enterprise prices."*
**Target Persona:**
- Jordan/UAE SMB owner or IT manager
- 5–200 employees
- Has a website and/or servers
- Has heard of "cyber attacks" but never had a security audit
- Budget-conscious but risk-aware

**Brand Pillars:**
- Transparency: Show exactly what we found, not vague reports
- Speed: Report within 24 hours of request
- Credibility: NCA ECC 2.0, ISO 27001 mapped findings
- Accessibility: Not intimidating — clear language, clear fixes

---

### 10.2 Marketing Architecture (3-Layer Funnel)

```
LAYER 1 — AWARENESS (Brand Presence)
  ├── Professional website (synapse-security.com or kyrie-security.com)
  ├── LinkedIn (personal: Muath + company page)
  ├── Freelance platforms (Upwork, Fiverr, Freelancer.com, Mostaql.com)
  └── Content: 2 posts/week — Arabic + English

LAYER 2 — ACQUISITION (Automated Lead Generation)
  ├── AI agent scrapes target company lists
  ├── Finds decision-maker emails (legal methods only)
  ├── Sends personalized cold email with free scan offer
  └── Lead accepts → automated scan → report delivered

LAYER 3 — CONVERSION + RETENTION (Connected to SOC Engine)
  ├── If subscribed → onboard to main Synapse pipeline
  ├── If not subscribed → periodic re-engagement sequence
  │   ├── Rescan after 30 days
  │   ├── Compare with previous scan
  │   ├── If improved → congratulate + upsell
  │   └── If unchanged → warn + urgency message
  └── All actions logged → fed back to sales pipeline
```

---

### PHASE 38 — BRAND FOUNDATION
**Goal:** Establish credible, professional online presence before outreach begins.
**Timeline:** Build in parallel with Phase 29 — do NOT wait.
**Dependency:** Brand name decision + domain purchased

#### 38.1 — Website (Priority 1)

```
Stack: Static HTML/CSS (no WordPress — too vulnerable for a security company)
Hosting: Cloudflare Pages (free, fast, secure — perfect brand alignment)
Domain: synapse-security.com OR kyrie-security.com (choose ONE today)

Pages required (MVP — 5 pages):
1. Home
   - Hero: "Protect Your Business Before Attackers Find It"
   - Sub: "Automated cybersecurity for Jordan & UAE businesses"
   - CTA: "Get Your Free Security Scan"
   - Social proof: "NCA ECC 2.0 | ISO 27001 aligned"

2. Services
   - List all 4 packages with pricing (transparent)
   - Comparison table
   - CTA per service

3. Free Scan Page
   - Form: Company name, domain, contact email
   - What they get: external scan + PDF report within 24 hours
   - No credit card, no commitment
   - Auto-triggers: lead_capture_agent.py → scan → report email

4. About / Trust
   - Muath's background (LinkedIn-style)
   - Technology stack (Wazuh, AI, NCA-aligned)
   - Privacy commitment (data never shared)

5. Contact
   - Email form → triggers Telegram notification to Muath
   - WhatsApp link (essential for Jordan/UAE market)

Design theme: Dark background (#0a0a0f), cyan/gold accents
Matches existing "Dark Sovereign" portfolio theme for consistency.

AI Content Rule:
Every page headline and body copy reviewed by Claude for:
- Tone consistency (confident, not salesy)
- Technical accuracy (no overclaiming)
- Arabic + English versions (separate pages or toggle)
```

#### 38.2 — LinkedIn Optimization

```
Personal Profile (Muath Yousef):
Headline: "Cybersecurity Engineer | Building AI-Native SOC for SMBs | Jordan & UAE"
About section: 3 paragraphs
  Para 1: What you do (MSSP for SMBs, AI-automated security)
  Para 2: Why (most SMBs can't afford enterprise security — you solve that)
  Para 3: CTA (free security assessment offer)

Featured section:
  - Link to free scan page
  - Sample executive report (anonymized AsasEdu or scanme.nmap.org)
  - Link to GitHub (public repos only)

Content calendar (2 posts/week — AI-assisted):
  Week 1: "We scanned 5 Jordanian business websites. Here's what we found." (findings from scanme-level targets)
  Week 2: "What is SPF/DMARC and why your business email is at risk right now"
  Week 3: "How we detected a brute force attack in 23 seconds (real case)"
  Week 4: "NCA ECC 2.0: What Jordanian businesses need to know in 2026"

Company Page (Synapse Security):
  - Logo + banner matching website
  - Mirror personal content
  - Tag clients when they consent (big trust signal)

AI Writing Rule:
Use Claude API to draft all posts.
Prompt template:
  "Write a LinkedIn post in Arabic for Jordanian SMB owners about [topic].
   Tone: authoritative but accessible. Max 200 words.
   End with: free scan CTA and link."
```

#### 38.3 — Freelance Platforms

```
Platforms (priority order):
1. Mostaql.com (Arabic — Jordan/Saudi/UAE audience — HIGHEST priority)
2. Upwork (global — English only)
3. Fiverr (global — English + Arabic gigs)

Profile optimization:
  - Consistent photo, name, bio across all platforms
  - Portfolio: anonymized scan report as sample work
  - Services listed:
    * External Security Assessment — $150
    * Email Security Audit — $75
    * Full SMB Security Review — $350
    * Monthly Security Monitoring (retainer) — $200/month

These are LEAD GENERATION channels, not primary revenue.
Goal: Build reviews and social proof in first 90 days.
Accept first 3 clients at 50% discount for reviews.

AI Rule:
Fiverr/Upwork proposal responses written by AI agent using template:
  Input: client's project description
  Output: personalized proposal referencing their specific needs
  Human review: Muath approves before sending (5 minutes max)
```

---

### PHASE 39 — AUTOMATED LEAD GENERATION ENGINE
**Goal:** AI agent identifies, qualifies, and emails potential clients automatically.
**Dependency:** Phase 38 complete (website live, brand established)
**Timeline:** Start building immediately, activate after website launch

#### 39.1 — Lead Identification Agent

```python
# agents/lead_gen_agent.py

"""
Sources for lead identification (legal, public data only):
1. LinkedIn company search (Jordan/UAE, 10-200 employees)
2. Google Maps business listings (by city + industry)
3. Yellow Pages Jordan / UAE (yellowpages.jo, etc.)
4. Chamber of Commerce member directories (public)
5. Domain registration databases (WHOIS — legal public data)

Output per lead:
{
  "company_name": str,
  "domain": str,
  "industry": str,
  "size_estimate": str,  # from LinkedIn employee count
  "decision_maker_name": str,  # LinkedIn CEO/IT Manager
  "email": str,  # found or guessed (pattern: info@, ceo@, etc.)
  "linkedin_url": str,
  "score": int,  # 0-100 lead quality score
  "country": str,
  "added_date": ISO8601
}

Lead scoring rules:
+20: Has active website
+20: Website has no HTTPS
+20: Missing SPF/DMARC (quick check before full scan)
+15: Education, Finance, or Healthcare industry (high value targets)
+15: 20-200 employees
+10: Jordan or UAE based
-20: Already a client
-20: Domain not resolving
-30: Government entity (avoid — complex procurement)

Minimum score to contact: 50
```

#### 39.2 — Automated Cold Email Sequence

```
Tool: Self-hosted email sequence (Python + SMTP — already have email_connector.py)
NOT: Mailchimp, SendGrid (cost + privacy concerns)

Email 1 — Day 0 (Offer):
Subject: "Free Security Report for [Company Name]"
Body:
  "Hello [Name],
  
  We ran a quick external check on [domain] and noticed
  [SPECIFIC FINDING — e.g., 'your email domain has no SPF record,
  making it possible for anyone to send emails pretending to be you'].
  
  We'd like to send you a complete security report — free, no obligation.
  
  Click here to confirm and receive your report: [link]
  
  Muath Yousef
  Synapse Security"

IMPORTANT: The "quick check" is real — run a lightweight pre-scan
(DNS check only — 5 seconds) before sending email.
This is what makes it personal, not spam.

Email 2 — Day 3 (if no response):
Subject: "Your [domain] security report is ready"
Body: shorter, more urgent, same CTA

Email 3 — Day 7 (final):
Subject: "Last chance — security report expires"
Body: 3 sentences max, urgency, then silence

If clicked/confirmed:
→ Trigger full scan via main_orchestrator.py
→ Generate executive report
→ Deliver via email within 24 hours
→ Add to lead CRM (simple JSON or Notion)

If no response after Email 3:
→ Move to "cold" list
→ Re-engage in 60 days with new finding
```

#### 39.3 — Post-Scan Engagement (Non-Subscribers)

```python
# agents/re_engagement_agent.py

"""
Triggered by scheduler.py for leads who:
- Received free scan
- Did NOT subscribe
- Are still in "interested" status

Schedule: Re-scan every 30 days

Logic:
1. Run new scan on lead's domain
2. Compare with previous scan using delta_analyzer.py
3. Decision tree:

   If new_critical_findings > old_critical_findings:
     → Send: "Warning: New security risk detected on [domain]"
     → Urgency: HIGH
     → CTA: "Protect your business now — see our plans"

   If findings improved (lead fixed something):
     → Send: "We noticed you improved [specific fix]"
     → Tone: Congratulatory
     → CTA: "You're on the right track — let us handle the rest"

   If no change after 90 days:
     → Move to "dormant" list
     → Re-engage only if new critical CVE affects their stack

All re-engagement emails:
- Reference SPECIFIC finding from THEIR scan
- Never generic
- AI-written using Claude API with scan data as context
"""
```

---

### PHASE 40 — MARKETING AUTOMATION INTEGRATION
**Goal:** Connect marketing pipeline directly to SOC engine. A subscribed lead automatically becomes an active client.
**Dependency:** Phase 39 + Phase 30 (scheduler operational)

#### 40.1 — Lead-to-Client Conversion Flow

```
AUTOMATED FLOW:

[Lead confirms free scan]
         ↓
[main_orchestrator.py runs full scan]
         ↓
[client_report_generator.py creates executive PDF]
         ↓
[upsell_engine.py adds recommended package to report]
         ↓
[email_connector.py sends report + pricing]
         ↓
         ├── [Lead clicks "Subscribe"]
         │         ↓
         │   [onboard_client.py creates client profile]
         │         ↓
         │   [scheduler.py adds to monitoring cycle]
         │         ↓
         │   [Telegram: Muath notified of new client + revenue]
         │         ↓
         │   [contract_manager.py creates contract record]
         │
         └── [Lead does NOT click — 48 hours]
                   ↓
           [re_engagement_agent.py adds to 30-day rescan queue]
```

#### 40.2 — Marketing Dashboard Addition

```
Add to dashboard.py — Marketing section:

== GROWTH ENGINE ==
Active leads:          [N]
Free scans delivered:  [N]
Conversion rate:       [N]%
Re-engagement queue:   [N]
MRR from marketing:    JOD [N]

Recent activity:
[timestamp] New lead: company.jo — score: 72
[timestamp] Scan delivered: company2.com — status: pending
[timestamp] Converted: company3.net → Guard package — JOD 590/mo
```

---

### 10.3 Content Strategy (AI-Maintained)

```
Content types and AI rules:

1. Case Studies (monthly):
   Input: anonymized scan data from real client
   AI generates: narrative story format
   "A Jordanian e-commerce company had [finding].
    Here's how we detected it and what happened next."
   Human review: Muath approves tone + accuracy

2. Educational Posts (weekly):
   Topics pulled from: most common findings in recent scans
   Format: "What is [technical term] and why should your business care?"
   Length: 200 words LinkedIn / 800 words blog

3. Threat Alerts (when relevant):
   When new CVE affects common SMB stack (WordPress, Apache, etc.)
   AI generates: urgent advisory with specific action
   Speed: post within 24 hours of CVE publication

4. Transparency Reports (quarterly):
   "This quarter we scanned N businesses. Here's what we found."
   Aggregate stats only — no client names
   Builds trust + demonstrates scale

AI Consistency Rule:
All content passes through brand_voice_checker.py (to build):
  - Checks for: overclaiming, technical inaccuracy, tone mismatch
  - Enforces: consistent terminology, NCA/ISO references
  - Output: approved or flagged for human review
```

---

### 10.4 Privacy & Legal Compliance for Marketing

```
MANDATORY rules before any outreach:

1. Pre-scan consent:
   - Email mentions we ran a "quick public check"
   - Full scan only runs AFTER lead confirms
   - Never scan without explicit confirmation

2. Data handling:
   - Lead data stored locally (NOT in cloud CRM)
   - Lead can request deletion at any time
   - No data sold or shared ever

3. Email compliance:
   - Every email includes unsubscribe link
   - Unsubscribe = immediate removal from all lists
   - Respect UAE/Jordan anti-spam regulations

4. Scan scope:
   - Only external passive recon on lead's domain
   - No exploitation, no intrusive scanning
   - Same tools as client scans: nmap, nuclei-safe-templates, dns
```

---

### 10.5 Marketing Phase Timeline

| Phase | Task | When | Dependency |
|---|---|---|---|
| 38 | Website + LinkedIn + Freelance profiles | Now — parallel to Phase 29 | Brand name decision |
| 39 | Lead gen agent + cold email sequence | After website live (2 weeks) | Phase 38 complete |
| 40 | Full marketing → SOC integration | After Phase 30 (scheduler live) | Paying client + stable pipeline |

---

### 10.6 Success Metrics for Marketing Pipeline

| Metric | 30-day target | 90-day target | 6-month target |
|---|---|---|---|
| Website visitors/month | 200 | 1,000 | 5,000 |
| Free scan requests | 5 | 30 | 150 |
| Conversion rate | 10% | 15% | 20% |
| New clients from marketing | 0 | 3 | 20 |
| LinkedIn followers | 200 | 500 | 2,000 |
| Freelance platform reviews | 0 | 3 | 10 |

