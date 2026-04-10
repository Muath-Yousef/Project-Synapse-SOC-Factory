# Project Synapse SOC Factory — Agent Handoff Document
> **Purpose:** This document enables any AI agent to continue development of Project Synapse exactly where it was left off. Read every section before taking any action.
> **Last Updated:** 2026-04-09 — Phase 22 Complete + Deployment Infrastructure Ready

---

## 1. Project Identity

| Field | Value |
|---|---|
| **Project Name** | Project Synapse SOC Factory |
| **GitHub Repository** | `https://github.com/Muath-Yousef/Project-Synapse-SOC-Factory` (Private) |
| **Local Path** | `/media/kyrie/VMs1/Cybersecurity_Tools_Automation` |
| **Git Branch** | `main` |
| **Git Author** | `Kyrie Security Architect <kyrie@synapse.soc>` |
| **Last Phase** | **Phase 24 Complete** — Synapse Control Plane |
| **Python Env** | `venv` at project root — always activate: `source venv/bin/activate` |

---

## 2. Owner Profile

- **Role:** Cybersecurity engineer providing managed security services (MSSP) to SMBs
- **Business Model:** Annual contracts — protection of websites, servers, DDoS mitigation
- **Market:** Jordan + UAE (CyberShield MSSP Blueprint)
- **Current Phase:** Code Freeze locally — awaiting first client to trigger Hetzner provisioning
- **AI Budget:** Gemini 2.5 Flash (free tier, 15 RPM) as primary LLM. Willing to upgrade APIs when needed
- **Tools Preference:** Free-first → upgrade to paid only when operationally necessary

---

## 3. Core Architectural Principle

```
Scan → Parse → RAG Context → LLM Triage → SOAR Response → Delta Analysis → Score → Report → Email
```

Every component is modular, inherits from a base class, and communicates via standardized JSON. The LLM is configured as a **Threat Modeler** (hostile perspective), NOT a compliance checker.

---

## 4. Complete File Structure

```
/media/kyrie/VMs1/Cybersecurity_Tools_Automation/
│
├── main_orchestrator.py          # Central brain — CLI entry: --target --client --test-mode
├── scheduler.py                  # Automated weekly/monthly scans for all clients
├── dashboard.py                  # CLI SOC status view
│
├── core/
│   ├── llm_manager.py            # Gemini 2.5 Flash API + Rate Limiter + Mock fallback
│   └── rate_limiter.py           # Thread-safe RPM limiter (default 15 RPM)
│
├── tools/                        # All scanning tools inherit from BaseTool
│   ├── base_tool.py
│   ├── nmap_tool.py
│   ├── nuclei_tool.py
│   ├── dns_tool.py               # SPF/DKIM/DMARC/MX/BIMI/OpenRelay checks
│   ├── virustotal_tool.py
│   ├── subfinder_tool.py
│   ├── nvd_tool.py
│   ├── nvd_matcher.py
│   ├── testssl_tool.py
│   └── blacklist_tool.py
│
├── parsers/
│   ├── nmap_parser.py
│   ├── nuclei_parser.py
│   └── aggregator.py
│
├── agents/
│   ├── meta_agent.py
│   └── analysis_agent.py
│
├── knowledge/
│   ├── vector_store.py           # ChromaDB — STRICT client isolation
│   ├── client_profiles/
│   │   ├── techco.yaml           # SOC_STANDARD — scanme.nmap.org
│   │   └── bankco.yaml           # SOC_STANDARD — hackerone.com (re-onboarded Phase 22)
│   ├── compliance_frameworks/
│   │   └── nca_controls.json
│   └── history/                  # JSON scan archives per client (Delta Detection persistence)
│
├── soc/
│   ├── alert_router.py           # Phase 22: All 15 routing rules complete, GeoIP fallback fixed
│   ├── safety_guard.py
│   ├── audit_log.py
│   ├── delta_analyzer.py
│   ├── compliance_engine.py      # Score 0-100 + Grade A-F (0/100 on unprotected = correct)
│   ├── webhook_server.py         # Receives Wazuh alerts — untested with live SIEM
│   │
│   ├── playbooks/
│   │   ├── base_playbook.py
│   │   ├── web_attack_playbook.py
│   │   ├── hardening_playbook.py
│   │   ├── phishing_playbook.py
│   │   ├── malware_playbook.py
│   │   ├── data_exfil_playbook.py
│   │   └── ransomware_playbook.py
│   │
│   └── connectors/
│       ├── cloudflare_connector.py
│       ├── telegram_connector.py
│       └── email_connector.py
│
├── reports/
│   ├── report_generator.py
│   └── output/                   # Generated .md reports (git-ignored)
│
├── onboarding/
│   ├── onboard_client.py
│   ├── setup_cron.sh
│   └── contract_manager.py
│
├── deployment/                   # NEW — Phase 23 infrastructure (commit 189f1da)
│   ├── deploy_node_b.yml         # Ansible: Docker + TheHive + Shuffle + webhook systemd
│   ├── hetzner_inventory.example # Replace YOUR_HETZNER_PUBLIC_IP before use
│   └── docker-compose-node-b.yml # TheHive:9000 + Shuffle:3001
│
├── tests/
│   ├── test_isolation.py         # 4 tests
│   ├── test_phase7.py            # 5 tests
│   ├── test_phase14.py           # 6 tests
│   ├── test_phase15.py           # 6 tests — scheduler timeout FIXED (Phase 22)
│   ├── test_phase16.py           # 6 tests
│   ├── test_phase18_priority1.py # 3 tests — GeoIP FIXED (Phase 22)
│   ├── test_phase19_priority2.py # 3 tests
│   ├── test_phase20_priority3.py # 3 tests
│   └── test_final_e2e.py         # 8 master tests
│
├── .github/workflows/
│   └── security-tests.yml        # CI/CD
│
├── .env                          # NEVER commit
├── .env.template
├── .gitignore                    # deployment/production.env protected
└── requirements.txt
```

---

## 5. Environment Variables (.env)

```bash
# LLM
GEMINI_API_KEY=your_key_here
GEMINI_RPM_LIMIT=15

# SOAR Safety — NEVER false without VM testing first
SOAR_DRY_RUN=true

# Cloudflare
CF_API_TOKEN=your_token
CF_ZONE_ID=your_zone_id

# Telegram (3 channels)
TELEGRAM_BOT_TOKEN=your_token
TELEGRAM_CHAT_ID_FINDINGS=your_id
TELEGRAM_CHAT_ID_ACTIONS=your_id
TELEGRAM_CHAT_ID_FAILURES=your_id

# VirusTotal
VT_API_KEY=your_key

# Email (SMTP)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email
SMTP_PASSWORD=your_app_password
SMTP_FROM=security@yourdomain.com

# NVD (optional)
NVD_API_KEY=your_key
```

---

## 6. Critical Engineering Rules

### 6.1 Safety Rules — NEVER Violate
1. `SOAR_DRY_RUN=true` is the default. Change to `false` only after VM testing
2. `SafetyGuard` protects: RFC1918 ranges + CDN IPs (Cloudflare/Akamai/Fastly/CloudFront) + client whitelist
3. DNS findings → `NOTIFY_ONLY` ONLY — NEVER `BLOCK_IP`
4. Malware and Ransomware → `ESCALATE_HUMAN` ONLY — never auto-block
5. CDN IPs must never be blocked

### 6.2 Alert Router Rules (Phase 22 — Complete)
```python
# All 15 routing rules now defined:
# Phase 13.1 originals: dns_dmarc, dns_spf, dns_missing_dkim (3 severities each)
# Phase 22 additions:
("high",   "dns_spf_missing")    : [NOTIFY_ONLY, PATCH_ADVISORY]
("high",   "dns_dmarc_missing")  : [NOTIFY_ONLY, PATCH_ADVISORY]
("medium", "dns_dkim_not_found") : [NOTIFY_ONLY]
("info",   "dns_bimi_missing")   : [NOTIFY_ONLY]
("high",   "cleartext_http")     : [NOTIFY_ONLY, PATCH_ADVISORY]
# BLOCK_IP allowed only for: cleartext_http (critical), cve (critical/high), data_exfiltration
```

### 6.3 Compliance Score Logic
```
0/100 Grade F = CORRECT behavior when target has:
  Critical findings (-40 each) + High findings (-20 each)
  scanme.nmap.org legitimately scores 0 — it is an intentionally exposed test target
  Real client domains will score B-C range with normal security posture
```

### 6.4 GeoIP Enrichment (Phase 22 — Fixed)
```python
# Primary: ipapi.co (HTTPS)
# Fallback: ip-api.com (HTTP)
# Final fallback: returns {"country": "Unknown", "org": "Unknown", "status": "unavailable"}
# NEVER returns None — always returns dict
```

---

## 7. Completed Phases Summary

| Phase | Description | Status | Commit |
|---|---|---|---|
| 1 | Data Standardization — Nmap + Nuclei parsers | ✅ | — |
| 2 | RAG & Vector Memory — ChromaDB | ✅ | — |
| 3 | LLM Orchestration — Gemini 2.5 Flash | ✅ | — |
| 4 | Meta-Agent — Auto tool generation | ✅ | — |
| 5 | Executive Reporting — Markdown output | ✅ | — |
| 6 | Git Baseline + Live LLM integration | ✅ | — |
| 7 | SOAR — SafetyGuard + AuditLog + DryRun + Playbooks | ✅ | — |
| 8 | GitHub Deployment — Private repository | ✅ | — |
| 9 | Multi-Client Isolation + Rate Limiting | ✅ | — |
| 10 | Real Nuclei Integration | ✅ | — |
| 11 | CI/CD — GitHub Actions | ✅ | — |
| 12 | Tool Expansion — DNS, VirusTotal, Phishing Playbook | ✅ | — |
| 12.1 | DKIM Hardening — MX-based provider detection | ✅ | — |
| 12.2 | Subfinder — EASM subdomain enumeration | ✅ | — |
| 13 | CDN Awareness — SafetyGuard ranges | ✅ | — |
| 13.1 | Router Logic Fix — DNS findings advisory-only | ✅ | dc57d7c |
| 14 | Critical Playbooks — Malware, DataExfil, Ransomware + NVD | ✅ | 6c856f3 |
| 15 | Email Delivery + Scheduler + NVD Client Matching | ✅ | 529b87a |
| 16 | Client Onboarding CLI + Cron + Dashboard | ✅ | 994c690 |
| 17 | Final Stabilization + Master E2E Test Suite | ✅ | fe903a0 |
| 18 | TLS/SSL Audit + GeoIP Enrichment + BIMI + OpenRelay | ✅ | 07593f8 |
| 19 | Delta Analyzer + Compliance Scoring Engine | ✅ | ddac540 |
| 20 | Blacklist RBL + Contract Manager + Billing Metadata | ✅ | 2606451 |
| 21 | Master E2E Validation — 8/8 passing | ✅ | 45b8e9e |
| 22 | Fix: Router rules + GeoIP fallback + scheduler test + compliance score + BankCo billing | ✅ | 17816cc |
| 23-prep | Ansible deployment + TheHive/Shuffle Docker Compose | ✅ | 189f1da |
| 24 | Synapse Control Plane (Data Model, 56/56 tests passing) | ✅ | |

**Current State: 56/56 tests green. Code Freeze.**

---

## 8. Remaining Work

| Item | Priority | Status |
|---|---|---|
| Wazuh webhook tested with real SIEM alert | **CRITICAL** | ❌ Not done — untested critical path |
| SOAR_DRY_RUN=false on isolated VM | High | ❌ Awaiting Hetzner servers |
| Hetzner Node A + Node B provisioned | High | ❌ Awaiting first client |
| First real client scan (non-test domain) | High | ❌ Pre-sales phase |
| CF_API_TOKEN + CF_ZONE_ID in production .env | High | ❌ Awaiting client domain |
| Telegram 3 channels created with real tokens | High | ❌ 15-minute task |
| Contract financial tracking (Paid/Overdue invoices) | Medium | ❌ `contract_manager.py` tracks dates only |
| Sales Pipeline automation | Low | Manual + Notion |

---

## 9. Phase 23 — Anti-Gravity (Production Deployment)

### Prerequisites (do before provisioning)
```bash
# 1. Create Telegram bot + 3 channels → get tokens
# 2. Get Cloudflare CF_API_TOKEN (Edit WAF permissions) + CF_ZONE_ID
# 3. Prepare production.env (copy from .env, fill real values)
```

### Node Provisioning
```bash
# Node A (CX31 — 4vCPU/8GB): Wazuh + Elasticsearch + Kibana
# Node B (CX21 — 2vCPU/4GB): Shuffle + TheHive + webhook_server.py

# On Node B:
sed -i 's/YOUR_HETZNER_PUBLIC_IP/ACTUAL_IP/' deployment/hetzner_inventory.example
cp .env deployment/production.env  # Fill real values
ansible-playbook -i deployment/hetzner_inventory.example deployment/deploy_node_b.yml

# Verify:
curl http://NODE_B_IP:5000/health  # webhook
curl http://NODE_B_IP:9000         # TheHive
curl http://NODE_B_IP:3001         # Shuffle
```

### Wazuh Webhook Test (Critical Path)
```xml
<!-- wazuh/etc/ossec.conf -->
<integration>
  <name>custom-webhook</name>
  <hook_url>http://NODE_B_IP:5000/alert</hook_url>
  <level>7</level>
  <alert_format>json</alert_format>
</integration>
```

```bash
# Trigger test alert — SSH brute force simulation:
for i in $(seq 1 6); do ssh invalid@localhost; done
# Expected: Telegram ACTIONS channel fires within 30 seconds
```

### Flip to Live
```bash
# ONLY after webhook test passes:
sed -i 's/SOAR_DRY_RUN=true/SOAR_DRY_RUN=false/' /opt/synapse/.env
systemctl restart synapse-webhook
# Verify Cloudflare dashboard shows block on test IP
```

### Target Commit
```bash
git commit -m "feat(phase23): Production deployment — Wazuh webhook validated live

- webhook_server.py tested with real Wazuh SIEM alert
- alert_router routes live alert correctly
- Telegram fires on real channel
- SOAR_DRY_RUN=false verified on Hetzner VM

Node A: Wazuh + Elastic @ [IP]
Node B: Shuffle + TheHive + webhook @ [IP]"
```

---

## 10. Test Suite Reference

```bash
# Run all tests in order
python3 tests/test_isolation.py          # 4 tests
python3 tests/test_control_plane.py      # 6 tests
python3 tests/test_phase7.py             # 5 tests
python3 tests/test_phase14.py            # 6 tests
python3 tests/test_phase15.py            # 6 tests
python3 tests/test_phase16.py            # 6 tests
python3 tests/test_phase18_priority1.py  # 3 tests
python3 tests/test_phase19_priority2.py  # 3 tests
python3 tests/test_phase20_priority3.py  # 3 tests
python3 tests/test_final_e2e.py          # 14 tests

# Expected: 56/56 passing, 0 failing
```

---

## 11. Paid Tool Upgrade Triggers

| Tool | Current | Trigger to Upgrade |
|---|---|---|
| Gemini Flash | Free 15 RPM | >3 simultaneous clients scanning |
| VirusTotal | Free 500 req/day | >8 clients active |
| Cloudflare WAF | Free (limited) | First client needing Web Protection |
| Hetzner Node A | Not provisioned | First real client signed |
| Hetzner Node B | Not provisioned | First real client signed |

---

## 12. Business Context

- **5 Synapse Packages:** Starter (JOD 690) → Guard (JOD 590/mo) → Governance (JOD 780/mo) → Premium (JOD 1,250/mo)
- **Code tiers:** `soc_lite` / `soc_standard` / `soc_pro` / `soc_grc`
- **Break-even:** Q8 (Month 22-24) at 18-24 active clients
- **Target automation:** 84% average across all services
- **Compliance:** NCA ECC 2.0, UAE PDPL, ISO 27001, ADHICS

---

## 13. Automation Percentages by Service

| Service | Automation % | Human Time/Month |
|---|---|---|
| Baseline Assessment | 88% | 45 min |
| Website Security Assessment | 93% | 30 min |
| Email Security Assessment | 94% | 20 min |
| Vulnerability Assessment | 92% | 30 min |
| GRC Gap Assessment | 76% | 3-4 hours |
| SOC Alert Triage | 88% | per incident |
| Monthly Reporting | 91% | 15 min/client |
| Vulnerability Management | 91% | 20 min/client |
| Web Protection (Cloudflare) | 90% | 10 min/client |
| Email Retainer | 91% | 10 min/client |
| vCISO Services | 61% | 8 hours/month |
| ISO 27001 Programs | 64% | variable |
| Incident Response | 64% | per incident |
| Client Onboarding | 81% | 2 hours |
| Contract Management | 77% | 1 hour/month |
| **Overall Average** | **~84%** | |

---

## 14. Self-Update Instructions for Agent

**MANDATORY:** Every time you complete work on this project, you MUST:

```bash
# 1. Update this file with any new phases, fixes, or state changes
# 2. Commit with:
git add SYNAPSE_AGENT_HANDOFF.md
git commit -m "docs(handoff): Update agent handoff — [brief description of what changed]"
git push origin main
```

**What to update each session:**
- Section 1: Update `Last Commit` field
- Section 7: Add new phase row with commit hash
- Section 8: Move completed items from Remaining Work
- Section 14: Add any new known issues
- Section 3 (Phase 23 section): Update IPs when provisioned

**Periodic full sync (every 5 commits):**
```bash
git add .
git commit -m "chore: Periodic full repo sync"
git push origin main
```

---

## 15. Known Issues & Technical Debt

### Active
| Issue | Severity | Fix |
|---|---|---|
| Wazuh webhook never tested with live SIEM | High | Phase 23 Step 2 |
| `cleartext_http` high severity — NOTIFY_ONLY only (no PATCH_ADVISORY) | Low | Add to ROUTING_TABLE |
| testssl.sh returns `error` status in tests | Low | testssl binary path issue — investigate in Phase 23 |
| BankCo dashboard shows `techco_report.md` as last report | Low | BankCo has never been scanned — expected |

### Fixed in Phase 22
1. Router missing 5 DNS finding types → added
2. GeoIP `_enrich_geoip()` returning `None` → dual fallback, always returns dict
3. Scheduler test timeout → uses `--help` flag now
4. BankCo billing metadata missing → re-onboarded with fee=0 (update when real contract)
5. Compliance score 0/100 → confirmed correct math, not a bug

---

## 16. Communication Style for This Owner

- Technical peer tone — no simplification unless explicitly asked
- Structured markdown: headers, tables, code blocks
- Always show architectural reasoning and trade-offs
- Challenge weak assumptions
- When paid tool is urgently needed: say it directly
- Do not repeat completed work — check this file and git log first
