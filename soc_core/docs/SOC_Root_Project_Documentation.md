# SOC Root — AI-Native MSSP Platform: Full Build & Launch Documentation

## Overview

This conversation documents the end-to-end conception, architecture, development, and initial commercial launch of **SOC Root** (formerly Project Synapse SOC Factory / KYRIE SOC), an AI-native Managed Security Service Provider (MSSP) platform targeting SMBs in Jordan and the UAE. The primary objective was to transform an existing automated security engine into a fully operational, revenue-generating business — covering infrastructure deployment, client delivery, marketing automation, and commercial website launch. The conversation also served as a strategic advisory session, resolving critical decision paralysis and enforcing a bias toward execution over continued engineering.

---

## Key Discussed Points

### Strategic & Business

- **Analysis Paralysis identification**: Owner was repeatedly designing new architectures (AutoGen, local LLMs, KYRIE OS, Privacy Broker) instead of executing with the existing, production-ready engine (Phase 25). Strategic advisor enforced a hard stop on new building and redirected focus to revenue generation.
- **Business model validation**: Confirmed 4-tier MSSP packaging — Starter ($190/yr), Guard ($160/mo), Governance ($210/mo), Premium ($340/mo) — targeting Jordan and UAE SMBs under NCA ECC 2.0 and ISO 27001 compliance frameworks.
- **First client (AsasEdu)**: `asas4edu.net` identified as first real client. Full scan, triage, and executive PDF report completed. Client outreach strategy defined.
- **Path 2 (30-day freeze plan)**: Defined a fully free alternative action plan when capital was $0 — including Oracle Cloud Free Tier, Google/AWS startup credits, and local LLC registration.
- **Funding opportunities**: Mapped Jordan/UAE startup grants — MoDEE Jahez ($10K), YTJ Talent Incentive (50% salary subsidy), Orange AI Incubator, Zain ZINC (JOD 10K+), AWS Activate ($100K credits), Google Cloud Startups ($350K AI credits).
- **Brand naming decision**: Progressed through KYRIE → KYRIE SOC → **SOC Root** as final brand name with domain `socroot.com`.
- **Marketing pipeline architecture**: Designed 3-layer automated funnel — Awareness (website/LinkedIn/freelance platforms), Acquisition (AI lead gen + cold email), Conversion (automated scan → report → upsell → onboarding).

### Technical Architecture

- **Core pipeline confirmed**:
  ```
  Scan → Parse → RAG → LLM Triage → Compliance Engine → Delta Analysis → SOAR → Report → Email
  ```
- **Dual report system**: Internal SOC report (technical, for analysts) + Executive client report (business-framed, for decision makers) — generated from same scan JSON.
- **Gemini API issues resolved**: Model fallback chain implemented — `gemini-2.5-flash` → `gemini-2.0-flash` → `gemini-2.0-flash-lite` → structured mock (labeled). Exponential backoff added (15/30/45s).
- **KYRIE architecture review**: Privacy Broker, 4-layer model, Controller + Router designs reviewed — deemed premature but architecturally sound. Scheduled for Phase 36+ when multi-client AI routing is required.
- **Telegram pipeline**: Root cause identified (placeholder `.env` credentials). Fixed with production credentials. All 3 channels (Findings, Actions, Failures) confirmed operational.
- **Report truncation bug**: Fixed `fpdf2` `multi_cell` truncation by adding explicit `pdf.set_x(pdf.l_margin)` before every cell and dynamic `effective_w` calculation.
- **Discount code system**: JavaScript-based with codes `LAUNCH20` (20%), `PARTNER30` (30%), `PILOT50` (50%).

### Infrastructure & Deployment

- **Production nodes (Contabo VPS)**:
  - Node A: `167.86.98.91` — Wazuh 4.7.3, Elasticsearch, Kibana
  - Node B: `164.68.121.179` — Webhook server (port 5000), TheHive, Shuffle SOAR
- **Wazuh webhook**: Deployed, configured (`ossec.conf` integration block), and tested end-to-end. SSH brute-force simulation confirmed alert delivery to Telegram within 30 seconds.
- **UFW hardening**: Both nodes hardened. Port 5000 on Node B restricted to Node A IP only.
- **SSH hardening**: `harden_ssh.yml` Ansible playbook — port 22→2222, fail2ban installed (5 retries/1hr ban), key-only auth, UFW updated.
- **Cloudflare WAF connector**: `cloudflare_connector.py` upgraded to production. Live block/unblock cycle tested on `socroot.com` zone. Full read/write confirmed.
- **Cloudflare API token**: Created with permissions — Zone DNS Edit, Zone Read, Firewall Services Edit, Zone WAF Edit. IP-restricted to Node A + Node B IPs.

### Service Delivery

- **AsasEdu scan findings**:
  - CRITICAL: Cleartext HTTP (Port 80) — NCA-2-1-3 violation
  - HIGH: Default SSH (Port 22) — NCA-3-1-1 warning
  - HIGH: Missing SPF record — NCA-2-3-1 violation
  - HIGH: Missing DMARC record — NCA-2-3-1 violation
  - MEDIUM: Missing DKIM
  - INFO: Missing BIMI, MX records noted
  - Compliance score: **0/100 Grade F** (mathematically correct — intentionally unhardened target)
- **Report critique resolved**: External review identified missing Business Impact framing, Attack Narrative, Methodology section, and Remediation Roadmap. All added to `client_report_generator.py`.
- **Payment methods selected**: Binance Pay (USDT/USDC/BNB) + PayPal. Bank transfer and Wise available on request.

---

## Final Outputs & Results

### Infrastructure Status

| Component | Status | Details |
|---|---|---|
| Node A (SIEM) | ✅ LIVE | Wazuh 4.7.3, port 1514 open |
| Node B (SOAR) | ✅ LIVE | Webhook :5000, TheHive :9000, Shuffle :3001 |
| Wazuh → Webhook pipeline | ✅ VERIFIED | Alert in <30s confirmed |
| Telegram (3 channels) | ✅ LIVE | Findings, Actions, Failures |
| UFW hardening | ✅ DONE | Both nodes secured |
| SSH hardening | ✅ DONE | Port 2222, fail2ban, key-only |
| Cloudflare WAF connector | ✅ LIVE | Block/unblock tested on socroot.com |
| SOAR_DRY_RUN | ⚠️ true | Flip to false after Cloudflare full test |

### Completed Phases

| Phase | Description | Status |
|---|---|---|
| 1–22 | Core engine — parsers, RAG, LLM, SOAR, scheduler, CI/CD | ✅ |
| 23 | Ansible deploy + Wazuh + TheHive + Shuffle Docker | ✅ |
| 24–25 | Control Plane + SOAR inline execution | ✅ |
| 26 | Wazuh webhook LIVE on Contabo VPS | ✅ |
| 27 | UFW production hardening | ✅ |
| 28 | AsasEdu first client — onboard + scan + dual PDF report | ✅ |
| 29 | Revenue foundation — Telegram fix, Gemini fallback, dual report CLI | ✅ |
| 30 | Client operations — scheduler systemd, client YAML schema, contract manager, SSH hardening | ✅ |
| 38 | SOC Root website — 5 pages live on GitHub Pages + socroot.com | ✅ |
| 39 | Cloudflare WAF live + Financial ledger + Delta Telegram alerts | ✅ |

### Master Roadmap Structure

```
SYNAPSE_MASTER_ROADMAP.md — 10 Parts:

Part 0:  Project Identity & Vision
Part 1:  Architecture Overview (pipeline + infrastructure + AI stack)
Part 2:  Service Catalog (available now + roadmap)
Part 3:  Completed Phases (reference)
Part 4:  Active Roadmap (Phase 29 → 37, detailed sub-tasks)
Part 5:  Engineering Rules (safety, code standards, AI rules, report standards)
Part 6:  Paid Tool Upgrade Triggers
Part 7:  Known Issues & Technical Debt
Part 8:  Agent Instructions (antigravity + all AI agents)
Part 9:  Success Metrics (30-day / 90-day / 6-month / 12-month)
Part 10: Automated Marketing Pipeline (Phase 38 → 40)
```

### Website (socroot.com)

| Page | URL | Status |
|---|---|---|
| Home | socroot.com/ | ✅ Live |
| Services | socroot.com/services.html | ✅ Live + discount codes |
| Free Scan | socroot.com/scan.html | ✅ Live — FormSubmit pending activation |
| About | socroot.com/about.html | ✅ Live |
| Contact | socroot.com/contact.html | ✅ Live |
| Training | socroot.com/training.html | 🔄 In progress |

**DNS Records (Cloudflare → GitHub Pages)**:
```
A     socroot.com → 185.199.108.153
A     socroot.com → 185.199.109.153
A     socroot.com → 185.199.110.153
A     socroot.com → 185.199.111.153
CNAME www         → muath-yousef.github.io
```

### AsasEdu Executive Report (Final Version)

```
File: reports/output/asasEdu_executive_report_2026-04.pdf
Pages: 3
Sections:
  1. Cover — Risk Level: CRITICAL, Client: Asas Educational Platform
  2. Executive Summary (non-technical, 6 lines)
  3. Risk Summary Table (Severity + Business Impact + Priority)
  4. Attack Scenario Narrative
  5. Remediation Roadmap (3 phases: 0-7 days / 7-30 days / 30-90 days)
  6. Compliance Status (NCA ECC 2.0 — 3 controls mapped)
  7. Methodology & Scope
  8. About SOC Root
```

### Discount Code System

```javascript
const DISCOUNT_CODES = {
  "LAUNCH20":  0.20,  // 20% — launch offer
  "PARTNER30": 0.30,  // 30% — partner deal
  "PILOT50":   0.50   // 50% — pilot clients (e.g. AsasEdu)
};
```

### AI Stack (Current)

| Task | Model | Notes |
|---|---|---|
| Threat triage & analysis | gemini-2.0-flash | Primary — stable free tier |
| Fallback | gemini-2.0-flash-lite | Auto-fallback on 503 |
| Final fallback | Structured mock | Always labeled "OFFLINE ANALYSIS" |
| Embeddings / RAG | ChromaDB default | Client-isolated |
| Report writing | Gemini (same) | Deterministic temp=0.2, seed=42 |

### Automated Marketing Pipeline (Designed — Phases 38–40)

```
Layer 1 — Awareness:
  Website (socroot.com) + LinkedIn + Mostaql + Upwork + Fiverr

Layer 2 — Acquisition:
  lead_gen_agent.py → DNS pre-check → cold email (3-step sequence)
  → lead confirms → automated full scan → executive PDF delivered

Layer 3 — Conversion:
  Click "Subscribe" → onboard_client.py → scheduler.py → contract_manager.py
  No subscribe → re_engagement_agent.py → rescan every 30 days → delta comparison
```

### Logo Design Brief (for external tool)

```
Name: SOC Root
Style: Flat vector, minimalist, B2B enterprise cybersecurity
Colors: Cyan #00D4FF, Gold #FFD700, Background #0A0A0F
Icon concept: Hexagonal shield with Linux root symbol (#) inside
Typography: "SOC" bold Space Mono + "ROOT" lighter, wider tracking
Reference aesthetic: CrowdStrike / Darktrace / Palo Alto — minimalist
Output: Horizontal + stacked lockup, vector-ready, transparent background
```

---

## Next Steps / Recommendations

### 1. Close AsasEdu Contract (Immediate — This Week)
Send the executive PDF report to AsasEdu, schedule a 30-minute call, and present the Guard package ($160/month or PILOT50 discounted rate). This is the single highest-priority action — all subsequent phases depend on first-paid-client revenue and real-world feedback.

**Action items**:
- Activate FormSubmit at `security@kyriesoc.com` (check inbox for activation email)
- Reboot Node A and Node B (pending kernel upgrade from Phase 30)
- Set `SOAR_DRY_RUN=false` in `/opt/synapse/.env` after Cloudflare full pipeline test

### 2. Complete SOC Root Website (3 Remaining Items)
- Add finalized SVG logo to all pages once design is approved from external tool
- Add `training.html` — cybersecurity awareness course with 3 chapters, quizzes, and certificate generation
- Apply for Google Cloud Startups program ($350K AI credits) — removes infrastructure cost constraint permanently

### 3. Activate Automated Lead Generation (Phase 39 — After Website Complete)
Build and activate `lead_gen_agent.py` targeting Jordan/UAE SMBs via LinkedIn, Google Maps, and Chamber of Commerce directories. The automated cold email sequence (3-step) with personalized DNS pre-check findings will scale outreach without human effort. Target: 30 free scan requests in first 90 days with 15% conversion = 4–5 new clients.

---

*Document generated: April 2026*
*Project: SOC Root — Automated MSSP Platform*
*Maintainer: Muath Yousef — Kyrie Security Architect*
*Repository: github.com/Muath-Yousef/Project-Synapse-SOC-Factory (private)*
*Website: socroot.com*
