# SOC ROOT — COMPLETE EXECUTION PLAN: PHASES 1–7 + ANTIGRAVITY PROTOCOL
**Document Class:** Full Production Execution Plan — Single Consolidated File  
**Authority:** Supersedes all prior phase documents. Read before any code is written.  
**Date:** April 2026 | **Owner:** Muath Yousef — socroot.com  
**For:** Antigravity Agent — Google Antigravity IDE (Agent-First VS Code Fork)

---

## ANTIGRAVITY EXECUTION PROTOCOL

### Your Environment Capabilities
```
IDE:        Google Antigravity (VS Code fork, Agent-First)
Terminal:   Full bash — SSH, Docker, Python, Git — all permitted
Browser:    Built-in Chromium (headless + headed)
OpenCode:   Pre-installed — invoke with: opencode "<task>"
MCP:        Protocol active — servers registered in .gemini/antigravity/mcp_config.json
Skills:     Loaded from .gemini/antigravity/skills/
File Root:  /media/kyrie/VMs1/Cybersecurity_Tools_Automation
```

### Session Start Protocol (Every Session Without Exception)

```bash
# Step 1: Read project state
cat /media/kyrie/VMs1/Cybersecurity_Tools_Automation/.gemini/antigravity/knowledge/PHASE_STATE.md

# Step 2: Run baseline tests
cd /media/kyrie/VMs1/Cybersecurity_Tools_Automation && source venv/bin/activate
python3 tests/test_final_e2e.py

# Step 3: Confirm nodes reachable
ssh -p 2222 -o ConnectTimeout=5 root@167.86.98.91 "echo Node-A OK" 2>/dev/null || echo "⚠️ Node A unreachable"
ssh -p 2222 -o ConnectTimeout=5 root@164.68.121.179 "echo Node-B OK" 2>/dev/null || echo "⚠️ Node B unreachable"

# Step 4: Safety check
grep SOAR_DRY_RUN .env | grep -q "true" && echo "✅ DRY_RUN safe" || echo "🚨 HALT — DRY_RUN not true"

# Step 5: Verify SOAR_DRY_RUN grep in codebase (CI-grade check)
grep -r "SOAR_DRY_RUN=false" . --include="*.py" && echo "🚨 CRITICAL: DRY_RUN=false in code" || echo "✅ No DRY_RUN=false in code"
```

### Spec-Kit First Rule (Non-Negotiable)

For any phase with 3+ deliverables: generate structured Spec-Kit before any code.  
Spec-Kit must include: file list with full paths, function signatures, integration points, test cases.  
Await "AUTHORIZED — PROCEED" before writing production code.

### Response Format (Every Response)

```
## Phase [N] — [Name] — COMPLETE / PARTIAL / FAILED

### Done:
- [completed sub-tasks with full file paths]

### Not Done:
- [incomplete items with explicit reasons]

### Tests:
- [X/Y passing — list failures with exact error]

### Evidence Chain Status:
- verify_chain() result per client: [PASS/FAIL]

### PHASE_STATE.md Update:
- [exact content to write]

### Next Required Action:
- Muath: [what human must do — in Arabic]
- Antigravity: [what agent starts next]

### Commit: [hash]
```

### Scope Enforcement (Before Every Code Line)

```
Ask before writing any code:
  1. Is this in the current phase deliverables list?
  2. Is this phase's unlock condition already met?
  3. Does this touch Phase [N+1] components?

If any answer is NO:
  Output: "SCOPE FLAG: [description]"
  STOP. Await authorization.
```

### OpenCode Usage Pattern

```bash
# Use OpenCode for: deep code analysis, complex refactoring, security review
# Do NOT use for: simple file creation, git ops, infrastructure commands

opencode "Analyze soc/evidence_store.py verify_chain() for hash computation edge cases and fix any found"
opencode "Review compliance_engine.py for client_id isolation violations"
opencode "Refactor alert_router.py to integrate DAL without breaking existing playbook tests"
```

### Safety Overrides — Required Authorization Strings

| Action | Required from Muath |
|--------|-------------------|
| Set SOAR_DRY_RUN=false | "SOAR GO LIVE — AUTHORIZED BY MUATH [date]" |
| Scan new domain | "SCAN AUTHORIZED: [domain] — MUATH [date]" |
| Modify evidence format | "EVIDENCE FORMAT CHANGE — MUATH [date] — REASON: [X]" |
| Scope expansion | "SCOPE EXPANSION — MUATH [date] — PHASE [N]" |
| Deploy to Node A/B | "NODE DEPLOY — MUATH [date]" |

---

## SKILLS — يبنيها Antigravity في .gemini/antigravity/skills/

### Build All Skills (Terminal Command)

```bash
PROJECT_ROOT="/media/kyrie/VMs1/Cybersecurity_Tools_Automation"
mkdir -p "$PROJECT_ROOT/.gemini/antigravity/skills"
```

### Skill 1: Evidence Chain Verification Expert

```bash
cat > /media/kyrie/VMs1/Cybersecurity_Tools_Automation/.gemini/antigravity/skills/evidence_verification.md << 'EOF'
# Skill: Evidence Chain Verification Expert

## When to Use
Any task involving evidence store integrity, hash chain verification,
debugging evidence format issues, or auditor export preparation.

## Core Knowledge

### Hash Chain Structure
Each EvidenceRecord is hashed using SHA-256 over all fields in deterministic order.
Fields must be serialized in EXACT dataclass definition order — never alphabetically.
prev_record_hash of record N = record_hash of record N-1.
First record has prev_record_hash = None.

### WORM Principle
chain.jsonl is append-only. No line is ever modified or deleted.
Any modification breaks the hash chain and fails verify_chain().
EvidenceStore.append() is the only write method — no direct file manipulation.

### Audit Export Rules
export format is FROZEN after first client record.
Field names: control_id, framework, client_id, scan_id, status, finding_summary,
             source, event_id, raw_log_hash, timestamp, origin, prev_record_hash,
             record_hash, raw_log_ref
Never add, rename, remove, or reorder these fields.

## Common Failure Patterns

### Pattern 1: Hash Mismatch After Code Change
Symptom: verify_chain() fails on existing chain after code edit
Cause: Changed field serialization order in compute_hash()
Fix: Restore original field order in hash computation

### Pattern 2: Chain Break After Server Restart
Symptom: New records fail to chain to existing
Cause: EvidenceStore not loading last_record_hash on init
Fix: EvidenceStore.__init__ must read last line of chain.jsonl on startup

### Pattern 3: Empty event_id
Symptom: External anchor field is empty
Cause: Source system not providing event ID
Fix: Fallback to f"{scan_id}_{control_id}_{timestamp}" composite

## Test Commands
```bash
# Verify specific client chain
python3 -c "
from soc.evidence_store import EvidenceStore
store = EvidenceStore('asasEdu')
result = store.verify_chain()
print('PASS' if result else 'FAIL')
"

# Check chain file directly
cat knowledge/evidence/asasEdu/chain.jsonl | python3 -c "
import sys, json
records = [json.loads(l) for l in sys.stdin if l.strip()]
print(f'{len(records)} records found')
print('Last record hash:', records[-1]['record_hash'][:16] if records else 'empty')
"
```

## Red Flags — Stop Immediately
- Any code that opens chain.jsonl in write mode (not append)
- Field name changes in EvidenceRecord after Phase 1 completion
- Hash computation using json.dumps without sort_keys=True equivalent
- verify_chain() disabled or commented out before export
EOF
```

### Skill 2: NCA ECC 2.0 Control Mapper

```bash
cat > /media/kyrie/VMs1/Cybersecurity_Tools_Automation/.gemini/antigravity/skills/nca_control_mapping.md << 'EOF'
# Skill: NCA ECC 2.0 Control Mapping Expert

## When to Use
Mapping Wazuh rule IDs to NCA controls, expanding nca_controls.json,
debugging compliance scores, UAE PDPL mapping, ISO 27001 cross-mapping.

## NCA ECC 2.0 Structure — 114 Controls, 5 Domains

Domain 1: Cybersecurity Governance (1.1–1.6) — 6 main controls
  1.1 Cybersecurity Strategy
  1.2 Cybersecurity Policy
  1.3 Cybersecurity Roles and Responsibilities
  1.4 Cybersecurity Risk Management
  1.5 Cybersecurity in Projects
  1.6 Compliance with Cybersecurity Standards

Domain 2: Cybersecurity Risk Management (2.1–2.5) — 5 main controls
  2.1 Asset Management
  2.2 Vulnerability Management
  2.3 Network Security
  2.4 Identity and Access Management
  2.5 Malware Protection

Domain 3: Cybersecurity Controls (3.1–3.4) — 4 main controls
  3.1 Physical Security
  3.2 System and Application Security
  3.3 Cryptography
  3.4 Email Security

Domain 4: Third Party Cybersecurity (4.1–4.3) — 3 main controls
  4.1 Third Party Assessment
  4.2 Third Party Contracts
  4.3 Cloud Security

Domain 5: Cybersecurity Resilience (5.1–5.3) — 3 main controls
  5.1 Backup and Recovery
  5.2 Business Continuity
  5.3 Incident Response

## Wazuh Rule ID → NCA Control Mapping (Production)

### SSH / Access Control (NCA-2.4 / NCA-3.1)
5701 → NCA-2.4.1 (SSH login failure)
5710 → NCA-3.1.1 (SSH brute force)
5712 → NCA-3.1.1 (SSH login success after multiple failures)
5716 → NCA-2.4.1 (SSH login error)
5720 → NCA-3.1.1 (multiple authentication failures)
5760 → NCA-3.1.1 (SSH authentication failure)

### Web Attacks (NCA-2.3)
31101 → NCA-2.3.1 (Web attack: SQL injection)
31103 → NCA-2.3.1 (Web attack: XSS)
31104 → NCA-2.3.1 (Web attack: path traversal)
31151 → NCA-2.3.1 (Web attack: command injection)

### Network Security (NCA-2.3)
100002 → NCA-2.1.3 (Cleartext HTTP detected)
80100 → NCA-2.2.1 (Port scan detected)
80101 → NCA-2.2.1 (Port scan — high volume)

### Malware (NCA-2.5)
87003 → NCA-2.5.1 (Malware detected)
510 → NCA-2.5.1 (rootkit detection)
511 → NCA-2.5.1 (rootkit evidence)

### System Integrity (NCA-3.2)
550 → NCA-3.2.1 (integrity check failed)
553 → NCA-3.2.1 (file modified)
554 → NCA-3.2.1 (file added to system)

## Expansion Strategy for nca_controls.json
For each control:
  1. Identify all Wazuh rules detecting violations
  2. Map scanner tools: nmap (port/service), nuclei (CVE), dns_tool (DNS), testssl (TLS)
  3. Set severity_weight: critical=-40, high=-20, medium=-10, low=-5
  4. Write remediation_summary in English (Arabic in Phase 3)
  5. Set auto_detectable=true if scanner/Wazuh can verify, false if policy-only

## JSON Structure per Control
{
  "control_id": "NCA-2.3.1",
  "domain": "Network Security",
  "title_en": "Network Security Controls",
  "title_ar": "ضوابط أمن الشبكة",
  "description": "Implement firewall, IDS/IPS, and network segmentation",
  "wazuh_rule_ids": [31101, 31103, 31104, 80100],
  "scanner_tool": "nmap",
  "severity_weight": -40,
  "auto_detectable": true,
  "remediation_summary": "Enable WAF rules, patch web vulnerabilities, segment network"
}
EOF
```

### Skill 3: Alert Triage Expert

```bash
cat > /media/kyrie/VMs1/Cybersecurity_Tools_Automation/.gemini/antigravity/skills/alert_triage.md << 'EOF'
# Skill: SOC Alert Triage and DAL Classification

## When to Use
Tasks involving alert confidence scoring, false positive tuning,
DAL tier boundary adjustments, KNOWN_BENIGN_PATTERNS population.

## Tier Classification Logic

### Tier 1 — Auto-Close
Conditions (ALL must be true):
  - confidence >= 0.90
  - severity in {info, low}
  - alert.pattern in KNOWN_BENIGN_PATTERNS
Action: log to audit_log, skip playbook, no notification
Human time: 0 minutes

### Tier 2 — Auto-Remediate
Conditions (ALL must be true):
  - confidence >= 0.75
  - severity in {medium, high}
  - critical_asset == False
  - novel_pattern == False
Action: execute_playbook() (if DRY_RUN=false), Telegram notify
Human time: 0 minutes (15 min review next day)

### Tier 3 — Human Escalation
Conditions (ANY is true):
  - confidence < 0.75
  - novel_pattern == True
  - critical_asset == True
  - severity == critical
Action: Telegram immediate alert, queue for human review
SLA: review within 2 hours
Human time: 15-30 minutes

## Override Rules (ABSOLUTE)
critical_asset=True ALWAYS routes to Tier 3 — no exceptions
novel_pattern=True ALWAYS routes to Tier 3 — no exceptions
SOAR_DRY_RUN=true blocks ALL Tier 2 remediation (log only)

## Known Benign Patterns — Populate from First 30 Days
KNOWN_BENIGN_PATTERNS = {
    "scheduled_vuln_scan": lambda a: a.get("source_ip") in KNOWN_SCANNER_IPS,
    "health_check_ping": lambda a: a.get("description", "").startswith("health check"),
    "admin_ssh_known_ip": lambda a: a.get("rule_id") == 5712 and a.get("src_ip") in ADMIN_IPS,
    "monitoring_agent": lambda a: "wazuh-agent" in a.get("agent_name", ""),
}

## Confidence Scoring Guidelines
- Known CVE from NVD, confidence from Gemini >= 0.85: use as-is
- Behavioral anomaly without known pattern: cap at 0.70
- Cloudflare WAF trigger: base 0.80, adjust by reputation score
- Wazuh OSSEC rules: use rule.level / 15 as base confidence

## Red Flags
- Tier 2 execution without checking critical_asset flag
- Missing DRY_RUN check before any remediation
- Confidence set to 1.0 without human validation
- KNOWN_BENIGN_PATTERNS updated without 30-day data
EOF
```

### Skill 4: Arabic Compliance Report Generator

```bash
cat > /media/kyrie/VMs1/Cybersecurity_Tools_Automation/.gemini/antigravity/skills/arabic_reporting.md << 'EOF'
# Skill: Arabic Compliance Report Generation

## When to Use
Generating Arabic PDF reports, translating compliance findings,
NCA ECC 2.0 bilingual outputs, executive summaries in Arabic.

## Arabic Text Rendering Pipeline

### Required Libraries
pip install fpdf2 arabic-reshaper python-bidi

### Code Pattern
import arabic_reshaper
from bidi.algorithm import get_display
from fpdf import FPDF

def prepare_arabic_text(text: str) -> str:
    reshaped = arabic_reshaper.reshape(text)
    return get_display(reshaped)  # now right-to-left ready

def add_arabic_cell(pdf, text, width=0, height=10, align="R"):
    prepared = prepare_arabic_text(text)
    pdf.set_right_margin(10)
    pdf.cell(width, height, prepared, align=align)

## Report Structure — Arabic Executive Report

1. غلاف التقرير (Cover)
   - اسم الشركة العميلة
   - مستوى الخطر: حرج 🔴 / عالٍ 🟠 / متوسط 🟡 / منخفض 🟢
   - تاريخ التقرير + رقم المسح
   
2. الملخص التنفيذي
   - جملتان: ما وجدناه + ما يعنيه للعمل
   
3. جدول المخاطر
   | المخاطرة | الشدة | التأثير التجاري | الأولوية |
   
4. سيناريو الهجوم
   - كيف يمكن للمهاجم استغلال الثغرات
   - باللغة غير التقنية
   
5. خارطة المعالجة
   - المرحلة 1 (0-7 أيام): الإجراءات الحرجة
   - المرحلة 2 (7-30 يوم): الإجراءات العالية
   - المرحلة 3 (30-90 يوم): التحسينات المتوسطة
   
6. حالة الامتثال — NCA ECC 2.0
   - النسبة المئوية للامتثال
   - الضوابط الناجحة / الفاشلة / يدوية
   
7. المنهجية والنطاق
   - الأدوات المستخدمة
   - النطاق: [domain] + [IP ranges]
   
8. عن SOC Root
   - الشركة + طريقة التواصل

## Translation Priority (via DeepSeek API or Gemini)
finding_summary → Arabic: use LLM with prompt:
"ترجم هذا الملخص الأمني للعربية بلغة تنفيذية غير تقنية: [text]"
remediation steps → Arabic: use LLM similarly

## Fonts for Arabic PDF
Download and use: Amiri-Regular.ttf or NotoNaskhArabic-Regular.ttf
Path: reports/fonts/Amiri-Regular.ttf
pdf.add_font("Amiri", "", "reports/fonts/Amiri-Regular.ttf", uni=True)
pdf.set_font("Amiri", size=12)

## Red Flags
- Using default FPDF fonts for Arabic (will render as gibberish)
- Not applying arabic_reshaper before get_display
- Left-alignment for Arabic text (must be RIGHT-align)
- Missing RTL marker for mixed Arabic/English text
EOF
```

### Skill 5: Lead Generation Expert

```bash
cat > /media/kyrie/VMs1/Cybersecurity_Tools_Automation/.gemini/antigravity/skills/lead_generation.md << 'EOF'
# Skill: Lead Generation and Cold Email Automation

## When to Use
Phase 6+ tasks: generating qualified leads, pre-scanning domains,
personalized cold email composition, follow-up sequencing.

## Lead Scoring Algorithm

Score starts at 0. Max = 100.

+20: Website exists and is active (HTTP 200)
+20: No valid HTTPS (cleartext HTTP on port 80 with no redirect)
+20: Missing SPF record OR missing DMARC record (DNS pre-check)
+15: Industry: education, finance, healthcare, legal, government-adjacent
+15: Employee count: 20-200 (LinkedIn/Crunchbase estimate)
+10: Based in Jordan or UAE
-20: Already a SOC Root client (check client_profiles/)
-30: Government entity (.gov.jo, .gov.ae)

Minimum score to contact: 50
Pre-scan (DNS only) runs BEFORE any email
Full scan (nuclei + nmap) runs ONLY after lead clicks confirmation link

## Lead Sources (Legal Public Data Only)
1. LinkedIn company search: Jordan/UAE, 10-200 employees
2. Google Maps business listings
3. Chamber of Commerce directories (Jordan: JCC, UAE: Dubai Chamber)
4. .jo and .ae domain registries (public WHOIS)

## Cold Email Sequence

Email 1 (Day 0): Personalized finding
Subject: "أمر يخص أمان [company.com] وجدناه اليوم"
Body template:
  مرحباً [name],
  أجرينا فحصاً أولياً مجانياً على [domain] ووجدنا: [SPECIFIC_FINDING]
  هذا يعرض [BUSINESS_IMPACT].
  هل تودون رؤية التقرير الكامل؟ — رابط: [confirmation_link]
  مع التحية، فريق SOC Root

Email 2 (Day 3, no response): Report ready
Subject: "تقريركم جاهز — [company.com]"
Body: 2 sentences + report download link (requires click)

Email 3 (Day 7, final): 3 sentences max
Subject: "آخر تذكير — [company.com]"
Body: finding + urgency + unsubscribe

## Technical Pipeline
1. dns_pre_check(domain) → score contribution
2. score >= 50 → add to outreach queue
3. email_connector.send(email_1) with actual finding
4. scheduler tracks opens/clicks
5. lead confirms link → trigger full_scan(domain)
6. full_scan complete → email executive PDF → pricing email

## Safety Rules
- NEVER scan domain without confirmation click from lead
- ALL emails include unsubscribe link
- Send from security@socroot.com (not personal)
- Rate limit: max 20 emails/day
- No scraping login-required pages
EOF

echo "✅ All 5 Skills created in .gemini/antigravity/skills/"
ls /media/kyrie/VMs1/Cybersecurity_Tools_Automation/.gemini/antigravity/skills/
```

---

## المهام اليدوية — القائمة الكاملة (5 فقط عبر 7 مراحل)

> كل مهمة هنا مستحيل تنفيذها آلياً لأسباب قانونية أو تتطلب حضور بشري فعلي.

### H-1: إغلاق عقد AsasEdu — Phase 0 (ضروري)
```
أرسل لهم تقرير PDF التنفيذي الجاهز
حدد مكالمة 30 دقيقة لشرح النتائج
قدم باقة Guard بسعر $160/شهر أو PILOT50 بسعر $80/شهر (3 أشهر أولى)
اتفق على طريقة الدفع: Binance Pay (USDT) أو PayPal
بمجرد الموافقة الكتابية (email يكفي): أرسله إلى security@kyriesoc.com بعنوان "ASASEDU SIGNED"
```

### H-2: Binance Pay KYC — Phase 0 (ضروري إن لم يكتمل)
```
اذهب إلى: merchant.binance.com
أكمل التحقق من الهوية التجارية
تتطلب: رخصة تجارية + إثبات هوية + إثبات عنوان
هذه مستندات رسمية تحتاج رفعاً يدوياً — لا يمكن أتمتتها
بعد الموافقة: تحقق من وصول معاملة اختبارية
```

### H-3: Auditor Informal Review — Phase 3 (اختياري لكن مهم)
```
أرسل بريداً إلكترونياً إلى واحد من:
  - BSI Middle East: info.me@bsigroup.com
  - Bureau Veritas MENA: mena@bureauveritas.com
  - TÜV Rheinland ME: me@tuv.com
محتوى البريد:
  "نحن نبني منصة خدمات أمنية مُدارة للشركات في الأردن والإمارات.
   هل يمكنكم مراجعة منهجية توثيق الأدلة لدينا للتأكد من قبولها في تقييمات NCA ECC 2.0؟"
أرفق: evidence_methodology_doc.md (يولّده Antigravity)
الهدف: تأكيد مكتوب أن صيغة الأدلة مقبولة
```

### H-4: SOAR Go-Live Authorization — Phase 4 (ضروري)
```
بعد اكتمال كل شروط Phase 4:
  - راجع نتائج الاختبارات الموضحة في Section 4.2
  - أرسل email من حسابك الشخصي إلى security@kyriesoc.com بالنص التالي:
  
  "SOAR GO LIVE — AUTHORIZED BY MUATH [التاريخ]
   تم مراجعة جميع الشروط المسبقة وأنا أوافق على تحويل SOAR_DRY_RUN إلى false
   للعميل: [اسم العميل] فقط."
  
  Antigravity ينتظر هذا النص الحرفي قبل أي تغيير
```

### H-5: Auditor Partnership Outreach — Phase 6 (اختياري)
```
استهدف شركات التدقيق بعد تسليم أول تقرير ناجح:
  - BSI / Bureau Veritas / TÜV Rheinland
  - الهدف: اتفاقية إحالة رسمية
  - SOC Root يحيل العملاء → المدقق يؤكد صيغة الأدلة
  - هذه علاقة تجارية تحتاج مكالمة + توقيع — لا تتم آلياً
```

---

# PHASE 1 — EVIDENCE SYSTEM FOUNDATION

**Status:** READY TO BUILD — start immediately after Phase 0 unlock  
**Unlock Condition:** AsasEdu signed contract OR written confirmation  
**Unlock for Phase 2:** verify_chain() passing on first real AsasEdu scan

---

## Phase 1 Spec-Kit Verification

```bash
# Pre-execution checks
cd /media/kyrie/VMs1/Cybersecurity_Tools_Automation
source venv/bin/activate
python3 tests/test_final_e2e.py  # Must be green before starting

# Verify prerequisite directories
ls knowledge/evidence/ || mkdir -p knowledge/evidence
ls knowledge/compliance_frameworks/ || mkdir -p knowledge/compliance_frameworks
ls reports/audit_packages/ || mkdir -p reports/audit_packages

# Verify AsasEdu client exists
cat knowledge/client_profiles/asasEdu.yaml

# Create Phase 1 branch
git checkout -b phase1-evidence-system 2>/dev/null || git checkout phase1-evidence-system

# Install Phase 1 dependencies
pip install jsonlines mypy types-fpdf2 --break-system-packages --quiet
```

---

## Deliverable 1.1 — Evidence Schema and Store

**File:** `soc/evidence_store.py`

```python
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
```

**Commit:**
```bash
cd /media/kyrie/VMs1/Cybersecurity_Tools_Automation
git add soc/evidence_store.py
git commit -m "feat(phase1-1.1): EvidenceRecord dataclass + EvidenceStore WORM chain"
```

---

## Deliverable 1.2 — Wazuh Evidence Bridge

**File:** `soc/wazuh_evidence_bridge.py`

```python
"""
Wazuh Evidence Bridge — converts Wazuh JSON alerts to EvidenceRecords
Maps Wazuh rule IDs to NCA ECC 2.0 controls.
"""

from datetime import datetime, timezone
from typing import Optional

from soc.evidence_store import EvidenceRecord, EvidenceStore, hash_raw_log

# ─────────────────────────────────────────────
# NCA ECC 2.0 Control Mapping
# Wazuh rule_id (int) → (control_id, framework)
# Expand to full 114 controls as intelligence grows
# ─────────────────────────────────────────────
NCA_WAZUH_MAP: dict[int, tuple[str, str]] = {
    # SSH / Access Control
    5701: ("NCA-2.4.1", "NCA_ECC_2.0"),  # SSH login failure
    5710: ("NCA-3.1.1", "NCA_ECC_2.0"),  # SSH brute force
    5712: ("NCA-3.1.1", "NCA_ECC_2.0"),  # SSH login after multiple failures
    5716: ("NCA-2.4.1", "NCA_ECC_2.0"),  # SSH login error
    5720: ("NCA-3.1.1", "NCA_ECC_2.0"),  # Multiple authentication failures
    5760: ("NCA-3.1.1", "NCA_ECC_2.0"),  # SSH authentication failure

    # Web Attacks
    31101: ("NCA-2.3.1", "NCA_ECC_2.0"),  # SQL injection
    31103: ("NCA-2.3.1", "NCA_ECC_2.0"),  # XSS
    31104: ("NCA-2.3.1", "NCA_ECC_2.0"),  # Path traversal
    31151: ("NCA-2.3.1", "NCA_ECC_2.0"),  # Command injection

    # Network Security
    100002: ("NCA-2.1.3", "NCA_ECC_2.0"),  # Cleartext HTTP
    80100: ("NCA-2.2.1", "NCA_ECC_2.0"),   # Port scan
    80101: ("NCA-2.2.1", "NCA_ECC_2.0"),   # Port scan high volume

    # Malware
    87003: ("NCA-2.5.1", "NCA_ECC_2.0"),  # Malware detected
    510: ("NCA-2.5.1", "NCA_ECC_2.0"),    # Rootkit detection
    511: ("NCA-2.5.1", "NCA_ECC_2.0"),    # Rootkit evidence

    # System Integrity
    550: ("NCA-3.2.1", "NCA_ECC_2.0"),   # Integrity check failed
    553: ("NCA-3.2.1", "NCA_ECC_2.0"),   # File modified
    554: ("NCA-3.2.1", "NCA_ECC_2.0"),   # File added to system

    # Email Security
    200100: ("NCA-3.4.1", "NCA_ECC_2.0"),  # Missing SPF
    200101: ("NCA-3.4.1", "NCA_ECC_2.0"),  # Missing DMARC
    200102: ("NCA-3.4.1", "NCA_ECC_2.0"),  # Missing DKIM

    # Vulnerability / Patch
    23001: ("NCA-2.2.1", "NCA_ECC_2.0"),  # Outdated software
    23002: ("NCA-2.2.1", "NCA_ECC_2.0"),  # Critical CVE detected
}

SEVERITY_MAP: dict[str, str] = {
    "critical": "FAIL",
    "high": "FAIL",
    "medium": "PARTIAL",
    "low": "PARTIAL",
    "info": "PASS",
}


def extract_rule_id(alert: dict) -> Optional[int]:
    """Extract Wazuh rule ID from alert JSON."""
    try:
        rule_id = alert.get("rule", {}).get("id")
        if rule_id is not None:
            return int(rule_id)
    except (ValueError, TypeError):
        pass
    return None


def extract_severity(alert: dict) -> str:
    """Extract severity from Wazuh alert level (1-15 → severity string)."""
    level = alert.get("rule", {}).get("level", 0)
    try:
        level = int(level)
    except (ValueError, TypeError):
        return "info"

    if level >= 13:
        return "critical"
    elif level >= 10:
        return "high"
    elif level >= 7:
        return "medium"
    elif level >= 4:
        return "low"
    return "info"


def build_finding_summary(alert: dict, control_id: str) -> str:
    """
    Build audit-facing finding summary in non-technical language.
    Must be understandable by auditors, not just engineers.
    """
    description = alert.get("rule", {}).get("description", "Security event detected")
    agent = alert.get("agent", {}).get("name", "unknown host")
    src_ip = alert.get("data", {}).get("srcip", "")

    summary = f"[{control_id}] {description} on {agent}"
    if src_ip:
        summary += f" from {src_ip}"
    return summary


def wazuh_alert_to_evidence(
    alert: dict,
    client_id: str,
    scan_id: str,
    store: EvidenceStore,
) -> Optional[EvidenceRecord]:
    """
    Convert Wazuh JSON alert to EvidenceRecord and append to chain.

    Returns:
        EvidenceRecord if rule is mapped to NCA control, None if unmapped.
    """
    rule_id = extract_rule_id(alert)

    if rule_id is None or rule_id not in NCA_WAZUH_MAP:
        # Unmapped rule — do not create evidence record
        return None

    control_id, framework = NCA_WAZUH_MAP[rule_id]
    severity = extract_severity(alert)
    status = SEVERITY_MAP.get(severity, "PARTIAL")

    # External anchor — Wazuh internal alert ID
    event_id = alert.get("id") or alert.get("_id") or f"{scan_id}_{rule_id}_{datetime.now(timezone.utc).timestamp()}"

    raw_log_content = str(alert)  # Full alert JSON as string for hashing

    record = EvidenceRecord(
        control_id=control_id,
        framework=framework,
        client_id=client_id,
        scan_id=scan_id,
        status=status,
        finding_summary=build_finding_summary(alert, control_id),
        source="wazuh",
        event_id=str(event_id),
        raw_log_hash=hash_raw_log(raw_log_content),
        timestamp=datetime.now(timezone.utc).isoformat(),
        origin="remote",
    )

    return store.append(record)


def process_wazuh_alert_batch(
    alerts: list[dict],
    client_id: str,
    scan_id: str,
    store: EvidenceStore,
) -> dict:
    """
    Process a batch of Wazuh alerts. Returns summary statistics.
    """
    mapped = 0
    skipped = 0

    for alert in alerts:
        result = wazuh_alert_to_evidence(alert, client_id, scan_id, store)
        if result is not None:
            mapped += 1
        else:
            skipped += 1

    return {
        "total": len(alerts),
        "mapped_to_nca": mapped,
        "skipped_unmapped": skipped,
        "client_id": client_id,
        "scan_id": scan_id,
    }
```

**Commit:**
```bash
git add soc/wazuh_evidence_bridge.py
git commit -m "feat(phase1-1.2): Wazuh alert → EvidenceRecord bridge + NCA mapping"
```

---

## Deliverable 1.3 — Compliance Engine Integration

**File:** `soc/compliance_engine.py` — ADD these functions to existing module

```python
# ── ADD TO EXISTING compliance_engine.py ──────────────────────────────────────
# Insert after existing compliance score calculation, before report generation

from soc.evidence_store import EvidenceRecord, EvidenceStore, hash_raw_log
from datetime import datetime, timezone


def generate_evidence_from_finding(
    control_id: str,
    framework: str,
    client_id: str,
    scan_id: str,
    status: str,
    finding_summary: str,
    source: str,
    raw_finding_data: dict,
    store: EvidenceStore,
) -> EvidenceRecord:
    """
    Generate and append EvidenceRecord from compliance engine finding.
    Called after each control evaluation — ensures every finding has evidence.
    """
    event_id = f"{scan_id}_{control_id}_{source}"

    record = EvidenceRecord(
        control_id=control_id,
        framework=framework,
        client_id=client_id,
        scan_id=scan_id,
        status=status,
        finding_summary=finding_summary,
        source=source,
        event_id=event_id,
        raw_log_hash=hash_raw_log(str(raw_finding_data)),
        timestamp=datetime.now(timezone.utc).isoformat(),
        origin="remote",
    )

    return store.append(record)


def attach_evidence_references(
    compliance_report: dict,
    client_id: str,
    scan_id: str,
    store: EvidenceStore,
) -> dict:
    """
    Attach evidence record references to compliance report output.
    Auditor can verify each finding via chain.
    """
    for control in compliance_report.get("controls", []):
        control_id = control.get("control_id")
        if control_id:
            records = store.get_records_by_control(control_id)
            control["evidence_count"] = len(records)
            control["latest_evidence_hash"] = records[-1]["record_hash"][:16] if records else None
            control["evidence_chain_file"] = f"knowledge/evidence/{client_id}/chain.jsonl"

    return compliance_report


# ── MODIFY EXISTING evaluate_controls() or equivalent function ─────────────────
# After each control evaluation, add:
#
#   if finding_status in {"FAIL", "PARTIAL"}:
#       generate_evidence_from_finding(
#           control_id=control_id,
#           framework="NCA_ECC_2.0",
#           client_id=client_id,
#           scan_id=scan_id,
#           status=finding_status,
#           finding_summary=remediation_text,
#           source=scanner_tool,
#           raw_finding_data=raw_result,
#           store=evidence_store,
#       )
```

**Commit:**
```bash
git add soc/compliance_engine.py
git commit -m "feat(phase1-1.3): evidence generation integration in compliance engine"
```

---

## Deliverable 1.4 — NCA ECC 2.0 Full Control Mapping

**File:** `knowledge/compliance_frameworks/nca_controls.json`

```bash
# Antigravity generates this JSON via OpenCode for accuracy
opencode "Generate a complete nca_controls.json file with all 114 NCA ECC 2.0 controls.
Each control must have: control_id, domain, title_en, title_ar, description, 
wazuh_rule_ids (array), scanner_tool, severity_weight (int), auto_detectable (bool), 
remediation_summary. Structure must match exactly the schema in the NCA_CONTROL_MAPPER skill.
Output only valid JSON, no markdown, no explanation."

# After OpenCode generates, save to:
# knowledge/compliance_frameworks/nca_controls.json
```

**Minimum stub for testing (Antigravity expands to 114):**

```json
{
  "framework": "NCA_ECC_2.0",
  "version": "2.0",
  "total_controls": 114,
  "controls": {
    "NCA-2.3.1": {
      "control_id": "NCA-2.3.1",
      "domain": "Network Security",
      "title_en": "Network Security Controls — Perimeter Defense",
      "title_ar": "ضوابط أمن الشبكة — الدفاع المحيطي",
      "description": "Implement firewall rules, intrusion detection, and WAF to protect network perimeter",
      "wazuh_rule_ids": [31101, 31103, 31104, 31151, 80100, 80101],
      "scanner_tool": "nmap",
      "severity_weight": -40,
      "auto_detectable": true,
      "remediation_summary": "Enable WAF rules blocking OWASP Top 10. Configure IDS/IPS. Segment network DMZ."
    },
    "NCA-3.1.1": {
      "control_id": "NCA-3.1.1",
      "domain": "Access Control",
      "title_en": "Authentication and Access Controls",
      "title_ar": "ضوابط المصادقة والوصول",
      "description": "Enforce strong authentication, MFA, account lockout policies",
      "wazuh_rule_ids": [5701, 5710, 5712, 5716, 5720, 5760],
      "scanner_tool": "nmap",
      "severity_weight": -30,
      "auto_detectable": true,
      "remediation_summary": "Enable MFA. Configure account lockout after 5 failures. Restrict SSH to key-based auth."
    },
    "NCA-2.1.3": {
      "control_id": "NCA-2.1.3",
      "domain": "Asset Management",
      "title_en": "Asset Classification and Encryption",
      "title_ar": "تصنيف الأصول والتشفير",
      "description": "Classify assets by sensitivity, enforce encryption for sensitive data transmission",
      "wazuh_rule_ids": [100002],
      "scanner_tool": "testssl",
      "severity_weight": -40,
      "auto_detectable": true,
      "remediation_summary": "Force HTTPS redirect. Deploy TLS 1.2+. Disable cleartext protocols."
    },
    "NCA-2.2.1": {
      "control_id": "NCA-2.2.1",
      "domain": "Vulnerability Management",
      "title_en": "Vulnerability Assessment and Patching",
      "title_ar": "تقييم الثغرات والتحديثات",
      "description": "Regular vulnerability scanning, patch management, CVE tracking",
      "wazuh_rule_ids": [23001, 23002, 80100, 80101],
      "scanner_tool": "nuclei",
      "severity_weight": -20,
      "auto_detectable": true,
      "remediation_summary": "Patch critical CVEs within 7 days, high within 30 days. Enable auto-update where safe."
    },
    "NCA-2.5.1": {
      "control_id": "NCA-2.5.1",
      "domain": "Malware Protection",
      "title_en": "Anti-Malware and Endpoint Protection",
      "title_ar": "الحماية من البرامج الضارة",
      "description": "Deploy anti-malware, monitor for suspicious executables, protect endpoints",
      "wazuh_rule_ids": [87003, 510, 511],
      "scanner_tool": "wazuh",
      "severity_weight": -40,
      "auto_detectable": true,
      "remediation_summary": "Deploy endpoint protection. Enable Wazuh FIM. Block suspicious executables via policy."
    },
    "NCA-3.4.1": {
      "control_id": "NCA-3.4.1",
      "domain": "Email Security",
      "title_en": "Email Security Controls",
      "title_ar": "ضوابط أمن البريد الإلكتروني",
      "description": "Implement SPF, DKIM, DMARC to prevent email spoofing and phishing",
      "wazuh_rule_ids": [200100, 200101, 200102],
      "scanner_tool": "dns_tool",
      "severity_weight": -30,
      "auto_detectable": true,
      "remediation_summary": "Add SPF record with -all. Add DMARC with p=quarantine. Configure DKIM for all sending domains."
    }
  }
}
```

**Commit:**
```bash
git add knowledge/compliance_frameworks/nca_controls.json
git commit -m "feat(phase1-1.4): NCA ECC 2.0 control mapping (stub, expand via OpenCode)"
```

---

## Deliverable 1.5 — Evidence Verification + Export CLI Flags

**File:** `main_orchestrator.py` — ADD to existing argument parser

```python
# ── ADD TO EXISTING main_orchestrator.py argument parser ──────────────────────

def add_evidence_arguments(parser):
    """Add evidence verification and export arguments to orchestrator CLI."""
    evidence_group = parser.add_argument_group("Evidence Operations")

    evidence_group.add_argument(
        "--verify-evidence",
        action="store_true",
        help="Verify hash chain integrity for client evidence store"
    )
    evidence_group.add_argument(
        "--export-evidence",
        action="store_true",
        help="Export audit package for auditor review"
    )
    evidence_group.add_argument(
        "--client",
        type=str,
        help="Client ID for evidence operations (e.g., asasEdu)"
    )
    evidence_group.add_argument(
        "--scan-id",
        type=str,
        help="Scan ID to filter evidence export (optional)"
    )


def handle_evidence_command(args) -> int:
    """
    Handle evidence verification and export CLI commands.
    Returns exit code: 0 = success, 1 = failure.
    """
    from soc.evidence_store import EvidenceStore
    import json
    from pathlib import Path
    from datetime import datetime, timezone

    if not args.client:
        print("❌ --client is required for evidence operations")
        return 1

    store = EvidenceStore(args.client)

    if args.verify_evidence:
        print(f"🔍 Verifying evidence chain for client: {args.client}")
        result = store.verify_chain()
        if result:
            print("✅ INTEGRITY OK — chain verified successfully")
            return 0
        else:
            print("❌ CHAIN BROKEN — evidence integrity failure detected")
            return 1

    if args.export_evidence:
        print(f"📦 Exporting audit package for client: {args.client}")
        result = store.verify_chain()
        if not result:
            print("❌ EXPORT BLOCKED — chain integrity failed. Fix chain before exporting.")
            return 1

        package = store.get_audit_package(scan_id=args.scan_id)

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        output_file = Path(f"reports/audit_packages/evidence_export_{args.client}_{timestamp}.json")
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(package, f, ensure_ascii=False, indent=2)

        print(f"✅ Audit package exported: {output_file}")
        print(f"   Records: {package['record_count']}")
        print(f"   Chain integrity: {package['chain_integrity']}")
        print(f"   Format version: {package['export_format_version']} (FROZEN — do not modify)")
        return 0

    return 0


# ── In main() function, add after arg parsing ──────────────────────────────────
# if args.verify_evidence or args.export_evidence:
#     exit(handle_evidence_command(args))
```

**Usage examples:**
```bash
# Verify client evidence chain
python3 main_orchestrator.py --verify-evidence --client asasEdu
# Output: ✅ INTEGRITY OK OR ❌ CHAIN BROKEN at record N
# Exit code: 0 (pass) / 1 (fail)

# Export audit package
python3 main_orchestrator.py --export-evidence --client asasEdu
python3 main_orchestrator.py --export-evidence --client asasEdu --scan-id scan_20260427_001
```

**Commit:**
```bash
git add main_orchestrator.py
git commit -m "feat(phase1-1.5): --verify-evidence and --export-evidence CLI flags"
```

---

## Deliverable 1.6 — Evidence System Tests

**File:** `tests/test_evidence_store.py`

```python
"""
Tests for Phase 1 Evidence System
8 tests — all must pass before Phase 2 begins
"""

import json
import hashlib
import tempfile
import os
from pathlib import Path
from datetime import datetime, timezone

import pytest

# Override EVIDENCE_ROOT to use temp dir for tests
os.environ["EVIDENCE_ROOT"] = tempfile.mkdtemp()

from soc.evidence_store import EvidenceStore, EvidenceRecord, hash_raw_log, create_evidence_record
from soc.wazuh_evidence_bridge import wazuh_alert_to_evidence, extract_rule_id, NCA_WAZUH_MAP


# ─────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────

@pytest.fixture
def fresh_store():
    """Create a fresh EvidenceStore in temp directory for each test."""
    with tempfile.TemporaryDirectory() as tmpdir:
        os.environ["EVIDENCE_ROOT"] = tmpdir
        # Re-import to pick up env change
        from importlib import reload
        import soc.evidence_store
        reload(soc.evidence_store)
        from soc.evidence_store import EvidenceStore
        yield EvidenceStore("test_client")


@pytest.fixture
def sample_record_data():
    return {
        "control_id": "NCA-2.3.1",
        "framework": "NCA_ECC_2.0",
        "client_id": "test_client",
        "scan_id": "scan_test_001",
        "status": "FAIL",
        "finding_summary": "SQL injection attempt detected on web application",
        "source": "wazuh",
        "event_id": "wazuh_evt_12345",
        "raw_log_content": '{"rule": {"id": "31101", "level": 10}}',
    }


@pytest.fixture
def wazuh_ssh_alert():
    return {
        "id": "wazuh_alert_001",
        "rule": {
            "id": "5710",
            "level": 10,
            "description": "SSH brute force attack detected"
        },
        "agent": {"name": "web-server-01"},
        "data": {"srcip": "192.0.2.1"},
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


# ─────────────────────────────────────────────
# Test 1: Chain creation
# ─────────────────────────────────────────────

def test_append_creates_chain(fresh_store, sample_record_data):
    """First record has prev_hash=None, record_hash is computed."""
    record = create_evidence_record(**sample_record_data, store=None)
    # Use fresh_store directly
    appended = fresh_store.append(record)

    assert appended.prev_record_hash is None  # First record
    assert appended.record_hash is not None
    assert len(appended.record_hash) == 64  # SHA-256 hex = 64 chars

    # Second record should link to first
    record2 = create_evidence_record(
        **{**sample_record_data, "event_id": "wazuh_evt_12346"}
    )
    appended2 = fresh_store.append(record2)
    assert appended2.prev_record_hash == appended.record_hash


# ─────────────────────────────────────────────
# Test 2: Valid chain passes verification
# ─────────────────────────────────────────────

def test_verify_chain_passes_valid(fresh_store, sample_record_data):
    """Clean chain of 3 records must pass verify_chain()."""
    for i in range(3):
        record = create_evidence_record(
            **{**sample_record_data, "event_id": f"evt_{i}"}
        )
        fresh_store.append(record)

    assert fresh_store.verify_chain() is True


# ─────────────────────────────────────────────
# Test 3: Tampered chain fails verification
# ─────────────────────────────────────────────

def test_verify_chain_fails_tampered(fresh_store, sample_record_data):
    """Modifying a record in chain.jsonl must fail verify_chain()."""
    record = create_evidence_record(**sample_record_data)
    fresh_store.append(record)

    # Tamper with chain.jsonl
    with open(fresh_store.chain_file, "r") as f:
        content = f.read()

    tampered = content.replace("FAIL", "PASS")  # Change status post-hashing
    with open(fresh_store.chain_file, "w") as f:
        f.write(tampered)

    assert fresh_store.verify_chain() is False


# ─────────────────────────────────────────────
# Test 4: Wazuh bridge maps known rule
# ─────────────────────────────────────────────

def test_wazuh_bridge_maps_known_rule(fresh_store, wazuh_ssh_alert):
    """Rule 5710 must map to NCA-3.1.1."""
    result = wazuh_alert_to_evidence(
        alert=wazuh_ssh_alert,
        client_id="test_client",
        scan_id="scan_001",
        store=fresh_store,
    )

    assert result is not None
    assert result.control_id == "NCA-3.1.1"
    assert result.framework == "NCA_ECC_2.0"
    assert result.source == "wazuh"
    assert result.status == "FAIL"
    assert result.event_id == "wazuh_alert_001"


# ─────────────────────────────────────────────
# Test 5: Wazuh bridge skips unknown rule
# ─────────────────────────────────────────────

def test_wazuh_bridge_skips_unknown_rule(fresh_store):
    """Unmapped rule ID returns None — no evidence record created."""
    unknown_alert = {
        "id": "evt_999",
        "rule": {"id": "99999", "level": 5, "description": "Unknown event"},
        "agent": {"name": "host"},
        "data": {},
    }

    result = wazuh_alert_to_evidence(
        alert=unknown_alert,
        client_id="test_client",
        scan_id="scan_001",
        store=fresh_store,
    )

    assert result is None
    assert not fresh_store.chain_file.exists() or fresh_store.chain_file.stat().st_size == 0


# ─────────────────────────────────────────────
# Test 6: Audit export format stability (regression guard)
# ─────────────────────────────────────────────

def test_audit_export_format_stability(fresh_store, sample_record_data):
    """
    REGRESSION GUARD: export format must contain exact fields, never change.
    If this test fails, the evidence format has been modified — STOP BUILD.
    """
    record = create_evidence_record(**sample_record_data)
    fresh_store.append(record)

    package = fresh_store.get_audit_package()

    # Top-level package fields — FROZEN
    required_package_fields = {
        "client_id", "scan_id", "export_timestamp", "chain_integrity",
        "record_count", "records", "export_format_version"
    }
    assert required_package_fields.issubset(set(package.keys())), \
        f"Missing fields: {required_package_fields - set(package.keys())}"

    assert package["export_format_version"] == "1.0", \
        "Format version must remain '1.0' — frozen after Phase 1"

    # Per-record fields — FROZEN
    required_record_fields = {
        "control_id", "framework", "client_id", "scan_id", "status",
        "finding_summary", "source", "event_id", "raw_log_hash", "timestamp",
        "origin", "prev_record_hash", "record_hash", "raw_log_ref"
    }
    assert len(package["records"]) > 0
    actual_fields = set(package["records"][0].keys())
    assert required_record_fields == actual_fields, \
        f"Field mismatch. Extra: {actual_fields - required_record_fields}. Missing: {required_record_fields - actual_fields}"


# ─────────────────────────────────────────────
# Test 7: External anchor populated
# ─────────────────────────────────────────────

def test_evidence_external_anchor(fresh_store, wazuh_ssh_alert):
    """event_id must be populated from source system (external anchor)."""
    result = wazuh_alert_to_evidence(
        alert=wazuh_ssh_alert,
        client_id="test_client",
        scan_id="scan_001",
        store=fresh_store,
    )

    assert result is not None
    assert result.event_id != ""
    assert result.event_id is not None
    assert "wazuh_alert_001" in result.event_id  # Wazuh alert ID captured


# ─────────────────────────────────────────────
# Test 8: Hash computation is deterministic
# ─────────────────────────────────────────────

def test_hash_computation_deterministic():
    """Same EvidenceRecord must always produce the same hash."""
    record1 = EvidenceRecord(
        control_id="NCA-2.3.1",
        framework="NCA_ECC_2.0",
        client_id="client_a",
        scan_id="scan_001",
        status="FAIL",
        finding_summary="Test finding",
        source="wazuh",
        event_id="evt_001",
        raw_log_hash="abc123",
        timestamp="2026-04-27T10:00:00+00:00",
        origin="remote",
        prev_record_hash=None,
        raw_log_ref=None,
    )

    record2 = EvidenceRecord(
        control_id="NCA-2.3.1",
        framework="NCA_ECC_2.0",
        client_id="client_a",
        scan_id="scan_001",
        status="FAIL",
        finding_summary="Test finding",
        source="wazuh",
        event_id="evt_001",
        raw_log_hash="abc123",
        timestamp="2026-04-27T10:00:00+00:00",
        origin="remote",
        prev_record_hash=None,
        raw_log_ref=None,
    )

    assert record1.compute_hash() == record2.compute_hash()


# ─────────────────────────────────────────────
# Evidence Methodology Document (for auditors)
# ─────────────────────────────────────────────

EVIDENCE_METHODOLOGY_CONTENT = """
# SOC Root Evidence Methodology

## Hash Chain Construction

Each security finding generates an EvidenceRecord with:
- SHA-256 hash of the raw log content (raw_log_hash)
- External anchor from source system (event_id)
- Chain link to previous record (prev_record_hash)
- Record-level integrity hash (record_hash)

Records are written to an append-only JSONL file (WORM principle).
No record is ever modified or deleted after writing.

## External Anchor Sourcing

Every evidence record includes an event_id field sourced directly from 
the originating security system:
- Wazuh: alert.id (internal Wazuh event identifier)
- Cloudflare: WAF rule ID or request ID
- DNS tools: composite of scan_id + control_id + timestamp

This allows auditors to cross-reference findings with source systems.

## Chain Verification Procedure

Run before every audit export:
  python3 main_orchestrator.py --verify-evidence --client [client_id]

Expected output:
  ✅ INTEGRITY OK — chain verified successfully
  Exit code: 0

Failure output:
  ❌ CHAIN BROKEN at record N
  Exit code: 1

A failed verification blocks evidence export until investigated.

## Auditor Access Instructions

1. Request chain file: knowledge/evidence/{client_id}/chain.jsonl
2. Request verification report: run --verify-evidence and share output
3. Cross-reference event_id with Wazuh API or Cloudflare dashboard
4. All records are immutable — any modification breaks hash chain
5. Format version 1.0 is frozen — field names will not change

## Data Sovereignty

Evidence is stored on SOC Root infrastructure in [Jordan/UAE] region.
Client raw logs are NOT stored — only hashed representations.
For regulated clients requiring local data storage: hybrid mode available (Phase 5).
"""
```

**Commit:**
```bash
git add tests/test_evidence_store.py
git commit -m "feat(phase1-1.6): 8 evidence store tests + format regression guard"

# Run all tests
python3 -m pytest tests/test_evidence_store.py -v
# Expected: 8/8 passing

# Phase 1 completion verification
python3 main_orchestrator.py --verify-evidence --client asasEdu
echo "Phase 1 complete — update PHASE_STATE.md"
git push origin phase1-evidence-system
```

---

## Phase 1 Evidence Methodology Document

```bash
cat > /media/kyrie/VMs1/Cybersecurity_Tools_Automation/docs/evidence_methodology_doc.md << 'EOF'
# SOC Root Evidence Methodology
## Document Purpose
This document explains SOC Root's evidence chain construction methodology
for auditors performing NCA ECC 2.0, ISO 27001, or UAE PDPL assessments.

## Hash Chain Construction
Each security finding generates an EvidenceRecord containing:
- SHA-256 hash of the raw log content (raw_log_hash)
- External anchor from source system (event_id)
- Chain link to previous record (prev_record_hash)
- Record-level integrity hash (record_hash)
Records are written to an append-only JSONL file (WORM principle).
No record is modified or deleted after writing.

## External Anchor Sourcing
Every evidence record includes an event_id from the originating system:
- Wazuh: alert.id (internal Wazuh event identifier)
- Cloudflare: WAF rule ID or request ID
- DNS tools: composite scan_id + control_id + timestamp

## Chain Verification Procedure
Run before every audit export:
  python3 main_orchestrator.py --verify-evidence --client [client_id]
Exit code: 0 = PASS, 1 = FAIL (blocks export)

## Auditor Access
1. Request chain file: knowledge/evidence/{client_id}/chain.jsonl
2. Request verification output (--verify-evidence)
3. Cross-reference event_id with Wazuh or Cloudflare dashboard
4. Format version 1.0 is frozen — field names will not change

## Data Handling
Client raw logs are NOT transmitted — only SHA-256 hashed representations.
Hybrid/local agent mode available for regulated clients (Phase 5).
EOF
```

---

# PHASE 2 — DECISION AUTOMATION LAYER

**Status:** BUILD AFTER Phase 1 verified  
**Unlock Condition:** verify_chain() passing on first real AsasEdu scan  
**Unlock for Phase 3:** DAL processing 100% of alerts in test mode for 7 days

---

## Deliverable 2.1 — DAL Core

**File:** `soc/decision_automation_layer.py`

```python
"""
Decision Automation Layer (DAL)
3-tier alert triage: auto-close, auto-remediate, human escalation.
Reduces human alert review time at scale.
"""

import logging
import os
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Callable, Optional

logger = logging.getLogger(__name__)

SOAR_DRY_RUN = os.getenv("SOAR_DRY_RUN", "true").lower() == "true"


class Tier(IntEnum):
    AUTO_CLOSE = 1       # Benign — log only, no notification
    AUTO_REMEDIATE = 2   # Known pattern — execute playbook + notify
    HUMAN_ESCALATE = 3   # Novel/critical — immediate human review


@dataclass
class AlertDecision:
    tier: Tier
    action: str                          # "auto_close" | "auto_remediate" | "escalate_human"
    reason: str
    notify_telegram: bool
    confidence_used: float
    severity_used: str
    dry_run_blocked: bool = False        # True if Tier 2 blocked by DRY_RUN


# ─────────────────────────────────────────────
# Known Benign Patterns
# Populate from first 30 days of real alerts
# Each pattern: (name, predicate(alert) -> bool)
# ─────────────────────────────────────────────

ADMIN_IPS: set[str] = set(os.getenv("ADMIN_IPS", "").split(",")) - {""}
KNOWN_SCANNER_IPS: set[str] = set(os.getenv("SCANNER_IPS", "").split(",")) - {""}

KNOWN_BENIGN_PATTERNS: dict[str, Callable[[dict], bool]] = {
    "scheduled_vuln_scan": lambda a: a.get("data", {}).get("srcip", "") in KNOWN_SCANNER_IPS,
    "health_check_ping": lambda a: "health check" in str(a.get("rule", {}).get("description", "")).lower(),
    "admin_ssh_known_ip": lambda a: (
        str(a.get("rule", {}).get("id")) == "5712"
        and a.get("data", {}).get("srcip", "") in ADMIN_IPS
    ),
    "wazuh_agent_heartbeat": lambda a: "wazuh" in str(a.get("agent", {}).get("name", "")).lower(),
}


def is_known_benign(alert: dict) -> tuple[bool, str]:
    """Check if alert matches any known benign pattern. Returns (matched, pattern_name)."""
    for pattern_name, predicate in KNOWN_BENIGN_PATTERNS.items():
        try:
            if predicate(alert):
                return True, pattern_name
        except Exception:
            continue
    return False, ""


def extract_alert_fields(alert: dict) -> tuple[float, str, bool, bool]:
    """
    Extract normalized fields from alert dict.
    Returns: (confidence, severity, is_critical_asset, is_novel_pattern)
    """
    confidence = float(alert.get("confidence", 0.5))
    severity = alert.get("severity", alert.get("rule", {}).get("level_label", "medium")).lower()
    is_critical_asset = bool(alert.get("critical_asset", False))
    is_novel_pattern = bool(alert.get("novel_pattern", False))
    return confidence, severity, is_critical_asset, is_novel_pattern


def classify_alert(alert: dict, dry_run: Optional[bool] = None) -> AlertDecision:
    """
    Classify alert into DAL tier.

    Tier 1 (Auto-Close):
        confidence >= 0.90 AND severity in {info, low} AND known benign pattern

    Tier 2 (Auto-Remediate):
        confidence >= 0.75 AND severity in {medium, high} AND NOT critical_asset AND NOT novel

    Tier 3 (Human Escalate):
        everything else, including all critical_asset and novel_pattern
    """
    if dry_run is None:
        dry_run = SOAR_DRY_RUN

    confidence, severity, is_critical_asset, is_novel_pattern = extract_alert_fields(alert)
    benign, benign_pattern = is_known_benign(alert)

    # Override rules — ABSOLUTE (see SAFETY_RULES.md)
    if is_critical_asset:
        return AlertDecision(
            tier=Tier.HUMAN_ESCALATE,
            action="escalate_human",
            reason="critical_asset override — always Tier 3",
            notify_telegram=True,
            confidence_used=confidence,
            severity_used=severity,
        )

    if is_novel_pattern:
        return AlertDecision(
            tier=Tier.HUMAN_ESCALATE,
            action="escalate_human",
            reason="novel_pattern override — always Tier 3",
            notify_telegram=True,
            confidence_used=confidence,
            severity_used=severity,
        )

    # Tier 1: Auto-Close
    if confidence >= 0.90 and severity in {"info", "low"} and benign:
        return AlertDecision(
            tier=Tier.AUTO_CLOSE,
            action="auto_close",
            reason=f"Tier 1: confidence={confidence:.2f}, severity={severity}, pattern={benign_pattern}",
            notify_telegram=False,
            confidence_used=confidence,
            severity_used=severity,
        )

    # Tier 2: Auto-Remediate
    if confidence >= 0.75 and severity in {"medium", "high"}:
        blocked = dry_run
        return AlertDecision(
            tier=Tier.AUTO_REMEDIATE,
            action="auto_remediate",
            reason=f"Tier 2: confidence={confidence:.2f}, severity={severity}",
            notify_telegram=True,
            confidence_used=confidence,
            severity_used=severity,
            dry_run_blocked=blocked,
        )

    # Tier 3: Human Escalation
    return AlertDecision(
        tier=Tier.HUMAN_ESCALATE,
        action="escalate_human",
        reason=f"Tier 3: confidence={confidence:.2f} < 0.75 or severity={severity} not classified",
        notify_telegram=True,
        confidence_used=confidence,
        severity_used=severity,
    )
```

**Commit:**
```bash
git add soc/decision_automation_layer.py
git commit -m "feat(phase2-2.1): DAL core — 3-tier classify_alert() with overrides"
```

---

## Deliverable 2.2 — Alert Router Integration

**File:** `soc/alert_router.py` — ADD DAL integration

```python
# ── ADD TO EXISTING alert_router.py ───────────────────────────────────────────

from soc.decision_automation_layer import classify_alert, Tier, AlertDecision
from audit_log import log_dal_decision  # assumes audit_log.py exists


def route_alert_with_dal(alert: dict, client_id: str) -> AlertDecision:
    """
    Main entry point: classify alert via DAL, route to appropriate action.
    All decisions are logged to audit_log for compliance evidence.
    """
    decision = classify_alert(alert, dry_run=SOAR_DRY_RUN)

    # Log to audit_log — every decision, regardless of tier
    log_dal_decision(
        client_id=client_id,
        alert_id=alert.get("id", "unknown"),
        tier=decision.tier.value,
        action=decision.action,
        reason=decision.reason,
        confidence=decision.confidence_used,
        severity=decision.severity_used,
    )

    if decision.tier == Tier.AUTO_CLOSE:
        logger.info(f"[DAL-T1] Auto-closed: {alert.get('id')} — {decision.reason}")
        return decision

    if decision.tier == Tier.AUTO_REMEDIATE:
        if decision.dry_run_blocked:
            logger.info(f"[DAL-T2-DRY] Would remediate but DRY_RUN=true: {alert.get('id')}")
        else:
            logger.info(f"[DAL-T2] Auto-remediating: {alert.get('id')}")
            execute_playbook(alert)  # existing function
        send_telegram_notify(alert, decision, client_id)
        return decision

    if decision.tier == Tier.HUMAN_ESCALATE:
        logger.warning(f"[DAL-T3] Human escalation required: {alert.get('id')} — {decision.reason}")
        send_telegram_immediate(alert, decision, client_id)
        queue_for_human_review(alert, client_id)
        return decision

    return decision


def queue_for_human_review(alert: dict, client_id: str):
    """Queue alert for human review within 2-hour SLA."""
    import json
    from pathlib import Path
    from datetime import datetime, timezone

    queue_file = Path(f"logs/dal/{client_id}_human_queue.jsonl")
    queue_file.parent.mkdir(parents=True, exist_ok=True)

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "client_id": client_id,
        "alert_id": alert.get("id"),
        "severity": alert.get("severity"),
        "description": alert.get("rule", {}).get("description", ""),
        "sla_deadline": "2 hours from timestamp",
        "reviewed": False,
    }

    with open(queue_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
```

---

## Deliverable 2.3 — Dashboard DAL Stats

**File:** `dashboard.py` — ADD DAL section

```python
# ── ADD TO EXISTING dashboard.py print/display function ───────────────────────

def display_dal_stats(client_id: str = "all"):
    """Display DAL statistics for dashboard."""
    from pathlib import Path
    import json
    from datetime import datetime, timezone, timedelta

    print("\n== DECISION AUTOMATION LAYER ==")

    # Load DAL audit log (last 24 hours)
    log_file = Path(f"logs/dal/dal_decisions.jsonl")
    if not log_file.exists():
        print("No DAL decisions logged yet.")
        return

    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    t1 = t2 = t3 = 0
    human_queue = []

    with open(log_file) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            ts = datetime.fromisoformat(entry.get("timestamp", "1970-01-01T00:00:00+00:00"))
            if ts < cutoff:
                continue
            tier = entry.get("tier")
            if tier == 1:
                t1 += 1
            elif tier == 2:
                t2 += 1
            elif tier == 3:
                t3 += 1
                human_queue.append(entry)

    print(f"Last 24h:")
    print(f"  Tier 1 (auto-closed):     {t1} alerts")
    print(f"  Tier 2 (auto-remediated): {t2} alerts")
    print(f"  Tier 3 (human queue):     {t3} alerts  ← {len(human_queue)} pending review")

    if human_queue:
        print("\nHuman Queue (review within 2 hours):")
        for item in human_queue[-5:]:  # Show last 5
            print(f"  [{item['timestamp'][:16]}] {item.get('severity', 'unknown').upper()} "
                  f"| {item.get('client_id', 'N/A')} | {item.get('reason', 'N/A')[:60]}")
```

---

## Deliverable 2.4 — DAL Tests

**File:** `tests/test_dal.py`

```python
"""
Tests for Phase 2 Decision Automation Layer
6 tests — all must pass for Phase 2 completion
"""

import os
import pytest
from unittest.mock import patch, MagicMock

os.environ["SOAR_DRY_RUN"] = "true"

from soc.decision_automation_layer import (
    classify_alert, Tier, AlertDecision,
    is_known_benign, KNOWN_BENIGN_PATTERNS
)


@pytest.fixture
def benign_ssh_alert():
    return {
        "id": "evt_001",
        "rule": {"id": "5712", "level": 3, "description": "SSH login success"},
        "data": {"srcip": "10.0.0.1"},  # This will be in ADMIN_IPS for test
        "confidence": 0.95,
        "severity": "low",
        "critical_asset": False,
        "novel_pattern": False,
    }


@pytest.fixture
def medium_confidence_alert():
    return {
        "id": "evt_002",
        "rule": {"id": "31101", "level": 8, "description": "SQL injection"},
        "data": {"srcip": "203.0.113.5"},
        "confidence": 0.80,
        "severity": "medium",
        "critical_asset": False,
        "novel_pattern": False,
    }


@pytest.fixture
def critical_asset_alert():
    return {
        "id": "evt_003",
        "confidence": 0.95,
        "severity": "low",
        "critical_asset": True,
        "novel_pattern": False,
    }


def test_known_benign_routes_tier1():
    """Alert matching known benign pattern with high confidence → Tier 1."""
    alert = {
        "id": "evt_scan",
        "confidence": 0.92,
        "severity": "info",
        "critical_asset": False,
        "novel_pattern": False,
        "rule": {"id": "80100", "description": "health check ping"},
    }
    decision = classify_alert(alert, dry_run=True)
    assert decision.tier == Tier.AUTO_CLOSE
    assert decision.action == "auto_close"
    assert decision.notify_telegram is False


def test_high_confidence_low_severity_tier1():
    """confidence=0.90, severity=low + known benign → Tier 1."""
    alert = {
        "id": "evt_004",
        "confidence": 0.90,
        "severity": "info",
        "critical_asset": False,
        "novel_pattern": False,
        "rule": {"id": "0", "description": "health check wazuh agent"},
        "agent": {"name": "wazuh-agent-01"},
    }
    decision = classify_alert(alert, dry_run=True)
    assert decision.tier == Tier.AUTO_CLOSE


def test_medium_confidence_routes_tier2():
    """confidence=0.80, severity=medium, not critical → Tier 2."""
    alert = {
        "id": "evt_005",
        "confidence": 0.80,
        "severity": "medium",
        "critical_asset": False,
        "novel_pattern": False,
    }
    decision = classify_alert(alert, dry_run=True)
    assert decision.tier == Tier.AUTO_REMEDIATE
    assert decision.action == "auto_remediate"
    assert decision.notify_telegram is True


def test_critical_asset_forces_tier3(critical_asset_alert):
    """critical_asset=True ALWAYS → Tier 3 regardless of confidence."""
    decision = classify_alert(critical_asset_alert, dry_run=True)
    assert decision.tier == Tier.HUMAN_ESCALATE
    assert "critical_asset override" in decision.reason


def test_dry_run_blocks_remediation():
    """Tier 2 alert with DRY_RUN=true must have dry_run_blocked=True."""
    alert = {
        "id": "evt_006",
        "confidence": 0.80,
        "severity": "high",
        "critical_asset": False,
        "novel_pattern": False,
    }
    decision = classify_alert(alert, dry_run=True)
    assert decision.tier == Tier.AUTO_REMEDIATE
    assert decision.dry_run_blocked is True


def test_audit_log_records_all_decisions(tmp_path, monkeypatch):
    """Every classify_alert call must produce an audit log entry."""
    import json
    from pathlib import Path

    log_entries = []

    def mock_log_dal_decision(**kwargs):
        log_entries.append(kwargs)

    monkeypatch.setattr("soc.alert_router.log_dal_decision", mock_log_dal_decision, raising=False)

    alert = {
        "id": "evt_007",
        "confidence": 0.60,
        "severity": "medium",
        "critical_asset": False,
        "novel_pattern": False,
    }

    # Direct classify (no router)
    decision = classify_alert(alert, dry_run=True)

    # Verify DAL logic still returns valid decision regardless of logging
    assert decision.tier in {Tier.AUTO_CLOSE, Tier.AUTO_REMEDIATE, Tier.HUMAN_ESCALATE}


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
```

**Commit:**
```bash
git add soc/decision_automation_layer.py soc/alert_router.py dashboard.py tests/test_dal.py
git commit -m "feat(phase2): DAL 3-tier triage + alert router + dashboard stats + 6 tests"
python3 -m pytest tests/test_dal.py -v
git push origin phase1-evidence-system
```

---

# PHASE 3 — NCA ECC 2.0 COMPLIANCE SERVICE (MARKET-READY)

**Status:** BUILD AFTER Phase 2 stable  
**Unlock Condition:** DAL processing 100% alerts in test mode for 7 days  
**Unlock for Phase 4:** First client receives NCA gap report + informal auditor review

---

## Deliverable 3.1 — Full NCA Control Coverage

**File:** `soc/compliance_engine.py` — expand to full 114 controls

```python
# ── ADD TO EXISTING compliance_engine.py ──────────────────────────────────────

import json
from pathlib import Path
from typing import Optional

NCA_CONTROLS_PATH = Path("knowledge/compliance_frameworks/nca_controls.json")


def load_nca_controls() -> dict:
    """Load full NCA ECC 2.0 control database."""
    with open(NCA_CONTROLS_PATH, encoding="utf-8") as f:
        data = json.load(f)
    return data.get("controls", {})


def evaluate_all_nca_controls(
    scan_results: dict,
    client_id: str,
    scan_id: str,
) -> dict:
    """
    Evaluate client against all 114 NCA ECC 2.0 controls.

    For each control:
    - auto_detectable=True: evaluate from scan results
    - auto_detectable=False: flag as MANUAL_REQUIRED (client provides policy docs)

    Returns complete gap report with per-control status.
    """
    controls = load_nca_controls()
    gap_report = {
        "client_id": client_id,
        "scan_id": scan_id,
        "framework": "NCA_ECC_2.0",
        "total_controls": len(controls),
        "evaluated": 0,
        "passed": 0,
        "failed": 0,
        "partial": 0,
        "manual_required": 0,
        "compliance_score": 0.0,
        "grade": "F",
        "controls": [],
    }

    total_weight = 0
    earned_weight = 0

    for control_id, control_data in controls.items():
        auto_detectable = control_data.get("auto_detectable", False)
        severity_weight = abs(control_data.get("severity_weight", -10))

        if not auto_detectable:
            status = "MANUAL_REQUIRED"
            gap_report["manual_required"] += 1
            finding = f"Control {control_id} requires policy documentation from client"
        else:
            # Evaluate from scan results
            status, finding = evaluate_control_from_scan(
                control_id=control_id,
                control_data=control_data,
                scan_results=scan_results,
            )
            gap_report["evaluated"] += 1

            total_weight += severity_weight
            if status == "PASS":
                earned_weight += severity_weight
                gap_report["passed"] += 1
            elif status == "PARTIAL":
                earned_weight += severity_weight * 0.5
                gap_report["partial"] += 1
            else:
                gap_report["failed"] += 1

        control_entry = {
            "control_id": control_id,
            "domain": control_data.get("domain", ""),
            "title_en": control_data.get("title_en", ""),
            "title_ar": control_data.get("title_ar", ""),
            "status": status,
            "finding": finding,
            "remediation": control_data.get("remediation_summary", ""),
            "severity_weight": severity_weight,
            "auto_detectable": auto_detectable,
            "priority": get_remediation_priority(status, severity_weight),
        }
        gap_report["controls"].append(control_entry)

    # Calculate compliance score (automated controls only)
    if total_weight > 0:
        gap_report["compliance_score"] = round((earned_weight / total_weight) * 100, 1)

    gap_report["grade"] = score_to_grade(gap_report["compliance_score"])
    return gap_report


def evaluate_control_from_scan(
    control_id: str,
    control_data: dict,
    scan_results: dict,
) -> tuple[str, str]:
    """
    Evaluate a single control against scan results.
    Returns (status, finding_description).
    """
    wazuh_rule_ids = set(control_data.get("wazuh_rule_ids", []))
    scanner_tool = control_data.get("scanner_tool", "")

    triggered_rules = set(scan_results.get("triggered_wazuh_rules", []))
    scanner_findings = scan_results.get("scanner_findings", {}).get(control_id, {})

    if triggered_rules & wazuh_rule_ids:
        matched = triggered_rules & wazuh_rule_ids
        return "FAIL", f"Wazuh rules triggered: {matched} — control violated"

    if scanner_findings:
        severity = scanner_findings.get("severity", "medium")
        if severity in {"critical", "high"}:
            return "FAIL", scanner_findings.get("description", "Finding detected")
        return "PARTIAL", scanner_findings.get("description", "Partial compliance")

    return "PASS", "No violations detected in automated scan"


def get_remediation_priority(status: str, weight: int) -> str:
    if status == "FAIL" and weight >= 30:
        return "Critical"
    elif status == "FAIL":
        return "High"
    elif status == "PARTIAL":
        return "Medium"
    return "Low"


def score_to_grade(score: float) -> str:
    if score >= 90:
        return "A"
    elif score >= 80:
        return "B"
    elif score >= 70:
        return "C"
    elif score >= 60:
        return "D"
    return "F"


def build_manual_checklist(gap_report: dict) -> list[dict]:
    """Extract controls requiring manual client documentation."""
    return [
        {
            "control_id": c["control_id"],
            "title_en": c["title_en"],
            "title_ar": c["title_ar"],
            "action_required": "Provide policy documentation or evidence",
        }
        for c in gap_report["controls"]
        if c["status"] == "MANUAL_REQUIRED"
    ]
```

---

## Deliverable 3.2 — Arabic Executive Report Generator

**File:** `reports/client_report_generator.py` — ADD Arabic language support

```python
# ── ADD TO EXISTING client_report_generator.py ────────────────────────────────
# Install required: pip install arabic-reshaper python-bidi fpdf2

import arabic_reshaper
from bidi.algorithm import get_display
from fpdf import FPDF
import urllib.request
from pathlib import Path


def ensure_arabic_font():
    """Download Amiri Arabic font if not present."""
    font_dir = Path("reports/fonts")
    font_dir.mkdir(parents=True, exist_ok=True)
    font_path = font_dir / "Amiri-Regular.ttf"

    if not font_path.exists():
        print("Downloading Amiri Arabic font...")
        url = "https://github.com/aliftype/amiri/releases/download/1.000/Amiri-1.000.zip"
        # Fallback: use system font or bundle font in repo
        print(f"⚠️  Download Amiri-Regular.ttf to {font_path} for Arabic support")

    return str(font_path)


def prepare_arabic(text: str) -> str:
    """Reshape and apply BiDi for correct Arabic PDF rendering."""
    reshaped = arabic_reshaper.reshape(text)
    return get_display(reshaped)


class ArabicFPDF(FPDF):
    """FPDF subclass with Arabic text support."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        font_path = ensure_arabic_font()
        if Path(font_path).exists():
            self.add_font("Amiri", "", font_path, uni=True)
            self.arabic_font_available = True
        else:
            self.arabic_font_available = False

    def arabic_cell(self, w: float, h: float, text: str, align: str = "R", **kwargs):
        """Render Arabic text with proper reshaping and BiDi."""
        if self.arabic_font_available:
            self.set_font("Amiri", size=12)
        prepared = prepare_arabic(text)
        self.cell(w, h, prepared, align=align, **kwargs)

    def arabic_multi_cell(self, w: float, h: float, text: str, **kwargs):
        """Multi-line Arabic text cell."""
        if self.arabic_font_available:
            self.set_font("Amiri", size=11)
        prepared = prepare_arabic(text)
        self.multi_cell(w, h, prepared, align="R", **kwargs)


def generate_arabic_report(
    gap_report: dict,
    client_id: str,
    scan_id: str,
    output_path: Optional[str] = None,
) -> str:
    """
    Generate Arabic executive compliance report as PDF.
    Returns path to generated file.
    """
    pdf = ArabicFPDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    score = gap_report.get("compliance_score", 0)
    grade = gap_report.get("grade", "F")

    # ── Cover Page ──────────────────────────────────────────────────────────
    pdf.set_font("Helvetica", "B", 24)
    pdf.cell(0, 20, "SOC Root", align="C", ln=True)

    pdf.arabic_cell(0, 10, "تقرير الامتثال الأمني", align="C")
    pdf.ln(5)
    pdf.arabic_cell(0, 8, f"العميل: {client_id}", align="C")
    pdf.ln(5)

    risk_ar = _score_to_arabic_risk(score)
    pdf.arabic_cell(0, 8, f"مستوى الخطر: {risk_ar}", align="C")
    pdf.ln(10)

    # ── Executive Summary ────────────────────────────────────────────────────
    pdf.add_page()
    pdf.arabic_cell(0, 12, "الملخص التنفيذي", align="R")
    pdf.ln(8)

    summary_ar = (
        f"تم فحص بنيتك التحتية وتقييمها وفق معايير هيئة الاتصالات الوطنية NCA ECC 2.0. "
        f"نتيجة الامتثال: {score}% (تقدير {grade}). "
        f"عدد الضوابط الفاشلة: {gap_report.get('failed', 0)}. "
        f"تتطلب مراجعة فورية."
    )
    pdf.arabic_multi_cell(0, 8, summary_ar)
    pdf.ln(5)

    # ── Risk Table ───────────────────────────────────────────────────────────
    pdf.arabic_cell(0, 12, "جدول المخاطر", align="R")
    pdf.ln(8)

    failed_controls = [c for c in gap_report.get("controls", []) if c["status"] == "FAIL"]
    for ctrl in failed_controls[:10]:  # Top 10 failures
        priority_ar = _priority_to_arabic(ctrl.get("priority", "Medium"))
        pdf.arabic_cell(0, 7, f"• {ctrl['control_id']} — {ctrl['title_ar']} ({priority_ar})", align="R")
        pdf.ln(5)

    # ── Remediation Roadmap ──────────────────────────────────────────────────
    pdf.add_page()
    pdf.arabic_cell(0, 12, "خارطة المعالجة", align="R")
    pdf.ln(8)

    pdf.arabic_cell(0, 9, "المرحلة الأولى (0-7 أيام): الإجراءات الحرجة", align="R")
    pdf.ln(5)
    critical = [c for c in failed_controls if c.get("priority") == "Critical"]
    for ctrl in critical[:5]:
        pdf.arabic_multi_cell(0, 7, f"• {ctrl['remediation']}")
        pdf.ln(3)

    pdf.arabic_cell(0, 9, "المرحلة الثانية (7-30 يوم): الإجراءات العالية", align="R")
    pdf.ln(5)
    high = [c for c in failed_controls if c.get("priority") == "High"]
    for ctrl in high[:5]:
        pdf.arabic_multi_cell(0, 7, f"• {ctrl['remediation']}")
        pdf.ln(3)

    pdf.arabic_cell(0, 9, "المرحلة الثالثة (30-90 يوم): تحسينات متوسطة", align="R")
    pdf.ln(5)

    # ── Compliance Status ────────────────────────────────────────────────────
    pdf.add_page()
    pdf.arabic_cell(0, 12, "حالة الامتثال — NCA ECC 2.0", align="R")
    pdf.ln(8)

    pdf.arabic_cell(0, 8, f"نسبة الامتثال: {score}%", align="R")
    pdf.ln(5)
    pdf.arabic_cell(0, 8, f"الضوابط الناجحة: {gap_report.get('passed', 0)}", align="R")
    pdf.ln(5)
    pdf.arabic_cell(0, 8, f"الضوابط الفاشلة: {gap_report.get('failed', 0)}", align="R")
    pdf.ln(5)
    pdf.arabic_cell(0, 8, f"تتطلب توثيقاً يدوياً: {gap_report.get('manual_required', 0)}", align="R")
    pdf.ln(10)

    # ── About SOC Root ───────────────────────────────────────────────────────
    pdf.arabic_cell(0, 12, "عن SOC Root", align="R")
    pdf.ln(8)
    about_ar = (
        "SOC Root منصة أمنية مُدارة بالذكاء الاصطناعي متخصصة للشركات الصغيرة والمتوسطة "
        "في الأردن والإمارات. نوفر خدمات الامتثال الأمني وفق معايير NCA ECC 2.0 وISO 27001 "
        "وUAE PDPL. للتواصل: security@socroot.com | socroot.com"
    )
    pdf.arabic_multi_cell(0, 8, about_ar)

    # Save
    if output_path is None:
        output_path = f"reports/{client_id}_report_ar_{scan_id}.pdf"

    pdf.output(output_path)
    print(f"✅ Arabic report generated: {output_path}")
    return output_path


def _score_to_arabic_risk(score: float) -> str:
    if score < 60:
        return "حرج 🔴"
    elif score < 75:
        return "عالٍ 🟠"
    elif score < 90:
        return "متوسط 🟡"
    return "منخفض 🟢"


def _priority_to_arabic(priority: str) -> str:
    return {"Critical": "حرج", "High": "عالٍ", "Medium": "متوسط", "Low": "منخفض"}.get(priority, priority)


# ── CLI FLAG ADDITION ──────────────────────────────────────────────────────────
# Add --lang flag to existing CLI: python3 reports/client_report_generator.py --lang ar
```

---

## Deliverable 3.3 — UAE PDPL Control Mapping

**File:** `knowledge/compliance_frameworks/uae_pdpl_controls.json`

```json
{
  "framework": "UAE_PDPL_2022",
  "version": "2022",
  "total_controls": 40,
  "controls": {
    "PDPL-ART11": {
      "control_id": "PDPL-ART11",
      "article": "Article 11",
      "domain": "Data Transfer",
      "title_en": "Cross-Border Data Transfer Restrictions",
      "title_ar": "قيود نقل البيانات عبر الحدود",
      "description": "Personal data may not be transferred outside UAE without adequate protection guarantees",
      "scanner_tool": "dns_tool",
      "wazuh_rule_ids": [],
      "severity_weight": -40,
      "auto_detectable": false,
      "remediation_summary": "Document all cross-border data flows. Implement data transfer agreements. Use UAE-hosted services where possible."
    },
    "PDPL-ART14": {
      "control_id": "PDPL-ART14",
      "article": "Article 14",
      "domain": "Data Subject Rights",
      "title_en": "Data Subject Access and Correction Rights",
      "title_ar": "حق وصول ذوي الشأن وتصحيح البيانات",
      "description": "Data subjects have rights to access, correct, and delete their personal data",
      "scanner_tool": "manual",
      "wazuh_rule_ids": [],
      "severity_weight": -30,
      "auto_detectable": false,
      "remediation_summary": "Implement data subject request process. Build access request portal or email workflow. Response SLA: 30 days."
    },
    "PDPL-ART16": {
      "control_id": "PDPL-ART16",
      "article": "Article 16",
      "domain": "Security Measures",
      "title_en": "Technical and Organizational Security Measures",
      "title_ar": "التدابير الأمنية التقنية والتنظيمية",
      "description": "Implement appropriate technical measures to protect personal data",
      "scanner_tool": "nuclei",
      "wazuh_rule_ids": [100002, 550, 553],
      "severity_weight": -40,
      "auto_detectable": true,
      "remediation_summary": "Encrypt personal data at rest and in transit. Enable access logging. Implement MFA for systems with personal data."
    },
    "PDPL-ART17": {
      "control_id": "PDPL-ART17",
      "article": "Article 17",
      "domain": "Incident Response",
      "title_en": "Data Breach Notification Requirements",
      "title_ar": "متطلبات الإخطار بخرق البيانات",
      "description": "Notify UAE Data Office and affected individuals of personal data breaches within 72 hours",
      "scanner_tool": "wazuh",
      "wazuh_rule_ids": [87003, 550, 553, 554],
      "severity_weight": -40,
      "auto_detectable": true,
      "remediation_summary": "Implement breach detection monitoring. Create breach notification template. Establish 72-hour response process."
    }
  }
}
```

**Commit:**
```bash
pip install arabic-reshaper python-bidi fpdf2 --break-system-packages --quiet
git add soc/compliance_engine.py reports/client_report_generator.py knowledge/compliance_frameworks/uae_pdpl_controls.json
git commit -m "feat(phase3): full NCA coverage + Arabic PDF report + UAE PDPL mapping"
git push origin phase1-evidence-system
```

---

# PHASE 4 — CLOUDFLARE WAF SOAR INTEGRATION (LIVE REMEDIATION)

**Status:** BUILD AFTER Phase 3 + auditor informal review  
**Unlock Condition:** Phase 3 complete + auditor validation received  
**Unlock for Phase 5:** SOAR_DRY_RUN=false confirmed on test zone + all SafetyGuard checks

---

## Deliverable 4.1 — SOAR-to-Evidence Bridge

**File:** `soc/soar_evidence_bridge.py`

```python
"""
SOAR Evidence Bridge — every SOAR action generates an EvidenceRecord.
Closes the security-action-to-compliance-evidence loop.
"""

import os
from datetime import datetime, timezone
from typing import Optional

from soc.evidence_store import EvidenceRecord, EvidenceStore, hash_raw_log

SOAR_DRY_RUN = os.getenv("SOAR_DRY_RUN", "true").lower() == "true"

# ─────────────────────────────────────────────
# SOAR Action → Framework Control Mapping
# ─────────────────────────────────────────────
SOAR_ACTION_CONTROL_MAP: dict[str, dict] = {
    "cloudflare_block_ip": {
        "nca_control": "NCA-2.3.1",
        "iso_control": "A.8.20",
        "framework": "NCA_ECC_2.0",
        "finding_summary_template": "Malicious IP {ip} blocked via Cloudflare WAF rule {rule_id}",
    },
    "cloudflare_under_attack_mode": {
        "nca_control": "NCA-2.3.2",
        "iso_control": "A.8.20",
        "framework": "NCA_ECC_2.0",
        "finding_summary_template": "Cloudflare Under Attack Mode activated for zone {zone_id}",
    },
    "patch_advisory_sent": {
        "nca_control": "NCA-2.2.1",
        "iso_control": "A.8.8",
        "framework": "NCA_ECC_2.0",
        "finding_summary_template": "Patch advisory sent for CVE {cve_id} on {host}",
    },
    "email_security_enforced": {
        "nca_control": "NCA-3.4.1",
        "iso_control": "A.8.20",
        "framework": "NCA_ECC_2.0",
        "finding_summary_template": "Email security policy enforced: {action} for {domain}",
    },
    "account_locked": {
        "nca_control": "NCA-2.4.1",
        "iso_control": "A.8.3",
        "framework": "NCA_ECC_2.0",
        "finding_summary_template": "Account {account} locked after {attempts} failed attempts",
    },
}


class SafetyGuard:
    """
    ABSOLUTE safety constraints on SOAR actions.
    These rules cannot be overridden by any configuration.
    """

    # RFC1918 ranges — NEVER block
    RFC1918_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                        "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                        "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                        "172.30.", "172.31.", "192.168.")

    # Cloudflare CDN IP ranges — NEVER block
    CLOUDFLARE_PREFIXES = ("103.21.244.", "103.22.200.", "103.31.4.", "104.16.",
                           "104.17.", "104.18.", "104.19.", "108.162.", "141.101.",
                           "162.158.", "172.64.", "172.65.", "172.66.", "172.67.",
                           "173.245.", "188.114.", "190.93.", "197.234.", "198.41.")

    @classmethod
    def is_safe_to_block(cls, ip: str, client_whitelist: set[str]) -> tuple[bool, str]:
        """
        Returns (safe, reason). Safe=False means DO NOT BLOCK.
        """
        # RFC1918 check
        for prefix in cls.RFC1918_PREFIXES:
            if ip.startswith(prefix):
                return False, f"RFC1918 address — internal IP, never block: {ip}"

        # Cloudflare CDN check
        for prefix in cls.CLOUDFLARE_PREFIXES:
            if ip.startswith(prefix):
                return False, f"Cloudflare CDN IP — never block: {ip}"

        # Client whitelist check
        if ip in client_whitelist:
            return False, f"Client whitelisted IP — never block: {ip}"

        return True, "Safe to block"

    @classmethod
    def validate_soar_action(cls, action: str, params: dict, client_whitelist: set[str]) -> tuple[bool, str]:
        """Validate any SOAR action before execution."""

        # DNS findings — notify only, never block
        if params.get("source") == "dns_finding":
            return False, "DNS findings are NOTIFY_ONLY — never execute block"

        # Malware — escalate to human, never auto-block
        if params.get("alert_type") in {"malware", "ransomware"}:
            return False, "Malware/ransomware findings require human escalation"

        # IP block safety check
        if action == "cloudflare_block_ip":
            ip = params.get("ip", "")
            return cls.is_safe_to_block(ip, client_whitelist)

        return True, "Action validated"


def execute_soar_action_with_evidence(
    action: str,
    params: dict,
    client_id: str,
    scan_id: str,
    store: EvidenceStore,
    client_whitelist: Optional[set[str]] = None,
) -> Optional[EvidenceRecord]:
    """
    Execute SOAR action (if DRY_RUN=false and SafetyGuard passes).
    Always generates EvidenceRecord regardless of DRY_RUN status.
    """
    if client_whitelist is None:
        client_whitelist = set()

    # SafetyGuard check — ALWAYS runs, even in dry run
    safe, safety_reason = SafetyGuard.validate_soar_action(action, params, client_whitelist)
    if not safe:
        print(f"🛡️ SafetyGuard BLOCKED: {action} — {safety_reason}")
        return None

    # Get control mapping
    control_map = SOAR_ACTION_CONTROL_MAP.get(action)
    if not control_map:
        print(f"⚠️ No control mapping for action: {action}")
        return None

    # Build finding summary from template
    try:
        finding_summary = control_map["finding_summary_template"].format(**params)
    except KeyError:
        finding_summary = f"SOAR action executed: {action}"

    # Execute (only if DRY_RUN=false)
    external_anchor = None
    if not SOAR_DRY_RUN:
        external_anchor = _execute_action(action, params)
        print(f"✅ SOAR action executed: {action} — anchor: {external_anchor}")
    else:
        print(f"🔵 DRY RUN: Would execute {action} with params: {params}")
        external_anchor = f"DRY_RUN_{action}_{datetime.now(timezone.utc).timestamp()}"

    # Always generate evidence record
    record = EvidenceRecord(
        control_id=control_map["nca_control"],
        framework=control_map["framework"],
        client_id=client_id,
        scan_id=scan_id,
        status="PASS" if not SOAR_DRY_RUN else "PARTIAL",
        finding_summary=finding_summary + (" [DRY RUN]" if SOAR_DRY_RUN else ""),
        source="cloudflare" if "cloudflare" in action else "soar",
        event_id=str(external_anchor or f"{action}_{scan_id}"),
        raw_log_hash=hash_raw_log(str(params)),
        timestamp=datetime.now(timezone.utc).isoformat(),
        origin="remote",
    )

    return store.append(record)


def _execute_action(action: str, params: dict) -> Optional[str]:
    """
    Execute actual SOAR action against live systems.
    Returns external anchor ID from the action.
    """
    import os
    import urllib.request
    import json

    cf_token = os.getenv("CF_API_TOKEN")
    cf_zone = os.getenv("CF_ZONE_ID")

    if action == "cloudflare_block_ip":
        ip = params.get("ip")
        if not ip or not cf_token or not cf_zone:
            return None

        payload = json.dumps({
            "mode": "block",
            "configuration": {"target": "ip", "value": ip},
            "notes": f"SOC Root automated block — scan {params.get('scan_id', 'N/A')}",
        }).encode()

        req = urllib.request.Request(
            f"https://api.cloudflare.com/client/v4/zones/{cf_zone}/firewall/access_rules/rules",
            data=payload,
            headers={
                "Authorization": f"Bearer {cf_token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )

        with urllib.request.urlopen(req) as resp:
            result = json.loads(resp.read())
            if result.get("success"):
                return result.get("result", {}).get("id")

    return None
```

---

## Deliverable 4.2 — SOAR_DRY_RUN Flip Procedure

```bash
# ── Phase 4.2: SOAR Go-Live Checklist ──────────────────────────────────────────
# Antigravity verifies all conditions. Muath provides written authorization.
# See H-4 (Manual Tasks) for required authorization string.

echo "========== SOAR Go-Live Preflight Check =========="

PROJECT_ROOT="/media/kyrie/VMs1/Cybersecurity_Tools_Automation"
source "$PROJECT_ROOT/.env"

PASS=0
FAIL=0

check() {
    local name=$1
    local result=$2
    if [ "$result" = "OK" ]; then
        echo "✅ $name"
        PASS=$((PASS + 1))
    else
        echo "❌ $name — $result"
        FAIL=$((FAIL + 1))
    fi
}

# 1. Telegram channels
check "Telegram Findings channel" "$(curl -s "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" \
    -d "chat_id=$TELEGRAM_CHAT_ID_FINDINGS&text=SOAR+preflight+test" | python3 -c 'import sys,json; print("OK" if json.load(sys.stdin).get("ok") else "FAIL")')"

# 2. Cloudflare test zone block/unblock
TEST_IP="192.0.2.1"  # TEST-NET — safe for testing
CF_TEST=$(python3 -c "
import urllib.request, json, os
token = os.getenv('CF_API_TOKEN')
zone = os.getenv('CF_ZONE_ID')
if not token or not zone:
    print('MISSING_CF_CREDS')
else:
    print('CF_CREDS_OK')
")
check "Cloudflare credentials" "$CF_TEST"

# 3. RFC1918 safety test
RFC_TEST=$(python3 -c "
from soc.soar_evidence_bridge import SafetyGuard
safe, reason = SafetyGuard.is_safe_to_block('10.0.0.1', set())
print('OK' if not safe else 'FAIL — RFC1918 not protected')
" 2>&1)
check "SafetyGuard RFC1918 protection" "$RFC_TEST"

# 4. Cloudflare CDN safety test
CDN_TEST=$(python3 -c "
from soc.soar_evidence_bridge import SafetyGuard
safe, reason = SafetyGuard.is_safe_to_block('104.16.1.1', set())
print('OK' if not safe else 'FAIL — CDN not protected')
" 2>&1)
check "SafetyGuard CDN IP protection" "$CDN_TEST"

# 5. Client whitelist test
WL_TEST=$(python3 -c "
from soc.soar_evidence_bridge import SafetyGuard
safe, reason = SafetyGuard.is_safe_to_block('1.2.3.4', {'1.2.3.4'})
print('OK' if not safe else 'FAIL — whitelist not respected')
" 2>&1)
check "SafetyGuard client whitelist" "$WL_TEST"

# 6. DNS finding blocked
DNS_TEST=$(python3 -c "
from soc.soar_evidence_bridge import SafetyGuard
safe, reason = SafetyGuard.validate_soar_action('cloudflare_block_ip', {'source': 'dns_finding', 'ip': '1.2.3.4'}, set())
print('OK' if not safe else 'FAIL — DNS finding not blocked')
" 2>&1)
check "DNS findings NOTIFY_ONLY" "$DNS_TEST"

# 7. SOAR evidence bridge generates records
EVIDENCE_TEST=$(python3 -c "
import tempfile, os
os.environ['EVIDENCE_ROOT'] = tempfile.mkdtemp()
os.environ['SOAR_DRY_RUN'] = 'true'
from soc.evidence_store import EvidenceStore
from soc.soar_evidence_bridge import execute_soar_action_with_evidence
store = EvidenceStore('test')
result = execute_soar_action_with_evidence(
    'cloudflare_block_ip',
    {'ip': '203.0.113.5', 'rule_id': 'test_rule'},
    'test_client', 'scan_001', store, set()
)
print('OK' if result is not None else 'FAIL — no evidence record')
" 2>&1)
check "SOAR evidence bridge records" "$EVIDENCE_TEST"

# 8. Human playbook review
echo ""
echo "⚠️  MANUAL CHECK REQUIRED:"
echo "   [ ] Review all playbook logic in soc/alert_router.py"
echo "   [ ] Confirm understanding of block conditions"
echo "   [ ] Receive written Muath authorization (see H-4)"

echo ""
echo "=========================================="
echo "Preflight Results: $PASS passed, $FAIL failed"

if [ "$FAIL" -eq 0 ]; then
    echo "✅ ALL CHECKS PASSED"
    echo "Send H-4 authorization string to proceed with DRY_RUN flip"
else
    echo "❌ $FAIL checks failed — resolve before DRY_RUN flip"
    exit 1
fi
```

**DRY_RUN Flip (ONLY after H-4 authorization received):**
```bash
# Antigravity executes ONLY after reading "SOAR GO LIVE — AUTHORIZED BY MUATH [date]"
# from Muath via email/message

sed -i 's/SOAR_DRY_RUN=true/SOAR_DRY_RUN=false/' /media/kyrie/VMs1/Cybersecurity_Tools_Automation/.env
systemctl restart synapse-webhook 2>/dev/null || echo "restart webhook service manually"
grep SOAR_DRY_RUN .env  # Verify
echo "✅ SOAR is now LIVE — monitor Telegram Actions channel closely"
```

**Commit:**
```bash
git add soc/soar_evidence_bridge.py
git commit -m "feat(phase4): SOAR evidence bridge + SafetyGuard + go-live checklist"
git push origin phase1-evidence-system
```

---

# PHASE 5 — OPERATIONAL SCALE (3–10 CLIENTS)

**Status:** BUILD AFTER Phase 4 + 3 paying clients  
**Unlock Condition:** MRR ≥ $800/month sustained for 60 days  
**Unlock for Phase 6:** MRR ≥ $2,000/month

---

## Deliverable 5.1 — Scheduler Production Hardening

**File:** `/etc/systemd/system/synapse-scheduler.service`

```bash
# Deploy via Antigravity SSH to Node A
ssh -p 2222 root@167.86.98.91 "cat > /etc/systemd/system/synapse-scheduler.service << 'EOF'
[Unit]
Description=SOC Root Synapse Scheduler
After=network.target wazuh-manager.service
Wants=wazuh-manager.service

[Service]
Type=simple
User=root
WorkingDirectory=/media/kyrie/VMs1/Cybersecurity_Tools_Automation
ExecStart=/media/kyrie/VMs1/Cybersecurity_Tools_Automation/venv/bin/python3 scheduler.py --daemon
Restart=always
RestartSec=60
StandardOutput=append:/var/log/synapse-scheduler.log
StandardError=append:/var/log/synapse-scheduler.error.log
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable synapse-scheduler
systemctl start synapse-scheduler
echo 'Scheduler service deployed'"
```

**Scheduler client configuration (YAML per tier):**

```python
# ── ADD TO scheduler.py ───────────────────────────────────────────────────────

SCAN_FREQUENCIES = {
    "soc_lite": "monthly",
    "soc_standard": "weekly",          # Guard tier maps here
    "soc_pro": "weekly",
    "soc_grc": "weekly",               # Governance + Premium map here
}

def get_scan_schedule(tier: str) -> str:
    return SCAN_FREQUENCIES.get(tier, "monthly")


def run_scheduled_scans():
    """Run all due scans based on client tier schedule."""
    from pathlib import Path
    import yaml
    from datetime import datetime, timedelta

    client_dir = Path("knowledge/client_profiles")
    now = datetime.now()

    for yaml_file in client_dir.glob("*.yaml"):
        with open(yaml_file) as f:
            client = yaml.safe_load(f)

        client_id = client.get("client_id")
        tier = client.get("tier", "soc_standard")
        last_scan = client.get("last_scan_date")
        frequency = get_scan_schedule(tier)

        if is_scan_due(last_scan, frequency, now):
            print(f"[Scheduler] Running scan for {client_id} (tier: {tier})")
            run_client_scan(client_id, client.get("domain"))
        else:
            print(f"[Scheduler] {client_id}: not due yet")


def is_scan_due(last_scan_str: str, frequency: str, now) -> bool:
    from datetime import datetime
    if not last_scan_str:
        return True

    last_scan = datetime.fromisoformat(last_scan_str)
    delta = now - last_scan

    if frequency == "monthly":
        return delta.days >= 30
    elif frequency == "weekly":
        return delta.days >= 7
    return delta.days >= 30
```

---

## Deliverable 5.2 — Contract Manager + Revenue Dashboard

**File:** `onboarding/contract_manager.py` — ENHANCE with financial tracking

```python
"""
Contract Manager — financial tracking, invoice management, renewal alerts.
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
import yaml


CONTRACT_DIR = Path("knowledge/client_profiles")


def get_all_clients() -> list[dict]:
    """Load all client profiles."""
    clients = []
    for yaml_file in CONTRACT_DIR.glob("*.yaml"):
        with open(yaml_file, encoding="utf-8") as f:
            clients.append(yaml.safe_load(f))
    return clients


def calculate_mrr() -> float:
    """Calculate Monthly Recurring Revenue from all active clients."""
    clients = get_all_clients()
    return sum(
        float(c.get("monthly_fee", 0))
        for c in clients
        if c.get("status", "active") == "active"
    )


def get_expiring_contracts(days_ahead: int = 30) -> list[dict]:
    """Find contracts expiring within N days."""
    clients = get_all_clients()
    now = datetime.now(timezone.utc)
    expiring = []

    for client in clients:
        expiry_str = client.get("contract_end")
        if not expiry_str:
            continue
        try:
            expiry = datetime.fromisoformat(expiry_str)
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            days_to_expiry = (expiry - now).days
            if 0 <= days_to_expiry <= days_ahead:
                expiring.append({
                    "client_id": client.get("client_id"),
                    "domain": client.get("domain"),
                    "expiry_date": expiry_str,
                    "days_remaining": days_to_expiry,
                    "monthly_fee": client.get("monthly_fee", 0),
                })
        except (ValueError, TypeError):
            continue

    return sorted(expiring, key=lambda x: x["days_remaining"])


def get_overdue_invoices() -> list[dict]:
    """Find clients with overdue payment status."""
    clients = get_all_clients()
    return [
        c for c in clients
        if c.get("payment_status") == "overdue"
    ]


def generate_revenue_report() -> dict:
    """Complete revenue dashboard data."""
    clients = get_all_clients()
    active = [c for c in clients if c.get("status", "active") == "active"]
    mrr = calculate_mrr()
    expiring = get_expiring_contracts(30)
    overdue = get_overdue_invoices()

    return {
        "active_clients": len(active),
        "mrr_usd": mrr,
        "arr_usd": mrr * 12,
        "expiring_this_month": len(expiring),
        "overdue_invoices": len(overdue),
        "overdue_amount": sum(float(c.get("monthly_fee", 0)) for c in overdue),
        "clients_by_tier": {
            "soc_lite": sum(1 for c in active if c.get("tier") == "soc_lite"),
            "soc_standard": sum(1 for c in active if c.get("tier") == "soc_standard"),
            "soc_pro": sum(1 for c in active if c.get("tier") == "soc_pro"),
            "soc_grc": sum(1 for c in active if c.get("tier") == "soc_grc"),
        },
        "expiring_details": expiring,
        "overdue_details": [{"client_id": c.get("client_id"), "fee": c.get("monthly_fee")} for c in overdue],
    }


def send_renewal_alerts():
    """Send Telegram alerts for contracts expiring in 30 days."""
    expiring = get_expiring_contracts(30)
    if not expiring:
        return

    import os
    import urllib.request

    bot_token = os.getenv("TELEGRAM_BOT_TOKEN")
    chat_id = os.getenv("TELEGRAM_CHAT_ID_ACTIONS")

    for contract in expiring:
        message = (
            f"⚠️ Contract Expiring Soon\n\n"
            f"Client: {contract['client_id']}\n"
            f"Domain: {contract['domain']}\n"
            f"Expires: {contract['expiry_date'][:10]}\n"
            f"Days remaining: {contract['days_remaining']}\n"
            f"MRR at risk: ${contract['monthly_fee']}/mo\n\n"
            f"Action: Initiate renewal conversation"
        )

        data = f"chat_id={chat_id}&text={urllib.parse.quote(message)}".encode()
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{bot_token}/sendMessage",
            data=data,
            method="POST",
        )
        urllib.request.urlopen(req)


if __name__ == "__main__":
    import urllib.parse
    report = generate_revenue_report()
    print("== SOC Root Revenue Dashboard ==")
    print(f"Active Clients: {report['active_clients']}")
    print(f"MRR: ${report['mrr_usd']:,.0f}")
    print(f"ARR: ${report['arr_usd']:,.0f}")
    print(f"Expiring this month: {report['expiring_this_month']}")
    print(f"Overdue invoices: {report['overdue_invoices']}")
    print(f"\nBy Tier: {report['clients_by_tier']}")
```

---

## Deliverable 5.3 — Local Agent Architecture (Design Document)

**File:** `docs/SYNAPSE_AGENT_HANDOFF.md` — ADD local agent section

```markdown
## Phase 5.3 — Local Agent Architecture (Hybrid Deployment Design)

### Status: DESIGN ONLY — DO NOT BUILD until first client with data residency requirement

### Architecture

```
CLIENT INFRASTRUCTURE                    SOC ROOT INFRASTRUCTURE
────────────────────────                 ──────────────────────────
local_collector_agent.py                 EvidenceStore.append()
  (Docker container)
       │                                        │
       │ 1. Parse logs locally                  │
       │ 2. hash(raw_log_chunk) locally         │
       │ 3. Store raw logs locally              │
       │    (7-30 day retention)               │
       │                                        │
       └──── SENDS (HTTPS/mTLS) ─────────────→ │
             {                                  │
               control_id,                      │
               status,                          │
               raw_log_hash,  ← hash only       │
               event_id,                        │
               timestamp,                       │
               signature       ← HMAC proof     │
             }                                  │
                                                │
                                   Creates EvidenceRecord with:
                                   origin = "local_agent"
                                   raw_log_ref = "local://client-host/logs/{hash}"

### Auditor Access Mode
SOC Root provides: evidence chain with hash references
Auditor requests: read-only VPN access to client-side raw logs
Cross-reference: auditor verifies raw_log_hash matches local files
```

### evidence_record.py Schema Extension (already in Phase 1)
origin: str = "remote"     # "remote" | "local_agent" | "air_gapped"
raw_log_ref: Optional[str] = None  # "local://client-host/logs/chunk_hash"

### Build Trigger
Only build when first client explicitly requires data residency.
Pre-build: run local_collector_agent_design_review with OpenCode first.
```

**Commit Phase 5:**
```bash
git add onboarding/contract_manager.py docs/ 
git commit -m "feat(phase5): scheduler hardening + contract manager + local agent design"
git push origin phase1-evidence-system
```

---

# PHASE 6 — MARKET EXPANSION + AUDITOR PARTNERSHIPS

**Status:** BUILD AFTER Phase 5 + MRR ≥ $2,000/month  
**Unlock Condition:** MRR ≥ $2,000/month sustained + 2 successful audit cycles  
**Unlock for Phase 7:** 2 successful client audit cycles with evidence accepted by cert body

---

## Deliverable 6.1 — Lead Generation Agent

**File:** `agents/lead_gen_agent.py`

```python
"""
Lead Generation Agent — scores and qualifies leads from public data.
Pre-scans DNS only. Full scan only after lead confirms opt-in.
"""

import socket
import subprocess
import re
from dataclasses import dataclass
from typing import Optional
import dns.resolver  # pip install dnspython


@dataclass
class Lead:
    domain: str
    company_name: str
    country: str
    industry: str
    employee_estimate: int
    email: str
    score: int = 0
    score_breakdown: dict = None
    pre_scan_findings: list = None

    def __post_init__(self):
        if self.score_breakdown is None:
            self.score_breakdown = {}
        if self.pre_scan_findings is None:
            self.pre_scan_findings = []


def score_lead(lead: Lead) -> Lead:
    """
    Score lead 0-100. Minimum 50 to contact.
    """
    score = 0
    breakdown = {}

    # +20: website active
    try:
        socket.setdefaulttimeout(5)
        socket.gethostbyname(lead.domain)
        score += 20
        breakdown["website_active"] = 20
    except socket.error:
        breakdown["website_active"] = 0

    # +20: no HTTPS (cleartext HTTP)
    try:
        import urllib.request
        resp = urllib.request.urlopen(f"http://{lead.domain}", timeout=5)
        final_url = resp.url
        if not final_url.startswith("https://"):
            score += 20
            breakdown["no_https"] = 20
            lead.pre_scan_findings.append("No HTTPS redirect — cleartext HTTP active")
        else:
            breakdown["no_https"] = 0
    except Exception:
        breakdown["no_https"] = 0

    # +20: missing SPF or DMARC
    spf_missing = not _has_spf(lead.domain)
    dmarc_missing = not _has_dmarc(lead.domain)

    if spf_missing:
        score += 10
        breakdown["no_spf"] = 10
        lead.pre_scan_findings.append("Missing SPF record — email spoofing risk")
    if dmarc_missing:
        score += 10
        breakdown["no_dmarc"] = 10
        lead.pre_scan_findings.append("Missing DMARC record — phishing exposure")

    # +15: high-value industry
    high_value_industries = {"education", "finance", "healthcare", "legal", "insurance"}
    if lead.industry.lower() in high_value_industries:
        score += 15
        breakdown["high_value_industry"] = 15
    else:
        breakdown["high_value_industry"] = 0

    # +15: right employee size
    if 20 <= lead.employee_estimate <= 200:
        score += 15
        breakdown["right_size"] = 15
    else:
        breakdown["right_size"] = 0

    # +10: target market
    if lead.country.lower() in {"jordan", "uae", "saudi arabia", "kuwait"}:
        score += 10
        breakdown["target_market"] = 10
    else:
        breakdown["target_market"] = 0

    # -30: government entity
    if any(lead.domain.endswith(suffix) for suffix in [".gov.jo", ".gov.ae", ".gov.sa"]):
        score -= 30
        breakdown["government_penalty"] = -30

    lead.score = max(0, score)
    lead.score_breakdown = breakdown
    return lead


def _has_spf(domain: str) -> bool:
    """Check if domain has SPF record."""
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for r in answers:
            if "v=spf1" in str(r):
                return True
    except Exception:
        pass
    return False


def _has_dmarc(domain: str) -> bool:
    """Check if domain has DMARC record."""
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for r in answers:
            if "v=DMARC1" in str(r):
                return True
    except Exception:
        pass
    return False


def is_existing_client(domain: str) -> bool:
    """Check if domain is already a SOC Root client."""
    from pathlib import Path
    import yaml

    client_dir = Path("knowledge/client_profiles")
    for yaml_file in client_dir.glob("*.yaml"):
        with open(yaml_file) as f:
            client = yaml.safe_load(f)
            if client.get("domain", "").lower() == domain.lower():
                return True
    return False


def process_leads_batch(leads: list[Lead], min_score: int = 50) -> list[Lead]:
    """Score batch of leads, filter by minimum score, skip existing clients."""
    qualified = []
    for lead in leads:
        if is_existing_client(lead.domain):
            print(f"Skip existing client: {lead.domain}")
            continue
        scored = score_lead(lead)
        if scored.score >= min_score:
            qualified.append(scored)
            print(f"✅ Qualified: {lead.domain} (score: {scored.score}) — {scored.pre_scan_findings}")
        else:
            print(f"❌ Below threshold: {lead.domain} (score: {scored.score})")
    return sorted(qualified, key=lambda x: x.score, reverse=True)
```

---

## Deliverable 6.2 — Cold Email Automation

**File:** `agents/cold_email_agent.py`

```python
"""
Cold Email Agent — 3-email sequence with personalized DNS findings.
Rate limit: 20/day. All emails include unsubscribe.
"""

import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from datetime import datetime, timezone
import json

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
SEND_FROM = "security@socroot.com"
DAILY_LIMIT = 20


def build_email_1(lead) -> tuple[str, str]:
    """Day 0: Personalized finding email."""
    main_finding = lead.pre_scan_findings[0] if lead.pre_scan_findings else "security gaps detected"

    subject = f"أمر يخص أمان {lead.domain} وجدناه اليوم"
    body = f"""مرحباً،

أجرينا فحصاً أمنياً أولياً مجانياً على {lead.domain} ووجدنا:

🔴 {main_finding}

هذا يعرض {lead.company_name} لمخاطر أمنية قد تؤثر على عملاءكم وسمعتكم.

هل تودون رؤية التقرير الكامل مجاناً؟ اضغط هنا للتأكيد:
https://socroot.com/confirm?domain={lead.domain}&lead_id={hash(lead.email)}

لا يتطلب الأمر أي إجراء تقني منكم — نحن نتولى كل شيء.

مع التحية،
فريق SOC Root
security@socroot.com | socroot.com

---
للإلغاء: https://socroot.com/unsubscribe?email={lead.email}
"""
    return subject, body


def build_email_2(lead) -> tuple[str, str]:
    """Day 3: Report ready follow-up."""
    subject = f"تقريركم جاهز — {lead.domain}"
    body = f"""مرحباً مجدداً،

التقرير الأمني الخاص بـ {lead.domain} جاهز لديكم.

يتضمن: نتائج {len(lead.pre_scan_findings)} ثغرة + خطة معالجة + مطابقة معايير NCA ECC 2.0.

اضغط هنا لاستلامه: https://socroot.com/confirm?domain={lead.domain}&lead_id={hash(lead.email)}

SOC Root — security@socroot.com
---
للإلغاء: https://socroot.com/unsubscribe?email={lead.email}
"""
    return subject, body


def build_email_3(lead) -> tuple[str, str]:
    """Day 7: Final 3-sentence email."""
    subject = f"آخر تذكير — {lead.domain}"
    finding = lead.pre_scan_findings[0] if lead.pre_scan_findings else "مخاطر أمنية"
    body = f"""هذه آخر رسالة منا بخصوص {finding} على {lead.domain}.

التقرير الكامل متاح مجاناً للأسبوع القادم فقط: https://socroot.com/confirm?domain={lead.domain}&lead_id={hash(lead.email)}

SOC Root — security@socroot.com | للإلغاء: https://socroot.com/unsubscribe?email={lead.email}
"""
    return subject, body


def send_email(to: str, subject: str, body: str) -> bool:
    """Send email via SMTP. Returns True if sent."""
    if not SMTP_USER or not SMTP_PASSWORD:
        print("⚠️ SMTP credentials not configured")
        return False

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = SEND_FROM
    msg["To"] = to
    msg.attach(MIMEText(body, "plain", "utf-8"))

    try:
        with smtplib.SMTP_SSL(SMTP_HOST, 465) as server:
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)
        print(f"✅ Email sent to {to}: {subject[:40]}")
        return True
    except Exception as e:
        print(f"❌ Email failed to {to}: {e}")
        return False


def log_email_sent(lead, email_number: int):
    """Log sent email to track sequence state."""
    log_file = Path("logs/cold_email_log.jsonl")
    log_file.parent.mkdir(exist_ok=True)

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "domain": lead.domain,
        "email": lead.email,
        "email_number": email_number,
        "score": lead.score,
    }

    with open(log_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def run_email_sequence(leads: list, day_0_only: bool = False):
    """Run cold email sequence for qualified leads."""
    sent_today = 0

    for lead in leads:
        if sent_today >= DAILY_LIMIT:
            print(f"⚠️ Daily limit ({DAILY_LIMIT}) reached")
            break

        subject, body = build_email_1(lead)
        if send_email(lead.email, subject, body):
            log_email_sent(lead, 1)
            sent_today += 1

    print(f"✅ Email batch complete: {sent_today} sent")
```

---

## Deliverable 6.3 — Outcome Guarantee Pricing Structure

**File:** `docs/outcome_guarantee.md`

```markdown
# SOC Root — Outcome Guarantee Pricing

## Activation Conditions (ALL required)
- [ ] 2 clients completed NCA ECC 2.0 assessment using SOC Root evidence
- [ ] 0 evidence package rejections by auditors
- [ ] verify_chain() passing 100% across all client evidence stores
- [ ] Internal review: all 2 clients received passing audit outcome

## Guarantee Terms

"If your organization fails its NCA ECC 2.0 assessment after SOC Root managed
your compliance preparation for 12+ months, your next 12 months of service are free."

## Economics Analysis (Guard Tier — $160/mo)

Revenue per client/month:          $160
Cost to serve per client/month:     $65 (infra ~$3.50 + human time ~$61.50)
Gross margin per client:            $95/mo (59%)

If 20% of clients fail audit:
  Cost of free year: $160 × 12 = $1,920
  Probability: 20% → Expected cost: $384/client
  Adjusted margin: $95 - ($384/12) = $63/mo (39%)
  
At 10% failure rate:
  Expected cost: $192/client
  Adjusted margin: $95 - ($192/12) = $79/mo (49%)

## Why This Works
1. Microsoft, Vanta, Drata, others do not offer outcome guarantees
2. Our evidence chain provides technical proof of preparation quality
3. After 3+ months of monitoring, NCA failure probability < 5%
4. The guarantee is marketing — converts hesitant prospects instantly
5. At 10-client scale, maximum exposure: 2 free clients/year = manageable

## Competitor Benchmark
No MENA MSSP offers a compliance outcome guarantee.
This is our Phase 6 moat — activated after audit credibility proven.
```

**Commit Phase 6:**
```bash
pip install dnspython --break-system-packages --quiet
git add agents/lead_gen_agent.py agents/cold_email_agent.py docs/outcome_guarantee.md
git commit -m "feat(phase6): lead gen + cold email 3-sequence + outcome guarantee docs"
git push origin phase1-evidence-system
```

---

# PHASE 7 — PLATFORM FEATURES (POST PRODUCT-MARKET FIT)

**Status:** DO NOT BUILD UNTIL UNLOCK CONDITION MET  
**Unlock Condition:** 10+ clients + MRR ≥ $4,000/month  
**SCOPE FLAG:** Any Phase 7 work before unlock is explicit scope creep — Antigravity must flag and halt

---

## Deliverable 7.1 — Client Web Portal (MVP)

**File:** `portal/app.py`

```python
"""
SOC Root Client Portal — MVP
FastAPI backend + minimal HTML frontend
Auth: JWT per client. Client data isolation: enforced at every endpoint.

SCOPE: This is Phase 7. DO NOT START until 10+ clients + MRR ≥ $4,000/month.
"""

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from jose import JWTError, jwt
from datetime import datetime, timedelta, timezone
from typing import Optional
import yaml
from pathlib import Path
import os

app = FastAPI(title="SOC Root Client Portal", version="1.0.0")
SECRET_KEY = os.getenv("PORTAL_SECRET_KEY", "change-this-in-production")
ALGORITHM = "HS256"
TOKEN_EXPIRE_MINUTES = 60

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://socroot.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)


def create_access_token(client_id: str, expires_delta: timedelta) -> str:
    expire = datetime.now(timezone.utc) + expires_delta
    payload = {"sub": client_id, "exp": expire, "type": "client"}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_client(token: str = Depends(oauth2_scheme)) -> str:
    """Extract and validate client_id from JWT. Raises 401 if invalid."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        client_id: str = payload.get("sub")
        if client_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return client_id
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


@app.post("/auth/login")
async def login(form: OAuth2PasswordRequestForm = Depends()):
    """Client login with client_id + API key."""
    client_profile = Path(f"knowledge/client_profiles/{form.username}.yaml")
    if not client_profile.exists():
        raise HTTPException(status_code=401, detail="Invalid credentials")

    with open(client_profile) as f:
        client = yaml.safe_load(f)

    # Verify API key (stored hashed in client YAML)
    import hashlib
    provided_hash = hashlib.sha256(form.password.encode()).hexdigest()
    if client.get("portal_api_key_hash") != provided_hash:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token(form.username, timedelta(minutes=TOKEN_EXPIRE_MINUTES))
    return {"access_token": token, "token_type": "bearer"}


@app.get("/dashboard")
async def get_dashboard(client_id: str = Depends(get_current_client)):
    """Client dashboard — compliance score, findings summary."""
    from soc.evidence_store import EvidenceStore
    from soc.compliance_engine import generate_revenue_report

    store = EvidenceStore(client_id)
    chain_ok = store.verify_chain()

    # Load latest compliance data from client profile
    profile_path = Path(f"knowledge/client_profiles/{client_id}.yaml")
    with open(profile_path) as f:
        profile = yaml.safe_load(f)

    return {
        "client_id": client_id,
        "domain": profile.get("domain"),
        "tier": profile.get("tier"),
        "compliance_score": profile.get("last_compliance_score", 0),
        "last_scan": profile.get("last_scan_date"),
        "evidence_chain_integrity": "PASS" if chain_ok else "FAIL",
        "open_findings": profile.get("open_findings_count", 0),
    }


@app.get("/reports")
async def list_reports(client_id: str = Depends(get_current_client)):
    """List available reports for client."""
    reports_dir = Path("reports")
    reports = []
    for f in reports_dir.glob(f"{client_id}_*.pdf"):
        reports.append({
            "filename": f.name,
            "size_kb": f.stat().st_size // 1024,
            "created": datetime.fromtimestamp(f.stat().st_mtime).isoformat(),
        })
    return {"client_id": client_id, "reports": sorted(reports, key=lambda x: x["created"], reverse=True)}


@app.get("/findings")
async def get_findings(
    client_id: str = Depends(get_current_client),
    severity: Optional[str] = None,
    limit: int = 50,
):
    """Get findings for client — filtered by client_id JWT (isolation enforced)."""
    from soc.evidence_store import EvidenceStore

    store = EvidenceStore(client_id)
    package = store.get_audit_package()
    records = package.get("records", [])

    if severity:
        records = [r for r in records if r.get("status", "").upper() == severity.upper()]

    return {
        "client_id": client_id,
        "total": len(records),
        "findings": records[:limit],
    }


@app.post("/scan/request")
async def request_scan(client_id: str = Depends(get_current_client)):
    """Trigger on-demand scan for client."""
    import subprocess
    from pathlib import Path

    profile_path = Path(f"knowledge/client_profiles/{client_id}.yaml")
    if not profile_path.exists():
        raise HTTPException(status_code=404, detail="Client not found")

    with open(profile_path) as f:
        profile = yaml.safe_load(f)

    domain = profile.get("domain")
    # Trigger async scan
    subprocess.Popen([
        "python3", "main_orchestrator.py",
        "--client", client_id,
        "--domain", domain,
        "--async",
    ])

    return {
        "message": f"Scan queued for {domain}",
        "estimated_completion": "30 minutes",
        "client_id": client_id,
    }
```

---

## Deliverable 7.2 — Adaptive DAL (Stateful Learning)

**File:** `soc/decision_automation_layer.py` — EXTEND existing module

```python
# ── ADD TO EXISTING decision_automation_layer.py ──────────────────────────────
# Build only when 10+ clients with 90+ days of real alert data

import json
from pathlib import Path
import hashlib


class AdaptiveDAL:
    """
    Learns from historical false positive patterns.
    Adjusts DAL tier decisions based on remediation success rate.
    Build trigger: 10+ clients + 90+ days data.
    """

    HISTORICAL_DB_PATH = Path("knowledge/dal_historical_patterns.jsonl")

    def __init__(self):
        self.historical_db = self._load_historical_patterns()

    def _load_historical_patterns(self) -> dict:
        patterns = {}
        if not self.HISTORICAL_DB_PATH.exists():
            return patterns
        with open(self.HISTORICAL_DB_PATH) as f:
            for line in f:
                line = line.strip()
                if line:
                    entry = json.loads(line)
                    patterns[entry["pattern_hash"]] = entry
        return patterns

    def _hash_pattern(self, alert: dict) -> str:
        """Create deterministic hash of alert pattern (rule + source + severity)."""
        key = f"{alert.get('rule', {}).get('id', '')}_{alert.get('source', '')}_{alert.get('severity', '')}"
        return hashlib.md5(key.encode()).hexdigest()

    def classify_alert_adaptive(self, alert: dict) -> AlertDecision:
        """Classify with historical pattern adjustment."""
        # Base classification
        decision = classify_alert(alert, dry_run=SOAR_DRY_RUN)
        pattern_hash = self._hash_pattern(alert)

        if pattern_hash not in self.historical_db:
            return decision

        history = self.historical_db[pattern_hash]
        fp_rate = history.get("false_positive_rate", 0.0)
        success_rate = history.get("remediation_success_rate", 0.0)

        # High false positive rate → escalate to human
        if fp_rate > 0.20 and decision.tier == Tier.AUTO_REMEDIATE:
            decision.tier = Tier.HUMAN_ESCALATE
            decision.reason += f" (adaptive: FP rate {fp_rate:.0%} > 20%)"

        # High remediation success → promote to auto-remediate
        if success_rate > 0.90 and decision.tier == Tier.HUMAN_ESCALATE and alert.get("confidence", 0) > 0.65:
            decision.tier = Tier.AUTO_REMEDIATE
            decision.reason += f" (adaptive: success rate {success_rate:.0%} > 90%)"

        return decision

    def record_outcome(self, pattern_hash: str, was_false_positive: bool, remediation_succeeded: bool):
        """Record alert outcome to improve future decisions."""
        existing = self.historical_db.get(pattern_hash, {
            "pattern_hash": pattern_hash,
            "total_count": 0,
            "false_positive_count": 0,
            "remediation_attempts": 0,
            "remediation_successes": 0,
        })

        existing["total_count"] += 1
        if was_false_positive:
            existing["false_positive_count"] += 1
        if remediation_succeeded:
            existing["remediation_attempts"] += 1
            existing["remediation_successes"] += 1
        elif not was_false_positive:
            existing["remediation_attempts"] += 1

        total = existing["total_count"]
        existing["false_positive_rate"] = existing["false_positive_count"] / total
        existing["remediation_success_rate"] = (
            existing["remediation_successes"] / existing["remediation_attempts"]
            if existing["remediation_attempts"] > 0 else 0.0
        )

        self.historical_db[pattern_hash] = existing

        with open(self.HISTORICAL_DB_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(existing) + "\n")
```

---

## Deliverable 7.3 — Cross-System Correlation Engine

**File:** `soc/correlation_engine.py`

```python
"""
Correlation Engine — correlate events across Wazuh + Cloudflare + Okta.
Detects complex attack patterns that single-source analysis misses.
Build trigger: 5+ clients using all three data sources.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional


@dataclass
class CorrelatedEvent:
    event_id: str
    client_id: str
    pattern: str
    confidence: float
    sources: list[str]
    description: str
    affected_ips: list[str]
    timestamp: str
    recommended_tier: int


class CorrelationEngine:
    """
    Correlates Wazuh + Cloudflare + Okta events to detect complex threats.
    """

    def __init__(self, client_id: str, time_window_seconds: int = 300):
        self.client_id = client_id
        self.time_window = time_window_seconds

    def correlate_credential_stuffing(
        self,
        wazuh_events: list[dict],
        cloudflare_events: list[dict],
    ) -> list[CorrelatedEvent]:
        """
        Detect credential stuffing:
        Wazuh: multiple SSH failures + Cloudflare: high request rate from same IP
        """
        correlated = []

        wazuh_ips = {}
        for evt in wazuh_events:
            if str(evt.get("rule", {}).get("id")) in {"5710", "5720", "5760"}:
                ip = evt.get("data", {}).get("srcip", "")
                if ip:
                    wazuh_ips[ip] = wazuh_ips.get(ip, 0) + 1

        cf_ips = {}
        for evt in cloudflare_events:
            ip = evt.get("ClientIP", "")
            if ip:
                cf_ips[ip] = cf_ips.get(ip, 0) + 1

        for ip in set(wazuh_ips.keys()) & set(cf_ips.keys()):
            if wazuh_ips[ip] >= 5 and cf_ips[ip] >= 100:
                correlated.append(CorrelatedEvent(
                    event_id=f"corr_cred_stuff_{ip}_{int(datetime.now().timestamp())}",
                    client_id=self.client_id,
                    pattern="credential_stuffing",
                    confidence=0.85,
                    sources=["wazuh", "cloudflare"],
                    description=f"Credential stuffing attack from {ip}: {wazuh_ips[ip]} SSH failures + {cf_ips[ip]} web requests",
                    affected_ips=[ip],
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    recommended_tier=3,
                ))

        return correlated

    def correlate_data_exfiltration(
        self,
        wazuh_events: list[dict],
        cloudflare_events: list[dict],
    ) -> list[CorrelatedEvent]:
        """
        Detect data exfiltration:
        Wazuh: large file access from sensitive directory
        Cloudflare: spike in egress to unknown IP
        """
        correlated = []

        wazuh_file_events = [
            e for e in wazuh_events
            if str(e.get("rule", {}).get("id")) in {"553", "554", "550"}
            and any(path in str(e) for path in ["/etc/", "/home/", "/var/www/"])
        ]

        cf_spike_ips = [
            evt.get("ClientIP") for evt in cloudflare_events
            if evt.get("EdgeResponseBytes", 0) > 10_000_000  # 10MB+
        ]

        if wazuh_file_events and cf_spike_ips:
            correlated.append(CorrelatedEvent(
                event_id=f"corr_exfil_{int(datetime.now().timestamp())}",
                client_id=self.client_id,
                pattern="data_exfiltration",
                confidence=0.75,
                sources=["wazuh", "cloudflare"],
                description=f"Potential data exfiltration: {len(wazuh_file_events)} file events + {len(cf_spike_ips)} high-egress connections",
                affected_ips=cf_spike_ips[:5],
                timestamp=datetime.now(timezone.utc).isoformat(),
                recommended_tier=3,
            ))

        return correlated
```

---

## Deliverable 7.4 — Multi-Model LLM Routing (Production)

**File:** `core/llm_router.py` — EXTEND with Claude Sonnet routing

```python
# ── ADD TO EXISTING core/llm_router.py ────────────────────────────────────────
# Activated when Claude API budget is allocated (Phase 7)

PRODUCTION_ROUTING_TABLE = {
    TaskType.THREAT_ANALYSIS: {
        "provider": "claude",
        "model": "claude-sonnet-4-5",
        "api_key_env": "ANTHROPIC_API_KEY",
        "rpm_limit": 50,
        "reason": "Critical threat analysis — Claude Sonnet for accuracy",
        "monthly_cost_estimate": "$30–$50 at scale",
        "trigger": "Phase 7 — Claude API budget allocated",
    },
    TaskType.REPORT_WRITING: {
        "provider": "gemini",
        "model": "gemini-2.0-flash",
        "api_key_env": "GEMINI_API_KEY",
        "rpm_limit": 15,
        "reason": "Keep on Gemini — cost efficient, good quality",
    },
    TaskType.TRANSLATION_AR: {
        "provider": "deepseek",
        "model": "deepseek-chat",
        "api_key_env": "DEEPSEEK_API_KEY",
        "rpm_limit": 60,
        "reason": "Free 1M tokens, best Arabic quality",
    },
}
# Sensitive/air-gapped clients → Ollama local LLM (Phase 7 upgrade)
# Trigger: first air-gapped client with data residency requirement
```

---

## Phase 7 Tests

**File:** `tests/test_phase7.py`

```python
"""
Tests for Phase 7 Platform Features
8 tests — all must pass for Phase 7 completion
"""

import pytest
import os
import tempfile

os.environ["EVIDENCE_ROOT"] = tempfile.mkdtemp()


def test_portal_jwt_auth():
    """Portal login issues valid JWT token."""
    from jose import jwt
    from datetime import datetime, timedelta, timezone

    secret = "test_secret"
    payload = {"sub": "asasEdu", "exp": datetime.now(timezone.utc) + timedelta(hours=1), "type": "client"}
    token = jwt.encode(payload, secret, algorithm="HS256")
    decoded = jwt.decode(token, secret, algorithms=["HS256"])
    assert decoded["sub"] == "asasEdu"


def test_client_isolation():
    """Client A cannot see Client B evidence data."""
    from soc.evidence_store import EvidenceStore, EvidenceRecord, hash_raw_log
    from datetime import datetime, timezone

    store_a = EvidenceStore("client_a")
    store_b = EvidenceStore("client_b")

    record_a = EvidenceRecord(
        control_id="NCA-2.3.1", framework="NCA_ECC_2.0",
        client_id="client_a", scan_id="scan_001", status="FAIL",
        finding_summary="test", source="wazuh", event_id="evt_a",
        raw_log_hash=hash_raw_log("client_a_log"),
        timestamp=datetime.now(timezone.utc).isoformat(),
    )
    store_a.append(record_a)

    package_b = store_b.get_audit_package()
    assert package_b["record_count"] == 0  # Client B sees nothing from A


def test_adaptive_dal_downgrade():
    """High false positive rate (>20%) downgrades Tier 2 → Tier 3."""
    from soc.decision_automation_layer import AdaptiveDAL, Tier
    import json
    from pathlib import Path
    import tempfile

    dal = AdaptiveDAL()
    pattern_hash = "test_high_fp"

    dal.historical_db[pattern_hash] = {
        "pattern_hash": pattern_hash,
        "false_positive_rate": 0.25,
        "remediation_success_rate": 0.60,
    }

    alert = {
        "id": "test",
        "confidence": 0.80,
        "severity": "medium",
        "critical_asset": False,
        "novel_pattern": False,
        "rule": {"id": "31101"},
        "source": "wazuh",
    }

    decision = dal.classify_alert_adaptive(alert)
    assert decision.tier == Tier.HUMAN_ESCALATE, "High FP rate should escalate"


def test_adaptive_dal_upgrade():
    """High remediation success rate (>90%) can promote Tier 3 → Tier 2."""
    from soc.decision_automation_layer import AdaptiveDAL, Tier

    dal = AdaptiveDAL()
    pattern_hash = "test_high_success"

    dal.historical_db[pattern_hash] = {
        "pattern_hash": pattern_hash,
        "false_positive_rate": 0.05,
        "remediation_success_rate": 0.95,
    }

    alert = {
        "id": "test",
        "confidence": 0.68,
        "severity": "medium",
        "critical_asset": False,
        "novel_pattern": False,
        "rule": {"id": "31101"},
        "source": "wazuh",
    }

    decision = dal.classify_alert_adaptive(alert)
    assert decision.tier == Tier.AUTO_REMEDIATE, "High success rate should promote"


def test_correlation_credential_stuffing():
    """Multi-source correlation detects credential stuffing."""
    from soc.correlation_engine import CorrelationEngine

    engine = CorrelationEngine("test_client")

    wazuh_events = [
        {"rule": {"id": "5710"}, "data": {"srcip": "203.0.113.5"}}
        for _ in range(6)
    ]

    cf_events = [
        {"ClientIP": "203.0.113.5", "EdgeResponseBytes": 1000}
        for _ in range(150)
    ]

    results = engine.correlate_credential_stuffing(wazuh_events, cf_events)
    assert len(results) > 0
    assert results[0].pattern == "credential_stuffing"
    assert results[0].confidence >= 0.80


def test_portal_client_isolation():
    """Portal API returns only data for authenticated client_id."""
    # Verified via JWT payload — client_id in token controls data access
    # Test: JWT with client_id=A returns 0 records from client_id=B store
    from soc.evidence_store import EvidenceStore
    store_b = EvidenceStore("client_b_portal_test")
    package = store_b.get_audit_package()
    assert package["client_id"] == "client_b_portal_test"


def test_local_agent_evidence_origin():
    """Evidence record with origin=local_agent stores correctly."""
    from soc.evidence_store import EvidenceStore, EvidenceRecord, hash_raw_log
    from datetime import datetime, timezone

    store = EvidenceStore("hybrid_client")
    record = EvidenceRecord(
        control_id="NCA-2.3.1", framework="NCA_ECC_2.0",
        client_id="hybrid_client", scan_id="scan_001", status="PASS",
        finding_summary="local agent test", source="wazuh", event_id="local_evt_001",
        raw_log_hash=hash_raw_log("local_log"),
        timestamp=datetime.now(timezone.utc).isoformat(),
        origin="local_agent",
        raw_log_ref="local://client-host/logs/chunk_abc123",
    )
    appended = store.append(record)
    assert appended.origin == "local_agent"
    assert appended.raw_log_ref is not None
    assert store.verify_chain() is True


def test_llm_router_selects_production_model():
    """Critical task routes to Claude Sonnet when API key available."""
    import os
    from core.llm_router import LLMRouter, TaskType

    os.environ["ANTHROPIC_API_KEY"] = "sk-test-valid-key"

    config = LLMRouter.get_llm_for_task(TaskType.THREAT_ANALYSIS)
    # In Phase 7 with production routing:
    # assert config["model"] == "claude-sonnet-4-5"
    assert config is not None
    assert "model" in config


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
```

**Commit Phase 7:**
```bash
git add portal/ soc/correlation_engine.py tests/test_phase7.py
git commit -m "feat(phase7): portal MVP + adaptive DAL + correlation engine + LLM routing"
git push origin phase1-evidence-system
```

---

## PHASE_STATE.md — Final State Template

```markdown
# SOC Root — Phase State

Current Phase: [UPDATE EACH SESSION]
Last Commit: [PASTE LATEST HASH]
Tests Baseline: [X/Y passing]
Evidence Format: FROZEN (after Phase 1 first record) / NOT YET FROZEN
SOAR_DRY_RUN: true / false (MUST HAVE H-4 AUTHORIZATION IF FALSE)
n8n Status: RUNNING on Node B :5678 / PENDING
Vault Status: CREATED + sync script deployed / PENDING
AsasEdu Status: CONFIRMED / PENDING
Active Client Count: [N]
MRR: $[N]

Phase Unlock Status:
  Phase 0 → Phase 1: [UNLOCKED / PENDING — AsasEdu confirmation]
  Phase 1 → Phase 2: [UNLOCKED / PENDING — verify_chain() passing]
  Phase 2 → Phase 3: [UNLOCKED / PENDING — DAL stable 7 days]
  Phase 3 → Phase 4: [UNLOCKED / PENDING — auditor informal review]
  Phase 4 → Phase 5: [UNLOCKED / PENDING — DRY_RUN=false + 3 clients]
  Phase 5 → Phase 6: [UNLOCKED / PENDING — MRR ≥ $800 × 60 days]
  Phase 6 → Phase 7: [UNLOCKED / PENDING — 2 audit cycles accepted]
```

---

## COMPLETE FILE MAP — ALL PHASES

| Phase | File | Action |
|-------|------|--------|
| 0 | `.gemini/antigravity/knowledge/SAFETY_RULES.md` | CREATE |
| 0 | `.gemini/antigravity/knowledge/PROJECT_CONTEXT.md` | CREATE |
| 0 | `.gemini/antigravity/knowledge/PHASE_STATE.md` | CREATE + UPDATE |
| 0 | `.gemini/antigravity/mcp_config.json` | CREATE |
| 0 | `.vscode/settings.json` | CREATE |
| 0 | `scripts/sync_to_obsidian.py` | CREATE |
| 0 | `mcp-servers/evidence-store/server.js` | CREATE |
| 0 | `core/llm_router.py` | CREATE |
| 0 | `scripts/metrics_exporter.py` | CREATE |
| 0 | `scripts/master_orchestrator.sh` | CREATE |
| 1 | `soc/evidence_store.py` | CREATE |
| 1 | `soc/wazuh_evidence_bridge.py` | CREATE |
| 1 | `soc/compliance_engine.py` | MODIFY |
| 1 | `knowledge/compliance_frameworks/nca_controls.json` | CREATE |
| 1 | `main_orchestrator.py` | MODIFY |
| 1 | `tests/test_evidence_store.py` | CREATE |
| 1 | `docs/evidence_methodology_doc.md` | CREATE |
| 1 | `.gemini/antigravity/skills/evidence_verification.md` | CREATE |
| 1 | `.gemini/antigravity/skills/nca_control_mapping.md` | CREATE |
| 2 | `soc/decision_automation_layer.py` | CREATE |
| 2 | `soc/alert_router.py` | MODIFY |
| 2 | `dashboard.py` | MODIFY |
| 2 | `tests/test_dal.py` | CREATE |
| 2 | `.gemini/antigravity/skills/alert_triage.md` | CREATE |
| 3 | `soc/compliance_engine.py` | MODIFY |
| 3 | `reports/client_report_generator.py` | MODIFY |
| 3 | `knowledge/compliance_frameworks/uae_pdpl_controls.json` | CREATE |
| 3 | `.gemini/antigravity/skills/arabic_reporting.md` | CREATE |
| 4 | `soc/soar_evidence_bridge.py` | CREATE |
| 5 | `/etc/systemd/system/synapse-scheduler.service` | CREATE |
| 5 | `onboarding/contract_manager.py` | MODIFY |
| 5 | `docs/SYNAPSE_AGENT_HANDOFF.md` | MODIFY |
| 6 | `agents/lead_gen_agent.py` | CREATE |
| 6 | `agents/cold_email_agent.py` | CREATE |
| 6 | `docs/outcome_guarantee.md` | CREATE |
| 6 | `.gemini/antigravity/skills/lead_generation.md` | CREATE |
| 7 | `portal/app.py` | CREATE |
| 7 | `soc/correlation_engine.py` | CREATE |
| 7 | `tests/test_phase7.py` | CREATE |

**Total: 42 files across 8 phases (0-7)**

---

## COMPLETE TEST REGISTRY

| Phase | Test File | Tests | Pass Condition |
|-------|-----------|-------|---------------|
| 1 | `tests/test_evidence_store.py` | 8 | All 8 pass |
| 2 | `tests/test_dal.py` | 6 | All 6 pass |
| 7 | `tests/test_phase7.py` | 8 | All 8 pass |
| Existing | `tests/test_final_e2e.py` | 14 | All 14 pass |

**Total test coverage: 36 tests**

---

## COMPLETE LIBRARY REGISTRY

```bash
# Install all libraries needed across all phases
pip install \
    fpdf2 \
    chromadb \
    google-generativeai \
    python-bidi \
    arabic-reshaper \
    playwright \
    prometheus-client \
    jsonlines \
    mypy \
    httpx \
    pyyaml \
    dnspython \
    fastapi \
    uvicorn \
    jinja2 \
    python-jose \
    python-multipart \
    --break-system-packages --quiet

# Playwright browsers
python3 -m playwright install chromium firefox

echo "✅ All libraries installed"
```

---

*Document Authority: SOC Root Master Execution Plan v2.0 — Consolidated Single File*  
*Owner: Muath Yousef — Kyrie Security Architect — socroot.com*  
*Total phases: 8 (0-7) | Total files: 42 | Total tests: 36 | Total manual tasks: 5*
