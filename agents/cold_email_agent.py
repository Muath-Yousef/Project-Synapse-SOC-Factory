"""
Cold Email Agent — 3-email sequence with personalized DNS findings.
Rate limit: 20/day. All emails include unsubscribe.

Phase 6 Deliverable 6.2
"""

import os
import smtplib
import json
import urllib.parse
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from datetime import datetime, timezone

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
        print("⚠️ SMTP credentials not configured — set SMTP_USER and SMTP_PASSWORD")
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


def get_email_history(email: str) -> list[dict]:
    """Get email sequence history for a lead."""
    log_file = Path("logs/cold_email_log.jsonl")
    if not log_file.exists():
        return []

    history = []
    with open(log_file, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                entry = json.loads(line)
                if entry.get("email") == email:
                    history.append(entry)
    return history


def run_email_sequence(leads: list, day_0_only: bool = False):
    """Run cold email sequence for qualified leads."""
    sent_today = 0

    for lead in leads:
        if sent_today >= DAILY_LIMIT:
            print(f"⚠️ Daily limit ({DAILY_LIMIT}) reached — stopping")
            break

        # Check existing history to determine email sequence stage
        history = get_email_history(lead.email)
        emails_sent = len(history)

        if emails_sent == 0:
            subject, body = build_email_1(lead)
            email_num = 1
        elif emails_sent == 1 and not day_0_only:
            subject, body = build_email_2(lead)
            email_num = 2
        elif emails_sent == 2 and not day_0_only:
            subject, body = build_email_3(lead)
            email_num = 3
        else:
            print(f"⏭️  {lead.domain}: sequence complete or day_0_only mode")
            continue

        if send_email(lead.email, subject, body):
            log_email_sent(lead, email_num)
            sent_today += 1

    print(f"✅ Email batch complete: {sent_today} sent")


if __name__ == "__main__":
    print("Cold Email Agent — run via lead_gen_agent.py pipeline")
    print("Usage: process_leads_batch() → run_email_sequence(qualified_leads)")
