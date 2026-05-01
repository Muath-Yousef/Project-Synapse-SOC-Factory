#!/bin/bash
# SOC Root — Email Diagnostic & Auto-Fix Script
# Run this on Node B as root

echo "============================================"
echo "  SOC Root — Email System Diagnostic"
echo "============================================"

# ── 1. Check current SMTP config in .env ──────
echo ""
echo "[1] Reading current .env config..."
ENV_FILE="/opt/synapse/.env"

SMTP_HOST=$(grep "^SMTP_HOST" $ENV_FILE 2>/dev/null | cut -d= -f2)
SMTP_PORT=$(grep "^SMTP_PORT" $ENV_FILE 2>/dev/null | cut -d= -f2)
SMTP_USER=$(grep "^SMTP_USER" $ENV_FILE 2>/dev/null | cut -d= -f2)
SMTP_PASS=$(grep "^SMTP_PASSWORD" $ENV_FILE 2>/dev/null | cut -d= -f2)
SMTP_FROM=$(grep "^SMTP_FROM" $ENV_FILE 2>/dev/null | cut -d= -f2)

echo "  SMTP_HOST     : ${SMTP_HOST:-NOT SET}"
echo "  SMTP_PORT     : ${SMTP_PORT:-NOT SET}"
echo "  SMTP_USER     : ${SMTP_USER:-NOT SET}"
echo "  SMTP_PASSWORD : ${SMTP_PASS:+SET (hidden)}"
echo "  SMTP_FROM     : ${SMTP_FROM:-NOT SET}"

# ── 2. Check email_connector.py exists ────────
echo ""
echo "[2] Checking email_connector.py..."
CONNECTOR="/opt/synapse/soc/connectors/email_connector.py"
if [ -f "$CONNECTOR" ]; then
    echo "  FOUND: $CONNECTOR"
    echo "  --- Content ---"
    cat "$CONNECTOR"
    echo "  ---------------"
else
    echo "  MISSING: $CONNECTOR — will create it"
fi

# ── 3. Test SMTP connectivity ─────────────────
echo ""
echo "[3] Testing SMTP port connectivity..."

# Test Gmail SMTP
echo -n "  smtp.gmail.com:587 : "
timeout 5 bash -c "echo > /dev/tcp/smtp.gmail.com/587" 2>/dev/null && echo "OPEN" || echo "BLOCKED"

echo -n "  smtp.gmail.com:465 : "
timeout 5 bash -c "echo > /dev/tcp/smtp.gmail.com/465" 2>/dev/null && echo "OPEN" || echo "BLOCKED"

# Test Outlook SMTP
echo -n "  smtp.office365.com:587 : "
timeout 5 bash -c "echo > /dev/tcp/smtp.office365.com/587" 2>/dev/null && echo "OPEN" || echo "BLOCKED"

echo -n "  smtp-mail.outlook.com:587 : "
timeout 5 bash -c "echo > /dev/tcp/smtp-mail.outlook.com/587" 2>/dev/null && echo "OPEN" || echo "BLOCKED"

# ── 4. Test actual send with Python ───────────
echo ""
echo "[4] Testing Python SMTP send..."

cd /opt/synapse
source venv/bin/activate

python3 << 'PYEOF'
import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

env_file = "/opt/synapse/.env"
config = {}
try:
    with open(env_file) as f:
        for line in f:
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                config[k.strip()] = v.strip()
except:
    pass

host = config.get("SMTP_HOST", "")
port = int(config.get("SMTP_PORT", "587"))
user = config.get("SMTP_USER", "")
password = config.get("SMTP_PASSWORD", "")
from_addr = config.get("SMTP_FROM", user)

print(f"  Attempting send via {host}:{port} as {user}")

if not all([host, user, password]):
    print("  ERROR: SMTP credentials not configured in .env")
    print("  DIAGNOSIS: Missing SMTP config — will fix below")
    exit(1)

try:
    msg = MIMEMultipart()
    msg["From"] = from_addr
    msg["To"] = "socroot@outlook.com"
    msg["Subject"] = "SOC Root — Email Test"
    msg.attach(MIMEText("This is a test email from SOC Root backend.\n\nIf you received this, email is working correctly.", "plain"))

    if port == 465:
        server = smtplib.SMTP_SSL(host, port, timeout=10)
    else:
        server = smtplib.SMTP(host, port, timeout=10)
        server.ehlo()
        server.starttls()
        server.ehlo()

    server.login(user, password)
    server.sendmail(from_addr, "socroot@outlook.com", msg.as_string())
    server.quit()
    print("  SUCCESS: Email sent successfully")

except smtplib.SMTPAuthenticationError as e:
    print(f"  AUTH ERROR: Wrong username or password — {e}")
    print("  DIAGNOSIS: Credentials wrong or App Password required")
except smtplib.SMTPConnectError as e:
    print(f"  CONNECT ERROR: Cannot reach SMTP server — {e}")
    print("  DIAGNOSIS: Port blocked by firewall or wrong host")
except Exception as e:
    print(f"  ERROR: {type(e).__name__}: {e}")
PYEOF

# ── 5. Auto-fix: Create/replace email_connector.py ──
echo ""
echo "[5] Writing production email_connector.py..."

mkdir -p /opt/synapse/soc/connectors

cat << 'CONNECTOR_EOF' > /opt/synapse/soc/connectors/email_connector.py
"""
soc/connectors/email_connector.py
Reads SMTP config from /opt/synapse/.env
Supports Gmail (App Password) and Outlook
"""
import smtplib
import os
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path

logger = logging.getLogger("email_connector")

def _load_env():
    config = {}
    env_path = Path("/opt/synapse/.env")
    if env_path.exists():
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    config[k.strip()] = v.strip()
    # Also check os.environ (overrides .env)
    for key in ["SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASSWORD", "SMTP_FROM"]:
        if os.environ.get(key):
            config[key] = os.environ[key]
    return config

def send_email(to: str, subject: str, body: str) -> bool:
    config = _load_env()
    host     = config.get("SMTP_HOST", "")
    port     = int(config.get("SMTP_PORT", "587"))
    user     = config.get("SMTP_USER", "")
    password = config.get("SMTP_PASSWORD", "")
    from_addr = config.get("SMTP_FROM", user)

    if not all([host, user, password]):
        logger.error("SMTP not configured. Set SMTP_HOST, SMTP_USER, SMTP_PASSWORD in .env")
        return False

    try:
        msg = MIMEMultipart()
        msg["From"]    = from_addr
        msg["To"]      = to
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        if port == 465:
            server = smtplib.SMTP_SSL(host, port, timeout=15)
        else:
            server = smtplib.SMTP(host, port, timeout=15)
            server.ehlo()
            server.starttls()
            server.ehlo()

        server.login(user, password)
        server.sendmail(from_addr, to, msg.as_string())
        server.quit()
        logger.info(f"Email sent to {to} — subject: {subject}")
        return True

    except smtplib.SMTPAuthenticationError:
        logger.error("SMTP Auth failed. For Gmail: use App Password. For Outlook: use account password.")
        return False
    except Exception as e:
        logger.error(f"Email send failed: {type(e).__name__}: {e}")
        return False
CONNECTOR_EOF

echo "  DONE: email_connector.py written"

# ── 6. Check if SMTP is configured in .env ────
echo ""
echo "[6] Checking if .env needs SMTP update..."

if [ -z "$SMTP_HOST" ] || [ -z "$SMTP_USER" ] || [ -z "$SMTP_PASS" ]; then
    echo ""
    echo "  ════════════════════════════════════════"
    echo "  ACTION REQUIRED — Add SMTP to .env"
    echo "  ════════════════════════════════════════"
    echo ""
    echo "  Choose one option and add to /opt/synapse/.env:"
    echo ""
    echo "  OPTION A — Gmail (recommended, uses App Password):"
    echo "  ─────────────────────────────────────────────────"
    echo "  SMTP_HOST=smtp.gmail.com"
    echo "  SMTP_PORT=587"
    echo "  SMTP_USER=your_gmail@gmail.com"
    echo "  SMTP_PASSWORD=xxxx xxxx xxxx xxxx   <-- 16-char App Password"
    echo "  SMTP_FROM=SOC Root <your_gmail@gmail.com>"
    echo ""
    echo "  To get Gmail App Password:"
    echo "  myaccount.google.com → Security → 2-Step → App Passwords"
    echo "  App name: SOC Root — copy the 16-char code"
    echo ""
    echo "  OPTION B — Outlook (socroot@outlook.com):"
    echo "  ──────────────────────────────────────────"
    echo "  SMTP_HOST=smtp-mail.outlook.com"
    echo "  SMTP_PORT=587"
    echo "  SMTP_USER=socroot@outlook.com"
    echo "  SMTP_PASSWORD=your_outlook_password"
    echo "  SMTP_FROM=SOC Root <socroot@outlook.com>"
    echo ""
    echo "  Add with:"
    echo "  nano /opt/synapse/.env"
    echo "  (then re-run this script to verify)"
else
    echo "  SMTP config found — retesting with real send..."
    python3 -c "
import sys
sys.path.insert(0, '/opt/synapse')
from soc.connectors.email_connector import send_email
result = send_email(
    to='socroot@outlook.com',
    subject='SOC Root — OTP Test',
    body='Test email from diagnostic script.\n\n— SOC Root'
)
print('SEND RESULT:', 'SUCCESS' if result else 'FAILED')
"
fi

# ── 7. Restart service ────────────────────────
echo ""
echo "[7] Restarting synapse-webhook service..."
systemctl restart synapse-webhook
sleep 2
systemctl is-active synapse-webhook && echo "  Service: RUNNING" || echo "  Service: FAILED"

echo ""
echo "============================================"
echo "  Diagnostic Complete"
echo "============================================"
