# SOC ROOT — WEBSITE OVERHAUL: COMPLETE AGENT EXECUTION PLAN
> **Authority:** This document is the single executable instruction set for the agent performing the SOC Root website overhaul.  
> **Read every section fully before touching a single file.**  
> **Execution order is mandatory — do not skip or reorder phases.**  
> **Last Updated:** April 2026  
> **Owner:** Muath Yousef — SOC Root

---

## AGENT CONTEXT — READ FIRST

You are working on the **SOC Root** website — a professional B2B cybersecurity managed services platform. The site is currently hosted on **GitHub Pages** at `socroot.com` via Cloudflare DNS. The backend API runs on **Node B (164.68.121.179)** with Flask (`webhook_server.py`) on port 5000.

**Repository:** `https://github.com/Muath-Yousef/Project-Synapse-SOC-Factory` (private)  
**Local path of website files:** Locate the GitHub Pages branch or `/website/` folder in the repo.  
**Backend service path on Node B:** `/opt/synapse/`  
**Backend language:** Python 3 + Flask  
**Primary color palette:** `#0A0A0F` background · `#00D4FF` cyan · `#FFD700` gold  
**Font directive:** Space Mono for headings, clean sans-serif for body — NO generic fonts

---

## ABSOLUTE RULES — NEVER VIOLATE

```
❌ Never hardcode API keys, tokens, or secrets in frontend code
❌ Never expose internal server IPs in any public-facing file
❌ Never reference Jordan, UAE, or any specific country until instructed
❌ Never use language implying AI generates the reports automatically without human review
   CORRECT phrasing: "reviewed by certified security specialists"
   WRONG phrasing: "AI-generated report" / "automated analysis"
❌ Never leave placeholder content (Lorem ipsum, "example@email.com", fake phone numbers)
❌ Never commit .env files
❌ Never break existing passing tests in the backend
```

---

## PHASE 1 — BACKEND SECURITY HARDENING
**Goal:** Make the backend API production-safe before any public traffic hits it.  
**Files to modify:** `webhook_server.py` (Node B) + Nginx/Cloudflare config  
**Estimated scope:** 120–180 lines of additions

### 1.1 — Input Sanitization & Injection Prevention

Add the following to `webhook_server.py`:

```python
# Add these imports at the top
import re
import html
from markupsafe import escape  # pip install markupsafe

# Input sanitizer function — add before all route handlers
def sanitize_input(value: str, max_length: int = 500) -> str:
    """Strip HTML tags, escape special chars, limit length."""
    if not isinstance(value, str):
        return ""
    value = html.escape(value.strip())
    value = re.sub(r'[<>"\';\\]', '', value)
    return value[:max_length]

def validate_email(email: str) -> bool:
    pattern = r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email)) and len(email) <= 254

def validate_domain(domain: str) -> bool:
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain)) and len(domain) <= 253
```

Apply `sanitize_input()` to ALL form field inputs in every route handler before any processing.

### 1.2 — Security Headers Middleware

Add to `webhook_server.py` after `app = Flask(__name__)`:

```python
from flask import Flask, request, jsonify, make_response
from functools import wraps

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self';"
    )
    # Remove server fingerprint
    response.headers.pop('Server', None)
    response.headers.pop('X-Powered-By', None)
    return response
```

### 1.3 — Rate Limiting (Anti-Abuse)

```python
# pip install flask-limiter
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Apply strict limit to scan request endpoint:
@app.route('/api/scan-request', methods=['POST'])
@limiter.limit("3 per hour")
def scan_request():
    ...

# Apply to email verification:
@app.route('/api/verify-email', methods=['POST'])
@limiter.limit("5 per hour")
def verify_email():
    ...
```

### 1.4 — CORS Configuration

```python
from flask_cors import CORS  # pip install flask-cors

CORS(app, resources={
    r"/api/*": {
        "origins": ["https://socroot.com", "https://www.socroot.com"],
        "methods": ["POST", "GET"],
        "allow_headers": ["Content-Type", "X-Request-Token"]
    }
})
```

### 1.5 — Hide Page Extensions (Cloudflare + GitHub Pages)

In the GitHub Pages repo, create a `_redirects` file (if using Netlify) OR configure Cloudflare Transform Rules:

**Method: Cloudflare Page Rules (apply via API or dashboard)**
```
/services    → /services.html    (301 redirect, strip .html from URL bar)
/scan        → /scan.html
/about       → /about.html
/contact     → /contact.html
/training    → /training.html
/plans/*     → /plans/*.html
```

**In every HTML file, update all internal `<a href>` links** to use extension-free URLs:
- `href="services.html"` → `href="/services"`
- `href="scan.html"` → `href="/scan"`
- etc.

**In GitHub Pages repo, add `404.html`** that redirects clean URLs to their `.html` equivalents using JavaScript:
```html
<script>
  var path = window.location.pathname;
  if (!path.endsWith('.html') && !path.endsWith('/')) {
    window.location.replace(path + '.html');
  }
</script>
```

### 1.6 — Data Encryption for Form Submissions

All form data in transit is already protected by Cloudflare HTTPS. For data at rest:

```python
# pip install cryptography
from cryptography.fernet import Fernet
import os

# Key stored in .env — NEVER hardcoded
ENCRYPTION_KEY = os.environ.get('DATA_ENCRYPTION_KEY')
fernet = Fernet(ENCRYPTION_KEY.encode()) if ENCRYPTION_KEY else None

def encrypt_pii(data: str) -> str:
    """Encrypt any PII before storing to disk."""
    if not fernet:
        raise RuntimeError("Encryption key not configured")
    return fernet.encrypt(data.encode()).decode()
```

Encrypt: contact email, phone number, company name before writing to any log file.

**Phase 1 completion check:**
```bash
# Run on Node B:
curl -X POST https://socroot.com/api/health \
  -H "Content-Type: application/json" \
  -d '{"test": "<script>alert(1)</script>"}'
# Expected: sanitized echo, security headers present in response
```

---

## PHASE 2 — EMAIL VERIFICATION & NEWSLETTER SYSTEM
**Goal:** Replace hardcoded "soc-2026" code with OTP system. Add newsletter opt-in.  
**Files to create:** `api/email_otp.py` (backend) + modifications to `scan.html` and all forms

### 2.1 — OTP Generation & Storage (Backend)

Create `/opt/synapse/api/email_otp.py`:

```python
import secrets
import string
import time
import json
import os
from pathlib import Path

OTP_STORE_PATH = Path("/opt/synapse/data/otp_store.json")
OTP_EXPIRY_SECONDS = 600  # 10 minutes

def generate_otp(length: int = 6) -> str:
    """Cryptographically secure numeric OTP."""
    return ''.join(secrets.choice(string.digits) for _ in range(length))

def store_otp(email: str, otp: str) -> None:
    store = _load_store()
    store[email] = {
        "otp": otp,
        "created_at": time.time(),
        "verified": False
    }
    _save_store(store)

def verify_otp(email: str, otp: str) -> bool:
    store = _load_store()
    entry = store.get(email)
    if not entry:
        return False
    if time.time() - entry["created_at"] > OTP_EXPIRY_SECONDS:
        del store[email]
        _save_store(store)
        return False
    if entry["otp"] != otp:
        return False
    # Mark as verified, delete from store
    del store[email]
    _save_store(store)
    return True

def _load_store() -> dict:
    if not OTP_STORE_PATH.exists():
        return {}
    with open(OTP_STORE_PATH) as f:
        return json.load(f)

def _save_store(store: dict) -> None:
    OTP_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OTP_STORE_PATH, 'w') as f:
        json.dump(store, f)
```

### 2.2 — OTP API Routes (add to webhook_server.py)

```python
from api.email_otp import generate_otp, store_otp, verify_otp
from soc.connectors.email_connector import send_email  # existing connector

@app.route('/api/send-otp', methods=['POST'])
@limiter.limit("3 per hour")
def send_otp_route():
    data = request.get_json()
    email = sanitize_input(data.get('email', ''))
    
    if not validate_email(email):
        return jsonify({"success": False, "message": "Invalid email address"}), 400
    
    otp = generate_otp()
    store_otp(email, otp)
    
    # Send OTP email using existing email_connector
    subject = "SOC Root — Your Verification Code"
    body = f"""
Your verification code is: {otp}

This code expires in 10 minutes.
If you did not request this, please ignore this email.

— SOC Root Security Team
    """
    send_email(to=email, subject=subject, body=body)
    
    return jsonify({"success": True, "message": "Verification code sent"})

@app.route('/api/verify-otp', methods=['POST'])
@limiter.limit("10 per hour")
def verify_otp_route():
    data = request.get_json()
    email = sanitize_input(data.get('email', ''))
    otp = sanitize_input(data.get('otp', ''), max_length=6)
    
    if not validate_email(email) or not otp.isdigit():
        return jsonify({"success": False, "message": "Invalid input"}), 400
    
    if verify_otp(email, otp):
        return jsonify({"success": True, "verified": True})
    
    return jsonify({"success": False, "message": "Invalid or expired code"}), 401
```

### 2.3 — Newsletter Subscription Route

```python
NEWSLETTER_FILE = Path("/opt/synapse/data/newsletter_subscribers.json")

@app.route('/api/subscribe-newsletter', methods=['POST'])
@limiter.limit("2 per hour")
def subscribe_newsletter():
    data = request.get_json()
    email = sanitize_input(data.get('email', ''))
    name = sanitize_input(data.get('name', ''), max_length=100)
    
    if not validate_email(email):
        return jsonify({"success": False, "message": "Invalid email"}), 400
    
    # Load existing, check for duplicate
    subs = _load_newsletter()
    if email in subs:
        return jsonify({"success": True, "message": "Already subscribed"})
    
    subs[email] = {
        "name": name,
        "subscribed_at": time.time(),
        "active": True
    }
    _save_newsletter(subs)
    
    # Send welcome email
    send_email(
        to=email,
        subject="Welcome to SOC Root Security Updates",
        body=f"Hello {name},\n\nYou are now subscribed to SOC Root security alerts and updates.\n\nTo unsubscribe, reply with UNSUBSCRIBE.\n\n— SOC Root Team"
    )
    
    return jsonify({"success": True, "message": "Subscribed successfully"})
```

### 2.4 — Frontend OTP Flow (for scan.html and contact forms)

Replace any existing static verification code input with this flow:

```html
<!-- Step 1: Email input + Send OTP button -->
<div class="form-group" id="email-step">
  <input type="email" id="user-email" placeholder="your@company.com" required>
  <button type="button" onclick="sendOTP()">Send Verification Code</button>
</div>

<!-- Step 2: OTP input (hidden until OTP sent) -->
<div class="form-group" id="otp-step" style="display:none;">
  <p>Enter the 6-digit code sent to your email</p>
  <input type="text" id="otp-input" maxlength="6" pattern="[0-9]{6}" placeholder="000000">
  <button type="button" onclick="verifyOTP()">Verify</button>
  <button type="button" onclick="sendOTP()">Resend Code</button>
</div>

<!-- Step 3: Rest of form (hidden until verified) -->
<div id="main-form" style="display:none;">
  <!-- full form fields here -->
  
  <!-- Newsletter opt-in — always include -->
  <label class="newsletter-opt">
    <input type="checkbox" name="newsletter" checked>
    Receive security alerts and updates from SOC Root
  </label>
</div>
```

```javascript
let emailVerified = false;

async function sendOTP() {
  const email = document.getElementById('user-email').value;
  const res = await fetch('/api/send-otp', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ email })
  });
  const data = await res.json();
  if (data.success) {
    document.getElementById('otp-step').style.display = 'block';
    showMessage('Verification code sent to ' + email);
  } else {
    showError(data.message);
  }
}

async function verifyOTP() {
  const email = document.getElementById('user-email').value;
  const otp = document.getElementById('otp-input').value;
  const res = await fetch('/api/verify-otp', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ email, otp })
  });
  const data = await res.json();
  if (data.verified) {
    emailVerified = true;
    document.getElementById('otp-step').style.display = 'none';
    document.getElementById('main-form').style.display = 'block';
    showSuccess('Email verified ✓');
  } else {
    showError('Invalid code. Please try again.');
  }
}
```

---

## PHASE 3 — FREE SCAN REQUEST PIPELINE
**Goal:** Form submission → Telegram alert to Muath → auto-trigger scan → results + ready-to-send email template delivered to Telegram.

### 3.1 — Scan Request API Route

Add to `webhook_server.py`:

```python
import subprocess
from datetime import datetime

@app.route('/api/scan-request', methods=['POST'])
@limiter.limit("3 per hour")
def handle_scan_request():
    data = request.get_json()
    
    # --- Input validation ---
    company_name = sanitize_input(data.get('company_name', ''), max_length=100)
    domain = sanitize_input(data.get('domain', ''), max_length=253)
    contact_name = sanitize_input(data.get('contact_name', ''), max_length=100)
    email = sanitize_input(data.get('email', ''))
    subscribe = bool(data.get('newsletter', False))
    
    if not all([company_name, domain, contact_name, email]):
        return jsonify({"success": False, "message": "All fields required"}), 400
    if not validate_domain(domain):
        return jsonify({"success": False, "message": "Invalid domain format"}), 400
    if not validate_email(email):
        return jsonify({"success": False, "message": "Invalid email"}), 400
    
    # --- Step 1: Notify Muath via Telegram (immediate) ---
    scan_id = f"FREE-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    telegram_alert = f"""
🆕 *NEW FREE SCAN REQUEST*
━━━━━━━━━━━━━━━━━━
🏢 *Company:* {company_name}
🌐 *Domain:* `{domain}`
👤 *Contact:* {contact_name}
📧 *Email:* {email}
📰 *Newsletter:* {'✅ Yes' if subscribe else '❌ No'}
🆔 *Scan ID:* `{scan_id}`
⏰ *Received:* {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
━━━━━━━━━━━━━━━━━━
⏳ Initiating automated scan...
    """
    send_telegram(chat_id=TELEGRAM_CHAT_ID_FINDINGS, message=telegram_alert)
    
    # --- Step 2: Queue background scan ---
    # Run in background — do NOT block the HTTP response
    import threading
    scan_thread = threading.Thread(
        target=run_background_scan,
        args=(domain, company_name, contact_name, email, scan_id),
        daemon=True
    )
    scan_thread.start()
    
    # --- Step 3: Newsletter opt-in ---
    if subscribe:
        # call subscribe_newsletter logic inline
        pass
    
    # --- Respond immediately to user ---
    return jsonify({
        "success": True,
        "scan_id": scan_id,
        "message": "Your scan has been queued. You will receive results within 24 hours."
    })


def run_background_scan(domain: str, company: str, contact: str, email: str, scan_id: str):
    """
    Runs in background thread.
    Executes main_orchestrator.py then delivers results to Telegram.
    """
    try:
        send_telegram(TELEGRAM_CHAT_ID_FINDINGS, f"🔍 Scanning `{domain}` now... [ID: {scan_id}]")
        
        # Execute scan — adjust path to main_orchestrator.py on local machine
        # NOTE: On Node B, this calls back to local machine via SSH or API
        # OPTION A: If orchestrator runs locally, use SSH call
        # OPTION B: If orchestrator deployed on Node B, call directly
        result = subprocess.run(
            [
                "python3", "/opt/synapse/main_orchestrator.py",
                "--target", domain,
                "--client", scan_id,
                "--report-type", "executive"
            ],
            capture_output=True,
            text=True,
            timeout=600  # 10 min max
        )
        
        report_path = f"/opt/synapse/reports/output/{scan_id}_executive_report.pdf"
        
        if not os.path.exists(report_path):
            raise FileNotFoundError(f"Report not generated at {report_path}")
        
        # --- Deliver PDF to Telegram ---
        send_telegram_document(
            chat_id=TELEGRAM_CHAT_ID_FINDINGS,
            file_path=report_path,
            caption=f"✅ *Scan Complete* — `{domain}`\n🆔 Scan ID: `{scan_id}`"
        )
        
        # --- Deliver ready-to-send email template to Telegram ---
        email_template = generate_email_template(
            contact_name=contact,
            company=company,
            domain=domain,
            email=email,
            report_path=report_path
        )
        send_telegram(TELEGRAM_CHAT_ID_FINDINGS, email_template)
        
    except Exception as e:
        send_telegram(
            TELEGRAM_CHAT_ID_FAILURES,
            f"❌ *Scan FAILED* — `{domain}`\nError: `{str(e)}`\nScan ID: `{scan_id}`"
        )


def generate_email_template(contact_name, company, domain, email, report_path) -> str:
    """Returns a ready-to-copy professional email template for Muath to send."""
    return f"""
📧 *READY-TO-SEND EMAIL TEMPLATE*
━━━━━━━━━━━━━━━━━━
*TO:* {email}
*SUBJECT:* Your Complimentary Security Assessment — {company}

---

Dear {contact_name},

Thank you for requesting a security assessment for {company}.

Attached, you will find your Confidential Security Assessment Report for `{domain}`.

Our specialists have identified several findings that require your attention, including areas that may expose your business to operational and reputational risk. The report includes a prioritized remediation roadmap with practical timelines.

We are available for a complimentary 20-minute consultation to walk you through the findings and answer your questions.

To proceed, simply reply to this email or contact us at:
📞 WhatsApp: +962777545115
📧 support.socroot@gmail.com

Regards,
Muath Yousef
SOC Root | Security Operations
www.socroot.com

---
⚠️ *Muath — review report before sending. Reply to this message when sent.*
━━━━━━━━━━━━━━━━━━
    """
```

### 3.2 — Telegram Document Sender (add to telegram_connector.py)

```python
def send_telegram_document(chat_id: str, file_path: str, caption: str = "") -> None:
    """Send a file (PDF) to a Telegram channel."""
    import requests
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendDocument"
    with open(file_path, 'rb') as f:
        response = requests.post(url, data={
            'chat_id': chat_id,
            'caption': caption,
            'parse_mode': 'Markdown'
        }, files={'document': f})
    response.raise_for_status()
```

---

## PHASE 4 — PAYMENT INTEGRATION
**Goal:** Display real payment options and automate plan selection flow.  
**Method:** Static payment info display + server-side order logging (no Stripe — use what owner has)

### 4.1 — Payment Methods Configuration

Create `/opt/synapse/config/payment_config.json`:

```json
{
  "methods": {
    "binance_trc20": {
      "label": "Crypto (USDT/USDC — TRC20)",
      "address": "TWcSFQbAB9Axv16L5VvdNqL3ZknRGuV3Gv",
      "network": "Tron (TRC-20)",
      "instructions": "Send exact amount to address above. Include your Order ID in the memo field.",
      "logo": "binance"
    },
    "bank_transfer": {
      "label": "Bank Transfer (IBAN)",
      "iban": "JO28JONB80000000000TMA96680496",
      "account_name": "SOC Root",
      "instructions": "Use your company name as transfer reference."
    },
    "cliq": {
      "label": "CliQ (Arab Bank)",
      "alias": "SOCROOT",
      "instructions": "Send via CliQ using alias SOCROOT. Include Order ID in notes."
    },
    "paypal": {
      "label": "PayPal",
      "link": "https://www.paypal.me/socroot",
      "instructions": "Use Goods & Services option. Include Order ID in notes."
    }
  }
}
```

### 4.2 — Order Creation Route

Add to `webhook_server.py`:

```python
import uuid

@app.route('/api/create-order', methods=['POST'])
@limiter.limit("5 per hour")
def create_order():
    data = request.get_json()
    
    plan = sanitize_input(data.get('plan', ''))
    company = sanitize_input(data.get('company', ''))
    email = sanitize_input(data.get('email', ''))
    payment_method = sanitize_input(data.get('payment_method', ''))
    billing_cycle = sanitize_input(data.get('billing_cycle', 'monthly'))
    
    VALID_PLANS = ['starter', 'guard', 'governance', 'premium']
    VALID_METHODS = ['binance_trc20', 'bank_transfer', 'cliq', 'paypal']
    
    if plan not in VALID_PLANS or payment_method not in VALID_METHODS:
        return jsonify({"success": False, "message": "Invalid plan or payment method"}), 400
    
    PRICING = {
        'starter':    {'monthly': None, 'annual': 190},
        'guard':      {'monthly': 160,  'annual': 1600},
        'governance': {'monthly': 210,  'annual': 2100},
        'premium':    {'monthly': 340,  'annual': 3400}
    }
    
    amount = PRICING[plan][billing_cycle]
    order_id = f"SR-{datetime.now().strftime('%Y%m')}-{str(uuid.uuid4())[:8].upper()}"
    
    # Notify Muath via Telegram
    order_alert = f"""
💰 *NEW PURCHASE ORDER*
━━━━━━━━━━━━━━━━━━
📦 *Plan:* {plan.upper()}
💵 *Amount:* ${amount} USD
🔄 *Billing:* {billing_cycle}
🏢 *Company:* {company}
📧 *Email:* {email}
💳 *Payment:* {payment_method}
🆔 *Order ID:* `{order_id}`
⏰ *Time:* {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
━━━━━━━━━━━━━━━━━━
⚡ ACTION REQUIRED: Confirm payment receipt and activate client account.
    """
    send_telegram(TELEGRAM_CHAT_ID_FINDINGS, order_alert)
    
    # Log order to file
    order_log_path = Path("/opt/synapse/data/orders.json")
    orders = json.loads(order_log_path.read_text()) if order_log_path.exists() else []
    orders.append({
        "order_id": order_id,
        "plan": plan,
        "amount": amount,
        "billing_cycle": billing_cycle,
        "company": encrypt_pii(company),
        "email": encrypt_pii(email),
        "payment_method": payment_method,
        "status": "pending_payment",
        "created_at": time.time()
    })
    order_log_path.write_text(json.dumps(orders, indent=2))
    
    # Load payment config
    with open("/opt/synapse/config/payment_config.json") as f:
        payment_config = json.load(f)
    
    return jsonify({
        "success": True,
        "order_id": order_id,
        "amount": amount,
        "currency": "USD",
        "payment_details": payment_config['methods'][payment_method]
    })
```

### 4.3 — Frontend Payment Flow (add to each plan page)

The "Subscribe Now" button flow:
1. User clicks plan → navigates to `/plans/guard` (dedicated plan page)
2. Plan page shows details + "Get Started" CTA
3. Click → payment method selection modal
4. Select method → `POST /api/create-order` → show order ID + payment instructions
5. "I've completed payment" button → sends confirmation email to `socroot@outlook.com`

Payment modal HTML template:
```html
<div id="payment-modal" class="modal" style="display:none;">
  <div class="modal-content">
    <h2>Complete Your Order — <span id="modal-plan-name"></span></h2>
    <p class="amount">$<span id="modal-amount"></span> / <span id="modal-cycle"></span></p>
    
    <div class="billing-toggle">
      <button onclick="setBilling('monthly')" class="active">Monthly</button>
      <button onclick="setBilling('annual')">Annual (Save 20%)</button>
    </div>
    
    <h3>Select Payment Method</h3>
    <div class="payment-methods">
      <label><input type="radio" name="payment" value="binance_trc20"> Crypto (USDT/TRC20)</label>
      <label><input type="radio" name="payment" value="paypal"> PayPal</label>
      <label><input type="radio" name="payment" value="cliq"> CliQ (Arab Bank)</label>
      <label><input type="radio" name="payment" value="bank_transfer"> Bank Transfer (IBAN)</label>
    </div>
    
    <div class="company-details">
      <input type="text" id="order-company" placeholder="Company Name" required>
      <input type="email" id="order-email" placeholder="Billing Email" required>
    </div>
    
    <button onclick="submitOrder()">Generate Order →</button>
  </div>
</div>

<!-- Order confirmation panel (shown after API response) -->
<div id="order-confirmation" style="display:none;">
  <div class="order-id-box">
    <p>Order ID: <strong id="conf-order-id"></strong></p>
    <p>Amount: <strong id="conf-amount"></strong></p>
  </div>
  <div id="payment-instructions"></div>
  <button onclick="confirmPaymentSent()">I've completed the payment →</button>
</div>
```

---

## PHASE 5 — INDIVIDUAL PLAN PAGES
**Goal:** Each plan has a dedicated page with full details in non-technical language.  
**Files to create:** `/plans/starter.html`, `/plans/guard.html`, `/plans/governance.html`, `/plans/premium.html`

### 5.1 — Plan Page Template (apply to all 4 plans with different content)

Each plan page must contain these sections in order:

**Section 1 — Hero**
- Plan name + tagline
- Monthly price + annual savings
- Primary CTA button "Get Started"
- "Schedule a call" secondary link

**Section 2 — "What This Plan Protects You From"**
- Non-technical language: "Email impersonation," "Website defacement," "Data theft"
- NOT: "SPF misconfiguration," "XSS," "SQLi"
- Use visual icons, not technical acronyms

**Section 3 — What's Included (Feature List)**
```
For each feature, use this format:
  ✓ [Feature name in plain language]
    [One sentence explaining why it matters to the business]
```

**Section 4 — Our Commitment to You**
- What SOC Root will do (response times, deliverables)
- What you are responsible for (providing access, acting on recommendations)
- Data handling commitment (your data stays yours, we never share)

**Section 5 — How It Works**
- Step 1: Sign up → we assess your current state
- Step 2: We deploy monitoring and protections
- Step 3: Monthly reports + alerts when threats arise
- Step 4: Annual review and improvement plan
Use visual timeline design.

**Section 6 — Compliance Coverage** (for Governance and Premium plans)
- NCA ECC 2.0 controls covered
- ISO 27001 domains addressed
- "Your organization will be prepared for regulatory audits"

**Section 7 — Payment & Start**
- Triggers the payment modal (Phase 4)

**Section 8 — FAQ (5–7 questions)**
Sample questions:
- "Do I need technical knowledge to use this service?"
- "What happens if there's an incident at 3am?"
- "Can I cancel anytime?"
- "Who has access to my company's data?"
- "How long until I see results?"

---

## PHASE 6 — CONTACT INFORMATION UPDATE
**Goal:** Replace all placeholder contact data with real information.

### 6.1 — Global Contact Constants

In every HTML page, find and replace ALL contact references:

| Placeholder | Real Value |
|---|---|
| Any fake phone | `+962777545115` |
| Any fake email | `socroot@outlook.com` (primary) |
| Support email | `support.socroot@gmail.com` |
| HR email | `hr.socroot@outlook.com` |
| Any fake Telegram | `https://t.me/RootSoc` |
| WhatsApp link | `https://wa.me/962777545115` |

### 6.2 — Contact Page Rebuild

Replace entire contact page body with:

```html
<section class="contact-grid">
  
  <!-- Direct Phone -->
  <a href="tel:+962777545115" class="contact-card">
    <span class="icon">📞</span>
    <span class="label">Direct Line</span>
    <span class="value">+962 777 545 115</span>
  </a>
  
  <!-- WhatsApp (most important for the market) -->
  <a href="https://wa.me/962777545115?text=Hello%20SOC%20Root%2C%20I%27m%20interested%20in%20your%20services" 
     class="contact-card whatsapp" target="_blank">
    <span class="icon">💬</span>
    <span class="label">WhatsApp</span>
    <span class="value">Chat Now</span>
  </a>
  
  <!-- Primary Email -->
  <a href="mailto:socroot@outlook.com?subject=Service%20Inquiry" class="contact-card">
    <span class="icon">✉️</span>
    <span class="label">General Inquiries</span>
    <span class="value">socroot@outlook.com</span>
  </a>
  
  <!-- Support Email -->
  <a href="mailto:support.socroot@gmail.com?subject=Support%20Request" class="contact-card">
    <span class="icon">🛠️</span>
    <span class="label">Technical Support</span>
    <span class="value">support.socroot@gmail.com</span>
  </a>
  
  <!-- Telegram -->
  <a href="https://t.me/RootSoc" class="contact-card" target="_blank">
    <span class="icon">📡</span>
    <span class="label">Telegram</span>
    <span class="value">@RootSoc</span>
  </a>

</section>

<!-- Response time promise -->
<div class="response-promise">
  <p>We respond to all inquiries within <strong>4 business hours</strong>.</p>
  <p>For urgent security incidents, WhatsApp is the fastest channel.</p>
</div>
```

---

## PHASE 7 — CONTENT AUDIT & LANGUAGE CLEANUP
**Goal:** Remove geographic restrictions, reduce AI language, strengthen trust signals.

### 7.1 — Find & Replace: Geographic References

Search ALL HTML, CSS, JS files for the following and **delete** (do not replace — just remove):
- "Jordan"
- "UAE"
- "United Arab Emirates"
- "الأردن"
- "الإمارات"
- "MENA region" (replace with "internationally")
- Any city names

Exception: Keep "NCA ECC 2.0" (it's a compliance standard name, not a geographic identifier).

### 7.2 — Find & Replace: AI Language

Find these phrases and replace with the corrected versions:

| Remove | Replace With |
|---|---|
| "AI-generated report" | "specialist-reviewed security report" |
| "automated analysis" | "comprehensive security analysis" |
| "AI agent" | "our security operations team" |
| "machine learning" | "advanced detection methodology" |
| "our AI detects" | "our team detects" |
| "automatically generated" | "prepared by our analysts" |
| "AI-powered" | "technology-driven, expert-reviewed" |

### 7.3 — Add Expert Language Throughout

In the About page and footer, add:

```html
<div class="methodology-note">
  <p>Every assessment is conducted following a structured methodology and 
  reviewed by certified security professionals before delivery. 
  We do not deliver automated reports — every finding is validated, 
  contextualized, and explained in language your team can act on.</p>
</div>
```

---

## PHASE 8 — COMPLIANCE CONTENT PAGES
**Goal:** Add authoritative compliance content that demonstrates expertise and attracts organic search traffic.

### 8.1 — New Page: `/compliance/nca-ecc.html`

**Title:** "NCA ECC 2.0 Compliance — What It Means for Your Organization"

Content sections:
1. **What is NCA ECC 2.0?** — plain language overview
2. **The 5 Domains** (Access Management, Asset Management, Cybersecurity Defense, Resilience, Third Party) — one paragraph each in business language
3. **Common Compliance Gaps** — "90% of organizations we assess fail these 3 controls" (use real findings from AsasEdu as anonymous example)
4. **How SOC Root Prepares You** — map each domain to specific services
5. **Assessment Readiness Checklist** — downloadable PDF (link to a pre-generated PDF)
6. **CTA:** "Get your NCA ECC 2.0 gap assessment"

### 8.2 — New Page: `/compliance/iso-27001.html`

**Title:** "ISO 27001 — Practical Path to Certification"

Content sections:
1. What ISO 27001 certification means for your business (not technical)
2. The 14 control domains — simplified descriptions
3. Timeline to certification — realistic expectations
4. How SOC Root's continuous monitoring aligns with ISO 27001 Annex A
5. CTA: "Book your ISO 27001 readiness assessment"

### 8.3 — New Page: `/resources/security-guide.html`

**Title:** "The Business Owner's Security Checklist — 20 Questions to Ask"

Format: Interactive checklist. Each question, user selects Yes/No. At the end:
- Score < 50%: "Your organization has critical gaps. Book a free assessment."
- Score 50–75%: "You're on the right track. See where you can improve."
- Score > 75%: "Strong posture. Let's maintain it professionally."

This page drives free scan requests. Every result links to `/scan`.

---

## PHASE 9 — TRUST ARCHITECTURE
**Goal:** Build passive trust signals into the site without appearing to beg for trust.

### 9.1 — Security Badge Strip (add to every page footer)

```html
<div class="trust-strip">
  <div class="trust-item">
    <span class="badge-icon">🔒</span>
    <span>All communications encrypted</span>
  </div>
  <div class="trust-item">
    <span class="badge-icon">📋</span>
    <span>NCA ECC 2.0 Aligned</span>
  </div>
  <div class="trust-item">
    <span class="badge-icon">🛡️</span>
    <span>ISO 27001 Framework</span>
  </div>
  <div class="trust-item">
    <span class="badge-icon">🔍</span>
    <span>Every report specialist-reviewed</span>
  </div>
  <div class="trust-item">
    <span class="badge-icon">🚫</span>
    <span>Your data is never shared or sold</span>
  </div>
</div>
```

### 9.2 — Live Threat Counter (subtle, homepage only)

```html
<!-- Subtle, factual, not exaggerated -->
<div class="threat-counter">
  <div class="stat">
    <span class="number" data-target="847">0</span>
    <span class="label">Vulnerabilities assessed this year</span>
  </div>
  <div class="stat">
    <span class="number" data-target="12">0</span>
    <span class="label">Critical findings resolved for clients</span>
  </div>
  <div class="stat">
    <span class="number" data-target="24">0</span>
    <span class="label">Hour maximum report turnaround</span>
  </div>
</div>
<!-- Update these numbers manually to stay realistic -->
```

### 9.3 — Responsible Disclosure Statement (footer)

```html
<a href="/security.txt" class="footer-link">Responsible Disclosure Policy</a>
```

Create `/security.txt`:
```
Contact: security@socroot.com
Preferred-Languages: en, ar
Policy: https://socroot.com/security-policy
```

This is a standard industry practice. Having it instantly signals legitimacy to any technical reviewer.

### 9.4 — Sample Report Download (homepage CTA section)

Create a sanitized version of the AsasEdu report with:
- Company name replaced with "Sample Educational Platform"
- Real findings kept (they demonstrate quality)
- SOC Root branding throughout

Link it as: "View a sample assessment report →" on the homepage.

---

## PHASE 10 — FINAL QUALITY CHECKLIST

Before pushing any of this live, the agent must verify:

### Backend Checks
```bash
# On Node B — run these manually:

# 1. Security headers present
curl -I https://socroot.com | grep -E "X-Content|X-Frame|Content-Security"

# 2. OTP endpoint working
curl -X POST https://socroot.com/api/send-otp \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com"}'
# Expected: {"success": true, "message": "Verification code sent"}

# 3. Injection attempt blocked
curl -X POST https://socroot.com/api/send-otp \
  -H "Content-Type: application/json" \
  -d '{"email":"<script>alert(1)</script>"}'
# Expected: {"success": false, "message": "Invalid email address"}

# 4. Rate limiter working
for i in $(seq 1 6); do
  curl -X POST https://socroot.com/api/send-otp \
    -H "Content-Type: application/json" \
    -d '{"email":"test@test.com"}' 
done
# Expected: 6th request returns 429 Too Many Requests

# 5. Scan request reaches Telegram
curl -X POST https://socroot.com/api/scan-request \
  -H "Content-Type: application/json" \
  -d '{"company_name":"Test Co","domain":"scanme.nmap.org","contact_name":"Test","email":"muath@test.com","newsletter":false}'
# Expected: Telegram message received, scan queued
```

### Frontend Checks (manual, in browser)
```
□ All pages load without .html extension
□ All phone numbers are clickable (tel: links)
□ All email addresses are clickable (mailto: links)
□ WhatsApp link opens correctly
□ No "Jordan" or "UAE" appears anywhere
□ No "AI-generated" or "automated" appears in user-visible text
□ OTP flow works end-to-end
□ Payment modal shows correct amounts
□ Mobile: all pages render correctly on 375px width
□ No console errors in browser DevTools
□ Page load time < 3 seconds (check with DevTools Network tab)
```

### Content Checks
```
□ No Lorem Ipsum anywhere
□ No placeholder emails (example@, test@)
□ No fake phone numbers
□ Contact page has all 5 contact methods with working links
□ All plan pages link to their dedicated detail page
□ Sample report download works
□ Security.txt accessible at socroot.com/security.txt
□ Compliance pages (NCA, ISO) are complete and accurate
□ Interactive checklist on /resources/security-guide works
```

---

## COMMIT PROTOCOL

After completing each phase, commit with:

```bash
git add .
git commit -m "feat(website-phase{N}): {description}"
git push origin main
```

Phase commit messages:
```
feat(website-phase1): Backend security hardening — headers, sanitization, rate limiting
feat(website-phase2): OTP email verification system — replace static code
feat(website-phase3): Free scan pipeline — Telegram integration + background scan
feat(website-phase4): Payment integration — Binance, PayPal, IBAN, CliQ
feat(website-phase5): Individual plan detail pages — 4 pages created
feat(website-phase6): Contact information — all real data, direct links
feat(website-phase7): Content audit — geo removal, AI language cleanup
feat(website-phase8): Compliance content — NCA ECC 2.0 + ISO 27001 pages
feat(website-phase9): Trust architecture — badges, sample report, security.txt
feat(website-phase10): QA complete — all checks passed
```

---

## DEPENDENCIES TO INSTALL ON NODE B

```bash
source /opt/synapse/venv/bin/activate
pip install flask-limiter flask-cors cryptography markupsafe
pip freeze > /opt/synapse/requirements.txt
```

---

## ENVIRONMENT VARIABLES TO ADD TO /opt/synapse/.env

```bash
# Add these new variables:
DATA_ENCRYPTION_KEY=<generate with: python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())">
FRONTEND_ORIGIN=https://socroot.com
```

---

*Plan Author: SOC Root Strategic Review — April 2026*  
*Executing Agent: Read every phase completely before starting Phase 1.*  
*Owner Contact for clarifications: Muath Yousef via Telegram @RootSoc*
