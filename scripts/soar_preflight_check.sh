#!/usr/bin/env bash
# ── Phase 4.2: SOAR Go-Live Preflight Check ────────────────────────────────
# Antigravity verifies all conditions. Muath provides written authorization.
# See H-4 (Manual Tasks) for required authorization string.

set -euo pipefail

echo "========== SOAR Go-Live Preflight Check =========="

PROJECT_ROOT="/media/kyrie/VMs1/Cybersecurity_Tools_Automation"
cd "$PROJECT_ROOT"
source venv/bin/activate

# Load .env if present
if [ -f "$PROJECT_ROOT/.env" ]; then
    set -a
    source "$PROJECT_ROOT/.env"
    set +a
fi

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

# 1. RFC1918 safety test
RFC_TEST=$(python3 -c "
import sys
sys.path.insert(0, '.')
from soc.soar_evidence_bridge import SafetyGuard
safe, reason = SafetyGuard.is_safe_to_block('10.0.0.1', set())
print('OK' if not safe else 'FAIL — RFC1918 not protected')
" 2>&1)
check "SafetyGuard RFC1918 protection" "$RFC_TEST"

# 2. Cloudflare CDN safety test
CDN_TEST=$(python3 -c "
import sys
sys.path.insert(0, '.')
from soc.soar_evidence_bridge import SafetyGuard
safe, reason = SafetyGuard.is_safe_to_block('104.16.1.1', set())
print('OK' if not safe else 'FAIL — CDN not protected')
" 2>&1)
check "SafetyGuard CDN IP protection" "$CDN_TEST"

# 3. Client whitelist test
WL_TEST=$(python3 -c "
import sys
sys.path.insert(0, '.')
from soc.soar_evidence_bridge import SafetyGuard
safe, reason = SafetyGuard.is_safe_to_block('1.2.3.4', {'1.2.3.4'})
print('OK' if not safe else 'FAIL — whitelist not respected')
" 2>&1)
check "SafetyGuard client whitelist" "$WL_TEST"

# 4. DNS finding blocked
DNS_TEST=$(python3 -c "
import sys
sys.path.insert(0, '.')
from soc.soar_evidence_bridge import SafetyGuard
safe, reason = SafetyGuard.validate_soar_action('cloudflare_block_ip', {'source': 'dns_finding', 'ip': '1.2.3.4'}, set())
print('OK' if not safe else 'FAIL — DNS finding not blocked')
" 2>&1)
check "DNS findings NOTIFY_ONLY" "$DNS_TEST"

# 5. Malware escalation check
MALWARE_TEST=$(python3 -c "
import sys
sys.path.insert(0, '.')
from soc.soar_evidence_bridge import SafetyGuard
safe, reason = SafetyGuard.validate_soar_action('cloudflare_block_ip', {'alert_type': 'ransomware', 'ip': '5.6.7.8'}, set())
print('OK' if not safe else 'FAIL — ransomware not escalated')
" 2>&1)
check "Malware/ransomware human escalation" "$MALWARE_TEST"

# 6. SOAR evidence bridge generates records
EVIDENCE_TEST=$(python3 -c "
import tempfile, os, sys
sys.path.insert(0, '.')
tmp = tempfile.mkdtemp()
os.environ['EVIDENCE_ROOT'] = tmp
os.environ['SOAR_DRY_RUN'] = 'true'
# Reload module to pick up env
import importlib
import soc.soar_evidence_bridge as bridge
importlib.reload(bridge)
from soc.evidence_store import EvidenceStore
store = EvidenceStore('test_client')
result = bridge.execute_soar_action_with_evidence(
    'cloudflare_block_ip',
    {'ip': '203.0.113.5', 'rule_id': 'test_rule'},
    'test_client', 'scan_001', store, set()
)
print('OK' if result is not None else 'FAIL — no evidence record')
" 2>&1)
check "SOAR evidence bridge records" "$EVIDENCE_TEST"

# 7. Cloudflare credentials check
CF_TEST=$(python3 -c "
import os
token = os.getenv('CF_API_TOKEN', '')
zone = os.getenv('CF_ZONE_ID', '')
if token and zone:
    print('OK')
else:
    print('MISSING_CF_CREDS — set CF_API_TOKEN and CF_ZONE_ID in .env')
")
check "Cloudflare credentials present" "$CF_TEST"

# 8. Telegram channels check
if [ -n "${TELEGRAM_BOT_TOKEN:-}" ] && [ -n "${TELEGRAM_CHAT_ID_FINDINGS:-}" ]; then
    TG_TEST=$(curl -s "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
        -d "chat_id=${TELEGRAM_CHAT_ID_FINDINGS}&text=SOC+Root+SOAR+preflight+test" \
        | python3 -c 'import sys,json; d=json.load(sys.stdin); print("OK" if d.get("ok") else "FAIL")' 2>/dev/null || echo "FAIL — curl error")
    check "Telegram Findings channel" "$TG_TEST"
else
    echo "⚠️  SKIPPED: Telegram credentials not set"
fi

echo ""
echo "=========================================="
echo "Preflight Results: $PASS passed, $FAIL failed"

if [ "$FAIL" -eq 0 ]; then
    echo "✅ ALL CHECKS PASSED"
    echo ""
    echo "Next step: Receive H-4 authorization from Muath:"
    echo "  'SOAR GO LIVE — AUTHORIZED BY MUATH [date]'"
    echo ""
    echo "Then run:"
    echo "  sed -i 's/SOAR_DRY_RUN=true/SOAR_DRY_RUN=false/' .env"
    echo "  grep SOAR_DRY_RUN .env"
else
    echo "❌ $FAIL checks failed — resolve before DRY_RUN flip"
    exit 1
fi
