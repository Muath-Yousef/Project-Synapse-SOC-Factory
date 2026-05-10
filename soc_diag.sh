#!/bin/bash

# SOCROOT / Project-Synapse-SOC-Factory Diagnostic Script
# Optimized for high-performance and low-token consumption.

OUTPUT_FILE="diag_report.txt"
exec > >(tee "$OUTPUT_FILE") 2>&1

echo "=== SOCROOT SYSTEM DIAGNOSTICS ==="
echo "Timestamp: $(date -u)"
echo ""

# 1. STRUCTURE & FOOTPRINT (Depth 3 to save tokens)
echo "[1] DIRECTORY STRUCTURE"
tree -L 3 -I "node_modules|.git|.venv|__pycache__|dist"
echo ""

# 2. ENVIRONMENT CHECK
echo "[2] RUNTIME ENVIRONMENT"
python3 --version | tr -d '\n' && echo " | $(which python3)"
uv --version 2>/dev/null || echo "uv: not found"
docker --version 2>/dev/null || echo "docker: not found"
node --version 2>/dev/null || echo "node: not found"
echo ""

# 3. COMPONENT INTEGRITY (Check for key files)
echo "[3] CORE COMPONENTS"
[ -f "run_listener.sh" ] && echo "✅ Master Hook: Found" || echo "❌ Master Hook: Missing"
[ -d "packages/ide-engine" ] && echo "✅ Engine: Found" || echo "❌ Engine: Missing"
[ -f "profiles/api_keys.yaml" ] && echo "✅ API Keys: Found" || echo "❌ API Keys: Missing"
echo ""

# 4. DEPENDENCY ANALYSIS (Summarized)
echo "[4] DEPENDENCIES"
find . -maxdepth 4 -name "pyproject.toml" -exec echo "--- {} ---" \; -exec grep -E "dependencies|langgraph|mcp|fastapi" {} \;
echo ""

# 5. SECRET & CONFIG SECURITY (Look for placeholders/leaks)
echo "[5] CONFIG & SECRETS"
grep -rE "API_KEY|PASSWORD|SECRET|TOKEN" . --exclude-dir={.git,node_modules,.venv} --include=*.{env,yaml,py,sh} | grep -v "value:" | head -n 10
echo ""

# 6. API & INTEGRATION POINTS
echo "[6] API ENDPOINTS"
grep -r "@app\." . --include=*.py | head -n 15
echo ""

# 7. CODE QUALITY & ANOMALIES
echo "[7] TODOs & POTENTIAL DEBTS"
grep -rnEi "TODO|FIXME|XXX|HACK" . --exclude-dir={.git,node_modules,.venv} | head -n 10
echo ""

# 8. RECENT LOGS (Critical Errors)
echo "[8] CRITICAL ERROR LOGS"
find . -name "*.log" -exec tail -n 5 {} \; 2>/dev/null
echo ""

# 9. SUMMARY STATS
echo "[9] PROJECT METRICS"
echo "Total Python Files: $(find . -name "*.py" | wc -l)"
echo "Total Shell Scripts: $(find . -name "*.sh" | wc -l)"
echo "Total YAML Configs: $(find . -name "*.yaml" | wc -l)"

echo ""
echo "=== DIAGNOSTIC COMPLETE ==="
