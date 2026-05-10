#!/bin/bash
# ==============================================================================
# SOC Root Master Project Initialization Script
# Version: 1.0.0
# Description: Production-grade environment setup for AI-powered development.
# ==============================================================================

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Configurations
PROJECT_SPEC="PROJECT_SPEC.md"
STATE_FILE=".project_state.json"
ENV_FILE=".env"
ENV_GPG=".env.gpg"
CLAUDE_CONFIG="$HOME/.config/Claude/claude_desktop_config.json"
PROJECT_ROOT=$(pwd)

log() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# --- 1. IDEMPOTENCY & STATE CHECK ---
if [ -f "$STATE_FILE" ]; then
    INIT_DATE=$(jq -r '.init_date' "$STATE_FILE")
    log "Project already initialized on $INIT_DATE. Checking for updates..."
else
    log "First-time initialization starting..."
fi

# --- 2. PARSE PROJECT_SPEC.MD ---
# Simple YAML parser using sed/awk for specific keys
get_spec_val() {
    # Usage: get_spec_val "project" "name"
    # This is a basic parser for the provided structure
    grep -A 10 "$1:" "$PROJECT_SPEC" | grep "$2:" | head -n 1 | sed 's/.*: "\(.*\)".*/\1/' | sed 's/.*: \(.*\)/\1/' | tr -d '"' | xargs
}

PROJECT_NAME=$(get_spec_val "project" "name")
PROJECT_TYPE=$(get_spec_val "project" "type")

if [ -z "$PROJECT_NAME" ]; then
    error "Could not parse project name from $PROJECT_SPEC. Ensure it exists."
fi

log "Initializing project: $PROJECT_NAME ($PROJECT_TYPE)"

# --- 3. SECURE CREDENTIAL MANAGEMENT ---
setup_secrets() {
    if [ ! -f "$ENV_GPG" ]; then
        warn "Credentials not found. Starting first-time secret setup..."
        
        # Read from .env if it exists, otherwise prompt
        if [ -f "$ENV_FILE" ]; then
            log "Reading secrets from existing $ENV_FILE..."
            source "$ENV_FILE"
        else
            echo "🔐 Enter secrets (stored encrypted, never asked again):"
            read -p "GPG Passphrase (for encryption): " GPG_PASSPHRASE
            echo ""
            read -p "Gemini API Key: " GEMINI_API_KEY
            read -p "Cloudflare API Token: " CLOUDFLARE_API_TOKEN
            # Add others as needed or just use .env template
        fi

        # Ensure we have a passphrase
        if [ -z "$GPG_PASSPHRASE" ]; then
            error "GPG_PASSPHRASE is required for encryption."
        fi

        # Generate temp .env if needed
        cat > "$ENV_FILE.tmp" <<EOF
GEMINI_API_KEY=$GEMINI_API_KEY
CLOUDFLARE_API_TOKEN=$CLOUDFLARE_API_TOKEN
TELEGRAM_BOT_TOKEN=$TELEGRAM_BOT_TOKEN
GPG_PASSPHRASE=$GPG_PASSPHRASE
EOF
        
        # Encrypt with GPG
        gpg --batch --yes --passphrase "$GPG_PASSPHRASE" -c "$ENV_FILE.tmp"
        mv "$ENV_FILE.tmp.gpg" "$ENV_GPG"
        rm -f "$ENV_FILE.tmp" "$ENV_FILE" # Delete plaintext
        success "Credentials encrypted and saved to $ENV_GPG"
    else
        log "Using existing encrypted credentials."
    fi
}

load_secrets() {
    if [ -f "$ENV_GPG" ]; then
        # Try to get passphrase from environment or prompt
        if [ -z "$GPG_PASSPHRASE" ]; then
            read -sp "Enter GPG Passphrase to decrypt secrets: " GPG_PASSPHRASE
            echo ""
        fi
        gpg --batch --yes --passphrase "$GPG_PASSPHRASE" -d "$ENV_GPG" > "$ENV_FILE"
        source "$ENV_FILE"
        rm "$ENV_FILE" # Cleanup plaintext after sourcing
    fi
}

setup_secrets
load_secrets

# --- 4. DIRECTORY STRUCTURE ---
log "Creating directory structure..."
mkdir -p .gemini/antigravity/{skills,agents,knowledge,mcp}
mkdir -p mcp-servers docs n8n_workflows deployment
success "Directory structure ready."

# --- 5. ANTIGRAVITY CONFIGURATION ---

# A) Skills Auto-Generation
log "Generating AI skills..."
# Extract skills from PROJECT_SPEC.md (simple loop)
# For this script, we'll implement the ones in the prompt's example
cat > .gemini/antigravity/skills/evidence_verification.md <<'SKILL'
# Skill: Evidence Chain Verification Expert

## When to Use
Tasks involving hash chain integrity, WORM storage validation

## Core Knowledge
- SHA-256 computation
- Append-only JSONL format
- Chain verification: prev_hash matching

## Test Commands
python3 -c "from soc.evidence_store import verify_chain; print(verify_chain())"
SKILL

cat > .gemini/antigravity/skills/nca_mapping.md <<'SKILL'
# Skill: NCA Compliance Mapper

## When to Use
Mapping technical findings to National Cybersecurity Authority (NCA) controls.

## Core Knowledge
- ECC-1:2018 (Essential Cybersecurity Controls)
- Mapping scan results to control IDs (e.g., AM-1, VM-2)
- Gap analysis reporting
SKILL
success "Skills generated."

# B) Agent Orchestration
log "Configuring AI agents..."
cat > .gemini/antigravity/agents/security_analyzer.json <<EOF
{
  "name": "security_analyzer",
  "role": "threat_detection",
  "tools": ["wazuh", "nuclei", "nmap"],
  "parallelism": true,
  "priority": "high"
}
EOF
success "Agents configured."

# C) Persistent Context
log "Updating persistent context..."
cat > .gemini/antigravity/knowledge/project_context.md <<EOF
# Project: $PROJECT_NAME
Last updated: $(date)

## Tech Stack
$(grep -A 5 "tech_stack:" "$PROJECT_SPEC" | grep "-" | sed 's/    - //')

## Active Objectives
- Phase 1: Evidence System Implementation
- Phase 2: NCA Compliance Mapping
EOF
success "Context updated."

# --- 6. ENVIRONMENT SETUP ---
log "Setting up Python environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi
source venv/bin/activate
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
else
    pip install pydantic instructor opentelemetry-api
fi
success "Python environment ready."

# --- 7. MCP SERVER REGISTRATION ---
log "Registering MCP servers..."
# Ensure Claude config exists
mkdir -p "$(dirname "$CLAUDE_CONFIG")"
if [ ! -f "$CLAUDE_CONFIG" ]; then
    echo '{"mcpServers": {}}' > "$CLAUDE_CONFIG"
fi

# Use jq to merge new MCP servers
# Note: In a real script, you'd loop over the spec
TMP_CONFIG=$(mktemp)
jq --arg root "$PROJECT_ROOT" '.mcpServers["project-filesystem"] = {
    "command": "npx",
    "args": ["-y", "@modelcontextprotocol/server-filesystem", $root]
} | .mcpServers["project-git"] = {
    "command": "npx",
    "args": ["-y", "@modelcontextprotocol/server-git", "--repository", $root]
}' "$CLAUDE_CONFIG" > "$TMP_CONFIG"
mv "$TMP_CONFIG" "$CLAUDE_CONFIG"
success "MCP servers registered in Claude Desktop."

# --- 8. AUTOMATION (Workflows & Cron) ---
log "Setting up automation..."
# Cron job setup
(crontab -l 2>/dev/null | grep -v "scheduler.py"; echo "0 2 * * 1 cd $PROJECT_ROOT && ./venv/bin/python3 scheduler.py --run-due") | crontab -
success "Automation tasks configured."

# --- 9. SYSTEM MODIFICATIONS ---
log "Applying system modifications..."
if [ -f ".gemini/antigravity/settings.json" ]; then
    TMP_SETTINGS=$(mktemp)
    jq '.auto_commit = true | .max_parallel_agents = 5' .gemini/antigravity/settings.json > "$TMP_SETTINGS"
    mv "$TMP_SETTINGS" .gemini/antigravity/settings.json
else
    cat > .gemini/antigravity/settings.json <<EOF
{
    "auto_commit": true,
    "max_parallel_agents": 5
}
EOF
fi
success "System modifications applied."

# --- 10. VERIFICATION ---
log "Running post-initialization verification..."
FAILED=0

verify() {
    if eval "$2" >/dev/null 2>&1; then
        echo -e "  ✅ $1"
    else
        echo -e "  ❌ $1 FAILED"
        FAILED=1
    fi
}

verify "Python venv" "test -d venv"
verify "GPG Credentials" "test -f $ENV_GPG"
verify "Skills Presence" "test -f .gemini/antigravity/skills/evidence_verification.md"
verify "Claude Config" "test -f $CLAUDE_CONFIG"
verify "State File" "test -f $STATE_FILE" || true # Will be created next

if [ $FAILED -eq 0 ]; then
    success "All verification checks passed!"
else
    warn "Some verification checks failed. Review the logs."
fi

# --- 11. SAVE STATE ---
cat > "$STATE_FILE" <<EOF
{
  "initialized": true,
  "init_date": "$(date -Iseconds)",
  "last_run": "$(date -Iseconds)",
  "project_name": "$PROJECT_NAME",
  "phase": "Initialized",
  "secrets_configured": true
}
EOF

echo -e "\n${BLUE}==================================================${NC}"
echo -e "${GREEN}🎉 Project Initialization COMPLETE${NC}"
echo -e "Run: ${YELLOW}source venv/bin/activate${NC} to start."
echo -e "${BLUE}==================================================${NC}"