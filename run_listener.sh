#!/bin/bash
set -e

echo "=== Synapse SOC — Setup & Start ==="
echo ""

# 1. Install uv if not available
if ! command -v uv &>/dev/null; then
    echo "📦 Installing uv..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.local/bin:$PATH"
    echo "✅ uv installed."
fi

export PATH="$HOME/.local/bin:$PATH"

# 2. Sync virtual environment
echo ""
echo "📦 Syncing virtual environment..."
cd ~/Projects/ide-agentic-engine
uv sync

# 3. Run migrations — use direct SQL script (avoids Alembic ARRAY default bug)
echo ""
echo "🗄️  Running database migrations..."
cd ~/Projects/ide-agentic-engine
uv run python fix_migration.py || {
    echo "⚠️  Direct migration failed, trying alembic fallback..."
    cd ~/Projects/ide-agentic-engine/ide_engine
    uv run alembic upgrade head
}

# 4. Seed admin if needed
echo ""
echo "👤 Seeding admin user..."
uv run python seed_admin.py

# 5. Start server
echo ""
echo "🚀 Starting Synapse Backend on port 8000..."
fuser -k 8000/tcp 2>/dev/null && echo "⚠️  Previous process on port 8000 killed." || true

cd ~/Projects/ide-agentic-engine
PYTHONPATH=ide_engine uv run python -m uvicorn engine.webhook_listener:app \
    --app-dir ide_engine \
    --host 0.0.0.0 \
    --port 8000 \
    --reload
