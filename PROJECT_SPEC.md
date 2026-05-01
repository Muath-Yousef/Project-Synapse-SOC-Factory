# ide-agentic-engine v2.0 — Project Specification

## Purpose
CLI-based backend agentic engine serving as the "brain" for AI-powered IDEs
(VS Code, Antigravity). Manages cybersecurity tasks via MCP servers with
rigorous token optimisation.

## Architecture
- **Layer 0**: CLI entry (`engine/cli.py` — Typer)
- **Layer 1**: LangGraph orchestrator (`engine/orchestrator.py`)
- **Layer 2**: MCP Gateway / Batch Engine (`engine/mcp_gateway.py`) ★
- **Layer 3**: Tool servers (`tools/`) — filesystem, terminal, web, AST, Drive
- **Layer 4**: SOCROOT integration (`socroot/`) — Wazuh, Nuclei, n8n, EvidenceStore
- **Layer 5**: Cross-cutting — SOPS secrets, OTel tracing, Sentry errors, Redis cache

## Token Optimisation Rules (ENFORCE ALWAYS)
1. ALWAYS use `execute_batch_operations` — never call tools one at a time.
2. For file edits, use `apply_diff` — never rewrite entire files.
3. For reading code structure, use `get_code_skeleton` — never read full source.
4. Terminal output is auto-pruned to 50+50 lines — use `grep` for details.
5. Prompt cache is enabled for this spec — first block cached, yours billed.

## Available Tools (via execute_batch_operations)
- `read_file(path)` — read a file's full content
- `write_file(path, content)` — write/create a file
- `apply_diff(path, old_text, new_text)` — targeted patch
- `run_command(cmd, cwd?, timeout?)` — execute shell command
- `search_web(query, num_results?)` — web search
- `get_code_skeleton(path)` — AST signatures only
- `gdrive_read(file_id?, query?)` — Google Drive access
- `wazuh_query(query, limit?)` — SIEM alert search
- `nuclei_scan(target, severity?)` — vulnerability scan

## SOCROOT Context
Primary platform: Saudi cybersecurity SOC compliance for NCA ECC controls.
Evidence records are append-only with SHA-256 hash chaining.
Reports are generated as PDF using ReportLab.

## Coding Standards
- Python 3.10+ with strict type hints on all functions
- Pydantic v2 for all structured data
- Instructor + Anthropic for LLM calls
- asyncio throughout — no blocking I/O in the main event loop
- All secrets via SOPS + Age — never hardcoded
