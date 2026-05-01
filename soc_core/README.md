# Project Synapse — AI Security Orchestration Framework

> Private MSSP toolchain for automated vulnerability triage,
> contextual false-positive filtering, and SOAR response execution.

## Architecture

```
Scan (Nmap + Nuclei)
    → Parse & Aggregate (JSON unified format)
    → RAG Context Injection (ChromaDB + client profiles)
    → LLM Triage (Gemini 2.5 Flash — threat modeler perspective)
    → SOAR Response (SafetyGuard → Router → Playbook → Audit)
```

## Phases Completed

| Phase | Description | Status |
|-------|-------------|--------|
| 1 | Data Standardization & Parsers | ✅ |
| 2 | RAG & Vector Memory | ✅ |
| 3 | LLM Orchestration | ✅ |
| 4 | Meta-Agent (Auto Tool Generation) | ✅ |
| 5 | Executive Reporting | ✅ |
| 6 | Git Baseline & Live LLM | ✅ |
| 7 | SOAR Integration | ✅ |
| 8 | GitHub Deployment | 🔄 |

## Setup

```bash
cp .env.template .env
# Fill in API keys in .env
pip install -r requirements.txt
python3 tests/test_phase7.py
```

## Security Notice

This tool performs active scanning. Only use against
systems you own or have explicit written authorization to test.
