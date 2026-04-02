# DeepSafe Scan — Claude Code Integration

This directory contains **deepsafe-scan**, a preflight security scanner for AI agent environments.

## What it does

Scans for security risks across 5 dimensions:

| Module | What it checks | Needs API? |
|--------|---------------|-----------|
| **posture** | openclaw.json / .env config security | No |
| **skill** | Installed skills & MCP servers — 15+ static analyzers | No |
| **memory** | Session data — 27+ secret patterns, 9 PII patterns | No |
| **hooks** | `.claude/settings.json`, `.cursorrules`, `.vscode/tasks.json` — 12 injection patterns | No |
| **model** | 4 behavioral safety probes (persuasion, sandbagging, deception, hallucination) | Yes (ANTHROPIC_API_KEY) |

## When to use

Invoke this scanner when the user asks to:
- "Check if this project's AI config is safe"
- "Scan my setup for security issues"
- "Audit my skills/MCP servers"
- "Check for prompt injection in agent configs"
- "Run a security scan before I start using this project"

## How to run

```bash
# Quick static scan (no API key needed) — posture, skill, memory, hooks
python3 {skill_dir}/scripts/scan.py \
  --modules posture,skill,memory,hooks \
  --scan-dir . \
  --no-llm \
  --format markdown

# Full scan with LLM-enhanced analysis (uses ANTHROPIC_API_KEY automatically)
python3 {skill_dir}/scripts/scan.py \
  --modules posture,skill,memory,hooks,model \
  --scan-dir . \
  --format html \
  --output /tmp/deepsafe-report.html

# Scan only hooks (fastest — checks agent config files in current directory)
python3 {skill_dir}/scripts/scan.py \
  --modules hooks \
  --scan-dir . \
  --no-llm \
  --format markdown

# OpenClaw users (auto-reads gateway config)
python3 {skill_dir}/scripts/scan.py \
  --openclaw-root ~/.openclaw \
  --format html \
  --output /tmp/deepsafe-report.html
```

Replace `{skill_dir}` with the actual path to this directory.

## After scanning

1. Present the total score and per-module breakdown
2. List CRITICAL and HIGH findings first with clear explanations
3. For each finding, explain **what the risk is** and **how to fix it**
4. Offer to help fix issues

## Score interpretation

| Score | Risk Level |
|-------|-----------|
| 85–100 | LOW RISK |
| 65–84 | MEDIUM RISK |
| 40–64 | HIGH RISK |
| 4–39 | CRITICAL RISK |

## LLM API auto-detection

The scanner automatically uses `ANTHROPIC_API_KEY` if set (Claude Code users always have this). No manual configuration needed for:
- LLM-enhanced skill semantic analysis
- Model safety probes (persuasion, sandbagging, deception, hallucination)
