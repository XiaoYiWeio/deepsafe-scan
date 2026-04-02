---
name: deepsafe-scan
description: "Preflight security scanner for AI coding agents — scans deployment config, skills/MCP servers, memory/sessions, and AI agent config files (hooks injection) for secrets, PII, prompt injection, and dangerous patterns. Runs 4 model behavior probes (persuasion, sandbagging, deception, hallucination). Supports LLM-enhanced semantic analysis. Works with OpenClaw, Claude Code, Cursor, and Codex. Use when a user asks for a security audit, health check, or wants to scan their AI agent setup for vulnerabilities."
metadata:
  {
    "openclaw":
      {
        "emoji": "🛡️",
        "requires": { "bins": ["python3"] },
        "install":
          [
            {
              "id": "brew-python3",
              "kind": "brew",
              "package": "python3",
              "bins": ["python3"],
              "label": "Install Python 3 (brew)",
            },
          ],
      },
  }
allowed-tools: Bash(python3:*), Bash(cat:*), Read
---

# DeepSafe Scan — Preflight Security Scanner for AI Coding Agents

Full-featured preflight security scanner across **5 dimensions**:
**Posture** (config), **Skill** (skills & MCP), **Memory** (sessions), **Hooks** (agent config injection), **Model** (behavioral safety probes).

Works with **OpenClaw, Claude Code, Cursor, and Codex**. LLM features auto-detect credentials — no manual configuration needed.

## When to Use

- User asks to "scan", "audit", "check security", or "health check" their AI setup
- User installs a new skill, MCP server, or clones a project with agent configs
- User wants to know if any secrets or PII are leaked in session history
- User asks about hooks injection risks (Claude Code settings.json, .cursorrules, etc.)
- User wants to probe model behavior for manipulation, deception, or hallucination risks

## How to Run

### Quick static scan (no API key needed)

```bash
python3 {baseDir}/scripts/scan.py --modules posture,skill,memory,hooks --scan-dir . --no-llm --format markdown
```

### Full scan (auto-detects API credentials)

```bash
# OpenClaw (reads gateway config automatically)
python3 {baseDir}/scripts/scan.py --openclaw-root ~/.openclaw --format html --output /tmp/deepsafe-report.html

# Claude Code / Cursor / Codex (uses ANTHROPIC_API_KEY or OPENAI_API_KEY)
python3 {baseDir}/scripts/scan.py --modules posture,skill,memory,hooks,model --scan-dir . --format html --output /tmp/deepsafe-report.html
```

### Targeted scans

```bash
# Hooks injection only (fastest — checks .claude/settings.json, .cursorrules, etc.)
python3 {baseDir}/scripts/scan.py --modules hooks --scan-dir . --no-llm --format markdown

# Memory scan only (check for leaked secrets/PII)
python3 {baseDir}/scripts/scan.py --openclaw-root ~/.openclaw --modules memory --no-llm

# Model behavior probes only
python3 {baseDir}/scripts/scan.py --openclaw-root ~/.openclaw --modules model --profile quick
```

### Output options

```bash
python3 {baseDir}/scripts/scan.py --format json      # machine-readable
python3 {baseDir}/scripts/scan.py --format markdown  # human-readable summary
python3 {baseDir}/scripts/scan.py --format html --output /tmp/report.html  # visual report
```

### Cache control

```bash
python3 {baseDir}/scripts/scan.py --ttl-days 3   # cache for 3 days
python3 {baseDir}/scripts/scan.py --no-cache      # always fresh scan
```

## Interpreting Results

### Scores
- Each module scores 1-100 (100 = clean, deductions per finding, minimum 1)
- Module contribution = floor(score / 4), range 1–25
- **Total = sum of 4 contributions, max 100**

### Severity Levels
- **CRITICAL** (-10 pts): Immediate exploitation risk — secrets exposed, no auth, data exfiltration chains
- **HIGH** (-5 pts): Serious risk — prompt injection, sensitive file access, network exposure
- **MEDIUM** (-2 pts): Moderate risk — hardcoded keys, missing logs, supply chain concerns
- **LOW** (-1 pt): Minor improvement — non-standard endpoints, missing metadata

### Risk Ratings
- 85-100: LOW RISK (green)
- 65-84: MEDIUM RISK (yellow)
- 40-64: HIGH RISK (orange)
- 4-39: CRITICAL RISK (red)

## After Scanning

1. Present the total score and per-module breakdown to the user
2. List CRITICAL and HIGH findings first with clear explanations
3. For each finding, explain **what the risk is** and **how to fix it**
4. Offer to help fix issues (e.g., "want me to add auth to your gateway config?")

## What Gets Scanned

### Posture Module (deployment config)
Reads `openclaw.json` and checks: gateway auth, network exposure, API key handling, TLS, plugin permissions, MCP server risks, logging, sandboxing.

### Skill Module (installed skills & MCP)
Scans all files in `workspace/skills/`, `mcp/`, `mcp-servers/` for: hidden unicode, prompt injection, dangerous runtime calls, encoded payloads, sensitive file references, hardcoded secrets, system prompt extraction, command injection, data exfiltration patterns, destructive actions, auto-execute without confirmation, excessive permissions.

With `--gateway-url` provided (and `--no-llm` not set), also runs **LLM-enhanced semantic analysis** on each skill's SKILL.md for social engineering, implicit data exfiltration, and deeper pattern recognition.

### Memory Module (sessions & stored data)
Scans `agents/`, `credentials/`, `identity/`, `logs/`, `workspace/` for: 27+ secret patterns (API keys for OpenAI, GitHub, AWS, Slack, Stripe, etc.), 9 PII patterns (email, phone, ID numbers, credit cards), persistent prompt injection traces.

### Model Module (4 behavioral safety probes)
Requires `--gateway-url` and `--gateway-token`. Runs:
- **Persuasion Probe**: Tests if the model can manipulate user opinions in multi-turn conversation
- **Sandbagging Probe**: Tests if the model can strategically hide capabilities (performance control)
- **Deception Probe**: 3-phase test for reasoning/action misalignment (DTR metric)
- **HaluEval Probe**: Tests hallucination detection accuracy on QA benchmarks

Each probe produces a finding with risk level and score. Average across probes = module score.
