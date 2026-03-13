---
name: deepsafe-scan
description: "Preflight security scanner for OpenClaw — scans deployment config, skills, memory/sessions for secrets, PII, prompt injection, and dangerous patterns. Runs 4 model behavior probes (persuasion, sandbagging, deception, hallucination). Supports LLM-enhanced semantic analysis. Use when a user asks for a security audit, health check, or wants to scan their OpenClaw setup for vulnerabilities."
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

# DeepSafe Scan — OpenClaw Security Scanner

Full-featured preflight security scanner across **4 dimensions**:
**Posture** (deployment config), **Skill** (installed skills & MCP), **Memory** (sessions & stored data), **Model** (behavioral safety probes).

Optionally uses **LLM-enhanced semantic analysis** for deeper skill code inspection.

## When to Use

- User asks to "scan", "audit", "check security", or "health check" their OpenClaw setup
- User installs a new skill and wants to verify it's safe
- User wants to know if any secrets or PII are leaked in session history
- User asks about the security posture of their deployment
- User wants to probe model behavior for manipulation, deception, or hallucination risks

## How to Run

**IMPORTANT: Always use `--open` flag by default.** This generates an HTML report and auto-opens it in the user's browser — this is the expected default experience.

### Default scan (recommended — always use this unless user asks otherwise)

```bash
python3 {baseDir}/scripts/scan.py --openclaw-root ~/.openclaw --open
```

This auto-reads gateway config from `openclaw.json`, runs all 4 modules, generates a full HTML report, saves it to `~/.openclaw/deepsafe/reports/`, and opens it in the browser. No extra flags needed.

### Scan specific modules only

```bash
python3 {baseDir}/scripts/scan.py --openclaw-root ~/.openclaw --modules posture,skill --open
python3 {baseDir}/scripts/scan.py --openclaw-root ~/.openclaw --modules memory --open
python3 {baseDir}/scripts/scan.py --openclaw-root ~/.openclaw --modules model --open
```

### Static-only scan (no LLM, no model probes)

```bash
python3 {baseDir}/scripts/scan.py --openclaw-root ~/.openclaw --modules posture,skill,memory --no-llm --open
```

### Profile options

```bash
# Quick scan (small probe datasets, fast) — default
python3 {baseDir}/scripts/scan.py --profile quick --open

# Full comprehensive scan (complete datasets, thorough)
python3 {baseDir}/scripts/scan.py --profile full --open
```

### Output to chat instead of browser (only if user specifically asks)

```bash
# JSON output to stdout
python3 {baseDir}/scripts/scan.py --format json

# Markdown summary to stdout
python3 {baseDir}/scripts/scan.py --format markdown
```

### Cache control

```bash
# Reports are cached for 7 days by default (by fingerprint)
python3 {baseDir}/scripts/scan.py --ttl-days 3 --open

# Force fresh scan (skip cache)
python3 {baseDir}/scripts/scan.py --no-cache --open
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
