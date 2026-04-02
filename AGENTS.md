# DeepSafe Scan — Agent Instructions

This is the **deepsafe-scan** security scanner for AI agent environments.
Works with: OpenClaw, Claude Code, Cursor, Codex, and any AI agent.

## What this tool does

Scans for security risks in:
- AI agent config files (`.claude/settings.json`, `.cursorrules`, `.vscode/tasks.json`, etc.)
- Installed skills and MCP servers
- Session/memory data for leaked secrets and PII
- Deployment configuration
- Model behavioral safety (optional, needs API key)

## When to use

Use this scanner when:
- The user asks about security, audit, or vulnerability scan of their AI setup
- The user is about to install a new skill or MCP server
- The user clones a new project with agent config files
- The user reports unexpected behavior (possible prompt injection)

## How to invoke

**Static scan (no API key needed):**
```bash
python3 scripts/scan.py --modules posture,skill,memory,hooks --scan-dir . --no-llm --format markdown
```

**Full scan (auto-detects ANTHROPIC_API_KEY or OPENAI_API_KEY):**
```bash
python3 scripts/scan.py --modules posture,skill,memory,hooks,model --scan-dir . --format markdown
```

**OpenClaw users:**
```bash
python3 scripts/scan.py --openclaw-root ~/.openclaw --format html --output /tmp/report.html
```

**Targeted hooks-only scan (fastest):**
```bash
python3 scripts/scan.py --modules hooks --scan-dir . --no-llm --format markdown
```

## Modules

| Module | Scans | API Required |
|--------|-------|-------------|
| `posture` | openclaw.json or .env config files | No |
| `skill` | Skills, MCP servers — 15+ static analyzers | No (LLM analysis optional) |
| `memory` | Session data, credentials — 27+ secret patterns, 9 PII patterns | No |
| `hooks` | AI agent config files — 12 injection patterns | No |
| `model` | Behavioral safety probes (persuasion, sandbagging, deception, hallucination) | Yes |

## Interpreting results

**Scores:** Each module scores 1-100 (100 = clean). Total score is the average across active modules.

| Score | Risk |
|-------|------|
| 85–100 | LOW |
| 65–84 | MEDIUM |
| 40–64 | HIGH |
| 1–39 | CRITICAL |

**After scanning:** Present CRITICAL and HIGH findings first. Explain the risk and remediation for each. Offer to fix issues.

## LLM auto-detection

The scanner auto-detects API credentials in this order:
1. `--api-base` / `--api-key` flags
2. OpenClaw Gateway (`~/.openclaw/openclaw.json`)
3. `ANTHROPIC_API_KEY` environment variable
4. `OPENAI_API_KEY` environment variable
5. No API → static analysis only (all modules except model probes still work)
