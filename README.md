# deepsafe-scan

OpenClaw security scanner skill — powered by [DeepSafe](https://github.com/XiaoYiWeio/DeepSafe).

Full-featured preflight security audit across **4 modules**, with **LLM-enhanced semantic analysis** and **fingerprint-based caching**.

## Modules

| Module | What it scans | Requires Gateway |
|--------|--------------|:---:|
| **Posture** | `openclaw.json` — auth, network, TLS, sandbox, plugin permissions | No |
| **Skill** | Installed skills & MCP — 15+ pattern analyzers + LLM semantic audit | LLM audit only |
| **Memory** | Sessions & stored data — 27+ secret patterns, 9 PII patterns, injection | No |
| **Model** | Behavioral safety — 4 probes (persuasion, sandbagging, deception, HaluEval) | Yes |

## Install

```bash
clawhub install deepsafe-scan
```

Or manually:

```bash
cp -r deepsafe-skill ~/.openclaw/workspace/skills/deepsafe-scan
```

## Usage

Once installed, just ask your OpenClaw agent:

> "Run a security scan on my setup"
> "Check if my OpenClaw config is secure"
> "Scan my installed skills for vulnerabilities"
> "Run model safety probes"

### CLI Usage

```bash
# Full scan (all 4 modules, requires gateway for model probes & LLM)
python3 scripts/scan.py \
  --openclaw-root ~/.openclaw \
  --gateway-url http://127.0.0.1:PORT \
  --gateway-token YOUR_TOKEN \
  --format html \
  --output report.html

# Static-only scan (no gateway needed)
python3 scripts/scan.py \
  --openclaw-root ~/.openclaw \
  --modules posture,skill,memory \
  --no-llm \
  --format markdown

# Quick model-only probe
python3 scripts/scan.py \
  --modules model \
  --profile quick \
  --gateway-url http://127.0.0.1:PORT \
  --gateway-token TOKEN
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--openclaw-root` | `~/.openclaw` | Path to OpenClaw root |
| `--modules` | `posture,skill,memory,model` | Comma-separated modules |
| `--format` | `json` | Output format: `json`, `markdown`, `html` |
| `--output` | stdout | Write report to file |
| `--profile` | `quick` | Probe profile: `quick`, `standard`, `full` |
| `--gateway-url` | – | Gateway URL for LLM & model probes |
| `--gateway-token` | – | Gateway auth token (or `$OPENCLAW_GATEWAY_TOKEN`) |
| `--ttl-days` | `7` | Cache TTL in days |
| `--no-cache` | false | Skip cache |
| `--no-llm` | false | Skip LLM-enhanced analysis |
| `--debug` | false | Verbose debug output |

## What Gets Detected

### Posture Checks
- Gateway auth missing
- Network exposure (0.0.0.0 bind)
- Plaintext API keys
- HTTP without TLS
- Missing sandbox
- Dangerous plugin permissions
- Logging disabled

### Skill Analyzers (15+)
- Hidden Unicode / zero-width chars
- Prompt injection patterns
- Dangerous runtime (eval, exec, spawn)
- Base64/hex encoded payloads
- Sensitive file access (/etc/shadow, ~/.ssh)
- Embedded secrets
- System prompt extraction
- Command injection
- Data exfiltration patterns
- Destructive actions (delete, drop, wipe)
- Auto-execute without confirmation
- Excessive shell permissions
- Write + network combo
- LLM semantic audit (social engineering, implicit exfil)

### Secret Patterns (27+)
OpenAI, GitHub, AWS, Azure, GCP, Slack, Stripe, Twilio, SendGrid, JWT, SSH keys, Anthropic, Hugging Face, and more.

### PII Patterns (9)
Email, phone, SSN, credit cards, passport, IP addresses, driver's license, date of birth, street addresses.

### Model Safety Probes (4)
- **Persuasion**: Multi-turn manipulation success rate
- **Sandbagging**: Strategic capability concealment (SBS metric)
- **Deception**: Reasoning-action misalignment (DTR metric)
- **HaluEval**: Hallucination detection accuracy

## Scoring

- Each module: `max(1, 100 - deductions)` — minimum 1 point
- Deductions: CRITICAL=-10, HIGH=-5, MEDIUM=-2, LOW=-1
- Contribution per module: `floor(score / 4)` (1–25)
- **Total = sum of 4 contributions** (4–100)

## Dependencies

**Zero external dependencies.** Uses only Python 3 standard library:
- `re`, `json`, `os`, `pathlib` for scanning
- `urllib.request` for LLM/Gateway API calls
- `subprocess` for running model probe scripts
- `hashlib` for cache fingerprints
- `concurrent.futures` (in probes) for parallel execution

## Project Structure

```
deepsafe-skill/
├── SKILL.md                     # Skill definition for OpenClaw
├── README.md
├── data/                        # Bundled probe datasets
│   ├── manipulation_persuasion_topics.json
│   ├── sandbagging-samples-all.jsonl
│   ├── deceptionbench.json
│   ├── halueval_samples.json
│   └── qa_evaluation_instruction.txt
└── scripts/
    ├── scan.py                  # Main scanner (posture + skill + memory + LLM + cache + reports)
    └── probes/
        ├── persuasion_probe.py  # Persuasion & manipulation probe
        ├── sandbagging_probe.py # Strategic capability hiding probe
        ├── deception_probe.py   # Deception tendency probe
        └── halueval_probe.py    # Hallucination detection probe
```

## License

MIT
