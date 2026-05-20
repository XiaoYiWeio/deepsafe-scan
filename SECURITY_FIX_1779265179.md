# 安全漏洞修复：deepsafe-scan

## 发现摘要

| 漏洞类型 | 数量 |
|----------|------|
| hardcoded_secret | 68 |
| hardcoded_url | 2 |

## 漏洞详情（Top 5）

### [HIGH] 硬编码密钥/密码 — demo/attacker-server.py:35

**CWE**: CWE-798

**问题代码**:
```
──────────────{RESET} """  LABELS = {     "/exfil/api-keys":      ("API KEYS STOLEN",         RED),     "/e
```

**建议修复**:
```
# 修复前：硬编码密钥（危险！）
# api-key

# 修复后：使用环境变量
import os
SECRET_KEY = os.environ.get("API_KEY", "")
if not SECRET_KEY:
    raise ValueError("API_KEY environment variable is required")

```

---
### [HIGH] 硬编码密钥/密码 — demo/attacker-server.py:61

**CWE**: CWE-798

**问题代码**:
```
'━'*60}{RESET}")          if self.path == "/exfil/api-keys":             params = parse_qs(body)
```

**建议修复**:
```
# 修复前：硬编码密钥（危险！）
# api-key

# 修复后：使用环境变量
import os
SECRET_KEY = os.environ.get("API_KEY", "")
if not SECRET_KEY:
    raise ValueError("API_KEY environment variable is required")

```

---
### [HIGH] 硬编码密钥/密码 — scripts/llm_client.py:5

**CWE**: CWE-798

**问题代码**:
```
in this priority order:   1. Explicit api_base + api_key arguments   2. OpenClaw Gateway  (reads ~/.opencl
```

**建议修复**:
```
# 修复前：硬编码密钥（危险！）
# api_key

# 修复后：使用环境变量
import os
SECRET_KEY = os.environ.get("API_KEY", "")
if not SECRET_KEY:
    raise ValueError("API_KEY environment variable is required")

```

---
### [HIGH] 硬编码密钥/密码 — scripts/llm_client.py:7

**CWE**: CWE-798

**问题代码**:
```
(reads ~/.openclaw/openclaw.json)   3. ANTHROPIC_API_KEY environment variable  (Claude Code users)   4. OP
```

**建议修复**:
```
# 修复前：硬编码密钥（危险！）
# API_KEY

# 修复后：使用环境变量
import os
SECRET_KEY = os.environ.get("API_KEY", "")
if not SECRET_KEY:
    raise ValueError("API_KEY environment variable is required")

```

---
### [HIGH] 硬编码密钥/密码 — scripts/llm_client.py:8

**CWE**: CWE-798

**问题代码**:
```
ronment variable  (Claude Code users)   4. OPENAI_API_KEY    environment variable  (Codex users, most devel
```

**建议修复**:
```
# 修复前：硬编码密钥（危险！）
# API_KEY

# 修复后：使用环境变量
import os
SECRET_KEY = os.environ.get("API_KEY", "")
if not SECRET_KEY:
    raise ValueError("API_KEY environment variable is required")

```

---
## 注意事项

- 此 PR 包含安全修复，建议优先 review
- 所有修复均遵循安全编码最佳实践
- 如有疑问，请参考 OWASP 安全指南

## CLA

贡献此修复即表示您同意将代码按项目原有许可证发布。