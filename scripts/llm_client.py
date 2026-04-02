"""
Multi-platform LLM client for DeepSafe Scan.

Auto-detects API credentials in this priority order:
  1. Explicit api_base + api_key arguments
  2. OpenClaw Gateway  (reads ~/.openclaw/openclaw.json)
  3. ANTHROPIC_API_KEY environment variable  (Claude Code users)
  4. OPENAI_API_KEY    environment variable  (Codex users, most developers)
  5. None → graceful degradation (static analysis only, no LLM features)

Zero external dependencies — uses urllib only.
"""

import json
import os
import sys
from pathlib import Path
from typing import Optional
from urllib.error import HTTPError, URLError
from urllib import request as urllib_request


class LLMClient:
    """Unified LLM client supporting OpenAI-compatible and Anthropic APIs."""

    def __init__(self, api_base: str, api_key: str,
                 model: str = "auto", provider: str = "openai"):
        self.api_base = api_base.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.provider = provider  # "openai" or "anthropic"

    def chat(self, messages: list, max_tokens: int = 2048,
             temperature: float = 0.2, timeout: int = 120) -> str:
        if self.provider == "anthropic":
            return self._chat_anthropic(messages, max_tokens, temperature, timeout)
        return self._chat_openai(messages, max_tokens, temperature, timeout)

    def _chat_openai(self, messages: list, max_tokens: int,
                     temperature: float, timeout: int) -> str:
        url = f"{self.api_base}/chat/completions"
        payload = json.dumps({
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }).encode("utf-8")
        req = urllib_request.Request(url, data=payload, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Authorization", f"Bearer {self.api_key}")
        try:
            with urllib_request.urlopen(req, timeout=timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except (HTTPError, URLError, Exception):
            return ""
        choices = body.get("choices", [])
        if not choices or not isinstance(choices[0], dict):
            return ""
        msg = choices[0].get("message", {})
        content = msg.get("content")
        if isinstance(content, str):
            return content.strip()
        if isinstance(content, list):
            parts = [i.get("text", "") for i in content if isinstance(i, dict)]
            if parts:
                return "\n".join(parts).strip()
        reasoning = msg.get("reasoning_content")
        if isinstance(reasoning, str):
            return reasoning.strip()
        return ""

    def _chat_anthropic(self, messages: list, max_tokens: int,
                        temperature: float, timeout: int) -> str:
        url = f"{self.api_base}/messages"
        system_msg = ""
        api_messages = []
        for m in messages:
            if m.get("role") == "system":
                system_msg = m["content"]
            else:
                api_messages.append({"role": m["role"], "content": m["content"]})

        payload_dict: dict = {
            "model": self.model,
            "messages": api_messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if system_msg:
            payload_dict["system"] = system_msg

        payload = json.dumps(payload_dict).encode("utf-8")
        req = urllib_request.Request(url, data=payload, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("x-api-key", self.api_key)
        req.add_header("anthropic-version", "2023-06-01")
        try:
            with urllib_request.urlopen(req, timeout=timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except (HTTPError, URLError, Exception):
            return ""
        content_blocks = body.get("content", [])
        if isinstance(content_blocks, list):
            texts = [b.get("text", "") for b in content_blocks if isinstance(b, dict)]
            return "\n".join(texts).strip()
        return ""


def resolve_llm_client(
    explicit_base: str = "",
    explicit_key: str = "",
    explicit_model: str = "",
    explicit_provider: str = "",
    openclaw_root: str = "",
    debug: bool = False,
) -> Optional[LLMClient]:
    """
    Auto-detect LLM credentials. Returns LLMClient or None.

    Returns None when no credentials are found — callers should degrade
    gracefully (skip LLM-dependent features, keep static analysis).
    """

    # 1. Explicit arguments take highest priority
    if explicit_base and explicit_key:
        provider = explicit_provider or "openai"
        model = explicit_model or ("openclaw:main" if "openclaw" in explicit_base else "auto")
        if debug:
            print(f"[llm] explicit api_base={explicit_base} provider={provider}", file=sys.stderr)
        return LLMClient(explicit_base, explicit_key, model=model, provider=provider)

    # 2. OpenClaw Gateway (auto-read from openclaw.json)
    root = openclaw_root or os.path.expanduser("~/.openclaw")
    client = _try_openclaw_gateway(root, debug)
    if client:
        return client

    # 3. ANTHROPIC_API_KEY (Claude Code users always have this)
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if anthropic_key:
        model = explicit_model or "claude-sonnet-4-20250514"
        if debug:
            print(f"[llm] ANTHROPIC_API_KEY found, model={model}", file=sys.stderr)
        return LLMClient(
            "https://api.anthropic.com/v1", anthropic_key,
            model=model, provider="anthropic",
        )

    # 4. OPENAI_API_KEY (Codex users, many developers)
    openai_key = os.environ.get("OPENAI_API_KEY", "")
    if openai_key:
        base = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
        model = explicit_model or "gpt-4o"
        if debug:
            print(f"[llm] OPENAI_API_KEY found, base={base} model={model}", file=sys.stderr)
        return LLMClient(base, openai_key, model=model, provider="openai")

    # 5. No credentials found
    if debug:
        print(
            "[llm] no API credentials detected\n"
            "      LLM-enhanced analysis and model probes will be skipped.\n"
            "      To enable: set ANTHROPIC_API_KEY, OPENAI_API_KEY,\n"
            "      or provide --api-base/--api-key.",
            file=sys.stderr,
        )
    return None


def _try_openclaw_gateway(openclaw_root: str, debug: bool) -> Optional[LLMClient]:
    config_path = os.path.join(openclaw_root, "openclaw.json")
    if not os.path.isfile(config_path):
        return None
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
    except (json.JSONDecodeError, OSError):
        return None

    gateway = cfg.get("gateway", {})
    port = gateway.get("port")
    if not port:
        return None

    auth = gateway.get("auth", {})
    auth_mode = str(auth.get("mode", "")).lower()
    token = ""
    if auth_mode == "token":
        token = str(auth.get("token", ""))
    elif auth_mode == "password":
        token = str(auth.get("password", ""))
    if not token:
        token = os.environ.get("OPENCLAW_GATEWAY_TOKEN", "")
    if not token:
        return None

    url = f"http://localhost:{port}/v1"
    if debug:
        print(f"[llm] OpenClaw Gateway detected: {url}", file=sys.stderr)

    # Auto-enable chatCompletions endpoint if not already enabled
    _ensure_chat_completions_enabled(config_path, debug)

    return LLMClient(url, token, model="openclaw:main", provider="openai")


def _ensure_chat_completions_enabled(config_path: str, debug: bool) -> None:
    """Enable gateway chatCompletions endpoint in openclaw.json if needed."""
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
    except (json.JSONDecodeError, OSError):
        return

    gw = cfg.get("gateway", {})
    enabled = gw.get("http", {}).get("endpoints", {}).get("chatCompletions", {}).get("enabled")
    if enabled is True:
        return

    cfg.setdefault("gateway", {}).setdefault("http", {}).setdefault(
        "endpoints", {}).setdefault("chatCompletions", {})["enabled"] = True

    try:
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
        if debug:
            print("[llm] auto-enabled gateway.http.endpoints.chatCompletions", file=sys.stderr)
        print(
            "  [deepsafe] Enabled OpenClaw Gateway Chat Completions endpoint.\n"
            "             Please restart your OpenClaw Gateway for this to take effect.",
            file=sys.stderr,
        )
    except OSError:
        pass
