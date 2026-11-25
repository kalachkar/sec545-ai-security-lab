"""Provider: headless Claude Code (`claude -p`).

Uses the local Claude Code login, so no API key is needed. The session runs
inside the blind workspace with ONLY read-only built-in tools (Read, Grep,
Glob): no Bash, no Write, no web, no MCP servers, no user settings/hooks."""
from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path

from harness.core.run import log
from harness.providers.base import Provider, ProviderResult

READ_ONLY_TOOLS = "Read,Grep,Glob"


class ClaudeCliProvider(Provider):
    name = "claude_cli"

    def __init__(self) -> None:
        self.binary = shutil.which("claude")
        if not self.binary:
            raise SystemExit("`claude` CLI not found on PATH. Install Claude Code or use provider: anthropic_api")

    def run(self, *, prompt, schema, model, cwd, label, max_turns=40, max_budget_usd=3.0) -> ProviderResult:
        cmd = [
            self.binary, "-p",
            "--model", model,
            "--tools", READ_ONLY_TOOLS,
            "--strict-mcp-config",
            "--setting-sources", "",
            "--no-session-persistence",
            "--max-budget-usd", str(max_budget_usd),
            "--output-format", "stream-json", "--verbose",
            "--json-schema", json.dumps(schema, separators=(",", ":")),
        ]
        log(f"  claude -p [{model}] {label} (cwd={cwd.name})")
        t0 = time.time()
        proc = subprocess.run(cmd, input=prompt, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", cwd=str(cwd), timeout=1800)
        duration = time.time() - t0
        events, result, tool_calls = [], None, []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            events.append(ev)
            if ev.get("type") == "assistant":
                for block in ev.get("message", {}).get("content", []):
                    if block.get("type") == "tool_use":
                        tool_calls.append({"tool": block.get("name"), "input": block.get("input")})
            if ev.get("type") == "result":
                result = ev
        if result is None:
            raise RuntimeError(f"claude -p produced no result (exit {proc.returncode}): {proc.stderr[-2000:]}")
        data = result.get("structured_output")
        if data is None:
            data = _parse_json(result.get("result", ""))
        if data is None:
            raise RuntimeError(f"claude -p returned no structured output for {label}: {str(result.get('result'))[:500]}")
        usage = result.get("usage", {})
        return ProviderResult(
            data=data, model=model,
            cost_usd=float(result.get("total_cost_usd") or 0.0),
            input_tokens=int(usage.get("input_tokens", 0) + usage.get("cache_read_input_tokens", 0)
                             + usage.get("cache_creation_input_tokens", 0)),
            output_tokens=int(usage.get("output_tokens", 0)),
            duration_s=duration, turns=int(result.get("num_turns") or 0),
            transcript="\n".join(json.dumps(e, ensure_ascii=False) for e in events),
            tool_calls=tool_calls,
        )


def _parse_json(text: str):
    text = (text or "").strip()
    if "```" in text:
        text = text.split("```json")[-1].split("```")[0] if "```json" in text else text.split("```")[1]
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end < 0:
        return None
    try:
        return json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return None
