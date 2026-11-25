from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ProviderResult:
    data: Any                      # parsed JSON matching the phase schema
    model: str
    cost_usd: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0
    duration_s: float = 0.0
    turns: int = 0
    transcript: str = ""           # raw event log for the "watch it reason" demo
    tool_calls: list = field(default_factory=list)
    turn_log: list = field(default_factory=list)   # per-turn latency/usage/status (benchmark analytics)
    usage_raw: dict = field(default_factory=dict)  # summed provider usage incl. cached/reasoning tokens
    retries: int = 0
    error: str | None = None       # set when the session failed but the run continued
    stop: str = ""                 # why the session ended: final | max_turns | token_budget | error


class Provider:
    name = "base"

    def run(self, *, prompt: str, schema: dict, model: str, cwd: Path, label: str,
            max_turns: int = 40, max_budget_usd: float = 3.0) -> ProviderResult:
        raise NotImplementedError
