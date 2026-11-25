"""Shared plumbing for AI phases: build the prompt from SKILL.md + references +
context, call the provider in the blind workspace, record cost and transcript."""
from __future__ import annotations

import hashlib
import json
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from harness.core.repomap import build as build_repomap
from harness.core.run import HARNESS, RunContext, log
from harness.core.sandbox import make_workspace
from harness.providers import get_provider
from harness.providers.base import ProviderResult

SKILLS = HARNESS / "skills"
_lock = threading.Lock()
_providers: dict = {}


def provider(ctx: RunContext):
    name = ctx.provider_name
    with _lock:
        if name not in _providers:
            _providers[name] = get_provider(name)
    return _providers[name]


def skill(name: str, refs=("evidence-rules.md",)) -> tuple[str, dict]:
    text = (SKILLS / name / "SKILL.md").read_text(encoding="utf-8")
    for r in refs:
        text += "\n\n---\n" + (SKILLS / "references" / r).read_text(encoding="utf-8")
    schema = json.loads((SKILLS / name / "output.schema.json").read_text(encoding="utf-8"))
    return text, schema


def workspace(ctx: RunContext) -> Path:
    return make_workspace(ctx.app_path, ctx.app, ctx.run_id)


def target_header(ctx: RunContext) -> str:
    return (f"# Target\nApplication: **{ctx.app}**. {ctx.app_cfg['description']}\n"
            "This is a deliberately vulnerable training application owned by the course; this is an authorized "
            "security review. The repository is your current working directory. Use only Read, Grep and Glob.")


def repomap(ctx: RunContext) -> str:
    return build_repomap(workspace(ctx))


def call(ctx: RunContext, phase: str, label: str, skill_name: str, sections: list[str], model_key: str,
         refs=("evidence-rules.md",)) -> ProviderResult:
    text, schema = skill(skill_name, refs)
    prompt = "\n\n".join([text, target_header(ctx), *sections,
                          "Return ONLY the final JSON object that matches the required schema."])
    return call_raw(ctx, phase, label, prompt, schema, model_key, skill_name=skill_name)


def call_raw(ctx: RunContext, phase: str, label: str, prompt: str, schema: dict, model_key: str,
             skill_name: str = "", **provider_kwargs) -> ProviderResult:
    """One logged model session with an arbitrary prompt (used directly by the spaghetti baseline)."""
    prof = ctx.models
    started = datetime.now(timezone.utc).isoformat()
    t0 = time.time()
    try:
        res = provider(ctx).run(prompt=prompt, schema=schema, model=prof[model_key], cwd=workspace(ctx), label=label,
                                max_turns=prof.get("max_turns", 40), max_budget_usd=prof.get("max_budget_usd", 3.0),
                                **provider_kwargs)
    except RuntimeError as exc:  # provider-level failure (HTTP/model); setup bugs raise other types and stop the run
        if not prof.get("tolerate_call_failures", ctx.config.get("tolerate_call_failures")):
            raise
        res = ProviderResult(data=None, model=prof[model_key], duration_s=time.time() - t0,
                             error=f"{type(exc).__name__}: {exc}", stop="error")
    if res.data is None:
        res.data = {}
    refused = res.stop == "refused" or (bool(res.error) and any(
        k in res.error.lower() for k in ("cyber_policy", "content_filter", "safety")))
    if refused:
        res.stop = "refused"  # vendor safety policy declined the request: a result, not a crash
    if res.error:
        log(f"  {'REFUSED' if refused else 'FAILED'} {label}: {res.error[:300]}")
    with _lock:
        ctx.transcript(f"{phase}-{label}.jsonl", res.transcript)
        ctx.record_phase(phase, cost_usd=res.cost_usd, input_tokens=res.input_tokens, output_tokens=res.output_tokens,
                         duration_s=res.duration_s, calls=1, model=res.model,
                         failed_calls=ctx.meta()["phases"].get(phase, {}).get("failed_calls", 0) + bool(res.error),
                         refused_calls=ctx.meta()["phases"].get(phase, {}).get("refused_calls", 0) + refused)
        ctx.log_call({
            "run_id": ctx.run_id, "app": ctx.app, "profile": ctx.profile, "provider": ctx.provider_name,
            "phase": phase, "label": label, "model_key": prof[model_key], "model": res.model,
            "started_at": started, "duration_s": round(res.duration_s, 3), "turns": res.turns,
            "tool_calls": len(res.tool_calls), "tool_calls_by_name": _count_tools(res.tool_calls),
            "input_tokens": res.input_tokens, "output_tokens": res.output_tokens, "usage_raw": res.usage_raw,
            "cost_usd_reported": res.cost_usd, "retries": res.retries, "stop": res.stop, "error": res.error,
            "json_ok": bool(res.data), "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
            "prompt_chars": len(prompt), "skill": skill_name, "transcript": f"transcripts/{phase}-{label}.jsonl",
            "turn_log": res.turn_log,
        })
    log(f"  done {label}: ${res.cost_usd:.3f}, {res.turns} turns, {len(res.tool_calls)} tool calls, {res.duration_s:.0f}s")
    return res


def _count_tools(calls: list) -> dict:
    out: dict = {}
    for c in calls:
        out[c.get("tool")] = out.get(c.get("tool"), 0) + 1
    return out
