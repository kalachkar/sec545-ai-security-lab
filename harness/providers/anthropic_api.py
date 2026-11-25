"""Provider: Anthropic Python SDK with a manual read-only tool loop.

Needs ANTHROPIC_API_KEY (or an `ant auth login` profile). The model can only
call list_tree / read_file / grep, jailed to the blind workspace."""
from __future__ import annotations

import json
import time

from harness.core.run import load_config, log
from harness.providers.base import Provider, ProviderResult
from harness.providers.claude_cli import _parse_json
from harness.tools.readonly import TOOL_DEFS, ReadOnlyTools

SYSTEM = ("You are a meticulous application-security engineer running one phase of an authorized "
          "security review of a deliberately vulnerable training application. Use the tools to read code. "
          "When finished, reply with ONLY a JSON object matching the schema given in the task.")


class AnthropicApiProvider(Provider):
    name = "anthropic_api"

    def __init__(self) -> None:
        import anthropic  # imported lazily so claude_cli users don't need the SDK
        self.anthropic = anthropic
        self.client = anthropic.Anthropic()
        cfg = load_config()
        self.aliases = cfg["models"]
        self.pricing = cfg["pricing"]

    def _cost(self, model: str, usage_in: int, usage_out: int) -> float:
        price = self.pricing.get(model, {"input": 0, "output": 0})
        return usage_in / 1e6 * price["input"] + usage_out / 1e6 * price["output"]

    def run(self, *, prompt, schema, model, cwd, label, max_turns=40, max_budget_usd=3.0) -> ProviderResult:
        model_id = self.aliases.get(model, model)
        tools = ReadOnlyTools(cwd)
        task = f"{prompt}\n\nOutput JSON schema:\n{json.dumps(schema)}"
        messages = [{"role": "user", "content": task}]
        tin = tout = turns = 0
        calls, log_lines = [], []
        t0 = time.time()
        log(f"  api [{model_id}] {label}")
        response = None
        while turns < max_turns:
            turns += 1
            response = self.client.messages.create(
                model=model_id, max_tokens=16000, system=SYSTEM, tools=TOOL_DEFS, messages=messages)
            tin += response.usage.input_tokens
            tout += response.usage.output_tokens
            log_lines.append(json.dumps({"turn": turns, "stop": response.stop_reason,
                                         "content": [b.model_dump() for b in response.content]}, default=str))
            if response.stop_reason == "refusal":
                raise RuntimeError(f"model refused {label}")
            if response.stop_reason == "pause_turn":
                messages.append({"role": "assistant", "content": response.content})
                continue
            tool_uses = [b for b in response.content if b.type == "tool_use"]
            if not tool_uses:
                break
            messages.append({"role": "assistant", "content": response.content})
            results = []
            for tu in tool_uses:
                calls.append({"tool": tu.name, "input": tu.input})
                try:
                    out, err = tools.call(tu.name, dict(tu.input)), False
                except Exception as exc:  # report tool errors back to the model
                    out, err = f"Error: {exc}", True
                results.append({"type": "tool_result", "tool_use_id": tu.id, "content": out, "is_error": err})
            messages.append({"role": "user", "content": results})
            if self._cost(model_id, tin, tout) > max_budget_usd:
                log("  budget reached; asking for final answer")
                messages.append({"role": "user", "content": "Budget reached. Return the final JSON now."})

        text = "".join(b.text for b in response.content if b.type == "text") if response else ""
        data = _parse_json(text)
        if data is None:  # one structured-output call to coerce the answer into the schema
            final = self.client.messages.create(
                model=model_id, max_tokens=16000,
                messages=[{"role": "user", "content": f"Convert this analysis into JSON matching the schema.\n\n{text}"}],
                output_config={"format": {"type": "json_schema", "schema": schema}})
            tin += final.usage.input_tokens
            tout += final.usage.output_tokens
            data = json.loads(next(b.text for b in final.content if b.type == "text"))
        return ProviderResult(data=data, model=model_id, cost_usd=self._cost(model_id, tin, tout),
                              input_tokens=tin, output_tokens=tout, duration_s=time.time() - t0,
                              turns=turns, transcript="\n".join(log_lines), tool_calls=calls)
