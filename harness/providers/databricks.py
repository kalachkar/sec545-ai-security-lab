"""Provider: Databricks Model Serving / Unity Gateway with a read-only tool loop.

One harness, many vendors. Every model gets exactly the same prompt, the same three
jailed read-only tools (list_tree / read_file / grep) and the same limits; only the
model changes. Two wire formats are supported because Databricks exposes some
OpenAI reasoning models' function tools only through the Responses API:

  api: chat       OpenAI Chat Completions  (Claude, Gemini, Llama, Qwen, GLM, ...)
  api: responses  OpenAI Responses         (GPT-6.x)

Routes:
  endpoint: <name>  -> POST /serving-endpoints/<name>/invocations         (chat)
                       POST /serving-endpoints/responses  {model: <name>}  (responses)
  gateway:  <name>  -> POST /ai-gateway/openai/v1/{chat/completions|responses} {model: <name>}

Auth (first that works): DATABRICKS_HOST + DATABRICKS_TOKEN env vars, databricks-sdk
default auth (notebooks/jobs/serverless), or `databricks auth token --profile
$DATABRICKS_CONFIG_PROFILE` locally.

Everything is recorded per turn (request without auth, raw response, latency, usage,
retries) so cost/accuracy/latency insights can be re-derived without re-running models.
Dollar cost is not estimated here; it is joined later from Databricks billing tables.
"""
from __future__ import annotations

import http.client
import json
import os
import random
import subprocess
import time
import urllib.error
import urllib.request

from harness.core.run import load_config, log
from harness.providers.base import Provider, ProviderResult
from harness.providers.claude_cli import _parse_json
from harness.tools.readonly import TOOL_DEFS, ReadOnlyTools

SYSTEM = ("You are a meticulous application-security engineer running one phase of an authorized "
          "security review of a deliberately vulnerable training application. Use the tools to read code. "
          "When finished, reply with ONLY a JSON object matching the schema given in the task.")
RETRY_STATUS = {408, 429, 500, 502, 503, 504}


class _Auth:
    def __init__(self) -> None:
        self.host = (os.environ.get("DATABRICKS_HOST") or "").rstrip("/")
        self._token, self._exp, self._sdk = os.environ.get("DATABRICKS_TOKEN"), float("inf"), None
        # On Databricks the runner notebook keeps a fresh token in this file (child processes do not
        # inherit notebook credentials, and job tokens can expire during long runs).
        self._token_file = os.environ.get("SEC545_TOKEN_FILE")
        if self._token_file:
            if not self.host:
                raise SystemExit("SEC545_TOKEN_FILE requires DATABRICKS_HOST")
            return
        if not self._token:
            try:
                from databricks.sdk.core import Config  # preinstalled on Databricks compute
                self._sdk = Config()
                self.host = self.host or self._sdk.host.rstrip("/")
            except Exception:
                self._sdk = None
            if self._sdk is None:
                self._exp = 0.0
        if not self.host:
            profile = os.environ.get("DATABRICKS_CONFIG_PROFILE", "DEFAULT")
            out = subprocess.check_output(["databricks", "auth", "env", "--profile", profile], text=True)
            self.host = json.loads(out)["env"]["DATABRICKS_HOST"].rstrip("/")

    def headers(self) -> dict:
        if self._token_file:
            with open(self._token_file, encoding="utf-8") as f:
                return {"Authorization": f"Bearer {f.read().strip()}"}
        if self._sdk is not None:
            return self._sdk.authenticate()
        if time.time() > self._exp:  # CLI OAuth token, refreshed well before expiry
            profile = os.environ.get("DATABRICKS_CONFIG_PROFILE", "DEFAULT")
            tok = json.loads(subprocess.check_output(["databricks", "auth", "token", "--profile", profile], text=True))
            self._token, self._exp = tok["access_token"], time.time() + 20 * 60
        return {"Authorization": f"Bearer {self._token}"}


def _chat_tools() -> list:
    return [{"type": "function", "function": {"name": t["name"], "description": t["description"],
                                              "parameters": t["input_schema"]}} for t in TOOL_DEFS]


def _responses_tools() -> list:
    return [{"type": "function", "name": t["name"], "description": t["description"],
             "parameters": t["input_schema"]} for t in TOOL_DEFS]


def _text(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):  # some vendors return content parts
        return "".join(p.get("text", "") for p in content if isinstance(p, dict) and p.get("type") in (None, "text", "output_text"))
    return ""


def _add_usage(total: dict, usage: dict | None) -> None:
    def walk(prefix, obj):
        for k, v in (obj or {}).items():
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                total[prefix + k] = total.get(prefix + k, 0) + v
            elif isinstance(v, dict):
                walk(f"{prefix}{k}.", v)
    walk("", usage)


def _collect_stream(r) -> dict:
    """Assemble an OpenAI chat SSE stream into a normal chat.completion response."""
    text, usage, model, finish = [], {}, None, None
    for raw in r:
        line = raw.decode("utf-8", errors="replace").strip()
        if not line.startswith("data:"):
            continue
        data = line[5:].strip()
        if data == "[DONE]":
            break
        ev = json.loads(data)
        model = ev.get("model", model)
        usage = ev.get("usage") or usage
        for ch in ev.get("choices") or []:
            text.append(_text((ch.get("delta") or {}).get("content")) or "")
            finish = ch.get("finish_reason") or finish
    return {"model": model, "usage": usage, "streamed": True,
            "choices": [{"message": {"role": "assistant", "content": "".join(text)}, "finish_reason": finish}]}


class DatabricksProvider(Provider):
    name = "databricks"

    def __init__(self) -> None:
        cfg = load_config()
        self.registry = cfg.get("databricks_models", {})
        self.defaults = cfg.get("databricks", {})
        self.auth = _Auth()

    # ---------- transport ----------
    def _post(self, path: str, body: dict, label: str) -> tuple[dict, float, int]:
        timeout = self.defaults.get("request_timeout_s", 300)
        attempts = self.defaults.get("max_retries", 5) + 1
        for attempt in range(attempts):
            t0 = time.time()
            req = urllib.request.Request(self.auth.host + path, data=json.dumps(body).encode(), method="POST",
                                         headers={**self.auth.headers(), "Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    if body.get("stream"):
                        return _collect_stream(r), time.time() - t0, attempt
                    return json.load(r), time.time() - t0, attempt
            except urllib.error.HTTPError as e:
                detail = e.read().decode(errors="replace")[:2000]
                if e.code not in RETRY_STATUS or attempt == attempts - 1:
                    raise RuntimeError(f"HTTP {e.code} from {path}: {detail}") from None
                err = f"HTTP {e.code}"
            except (urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException, json.JSONDecodeError) as e:
                if attempt == attempts - 1:
                    raise RuntimeError(f"network error calling {path}: {e}") from None
                err = type(e).__name__
            wait = min(60, 2 ** attempt * 2) + random.random()
            log(f"  {label}: {err}, retry {attempt + 1} in {wait:.0f}s")
            time.sleep(wait)
        raise AssertionError("unreachable")

    def _spec(self, model: str) -> dict:
        spec = self.registry.get(model)
        if not spec:
            raise SystemExit(f"model {model!r} is not in databricks_models (harness/config.yaml)")
        return spec

    def _paths(self, spec: dict) -> tuple[str, str]:
        api = spec.get("api", "chat")
        if "gateway" in spec:
            return f"/ai-gateway/openai/v1/{'responses' if api == 'responses' else 'chat/completions'}", spec["gateway"]
        if api == "responses":
            return "/serving-endpoints/responses", spec["endpoint"]
        return f"/serving-endpoints/{spec['endpoint']}/invocations", spec["endpoint"]

    # ---------- session ----------
    def run(self, *, prompt, schema, model, cwd, label, max_turns=40, max_budget_usd=3.0,
            use_tools: bool = True, max_output_tokens: int | None = None, system: str | None = None) -> ProviderResult:
        spec = self._spec(model)
        api = spec.get("api", "chat")
        path, wire_model = self._paths(spec)
        token_budget = spec.get("max_session_tokens", self.defaults.get("max_session_tokens", 2_000_000))
        max_out = max_output_tokens or spec.get("max_output_tokens", self.defaults.get("max_output_tokens", 16000))
        tools = ReadOnlyTools(cwd) if use_tools else None
        task = f"{prompt}\n\nOutput JSON schema:\n{json.dumps(schema)}"
        res = ProviderResult(data=None, model=wire_model)
        usage: dict = {}
        t0 = time.time()
        log(f"  databricks [{wire_model} via {api}] {label}")
        if api == "responses":
            text = self._responses_loop(path, wire_model, task, tools, res, usage, max_turns, max_out, token_budget, label,
                                        system or SYSTEM)
        else:
            text = self._chat_loop(path, wire_model, task, tools, res, usage, max_turns, max_out, token_budget, label,
                                   system or SYSTEM)
        res.data = _parse_json(text)
        if res.data is None and res.stop != "refused":  # one coercion turn, same model, no tools
            res.turn_log.append({"turn": "coerce", "reason": "final answer was not valid JSON"})
            coerce = ("Convert this analysis into ONE JSON object matching the schema. Reply with JSON only.\n\n"
                      f"Schema:\n{json.dumps(schema)}\n\nAnalysis:\n{text[:60000]}")
            try:
                if api == "responses":
                    body = {"model": wire_model, "input": coerce, "max_output_tokens": max_out}
                else:
                    body = {"messages": [{"role": "user", "content": coerce}], "max_tokens": max_out}
                    if "gateway" in spec:
                        body["model"] = wire_model
                out, dt, retries = self._post(path, body, label)
                res.retries += retries
                u = out.get("usage") or {}
                _add_usage(usage, u)
                res.transcript += json.dumps({"turn": "coerce", "latency_s": round(dt, 3), "response": out}) + "\n"
                txt = (_text(out["choices"][0]["message"].get("content")) if api == "chat"
                       else "".join(_text(o.get("content")) for o in out.get("output", []) if o.get("type") == "message"))
                res.data = _parse_json(txt)
            except Exception as exc:
                res.error = f"coercion failed: {exc}"
        if res.data is None:
            res.error = res.error or "no parseable JSON in final answer"
            res.stop = res.stop or "error"
        res.usage_raw = usage
        res.input_tokens = int(usage.get("prompt_tokens", 0) + usage.get("input_tokens", 0))
        res.output_tokens = int(usage.get("completion_tokens", 0) + usage.get("output_tokens", 0))
        res.duration_s = time.time() - t0
        return res

    def _record(self, res, usage, turn, body, out, dt, retries, ntools):
        u = out.get("usage") or {}
        _add_usage(usage, u)
        res.retries += retries
        res.turns = turn
        res.turn_log.append({"turn": turn, "latency_s": round(dt, 3), "retries": retries, "tool_calls": ntools,
                             "usage": u, "served_model": out.get("model")})
        # Log only what is new since the previous turn (the full conversation is the concatenation),
        # so transcripts stay linear in size while remaining a complete record.
        history = body.get("messages") or body.get("input") or []
        seen = getattr(res, "_logged", 0)
        params = {k: v for k, v in body.items() if k not in ("tools", "messages", "input", "instructions")}
        if turn == 1:
            params["tools"] = [t.get("name") or t.get("function", {}).get("name") for t in body.get("tools", [])]
            params["instructions"] = body.get("instructions")
        res.transcript += json.dumps({"turn": turn, "latency_s": round(dt, 3), "retries": retries, "params": params,
                                      "new_input": history[seen:], "response": out}, default=str) + "\n"
        res._logged = len(history)

    def _spent(self, usage) -> int:
        return int(usage.get("prompt_tokens", 0) + usage.get("completion_tokens", 0)
                   + usage.get("input_tokens", 0) + usage.get("output_tokens", 0))

    def _tool(self, tools, res, name, raw_args) -> str:
        try:
            args = json.loads(raw_args) if isinstance(raw_args, str) else dict(raw_args or {})
        except json.JSONDecodeError:
            res.tool_calls.append({"tool": name, "input": raw_args, "error": "bad JSON arguments"})
            return "Error: tool arguments were not valid JSON"
        res.tool_calls.append({"tool": name, "input": args})
        try:
            return tools.call(name, args)
        except Exception as exc:  # report tool errors back to the model
            return f"Error: {exc}"

    def _chat_loop(self, path, wire_model, task, tools, res, usage, max_turns, max_out, budget, label, system) -> str:
        messages = [{"role": "system", "content": system}, {"role": "user", "content": task}]
        text, nudged, recovered = "", False, False
        for turn in range(1, max_turns + 1):
            body = {"messages": messages, "max_tokens": max_out}
            if tools is not None:
                body["tools"] = _chat_tools()
            else:  # single long answer (spaghetti): stream so it never hits a request timeout
                body["stream"], body["stream_options"] = True, {"include_usage": True}
            if path.startswith("/ai-gateway"):
                body["model"] = wire_model
            try:
                out, dt, retries = self._post(path, body, label)
            except RuntimeError as exc:
                res.error, res.stop = str(exc), "error"
                return text
            choice = out["choices"][0]
            msg = choice["message"]
            calls = msg.get("tool_calls") or []
            self._record(res, usage, turn, body, out, dt, retries, len(calls))
            if choice.get("finish_reason") == "content_filter":  # vendor safety filter blocked the output
                res.error, res.stop = "content_filter: output blocked by the provider's safety filter", "refused"
                return text
            final = _text(msg.get("content"))
            text = final or text
            if not calls:
                if _parse_json(final) is None and not recovered and turn < max_turns:
                    # some models end with reasoning only; ask once more in the same conversation
                    recovered = True
                    res.turn_log.append({"turn": turn, "recovery": "empty_or_unparseable_final"})
                    messages.append({"role": "assistant", "content": final or "(no answer text)"})
                    messages.append({"role": "user", "content": "Your last reply did not contain the final answer. Reply now with ONLY the final JSON object that matches the schema - no tools, no prose."})
                    continue
                res.stop = "final"
                return text
            messages.append({k: v for k, v in msg.items() if k in ("role", "content", "tool_calls")})
            for c in calls:
                fn = c.get("function", {})
                messages.append({"role": "tool", "tool_call_id": c.get("id"),
                                 "content": self._tool(tools, res, fn.get("name"), fn.get("arguments"))})
            if not nudged and (self._spent(usage) > budget or turn == max_turns - 1):
                res.stop, nudged = "token_budget" if self._spent(usage) > budget else "max_turns", True
                log(f"  {label}: {res.stop}; asking for the final answer")
                messages.append({"role": "user", "content": "Stop using tools. Return the final JSON now."})
        res.stop = res.stop or "max_turns"
        return text

    def _responses_loop(self, path, wire_model, task, tools, res, usage, max_turns, max_out, budget, label, system) -> str:
        items: list = [{"role": "user", "content": task}]
        text, nudged, recovered = "", False, False
        for turn in range(1, max_turns + 1):
            body = {"model": wire_model, "instructions": system, "input": items,
                    "max_output_tokens": max_out, "store": False, "include": ["reasoning.encrypted_content"]}
            if tools is not None:
                body["tools"] = _responses_tools()
            try:
                out, dt, retries = self._post(path, body, label)
            except RuntimeError as exc:
                res.error, res.stop = str(exc), "error"
                return text
            output = out.get("output", [])
            calls = [o for o in output if o.get("type") == "function_call"]
            self._record(res, usage, turn, body, out, dt, retries, len(calls))
            reason = (out.get("incomplete_details") or {}).get("reason")
            if reason == "content_filter":
                res.error, res.stop = "content_filter: output blocked by the provider's safety filter", "refused"
                return text
            msg_text = "".join(_text(o.get("content")) for o in output if o.get("type") == "message")
            text = msg_text or text
            if not calls:
                if _parse_json(msg_text) is None and not recovered and turn < max_turns:
                    recovered = True
                    res.turn_log.append({"turn": turn, "recovery": "empty_or_unparseable_final"})
                    items.extend(output)
                    items.append({"role": "user", "content": "Your last reply did not contain the final answer. Reply now with ONLY the final JSON object that matches the schema - no tools, no prose."})
                    continue
                res.stop = "final"
                return text
            items.extend(output)  # keep reasoning items paired with their function calls
            for c in calls:
                items.append({"type": "function_call_output", "call_id": c.get("call_id"),
                              "output": self._tool(tools, res, c.get("name"), c.get("arguments"))})
            if not nudged and (self._spent(usage) > budget or turn == max_turns - 1):
                res.stop, nudged = "token_budget" if self._spent(usage) > budget else "max_turns", True
                log(f"  {label}: {res.stop}; asking for the final answer")
                items.append({"role": "user", "content": "Stop using tools. Return the final JSON now."})
        res.stop = res.stop or "max_turns"
        return text
