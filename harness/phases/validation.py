"""Phase 4: validation - static disposition + live PoC (codex-security `validation`).

Static-only mode (profile `live_validation: false`, used by the Databricks benchmark):
the model still gives a disposition, evidence and a PoC *plan*, but nothing is executed.
`validated` then means "survives static code review" (resolute-style V1), never V2.

Round 1: the model gives a disposition + PoC for every candidate.
Live:    the harness resets the app and runs every PoC through the sandboxed probe.
Round 2: failed PoCs go back to the model with the real HTTP responses (one retry):
         it fixes the PoC or downgrades the claim. Then those PoCs run again."""
from __future__ import annotations

import json
import subprocess
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from harness.core.run import RunContext, log
from harness.phases.common import call
from harness.tools.http_probe import PocRunner


def candidates(ctx: RunContext) -> list[dict]:
    out = list(ctx.load("discovery")["candidates"])
    for t in ctx.load("triage")["items"]:
        if t["family"] == "sast" and t["triage"]["verdict"] in ("confirmed", "needs_review"):
            out.append({"id": t["triage_item_id"], "title": t["title"], "family": "sast", "cwe": t["cwe"],
                        "locations": [{"file": t["location"]["file"], "line": t["location"]["line"], "role": "sink"}],
                        "source": "(scanner finding)", "sink": t["summary"][:300],
                        "impact": t["triage"].get("rationale", ""), "origin": "scanner"})
    return out


def reset_app(ctx: RunContext) -> None:
    compose = str(ctx.app_path / "docker-compose.yml")
    log(f"resetting {ctx.app} to a fresh instance ...")
    subprocess.run(["docker", "compose", "-f", compose, "down", "-v"], capture_output=True)
    subprocess.run(["docker", "compose", "-f", compose, "up", "-d"], capture_output=True)
    for _ in range(60):
        try:
            with urllib.request.urlopen(ctx.app_cfg["base_url"] + "/healthz", timeout=3) as r:
                if r.status == 200:
                    time.sleep(2)
                    return
        except Exception:
            time.sleep(2)
    raise RuntimeError(f"{ctx.app} did not become healthy")


def _live(ctx: RunContext) -> bool:
    return ctx.models.get("live_validation", ctx.config["validation"].get("live", True))


def _engagement(ctx: RunContext) -> str:
    if not _live(ctx):
        return ("## Engagement (static only)\nNo running instance is available. Decide `survives` from code "
                "evidence alone: re-read the cited lines and trace source -> control -> sink, and state any proof "
                "gap explicitly.")
    accounts = {k: {kk: vv for kk, vv in v.items() if kk != "password"} for k, v in ctx.app_cfg["accounts"].items()}
    return (f"## Engagement\nLocal disposable instance: {ctx.app_cfg['base_url']} (the harness sends your PoC "
            f"requests there).\nTest accounts you may use in `auth` (low privilege, no admin):\n"
            f"```json\n{json.dumps(accounts, indent=1)}\n```\n"
            "Seeded demo data exists (e.g. orders/documents/conversations with small integer ids).")


def _ask(ctx: RunContext, label: str, items: list[dict], extra: str = "") -> list[dict]:
    size = ctx.config["validation"]["batch_size"]
    batches = [items[i:i + size] for i in range(0, len(items), size)]

    def work(idx_batch):
        idx, batch = idx_batch
        return call(ctx, "validation", f"{label}{idx + 1}", "validation" if _live(ctx) else "validation-static",
                    [_engagement(ctx), extra, f"## Candidates ({len(batch)})\n```json\n{json.dumps(batch, indent=1)}\n```"],
                    "validation").data.get("results", [])

    with ThreadPoolExecutor(3) as ex:
        return [r for part in ex.map(work, enumerate(batches)) for r in part]


def _runner(ctx: RunContext) -> PocRunner:
    r = PocRunner(ctx.app_cfg["base_url"], ctx.app_cfg["login"], ctx.app_cfg["accounts"], ctx.app_cfg["container"])
    r.login_all()
    return r


def _execute(ctx: RunContext, records: list[dict], runner: PocRunner, only=None) -> None:
    for rec in records:
        if only is not None and rec["id"] not in only:
            continue
        v = rec["validation"]
        rec["poc_result"] = None
        if v.get("poc") and v.get("survives") != "no":
            runner.login_all()
            rec["poc_result"] = runner.run(v["poc"])
            log(f"  PoC {rec['id']:6} {rec['poc_result']['status']:15} {rec['title'][:70]}")
        rec["validated"] = v.get("survives") == "yes" or (rec["poc_result"] or {}).get("status") == "passed"


def _counts(records):
    return {
        "candidates": len(records),
        "survives_yes": sum(r["validation"].get("survives") == "yes" for r in records),
        "survives_no": sum(r["validation"].get("survives") == "no" for r in records),
        "uncertain": sum(r["validation"].get("survives") == "uncertain" for r in records),
        "poc_passed": sum((r["poc_result"] or {}).get("status") == "passed" for r in records),
        "poc_failed": sum((r["poc_result"] or {}).get("status") == "failed" for r in records),
        "retried": sum(bool(r.get("attempts", 1) > 1) for r in records),
        "passed_after_retry": sum(r.get("attempts", 1) > 1 and (r["poc_result"] or {}).get("status") == "passed" for r in records),
    }


def retry_round(ctx: RunContext, records: list[dict], runner: PocRunner) -> None:
    failed = [r for r in records if (r["poc_result"] or {}).get("status") in ("failed", "no_expectation")]
    if not failed:
        return
    log(f"validation retry: {len(failed)} failed PoCs go back to the model with the live responses")
    items = [{**r["candidate"], "previous_attempt": {
        "survives": r["validation"].get("survives"), "poc": r["validation"].get("poc"),
        "live_result": [{k: s[k] for k in ("name", "method", "path", "statuses", "ok", "body_excerpt")}
                        for s in r["poc_result"]["steps"]]}} for r in failed]
    extra = ("## Retry round\nEach candidate below includes `previous_attempt`: your earlier PoC and the actual "
             "responses from the live app. Fix the PoC, or downgrade `survives` if the responses disprove the claim.")
    new = {r["id"]: r for r in _ask(ctx, "retry", items, extra)}
    for r in failed:
        if r["id"] in new:
            r["first_attempt"] = {"validation": r["validation"], "poc_result": r["poc_result"]}
            r["validation"] = new[r["id"]]
            r["attempts"] = 2
    _execute(ctx, records, runner, only={r["id"] for r in failed if r["id"] in new})


def run(ctx: RunContext, pocs_only: bool = False) -> dict:
    if pocs_only and ctx.has("validation"):
        records = ctx.load("validation")["records"]
        for r in records:  # restore first-attempt state, then replay with the current probe
            if r.get("first_attempt"):
                r["validation"], r["poc_result"] = r["first_attempt"]["validation"], r["first_attempt"]["poc_result"]
                r.pop("first_attempt"), r.pop("attempts", None)
        log(f"validation: replaying {len(records)} stored dispositions (no new round-1 model calls)")
    else:
        cands = candidates(ctx)
        log(f"validation: {len(cands)} candidates")
        by_id = {r["id"]: r for r in _ask(ctx, "batch", cands)}
        records = [{"id": c["id"], "origin": c.get("origin", "ai"), "title": c["title"], "candidate": c,
                    "validation": by_id.get(c["id"], {"survives": "uncertain", "confidence": "low",
                                                      "static_evidence": "no result returned"})} for c in cands]

    if not _live(ctx):
        for rec in records:
            rec["poc_result"] = None
            rec["validated"] = rec["validation"].get("survives") == "yes"
            rec["validation_level"] = "V1" if rec["validated"] else "V0"
    else:
        if ctx.config["validation"].get("reset_app_before", True):
            reset_app(ctx)
        runner = _runner(ctx)
        _execute(ctx, records, runner)
        if ctx.config["validation"].get("retry_failed", True):
            retry_round(ctx, records, runner)
        for rec in records:
            passed = (rec["poc_result"] or {}).get("status") == "passed"
            rec["validation_level"] = "V2" if passed else ("V1" if rec["validated"] else "V0")

    counts = _counts(records)
    data = {"app": ctx.app, "mode": "live" if _live(ctx) else "static", "counts": counts, "records": records}
    ctx.save("validation", data)
    ctx.record_phase("validation", **{f"n_{k}": v for k, v in counts.items()})
    log(f"validation: {counts}")
    return data
