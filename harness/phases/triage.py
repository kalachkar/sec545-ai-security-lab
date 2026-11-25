"""Phase 2: triage every grouped scanner item (codex-security `triage-finding`)."""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

from harness.core.run import RunContext, log
from harness.phases.common import call, repomap

BATCH = 30
KEEP = ("triage_item_id", "family", "title", "severity", "tools", "location", "cwe", "summary",
        "package", "version", "vulns", "fixed_versions", "rules", "count")


def run(ctx: RunContext) -> dict:
    items = ctx.load("normalized")["triage_items"]
    compact = [{k: it[k] for k in KEEP if k in it} for it in items]
    for c in compact:
        if "vulns" in c:
            c["vulns"] = c["vulns"][:12]
    batches = [compact[i:i + BATCH] for i in range(0, len(compact), BATCH)]
    log(f"triage: {len(items)} items in {len(batches)} batches")
    rmap = repomap(ctx)

    def work(idx_batch):
        idx, batch = idx_batch
        return call(ctx, "triage", f"batch{idx + 1}", "triage",
                    [f"## Repository map\n{rmap}",
                     f"## Scanner items to triage ({len(batch)})\n```json\n{json.dumps(batch, indent=1)}\n```"],
                    "triage").data.get("items", [])

    with ThreadPoolExecutor(3) as ex:
        verdicts = [v for part in ex.map(work, enumerate(batches)) for v in part]
    by_id = {v["triage_item_id"]: v for v in verdicts}
    merged = []
    for it in items:
        v = by_id.get(it["triage_item_id"]) or {"verdict": "needs_review", "confidence": "low",
                                                "rationale": "no verdict returned by model", "flip_fact": "re-run triage"}
        merged.append({**it, "triage": v})
    counts = {k: sum(1 for m in merged if m["triage"]["verdict"] == k) for k in ("confirmed", "not_actionable", "needs_review")}
    data = {"app": ctx.app, "counts": counts, "items": merged}
    ctx.save("triage", data)
    ctx.record_phase("triage", verdicts=counts)
    log(f"triage verdicts: {counts}")
    return data
