"""Phase 3: AI discovery of what the scanners missed (codex-security `finding-discovery`)."""
from __future__ import annotations

import json

from harness.core.run import RunContext, log
from harness.phases.common import call, repomap


def run(ctx: RunContext) -> dict:
    triage = ctx.load("triage")["items"]
    known = [{"id": t["triage_item_id"], "family": t["family"], "title": t["title"],
              "location": f"{t['location']['file']}:{t['location']['line'] or ''}", "verdict": t["triage"]["verdict"]}
             for t in triage if t["family"] in ("sast", "secret")]
    other = {fam: sum(1 for t in triage if t["family"] == fam) for fam in ("sca", "container", "misconfig")}
    rmap = repomap(ctx)
    candidates, notes = [], []
    for p in range(ctx.models.get("discovery_passes", 1)):
        already = known + [{"id": c["id"], "title": c["title"], "location": f"{c['locations'][0]['file']}:{c['locations'][0]['line']}"}
                           for c in candidates]
        res = call(ctx, "discovery", f"pass{p + 1}", "discovery", [
            f"## Repository map\n{rmap}",
            "## Already reported by scanners (do NOT re-report; you may use them in reasoning)\n"
            f"Dependency CVEs ({other['sca']} packages), base-image CVEs and {other['misconfig']} IaC/Docker "
            "misconfigurations are covered by Trivy.\n"
            f"```json\n{json.dumps(already, indent=1)}\n```",
            f"Number new candidates starting at D-{len(candidates) + 1:02d}.",
        ], "discovery")
        new = res.data.get("candidates", [])
        for i, c in enumerate(new):
            c["id"] = f"D-{len(candidates) + 1:02d}"
            c["pass"] = p + 1
            candidates.append(c)
        notes.append(res.data.get("coverage_notes", ""))
        log(f"discovery pass {p + 1}: {len(new)} candidates")
    data = {"app": ctx.app, "candidates": candidates, "coverage_notes": notes}
    ctx.save("discovery", data)
    ctx.record_phase("discovery", candidates=len(candidates))
    return data
