"""Phase 5: attack-path analysis + chains (codex-security `attack-path-analysis`),
then build the consolidated findings registry."""
from __future__ import annotations

import json
import re

from harness.core.run import RunContext, log
from harness.phases.common import call


def surviving(ctx: RunContext) -> list[dict]:
    triage = ctx.load("triage")["items"]
    val = {r["id"]: r for r in ctx.load("validation")["records"]}
    out = []
    for t in triage:
        if t["triage"]["verdict"] != "confirmed" and t["triage_item_id"] not in val:
            continue
        v = val.get(t["triage_item_id"])
        if v and not v["validated"] and v["validation"].get("survives") == "no":
            continue
        out.append({"id": t["triage_item_id"], "origin": "scanner", "tools": t["tools"], "family": t["family"],
                    "title": t["title"], "location": f"{t['location']['file']}:{t['location']['line'] or ''}",
                    "cwe": t["cwe"], "reachable": t["triage"].get("reachable"),
                    "evidence": (t["triage"].get("evidence") or t["triage"].get("rationale", ""))[:400],
                    "live_poc": (v or {}).get("poc_result", {}) and v["poc_result"]["status"] if v else None})
    for r in val.values():
        if r["origin"] != "ai":
            continue
        if r["validation"].get("survives") == "no" and not r["validated"]:
            continue
        c = r["candidate"]
        out.append({"id": c["id"], "origin": "ai", "family": c["family"], "title": c["title"],
                    "location": ", ".join(f"{l['file']}:{l['line']}" for l in c["locations"][:3]), "cwe": c["cwe"],
                    "source": c.get("source", ""), "sink": c.get("sink", ""), "impact": c.get("impact", ""),
                    "evidence": r["validation"].get("static_evidence", "")[:400],
                    "live_poc": (r["poc_result"] or {}).get("status")})
    return out


def run(ctx: RunContext) -> dict:
    items = surviving(ctx)
    log(f"attack-path: {len(items)} surviving findings")
    res = call(ctx, "attack_path", "all", "attack-path",
               [f"## Surviving findings ({len(items)})\n```json\n{json.dumps(items, indent=1)}\n```"],
               "attack_path", refs=("evidence-rules.md", "severity-policy.md"))
    data = {"app": ctx.app, "inputs": items, **res.data}
    ctx.save("attack_path", data)
    build_registry(ctx)
    ctx.record_phase("attack_path", chains=len(res.data.get("chains", [])))
    return data


def build_registry(ctx: RunContext) -> list[dict]:
    """findings.json: one row per final finding (scanner item or AI candidate) with every phase's verdict."""
    triage = ctx.load("triage")["items"]
    disc = {c["id"]: c for c in ctx.load("discovery")["candidates"]}
    val = {r["id"]: r for r in ctx.load("validation")["records"]}
    ap = ctx.load("attack_path")
    decisions = {f["id"]: f for f in ap.get("findings", [])}
    chain_of = {}
    for ch in ap.get("chains", []):
        for s in ch.get("steps", []):
            m = re.search(r"([DT]-\d{2,3})", str(s))
            if m:
                chain_of.setdefault(m.group(1), []).append(ch["id"])
    rows = []

    def row(fid, origin, family, title, tools, locations, cwe, triage_v=None):
        v, d = val.get(fid), decisions.get(fid, {})
        rows.append({
            "id": fid, "origin": origin, "family": family, "title": title, "tools": tools,
            "locations": locations, "cwe": cwe, "triage": triage_v,
            "survives": (v or {}).get("validation", {}).get("survives"),
            "poc": ((v or {}).get("poc_result") or {}).get("status"),
            "severity": d.get("severity"), "decision": d.get("decision"),
            "attacker_position": d.get("attacker_position"), "rationale": d.get("rationale"),
            "chains": chain_of.get(fid, []),
        })

    for t in triage:
        row(t["triage_item_id"], "scanner", t["family"], t["title"], t["tools"],
            [{"file": t["location"]["file"], "line": t["location"]["line"]}], t["cwe"], t["triage"]["verdict"])
    for cid, c in disc.items():
        row(cid, "ai", c["family"], c["title"], ["ai-discovery"],
            [{"file": l["file"], "line": l["line"], "role": l.get("role")} for l in c["locations"]], c["cwe"])
    ctx.save("findings", {"app": ctx.app, "findings": rows, "chains": ap.get("chains", [])})
    return rows
