"""Spaghetti baseline: "grab the shiniest model and shovel everything in".

What a reasonable person does without a harness: concatenate the source code and every raw
scanner finding into one prompt, ask once, no tools. Deliberately NOT given: repo map,
grouping/deduplication, skills, evidence rules, severity policy, phases, validation.

Kept identical to the harness so the comparison is fair: the same blind copy of the app
(no README, no answer key), the same raw scanner output, and the same scorer. The only
structure requested is a minimal JSON shape so the result can be scored at all.

Writes 02-triage.json and 03-discovery.json in the harness formats (so `score` works
unchanged) plus 02-spaghetti.json with the raw per-finding answers and consistency stats.
"""
from __future__ import annotations

import json
from collections import defaultdict

from harness.core.run import RunContext, log
from harness.phases.common import call_raw, workspace

SKIP_NAMES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Pipfile.lock"}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz", ".woff", ".woff2", ".ttf", ".db", ".sqlite"}
MAX_FILE_CHARS = 60_000

SYSTEM = "You are a helpful security expert."
ASK = """I ran three security scanners (Trivy, Semgrep, TruffleHog) on my application. Below is the complete
source code and every scanner finding. Please:
1. Tell me for EACH scanner finding whether it is a true positive or a false positive, with a short reason.
2. Find any other security vulnerabilities the scanners missed.

Answer in JSON with this shape:
{"scanner_findings": [{"id": "<finding id>", "verdict": "true_positive" | "false_positive", "reason": "...", "severity": "critical|high|medium|low"}],
 "new_vulnerabilities": [{"title": "...", "file": "<path>", "line": <int>, "cwe": "CWE-...", "severity": "critical|high|medium|low", "description": "..."}]}"""

SCHEMA = {"type": "object", "properties": {
    "scanner_findings": {"type": "array", "items": {"type": "object", "properties": {
        "id": {"type": "string"}, "verdict": {"type": "string"}, "reason": {"type": "string"},
        "severity": {"type": "string"}}, "required": ["id", "verdict"]}},
    "new_vulnerabilities": {"type": "array", "items": {"type": "object", "properties": {
        "title": {"type": "string"}, "file": {"type": "string"}, "line": {"type": ["integer", "null"]},
        "cwe": {"type": "string"}, "severity": {"type": "string"}, "description": {"type": "string"}},
        "required": ["title", "file"]}}},
    "required": ["scanner_findings", "new_vulnerabilities"]}


def code_dump(ctx: RunContext) -> tuple[str, dict]:
    root = workspace(ctx)
    parts, stats = [], {"files": 0, "chars": 0, "skipped": []}
    for f in sorted(root.rglob("*")):
        if not f.is_file():
            continue
        rel = f.relative_to(root).as_posix()
        if f.name in SKIP_NAMES or f.suffix.lower() in SKIP_EXT:
            stats["skipped"].append(rel)
            continue
        try:
            text = f.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            stats["skipped"].append(rel)
            continue
        if len(text) > MAX_FILE_CHARS:
            text = text[:MAX_FILE_CHARS] + "\n... (truncated)"
        parts.append(f"===== FILE: {rel} =====\n{text}")
        stats["files"] += 1
        stats["chars"] += len(text)
    return "\n\n".join(parts), stats


def compact(f: dict) -> dict:
    out = {"id": f["id"], "tool": f["tool"], "rule": f.get("rule_id"), "severity": f.get("severity"),
           "file": f.get("file"), "line": f.get("line"), "title": (f.get("title") or "")[:200],
           "message": (f.get("message") or "")[:300]}
    return {k: v for k, v in out.items() if v not in (None, "")}


VERDICT = {"true_positive": "confirmed", "false_positive": "not_actionable"}


def run(ctx: RunContext) -> dict:
    norm = ctx.load("normalized")
    raw = norm["findings"]
    code, cstats = code_dump(ctx)
    findings_json = json.dumps([compact(f) for f in raw], separators=(",", ":"))
    prompt = f"{ASK}\n\n## Source code\n{code}\n\n## Scanner findings ({len(raw)})\n{findings_json}"
    log(f"spaghetti: {cstats['files']} files ({cstats['chars']:,} chars) + {len(raw)} raw findings "
        f"-> one prompt of {len(prompt):,} chars")
    res = call_raw(ctx, "spaghetti", "oneshot", prompt, SCHEMA, "triage", skill_name="(none: spaghetti)",
                   use_tools=False, system=SYSTEM,
                   max_output_tokens=ctx.models.get("spaghetti_max_output_tokens", 64000))
    answers = res.data or {}

    # ---- per-raw-finding answers -> harness triage items (grouping only so the scorer can read it) ----
    by_id = {}
    for a in answers.get("scanner_findings", []) or []:
        if isinstance(a, dict) and a.get("id"):
            by_id.setdefault(str(a["id"]), a)
    unknown_ids = [i for i in by_id if i not in {f["id"] for f in raw}]
    items = []
    inconsistent_groups = 0
    for it in norm["triage_items"]:
        got = [by_id[fid] for fid in it["finding_ids"] if fid in by_id]
        labels = {VERDICT.get(str(a.get("verdict", "")).lower(), "needs_review") for a in got}
        if not got:
            v = {"verdict": "needs_review", "confidence": "low", "rationale": "not classified by the model",
                 "flip_fact": "n/a (spaghetti baseline)"}
        else:
            if len(labels) > 1:
                inconsistent_groups += 1
            verdict = "confirmed" if "confirmed" in labels else ("not_actionable" if labels == {"not_actionable"}
                                                                 else "needs_review")
            v = {"verdict": verdict, "confidence": "n/a", "flip_fact": "n/a (spaghetti baseline)",
                 "rationale": " | ".join(str(a.get("reason", ""))[:200] for a in got[:3]),
                 "raw_labels": sorted(labels), "classified": len(got), "of": len(it["finding_ids"])}
        items.append({**it, "triage": v})
    counts = {k: sum(i["triage"]["verdict"] == k for i in items) for k in ("confirmed", "not_actionable", "needs_review")}
    ctx.save("triage", {"app": ctx.app, "mode": "spaghetti", "counts": counts, "items": items})

    # same rule/CVE labelled both ways = "weird classifications"
    rule_labels = defaultdict(set)
    fmap = {f["id"]: f for f in raw}
    for fid, a in by_id.items():
        if fid in fmap:
            rule_labels[(fmap[fid]["tool"], fmap[fid].get("rule_id"))].add(str(a.get("verdict", "")).lower())
    contradictory_rules = sorted(f"{t}:{r}" for (t, r), labs in rule_labels.items() if len(labs) > 1)

    cands = []
    for i, n in enumerate(answers.get("new_vulnerabilities", []) or [], 1):
        if not isinstance(n, dict):
            continue
        cwe = n.get("cwe")
        cands.append({"id": f"D-{i:02d}", "title": n.get("title", ""), "family": "sast",
                      "cwe": [cwe] if isinstance(cwe, str) and cwe else (cwe or []),
                      "locations": [{"file": n.get("file", ""), "line": n.get("line"), "role": "sink"}],
                      "severity": n.get("severity"), "impact": n.get("description", ""), "pass": 1,
                      "origin": "spaghetti"})
    ctx.save("discovery", {"app": ctx.app, "mode": "spaghetti", "candidates": cands, "coverage_notes": []})

    stats = {"raw_findings": len(raw), "classified": sum(f["id"] in by_id for f in raw),
             "unclassified": sum(f["id"] not in by_id for f in raw), "hallucinated_ids": len(unknown_ids),
             "true_positive": sum(str(a.get("verdict", "")).lower() == "true_positive" for a in by_id.values()),
             "false_positive": sum(str(a.get("verdict", "")).lower() == "false_positive" for a in by_id.values()),
             "inconsistent_groups": inconsistent_groups, "contradictory_rules": len(contradictory_rules),
             "new_vulnerabilities": len(cands), "prompt_chars": len(prompt), "code_files": cstats["files"],
             "json_ok": bool(answers), "error": res.error}
    (ctx.dir / "02-spaghetti.json").write_text(json.dumps({
        "app": ctx.app, "stats": stats, "contradictory_rules": contradictory_rules,
        "hallucinated_ids": unknown_ids[:200], "code_stats": cstats, "answers": answers}, indent=1), encoding="utf-8")
    ctx.record_phase("spaghetti", **{f"n_{k}": v for k, v in stats.items() if isinstance(v, (int, bool))})
    log(f"spaghetti: {stats}")
    return stats
