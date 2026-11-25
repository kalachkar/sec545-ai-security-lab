"""Stage 6: score the run against the ground-truth answer key (never shown to the AI)."""
from __future__ import annotations

import re
from pathlib import Path

import yaml

from harness.core.run import ROOT, RunContext, log
from harness.scoring.matcher import groups_of, item_matches, resolve_gt

STEP_ID = re.compile(r"([DT]-\d{2,3})")


def step_id(text: str):
    m = STEP_ID.search(str(text))
    return m.group(1) if m else None


GOOD_TRIAGE = ("confirmed", "needs_review")


def _pct(a, b):
    return round(100 * a / b, 1) if b else 0.0


def score(ctx: RunContext) -> dict:
    gt = resolve_gt(yaml.safe_load((ROOT / "ground-truth" / f"{ctx.app}.yaml").read_text(encoding="utf-8")), ctx.app_path)
    norm = ctx.load("normalized")
    triage = ctx.load("triage")["items"]
    disc = ctx.load("discovery")["candidates"]
    val = {r["id"]: r for r in ctx.load("validation")["records"]} if ctx.has("validation") else {}
    ap = ctx.load("attack_path") if ctx.has("attack_path") else {"findings": [], "chains": []}
    decision = {f["id"]: f for f in ap.get("findings", [])}

    raw = norm["findings"]
    t_by_fid = {fid: t for t in triage for fid in t["finding_ids"]}

    def raw_hits(item):
        return [f for f in raw if item_matches(item, [(f["file"], f["line"])], groups_of(f["cwe"], f["family"]))]

    def disc_hits(item):
        return [c for c in disc if item_matches(item, [(l["file"], l.get("line")) for l in c["locations"]],
                                                groups_of(c.get("cwe"), c.get("family")))]

    def survives(fid):
        v = val.get(fid)
        if not v:
            return None
        return v["validation"].get("survives")

    def poc(fid):
        v = val.get(fid)
        return ((v or {}).get("poc_result") or {}).get("status")

    id_to_vulns: dict[str, set[str]] = {}
    vuln_rows = []
    for v in gt["vulns"]:
        rh = raw_hits(v)
        titems = {t_by_fid[f["id"]]["triage_item_id"]: t_by_fid[f["id"]] for f in rh if f["id"] in t_by_fid}
        dh = disc_hits(v)
        for tid in titems:
            id_to_vulns.setdefault(tid, set()).add(v["id"])
        for c in dh:
            id_to_vulns.setdefault(c["id"], set()).add(v["id"])
        verdicts = [t["triage"]["verdict"] for t in titems.values()]
        triage_ok = any(x in GOOD_TRIAGE for x in verdicts)
        ai_ok = [c for c in dh if survives(c["id"]) != "no" or poc(c["id"]) == "passed"]
        # strict: only a confirmed triage verdict or a candidate that positively survived validation
        # (no validation phase, e.g. the spaghetti baseline, means the claim stands as reported)
        strict = ("confirmed" in verdicts) or any(survives(c["id"]) in ("yes", None) or poc(c["id"]) == "passed"
                                                  for c in dh)
        ids = list(titems) + [c["id"] for c in dh]
        proved = any(poc(i) == "passed" for i in ids)
        sevs = [decision[i]["severity"] for i in ids if i in decision]
        found_by_scanner = bool(rh)
        found = triage_ok or bool(ai_ok)
        if found and not found_by_scanner:
            status = "ai_found"
        elif found:
            status = "scanner_confirmed"
        elif found_by_scanner:
            status = "dismissed"  # scanner saw it, AI triage wrongly dismissed
        else:
            status = "missed"
        vuln_rows.append({
            "found_strict": strict, "suppressed_items": sorted(i for i, t in titems.items()
                                                                if t["triage"]["verdict"] == "not_actionable"),
            "id": v["id"], "title": v["title"], "class": v["class"], "family": v.get("family"),
            "severity": v["severity"], "scanner_tools": sorted({f["tool"] for f in rh}),
            "triage_items": sorted(titems), "triage_verdicts": sorted(set(verdicts)),
            "ai_candidates": [c["id"] for c in dh], "found_by_scanner": found_by_scanner, "found": found,
            "proved_live": proved, "status": status, "ai_severity": sevs[0] if sevs else None,
            "locations": [{"file": l["file"], "line": l.get("line")} for l in v["locations"]],
        })

    decoy_rows = []
    for d in gt["decoys"]:
        rh = raw_hits(d)
        titems = {t_by_fid[f["id"]]["triage_item_id"]: t_by_fid[f["id"]] for f in rh if f["id"] in t_by_fid}
        planted_ids = {c for r in vuln_rows for c in r["ai_candidates"]}
        dh = [c for c in disc_hits(d) if survives(c["id"]) != "no" and c["id"] not in planted_ids]
        verdicts = sorted({t["triage"]["verdict"] for t in titems.values()})
        for i in list(titems) + [c["id"] for c in dh]:
            id_to_vulns.setdefault(i, set()).add(d["id"])
        if dh:
            outcome = "ai_overreported"
        elif titems and all(x == "not_actionable" for x in verdicts):
            outcome = "dismissed_correctly"
        elif titems:
            outcome = "kept_by_triage" if "confirmed" in verdicts else "needs_review"
        else:
            outcome = "ignored_correctly"
        decoy_rows.append({"id": d["id"], "title": d["title"], "flagged_by_scanners": sorted({f["tool"] for f in rh}),
                           "triage_verdicts": verdicts, "ai_candidates": [c["id"] for c in dh],
                           "outcome": outcome, "why_safe": d["why_safe"]})

    # AI precision on discovery
    disc_rows = []
    for c in disc:
        hits = sorted(id_to_vulns.get(c["id"], set()))
        s = survives(c["id"])
        kind = ("decoy" if hits and all("-D" in h for h in hits) else "planted" if hits else "unplanted")
        disc_rows.append({"id": c["id"], "title": c["title"], "family": c.get("family"), "matches": hits,
                          "kind": kind, "survives": s, "poc": poc(c["id"]),
                          "severity": (decision.get(c["id"]) or {}).get("severity")})
    kept = [r for r in disc_rows if r["survives"] != "no"]

    # chains: each step maps to its single best-matching planted vuln (most locations matched, then nearest line)
    gt_by_id = {v["id"]: v for v in gt["vulns"]}
    t_by_id = {t["triage_item_id"]: t for t in triage}
    d_by_id = {c["id"]: c for c in disc}

    def det_locs(fid):
        if fid in d_by_id:
            return [(l["file"], l.get("line")) for l in d_by_id[fid]["locations"]]
        if fid in t_by_id:
            return [(t_by_id[fid]["location"]["file"], t_by_id[fid]["location"]["line"])]
        return []

    def primary(fid):
        best, key = None, None
        locs = det_locs(fid)
        for vid in id_to_vulns.get(fid or "", set()):
            if vid not in gt_by_id:
                continue
            gl = gt_by_id[vid]["locations"]
            hits = sum(any(g["file"] == f for g in gl) for f, _ in locs)
            dist = min([abs((ln or 0) - (g.get("line") or 0)) for f, ln in locs for g in gl if g["file"] == f] or [9999])
            k = (hits, -dist)
            if key is None or k > key:
                best, key = vid, k
        return best

    ai_chains = []
    for ch in ap.get("chains", []):
        step_ids = [step_id(x) for x in ch.get("steps", [])]
        mapped = [p for p in (primary(sid) for sid in step_ids) if p]
        ai_chains.append({**ch, "step_ids": step_ids, "mapped_vulns": mapped})
    chain_rows = []
    for g in gt["chains"]:
        best, best_cov = None, 0
        for ch in ai_chains:
            cov = len(set(g["steps"]) & set(ch["mapped_vulns"]))
            if cov > best_cov:
                best, best_cov = ch, cov
        need = min(2, len(g["steps"]))
        chain_rows.append({"id": g["id"], "title": g["title"], "steps": g["steps"], "severity": g["severity"],
                           "matched_ai_chain": best["id"] if best and best_cov >= need else None,
                           "coverage": f"{best_cov}/{len(g['steps'])}",
                           "found": bool(best and best_cov >= need)})

    n = len(vuln_rows)
    scanner_hits = sum(r["found_by_scanner"] for r in vuln_rows)
    found = sum(r["found"] for r in vuln_rows)
    ai_only = [r for r in vuln_rows if r["status"] == "ai_found"]
    by_class = {}
    for cls in ("scanner", "hybrid", "ai_only"):
        rows = [r for r in vuln_rows if r["class"] == cls]
        by_class[cls] = {"total": len(rows), "scanner": sum(r["found_by_scanner"] for r in rows),
                         "harness": sum(r["found"] for r in rows)}
    # Step-5 metrics: what a human has to deal with, and what real bugs were silently dropped.
    planted_ids_all = {vid for vid in gt_by_id}
    def is_planted(i):
        return bool(id_to_vulns.get(i, set()) & planted_ids_all)
    queue_triage = [t for t in triage if t["triage"]["verdict"] in ("confirmed", "needs_review")]
    queue_disc = [r for r in disc_rows if r["survives"] != "no"]
    queue = len(queue_triage) + len(queue_disc)
    queue_planted = sum(is_planted(t["triage_item_id"]) for t in queue_triage) + sum(r["kind"] == "planted" for r in queue_disc)
    titems_all = len(triage)
    t_conf = sum(t["triage"]["verdict"] == "confirmed" for t in triage)
    t_na = sum(t["triage"]["verdict"] == "not_actionable" for t in triage)
    meta = ctx.meta()
    data = {
        "app": ctx.app, "run_id": ctx.run_id,
        "metrics": {
            "planted": n, "scanner_recall": _pct(scanner_hits, n), "harness_recall": _pct(found, n),
            "scanner_found": scanner_hits, "harness_found": found, "ai_only_found": len(ai_only),
            "proved_live": sum(r["proved_live"] for r in vuln_rows), "missed": n - found,
            "raw_scanner_findings": len(raw), "triage_items": titems_all, "triage_confirmed": t_conf,
            "triage_not_actionable": t_na, "noise_reduction": _pct(t_na, titems_all),
            "decoys": len(decoy_rows),
            "decoys_handled": sum(r["outcome"] in ("dismissed_correctly", "ignored_correctly") for r in decoy_rows),
            "ai_candidates": len(disc_rows), "ai_kept": len(kept),
            "ai_precision": _pct(sum(r["kind"] == "planted" for r in kept), len(kept)),
            "ai_unplanted": sum(r["kind"] == "unplanted" for r in kept),
            "ai_decoy_fp": sum(r["kind"] == "decoy" for r in kept),
            "harness_found_strict": sum(r["found_strict"] for r in vuln_rows),
            "harness_recall_strict": _pct(sum(r["found_strict"] for r in vuln_rows), n),
            "false_suppressions": sum(r["status"] == "dismissed" for r in vuln_rows),
            "suppressed_planted_items": sum(len(r["suppressed_items"]) for r in vuln_rows),
            "triage_needs_review": sum(t["triage"]["verdict"] == "needs_review" for t in triage),
            "review_queue": queue, "review_queue_planted": queue_planted,
            "review_signal_pct": _pct(queue_planted, queue),
            "decoys_flagged": sum(r["outcome"] in ("ai_overreported", "kept_by_triage") for r in decoy_rows),
            "chains_gt": len(chain_rows), "chains_found": sum(r["found"] for r in chain_rows),
            "ai_chains": len(ai_chains),
            "cost_usd": meta.get("total_cost_usd", 0),
            "duration_s": round(sum(p.get("duration_s", 0) for p in meta["phases"].values()), 1),
            "by_class": by_class,
        },
        "vulns": vuln_rows, "decoys": decoy_rows, "discovery": disc_rows, "chains": chain_rows,
        "ai_chains": ai_chains, "phases": meta["phases"],
    }
    ctx.save("score", data)
    m = data["metrics"]
    log(f"SCORE {ctx.app}: scanners {m['scanner_found']}/{n} ({m['scanner_recall']}%) -> harness "
        f"{m['harness_found']}/{n} ({m['harness_recall']}%), AI-only +{m['ai_only_found']}, proved live "
        f"{m['proved_live']}, decoys {m['decoys_handled']}/{m['decoys']}, chains {m['chains_found']}/{m['chains_gt']}, "
        f"AI precision {m['ai_precision']}%, cost ${m['cost_usd']}")
    return data
