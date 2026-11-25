"""Stage 1: normalize raw scanner output and group it into triage items.

Grouping keeps AI cost flat: hundreds of CVEs collapse to one item per
package (a reachability question), OS CVEs to one item per base image,
and duplicate secrets reported by several tools to one item per location."""
from __future__ import annotations

from collections import defaultdict

from harness.core.run import RunContext, log
from harness.normalizers import semgrep, trivy, trufflehog
from harness.normalizers.common import max_sev


def _group(findings: list[dict]) -> list[dict]:
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for f in findings:
        if f["family"] == "sca":
            key = ("sca", f["package"]["name"], f["package"]["installed"])
        elif f["family"] == "container":
            key = ("container", "base-image")
        elif f["family"] == "secret":
            key = ("secret", f["file"], f["line"])
        elif f["family"] == "misconfig":
            key = ("misconfig", f["file"], f["rule_id"])
        else:
            key = ("sast", f["file"], f["line"])
        groups[key].append(f)

    items = []
    for i, (key, fs) in enumerate(sorted(groups.items(), key=lambda kv: (kv[0][0], str(kv[0][1:])))):
        family = key[0]
        tools = sorted({f["tool"] for f in fs})
        if family == "sca":
            vulns = sorted({f["package"]["vuln"] for f in fs})
            fixed = sorted({f["package"]["fixed"] for f in fs if f["package"].get("fixed")})
            files = sorted({f["file"] for f in fs if f["file"]})
            title = f"{key[1]}=={key[2]}: {len(vulns)} known vulnerabilities"
            summary = "; ".join(sorted({f["title"].split(": ", 1)[-1] for f in fs})[:6])
            loc = {"file": next((x for x in files if not x.startswith("image:")), files[0] if files else ""), "line": None}
            extra = {"package": key[1], "version": key[2], "vulns": vulns[:40], "fixed_versions": fixed[:5], "seen_in": files}
        elif family == "container":
            pkgs = sorted({f["package"]["name"] for f in fs})
            title = f"Base image OS packages: {len(fs)} CVEs across {len(pkgs)} packages"
            summary = "EOL Debian base image with unpatched OS packages"
            loc = {"file": "Dockerfile", "line": 1}
            extra = {"packages": pkgs[:30]}
        else:
            f0 = fs[0]
            title = f0["title"] if len(fs) == 1 else f"{f0['title']} (+{len(fs) - 1} related)"
            summary = " | ".join(sorted({f["message"][:200] for f in fs}))[:600]
            loc = {"file": f0["file"], "line": f0["line"]}
            extra = {"rules": sorted({f["rule_id"] for f in fs})}
        items.append({
            "triage_item_id": f"T-{i + 1:03d}", "family": family, "title": title, "severity": max_sev(f["severity"] for f in fs),
            "tools": tools, "location": loc, "cwe": sorted({c for f in fs for c in f["cwe"]}),
            "summary": summary, "finding_ids": [f["id"] for f in fs], "count": len(fs), **extra,
        })
    return items


def normalize(ctx: RunContext) -> dict:
    d = ctx.dir / "00-scanners"
    parts = {
        "trivy-fs": trivy.parse(d / "trivy-fs.json", "trivy-fs"),
        "trivy-image": trivy.parse(d / "trivy-image.json", "trivy-image"),
        "semgrep": semgrep.parse(d / "semgrep.json"),
        "trufflehog": trufflehog.parse(d / "trufflehog.jsonl"),
    }
    findings, exclusions, stats = [], [], {}
    seen = set()
    for name, (fs, ex, raw) in parts.items():
        dupes = 0
        for f in fs:
            if f["id"] in seen:
                dupes += 1
                continue
            seen.add(f["id"])
            findings.append(f)
        for n, e in enumerate(ex, 1):
            exclusions.append({"n": len(exclusions) + 1, "source": name, **e})
        stats[name] = {"raw_rows": raw, "imported": len(fs) - dupes, "duplicates": dupes, "excluded": len(ex)}

    # image lang-pkgs duplicate the fs lockfile CVEs: keep both rows (evidence), group them together
    items = _group(findings)
    data = {
        "app": ctx.app, "stats": stats,
        "totals": {"raw_findings": len(findings), "triage_items": len(items),
                   "by_family": {fam: sum(1 for f in findings if f["family"] == fam)
                                 for fam in ("sca", "container", "misconfig", "secret", "sast")}},
        "findings": findings, "triage_items": items, "exclusions": exclusions,
    }
    ctx.save("normalized", data)
    log(f"normalized {len(findings)} findings -> {len(items)} triage items "
        f"({', '.join(f'{k}={v}' for k, v in data['totals']['by_family'].items())})")
    ctx.record_phase("normalize", raw_findings=len(findings), triage_items=len(items))
    return data
