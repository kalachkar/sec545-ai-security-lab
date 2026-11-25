import json
from pathlib import Path

from harness.normalizers.common import cwes, finding, rel

IAC_HINTS = ("dockerfile", "kubernetes", "terraform", "yaml.kubernetes", "hcl")
SECRET_HINTS = ("secrets", "detected-")


def parse(path: Path) -> tuple[list[dict], list[dict], int]:
    if not path.exists():
        return [], [{"reason": "semgrep.json missing"}], 0
    report = json.loads(path.read_text(encoding="utf-8"))
    out, excluded = [], []
    results = report.get("results") or []
    for r in results:
        rid = r.get("check_id", "")
        meta = r.get("extra", {}).get("metadata", {})
        family = "sast"
        if any(h in rid for h in IAC_HINTS):
            family = "misconfig"
        elif any(h in rid.split(".")[-1] for h in ("detected-",)) or ".secrets." in rid:
            family = "secret"
        out.append(finding("semgrep", family, rid, rid.split(".")[-1].replace("-", " "),
                           r.get("extra", {}).get("severity"), rel(r.get("path", "")),
                           r.get("start", {}).get("line"), r.get("extra", {}).get("message", ""),
                           cwes(meta.get("cwe")), extra={"end_line": r.get("end", {}).get("line")}))
    for e in report.get("errors") or []:
        excluded.append({"tool": "semgrep", "reason": f"scan error: {e.get('type')}",
                         "path": rel(str((e.get('spans') or [{}])[0].get('file', '')) if e.get('spans') else e.get('path', ''))})
    return out, excluded, len(results)
