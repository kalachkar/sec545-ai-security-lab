import json
from pathlib import Path

from harness.normalizers.common import cwes, finding, rel


def parse(path: Path, source: str) -> tuple[list[dict], list[dict], int]:
    """Returns (findings, exclusions, raw_rows)."""
    if not path.exists():
        return [], [{"reason": f"{path.name} missing"}], 0
    report = json.loads(path.read_text(encoding="utf-8"))
    out, excluded, raw = [], [], 0
    for res in report.get("Results") or []:
        target, cls = res.get("Target", ""), res.get("Class", "")
        is_os = cls == "os-pkgs"
        file = "Dockerfile (base image)" if is_os else ("" if source == "trivy-image" else rel(target))
        if source == "trivy-image" and cls == "lang-pkgs":
            file = f"image:{target}"
        for v in res.get("Vulnerabilities") or []:
            raw += 1
            pkg = {"name": v.get("PkgName"), "installed": v.get("InstalledVersion"),
                   "fixed": v.get("FixedVersion"), "vuln": v.get("VulnerabilityID")}
            out.append(finding(source, "container" if is_os else "sca", v.get("VulnerabilityID"),
                               f"{v.get('PkgName')} {v.get('InstalledVersion')}: {v.get('Title') or v.get('VulnerabilityID')}",
                               v.get("Severity"), file, None, v.get("Description", ""),
                               cwes(v.get("CweIDs")), pkg, {"target": target}))
        for m in res.get("Misconfigurations") or []:
            raw += 1
            if m.get("Status") != "FAIL":
                excluded.append({"tool": source, "rule": m.get("ID"), "reason": f"status {m.get('Status')}"})
                continue
            line = (m.get("CauseMetadata") or {}).get("StartLine")
            out.append(finding(source, "misconfig", m.get("AVDID") or m.get("ID"), m.get("Title", ""),
                               m.get("Severity"), rel(target), line, m.get("Message", "")))
        for s in res.get("Secrets") or []:
            raw += 1
            out.append(finding(source, "secret", s.get("RuleID"), s.get("Title", "secret"), s.get("Severity"),
                               rel(target), s.get("StartLine"), s.get("Match", "")[:120], ["CWE-798"]))
    return out, excluded, raw
