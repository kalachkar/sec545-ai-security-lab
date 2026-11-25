"""One schema for every scanner finding (modeled on codex-security `publish-findings`:
stable source id per occurrence, native evidence kept, every row accounted for)."""
from __future__ import annotations

import hashlib
import re

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def norm_sev(s: str | None) -> str:
    s = (s or "").lower()
    return {"error": "high", "warning": "medium", "unknown": "info", "note": "low"}.get(s, s if s in SEVERITY_ORDER else "info")


def max_sev(sevs) -> str:
    sevs = [s for s in sevs if s in SEVERITY_ORDER]
    return min(sevs, key=SEVERITY_ORDER.index) if sevs else "info"


def rel(path: str) -> str:
    path = (path or "").replace("\\", "/")
    for prefix in ("/src/", "src/" if False else "\0"):
        if path.startswith(prefix):
            path = path[len(prefix):]
    return path.lstrip("/")


def cwes(*texts) -> list[str]:
    found = set()
    for t in texts:
        if isinstance(t, (list, tuple)):
            t = " ".join(map(str, t))
        for m in re.findall(r"CWE-(\d+)", str(t or "")):
            found.add(f"CWE-{int(m)}")
    return sorted(found)


def finding(tool: str, family: str, rule_id: str, title: str, severity: str, file: str, line: int | None,
            message: str = "", cwe=None, package=None, extra=None) -> dict:
    key = f"{tool}|{rule_id}|{file}|{line}|{(package or {}).get('name', '')}|{(package or {}).get('vuln', '')}"
    return {
        "id": f"{tool[:3].upper()}-{hashlib.sha1(key.encode()).hexdigest()[:8]}",
        "tool": tool, "family": family, "rule_id": rule_id, "title": title, "severity": norm_sev(severity),
        "file": file, "line": line, "message": (message or "")[:600], "cwe": cwe or [],
        "package": package, "extra": extra or {},
    }
