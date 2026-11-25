"""Compact repository map handed to every AI phase so it reads targeted files
instead of crawling the whole tree (saves tokens)."""
from __future__ import annotations

import re
from pathlib import Path

CODE_EXT = {".py", ".ts", ".js", ".ejs", ".html", ".yaml", ".yml", ".tf", ".json", ".sh", ".txt", ".env", ".pem", ".cfg", ".toml", ""}
ROUTE_PATTERNS = [
    re.compile(r'@router\.(get|post|put|patch|delete)\(\s*"([^"]+)"'),            # FastAPI
    re.compile(r'\b\w*[Rr]outer\.(get|post|put|patch|delete)\(\s*"([^"]+)"'),      # Express routers
    re.compile(r'\bapp\.(get|post|put|patch|delete)\(\s*"([^"]+)"'),               # Express app
]


def build(root: Path) -> str:
    lines = ["## File tree (lines)"]
    routes = []
    for p in sorted(root.rglob("*")):
        if p.is_dir() or "node_modules" in p.parts:
            continue
        rel = p.relative_to(root).as_posix()
        if p.suffix not in CODE_EXT and p.name not in ("Dockerfile", ".dockerignore"):
            lines.append(f"- {rel} (binary/asset)")
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if p.name == "package-lock.json":
            lines.append(f"- {rel} (lockfile, {text.count(chr(10))} lines)")
            continue
        lines.append(f"- {rel} ({text.count(chr(10)) + 1})")
        for i, line in enumerate(text.splitlines(), 1):
            for pat in ROUTE_PATTERNS:
                m = pat.search(line)
                if m:
                    routes.append(f"- {m.group(1).upper():6} {m.group(2):45} {rel}:{i}")
    out = "\n".join(lines)
    if routes:
        out += "\n\n## HTTP routes\n" + "\n".join(routes)
    return out
