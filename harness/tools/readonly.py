"""Read-only code tools for the API provider, jailed to the blind workspace."""
from __future__ import annotations

import re
from pathlib import Path

MAX_CHARS = 20000

TOOL_DEFS = [
    {
        "name": "list_tree",
        "description": "List files under a directory of the target repository (relative path, default '.').",
        "input_schema": {"type": "object", "properties": {"path": {"type": "string"}}, "additionalProperties": False},
    },
    {
        "name": "read_file",
        "description": "Read a text file from the target repository with line numbers. Optional 1-based start/end lines.",
        "input_schema": {
            "type": "object",
            "properties": {"path": {"type": "string"}, "start": {"type": "integer"}, "end": {"type": "integer"}},
            "required": ["path"], "additionalProperties": False,
        },
    },
    {
        "name": "grep",
        "description": "Regex search across the target repository. Returns file:line: text matches (max 200).",
        "input_schema": {
            "type": "object",
            "properties": {"pattern": {"type": "string"}, "path": {"type": "string"}},
            "required": ["pattern"], "additionalProperties": False,
        },
    },
]


class ReadOnlyTools:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()

    def _safe(self, rel: str) -> Path:
        p = (self.root / (rel or ".")).resolve()
        if p != self.root and self.root not in p.parents:
            raise PermissionError(f"path escapes the repository: {rel}")
        return p

    def list_tree(self, path: str = ".") -> str:
        base = self._safe(path)
        files = [f.relative_to(self.root).as_posix() for f in sorted(base.rglob("*")) if f.is_file()]
        return "\n".join(files[:2000])

    def read_file(self, path: str, start: int | None = None, end: int | None = None) -> str:
        lines = self._safe(path).read_text(encoding="utf-8", errors="replace").splitlines()
        s = max(1, start or 1)
        e = min(len(lines), end or len(lines))
        out = "\n".join(f"{i}\t{lines[i - 1]}" for i in range(s, e + 1))
        return out[:MAX_CHARS]

    def grep(self, pattern: str, path: str = ".") -> str:
        rx = re.compile(pattern)
        hits = []
        for f in sorted(self._safe(path).rglob("*")):
            if not f.is_file() or f.name == "package-lock.json":
                continue
            try:
                for i, line in enumerate(f.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                    if rx.search(line):
                        hits.append(f"{f.relative_to(self.root).as_posix()}:{i}: {line.strip()[:200]}")
                        if len(hits) >= 200:
                            return "\n".join(hits)
            except OSError:
                continue
        return "\n".join(hits) or "(no matches)"

    def call(self, name: str, args: dict) -> str:
        if name not in ("list_tree", "read_file", "grep"):
            raise ValueError(f"unknown tool {name}")
        return getattr(self, name)(**args)
