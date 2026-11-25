"""Blind workspace: a copy of the target app outside the project tree.

The AI only ever sees this copy, so it cannot wander into ground-truth/,
exploit scripts, or the app README (which describes the demo)."""
from __future__ import annotations

import shutil
import tempfile
import threading
from pathlib import Path

EXCLUDE_DIRS = {"node_modules", "dist", "data", ".git", "__pycache__", ".venv"}
EXCLUDE_FILES = {"README.md"}


_lock = threading.Lock()


def make_workspace(app_path: Path, app: str, run_id: str) -> Path:
    dest = Path(tempfile.gettempdir()) / "sec545-blind" / f"{app}-{run_id}"
    with _lock:  # phases call this from parallel threads; create the copy exactly once
        return dest if dest.exists() else _copy(app_path, dest)


def _copy(app_path: Path, dest: Path) -> Path:

    def ignore(directory, names):
        return [n for n in names if n in EXCLUDE_DIRS or n in EXCLUDE_FILES]

    shutil.copytree(app_path, dest, ignore=ignore)
    return dest
