"""Run context: where artifacts live, how they are written, and the cost ledger."""
from __future__ import annotations

import json
import os
import time
import subprocess
import platform
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
HARNESS = ROOT / "harness"
# Overridable so the harness can run on Databricks with results in a UC Volume and the
# range extracted outside the pipeline checkout (the range never lands on the laptop).
RESULTS = Path(os.environ["SEC545_RESULTS"]) if os.environ.get("SEC545_RESULTS") else ROOT / "results"
RANGE_DIR = Path(os.environ["SEC545_RANGE_DIR"]) if os.environ.get("SEC545_RANGE_DIR") else ROOT / "apps"

ARTIFACTS = {
    "scanners": "00-scanners",
    "normalized": "01-normalized.json",
    "triage": "02-triage.json",
    "discovery": "03-discovery.json",
    "validation": "04-validation.json",
    "attack_path": "05-attack-paths.json",
    "findings": "findings.json",
    "score": "06-score.json",
}


def load_config() -> dict:
    return yaml.safe_load((HARNESS / "config.yaml").read_text(encoding="utf-8"))


def git_revision(path: Path) -> str | None:
    try:
        return subprocess.check_output(["git", "-C", str(path), "rev-parse", "HEAD"],
                                       text=True, stderr=subprocess.DEVNULL).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def _rel(p: Path) -> str:
    for base in (ROOT, RESULTS):
        try:
            return str(p.relative_to(base))
        except ValueError:
            continue
    return str(p)


def log(msg: str) -> None:
    print(f"[{datetime.now():%H:%M:%S}] {msg}", flush=True)


@dataclass
class RunContext:
    app: str
    run_id: str
    config: dict
    profile: str = "cheap"
    started: float = field(default_factory=time.time)

    @classmethod
    def create(cls, app: str, profile: str | None = None, run_id: str | None = None) -> "RunContext":
        cfg = load_config()
        if app not in cfg["apps"]:
            raise SystemExit(f"unknown app {app!r}; choose from {list(cfg['apps'])}")
        run_id = run_id or datetime.now().strftime("%Y%m%d-%H%M%S")
        if not run_id or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_." for c in run_id) or run_id in (".", ".."):
            raise SystemExit("run-id must be a simple name, not a path")
        existing = RESULTS / app / run_id / "run.json"
        saved = json.loads(existing.read_text(encoding="utf-8")) if existing.exists() else None
        profile = profile or (saved.get("profile", "cheap") if saved else "cheap")
        if profile not in cfg["profiles"]:
            raise SystemExit(f"unknown profile: {profile}")
        if saved and saved.get("profile") != profile:
            raise SystemExit("Existing run uses a different profile; choose a new run-id.")
        ctx = cls(app=app, run_id=run_id, config=cfg, profile=profile)
        ctx.dir.mkdir(parents=True, exist_ok=True)
        (ctx.dir / "transcripts").mkdir(exist_ok=True)
        latest = RESULTS / app / "LATEST"
        latest.write_text(ctx.run_id, encoding="utf-8")
        if not (ctx.dir / "run.json").exists():
            ctx._write_run_meta({"app": app, "run_id": ctx.run_id, "profile": profile,
                                 "provider": cfg["profiles"][profile].get("provider", cfg["provider"]),
                                 "started_at": datetime.now().isoformat(),
                                 "phases": {}, "pipeline_commit": git_revision(ROOT) or os.environ.get("SEC545_PIPELINE_COMMIT"),
                                 "range_commit": git_revision(RANGE_DIR) or os.environ.get("SEC545_RANGE_COMMIT"),
                                 "platform": platform.platform(), "python": platform.python_version(),
                                 "model_settings": cfg["profiles"][profile],
                                 "scanner_images": cfg["scanners"]})
        return ctx

    @classmethod
    def latest(cls, app: str) -> "RunContext":
        marker = RESULTS / app / "LATEST"
        if not marker.exists():
            raise SystemExit(f"no runs for {app}; run `harness scan --app {app}` first")
        run_id = marker.read_text(encoding="utf-8").strip()
        meta = json.loads((RESULTS / app / run_id / "run.json").read_text(encoding="utf-8"))
        return cls(app=app, run_id=run_id, config=load_config(), profile=meta.get("profile", "cheap"))

    # ---- paths ----
    @property
    def dir(self) -> Path:
        return RESULTS / self.app / self.run_id

    @property
    def app_cfg(self) -> dict:
        return self.config["apps"][self.app]

    @property
    def app_path(self) -> Path:
        path = RANGE_DIR / Path(self.app_cfg["path"]).name
        if not (path / "docker-compose.yml").exists():
            raise SystemExit("Range missing. Run: git submodule update --init --recursive")
        return path

    @property
    def models(self) -> dict:
        return self.config["profiles"][self.profile]

    @property
    def provider_name(self) -> str:
        return self.models.get("provider", self.config["provider"])

    def log_call(self, row: dict) -> None:
        """Append one model-session record to calls.jsonl (kept forever for later analysis)."""
        with (self.dir / "calls.jsonl").open("a", encoding="utf-8") as f:
            f.write(json.dumps(row, default=str) + "\n")

    def path(self, key: str) -> Path:
        return self.dir / ARTIFACTS[key]

    # ---- artifacts ----
    def save(self, key: str, data: Any) -> Path:
        p = self.path(key)
        p.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        log(f"wrote {_rel(p)}")
        return p

    def load(self, key: str) -> Any:
        p = self.path(key)
        if not p.exists():
            raise SystemExit(f"missing {_rel(p)}; run the earlier phase first")
        return json.loads(p.read_text(encoding="utf-8"))

    def has(self, key: str) -> bool:
        return self.path(key).exists()

    def transcript(self, name: str, content: str) -> Path:
        p = self.dir / "transcripts" / name
        p.write_text(content, encoding="utf-8")
        return p

    # ---- ledger ----
    def _write_run_meta(self, meta: dict) -> None:
        (self.dir / "run.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

    def meta(self) -> dict:
        return json.loads((self.dir / "run.json").read_text(encoding="utf-8"))

    def record_phase(self, phase: str, **stats) -> None:
        meta = self.meta()
        entry = meta["phases"].setdefault(phase, {"cost_usd": 0.0, "input_tokens": 0, "output_tokens": 0,
                                                  "duration_s": 0.0, "calls": 0})
        for k in ("cost_usd", "input_tokens", "output_tokens", "duration_s", "calls"):
            entry[k] = round(entry.get(k, 0) + stats.pop(k, 0), 6)
        entry.update(stats)
        meta["phases"][phase] = entry
        meta["total_cost_usd"] = round(sum(p.get("cost_usd", 0) for p in meta["phases"].values()), 4)
        meta["updated_at"] = datetime.now().isoformat()
        self._write_run_meta(meta)
