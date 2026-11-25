"""Stage 0: run Trivy, Semgrep and TruffleHog in pinned containers."""
from __future__ import annotations

import json
import subprocess
import time
import os
from pathlib import Path

from harness.core.run import ROOT, RunContext, log


def _docker(args: list[str], timeout: int = 1200) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", "run", "--rm", *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout)


def _rulesets() -> list[str]:
    lines = (ROOT / "scanners/semgrep/rulesets.txt").read_text(encoding="utf-8").splitlines()
    return [l.strip() for l in lines if l.strip() and not l.startswith("#")]


def run_scanners(ctx: RunContext) -> dict:
    out = ctx.dir / "00-scanners"
    out.mkdir(parents=True, exist_ok=True)
    src = str(ctx.app_path)
    images = ctx.config["scanners"]
    summary = {}

    jobs = {
        "trivy-fs": ([
            "-v", f"{src}:/src:ro", "-v", f"{out}:/out", "-v", "sec545-trivy-cache:/root/.cache",
            images["trivy"], "fs", "--scanners", "vuln,misconfig,secret", "--format", "json",
            "--output", "/out/trivy-fs.json", "--quiet", "/src"], "trivy-fs.json"),
        "trivy-image": ([
            "-v", ("//var/run/docker.sock" if os.name == "nt" else "/var/run/docker.sock") + ":/var/run/docker.sock", "-v", f"{out}:/out",
            "-v", "sec545-trivy-cache:/root/.cache", images["trivy"], "image", "--scanners", "vuln",
            "--format", "json", "--output", "/out/trivy-image.json", "--quiet", ctx.app_cfg["image"]], "trivy-image.json"),
        "semgrep": ([
            "-v", f"{src}:/src:ro", "-v", f"{out}:/out", images["semgrep"], "semgrep", "scan",
            *sum((["--config", r] for r in _rulesets()), []),
            "--json", "--output", "/out/semgrep.json", "--metrics", "off", "--quiet", "/src"], "semgrep.json"),
        "trufflehog": ([
            "-v", f"{src}:/src:ro", images["trufflehog"], "filesystem", "/src", "--json",
            "--no-verification", "--no-update"], "trufflehog.jsonl"),
    }
    for name, (args, fname) in jobs.items():
        log(f"scanning with {name} ...")
        t0 = time.time()
        proc = _docker(args)
        if name == "trufflehog":  # streams JSON lines on stdout
            (out / fname).write_text(proc.stdout, encoding="utf-8")
        dur = round(time.time() - t0, 1)
        ok = (out / fname).exists() and (out / fname).stat().st_size > 0
        if not ok:
            log(f"  {name} failed (exit {proc.returncode}): {proc.stderr[-800:]}")
        summary[name] = {"seconds": dur, "ok": ok, "exit": proc.returncode, "file": fname}
        log(f"  {name}: {'ok' if ok else 'FAILED'} in {dur}s")
    (out / "scan-summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    ctx.record_phase("scan", duration_s=sum(v["seconds"] for v in summary.values()), scanners=summary)
    return summary
