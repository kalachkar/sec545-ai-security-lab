"""Read-only preflight: python -m harness.doctor. Makes no model calls."""
import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path


def main():
    root = Path(__file__).resolve().parents[1]
    failures = []

    def check(label, ok, hint=""):
        print(f"{'OK' if ok else 'FAIL'}  {label}" + (f" — {hint}" if not ok else ""))
        if not ok:
            failures.append(label)

    check("Python 3.10+", sys.version_info >= (3, 10))
    for mod in ("yaml", "jsonschema"):
        check(mod, importlib.util.find_spec(mod) is not None, "pip install -r requirements.txt")
    for name in ("snackoverflow", "ragnarok"):
        check(f"Range: {name}", (root / "apps" / name / "docker-compose.yml").exists(),
              "git submodule update --init --recursive")
    for command in (["git", "--version"], ["docker", "info", "--format", "{{.OSType}}"],
                    ["docker", "compose", "version"]):
        try:
            proc = subprocess.run(command, capture_output=True, text=True, timeout=30)
            ok = proc.returncode == 0
            if command[1] == "info":
                ok = ok and proc.stdout.strip() == "linux"
            check(" ".join(command[:2]), ok, "Install/start Docker with Linux containers, or install Git")
        except (OSError, subprocess.TimeoutExpired):
            check(" ".join(command[:2]), False, "Executable unavailable or timed out")
    if importlib.util.find_spec("yaml"):
        from harness.core.run import load_config
        cfg = load_config()
        if cfg["provider"] == "claude_cli":
            check("Claude CLI on PATH", shutil.which("claude") is not None, "Install Claude Code and sign in")
            print("NOTE  Login/quota/model access must be checked in Claude Code; no paid probe was run.")
        else:
            import os
            check("Anthropic SDK", importlib.util.find_spec("anthropic") is not None, "pip install -r requirements-api.txt")
            check("ANTHROPIC_API_KEY present", bool(os.environ.get("ANTHROPIC_API_KEY")), "Set it locally; never commit it")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
