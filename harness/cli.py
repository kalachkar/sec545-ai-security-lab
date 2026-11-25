"""SEC545 AI security harness.

  python -m harness.cli scan        --app snackoverflow      # 00 trivy + semgrep + trufflehog
  python -m harness.cli normalize   --app snackoverflow      # 01 one schema + triage items
  python -m harness.cli triage      --app snackoverflow      # 02 AI verdicts on scanner items
  python -m harness.cli discover    --app snackoverflow      # 03 AI finds what scanners missed
  python -m harness.cli validate    --app snackoverflow      # 04 static disposition + live PoC
  python -m harness.cli attack-path --app snackoverflow      # 05 severity + chains + findings.json
  python -m harness.cli score       --app snackoverflow      # 06 compare with ground truth
  python -m harness.cli run         --app snackoverflow      # all of the above
  python -m harness.cli dashboard                            # build dashboard/dist/index.html
"""
from __future__ import annotations

import argparse
import json
import sys
import time

from harness.core.run import RunContext, log

POCS_ONLY = False
PHASES = ["scan", "normalize", "triage", "discover", "validate", "attack-path", "score"]


def _phase(name: str, ctx: RunContext) -> None:
    t0 = time.time()
    log(f"===== {name} [{ctx.app} / {ctx.run_id}] =====")
    if name == "scan":
        from harness.scanners import run_scanners
        run_scanners(ctx)
    elif name == "normalize":
        from harness.normalizers import normalize
        normalize(ctx)
    elif name == "triage":
        from harness.phases import triage
        triage.run(ctx)
    elif name == "discover":
        from harness.phases import discovery
        discovery.run(ctx)
    elif name == "validate":
        from harness.phases import validation
        validation.run(ctx, pocs_only=POCS_ONLY)
    elif name == "attack-path":
        from harness.phases import attack_path
        attack_path.run(ctx)
    elif name == "spaghetti":
        from harness.phases import spaghetti
        spaghetti.run(ctx)
    elif name == "score":
        from harness.scoring import score
        score(ctx)
    log(f"===== {name} done in {time.time() - t0:.0f}s =====")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="harness", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=PHASES + ["run", "spaghetti", "dashboard"],
                    help="spaghetti = no-harness baseline: one prompt with all code + raw findings, then score")
    ap.add_argument("--app", help="snackoverflow | ragnarok")
    ap.add_argument("--profile", default=None, help="new runs default to cheap; resumes preserve the saved profile")
    ap.add_argument("--run-id", help="defaults to a new id for scan/run, latest otherwise")
    ap.add_argument("--from", dest="start", choices=PHASES, help="with `run`: resume from this phase")
    ap.add_argument("--pocs-only", action="store_true", help="validate: reuse stored dispositions, re-run PoCs + retry round")
    ap.add_argument("--seed-from", help="with a new run: copy scanner output + normalized findings from this run id "
                                        "(identical inputs for every model) and start at triage")
    args = ap.parse_args(argv)
    global POCS_ONLY
    POCS_ONLY = args.pocs_only

    if args.command == "dashboard":
        from dashboard.build import build
        build()
        return 0
    if not args.app:
        ap.error("--app is required")

    if args.command in ("scan", "run", "spaghetti") and not args.start:
        from harness.core.run import RESULTS
        existing = args.run_id and (RESULTS / args.app / args.run_id / "run.json").exists()
        # a spaghetti run is one call: an existing folder without its answer is a crashed attempt, so reuse it
        if existing and not (args.command == "spaghetti"
                             and not (RESULTS / args.app / args.run_id / "02-spaghetti.json").exists()):
            ap.error("run-id already exists; use a new ID or run --from <phase> to resume")
        ctx = RunContext.create(args.app, args.profile, args.run_id)
    else:
        ctx = RunContext.create(args.app, args.profile, args.run_id) if args.run_id else RunContext.latest(args.app)

    if args.seed_from:
        import shutil
        from harness.core.run import ARTIFACTS, RESULTS
        src = RESULTS / args.app / args.seed_from
        if not (src / ARTIFACTS["normalized"]).exists():
            ap.error(f"--seed-from {args.seed_from}: no normalized findings in {src}")
        if not ctx.has("normalized"):
            shutil.copytree(src / ARTIFACTS["scanners"], ctx.path("scanners"), dirs_exist_ok=True)
            shutil.copy2(src / ARTIFACTS["normalized"], ctx.path("normalized"))
            meta = ctx.meta()
            meta["seeded_from"] = args.seed_from
            meta["phases"]["normalize"] = {**json.loads((src / "run.json").read_text(encoding="utf-8"))
                                           .get("phases", {}).get("normalize", {}), "seeded": True}
            ctx._write_run_meta(meta)
            log(f"seeded {ctx.run_id} from {args.seed_from} (scanner output + normalized findings)")
        if args.command == "run":
            args.start = args.start or "triage"
        elif args.command != "spaghetti":
            ap.error("--seed-from is used with `run` or `spaghetti`")

    phases = PHASES if args.command == "run" else (["spaghetti", "score"] if args.command == "spaghetti"
                                                   else [args.command])
    if args.start:
        phases = PHASES[PHASES.index(args.start):]
    for p in phases:
        _phase(p, ctx)
        st = ctx.meta()["phases"].get({"discover": "discovery", "validate": "validation",
                                       "attack-path": "attack_path"}.get(p, p), {})
        broken = st.get("failed_calls", 0) - st.get("refused_calls", 0)  # refusals are results; keep going
        if st.get("calls") and st.get("failed_calls", 0) >= st["calls"] and broken > 0:
            raise SystemExit(f"every model session in {p} failed ({st['calls']}); stopping - see calls.jsonl")
    m = ctx.meta()
    log(f"total AI cost so far for {ctx.app}/{ctx.run_id}: ${m.get('total_cost_usd', 0):.3f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
