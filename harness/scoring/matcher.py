"""Match harness detections to the ground truth.

A GT location matches a detection when they are in the same file and either
  * the GT location has no anchor (whole-file issues: lockfiles, IaC), or
  * the lines are within NEAR lines (any kind of finding), or
  * the lines are within FAR lines and the CWE groups overlap."""
from __future__ import annotations

import re
from pathlib import Path

NEAR, FAR = 6, 40

GROUPS = {
    "authz": {639, 862, 863, 284, 285, 915, 269, 266, 425, 1321, 566},
    "injection": {89, 78, 77, 94, 95, 943, 917, 1336, 74, 1321, 1427},
    "deser": {502},
    "xss": {79, 80, 116},
    "ssrf": {918},
    "path": {22, 23, 73, 36},
    "secrets": {798, 259, 321, 312, 522, 200, 540},
    "crypto": {327, 328, 916, 330, 338, 340, 759, 760, 261},
    "logic": {840, 841, 20, 367, 362, 682, 1284, 191, 799, 837, 770, 400, 1333},
    "info": {200, 209, 215, 532, 497, 538, 497},
    "auth": {347, 345, 287, 290, 294, 288, 306, 640, 620, 352, 1390, 330},
    "llm": {1427, 1426, 1039, 77, 74},
}
FAMILY_GROUPS = {
    "authz": {"authz"}, "logic": {"logic"}, "llm": {"llm", "injection"}, "injection": {"injection"},
    "deserialization": {"deser"}, "ssrf": {"ssrf"}, "path": {"path"}, "crypto": {"crypto"},
    "secret": {"secrets"}, "xss": {"xss"}, "info": {"info"},
}


def groups_of(cwes, family: str | None = None) -> set[str]:
    out = set(FAMILY_GROUPS.get(family or "", set()))
    for c in cwes or []:
        m = re.search(r"(\d+)", str(c))
        if m:
            n = int(m.group(1))
            out |= {g for g, nums in GROUPS.items() if n in nums}
    return out


def norm_file(f: str | None) -> str:
    f = (f or "").replace("\\", "/")
    while f.startswith("./") or f.startswith("/"):
        f = f[1:] if f.startswith("/") else f[2:]
    if f.startswith("Dockerfile ("):  # "Dockerfile (base image)"
        return "Dockerfile"
    if f.startswith("image:"):  # trivy-image lang packages inside the built image
        f = f[len("image:"):]
        for marker in ("/app/", "/src/"):
            if marker in f:
                f = f.split(marker, 1)[1]
        f = f.lstrip("/")
    return f


def resolve_gt(gt: dict, app_root: Path) -> dict:
    """Fill `line` for every anchored GT location."""
    for item in gt.get("vulns", []) + gt.get("decoys", []):
        for loc in item["locations"]:
            loc["line"] = None
            if loc.get("anchor"):
                try:
                    lines = (app_root / loc["file"]).read_text(encoding="utf-8").splitlines()
                except FileNotFoundError:
                    continue
                rx = re.compile(loc["anchor"])
                loc["line"] = next((i + 1 for i, l in enumerate(lines) if rx.search(l)), None)
    return gt


def loc_match(gt_loc: dict, gt_groups: set[str], det_file: str, det_line, det_groups: set[str]) -> bool:
    if norm_file(det_file) != gt_loc["file"]:
        return False
    if gt_loc.get("line") is None or det_line is None:
        return True  # whole-file GT issue, or a file-level finding (SCA / base image)
    d = abs(int(det_line) - gt_loc["line"])
    return d <= NEAR or (d <= FAR and bool(gt_groups & det_groups))


def item_matches(gt_item: dict, det_locs: list[tuple[str, int | None]], det_groups: set[str]) -> bool:
    gg = groups_of(gt_item.get("cwe", []), gt_item.get("family"))
    return any(loc_match(gl, gg, f, l, det_groups) for gl in gt_item["locations"] for f, l in det_locs)
