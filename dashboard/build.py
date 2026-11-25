"""Build site/index.html: the self-contained 10-page story (GitHub Pages ready).

  python -m harness.cli dashboard      (or: python dashboard/build.py)

Inputs (all committed, aggregate only, no code or secrets):
  dashboard/presentation.html   page shell + navigation
  dashboard/story/story.js|css  the ten pages
  dashboard/story/data.js       benchmark aggregates (runs, scores, tokens, cost)
  dashboard/story/scanners.json scanner findings list (rule, file, severity) for pages 1-3
  dashboard/story/assets/       tool logos and leaderboard screenshots
  harness/skills/*/SKILL.md     shown on the harness page
"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DASH = ROOT / "dashboard"
STORY = DASH / "story"


def _b64(paths, mime):
    return {p.stem: f"data:{mime};base64," + base64.b64encode(p.read_bytes()).decode() for p in sorted(paths)}


def build() -> Path:
    scanners = json.loads((STORY / "scanners.json").read_text(encoding="utf-8"))
    deck = {"runs": [{"app": app, "run_id": "run-01", "meta": {"profile": "baseline"}, "complete": False, "scanner_findings": rows}
                     for app, rows in scanners.items()],
            "skills": {p.parent.name: p.read_text(encoding="utf-8") for p in (ROOT / "harness" / "skills").glob("*/SKILL.md")}}
    bench = (STORY / "data.js").read_text(encoding="utf-8").split("=", 1)[1].strip().rstrip(";")
    safe = lambda s: s.replace("</", "<\\/")
    html = (DASH / "presentation.html").read_text(encoding="utf-8-sig")
    html = (html.replace("/*__STORY_CSS__*/", (STORY / "story.css").read_text(encoding="utf-8"))
                .replace("/*__STORY_JS__*/", (STORY / "story.js").read_text(encoding="utf-8"))
                .replace("/*__BENCH__*/{}", safe(bench))
                .replace("/*__LOGOS__*/{}", json.dumps(_b64((STORY / "assets").glob("*.png"), "image/png")))
                .replace("/*__SHOTS__*/{}", json.dumps(_b64((STORY / "assets" / "boards").glob("*.jpg"), "image/jpeg")))
                .replace("/*__DATA__*/{}", safe(json.dumps(deck, ensure_ascii=False))))
    site = ROOT / "site"
    site.mkdir(exist_ok=True)
    out = site / "index.html"
    out.write_text(html, encoding="utf-8")
    (site / ".nojekyll").write_text("", encoding="utf-8")
    print(f"site -> {out.relative_to(ROOT)} ({out.stat().st_size // 1024} KB)")
    return out


if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))
    build()
