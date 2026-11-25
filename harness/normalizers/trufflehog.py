"""TruffleHog JSONL parser (codex-security has no built-in TruffleHog reader, so this is ours)."""
import json
from pathlib import Path

from harness.normalizers.common import finding, rel


def parse(path: Path) -> tuple[list[dict], list[dict], int]:
    if not path.exists():
        return [], [{"reason": "trufflehog.jsonl missing"}], 0
    out, excluded, raw = [], [], 0
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        rec = json.loads(line)
        if "SourceMetadata" not in rec:  # log lines
            continue
        raw += 1
        fs = rec["SourceMetadata"]["Data"].get("Filesystem", {})
        verified = rec.get("Verified", False)
        out.append(finding("trufflehog", "secret", rec.get("DetectorName", "secret"),
                           f"{rec.get('DetectorName')} credential ({'verified' if verified else 'unverified'})",
                           "high" if verified else "medium", rel(fs.get("file", "")), fs.get("line"),
                           (rec.get("Redacted") or rec.get("Raw", ""))[:12] + "…", ["CWE-798"],
                           extra={"verified": verified, "decoder": rec.get("DecoderName")}))
    return out, excluded, raw
