# Scanners

All three scanners run as pinned Docker images (versions in `harness/config.yaml`), with the app folder mounted **read-only**.

| Tool | Role | Command (what `harness scan` runs) | Raw output |
|---|---|---|---|
| Trivy | SCA + IaC/Docker misconfig + secrets | `trivy fs --scanners vuln,misconfig,secret` on the source, plus `trivy image --scanners vuln` on the built app image | `trivy-fs.json`, `trivy-image.json` |
| Semgrep | SAST | `semgrep scan` with the rulesets in `semgrep/rulesets.txt` | `semgrep.json` |
| TruffleHog | Secrets | `trufflehog filesystem --no-verification` (offline: fake keys are never sent to vendors) | `trufflehog.jsonl` |

Raw outputs land in `results/<app>/<run-id>/00-scanners/` and are never modified. `harness normalize` turns them into one schema (`01-normalized.json`).

The Trivy vulnerability DB is cached in the `sec545-trivy-cache` Docker volume.
