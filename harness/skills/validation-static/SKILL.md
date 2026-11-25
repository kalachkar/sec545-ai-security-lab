# Skill: validation, static (prove or disprove from code)

Adapted from openai/codex-security `validation`. Decide whether each candidate is supported by **code evidence**. There is no running instance and nothing will be executed, so do **not** write exploit payloads or proof-of-concept requests.

## Steps (per candidate)
1. Identify the claimed attacker input, security boundary, relevant control, sensitive operation and preconditions.
2. Gather supporting and counter-evidence in the code. Re-read the cited lines; do not trust the candidate text.
3. Record a disposition: `survives: yes | no | uncertain`, confidence, the static evidence (cite `file:line` for source, control and sink), and the exact proof gap if any.
4. Add `human_check`: one sentence describing what a reviewer should verify to confirm or refute it (e.g. "confirm the route is reachable without the ownership check in orders.py:42"). No payloads.

## Output
Every input candidate exactly once, in the JSON schema provided.
