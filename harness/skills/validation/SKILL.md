# Skill: validation (prove or disprove)

Adapted from openai/codex-security `validation`. Decide whether each candidate is supported by evidence, and design a **live proof of concept** the harness will execute against a local, disposable instance of the app.

## Steps (per candidate)
1. Identify the claimed attacker input, security boundary, relevant control, sensitive operation and preconditions.
2. Gather supporting and counter-evidence in the code. Re-read the cited lines; do not trust the candidate text.
3. Record a disposition: `survives: yes | no | uncertain`, confidence, the static evidence, and the exact proof gap if any.
4. If `yes` or `uncertain`, write a PoC in the harness DSL (below) that would demonstrate impact **with the provided low-privilege test accounts only**. Prefer the smallest request sequence with an unambiguous success signal.

## PoC DSL (the harness runs it; you cannot)
- Requests go only to the app base URL given in the task. Any other host is refused.
- `steps[]`, each: `name`, `method`, `path` (may include query string; use `%2F` to keep encoded slashes), optional `auth` (a test-account name; the harness adds `Authorization: Bearer <token>`), `headers`, `json` | `form` | `raw_body` | `files` (multipart upload: `{field: {filename, content, content_type}}`, may be combined with `form`), `repeat` (N copies) with `parallel: true` for races, `extract` (`{var: regex with one capture group}` applied to the response body; use later as `{{var}}`), and `expect` (`status` list, `body_contains` list, `body_regex`).
- Code-execution proof: you may also set `expect.container_file` to an absolute path your payload creates (e.g. `/tmp/sec545_<id>`); the harness checks it inside the sandboxed container.
- A PoC passes when every step that has `expect` meets it. For a step with `repeat > 1`, it passes when **at least two** responses meet `expect` (proves duplicate success, e.g. a race).
- Prefer JSON API endpoints (`/api/...`) over HTML pages; login is already done for you via `auth`.
- Do not target accounts other than the test accounts and seeded demo data. No destructive actions (no deleting data, no dropping tables).

## Retry round
If you are shown a previous PoC attempt with the actual HTTP responses, treat it as evidence: fix the request (route, body shape, expectations) or, if the responses disprove the claim, set `survives` to `no`/`uncertain` and explain the proof gap. Do not loosen expectations until they prove nothing.

## Output
Every input candidate exactly once, in the JSON schema provided.
