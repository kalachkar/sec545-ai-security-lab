# Skill: discovery (what the scanners missed)

Adapted from openai/codex-security `finding-discovery` + `deep-security-scan`. Find **technically plausible vulnerabilities the static scanners did not report**, with evidence for later validation. Discovery does not decide final severity.

## Inputs
- Repository map (file tree + HTTP routes) and read-only access (Read, Grep, Glob).
- The list of findings **already reported by scanners**. Do not re-report those (same source/sink/location). You may reference them as chain steps.

## Where scanners are blind (prioritize)
- **Authorization:** missing ownership checks (IDOR), tenant isolation, role checks without resource checks, mass assignment, trust in client-supplied identity/role.
- **Business logic:** coupon/discount abuse, negative/unbounded numbers, state-machine skips, race conditions (check-then-act across an `await`/IO), idempotency.
- **AuthN/crypto logic:** predictable tokens, signature checks that can be skipped, JWT algorithm confusion, trust in network location (e.g. `127.0.0.1` checks).
- **Injection the rules missed:** template-literal/f-string SQL, unsafe deserialization libraries, SSRF from user-supplied URLs, path traversal through query params.
- **LLM / agent apps:** prompt injection via retrieved content, insecure output handling (model output rendered as HTML), excessive agency (tools with side effects, shell, network, email), system-prompt secrets, RAG cross-tenant retrieval, unbounded consumption.

## Evidence criteria
Follow `evidence-rules.md`. Each candidate: source → closest control → sink → impact, labeled locations (`entrypoint`, `root_control`, `sink`, `concrete_implementation`), counterevidence, and what validation should prove. Separate independently reachable instances; merge true duplicates.

## Output
Return candidates in the JSON schema provided. Prefer precision: every candidate should be something you would defend in a review. Note coverage limits honestly.
