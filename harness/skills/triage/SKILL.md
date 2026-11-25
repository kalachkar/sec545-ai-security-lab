# Skill: triage (scanner findings)

Adapted from openai/codex-security `triage-finding`. You give **one static-evidence verdict per scanner item**. You do not discover new bugs, run anything, or write fixes.

## Inputs
- Grouped scanner items (Trivy SCA/misconfig/secrets, Semgrep SAST, TruffleHog secrets) with `triage_item_id`, tools, location, rule/CVE summary.
- Read-only access to the repository (Read, Grep, Glob).

## Steps
1. **Normalize the claim.** What does the scanner say is wrong, where, and what would an attacker need?
2. **Assess against code.** Open the cited file/line. Trace source → control → sink per the evidence rules. For dependencies, reachability means the **vulnerable function** is called on a shipped path; an import alone is not reachability (use `needs_review` and name the call you could not find). For secrets, a hardcoded credential in **shipped code or config is `confirmed`** unless the repository itself proves it is overridden or unused at runtime; "dev default", "local-only" or "probably rotated" are assumptions about deployment, so they are `needs_review` (flip fact: the deployment config), never `not_actionable`. Only documented placeholders or test-only fixtures are `not_actionable`. For IaC/Docker, decide whether it ships with this app.
3. **Verdict**
   - `confirmed`: static evidence links attacker → source → consequence through all material controls on a shipped path.
   - `not_actionable`: positive evidence **in the repository** defeats the claim (allowlist, sanitizer, dead or test-only code, documented placeholder secret, non-security use). Assumptions about how the app is deployed are not evidence. When in doubt between `not_actionable` and `needs_review`, choose `needs_review`: a missed real bug costs more than a human review.
   - `needs_review`: a material fact is unresolved. Name the **smallest fact that would flip the verdict** in `flip_fact`.
4. Be efficient: one or two targeted reads per item. Group-read files that host several items.

## Output
Return every input item exactly once, in input order, in the JSON schema provided.
