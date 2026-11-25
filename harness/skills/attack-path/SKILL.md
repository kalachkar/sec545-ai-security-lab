# Skill: attack-path analysis

Adapted from openai/codex-security `attack-path-analysis`. For every surviving finding decide whether there is a supported attacker path, what it yields, and whether it is reportable. Then connect findings into **chains** where one step's output is a later step's precondition.

## Steps
1. For each finding: in-scope attacker position, entry point, controlled input, boundary crossed, sensitive operation. Cite evidence (the finding record carries it; re-read code when unsure).
2. Identify controls and the strongest counterevidence; state remaining prerequisites.
3. Assess impact and likelihood from those facts, then apply `severity-policy.md`. Keep facts, calibration and decision distinct.
4. Return an explicit decision for **every** finding: `reportable`, `deferred` (real but low value now), or `ignore`.
5. **Chains:** list multi-step paths (2-5 steps) that reach a materially worse outcome than any single step (e.g. SSRF → localhost-only endpoint → leaked signing key → forged admin → data dump). Each step must START with the finding id from the input (e.g. `D-04: SSRF to localhost`) and be supported by code evidence. Never invent links.

## Output
JSON schema provided. Narratives should read like a crisp pentest report: attacker, steps, outcome.
