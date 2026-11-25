# Mapping to openai/codex-security skills

We borrow the **phase contracts** (inputs, evidence rules, verdict vocabulary) from
<https://github.com/openai/codex-security/tree/main/plugins/codex-security/skills>.
We do **not** borrow its runtime. Their skills call hosted `record_codex_security_*` tools; ours write numbered JSON files.

| Our phase | Artifact | Codex skill | What we keep |
|---|---|---|---|
| normalize | `01-normalized.json` | `publish-findings` | Stable source ID per occurrence. Every scanner row is either imported or listed as a numbered exclusion. Native evidence kept. TruffleHog parser is ours (Codex has none). |
| triage | `02-triage.json` | `triage-finding` | Verdicts `confirmed` / `not_actionable` / `needs_review`. A `needs_review` must name the smallest fact that would flip it. Facts kept separate from assumptions. |
| discovery | `03-discovery.json` | `finding-discovery`, `deep-security-scan` | Candidate = source → closest control → sink → impact. Locations labeled `entrypoint` / `root_control` / `sink`. Counterevidence recorded. Already-known findings passed in so they aren't re-reported. |
| validation | `04-validation.json` | `validation` | Closure table with `survives: yes / no / uncertain`, evidence, proof gap and confidence. PoCs run only in the local sandbox. |
| attack-path | `05-attack-paths.json` | `attack-path-analysis` + `references/severity-policy.md` | Attacker position (remote / local_network / localhost), boundary crossed, impact, likelihood, severity `critical/P0 … low/P3 / ignore`. No invented chains. |
| score | `06-score.json` | *(ours)* | Match against `ground-truth/`: recall, precision, scanner-missed-AI-caught, cost per true finding. |
