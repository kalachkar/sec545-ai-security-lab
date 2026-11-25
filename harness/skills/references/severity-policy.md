# Severity policy

Adapted from openai/codex-security `attack-path-analysis/references/severity-policy.md`.

| Severity | Priority | Meaning |
|---|---|---|
| `critical` | P0 | Remote, low/no-privilege attacker gets code execution, full data access, admin takeover, or cross-tenant compromise |
| `high` | P1 | Serious confidentiality/integrity impact for many users, or account takeover, with realistic prerequisites |
| `medium` | P2 | Real impact, limited scope or meaningful prerequisites |
| `low` | P3 | Real, but low impact or likelihood |
| `ignore` | none | Disproved, no security impact, or fails reportability |

**Calibrate** from the candidate's hypothesis using impact, likelihood, prerequisites and mitigations. Do not reopen discovery.

**Likelihood by attacker position:** `remote_unauth` high · `remote_auth_low` (any self-registered/low-priv user) high · `remote_auth_privileged` low unless it is a privilege-escalation step · `local_network` medium · `localhost` low unless reachable via another bug (e.g. SSRF) · `none` → ignore.

**Reportability**
- Keep real low-impact bugs at a lower severity rather than discarding them.
- Ignore findings that need privileged/operator/developer/physical access, unless they are a step in a privilege-escalation chain.
- Require a realistic in-scope path for a lower-privileged attacker.
- Internal-only exposure does not suppress a real authorization or trust-boundary failure.
- SSRF: a documented outbound-fetch feature does not cancel a missing destination control.
- XSS: separate self-only effects from victim impact.
- Vulnerable dependency: severity depends on whether the vulnerable function is reachable from app code.
- **Chains:** a chain's severity is the impact of the final step for the attacker at the first step's position. Only chain steps you can support with code evidence. Never invent links.
