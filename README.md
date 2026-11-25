# SEC545 · AI Security Lab

**Can AI fix scanner triage?** A 10-minute, 10-page interactive story built from a real benchmark:
two deliberately vulnerable apps, three classic scanners, and 15 AI models run through the same
harness, scored against a hidden answer key of 42 planted bugs and 13 decoys.

▶ **View it:** https://kalachkar.github.io/sec545-ai-security-lab/ (or open `site/index.html`; it is self-contained and works offline).
Use ← → or the numbered dots to move between pages; *Show speaker notes* has the talk track.
**Deep dive ▾** has the detail views for questions: meet the two apps (all 42 planted bugs by class), a searchable explorer of all 1,791 scanner findings, a bug matrix
(42 planted bugs × 15 models: found / dismissed / missed), every run with tokens and cost, and the harness skills.

## The story

| # | Page | Takeaway |
|---|---|---|
| 1 | The pipeline | App → Trivy (SCA), Semgrep (SAST), TruffleHog (secrets) → findings → analyst → fix |
| 2 | The findings | Three problems: **noise** (1,791 alerts, 165 distinct claims), **accuracy** (18 of 42 planted bugs found, 5 of 13 decoys flagged), **time** (≈149 h at an assumed 5 min/alert) |
| 3 | Where AI fits | AI for triage and discovery; deterministic rules where they work. **Principle 1: use AI where it matters.** |
| 4 | Shiny model | One prompt with all code + findings: two runs, two answers, invented findings. Spaghetti. |
| 5 | The harness | The recipe: write down the analyst's workflow (phase contracts adapted from OpenAI Codex Security skills). **Principle 2: invest in the harness.** |
| 6 | Same model + harness | Same Opus: 21/21 planted bugs, 0 findings outside the key, fewer items for an analyst |
| 7 | Is it the model? | 15 models, 4 runs each: the cheapest Claude ties the top at ~3% of the flagship's price; vendor filters blocked some models |
| 8 | Best model? | Three public leaderboards, three different questions. You need the best harness, then the model that fits. |
| 9 | Production | False suppression and reproducibility; what a mature harness looks like. **Principle 3: AI accelerates, humans stay in the loop.** |
| 10 | Wrap-up | The three rules, and the receipt: what the whole lab cost, in pizzas. |

## Method, briefly

- **Apps:** SnackOverflow (Python/FastAPI) and RAGnarok (Node, GenAI), each with 21 planted bugs plus decoys.
- **Scanners:** pinned Trivy, Semgrep and TruffleHog containers (`scanners/`).
- **Harness** (`harness/`): normalize → triage → discover → validate → severity → score. AI phases use read-only
  tools on a blind copy of the app (no README, no answer key); scoring is deterministic against a hidden answer key.
- **Models:** 15 models, same inputs and limits. Validation in the benchmark is static (code evidence), not live exploitation.
- **Costs:** published list price per input/output/cache token × logged tokens, cross-checked against the actual bill.
- **Limits:** 2 apps, 1 run per model per harness version (Opus repeated), harness tuned on these apps. Treat ±1 bug as noise.

## Rebuild the site

```bash
pip install -r requirements.txt
python -m harness.cli dashboard     # writes site/index.html
```

The page is built from committed, aggregate-only data in `dashboard/story/` (`data.js` for benchmark
numbers, `scanners.json` for the scanner findings list). No code, transcripts or secrets are embedded.
`.github/workflows/pages.yml` publishes `site/` to GitHub Pages.

## What is (and isn't) in this repo

- ✅ The story site and its data, the AI **harness** (`harness/`: phases, skills, providers, scoring)
  and the scanner configuration (`scanners/`).
- 🚫 The vulnerable apps, the answer key and raw run artifacts are **not published**: they contain
  intentionally planted (fake) secrets and exploit details. The harness expects them under `apps/`,
  `ground-truth/` and `results/` if you bring your own range.

## Run the harness

```bash
python -m harness.cli run --app <app> --profile cheap       # scanners → harness → score
python -m harness.cli spaghetti --app <app> --profile <p>    # the no-harness baseline
```

Providers live in `harness/providers/`; model profiles in `harness/config.yaml`.

## Credits

- Phase contracts adapted from [OpenAI Codex Security skills](https://github.com/openai/codex-security/tree/main/plugins/codex-security/skills) (see `docs/codex-security-mapping.md`).
- Scanners: [Trivy](https://github.com/aquasecurity/trivy), [Semgrep](https://github.com/semgrep/semgrep), [TruffleHog](https://github.com/trufflesecurity/trufflehog). Logos belong to their owners.
- Leaderboards shown: [Cybench](https://cybench.github.io/), [CyberGym](https://www.cybergym.io/cybergym/), [Vals CyberBench](https://www.vals.ai/benchmarks/cyber) (screenshots, 2026-11-25).
- Mature-harness reference: [Microsoft MDASH](https://www.microsoft.com/en-us/security/blog/2026/05/12/defense-at-ai-speed-microsofts-new-multi-model-agentic-security-system-tops-leading-industry-benchmark/).
