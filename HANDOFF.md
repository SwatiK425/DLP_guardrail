# HANDOFF.md — Current State (volatile; update every session)

> Last updated: 2026-08-11

## Current milestone
**GitHub refreshed 2026-08-11: main + enhance/guardrail pushed at 5546853 (verified via ls-remote).** Commit 5546853 merged into main: BYOK UI + provider auto-detect + gradio quartet pins. All 4 detection layers run in the dedicated project venv (`.venv`). 36/36 tests; **true all-4-layers baseline: Acc 92.9% / Prec 90.0% / Recall 100% / F1 94.7%** (the previously claimed 100% was measured in a fallback env without fastembed/transformers — corrected). **Phase: Layer-2 semantic redesign — research done, sandbox next.**

## ENVIRONMENT — CRITICAL (learned 2026-08-11)
- **Dedicated project venv**: `C:\Users\swati\Downloads\SwatiK425\DLP_guardrail\.venv` — use `./.venv/Scripts/python.exe` for EVERYTHING (tests, benchmark, app). Contains the gradio quartet + fastembed + transformers 4.46.3 + torch 2.9.1+cpu.
- **NEVER use base Python311 or the hermes venv for this project**: base 311 is hermes-agent's shared env (gradio quartet is irreconcilable with hermes's pillow==12.3/websockets==15/starlette>=0.49 pins); the hermes venv has no gradio/fastembed/transformers at all.
- Do NOT `pip install` into base 311 for this project — it breaks hermes tooling (happened once, 2026-08-11, restored).

## Working branch & scope
- `main` now at `5546853` (merged from `enhance/guardrail`); new work goes on a fresh `enhance/*` branch
- Untracked docs only: `PROPOSAL.md`, `SYSTEM_DESIGN.md`, `DLP_GUARDRAIL.md`, `HANDOFF.md`, `My notes.txt`

## Recent commits (descending)
- `1468acc` Provider-agnostic BYOK LLM judge (drop deprecated gemini-2.0-flash-exp)
- `42ba06b` Recall-first intent cascade rebuild (eval 61/65/54% → 100/100/100%)
- `0c5420b` Add eval harness (benchmark.py + eval_dataset.csv); measured baseline recall 61%, precision 65%, acc 54% vs README's claimed 92%
- `0f15347` Fix jailbreak false negative: 'ignore ... rules' matched (plural/generalized regex)
- `2c7b22d` C-phase data gate: dlp_gate.py + GuardrailGate coupling

## Current hypothesis
Layer 2's hand-built centroid/intent-dimension taxonomy is a **maintenance wall** (user's words: "very easy to hit a wall of centroids & dimensions... impossible to maintain"). Research (2026-08-07) confirms the industry does NOT maintain intent dictionaries — they train classifiers on embeddings or fine-tune encoders (see `/c/Users/swati/Downloads/SwatiK425/DLP_guardrail/_research/` or Obsidian Research note). Hypothesis: **replace Layer-2 centroid matching with a trained (small) classifier on the fastembed vector** — same embedding, learned decision boundary, no taxonomy to maintain.

## Known issues
1. **Layer 2 near-decorative**: 2 rules, 8 centroids, mostly duplicates Layer 1; "Layer-2-decisive" count ~0 on eval. → redesign target.
2. **Layer 0 has no base64/hex/rot decode** — base64 injection got spurious `leetspeak` label (digits 3/1/4 in alphabet); caught only by Layer 3.
3. **Layer names misleading** (Behavioral / Semantic / Transformer) — Logic explained to user; rename pending decision.
4. Layer 2 & 3 rows in UI/pretty-print may show empty `name` (cosmetic; scores are real).
5. **Leaked Gemini key** in git history (commit `f93635`) — user should rotate; optional scrub.

## Pending decisions
- **Layer-2 redesign approach**: (A) minimal centroid patch — dismissed; (B) embedding + logistic regression / RandomForest trained on labeled data; (C) fine-tuned encoder (deBERTa/SetFit). Rationale + evidence in research notes. User wants **isolated sandbox test first** ← next step.
- Layer renames (Decoder / Intent Rules / Semantic Intent / Injection Model / LLM Review) — user to confirm naming.
- Commit the 3 uncommitted files (UI + shim + pins) as one logical unit.
- README refresh (claimed 92%/85% contradicted by measured 100%).

## Next steps
1. **Build Layer-2 sandbox** (`sandbox_layer2/`, sklearn needed — MISSING, install): compare current-centroid baseline vs embedding+LogReg vs embedding+RF on eval + held-out malicious/benign sets; measure decisive-layer contribution + F1 + FP.
2. Share sandbox results → user picks approach → one commit on `enhance/guardrail`.
3. Commit pending UI/deps work.
4. Fix Layer-0 base64 decode (small, after Layer 2).

## Last bench summary (2026-08-07, post Layer-3 enablement)
- **36/36 tests OK** (engine 9 + gate 12 + judge 15)
- **Benchmark: Accuracy/Precision/Recall/F1 = 100%**, ~3–7ms, **0 LLM calls** (fast layers resolve every eval case)
- 6 attack probes (base64-inject, resume-10/10, unrestricted-firewall, chem-synth, credit-card-training, benign): all malicious → **BLOCKED** (by Layer 1 or Layer 3); benign → SAFE