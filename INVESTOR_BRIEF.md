# DLP Guardrail — Investor Brief

**One-liner:** Intent-based guardrail that allows benign prompts and blocks prompt-injection, jailbreaks, and data-exfiltration attempts before they reach your LLM.

**Try it:** Attach your own LLM key (BYOK) → test a prompt → see layer breakdown + verdict. No prompts leave your account except to the provider you chose.

---

## 1. How it works

**Threat intent (in-memory cascade):**

1. L0 Obfuscation decode (base64/hex/rot13, leet, invisible chars, LaTeX)
2. L1 Behavioral intent (retrieval + sensitive target + bypass signals)
3. L2 Semantic similarity (fastembed ONNX, no torch required)
4. L3 Transformer classifier (deBERTa injection, optional)
5. Fusion: confident high signal stands alone; silent layers don't dilute it
6. Triage + LLM judge (BYOK, tail-only): confident BLOCK/SAFE skip the judge; everything uncertain goes to the judge; judge-down → fail-closed BLOCK

## 2. Why not just use Lakera / NeMo / Llama Guard?

2026 market reality:

* Managed APIs (Lakera/Check Point style): ~98% injection detection, sub-50ms, but prompts leave your VPC. CISOs in regulated deals reject this.
* Policy frameworks (NeMo Guardrails 0.24): 0% bypass in one 2026 tutor study, but ~16% false-positives — unshippable for enterprise SQL/code traffic.
* Model guards (Llama Guard / Granite Guardian): strong classifiers, still need BYOK and FP control to be deployable.

Our bet:

* **BYOK + tail-only judge:** 80%+ traffic resolves locally; LLM sees only uncertain cases (5–20%). Your key, your model, your VPC. Keys from env/session only, masked in logs, never stored.
* **FP discipline:** enterprise traffic is SQL, code, security-ops prose. Aggregate accuracy hides per-family collapse, so we gate per-family (attack recall + benign FP separately).

## 3. How to run

```bash
env -u PYTHONPATH pip install -r requirements.txt
python app.py  # Gradio on :7860 — Individual + CSV batch tabs
```

BYOK providers: google / anthropic / openai / openrouter / opencode-zen / nvidia. Key via provider env var or session input. Default models per provider in code; override supported.

API: Gradio `/api/predict` for programmatic access.

## 4. Trust model (enterprise checklist)

* Fail-closed: judge missing / rate-limited / error / empty → BLOCK, with reason. Confident local BLOCK/SAFE may complete without judge. Covered by focused policy tests (local-only).
* Privacy: no raw-prompt persistence by default. Eval traces = metadata + lengths unless explicitly opted-in.
* Isolation: per-session judge; keys never logged in full, never committed.
* Rate limits: 15 req/min default, transparent `used/remaining`, fallback chain with circuit-breaker.
* Reproducibility: evals record code revision, dataset hash, layer availability, LLM attempt/success counts, local vs LLM latency percentiles. No quality claim without those.

## 5. Honest status (Oct 2026)

* Targets (`<1% benign FP`, `>=95% attack recall`, `<50ms` local) are goals, not verified results.
* Last heuristic-only traces (no LLM, embedding fallback active) showed the expected two failure clusters: missed academic/credential/system-disclosure phrasing (intent regex too narrow) and over-flagged benign SQL/code (transformer + obfuscation heuristics too hot). Fix order is baseline → per-family diagnosis → thresholds, not the reverse.
* No LICENSE file yet (README says MIT) — adding before distribution.
* Live URLs / deployment notes from prior handoffs are historical until re-verified against the current Gradio config.

## 6. 2-week hardening plan

**Week 1 — Trustworthy baseline:**

* Freeze revision + dataset hash; restore env; record L2/L3 load state.
* Privacy-safe held-out run with LLM sanity gate (abort if judge down, don't silently score heuristic-only).
* Publish: accuracy, attack recall, benign FP, per-family table, LLM attempt/success %, local p50/p95 + LLM p50/p95.
* Pick demo set: 3 blocks, 2 allows, 1 uncertain→judge. Video backup for judge-down path.

**Week 2 — Enterprise hardening:**

* Per-family FP/FN fixes (intent coverage first, allowlists last).
* Session isolation + timeout + sanitized-error review; health/version tracking; SLO from Week-1 percentiles.
* Investor packet: architecture diagram, metrics table with denominators, limitations slide, roadmap (weekly intel loop, held-out growth).

## 7. What’s in this repo (and what isn’t)

This GitHub repo is intentionally small — only what’s needed to run and evaluate the claim:

```
README.md
app.py
dlp_guardrail_with_llm.py
requirements.txt
INVESTOR_BRIEF.md (this file)
.gitignore
```

Kept local-only (never pushed): raw eval datasets, eval results/traces, experiments, 10-K filings, internal handoffs, content drafts, telemetry. They’re needed for R&D but are not part of the deployable artifact and would bloat/clutter the investor surface.

---

*Measurement > claims. Systems > features. Every number ties to a revision + dataset hash.*
