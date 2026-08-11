# DLP_GUARDRAIL.md — Stable Project Map & Rulebook

> Last updated: 2026-08-07

## What this is
Intent-Based DLP Guardrail (SwatiK425/DLP_guardrail): a 4-layer prompt-intent gate that catches **jailbreaks, prompt injections, and data-exfiltration requests** before they reach an LLM, plus a data-plane redaction gate. Product wedge (per user): "AI data-exposure security for SMB/mid-market". Motor = catch all three attack families via the same signal: *unauthorized intent*.

## Architecture map
| File | Role |
|---|---|
| `dlp_guardrail_with_llm.py` | Engine: 4 detection layers + fusion + provider-agnostic BYOK LLM judge |
| `app.py` | Gradio BYOK try-it UI (individual + CSV batch), gradio_client compat shim |
| `dlp_gate.py` | Data-plane: redaction engine + policy gate + JSONL audit + GuardrailGate coupling |
| `benchmark.py` + `eval_dataset.csv` | 28-case labeled harness; real metrics, not claims |
| `test_engine.py` / `test_dlp_gate.py` / `test_judge.py` | Unit suites (9 + 12 + 15 = 36 tests) |
| `PROPOSAL.md` / `SYSTEM_DESIGN.md` | Product pitch + design (untracked) |

## The 4 layers (what each actually is)
- **Layer 0 — Obfuscation decoder**: 6 regex normalizations (char-insertion, backticks, space-split, LaTeX, leetspeak, invisible chars) → rewritten `normalized` text fed to layers 1–3. Fixed +15 if any technique fires. **No base64/hex/rot decode yet — known gap.**
- **Layer 1 — Behavioral (rule-intent)**: 6 regex behavior classes; risk from intent *combinations* (disclosure 88, jailbreak+role 90, role+retrieval 78, retrieval+target 85/65, unfiltered+retrieval 70; bare keywords → 0).
- **Layer 2 — Semantic (embedding intent)**: fastembed/all-MiniLM-L6-v2 (ONNX) cosine sim vs 3 hand-coded intent dimensions (8 centroids) + 2 risk rules (95/90). **The weak link: centroid wall, near-decorative. REDESIGN in progress — see HANDOFF.**
- **Layer 3 — Transformer**: deBERTa-v3-base-injection classifier → `INJECTION` label + confidence → risk 80/60. The strongest catcher once enabled.
- **Fusion**: escalation-aware (recall-first) — confident high signals stand alone, abstaining layers (risk 0) don't dilute.
- **LLM judge (BYOK)**: fires only on uncertain tail (25 < risk < 85 or low-confidence extremes); provider-agnostic (google/anthropic/openai/openrouter/opencode-zen).

## Non-negotiable rules
- **`main` FROZEN.** All work on feature branches (`enhance/*`); user approves merge; A/B zero-regression gate before go-live.
- **BYOK only**: keys from env var or runtime paste, never hardcoded; log masked (`key=sk-...abcd`); full key never printed.
- **"Prove, don't claim"**: every change re-runs `benchmark.py` + all 36 tests.
- **Read docs at session start; update HANDOFF.md at session end.** (This ritual is mandatory.)
- Gradio env quartet — do NOT upgrade: `gradio==4.44.1`, `gradio-client==1.3.0`, `huggingface_hub==0.23.4`, `starlette==0.41.3`, `transformers==4.46.3` (5.x conflicts with hf_hub 0.23.4).

## Key commands
> ALWAYS use the project venv: `./.venv/Scripts/python.exe` (never base Python311 — shared with hermes tooling; quartet irreconcilable with its pins)
```
./.venv/Scripts/python.exe -m unittest test_engine test_dlp_gate test_judge   # 36 tests
./.venv/Scripts/python.exe benchmark.py                                       # recall/precision/acc/F1 (true baseline 92.9%, not 100%)
set GRADIO_ANALYTICS_ENABLED=False && ./.venv/Scripts/python.exe -m app       # UI at 127.0.0.1:7860
./.venv/Scripts/python.exe -m dlp_guardrail_with_llm                          # interactive BYOK setup
```

## Where details live
- Skill `data-exposure-guardrail` (references: byok-judge-and-gradio-ui, detectors-and-pitfalls, gradio-layer-enablement-and-deps, security-hygiene) — the deep memory.
- `SYSTEM_DESIGN.md`, `PROPOSAL.md` — product/design docs.
- Obsidian vault `Research/` — intent-detection research notes (pending).

## Stack & models
- Embeddings: fastembed/ONNX `all-MiniLM-L6-v2` (no torch needed for Layer 2)
- Transformer: `deepset/deberta-v3-base-injection` via transformers 4.46.3 + torch (CPU)
- LLM judge defaults: google `gemini-2.5-flash`, opencode-zen `deepseek-v4-flash-free`
- Python 3.11, stdlib unittest, requests, gradio 4.x, fastembed, numpy