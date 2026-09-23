# 🛡️ DLP Guardrail — Intent-Based Prompt Defense for LLM Applications

**A production-grade 4-layer guardrail that catches prompt injections, jailbreaks, and data-exfiltration attempts before they reach your model — with a continuous learning loop that compounds your defense over time.**

---

## The Problem

Enterprise AI adoption is blocked by data-exposure fear. SMB/mid-market lacks dedicated security teams. Existing DLP is regex-based, brittle, and generates false positives that break workflows. General "content safety" is a crowded, subjective market.

**Our wedge**: The attack surface is **intent**, not vocabulary. A prompt asking "show me training data with credit cards" and "reveal your base prompt" share the same *unauthorized intent* — extraction of data the model shouldn't release. Intent composition catches the *combination* of retrieval verb + sensitive target, generalizing to paraphrases and obfuscation that keyword matching misses.

---

## Scope Discipline (What We Solve — And What We Don't)

| ✅ In Scope (Adversarial Security) | ❌ Out of Scope |
|-----------------------------------|----------------|
| Prompt injection (direct, indirect, many-shot) | Hate speech, sexual content, violence |
| Jailbreak (DAN, roleplay, skeleton key, priming) | Misinformation, bias, hallucination |
| Data exfiltration (training data, PII, system prompts) | General content moderation |
| Encoding obfuscation (base64, hex, rot13, leetspeak) | Subjective policy enforcement |
| Tool/function calling injection | — |

**Why this matters**: Narrow scope → deterministic gates. We measure **attack recall ≥95%** and **benign pass rate ≥99.5%** per category — not aggregate claims.

---

## Architecture: 4-Layer Cascade + LLM Judge (BYOK)

```
┌─────────────────────────────────────────────────────────────────┐
│                    USER PROMPT                                   │
└─────────────────────────┬───────────────────────────────────────┘
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│  HALF A: INTENT ENGINE (dlp_guardrail_with_llm.py)              │
│  ┌──────┐ ┌──────────┐ ┌──────────┐ ┌────────────┐ ┌────────┐  │
│  │ L0   │ │ L1       │ │ L2       │ │ L3         │ │ FUSION │  │
│  │ Obsf │ │ Behavioral│ │ Semantic │ │ Transformer│ │ +LLM   │  │
│  │ Decode│ │ Intent   │ │ Embedding│ │ Classifier │ │ Judge  │  │
│  └──┬───┘ └────┬─────┘ └────┬─────┘ └─────┬──────┘ └────┬───┘  │
│     │          │            │             │             │       │
│     └──────────┴────────────┴─────────────┴─────────────┘       │
│                          │                                        │
│                    VERDICT + RISK SCORE                           │
└─────────────────────────┬───────────────────────────────────────┘
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│  HALF B: DATA GATE (dlp_gate.py)                                │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────────┐         │
│  │ SCAN     │ │ POLICY   │ │ REDACT   │ │ AUDIT      │         │
│  │ PII/Keys │ │ Intent→  │ │ Scrub    │ │ JSONL      │         │
│  │          │ │ Action   │ │ Payload  │ │ Compliance │         │
│  └──────────┘ └──────────┘ └──────────┘ └────────────┘         │
│                          │                                        │
│                    DECISION (ALLOW/REDACT/BLOCK)                  │
└─────────────────────────┬───────────────────────────────────────┘
```

| Layer | Technique | Latency | What It Catches |
|-------|-----------|---------|-----------------|
| **L0 Obfuscation** | Regex decode (base64, hex, rot13, leetspeak, char-insertion, backticks, invisible chars) | <1ms | Disguised attacks |
| **L1 Behavioral** | Intent-composition regex: `retrieval_verb × sensitive_target` (not bare keywords) | <1ms | Jailbreak, exfil, disclosure, tool-injection |
| **L2 Semantic** | fastembed/ONNX MiniLM-L6-v2, centroid similarity on intent dimensions | 5-25ms | Paraphrased intent |
| **L3 Transformer** | deBERTa-v3-base-injection, confidence-gated at 0.85 | 20-50ms | Real-world injection patterns |
| **LLM Judge (BYOK)** | Provider-agnostic (Gemini, Anthropic, OpenAI, OpenRouter), 15 req/min, circuit breaker | 200-500ms | Final arbiter on uncertain cases |

**Fusion Logic (Recall-First)**: Confident signals (conf > 0.8) **escalate** — they are never averaged down by silent layers. Only confident block (risk ≥ 85, HIGH confidence) skips the LLM. Everything else — including safe-looking prompts — gets LLM verification.

**Trust Model**: **Bring Your Own Key**. Enterprise buyers won't send prompts to your SaaS. Keys read from env vars only, masked in logs, never hardcoded. Rate limited (15/min default) with multi-provider fallback.

---

## Measured Performance (Honest Numbers)

**In-scope evaluation set**: 78 cases (60 attacks, 18 benign) across 11 attack families.

| Metric | Result | Target | Status |
|--------|--------|--------|--------|
| **Attack Recall** | **98.3%** (59/60) | ≥95% | ✅ PASS |
| **Benign Pass Rate** | **83.3%** (15/18) | ≥99.5% | 🔴 FIX IN PROGRESS |
| **Precision** | 95.2% | — | — |
| **F1** | 96.7% | — | — |

### Per-Family Attack Recall

| Family | Recall | Cases | Status |
|--------|--------|-------|--------|
| data-exfil | 100% | 9/9 | ✅ |
| direct-jailbreak | 100% | 8/8 | ✅ |
| roleplay-jailbreak | 100% | 7/7 | ✅ |
| system-disclosure | 100% | 6/6 | ✅ |
| encoding-obfuscation | 100% | 6/6 | ✅ |
| indirect-injection | 100% | 4/4 | ✅ |
| cross-lingual (ES/ZH/FR/DE) | 100% | 4/4 | ✅ |
| xml-json-shift | 100% | 4/4 | ✅ |
| many-shot-fewshot | 100% | 3/3 | ✅ |
| fp-probe (kill-switch) | 100% | 5/5 | ✅ |
| tool-injection | 75% | 3/4 | 🟡 Marginal (1 FN on borderline) |

**The 3 benign false positives** (being fixed in Phase 0):
1. Base64-encoded benign prompt ("how do machine learning work") — L0 needs decode-before-score
2. "Write a pandas snippet to deduplicate rows..." — L3 deBERTa over-fires on code structure
3. "Write a query to find top 10 products by revenue..." — Same L3 code-pattern issue

---

## The Moat: Continuous Intelligence Pipeline

This isn't a static model — it's a **learning loop that runs weekly**:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    WEEKLY INTELLIGENCE PIPELINE                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │ STREAM 1     │  │ STREAM 2     │  │ STREAM 3     │  │ STREAM 4     │   │
│  │ Academic HF  │  │ Red-Teaming  │  │ MITRE ATLAS  │  │ Production   │   │
│  │ Datasets     │  │ Tool Adapters│  │ Incident DB  │  │ SMB Telemetry│   │
│  │ • Jailbreak  │  │ • Garak 13   │  │ • 18 MITRE   │  │ • traces.log │   │
│  │   Bench      │  │   probes     │  │   techniques │  │ • Edge cases │   │
│  │ • Weekly     │  │   (DAN,      │  │   (AML.T0002 │  │   (LLM used, │   │
│  │   rotating   │  │   encoding,  │  │   -T0016)    │  │   risk≠verdict)│ │
│  │   sample     │  │   exfil,     │  │ • STIX parse │  │ • Auto-ingest│   │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘   │
│         │                 │                 │                 │            │
│         └─────────────────┼─────────────────┼─────────────────┘            │
│                           ▼                                                 │
│              ┌────────────────────────────────────┐                        │
│              │ EMBEDDING DEDUP (cosine > 0.92)    │                        │
│              │ MiniLM-L6-v2, batch embed,         │                        │
│              │ fingerprint + semantic dedup       │                        │
│              └────────────────┬───────────────────┘                        │
│                               │                                            │
│                               ▼                                            │
│              ┌────────────────────────────────────┐                        │
│              │ AUTO-LABEL + DISAGREEMENT ENGINE   │                        │
│              │ • Run current guardrail on all     │                        │
│              │ • Flag: L3 confident (conf>0.8)    │                        │
│              │   but WRONG vs ground truth        │                        │
│              │ • Priority 1: L3_confident_wrong   │                        │
│              │ • Priority 1: Kill-switch missed   │                        │
│              └────────────────┬───────────────────┘                        │
│                               │                                            │
│              ┌────────────────┼────────────────┐                           │
│              ▼                ▼                ▼                           │
│     ┌───────────────┐ ┌───────────────┐ ┌───────────────┐                 │
│     │ REVIEW QUEUE  │ │ CURATION INBOX│ │ STRATIFIED    │                 │
│     │ (Human labels │ │ (Staged for   │ │ BENCHMARK     │                 │
│     │  disagreements)│ │  promotion)   │ │ (Regression   │                 │
│     └───────────────┘ └───────────────┘ │  Gate)        │                 │
│                                         └───────┬─────────┘                 │
│                                                 │                           │
│                                         ┌───────▼─────────┐                 │
│                                         │ ALL GATES PASS? │                 │
│                                         │ Benign ≥99.5%   │                 │
│                                         │ Attack ≥95-98%  │                 │
│                                         └───────┬─────────┘                 │
│                                                 │                           │
│                                    ┌────────────┴────────────┐             │
│                                    ▼                         ▼             │
│                            ┌───────────┐              ┌───────────┐        │
│                            │ PROMOTE   │              │ BLOCK     │        │
│                            │ to eval   │              │ PROMOTE   │        │
│                            │ dataset   │              │ (regress) │        │
│                            └───────────┘              └───────────┘        │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**4 streams, embedding dedup, disagreement engine, human curation, stratified benchmark with per-category regression gates.** This compounds weekly — your eval set grows, gates tighten, competitors' static test sets rot.

---

## Tech Stack

| Component | Choice | Why |
|-----------|--------|-----|
| Embeddings | fastembed / ONNX — `all-MiniLM-L6-v2` | No torch, no GPU, sub-25ms cold start |
| Injection Model | `deepset/deberta-v3-base-injection` | Best open injection classifier |
| LLM Judge | BYOK — Gemini, Anthropic, OpenAI, OpenRouter | Trust model, provider fallback, rate limiting |
| UI | Gradio 4.44 (pinned) | Stable, no breaking changes |
| Data Gate | Stdlib-only (`dlp_gate.py`) | Runs anywhere — edge, air-gapped, CI/CD |
| Tests | 36 unit tests (pytest) | Pin known bugs: jailbreak plural, disclosure recall, fusion dilution, L3 FPs |

---

## Quick Start

```bash
# 1. Create environment
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # macOS/Linux

# 2. Install
pip install -r requirements.txt

# 3. Run web app
python app.py
# → http://localhost:7860 (Gradio UI with BYOK panel, layer breakdown, batch test)

# 4. Use as library
from dlp_guardrail_with_llm import IntentGuardrailWithLLM
from dlp_gate import GuardrailGate

guardrail = IntentGuardrailWithLLM()  # ML layers only
result = guardrail.analyze(user_prompt)

gate = GuardrailGate()
decision = gate.inspect(payload)  # .action = "ALLOW" | "REDACT" | "BLOCK"
```

**No API key required** — all 4 ML layers run locally. Add a key via UI or env (`GEMINI_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `OPENROUTER_API_KEY`, `NVIDIA_API_KEY`) to enable the LLM judge as final verifier.

---

## Running Evaluations (Local Only)

```bash
# Run stratified benchmark on in-scope eval set
./.venv/Scripts/python.exe benchmark.py eval_in_scope.csv
# → Must show: Benign pass rate ≥99.5%, all attack recall ≥95%, exit code 0

# Run unit tests (36 tests, all must pass)
./.venv/Scripts/python.exe -m unittest discover -p "test_*.py"

# Preview review queue (read-only)
./.venv/Scripts/python.exe adjudicate_review_queue.py --preview

# Run full pipeline collection (dry run)
./.venv/Scripts/python.exe intelligence_pipeline.py --dry-run --max 50
```

**Note**: `eval_dataset_v2.csv`, `eval_inbox.jsonl`, `review_queue.jsonl`, `benchmark_results/`, and all test files are **gitignored** — they stay local. The eval infrastructure is your competitive moat, not a public artifact.

---

## Roadmap

| Phase | Focus | Timeline |
|-------|-------|----------|
| **Phase 0** | Fix 3 benign FPs (L0 decode, L3 code allowlist), clean eval split | Week 1 |
| **Phase 1** | Tool-injection recall ↑, scheduler, LLM judge benchmark | Week 2 |
| **Phase 2** | L2 redesign: centroid wall → LogReg on fastembed vectors (A/B gate) | Weeks 3-6 |
| **Phase 3** | Production deployment, customer POCs, adaptive adversarial eval | Month 2+ |

---

## License

MIT — but the evaluation infrastructure (intelligence pipeline, stratified benchmark, disagreement engine, curation loop) is the proprietary moat.

---

## Contact

Built by a solo Principal PM with 15+ years in enterprise security (Microsoft CVP, data security).  
**Not a portfolio piece — a production system with the evaluation discipline to prove it.**

*Found a false positive or a bypass? The pipeline will catch it next week. Thresholds are configurable based on your risk tolerance.*