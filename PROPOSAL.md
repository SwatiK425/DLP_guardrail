# PROPOSAL — Do we keep the heavy ML layers (2 & 3)?

> Living decision doc. Status: **DRAFT — waiting your go-ahead before any code change.**
> Scope: whether to keep `sentence-transformers` (Layer 2) + `deberta-v3-base-injection` (Layer 3) as the intent-detection stack, or restructure to something faster, cheaper, and more contextually accurate.
> Requirements you set: **intelligent (rich contextual understanding), real-time (sub-100ms), and cost-conscious (free/cheap tiers).**

---

## TL;DR — the recommendation in one paragraph

**Keep the *idea* of an ML intent layer, but stop carrying `torch` and stop trusting a single classifier — restructure into a 3-stage cascade with an uncertainty gate.** The research across ~120K labeled prompts (BIPIA, HarmBench, PINT, GuardChain, IBM) is unanimous: *no single classifier wins out-of-distribution, and bigger is not better.* Small fine-tuned classifiers **(DeBERTa-class, Prompt Guard 2 86M)** beat 7–8B LLM guards on **accuracy-per-ms**; frontier LLM judges only add recall on hard OOD inputs at 30–80× cost and +0.5–2s latency. Your measured 61% recall / 54% accuracy is **not** a "need more layers" problem — it is the documented **confident-miscalibration OOD failure mode** (OOD inputs classified benign at high confidence, never escalated). The single biggest accuracy lever available to you is **calibration + escalate-on-low-confidence + a cheap reference-set similarity step**, all of which run in <20ms and replace the fragile regex layer you already distrust.

---

## 1. What the research found (the three streams)

### 1a. Startup landscape — the industry converged on a pattern
- **Orion Security** (your "orion", IL): $38M, AI-native *contextual* DLP, 5 AI agents analyze every data movement (content sensitivity, lineage, user behavior, **intent**), policy-free, 96% FP reduction. → your product's north-star framing, funded to the teeth.
- **Ent** (your "ent", ent.ai): $100M seed, out of stealth June 2026. **Intent-aware** endpoint security using **locally-run small specialized AI models** + a "work model" — explicitly "you cannot backhaul everything to the cloud." → their operative lesson: **run small local models, understand intent, don't be brittle-rules.**
- **Convergence (2025–26) across all vendors:** hybrid **fast-filter → trained small classifier → optional LLM judge**. Inline detection uses fine-tuned small classifiers, **NOT** big LLM judges inline (Aporia benchmarked LLM-judge on the hot path as slow/unstable). Sub-100ms is the latency bar (best ~35–66ms).
- **Your `intent-combination-fusion` intuition is validated** — "intent, not keyword" is literally Orion & Ent's pitch.

### 1b. SOTA papers — what wins per ms/dollar
| Method | Hot-path latency | Strength | Weakness |
|---|---|---|---|
| **Regex/keyword** | <0.2ms, free | instant | misses paraphrased attacks |
| **Embedding similarity** | ~12ms | cheap intent signal | rarely benchmarked head-to-head |
| **Fine-tuned DeBERTa-class** (your Layer 3) | **18.9ms / ~79% PINT** | best accuracy-per-ms | drops to 7–37% on indirect/tool-role |
| **Prompt Guard 2 (86M)** | ~5–25ms CPU | near-perfect direct jailbreak/injection | flat on context; indirect 71% |
| **Llama Guard / ShieldGemma / WildGuard (7–8B)** | 141–950ms | more OOD recall | way past 100ms hot path |
| **LLM judge (Gemini/Claude/GPT)** | 300–1000ms | hardest cases | 30–80× cost |

☐ **GuardChain (USENIX ATC'26)** — the closest thing to your exact question, peer-reviewed: regex(<0.2ms) → CPU SVM/LightGBM (3–50ms, **$0.17–2.77/1M prompts**) → GPU Mamba-130M (24ms). **CPU stage alone resolves 80–95% of traffic; cost cut ~5×. LightGBM matches Gemma-2B-LoRA within 1 pp F1 at 1/5 the cost.** → Cascades, not bigger models.
☐ **The two caveats that dominate everything:** (1) adaptive attacks break all 8 defenses ([2503.00061]); (2) Prompt-Guard-2 & Llama-Guard-3 drop to **7–37%** on indirect/agentic tool-use ([2602.14161]) — because they flatten context. The fix the papers converge on: **LODO calibration + activation/embedding probes on the host model (~99% on indirect).**

### 1c. Engineering — the real-time path on your budget
- Your **#1 cold-start culprit is `torch`/`sentence-transformers`** (3–10s load, 500MB–2GB). **`fastembed` (ONNX Runtime) gives the *same* all-MiniLM/bge models with ~0.2–0.5s load and no torch.**
- **Winners on free tier:** **Cloudflare Workers AI** (edge, 10K neurons/day, embeddings 3K RPM) and **Groq** (30K TPM free, and **literally hosts Llama-Prompt-Guard** over HTTP at ultra-low latency). HF Serverless (10–30s cold start) is NOT viable for sub-100ms.
- **Cache by embedding-hash**: identical/repeated prompts never pay the LLM tail twice.

---

## 2. The decision — three options

### Option A — KEEP heavy layers as-is (status quo)
✅ No rework. ❌ torch cold-start pain; LLM judge called on every prompt (unaffordable); **the 4-layer overlap actually *hurts* fusion** (your measured DAN-dilution bug) — stacking DeBERTa-on-embeddings doesn't add independent signal. ❌ NOT sub-100ms, NOT cheap. → **Reject.**

### Option B — REPLACE with modern small-classifier stack (recommended)
A 3-stage cascade on the free tier:
```
Request
  L0  Regex/denylist (stdlib)         ~0–1ms   → ALLOW/BLOCK instantly (majority returns here)
  L1  Tiny ONNX classifiers            ~5–25ms  → deBERTa injection + embeddings intent
      + UNCERTAINTY GATE (calibrated)  → confident? return verdict : → L2
  L2  LLM judge (tail only)           +300–800ms (only ~5–20% of traffic)
      backends: Groq free / CloudFlare Workers AI → Gemini Flash → Gpt-4o-mini
      (cached by embedding-hash; batched)
```
✅ **20–40ms avg / sub-100ms p95**, free-tier-hostable, drops `torch`, **fixes the fusion bug** (clean layer can't dilute a real jailbreak), gets the real accuracy gains the papers show. ❌ Rebuild effort (moderate). Never ships today: keep tuning; fold into a spike.

### Option C — HYBRID (do B's architecture but self-host a 7B small guard for the tail)
Same as B but keep a WildGuard-/ShieldGemma-class 7B locally for OOD reasoning. ✅ more OOD recall. ❌ 7B on CPU or GPU ≠ free tier; cold start ~400ms+. → Park until a paid product/GPU tier exists.

---

## 3. Concrete proposed change to `dlp_guardrail_with_llm.py`

1. **Drop `sentence-transformers` → `fastembed` (ONNX)** for Layer 2 (same MiniLM model, no torch, instant load).
2. **Keep DeBERTa injection classifier (Layer 3)** but serve via **ONNX** and gate it through an **uncertainty + calibration** floor, not a raw 0.5 threshold.
3. **Restructure the URL into a cascade:** clear-allow/clear-block by regex → classifier+embedding with uncertainty gate → escalate the uncertain tail to an LLM judge, **called only on that tail** (no per-prompt judge).
4. **Add a contextual/embedding measure** (intent vs. data separation — the MDPI/position) and a **reference-set similarity** to catch paraphrased intent regex misses.
5. **LODO-style calibration & big keep dataset** (your `benchmark.py` becomes the operating-lines finder, not a one-off).
6. **Cache judge verdicts by embedding-hash**; batch when traffic bursts.

**Measured target:** your current 61% recall on the fallback path → ≥80%+, and **repeatably** — with a **cold-start <1s, hot path ~20–40ms, LLM-judge latency excluded (tail-only)**.

---

## 4. What I WILL NOT do (safety bounds)
- No tuning/cat without the eval harness (existing rule, restated).
- No change to `main`; all on branch.
- No new paid infra at this stage — free tier only.

---

## 5. Open questions for you
1. **OK to drop `torch`** and switch Layer 2 to `fastembed/ONNX`? (I recommend yes.) — **biggest dependency win.**
2. Ok with **calling an LLM judge only on the uncertain ~5–20%** (vs. today's per-prompt)? This is the accuracy+cost win but changes `GeminiLLMJudge`'s role.
3. Priority: **fix the 61% recall via cascade first**, or **get sub-100ms cold-start first**? (I'd do cascade/recall first — it's the product's actual claim.)

---

*Sources:* full reports at `C:\Users\swati\Downloads\sw_prompt_injection_sota_report.md`, `C:\Users\swati\sw_prompt_injection_sota_report.md`, `llm-guardrail-landscape-report.md`; primary papers cited inline (GuardChain 2512.19011, IBM 2502.15427, adaptive-attack 2503.00061, "when benchmarks lie" 2602.14161, BIPIA 2312.14197, StruQ/MELON/AgentSlice, FrugalGPT 2305.05176).