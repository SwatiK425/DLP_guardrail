# PROJECT CONTEXT

## 1. Mission
Building an enterprise-grade DLP (Data Loss Prevention) guardrail for prompt injection, jailbreaking, and inbound DLP detection. Target: enterprise SaaS customers who need sub-50ms latency, <1% false positive rate on benign enterprise traffic, and ≥95% attack recall.

## 2. Current user outcome
User can run eval against golden test set (712 cases: 367 attack / 345 benign) and get detailed traces per case showing layer-by-layer reasoning, fusion decision, and LLM judge invocation.

## 3. Current state
Working:
- Fastembed installed, Layer 2 (semantic) restored and operational
- Layer 3 (DeBERTa transformer) loads and runs
- Layer 0 (obfuscation) and Layer 1 (behavioral) functional
- Fusion logic: lone transformer hit now returns `route_to_llm: True` instead of auto-blocking
- Triage logic updated to check `fusion_result.get("route_to_llm")` flag
- Eval pipeline runs end-to-end producing summary CSV + detailed JSON traces
- 712 eval cases: 367 attack (10 families) / 345 benign (10 families)

Broken:
- **Indentation error** in `dlp_guardrail_with_llm.py` line 1254 (`use_llm = False` unexpected indent)
- **LLM judge not invoked** (0/712 cases) — environment variable not picked up in eval script context
- **212 false positives** (38.6% benign accuracy) — DeBERTa misclassifies benign enterprise SQL/legal/tool text as injection
- **4 false negatives** on attack side (92.4% attack accuracy)
- LLM judge (NVIDIA) configured but environment variable not propagating in eval script subprocess

## 4. Architecture
- **Frontend**: Gradio app (`app.py`) with BYOK panel for user-supplied LLM keys
- **Backend**: Python guardrail engine (`dlp_guardrail_with_llm.py`) — 4-layer cascade:
  - L0: Obfuscation detection (base64, rot13, leetspeak, etc.)
  - L1: Behavioral intent (regex patterns for retrieval, disclosure, etc.)
  - L2: Semantic similarity (fastembed ONNX embeddings + centroid rules)
  - L3: DeBERTa-v3 injection classifier (transformers pipeline)
- **Fusion**: Weighted average with confident-signal escalation; lone transformer hit now routes to LLM
- **LLM Judge**: Provider-agnostic (NVIDIA/OpenAI/Anthropic/Google/OpenRouter), BYOK, 15 RPM rate limit
- **Eval**: `run_eval_full.py` loads Excel dataset, runs guardrail, emits CSV + JSON traces

Important files:
- `dlp_guardrail_with_llm.py` — Core engine (1533 lines)
- `run_eval_full.py` — Eval runner (loads Excel, writes CSV/JSON)
- `guardrail_eval_v2.xlsx` — 712-case eval set (367 attack / 345 benign)
- `eval_results_summary.csv` / `eval_detailed_traces.json` — Output artifacts

## 5. What we are doing NOW
Current objective: Fix indentation error, ensure LLM judge invokes, re-run eval to measure impact of fusion/triage fixes.

Immediate next step: Fix indentation error at line 1254 in `dlp_guardrail_with_llm.py`, then re-run eval with NVIDIA key properly exported.

Definition of done: Eval runs without errors, LLM judge invoked on routed cases, false positive rate drops from 212→target <20, benign accuracy >90%.

## 6. Known constraints
- Windows environment (PowerShell env var syntax)
- Must use existing NVIDIA API key (already in run_eval_full.py)
- No new dependencies without approval
- Keep eval dataset frozen (712 cases frozen)
- No regex/centroid maintenance — architectural fixes only

## 7. Recent decisions
- Fusion: lone transformer hit → `route_to_llm: True` (MEDIUM confidence) instead of auto-block
- Triage: checks `fusion_result.get("route_to_llm")` flag before default LLM routing
- LLM judge: NVIDIA provider with `meta/llama-3.3-70b-instruct` model
- Fastembed installed for Layer 2 semantic layer
- Eval dataset frozen at 712 cases (367 attack / 345 benign)

## 8. Known problems
- [ ] Indentation error at line 1254 in `dlp_guardrail_with_llm.py`
- [ ] LLM judge not invoked (0/712) — env var not propagating in subprocess
- [ ] 212 false positives remain (benign_dlp_hard_negative, benign_documents, benign_encoded, etc.)
- [ ] 4 false negatives on attacks (indirect_injection, roleplay_jailbreak, inbound_dlp)
- [ ] LLM judge invocation = 0/712 — need to verify NVIDIA key propagation

## 9. Last verified
Date: 2026-10-07

Verified:
- Fusion logic: lone transformer hit → `route_to_llm: True` (confirmed in traces)
- Triage logic updated to check `fusion_result.get("route_to_llm")`
- Fastembed installed and Layer 2 loads successfully
- Eval pipeline produces summary CSV + JSON traces

Not verified:
- LLM judge actually invoked (0/712 so far)
- False positive reduction from fusion/triage fixes
- End-to-end eval with LLM judge operational

## 10. Rules for the coding agent
1. Inspect before modifying.
2. Make the smallest change that solves the current objective.
3. Do not refactor unrelated code.
4. Run the relevant test after changes.
5. Update this file if project state changes materially.

---

## 11. Website Deployment — Guard the Vault Game (NEW SECTION)

**Live URL**: https://midnightbuilds.fyi/guardrail.html  
**Gradio API**: https://praxis.midnightbuilds.fyi/gradio/api/predict  
**Status**: Deployed, API connectivity verified, some UX issues remain

### 11.1 Architecture
- **Frontend**: Static HTML/CSS/JS (`guardrail.html`, `assets/guardrail.css`, `assets/guardrail.js`, `assets/vault-door.js`, `assets/byok-modal.js`, `assets/guardrail-api.js`) deployed to GitHub Pages at `midnightbuilds.fyi/guardrail.html`
- **Backend**: Gradio app (`app.py`) running on Oracle VM (64.181.229.187:7860) via systemd service `dl-guardrail`
- **Reverse Proxy**: Caddy at `praxis.midnightbuilds.fyi` handling HTTPS + CORS + path stripping (`/gradio/*` → `localhost:7860`)
- **Auto-update**: Cron every 15 min on Oracle VM (`/home/ubuntu/update-guardrail.sh` → `git pull → pip install → systemctl restart dl-guardrail`)

### 11.2 Game Features (Attacker Perspective)
- Vault door SVG with binary verdicts: BREACHED 💎 (gold, door swings open, particles) vs REJECTED 🛡️ (red shield, scan lines, shake)
- 5 layer dots (L0–L3 + LLM Judge) — Blue pulse → Green (pass) / Red (caught) / Gold (breached)
- Arsenal: 6 tagged attacks (Jailbreak, Injection, Exfil, Benign)
- Scoreboard: Blocked vs Breached counters (localStorage persistence)
- BYOK Modal: Attach LLM key (Google/Anthropic/OpenAI/OpenRouter/OpenCode Zen)
- Share moment: Copy formatted result / Try another attack

### 11.3 API Contract
- **Base URL**: `https://praxis.midnightbuilds.fyi/gradio`
- **Endpoint**: `POST /api/predict`
- **Fn Index Mapping** (from Gradio config):
  - `ATTACH_KEY`: 0 (returns HTML status)
  - `CLEAR_KEY`: 1 (returns HTML status)
  - `ANALYZE_INDIVIDUAL`: 3 (returns verdict HTML + layers HTML + LLM status HTML)
  - `ANALYZE_CSV`: 4
- **Session**: `session_hash` for BYOK per-session state
- **CORS**: Caddy handles `Access-Control-Allow-Origin: https://midnightbuilds.fyi`

### 11.4 Verified Working
- [x] Game page loads at https://midnightbuilds.fyi/guardrail.html
- [x] Gradio API reachable via Caddy proxy (HTTPS + CORS)
- [x] `fn_index=3` (analyze_individual) returns real guardrail verdicts with layers
- [x] `fn_index=0` (attach_key) accepts BYOK key, returns HTML status
- [x] Auto-update pipeline: push to GitHub → Oracle VM pulls + restarts within 15 min
- [x] Nav links added to index/projects/articles pages

### 11.5 Unresolved Issues
- [ ] **BYOK Modal**: Clicking "Attach LLM Key" button doesn't open modal (JS event binding issue)
- [ ] **Launch Attack**: Button doesn't trigger API call (event handler not firing)
- [ ] **fn_index=3** returns `{"error":null}` instead of full response — intermittent 500 errors
- [ ] **Layer dots animation** not syncing with real API layer results
- [ ] **Scoreboard** not updating from API response
- [ ] **Share moment** not appearing after verdict
- [ ] **Game sounds/visual feedback** missing (no haptic/audio on breach/reject)

### 11.6 Key Files for Website
```
Midnight Builds/
├── guardrail.html                    # Main game page
├── assets/
│   ├── guardrail.css                 # Game-specific styles
│   ├── guardrail.js                  # Main game logic (ES module)
│   ├── vault-door.js                 # SVG + animation module
│   ├── byok-modal.js                 # BYOK modal module
│   ├── guardrail-api.js              # API client (GRADIO_URL + fn_index)
│   └── guardrail.css                 # Base styles (shared)
└── .hermes/plans/...                 # Implementation plan

DLP_guardrail/
├── app.py                            # Gradio app (serves API)
├── dlp_guardrail_with_llm.py         # Core engine
├── requirements.txt                  # gr==4.44.1, fastembed, etc.
└── /home/ubuntu/update-guardrail.sh  # Auto-update script on Oracle VM
```

### 11.7 Decisions Made
- Attacker perspective (not defender) — user crafts prompts to breach vault
- Binary verdicts only (BREACHED/REJECTED) — no HIGH_RISK/MEDIUM_RISK for normal users
- Jewel room revealed on breach (gold glow + particles) as reward
- Lock + shake + scan lines on reject as consequence
- Scoreboard in nav creates "just one more try" loop
- Oracle VM chosen over HF Spaces (always-on, no cold starts, full control)
- Caddy reverse proxy for HTTPS + CORS + path stripping

### 11.8 Next Actions (Priority Order)
1. **Fix BYOK Modal** — Debug `keyBtn.addEventListener` not opening modal
2. **Fix Launch Attack** — Debug `launchBtn.addEventListener` not firing API call
3. **Stabilize fn_index=3** — Investigate intermittent `{"error":null}` / 500 errors
4. **Wire layer dots to real API results** — Replace mock animation with `animateLayerDotsReal()`
5. **Scoreboard + Share moment** — Connect to API response data
6. **Polish** — Add sound/haptic feedback, refine animations, test mobile

---

## 10. Rules for the coding agent