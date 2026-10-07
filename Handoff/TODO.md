## 🔴 NOW

- [ ] **Fix indentation error** at line 1254 in `dlp_guardrail_with_llm.py` (unexpected indent on `use_llm = False`)
- [ ] **Ensure NVIDIA API key propagates** to eval subprocess — verify LLM judge invokes (>0/712)
- [ ] **Re-run full eval** with fixed indentation + NVIDIA key propagated
- [ ] **Verify LLM judge invoked** on routed cases (target >0/712, ideally >50 cases)

Definition of done:
- Eval runs without errors
- LLM judge invoked on routed cases (target >0/712)
- False positive rate drops from 212 → target <20
- Benign accuracy >90%
- Attack accuracy stays ≥90%

## 🟡 NEXT

- [ ] **Fix false positives root cause** — benign_dlp_hard_negative (73 cases), benign_documents (48), benign_encoded (16), benign_enterprise_workflows (36), benign_trigger_words (25)
- [ ] **Add L1 behavioral patterns** for inbound_dlp (credential/secret extraction) and indirect_injection (embedded in email/PDF/web/RAG/Jira/CRM)
- [ ] **Add L1 intent rules** for credential_harvest (AWS keys, JWT, DB strings, K8s secrets, service tokens)
- [ ] **Fix false negatives** on indirect_injection (15), inbound_dlp (11), hypothetical_academic (12)
- [ ] **Add code suppression** to transformer detector for SQL/legal/tool text (structural detection, not keyword-based)

## 🟢 LATER

- [ ] **Replace DeBERTa with fine-tuned safety model** (StruQ/SecAlign approach) — architectural fix
- [ ] **Structured query format** (StruQ) — instruction/data channel separation
- [ ] **Declarative policy language** (Colang/Guardrails AI) for rule maintenance
- [ ] **Gradient-based adversarial testing** (continuous red-teaming)
- [ ] **Production deployment** with monitoring/alerting
- [ ] **Multi-tenant key isolation** (fix global singleton API key bleed)

## 📋 ARCHITECTURE DECISIONS LOGGED

- **Fusion**: lone transformer hit → `route_to_llm: True` (MEDIUM) instead of auto-block ✅
- **Triage**: checks `fusion_result.get("route_to_llm")` flag ✅
- **LLM Judge**: NVIDIA provider, `meta/llama-3.3-70b-instruct` ✅
- **Fastembed** installed for Layer 2 ✅
- **Eval dataset** frozen at 712 cases (367 attack / 345 benign) ✅
- **LLM Judge**: NVIDIA provider, `meta/llama-3.3-70b-instruct` model

---

## 🌐 WEBSITE — Guard the Vault Game

### 🔴 NOW (Blocking game functionality)
- [ ] **Fix BYOK Modal** — `keyBtn.addEventListener` not opening modal (check `assets/byok-modal.js` + `guardrail.js` init order)
- [ ] **Fix Launch Attack** — `launchBtn.addEventListener` not firing API call (check `assets/guardrail.js` bindEvents)
- [ ] **Stabilize fn_index=3** — Intermittent `{"error":null}` / 500 errors on `analyze_individual` (check Gradio logs)
- [ ] **Wire layer dots to real API** — Replace mock `animateLayerDots()` with `animateLayerDotsReal()` using actual layer results
- [ ] **Scoreboard update** — Connect `stats.blocked/breached` to API response verdict
- [ ] **Share moment** — Show/hide logic tied to verdict state

### 🟡 NEXT (Polish)
- [ ] **Sound/haptic feedback** — Audio on breach (gold chime) / reject (shield thud)
- [ ] **Mobile responsive** — Test vault SVG + arsenal scrolling on ≤480px
- [ ] **Loading states** — Better visual during API latency (door pulse, button spinner)
- [ ] **Error toast** — User-friendly message when API fails (not console only)
- [ ] **Keyboard shortcuts** — Enter to launch, Escape to reset, Tab navigation

### 🟢 LATER
- [ ] **Leaderboard** — Persist top scores to backend (optional)
- [ ] **Attack templates** — Expand arsenal with more real-world variants
- [ ] **Analytics** — Privacy-friendly event tracking (breach/reject rates, key attach rate)
- [ ] **Shareable URLs** — Encode prompt+verdict in URL hash for social sharing