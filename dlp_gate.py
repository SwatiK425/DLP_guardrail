"""
dlp_gate.py — The C-phase data-plane gate for DLP Guardrail.

Core shift: from a *classifier that returns a label* (BLOCKED/SAFE + score)
to an *enforceable gate* that returns a Decision you act on.

  decision = guardrail.inspect(payload)
  decision.action        -> "ALLOW" | "REDACT" | "BLOCK"
  decision.redacted      -> safe payload to forward (action == "REDACT")
  decision.findings      -> what sensitive data was found

Deliberately stdlib-only (no numpy/torch/Gemini) so it runs anywhere and is
unit-testable in isolation. The existing 4-layer intent guardrail stays as
the *threat intent* source; this file is the *data-plane* half — it decides
the action and scrubs the actual sensitive DATA.

Coupling: `GuardrailGate` wires the original `IntentGuardrailWithLLM` into
the engine so one call yields an enforceable decision + audit entry.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

REDACT_TOKEN = "[REDACTED]"


# ============================================================================
# FINDINGS + DECISIONS
# ============================================================================
@dataclass
class Finding:
    dtype: str
    start: int
    end: int
    snippet: str
    confidence: str = "HIGH"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Decision:
    action: str                          # ALLOW | REDACT | BLOCK
    reason: str
    redacted: str
    findings: List[Finding] = field(default_factory=list)
    intent_verdict: str = "n/a"
    risk_score: int = 0
    llm_used: bool = False

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "reason": self.reason,
            "redacted": self.redacted,
            "findings": [f.to_dict() for f in self.findings],
            "intent_verdict": self.intent_verdict,
            "risk_score": self.risk_score,
            "llm_used": self.llm_used,
        }


# ============================================================================
# DETECTORS
# ============================================================================
def _regex_detector(pattern_str: str) -> re.Pattern:
    return re.compile(pattern_str, re.IGNORECASE)


def _card_luhn_ok(text: str) -> bool:
    """Validate a candidate card number with the Luhn checksum."""
    digits = [int(c) for c in text if c.isdigit()]
    if len(digits) < 12 or len(digits) > 19:
        return False
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _detect_credit_cards(text: str) -> List[Finding]:
    findings = []
    for m in re.finditer(r"(?<!\d)(?:[0-9][ -]?){13,19}(?<!\s)\d(?!\d)", text):
        if _card_luhn_ok(m.group(0)):
            findings.append(Finding("CREDIT_CARD", m.start(), m.end(), m.group(0)))
    return findings


# name -> compiled regex
REGEX_DETECTORS: Dict[str, re.Pattern] = {
    "SSN":           _regex_detector(r"\b\d{3}-\d{2}-\d{4}\b"),
    "EMAIL":         _regex_detector(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"),
    "IPV4":          _regex_detector(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "AWS_KEY":       _regex_detector(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "OPENAI_KEY":    _regex_detector(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    "GITHUB_KEY":    _regex_detector(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    "GOOGLE_KEY":    _regex_detector(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
    "SLACK_TOKEN":   _regex_detector(r"\bxox[baprs](-[A-Za-z0-9-]{10,})+"),
    "SECRET_ASSIGN": _regex_detector(
        r"\b(?:(?:api|secret|client|pass|user)_?)?(?:key|token|password|secret)"
        r"\s*[:=]\s*\S+"),
}

# dtypes we treat as live credential (hard block) vs scrub-able PII/card
KEY_TYPES = {"AWS_KEY", "OPENAI_KEY", "GITHUB_KEY", "GOOGLE_KEY",
             "SLACK_TOKEN", "SECRET_ASSIGN"}


def detect_spans(text: str) -> List[Finding]:
    findings: List[Finding] = []
    findings.extend(_detect_credit_cards(text))
    for dtype, pat in REGEX_DETECTORS.items():
        for m in pat.finditer(text):
            findings.append(Finding(dtype, m.start(), m.end(), m.group(0)))
    # keep longest span, drop shorter overlaps (higher-priority larger wins)
    findings.sort(key=lambda f: (f.start, -(f.end - f.start)))
    merged: List[Finding] = []
    for f in findings:
        if merged and f.start < merged[-1].end:
            continue
        merged.append(f)
    return merged


def redact(text: str, findings: List[Finding]) -> str:
    out = text
    for f in sorted(findings, key=lambda s: s.start, reverse=True):
        out = out[:f.start] + REDACT_TOKEN + out[f.end:]
    return out


# ============================================================================
# POLICY ENGINE
# ============================================================================
# Maps an intent verdict from the existing guardrail onto an enforceable action.
INTENT_TO_POLICY: Dict[str, str] = {
    "BLOCKED":     "BLOCK",
    "HIGH_RISK":   "BLOCK",      # product blocks HIGH_RISK; no data to scrub -> reject
    "MEDIUM_RISK": "REDACT",     # suspicious -> strip data, forward, monitor
    "SAFE":        "ALLOW",
}


class DataGate:
    """Pure, dependency-free data-plane gate (unit-testable in isolation)."""

    def __init__(self,
                 auto_redact: bool = True,
                 hard_block_keys: bool = True,
                 policy: Optional[Dict[str, str]] = None):
        self.auto_redact = auto_redact
        self.hard_block_keys = hard_block_keys
        self._policy = dict(policy) if policy else dict(INTENT_TO_POLICY)

    def inspect(self,
                text: str,
                intent_verdict: str = "SAFE",
                risk_score: int = 0,
                llm_used: bool = False) -> Decision:
        findings = detect_spans(text)
        redacted_text = redact(text, findings)
        keys_present = any(f.dtype in KEY_TYPES for f in findings)

        # 1. Block outright on a high-confidence threatening intent
        if self._policy.get(intent_verdict) == "BLOCK":
            return Decision("BLOCK", "High-risk intent", redacted_text,
                            findings, intent_verdict, risk_score, llm_used)

        # 2. Block when a live credential is present and we hard-block keys
        if self.hard_block_keys and keys_present:
            return Decision("BLOCK", "Live credential found", redacted_text,
                            findings, intent_verdict, risk_score, llm_used)

        # 3. Scrub PII / card data and forward the safe copy
        if findings:
            action = "REDACT" if self.auto_redact else "QUARANTINE"
            return Decision(
                action, f"{len(findings)} sensitive item(s) found",
                redacted_text, findings, intent_verdict, risk_score, llm_used)

        # 4. Clean
        return Decision("ALLOW", "Clean", text, findings,
                        intent_verdict, risk_score, llm_used)


class AuditTrail:
    """Append-only JSONL audit log — the compliance-facing surface."""

    def __init__(self, path: str = "dlp_audit.jsonl"):
        self.path = path

    def record(self, decision: Decision, payload: str) -> None:
        row = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "payload_sha256": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
            **decision.to_dict(),
        }
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(row) + "\n")


# ============================================================================
# COUPLING TO THE ORIGINAL 4-LAYER GUARDRAIL
# ============================================================================
class GuardrailGate:
    """Wrap the original IntentGuardrailWithLLM + the new gate into one call."""

    def __init__(self,
                 guardrail=None,
                 gate: Optional[DataGate] = None,
                 audit: Optional[AuditTrail] = None):
        self._guardrail = guardrail
        self._gate = gate or DataGate()
        self._audit = audit or AuditTrail()

    def inspect(self, payload: str) -> Decision:
        intent_verdict, risk, llm_used = "SAFE", 0, False
        if self._guardrail is not None:
            try:
                g = self._guardrail.analyze(payload, verbose=False)
                intent_verdict = g["verdict"]
                risk = g["risk_score"]
                llm_used = g["llm_status"]["used"]
            except Exception:
                # the gate must never be a single point of failure
                pass
        decision = self._gate.inspect(payload, intent_verdict, risk, llm_used)
        self._audit.record(decision, payload)
        return decision


# ============================================================================
# DEMO
# ============================================================================
if __name__ == "__main__":
    gate = DataGate()
    samples = [
        "My email is alice@example.com and phone 555-010-1234",  # PII -> REDACT
        "Key: AKIAIOSFODNN7EXAMPLE",                              # AWS key -> BLOCK
        "Card 4111 1111 1111 1111 expires soon",                  # card -> REDACT
        "Just a normal help request please",                      # clean -> ALLOW
    ]
    for s in samples:
        d = gate.inspect(s)
        print(f"[{d.action:9s}] {s!r:45s} -> {d.redacted!r}   {d.reason}")