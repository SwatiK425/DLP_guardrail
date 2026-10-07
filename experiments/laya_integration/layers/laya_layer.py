"""
Laya Layer Wrapper for DLP Guardrail Integration.
Provides a consistent interface matching existing guardrail layers.
"""

import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum

try:
    import laya
    from laya import Router
    LAYA_AVAILABLE = True
except ImportError:
    LAYA_AVAILABLE = False
    print("⚠️  Laya not installed. Install from laya-playground.")


class LayaModel(Enum):
    ENGLISH = "english"
    MULTILINGUAL = "multilingual"
    TYPED_DECISIONS = "typed-decisions"


@dataclass
class LayaResult:
    """Standardized result from Laya analysis."""
    jailbreak: float = 0.0          # P(jailbreak)
    prompt_injection: float = 0.0   # P(prompt_injection)
    sensitive_data: float = 0.0     # P(sensitive_data)
    harm_severity: float = 0.0      # 1-5 score
    topic: str = "other"            # topic classification
    confidence: float = 0.0         # max confidence across signals
    risk_score: int = 0             # 0-100 derived risk
    latency_ms: float = 0.0
    raw_answers: Dict = None


class LayaLayer:
    """
    Laya decision layer for DLP guardrail.
    
    Wraps Laya's Router with guard_questions() to provide:
    - jailbreak detection
    - prompt injection detection  
    - sensitive data detection
    - harm severity scoring
    - topic classification
    
    Designed to match the interface of existing guardrail layers.
    """
    
    def __init__(self, 
                 model: LayaModel = LayaModel.TYPED_DECISIONS,
                 device: Optional[str] = None,
                 confidence_threshold: float = 0.85,
                 enable_cache: bool = True):
        """
        Initialize Laya layer.
        
        Args:
            model: Which Laya checkpoint to use
            device: 'cuda', 'mps', 'cpu', or None for auto
            confidence_threshold: Threshold for confident decisions
            enable_cache: Cache router instance
        """
        if not LAYA_AVAILABLE:
            raise RuntimeError("Laya not available. Install from laya-playground.")
        
        self.model = model
        self.device = device
        self.confidence_threshold = confidence_threshold
        self.enable_cache = enable_cache
        self._router = None
        self._questions = None
    
    @property
    def router(self) -> Router:
        """Lazy-load router."""
        if self._router is None:
            print(f"Loading Laya {self.model.value} model...")
            start = time.time()
            if self.device:
                self._router = Router(preload=False)
                self._router.load(self.model.value, device=self.device)
            else:
                self._router = Router(preload=True)
            print(f"Loaded in {time.time() - start:.1f}s")
        return self._router
    
    @property
    def questions(self) -> Dict:
        """Get guard questions."""
        if self._questions is None:
            self._questions = laya.guard_questions()
        return self._questions
    
    def analyze(self, prompt: str, verbose: bool = False) -> LayaResult:
        """
        Analyze a prompt with Laya's guard questions.
        
        Returns LayaResult with standardized fields.
        """
        start = time.time()
        
        state = {"prompt": prompt}
        
        try:
            result = self.router.predict(state, self.questions, model=self.model.value)
            answers = result.get("answers", {})
            
            # Extract probabilities
            jailbreak = answers.get("jailbreak", {}).get("noul", 0.0)
            prompt_injection = answers.get("prompt_injection", {}).get("noul", 0.0)
            sensitive_data = answers.get("sensitive_data", {}).get("noul", 0.0)
            
            # Harm severity (1-5)
            harm = answers.get("harm_severity", {})
            harm_severity = harm.get("score", 1.0) if harm.get("type") == "score" else 1.0
            
            # Topic
            topic_ans = answers.get("topic", {})
            topic = topic_ans.get("choice", "other") if topic_ans.get("type") == "choice" else "other"
            
            # Overall confidence (max of key signals)
            confidence = max(jailbreak, prompt_injection, sensitive_data)
            
            # Derive risk score (0-100)
            risk_score = self._compute_risk_score(
                jailbreak, prompt_injection, sensitive_data, harm_severity
            )
            
            latency = (time.time() - start) * 1000
            
            laya_result = LayaResult(
                jailbreak=jailbreak,
                prompt_injection=prompt_injection,
                sensitive_data=sensitive_data,
                harm_severity=harm_severity,
                topic=topic,
                confidence=confidence,
                risk_score=risk_score,
                latency_ms=latency,
                raw_answers=answers
            )
            
            if verbose:
                print(f"  Laya: jailbreak={jailbreak:.3f}, injection={prompt_injection:.3f}, "
                      f"sensitive={sensitive_data:.3f}, harm={harm_severity:.1f}, "
                      f"topic={topic}, risk={risk_score}, latency={latency:.1f}ms")
            
            return laya_result
            
        except Exception as e:
            latency = (time.time() - start) * 1000
            if verbose:
                print(f"  Laya ERROR: {e}")
            return LayaResult(
                latency_ms=latency,
                raw_answers={"error": str(e)}
            )
    
    def _compute_risk_score(self, jailbreak: float, injection: float, 
                           sensitive: float, harm: float) -> int:
        """
        Compute 0-100 risk score from Laya signals.
        Calibrated to match existing guardrail risk scale.
        """
        # Weighted combination
        weights = {
            "jailbreak": 0.35,
            "prompt_injection": 0.35,
            "sensitive_data": 0.20,
            "harm_severity": 0.10,
        }
        
        # Normalize harm to 0-1 (1-5 scale)
        harm_norm = (harm - 1) / 4
        
        weighted = (
            jailbreak * weights["jailbreak"] +
            injection * weights["prompt_injection"] +
            sensitive * weights["sensitive_data"] +
            harm_norm * weights["harm_severity"]
        )
        
        # Map to 0-100 with non-linear scaling for better separation
        if weighted > 0.8:
            return int(60 + weighted * 40)  # 60-100
        elif weighted > 0.5:
            return int(30 + weighted * 60)  # 30-60
        else:
            return int(weighted * 60)       # 0-30
    
    def is_confident_safe(self, result: LayaResult) -> bool:
        """Check if result is confidently safe (all signals low)."""
        return (result.jailbreak < 0.15 and 
                result.prompt_injection < 0.15 and 
                result.sensitive_data < 0.15 and
                result.harm_severity < 2.0)
    
    def is_confident_attack(self, result: LayaResult) -> bool:
        """Check if result is confidently an attack (any signal high)."""
        return (result.jailbreak > self.confidence_threshold or
                result.prompt_injection > self.confidence_threshold or
                result.sensitive_data > self.confidence_threshold or
                result.harm_severity >= 4.0)
    
    def get_decision(self, result: LayaResult) -> str:
        """Get triage decision from Laya result."""
        if self.is_confident_attack(result):
            return "BLOCK"
        elif self.is_confident_safe(result):
            return "ALLOW"
        else:
            return "UNCERTAIN"


class LayaObfuscationLayer:
    """
    Combined Layer 0 (Obfuscation) + Laya Fast Path.
    Runs obfuscation normalization first, then Laya on normalized text.
    """
    
    def __init__(self, 
                 laya_model: LayaModel = LayaModel.TYPED_DECISIONS,
                 device: Optional[str] = None):
        self.laya_layer = LayaLayer(model=laya_model, device=device)
        # Import existing obfuscation detector
        import sys
        sys.path.insert(0, "C:/Users/swati/Downloads/SwatiK425/DLP_guardrail")
        from dlp_guardrail_with_llm import ObfuscationDetector
        self.obfuscation = ObfuscationDetector()
    
    def analyze(self, prompt: str, verbose: bool = False) -> Dict:
        """
        Run obfuscation normalization then Laya analysis.
        Returns dict compatible with guardrail layer format.
        """
        start = time.time()
        
        # Layer 0: Obfuscation
        obf_result = self.obfuscation.detect_and_normalize(prompt)
        normalized = obf_result["normalized"]
        obf_risk = 15 if obf_result["obfuscation_detected"] else 0
        
        # Laya on normalized text
        laya_result = self.laya_layer.analyze(normalized, verbose=verbose)
        
        total_latency = (time.time() - start) * 1000
        
        # Combined decision
        decision = self.laya_layer.get_decision(laya_result)
        
        return {
            "name": "Layer 0+Laya",
            "obfuscation_risk": obf_risk,
            "obfuscation_techniques": obf_result["techniques"],
            "normalized_prompt": normalized,
            "laya": laya_result,
            "decision": decision,
            "risk_score": max(obf_risk, laya_result.risk_score),
            "confidence": laya_result.confidence,
            "total_latency_ms": total_latency,
            "layers_breakdown": {
                "obfuscation": {"risk": obf_risk, "latency_ms": 0},
                "laya": {"risk": laya_result.risk_score, "latency_ms": laya_result.latency_ms}
            }
        }


def create_laya_layer(config: Dict = None) -> LayaLayer:
    """Factory function to create LayaLayer from config."""
    if config is None:
        config = {}
    return LayaLayer(
        model=LayaModel(config.get("model", "typed-decisions")),
        device=config.get("device"),
        confidence_threshold=config.get("confidence_threshold", 0.85),
    )