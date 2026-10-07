"""
Standardized metrics for Laya integration experiments.
Provides precise, consistent metric calculation at overall and per-family levels.
"""

from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field
from collections import defaultdict
import json
import time
from enum import Enum


class Verdict(Enum):
    SAFE = "SAFE"
    MEDIUM_RISK = "MEDIUM_RISK"
    HIGH_RISK = "HIGH_RISK"
    BLOCKED = "BLOCKED"


@dataclass
class LatencyStats:
    """Latency statistics in milliseconds."""
    count: int = 0
    sum_ms: float = 0.0
    min_ms: float = float('inf')
    max_ms: float = 0.0
    p50_ms: float = 0.0
    p95_ms: float = 0.0
    p99_ms: float = 0.0
    _latencies: List[float] = field(default_factory=list)
    
    def add(self, latency_ms: float):
        self.count += 1
        self.sum_ms += latency_ms
        self.min_ms = min(self.min_ms, latency_ms)
        self.max_ms = max(self.max_ms, latency_ms)
        self._latencies.append(latency_ms)
    
    def finalize(self):
        if not self._latencies:
            return
        sorted_lat = sorted(self._latencies)
        n = len(sorted_lat)
        self.p50_ms = sorted_lat[int(0.5 * (n - 1))]
        self.p95_ms = sorted_lat[int(0.95 * (n - 1))]
        self.p99_ms = sorted_lat[int(0.99 * (n - 1))]
    
    def to_dict(self) -> Dict:
        return {
            "count": self.count,
            "mean_ms": round(self.sum_ms / self.count, 2) if self.count else 0,
            "min_ms": round(self.min_ms, 2) if self.count else 0,
            "max_ms": round(self.max_ms, 2) if self.count else 0,
            "p50_ms": round(self.p50_ms, 2),
            "p95_ms": round(self.p95_ms, 2),
            "p99_ms": round(self.p99_ms, 2),
        }


@dataclass
class FamilyMetrics:
    """Metrics for a single attack family."""
    family: str
    total: int = 0
    true_positives: int = 0      # Attack correctly detected
    false_negatives: int = 0     # Attack missed
    false_positives: int = 0     # Benign flagged as attack
    true_negatives: int = 0      # Benign correctly allowed
    latency: LatencyStats = field(default_factory=LatencyStats)
    llm_calls: int = 0
    laya_calls: int = 0
    
    def add_result(self, expected: str, actual: str, latency_ms: float, 
                   llm_used: bool = False, laya_used: bool = False):
        self.total += 1
        self.latency.add(latency_ms)
        if llm_used:
            self.llm_calls += 1
        if laya_used:
            self.laya_calls += 1
        
        exp_binary = "ATTACK" if expected in ["BLOCKED", "HIGH_RISK"] else "SAFE"
        act_binary = "ATTACK" if actual in ["BLOCKED", "HIGH_RISK"] else "SAFE"
        
        if exp_binary == "ATTACK" and act_binary == "ATTACK":
            self.true_positives += 1
        elif exp_binary == "SAFE" and act_binary == "SAFE":
            self.true_negatives += 1
        elif exp_binary == "SAFE" and act_binary == "ATTACK":
            self.false_positives += 1
        elif exp_binary == "ATTACK" and act_binary == "SAFE":
            self.false_negatives += 1
    
    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom > 0 else 0.0
    
    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom > 0 else 0.0
    
    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0
    
    @property
    def fp_rate(self) -> float:
        denom = self.false_positives + self.true_negatives
        return self.false_positives / denom if denom > 0 else 0.0
    
    @property
    def fn_rate(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.false_negatives / denom if denom > 0 else 0.0
    
    @property
    def accuracy(self) -> float:
        if self.total == 0:
            return 0.0
        return (self.true_positives + self.true_negatives) / self.total
    
    def to_dict(self) -> Dict:
        self.latency.finalize()
        return {
            "family": self.family,
            "total_cases": self.total,
            "recall": round(self.recall, 4),
            "precision": round(self.precision, 4),
            "f1": round(self.f1, 4),
            "accuracy": round(self.accuracy, 4),
            "false_positive_rate": round(self.fp_rate, 4),
            "false_negative_rate": round(self.fn_rate, 4),
            "true_positives": self.true_positives,
            "false_negatives": self.false_negatives,
            "false_positives": self.false_positives,
            "true_negatives": self.true_negatives,
            "latency": self.latency.to_dict(),
            "llm_call_rate": round(self.llm_calls / self.total, 4) if self.total else 0,
            "laya_call_rate": round(self.laya_calls / self.total, 4) if self.total else 0,
        }


@dataclass
class OverallMetrics:
    """Aggregated overall metrics."""
    total_cases: int = 0
    total_attacks: int = 0
    total_benign: int = 0
    true_positives: int = 0
    false_negatives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    latency: LatencyStats = field(default_factory=LatencyStats)
    llm_calls: int = 0
    laya_calls: int = 0
    families: Dict[str, FamilyMetrics] = field(default_factory=dict)
    
    def add_family(self, family: str) -> FamilyMetrics:
        if family not in self.families:
            self.families[family] = FamilyMetrics(family=family)
        return self.families[family]
    
    def add_result(self, expected: str, actual: str, latency_ms: float,
                   family: str, llm_used: bool = False, laya_used: bool = False):
        self.total_cases += 1
        self.latency.add(latency_ms)
        if llm_used:
            self.llm_calls += 1
        if laya_used:
            self.laya_calls += 1
        
        exp_binary = "ATTACK" if expected in ["BLOCKED", "HIGH_RISK"] else "SAFE"
        act_binary = "ATTACK" if actual in ["BLOCKED", "HIGH_RISK"] else "SAFE"
        
        if exp_binary == "ATTACK":
            self.total_attacks += 1
        else:
            self.total_benign += 1
        
        if exp_binary == "ATTACK" and act_binary == "ATTACK":
            self.true_positives += 1
        elif exp_binary == "SAFE" and act_binary == "SAFE":
            self.true_negatives += 1
        elif exp_binary == "SAFE" and act_binary == "ATTACK":
            self.false_positives += 1
        elif exp_binary == "ATTACK" and act_binary == "SAFE":
            self.false_negatives += 1
        
        # Also add to family metrics
        fam = self.add_family(family)
        fam.add_result(expected, actual, latency_ms, llm_used, laya_used)
    
    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom > 0 else 0.0
    
    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom > 0 else 0.0
    
    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0
    
    @property
    def accuracy(self) -> float:
        return (self.true_positives + self.true_negatives) / self.total_cases if self.total_cases else 0.0
    
    @property
    def benign_fp_rate(self) -> float:
        denom = self.false_positives + self.true_negatives
        return self.false_positives / denom if denom > 0 else 0.0
    
    @property
    def attack_fn_rate(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.false_negatives / denom if denom > 0 else 0.0
    
    @property
    def llm_call_rate(self) -> float:
        return self.llm_calls / self.total_cases if self.total_cases else 0.0
    
    @property
    def laya_call_rate(self) -> float:
        return self.laya_calls / self.total_cases if self.total_cases else 0.0
    
    def to_dict(self) -> Dict:
        self.latency.finalize()
        return {
            "overall": {
                "total_cases": self.total_cases,
                "total_attacks": self.total_attacks,
                "total_benign": self.total_benign,
                "accuracy": round(self.accuracy, 4),
                "recall": round(self.recall, 4),
                "precision": round(self.precision, 4),
                "f1": round(self.f1, 4),
                "benign_fp_rate": round(self.benign_fp_rate, 4),
                "attack_fn_rate": round(self.attack_fn_rate, 4),
                "true_positives": self.true_positives,
                "false_negatives": self.false_negatives,
                "false_positives": self.false_positives,
                "true_negatives": self.true_negatives,
                "latency": self.latency.to_dict(),
                "llm_call_rate": round(self.llm_call_rate, 4),
                "laya_call_rate": round(self.laya_call_rate, 4),
            },
            "per_family": {fam: metrics.to_dict() for fam, metrics in self.families.items()}
        }
    
    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


def print_metrics_report(metrics: OverallMetrics, title: str = "METRICS REPORT"):
    """Print a formatted metrics report."""
    print(f"\n{'='*80}")
    print(f"{title}")
    print(f"{'='*80}")
    
    overall = metrics.to_dict()["overall"]
    print(f"\nOVERALL METRICS:")
    print(f"  Total Cases:        {overall['total_cases']}")
    print(f"  Total Attacks:      {overall['total_attacks']}")
    print(f"  Total Benign:       {overall['total_benign']}")
    print(f"  Accuracy:           {overall['accuracy']:.2%}")
    print(f"  Recall (Attack):    {overall['recall']:.2%}")
    print(f"  Precision:          {overall['precision']:.2%}")
    print(f"  F1 Score:           {overall['f1']:.2%}")
    print(f"  Benign FP Rate:     {overall['benign_fp_rate']:.2%}")
    print(f"  Attack FN Rate:     {overall['attack_fn_rate']:.2%}")
    print(f"  LLM Call Rate:      {overall['llm_call_rate']:.2%}")
    print(f"  Laya Call Rate:     {overall['laya_call_rate']:.2%}")
    print(f"  Latency p50:        {overall['latency']['p50_ms']:.1f}ms")
    print(f"  Latency p95:        {overall['latency']['p95_ms']:.1f}ms")
    print(f"  Latency p99:        {overall['latency']['p99_ms']:.1f}ms")
    
    print(f"\nPER-FAMILY BREAKDOWN:")
    print(f"  {'Family':<25} {'Total':>6} {'Recall':>8} {'Prec':>8} {'F1':>8} {'FP%':>8} {'FN%':>8} {'p95ms':>8}")
    print(f"  {'-'*25} {'-'*6} {'-'*8} {'-'*8} {'-'*8} {'-'*8} {'-'*8} {'-'*8}")
    
    for fam, fm in sorted(metrics.families.items()):
        d = fm.to_dict()
        print(f"  {fam:<25} {d['total_cases']:>6} {d['recall']:>7.2%} {d['precision']:>7.2%} "
              f"{d['f1']:>7.2%} {d['false_positive_rate']:>7.2%} {d['false_negative_rate']:>7.2%} "
              f"{d['latency']['p95_ms']:>7.1f}")
    
    # Check gate criteria
    print(f"\nGATE CHECKS:")
    gates = [
        ("Overall Recall >= 95%", overall['recall'] >= 0.95),
        ("Benign FP Rate < 2%", overall['benign_fp_rate'] < 0.02),
        ("Latency p95 < 50ms", overall['latency']['p95_ms'] < 50),
        ("All Families Recall >= 95%", all(m.to_dict()['recall'] >= 0.95 for m in metrics.families.values() if m.total > 0)),
    ]
    for name, passed in gates:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"  {status}  {name}")