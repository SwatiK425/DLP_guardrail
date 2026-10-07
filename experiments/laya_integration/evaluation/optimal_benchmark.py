"""
Full benchmark with optimal configuration: English model, threshold ~0.65
"""

import sys
import time
import json
from pathlib import Path

sys.path.insert(0, "C:/Users/swati/Downloads/SwatiK425/DLP_guardrail")

from experiments.laya_integration.shared.eval_datasets import EvalDatasets
from experiments.laya_integration.shared.metrics import OverallMetrics, print_metrics_report
from experiments.laya_integration.layers.laya_layer import LayaLayer, LayaModel, LayaObfuscationLayer


def run_optimal_benchmark():
    """Run with optimal config: English model, threshold 0.65"""
    datasets = EvalDatasets()
    cases = datasets.load_in_scope()
    
    print(f"\n{'='*60}")
    print(f"OPTIMAL CONFIG: English model, threshold 0.65")
    print(f"Full dataset: {len(cases)} cases")
    print(f"{'='*60}")
    
    # Load model once
    laya_layer = LayaLayer(model=LayaModel.ENGLISH, confidence_threshold=0.65)
    _ = laya_layer.router  # Force load
    
    # Also test Laya + Obfuscation
    obf_laya = LayaObfuscationLayer(laya_model=LayaModel.ENGLISH)
    _ = obf_laya.laya_layer.router  # Force load (same router)
    
    metrics_laya = OverallMetrics()
    metrics_obf_laya = OverallMetrics()
    
    detailed = []
    
    for i, case in enumerate(cases):
        if i % 20 == 0:
            print(f"  [{i+1}/{len(cases)}] {case.attack_family}")
        
        # Laya standalone
        laya_result = laya_layer.analyze(case.prompt)
        decision = laya_layer.get_decision(laya_result)
        actual = "BLOCKED" if decision == "BLOCK" else ("SAFE" if decision == "ALLOW" else "MEDIUM_RISK")
        
        metrics_laya.add_result(
            expected=case.expected_verdict,
            actual=actual,
            latency_ms=laya_result.latency_ms,
            family=case.attack_family,
            laya_used=True
        )
        
        # Obfuscation + Laya
        obf_result = obf_laya.analyze(case.prompt)
        obf_decision = obf_result["decision"]
        obf_actual = "BLOCKED" if obf_decision == "BLOCK" else ("SAFE" if obf_decision == "ALLOW" else "MEDIUM_RISK")
        
        metrics_obf_laya.add_result(
            expected=case.expected_verdict,
            actual=obf_actual,
            latency_ms=obf_result["total_latency_ms"],
            family=case.attack_family,
            laya_used=True
        )
        
        detailed.append({
            "case_id": case.case_id,
            "prompt": case.prompt[:100],
            "family": case.attack_family,
            "expected": case.expected_verdict,
            "laya_verdict": actual,
            "laya_decision": decision,
            "laya_risk": laya_result.risk_score,
            "laya_conf": laya_result.confidence,
            "laya_latency": laya_result.latency_ms,
            "obf_laya_verdict": obf_actual,
            "obf_laya_decision": obf_decision,
            "obf_laya_risk": obf_result["risk_score"],
            "obf_laya_latency": obf_result["total_latency_ms"],
        })
    
    # Print reports
    print_metrics_report(metrics_laya, "LAYA STANDALONE (English, thresh=0.65)")
    print_metrics_report(metrics_obf_laya, "OBFUSCATION + LAYA (English, thresh=0.65)")
    
    # Save
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    result_file = Path("C:/Users/swati/Downloads/SwatiK425/DLP_guardrail/experiments/laya_integration/results") / f"optimal_benchmark_{timestamp}.json"
    
    output = {
        "config": {
            "model": "english",
            "threshold": 0.65,
            "dataset": "in_scope_full",
        },
        "laya_standalone": metrics_laya.to_dict(),
        "obfuscation_laya": metrics_obf_laya.to_dict(),
        "detailed": detailed
    }
    
    with open(result_file, "w") as f:
        json.dump(output, f, indent=2)
    
    print(f"\nResults saved to: {result_file}")
    
    return metrics_laya, metrics_obf_laya


if __name__ == "__main__":
    run_optimal_benchmark()