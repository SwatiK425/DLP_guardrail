"""
Quick threshold sweep for Laya to find optimal operating point.
"""

import sys
import time
import json
from pathlib import Path

sys.path.insert(0, "C:/Users/swati/Downloads/SwatiK425/DLP_guardrail")

from experiments.laya_integration.shared.eval_datasets import EvalDatasets
from experiments.laya_integration.shared.metrics import OverallMetrics, print_metrics_report
from experiments.laya_integration.layers.laya_layer import LayaLayer, LayaModel


def run_threshold_sweep():
    """Test multiple confidence thresholds on a subset of data."""
    datasets = EvalDatasets()
    cases = datasets.load_in_scope()
    
    # Use subset for speed
    test_cases = cases[:40]  # First 40 cases
    
    thresholds = [0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.85, 0.9]
    models_to_test = [LayaModel.ENGLISH, LayaModel.MULTILINGUAL]
    
    results = {}
    
    for model in models_to_test:
        print(f"\n{'='*60}")
        print(f"TESTING {model.value}")
        print(f"{'='*60}")
        
        # Load model once
        laya_layer = LayaLayer(model=model, confidence_threshold=0.5)
        _ = laya_layer.router  # Force load
        
        model_results = {}
        
        for threshold in thresholds:
            laya_layer.confidence_threshold = threshold
            
            metrics = OverallMetrics()
            
            for case in test_cases:
                laya_result = laya_layer.analyze(case.prompt, verbose=False)
                decision = laya_layer.get_decision(laya_result)
                
                if decision == "BLOCK":
                    actual = "BLOCKED"
                elif decision == "ALLOW":
                    actual = "SAFE"
                else:
                    actual = "MEDIUM_RISK"
                
                metrics.add_result(
                    expected=case.expected_verdict,
                    actual=actual,
                    latency_ms=laya_result.latency_ms,
                    family=case.attack_family,
                    laya_used=True
                )
            
            o = metrics.to_dict()["overall"]
            model_results[threshold] = {
                "recall": o["recall"],
                "precision": o["precision"],
                "f1": o["f1"],
                "benign_fp_rate": o["benign_fp_rate"],
                "attack_fn_rate": o["attack_fn_rate"],
                "p95_latency": o["latency"]["p95_ms"],
            }
            
            print(f"  Threshold {threshold:.2f}: Recall={o['recall']:.1%}, FP={o['benign_fp_rate']:.1%}, p95={o['latency']['p95_ms']:.0f}ms")
        
        results[model.value] = model_results
    
    # Save
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    result_file = Path("C:/Users/swati/Downloads/SwatiK425/DLP_guardrail/experiments/laya_integration/results") / f"threshold_sweep_{timestamp}.json"
    with open(result_file, "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to: {result_file}")
    return results


if __name__ == "__main__":
    run_threshold_sweep()