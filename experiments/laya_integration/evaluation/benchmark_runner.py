"""
Benchmark Runner for Laya Integration Experiments.
Runs Laya standalone on eval datasets and produces detailed metrics.
"""

import sys
import time
import json
from pathlib import Path
from typing import Dict, List, Optional

# Add project root to path
sys.path.insert(0, "C:/Users/swati/Downloads/SwatiK425/DLP_guardrail")

from experiments.laya_integration.shared.eval_datasets import EvalDatasets, normalize_verdict
from experiments.laya_integration.shared.metrics import OverallMetrics, print_metrics_report
from experiments.laya_integration.layers.laya_layer import LayaLayer, LayaModel, LayaObfuscationLayer


class LayaBenchmark:
    """Runs Laya benchmarks on DLP evaluation datasets."""
    
    def __init__(self, 
                 laya_model: LayaModel = LayaModel.TYPED_DECISIONS,
                 device: Optional[str] = None,
                 confidence_threshold: float = 0.85):
        self.laya_layer = LayaLayer(
            model=laya_model,
            device=device,
            confidence_threshold=confidence_threshold
        )
        self.datasets = EvalDatasets()
        self.results_dir = Path("C:/Users/swati/Downloads/SwatiK425/DLP_guardrail/experiments/laya_integration/results")
        self.results_dir.mkdir(parents=True, exist_ok=True)
    
    def run_benchmark(self, 
                      dataset: str = "in_scope",
                      verbose: bool = False,
                      save_results: bool = True) -> OverallMetrics:
        """
        Run benchmark on specified dataset.
        
        Args:
            dataset: "in_scope", "out_of_scope", "benign", "attacks", or "all"
            verbose: Print per-case results
            save_results: Save detailed results to JSON
            
        Returns:
            OverallMetrics with all computed metrics
        """
        # Load test cases
        if dataset == "in_scope":
            cases = self.datasets.load_in_scope()
        elif dataset == "out_of_scope":
            cases = self.datasets.load_out_of_scope()
        elif dataset == "benign":
            cases = self.datasets.load_all_benign()
        elif dataset == "attacks":
            cases = self.datasets.load_all_attacks()
        elif dataset == "all":
            cases = self.datasets.load_in_scope() + self.datasets.load_out_of_scope()
        else:
            raise ValueError(f"Unknown dataset: {dataset}")
        
        print(f"\n{'='*80}")
        print(f"LAYA BENCHMARK: {dataset.upper()} ({len(cases)} cases)")
        print(f"Model: {self.laya_layer.model.value}")
        print(f"Confidence Threshold: {self.laya_layer.confidence_threshold}")
        print(f"{'='*80}")
        
        metrics = OverallMetrics()
        detailed_results = []
        
        for i, case in enumerate(cases):
            if verbose or i % 50 == 0:
                print(f"  [{i+1}/{len(cases)}] {case.attack_family}: {case.prompt[:60]}...")
            
            start = time.time()
            laya_result = self.laya_layer.analyze(case.prompt, verbose=False)
            latency = (time.time() - start) * 1000
            
            # Get Laya's decision
            decision = self.laya_layer.get_decision(laya_result)
            
            # Map to verdict
            if decision == "BLOCK":
                actual_verdict = "BLOCKED"
            elif decision == "ALLOW":
                actual_verdict = "SAFE"
            else:
                actual_verdict = "MEDIUM_RISK"
            
            # Record metrics
            metrics.add_result(
                expected=case.expected_verdict,
                actual=actual_verdict,
                latency_ms=latency,
                family=case.attack_family,
                llm_used=False,
                laya_used=True
            )
            
            detailed_results.append({
                "case_id": case.case_id,
                "prompt": case.prompt,
                "expected": case.expected_verdict,
                "actual": actual_verdict,
                "family": case.attack_family,
                "laya_decision": decision,
                "laya_risk_score": laya_result.risk_score,
                "laya_confidence": laya_result.confidence,
                "jailbreak": laya_result.jailbreak,
                "prompt_injection": laya_result.prompt_injection,
                "sensitive_data": laya_result.sensitive_data,
                "harm_severity": laya_result.harm_severity,
                "topic": laya_result.topic,
                "latency_ms": latency,
                "correct": normalize_verdict(case.expected_verdict) == normalize_verdict(actual_verdict)
            })
        
        # Print report
        print_metrics_report(metrics, f"LAYA STANDALONE - {dataset.upper()}")
        
        # Save results
        if save_results:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            result_file = self.results_dir / f"laya_standalone_{dataset}_{timestamp}.json"
            
            output = {
                "config": {
                    "model": self.laya_layer.model.value,
                    "confidence_threshold": self.laya_layer.confidence_threshold,
                    "dataset": dataset,
                    "timestamp": timestamp
                },
                "metrics": metrics.to_dict(),
                "detailed_results": detailed_results
            }
            
            with open(result_file, "w") as f:
                json.dump(output, f, indent=2)
            print(f"\nResults saved to: {result_file}")
        
        return metrics
    
    def run_per_family_benchmark(self, 
                                  families: Optional[List[str]] = None,
                                  verbose: bool = False) -> Dict[str, OverallMetrics]:
        """Run benchmark separately for each attack family."""
        if families is None:
            families = self.datasets.get_families()
        
        print(f"\n{'='*80}")
        print(f"PER-FAMILY BENCHMARK")
        print(f"{'='*80}")
        
        family_results = {}
        
        for family in families:
            cases = self.datasets.get_by_family(family)
            if not cases:
                continue
            
            print(f"\n--- {family} ({len(cases)} cases) ---")
            
            metrics = OverallMetrics()
            for case in cases:
                laya_result = self.laya_layer.analyze(case.prompt, verbose=False)
                decision = self.laya_layer.get_decision(laya_result)
                
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
            
            family_results[family] = metrics
            
            # Print family summary
            fam_metrics = metrics.families.get(family)
            if fam_metrics:
                d = fam_metrics.to_dict()
                print(f"  Recall: {d['recall']:.2%}, Precision: {d['precision']:.2%}, "
                      f"FP: {d['false_positive_rate']:.2%}, FN: {d['false_negative_rate']:.2%}")
        
        return family_results


def run_baseline_comparison():
    """Run Laya baseline comparison across all model variants."""
    print("\n" + "="*80)
    print("LAYA MODEL VARIANT COMPARISON")
    print("="*80)
    
    models_to_test = [
        LayaModel.ENGLISH,
        LayaModel.MULTILINGUAL,
        LayaModel.TYPED_DECISIONS,
    ]
    
    all_results = {}
    
    for model in models_to_test:
        print(f"\n\nTesting {model.value}...")
        try:
            benchmark = LayaBenchmark(laya_model=model)
            metrics = benchmark.run_benchmark(dataset="in_scope", verbose=False)
            all_results[model.value] = metrics.to_dict()
        except Exception as e:
            print(f"  ERROR with {model.value}: {e}")
            all_results[model.value] = {"error": str(e)}
    
    # Save comparison
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    result_file = Path("C:/Users/swati/Downloads/SwatiK425/DLP_guardrail/experiments/laya_integration/results") / f"laya_model_comparison_{timestamp}.json"
    
    with open(result_file, "w") as f:
        json.dump(all_results, f, indent=2)
    
    print(f"\n\nComparison saved to: {result_file}")
    
    # Print summary table
    print(f"\n{'Model':<20} {'Recall':>8} {'Prec':>8} {'F1':>8} {'FP%':>8} {'FN%':>8} {'p95ms':>8}")
    print("-" * 70)
    for model_name, result in all_results.items():
        if "error" in result:
            print(f"{model_name:<20} ERROR: {result['error']}")
        else:
            o = result["overall"]
            print(f"{model_name:<20} {o['recall']:>7.2%} {o['precision']:>7.2%} "
                  f"{o['f1']:>7.2%} {o['benign_fp_rate']:>7.2%} {o['attack_fn_rate']:>7.2%} "
                  f"{o['latency']['p95_ms']:>7.1f}")
    
    return all_results


if __name__ == "__main__":
    import time
    
    # Run baseline on in-scope dataset
    benchmark = LayaBenchmark(laya_model=LayaModel.TYPED_DECISIONS)
    metrics = benchmark.run_benchmark(dataset="in_scope", verbose=True)
    
    # Also run per-family
    benchmark.run_per_family_benchmark()
    
    # Run model comparison
    run_baseline_comparison()