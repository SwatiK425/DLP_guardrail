"""
benchmark.py — Run the DLP Guardrail over a labeled dataset and report REAL
metrics (confusion matrix, recall/precision/F1 per class) instead of claims.

Run:  python benchmark.py [path-to-csv]

Binary rule used here: an verdict in {BLOCKED, HIGH_RISK, MEDIUM_RISK} counts
as "defended/unsafe"; SAFE counts as benign. Adjust in ATTACK_SETS if needed.
"""
import csv
import sys
import time
from collections import defaultdict

from dlp_guardrail_with_llm import IntentGuardrailWithLLM

ATTACK_SETS = {"BLOCKED", "HIGH_RISK", "MEDIUM_RISK"}


def normalized(verdict: str) -> str:
    v = verdict.strip().upper()
    return v


def main(csv_path: str) -> None:
    with open(csv_path, encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    print(f"\nLoaded {len(rows)} labeled cases from {csv_path}\n")

    guardrail = IntentGuardrailWithLLM(gemini_api_key=None, rate_limit=1000)

    # confusion
    tp = tn = fp = fn = 0
    llm_used = 0
    total_ms = 0.0
    detail = []
    per_type = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0, "n": 0})

    for i, row in enumerate(rows, 1):
        prompt = row["prompt"]
        expected = row["expected"]
        source = row.get("source", "")
        t0 = time.time()
        r = guardrail.analyze(prompt, verbose=False)
        elapsed = (time.time() - t0) * 1000
        total_ms += elapsed

        actual = r["verdict"]
        if r["llm_status"].get("used"):
            llm_used += 1

        exp_attack = normalized(expected) in ATTACK_SETS
        act_attack = normalized(actual) in ATTACK_SETS

        key = f"{expected} / {actual}"
        if exp_attack and act_attack:
            tp += 1; cat = "TP"
        elif not exp_attack and act_attack:
            fp += 1; cat = "FP"
        elif exp_attack and not act_attack:
            fn += 1; cat = "FN"
        else:
            tn += 1; cat = "TN"
        per_type[source]["n"] += 1
        if cat == "TP":
            per_type[source]["tp"] += 1
        elif cat == "FN":
            per_type[source]["fn"] += 1

        detail.append((i, cat, expected, actual, r["risk_score"], prompt))

    accuracy = (tp + tn) / len(rows)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    print(f"{'METRIC':<12} {'VALUE':>8}")
    print("-" * 34)
    print(f"{'Accuracy':<12} {accuracy:>7.1%}")
    print(f"{'Precision':<12} {precision:>7.1%}")
    print(f"{'Recall':<12} {recall:>7.1%}")
    print(f"{'F1':<12} {f1:>7.1%}")
    print(f"{'LLM used':<12} {llm_used:>7}{' / ' + str(len(rows))}")
    print(f"{'Avg latency':<12} {total_ms / len(rows):>7.0f}ms")
    print()
    print("CONFUSION  (actual-unsafe)  (actual-safe)")
    print(f"  expected-unsafe   {tp:>8} {fn:>15}")
    print(f"  expected-safe     {fp:>8} {tn:>15}")
    print()

    # per-source breakdown (README vs synthetic vs fp-probes)
    print("PER-SOURCE RECALL:")
    for src, c in per_type.items():
        r_ = c["tp"] / (c["tp"] + c["fn"]) if (c["tp"] + c["fn"]) else float("nan")
        print(f"  {src:<22} n={c['n']:<3} recall={r_:>6.0%}")

    print("\nCASE LIST (expec /actual):")
    for num, cat, exp, act, risk, prompt in detail:
        print(f"  {num:>3} [{cat}] {exp:<12} → {act:<12} {risk:>3}  {prompt[:50]}")


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "eval_dataset.csv"
    main(path)