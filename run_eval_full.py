import os
os.environ["NVIDIA_API_KEY"] = "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"
os.environ["LLM_PROVIDER"] = "nvidia"

import pandas as pd
import json
from dlp_guardrail_with_llm import IntentGuardrailWithLLM

# Load eval dataset
df = pd.read_excel('C:/Users/swati/Downloads/SwatiK425/DLP_guardrail/guardrail_eval_v2.xlsx')
print(f'Loaded {len(df)} eval cases')

# Initialize guardrail with NVIDIA provider (will pick up NVIDIA_API_KEY from env)
print('Initializing guardrail...')
g = IntentGuardrailWithLLM(provider="nvidia")

# Verify LLM judge is configured
print(f'LLM Judge: {g.llm_judge.provider if g.llm_judge else "NOT CONFIGURED"}')
print(f'Model: {g.llm_judge.model if g.llm_judge else "N/A"}')
print(f'Semantic: {"loaded" if g.semantic_analyzer else "NOT LOADED"}')

# Results storage
results = []
detailed_traces = []

# Run eval
for i, row in df.iterrows():
    prompt = row['prompt']
    expected = row['expected']
    category = row['category']
    family = row['family']
    case_id = row['id']
    
    if (i + 1) % 50 == 0:
        print(f'  Processed {i + 1}/{len(df)}')
    
    try:
        # Get detailed trace
        result = g.analyze(prompt, verbose=True)
        
        verdict = result['verdict']
        risk = result['risk_score']
        llm_used = result['llm_status']['used']
        llm_reason = result['llm_status']['reason']
        
        # Map verdict to binary
        predicted = 'ATTACK' if verdict in ('BLOCKED', 'HIGH_RISK', 'MEDIUM_RISK') else 'SAFE'
        actual = 'ATTACK' if expected in ('BLOCKED', 'HIGH_RISK', 'MEDIUM_RISK') else 'SAFE'
        correct = predicted == actual
        
        # Summary result
        results.append({
            'id': case_id,
            'family': family,
            'category': category,
            'expected': expected,
            'predicted_verdict': verdict,
            'predicted_binary': predicted,
            'correct': correct,
            'risk_score': risk,
            'llm_used': llm_used,
            'llm_reason': llm_reason
        })
        
        # Detailed trace
        trace = {
            'id': case_id,
            'prompt': prompt,
            'expected': expected,
            'category': category,
            'family': family,
            'subtype': row['subtype'],
            'policy_rule': row['policy_rule'],
            'verdict': verdict,
            'risk_score': risk,
            'confidence': result.get('confidence', 'N/A'),
            'time_ms': result.get('time_ms', 'N/A'),
            'llm_used': llm_used,
            'llm_reason': llm_reason,
            'correct': correct,
            'layers': {}
        }
        
        if 'layers' in result:
            for layer_item in result['layers']:
                for layer_name, layer_data in layer_item.items():
                    trace['layers'][layer_name] = layer_data
        
        trace['fusion'] = result.get('fusion', 'N/A')
        trace['triage'] = result.get('triage', 'N/A')
        
        detailed_traces.append(trace)
        
    except Exception as e:
        results.append({
            'id': case_id,
            'family': family,
            'category': category,
            'expected': expected,
            'predicted_verdict': 'ERROR',
            'predicted_binary': 'ERROR',
            'correct': False,
            'error': str(e)
        })
        detailed_traces.append({
            'id': case_id,
            'prompt': prompt,
            'expected': expected,
            'category': category,
            'family': family,
            'error': str(e)
        })

# Save summary results
results_df = pd.DataFrame(results)
results_df.to_csv('eval_results_summary.csv', index=False)

# Save detailed traces as JSON
with open('eval_detailed_traces.json', 'w') as f:
    json.dump(detailed_traces, f, indent=2)

# Print summary
total = len(results)
correct = sum(1 for r in results if r['correct'])
print(f'\n=== EVAL SUMMARY ===')
print(f'Total: {total}')
print(f'Correct: {correct} ({correct/total*100:.1f}%)')
print(f'Incorrect: {total-correct} ({(total-correct)/total*100:.1f}%)')

# Per family breakdown
from collections import defaultdict
fam_stats = defaultdict(lambda: {'correct': 0, 'total': 0})
for r in results:
    fam_stats[r['family']]['total'] += 1
    if r['correct']:
        fam_stats[r['family']]['correct'] += 1

print('\n=== PER FAMILY ===')
for fam in sorted(fam_stats.keys()):
    s = fam_stats[fam]
    acc = s['correct'] / s['total'] * 100
    print(f'  {fam}: {s["correct"]}/{s["total"]} = {acc:.1f}%')

# False negatives (attacks that passed)
fn = [r for r in results if r['category'] == 'attack' and not r['correct']]
print(f'\n=== FALSE NEGATIVES ({len(fn)}) ===')
for r in fn:
    print(f'  {r["id"]} [{r["family"]}]: expected={r["expected"]} got={r["predicted_verdict"]} risk={r.get("risk_score", "N/A")}')

# False positives (benign that blocked)
fp = [r for r in results if r['category'] == 'benign' and not r['correct']]
print(f'\n=== FALSE POSITIVES ({len(fp)}) ===')
for r in fp:
    print(f'  {r["id"]} [{r["family"]}]: expected={r["expected"]} got={r["predicted_verdict"]} risk={r.get("risk_score", "N/A")}')

# LLM usage
llm_total = sum(1 for r in results if r.get('llm_used'))
print(f'\nLLM used: {llm_total}/{total} = {llm_total/total*100:.1f}%')

# Attack vs Benign accuracy
attack_acc = sum(1 for r in results if r['category']=='attack' and r['correct']) / sum(1 for r in results if r['category']=='attack')
benign_acc = sum(1 for r in results if r['category']=='benign' and r['correct']) / sum(1 for r in results if r['category']=='benign')
print(f'\nAttack accuracy: {attack_acc*100:.1f}%')
print(f'Benign accuracy: {benign_acc*100:.1f}%')

print('\nDetailed traces saved to eval_detailed_traces.json')
print('Summary saved to eval_results_summary.csv')