"""Interactive adjudication of review-queue disagreements -> gold set.

Walks review_queue.jsonl, asks the reviewer to take a call per case:

  [g]  Guardrail is RIGHT  -> gold expected = guardrail_verdict
  [t]  Ground truth RIGHT  -> gold expected = ground_truth
  [s]  Skip (no gold row, stays out of the eval set)
  [q]  Quit (apply decisions made so far)

Decisions are applied IMMEDIATELY (resumable): each accepted case is appended
to the gold eval CSV in ITS schema (prompt,expected,family,source), logged to
adjudicated.jsonl, and its fingerprint is marked for removal from
eval_inbox.jsonl at the end of the run.

Dedup / idempotency:
  - A gold row is only written if (normalized prompt, expected) is not already
    present, so re-running never duplicates.
  - Review-queue entries are matched to inbox entries by fingerprint
    sha256(f"{source}:{prompt}".encode("utf-8")).hexdigest()[:16], the same
    scheme CrowdSample.fingerprint() uses.

String hygiene:
  - normalize_prompt_text() strips surrounding whitespace and forces Unix LF
    line endings BEFORE fingerprinting and CSV lookup, so CRLF-prompts from a
    Windows checkout never break matching.
"""
import csv
import hashlib
import json
import sys
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass

BASE = Path(__file__).parent
REVIEW_QUEUE = BASE / "review_queue.jsonl"
EVAL_INBOX = BASE / "eval_inbox.jsonl"
GOLD_EVAL = BASE / "eval_dataset_v2.csv"
AUDIT_LOG = BASE / "adjudicated.jsonl"

# Mirrors CURATED_CATEGORY_MAP in intelligence_pipeline.py; kept in sync so
# family defaults match the benchmark's controlled vocabulary.
CURATED_CATEGORY_MAP = {
    "benign-guard":         ("benign_ops", "benign_ops"),
    "cross-lingual":        ("benign_education", "jailbreak"),
    "data-exfil":           ("benign_ops", "exfiltration"),
    "direct-jailbreak":     ("benign_ops", "jailbreak"),
    "encoding-obfuscation": ("benign_ops", "encoding"),
    "fp-probe":             ("benign_ops", "kill_switch"),
    "indirect-injection":   ("benign_ops", "injection"),
    "many-shot-fewshot":    ("benign_ops", "jailbreak"),
    "roleplay-jailbreak":   ("benign_ops", "jailbreak"),
    "system-disclosure":    ("benign_ops", "exfiltration"),
    "tool-injection":       ("benign_ops", "injection"),
    "xml-json-shift":       ("benign_ops", "injection"),
}


def normalize_prompt_text(text: str) -> str:
    """Strip whitespace and force Unix LF line endings for comparisons."""
    return (text or "").replace("\r\n", "\n").strip()


def fingerprint(source: str, prompt: str) -> str:
    """Same scheme as CrowdSample.fingerprint() (16 hex chars)."""
    return hashlib.sha256(f"{source}:{prompt}".encode("utf-8")).hexdigest()[:16]


# Explicit default family per controlled category+side: the most
# representative family rather than an alphabetical accident.
FAMILY_DEFAULTS = {
    ("benign_ops", True): "benign-guard",
    ("benign_education", True): "cross-lingual",
    ("benign_code", True): "benign-guard",
    ("jailbreak", False): "direct-jailbreak",
    ("injection", False): "tool-injection",
    ("exfiltration", False): "data-exfil",
    ("encoding", False): "encoding-obfuscation",
    ("kill_switch", False): "fp-probe",
}


def family_default(category: str, is_benign: bool) -> str:
    """Pick a gold 'family' from CURATED_CATEGORY_MAP for a controlled category."""
    default = FAMILY_DEFAULTS.get((category, is_benign))
    if default and default in CURATED_CATEGORY_MAP:
        return default
    matches = []
    for fam, (b, h) in CURATED_CATEGORY_MAP.items():
        if (is_benign and b == category) or (not is_benign and h == category):
            matches.append(fam)
    if not matches:
        return "benign-guard" if is_benign else "direct-jailbreak"
    matches.sort()
    return matches[0]


def load_jsonl(path: Path):
    out = []
    if path.exists():
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        out.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    return out


def load_gold(path: Path):
    """Return (header, set of (normalized_prompt, expected)) for dedup."""
    rows = set()
    header = None
    if path.exists():
        with open(path, newline="", encoding="utf-8-sig") as f:
            reader = csv.reader(f)
            for i, row in enumerate(reader):
                if i == 0:
                    header = [c.strip().lower().lstrip("\ufeff") for c in row]
                    continue
                if len(row) >= 4:
                    rows.add((normalize_prompt_text(row[0]), row[1].strip()))
    if header is None:
        header = ["prompt", "expected", "family", "source"]
    return header, rows


def append_gold(path: Path, prompt: str, expected: str, family: str, source: str,
                existing_rows: set, header):
    """Append a row if (prompt, expected) is not already present. Idempotent."""
    key = (normalize_prompt_text(prompt), expected)
    if key in existing_rows:
        return False
    with open(path, "a", newline="", encoding="utf-8") as f:
        # If the file doesn't end in a newline (e.g. last curated row has no
        # trailing \n), the first appended row would glue onto it and corrupt
        # the CSV. Ensure a clean row boundary first.
        if path.exists() and path.stat().st_size:
            with open(path, "rb") as rf:
                rf.seek(-1, 2)
                if rf.read(1) != b"\n":
                    f.write("\n")
        writer = csv.writer(f)
        writer.writerow([prompt, expected, family, source])
    existing_rows.add(key)
    return True


def drop_inbox_fingerprints(path: Path, fps: set):
    """Rewrite eval_inbox.jsonl removing curated fingerprints."""
    if not fps or not path.exists():
        return
    kept = [d for d in load_jsonl(path) if d.get("fingerprint") not in fps]
    with open(path, "w", encoding="utf-8") as f:
        for d in kept:
            f.write(json.dumps(d) + "\n")


def recommended_call(case: dict) -> str:
    """Evidence-based suggestion.

    Normalizes to the benchmark's binary axis (SAFE = benign; anything else =
    defended), then suggests for each corner:
      - GT defended, GR benign      -> guardrail MISSED a real attack -> truth right [t]
      - GT benign,  GR defended     -> guardrail FALSE-POSITIVE       -> truth right [t]
      - GT defended, GR defended    -> string-only mismatch (BLOCKED vs HIGH_RISK)
                                     -> either label grades the same; keep ground truth [t]
      - GT benign,  GR benign       -> both safe; likely mislabeled as a disagreement -> [t]
    Rule of thumb: prefer [t] when stream and guardrail disagree in the risky
    direction, since the curated streams (jbb/mitre/garak/benign) are gold. Override
    with [g] only when you're confident the STREAM mislabeled (e.g. benign request
    flagged malicious, or a clearly-SAFE ops prompt).
    """
    def axis(v): return "benign" if v in ("SAFE",) else "defended"
    gt_a, gr_a = axis(case.get("ground_truth", "")), axis(case.get("guardrail_verdict", ""))
    if gt_a == "defended" and gr_a == "benign":
        return "t"  # guardrail missed an attack
    if gt_a == "benign" and gr_a == "defended":
        return "t"  # false positive, unless stream clearly mislabeled -> override g
    return "t"  # congruent on the defended axis; keep ground-truth label


def preview(review: list, inbox_by_fp: dict, existing_rows: set):
    """Read-only table of every case + recommended call. No writes."""
    print(f"{'#':>2}  {'src':16s} {'GT':8s} {'GR':8s} risk l3conf rec  prompt")
    print("-" * 100)
    for i, case in enumerate(review, 1):
        prompt = normalize_prompt_text(case.get("prompt", ""))
        source = case.get("source", "")
        fp = fingerprint(source, prompt)
        hit = inbox_by_fp.get(fp)
        xref = hit.get("source_id", "") if hit else ""
        rec = recommended_call(case)
        gt, gr = case.get("ground_truth", ""), case.get("guardrail_verdict", "")
        risk = case.get("guardrail_risk", 0)
        l3 = case.get("l3_confidence", 0.0)
        # Flag already-in-gold as [skip]
        if (prompt, gr) in existing_rows or (prompt, gt) in existing_rows:
            rec = "s(dup)"
        print(f"{i:>2}  {source:16s} {gt:8s} {gr:8s} {risk:3d} {l3:4.2f}  {rec:6s} {prompt[:70]}")
        if xref:
            print(f"     ^ inbox ref {xref}")
    return {"g": sum(1 for c in review if recommended_call(c) == "g"),
            "t": sum(1 for c in review if recommended_call(c) == "t")}


def main():
    review = load_jsonl(REVIEW_QUEUE)
    inbox = load_jsonl(EVAL_INBOX)
    inbox_by_fp = {d.get("fingerprint"): d for d in inbox}
    header, existing_rows = load_gold(GOLD_EVAL)

    if not review:
        print("No entries in review_queue.jsonl — nothing to adjudicate.")
        return 0

    print(f"Adjudicating {len(review)} disagreement(s) -> {GOLD_EVAL.name}\n")
    print("Commands: [g]uardrail right  [t]ruth right  [s]kip  [q]uit\n")

    stats = {"g": 0, "t": 0, "s": 0, "wrote": 0, "dup": 0}
    to_drop = set()
    audit = load_jsonl(AUDIT_LOG)

    for i, case in enumerate(review, 1):
        prompt = case.get("prompt", "")
        norm = normalize_prompt_text(prompt)
        source = case.get("source", "")
        fp = fingerprint(source, prompt)
        inbox_hit = inbox_by_fp.get(fp)
        cross_ref = f"inbox:{inbox_hit.get('source_id', '?')}" if inbox_hit else "no-inbox-match"

        print(f"--- [{i}/{len(review)}] {source} | {case.get('priority', '?')} | "
              f"{case.get('reason', '')} | xref {cross_ref}")
        print(f"    GT: {case.get('ground_truth'):8s} GR: {case.get('guardrail_verdict'):8s} "
              f"risk={case.get('guardrail_risk')} l3={case.get('l3_confidence'):.2f}")
        print(f"    prompt: {norm}")
        print("    -> [g] guardrail right | [t] truth right | [s] skip | [q] quit ", end="")
        sys.stdout.flush()
        try:
            choice = input().strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nEOF — stopping.")
            break
        if choice == "q":
            print("Stopping.")
            break
        if choice not in ("g", "t", "s"):
            print("    (unrecognized, treated as skip)")
            choice = "s"

        if choice == "s":
            stats["s"] += 1
            continue

        stats[choice] += 1
        expected = case["guardrail_verdict"] if choice == "g" else case["ground_truth"]
        is_benign = expected in ("SAFE",)
        family = family_default(case.get("ground_truth_category", ""), is_benign)

        wrote = append_gold(GOLD_EVAL, prompt, expected, family, source,
                            existing_rows, header)
        stats["wrote" if wrote else "dup"] += 1
        to_drop.add(fp)
        audit.append({
            "fingerprint": fp,
            "prompt": prompt,
            "source": source,
            "adjudicated_expected": expected,
            "family": family,
            "winning_side": "guardrail" if choice == "g" else "ground_truth",
            "ground_truth": case.get("ground_truth"),
            "guardrail_verdict": case.get("guardrail_verdict"),
            "reason": case.get("reason"),
        })

    if audit:
        with open(AUDIT_LOG, "w", encoding="utf-8") as f:
            for entry in audit:
                f.write(json.dumps(entry) + "\n")

    if to_drop:
        drop_inbox_fingerprints(EVAL_INBOX, to_drop)

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"  guardrail right: {stats['g']}   truth right: {stats['t']}   skip: {stats['s']}")
    print(f"  gold rows written: {stats['wrote']}   skipped-duplicate: {stats['dup']}")
    print(f"  inbox entries dropped: {len(to_drop)}")
    print(f"  audit log: {AUDIT_LOG.name}")
    return 0


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if a in ("--preview", "--dry-run") or a.startswith("--")]
    if "--preview" in args or "--dry-run" in args:
        _review = load_jsonl(REVIEW_QUEUE)
        _inbox = load_jsonl(EVAL_INBOX)
        _by_fp = {d.get("fingerprint"): d for d in _inbox}
        _, _rows = load_gold(GOLD_EVAL)
        preview(_review, _by_fp, _rows)
        sys.exit(0)
    sys.exit(main())
