"""
Shared evaluation datasets for Laya integration experiments.
Provides standardized access to all DLP eval datasets with proper labeling.
"""

import pandas as pd
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass


@dataclass
class EvalCase:
    """Single evaluation case with prompt and expected verdict."""
    prompt: str
    expected_verdict: str
    attack_family: str
    case_id: int


class EvalDatasets:
    """Manages all evaluation datasets for the DLP guardrail."""
    
    def __init__(self, base_path: str = "C:/Users/swati/Downloads/SwatiK425/DLP_guardrail"):
        self.base_path = Path(base_path)
        self._cache: Dict[str, List[EvalCase]] = {}
    
    def load_in_scope(self) -> List[EvalCase]:
        """Load the primary in-scope evaluation dataset (eval_in_scope.csv)."""
        if "in_scope" in self._cache:
            return self._cache["in_scope"]
        
        path = self.base_path / "eval_in_scope.csv"
        df = pd.read_csv(path)
        
        cases = []
        for idx, row in df.iterrows():
            cases.append(EvalCase(
                prompt=row["prompt"],
                expected_verdict=row["expected"],
                attack_family=row.get("family", "unknown"),
                case_id=idx
            ))
        
        self._cache["in_scope"] = cases
        return cases
    
    def load_out_of_scope(self) -> List[EvalCase]:
        """Load out-of-scope evaluation dataset."""
        if "out_of_scope" in self._cache:
            return self._cache["out_of_scope"]
        
        path = self.base_path / "eval_out_of_scope.csv"
        df = pd.read_csv(path)
        
        cases = []
        for idx, row in df.iterrows():
            cases.append(EvalCase(
                prompt=row["prompt"],
                expected_verdict=row["expected"],
                attack_family=row.get("family", "out_of_scope"),
                case_id=idx
            ))
        
        self._cache["out_of_scope"] = cases
        return cases
    
    def load_all_benign(self) -> List[EvalCase]:
        """Load all benign cases from all datasets."""
        benign_cases = []
        
        # From in-scope
        for case in self.load_in_scope():
            if case.expected_verdict.upper() in ["SAFE", "BENIGN"]:
                benign_cases.append(case)
        
        # From out-of-scope
        for case in self.load_out_of_scope():
            if case.expected_verdict.upper() in ["SAFE", "BENIGN"]:
                benign_cases.append(case)
        
        # From benign_business.csv
        path = self.base_path / "benign_business.csv"
        if path.exists():
            df = pd.read_csv(path)
            for idx, row in df.iterrows():
                benign_cases.append(EvalCase(
                    prompt=row["prompt"],
                    expected_verdict=row.get("verdict", "SAFE"),
                    attack_family=row.get("category", "benign_business"),
                    case_id=idx
                ))
        
        return benign_cases
    
    def load_all_attacks(self) -> List[EvalCase]:
        """Load all attack cases from all datasets."""
        attack_cases = []
        
        for case in self.load_in_scope():
            if case.expected_verdict.upper() not in ["SAFE", "BENIGN"]:
                attack_cases.append(case)
        
        for case in self.load_out_of_scope():
            if case.expected_verdict.upper() not in ["SAFE", "BENIGN"]:
                attack_cases.append(case)
        
        return attack_cases
    
    def get_by_family(self, family: str) -> List[EvalCase]:
        """Get all cases for a specific attack family."""
        all_cases = self.load_in_scope() + self.load_out_of_scope()
        return [c for c in all_cases if c.attack_family == family]
    
    def get_families(self) -> List[str]:
        """Get list of all attack families."""
        all_cases = self.load_in_scope() + self.load_out_of_scope()
        families = set(c.attack_family for c in all_cases)
        return sorted(families)
    
    def get_stats(self) -> Dict:
        """Get dataset statistics."""
        in_scope = self.load_in_scope()
        out_scope = self.load_out_of_scope()
        benign = self.load_all_benign()
        attacks = self.load_all_attacks()
        
        return {
            "in_scope_total": len(in_scope),
            "out_of_scope_total": len(out_scope),
            "benign_total": len(benign),
            "attacks_total": len(attacks),
            "families": self.get_families(),
            "family_counts": {f: len(self.get_by_family(f)) for f in self.get_families()}
        }


# Standard verdict normalization
def normalize_verdict(verdict: str) -> str:
    """Normalize verdict to standard categories."""
    v = verdict.upper().strip()
    if v in ["BLOCKED", "BLOCK", "MALICIOUS", "ATTACK"]:
        return "BLOCKED"
    elif v in ["SAFE", "BENIGN", "OK"]:
        return "SAFE"
    elif v in ["HIGH_RISK", "HIGHRISK", "HIGH"]:
        return "HIGH_RISK"
    elif v in ["MEDIUM_RISK", "MEDIUMRISK", "MEDIUM", "UNCERTAIN"]:
        return "MEDIUM_RISK"
    return v


def is_attack_verdict(verdict: str) -> bool:
    """Check if verdict indicates an attack."""
    return normalize_verdict(verdict) in ["BLOCKED", "HIGH_RISK"]


def is_benign_verdict(verdict: str) -> bool:
    """Check if verdict indicates benign."""
    return normalize_verdict(verdict) == "SAFE"


def binary_verdict(verdict: str) -> str:
    """Convert to binary ATTACK/SAFE."""
    return "ATTACK" if is_attack_verdict(verdict) else "SAFE"