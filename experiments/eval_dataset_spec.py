"""
Eval Dataset Specification - Controlled Vocabularies & Validation
Single source of truth for all controlled fields in the benchmark.
"""

from enum import Enum
from typing import Dict, List, Set
from dataclasses import dataclass
from pathlib import Path
import csv
import hashlib


# ============================================================================
# CONTROLLED VOCABULARIES (enums - single source of truth)
# ============================================================================

class Verdict(str, Enum):
    BLOCKED = "BLOCKED"
    HIGH_RISK = "HIGH_RISK"
    MEDIUM_RISK = "MEDIUM_RISK"
    SAFE = "SAFE"

    @property
    def is_attack(self) -> bool:
        return self in (Verdict.BLOCKED, Verdict.HIGH_RISK, Verdict.MEDIUM_RISK)

    @property
    def binary_label(self) -> str:
        return "ATTACK" if self.is_attack else "SAFE"


class Category(str, Enum):
    ATTACK = "attack"
    BENIGN = "benign"


class AttackFamily(str, Enum):
    # Pillar 1: Prompt Injection
    DIRECT_INJECTION = "direct_injection"
    INDIRECT_INJECTION = "indirect_injection"
    TOOL_INJECTION = "tool_injection"
    MANY_SHOT_PRIMING = "many_shot_priming"
    
    # Pillar 2: Jailbreaking
    ROLEPLAY_JAILBREAK = "roleplay_jailbreak"
    HYPOTHETICAL_ACADEMIC = "hypothetical_academic"
    CROSS_LINGUAL_JAILBREAK = "cross_lingual_jailbreak"
    
    # Pillar 3: DLP / Exfiltration
    SYSTEM_DISCLOSURE = "system_disclosure"
    TRAINING_DATA_EXFIL = "training_data_exfil"
    CREDENTIAL_PII_HARVEST = "credential_pii_harvest"
    ENCODING_OBFUSCATION = "encoding_obfuscation"


class BenignFamily(str, Enum):
    BENIGN_CODE_SQL = "benign_code_sql"
    BENIGN_SECURITY_OPS = "benign_security_ops"
    BENIGN_BUSINESS_WORKFLOWS = "benign_business_workflows"
    BENIGN_TOOL_INVOCATIONS = "benign_tool_invocations"


class Source(str, Enum):
    # Adversarial
    MITRE_ATLAS = "mitre_atlas"
    JAILBREAK_BENCH = "jailbreakbench"
    GARAK_REDTEAM = "garak_redteam"
    BIPIA = "bipia"
    HARM_BENCH = "harm_bench"
    WILD_JAILBREAK = "wild_jailbreak"
    AGENT_SLICE = "agent_slice"
    
    # Benign
    DBT_HUB = "dbt_hub"
    APACHE_SUPERSET = "apache_superset"
    AWS_WELL_ARCHITECTED = "aws_well_architected"
    TERRAFORM_AWS = "terraform_aws"
    KUBERNETES_MANIFESTS = "kubernetes_manifests"
    SEC_EDGAR = "sec_edgar"
    LANGCHAIN_TOOLS = "langchain_tools"
    LOOKER_METABASE = "looker_metabase"
    
    # Synthetic (vetted)
    SYNTHETIC_VETTED = "synthetic_vetted"


# All families combined
ALL_ATTACK_FAMILIES = [f.value for f in AttackFamily]
ALL_BENIGN_FAMILIES = [f.value for f in BenignFamily]
ALL_FAMILIES = ALL_ATTACK_FAMILIES + ALL_BENIGN_FAMILIES

# Mapping from family to pillar (for reporting)
FAMILY_TO_PILLAR = {
    **{f.value: "prompt_injection" for f in [AttackFamily.DIRECT_INJECTION, AttackFamily.INDIRECT_INJECTION, AttackFamily.TOOL_INJECTION, AttackFamily.MANY_SHOT_PRIMING]},
    **{f.value: "jailbreaking" for f in [AttackFamily.ROLEPLAY_JAILBREAK, AttackFamily.HYPOTHETICAL_ACADEMIC, AttackFamily.CROSS_LINGUAL_JAILBREAK]},
    **{f.value: "dlp_exfiltration" for f in [AttackFamily.SYSTEM_DISCLOSURE, AttackFamily.TRAINING_DATA_EXFIL, AttackFamily.CREDENTIAL_PII_HARVEST, AttackFamily.ENCODING_OBFUSCATION]},
    **{f.value: "benign_controls" for f in BenignFamily},
}

# Golden allocation targets (from spec)
GOLDEN_ALLOCATION = {
    # Benign (500 total)
    BenignFamily.BENIGN_CODE_SQL.value: 150,
    BenignFamily.BENIGN_SECURITY_OPS.value: 125,
    BenignFamily.BENIGN_BUSINESS_WORKFLOWS.value: 125,
    BenignFamily.BENIGN_TOOL_INVOCATIONS.value: 100,
    # Attack (500 total)
    AttackFamily.DIRECT_INJECTION.value: 60,
    AttackFamily.INDIRECT_INJECTION.value: 60,
    AttackFamily.TOOL_INJECTION.value: 50,
    AttackFamily.MANY_SHOT_PRIMING.value: 35,
    AttackFamily.ROLEPLAY_JAILBREAK.value: 60,
    AttackFamily.HYPOTHETICAL_ACADEMIC.value: 40,
    AttackFamily.CROSS_LINGUAL_JAILBREAK.value: 45,
    AttackFamily.SYSTEM_DISCLOSURE.value: 50,
    AttackFamily.TRAINING_DATA_EXFIL.value: 40,
    AttackFamily.CREDENTIAL_PII_HARVEST.value: 30,
    AttackFamily.ENCODING_OBFUSCATION.value: 30,
}

DEV_ALLOCATION = {k: v // 2 for k, v in GOLDEN_ALLOCATION.items()}  # Half for dev

# Verify totals
assert sum(GOLDEN_ALLOCATION[f] for f in BenignFamily) == 500
assert sum(GOLDEN_ALLOCATION[f] for f in AttackFamily) == 500
assert sum(GOLDEN_ALLOCATION.values()) == 1000


# ============================================================================
# SCHEMA & VALIDATION
# ============================================================================

REQUIRED_COLUMNS = ["id", "prompt", "expected", "category", "family", "source"]
CSV_SCHEMA = {
    "id": str,
    "prompt": str,
    "expected": str,
    "category": str,
    "family": str,
    "source": str,
}

VALID_VERDICTS = {v.value for v in Verdict}
VALID_CATEGORIES = {c.value for c in Category}
VALID_FAMILIES = set(ALL_FAMILIES)
VALID_SOURCES = {s.value for s in Source}

# Expected verdict per family
FAMILY_DEFAULT_VERDICT = {
    **{f.value: Verdict.SAFE.value for f in BenignFamily},
    **{f.value: Verdict.BLOCKED.value for f in [
        AttackFamily.DIRECT_INJECTION, AttackFamily.INDIRECT_INJECTION,
        AttackFamily.TOOL_INJECTION, AttackFamily.MANY_SHOT_PRIMING,
        AttackFamily.ROLEPLAY_JAILBREAK, AttackFamily.HYPOTHETICAL_ACADEMIC,
        AttackFamily.CROSS_LINGUAL_JAILBREAK, AttackFamily.SYSTEM_DISCLOSURE,
        AttackFamily.TRAINING_DATA_EXFIL, AttackFamily.CREDENTIAL_PII_HARVEST,
        AttackFamily.ENCODING_OBFUSCATION,
    ]},
}


@dataclass
class EvalCase:
    """Single evaluation case with full validation."""
    id: str
    prompt: str
    expected: str  # Verdict value
    category: str  # Category value
    family: str    # Family value
    source: str    # Source value
    
    def __post_init__(self):
        self.validate()
    
    def validate(self):
        errors = []
        
        # ID format
        if not self.id:
            errors.append("id is required")
        elif not (self.id.startswith("gt_") or self.id.startswith("dev_")):
            errors.append(f"id must start with 'gt_' or 'dev_': {self.id}")
        
        # Prompt
        if not self.prompt or not self.prompt.strip():
            errors.append("prompt is required and non-empty")
        elif len(self.prompt) > 10000:
            errors.append(f"prompt too long ({len(self.prompt)} chars, max 10000)")
        
        # Expected verdict
        if self.expected not in VALID_VERDICTS:
            errors.append(f"invalid expected verdict: {self.expected} (valid: {VALID_VERDICTS})")
        
        # Category
        if self.category not in VALID_CATEGORIES:
            errors.append(f"invalid category: {self.category} (valid: {VALID_CATEGORIES})")
        
        # Family
        if self.family not in VALID_FAMILIES:
            errors.append(f"invalid family: {self.family} (valid: {VALID_FAMILIES})")
        
        # Category/Family consistency
        if self.category == Category.BENIGN.value and self.family not in ALL_BENIGN_FAMILIES:
            errors.append(f"benign category requires benign family, got: {self.family}")
        if self.category == Category.ATTACK.value and self.family not in ALL_ATTACK_FAMILIES:
            errors.append(f"attack category requires attack family, got: {self.family}")
        
        # Source
        if self.source not in VALID_SOURCES:
            errors.append(f"invalid source: {self.source} (valid: {VALID_SOURCES})")
        
        # Verdict/Family consistency
        expected_attack = self.expected in (Verdict.BLOCKED.value, Verdict.HIGH_RISK.value, Verdict.MEDIUM_RISK.value)
        family_is_attack = self.family in ALL_ATTACK_FAMILIES
        if expected_attack != family_is_attack:
            errors.append(f"verdict/family mismatch: expected={self.expected} (attack={expected_attack}) vs family={self.family} (attack={family_is_attack})")
        
        if errors:
            raise ValueError(f"Validation failed for {self.id}: {'; '.join(errors)}")
    
    def to_row(self) -> List[str]:
        return [self.id, self.prompt, self.expected, self.category, self.family, self.source]
    
    @property
    def sha256(self) -> str:
        """Deterministic hash for deduplication."""
        content = f"{self.source}:{self.prompt.strip()}"
        return hashlib.sha256(content.encode("utf-8")).hexdigest()


# ============================================================================
# CSV I/O
# ============================================================================

def write_csv(cases: List[EvalCase], path: Path) -> None:
    """Write cases to CSV with strict column ordering."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(REQUIRED_COLUMNS)
        for case in cases:
            writer.writerow(case.to_row())

def read_csv(path: Path) -> List[EvalCase]:
    """Read and validate cases from CSV."""
    cases = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames != REQUIRED_COLUMNS:
            raise ValueError(f"Invalid CSV columns: {reader.fieldnames} (expected: {REQUIRED_COLUMNS})")
        for row in reader:
            cases.append(EvalCase(**row))
    return cases


def get_allocation(family: str, split: str = "golden") -> int:
    """Get target count for a family in a split."""
    alloc = GOLDEN_ALLOCATION if split == "golden" else DEV_ALLOCATION
    return alloc.get(family, 0)