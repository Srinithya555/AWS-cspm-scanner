"""
Normalized finding model, shared across all rule modules regardless of
which AWS service they audit. Keeping this one shape means the report
generator, the risk scorer, and any future export format (JSON, SARIF,
a ticketing-system integration) only need to know about ONE structure.
"""
from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    CRITICAL = 40
    HIGH = 20
    MEDIUM = 10
    LOW = 5
    INFO = 1


@dataclass
class Finding:
    resource_type: str      # "iam_policy" | "iam_user" | "s3_bucket" | "security_group"
    resource_id: str
    rule_id: str
    severity: Severity
    title: str
    description: str
    remediation: str
    cis_reference: str = ""  # e.g. "CIS AWS Foundations Benchmark 5.2 (verify against current version)"
