"""
Orchestrates all rule modules against normalized account data and computes
an aggregate risk score. This module has ZERO AWS SDK dependency — it only
knows about the normalized shapes documented in each rules/*.py module,
which is what makes it fully unit-testable without boto3 or any AWS
credentials (see tests/test_engine.py and the offline demo).
"""
from cspm.rules.iam_rules import run_iam_rules
from cspm.rules.s3_rules import run_s3_rules
from cspm.rules.sg_rules import run_sg_rules
from cspm.models import Severity


def run_scan(account_data: dict) -> list:
    """
    account_data shape:
        {
            "iam_policies": [...],
            "iam_users": [...],
            "s3_buckets": [...],
            "security_groups": [...],
        }
    Any key can be omitted/empty if that resource type wasn't collected.
    """
    findings = []
    findings.extend(run_iam_rules(
        account_data.get("iam_policies", []),
        account_data.get("iam_users", []),
    ))
    findings.extend(run_s3_rules(account_data.get("s3_buckets", [])))
    findings.extend(run_sg_rules(account_data.get("security_groups", [])))
    return findings


def compute_risk_score(findings: list, cap: int = 100) -> int:
    """
    Simple weighted-sum risk score, capped at 100. This is intentionally
    simple (not a substitute for a real risk model that would weight by
    asset criticality, exposure, compensating controls, etc.) — it's meant
    to give a quick at-a-glance signal and a trend line over time (is this
    account's score going up or down scan over scan), not a precise
    probability of compromise.
    """
    raw = sum(f.severity.value for f in findings)
    return min(raw, cap)


def group_by_severity(findings: list) -> dict:
    groups = {s: [] for s in Severity}
    for f in findings:
        groups[f.severity].append(f)
    return groups


def group_by_resource(findings: list) -> dict:
    groups = {}
    for f in findings:
        key = f"{f.resource_type}:{f.resource_id}"
        groups.setdefault(key, []).append(f)
    return groups
