"""
Generates human-readable and JSON reports from scan findings.
"""
import json
from cspm.engine import compute_risk_score, group_by_severity
from cspm.models import Severity

SEVERITY_COLOR = {
    Severity.CRITICAL: "\033[91m",
    Severity.HIGH: "\033[91m",
    Severity.MEDIUM: "\033[93m",
    Severity.LOW: "\033[94m",
    Severity.INFO: "\033[90m",
}
RESET = "\033[0m"


def print_text_report(findings: list) -> None:
    score = compute_risk_score(findings)
    groups = group_by_severity(findings)

    print("=" * 72)
    print("AWS CLOUD SECURITY POSTURE REPORT")
    print("=" * 72)
    print(f"\nRisk score: {score}/100  ({len(findings)} findings)\n")

    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        items = groups.get(sev, [])
        if not items:
            continue
        color = SEVERITY_COLOR.get(sev, "")
        print(f"{color}--- {sev.name} ({len(items)}) ---{RESET}")
        for f in items:
            print(f"  [{f.rule_id}] {f.resource_type}:{f.resource_id} — {f.title}")
            print(f"      {f.description}")
            print(f"      Fix: {f.remediation}")
            if f.cis_reference:
                print(f"      Reference: {f.cis_reference}")
            print()


def to_json_report(findings: list) -> str:
    score = compute_risk_score(findings)
    payload = {
        "risk_score": score,
        "finding_count": len(findings),
        "findings": [
            {
                "rule_id": f.rule_id,
                "resource_type": f.resource_type,
                "resource_id": f.resource_id,
                "severity": f.severity.name,
                "title": f.title,
                "description": f.description,
                "remediation": f.remediation,
                "cis_reference": f.cis_reference,
            }
            for f in findings
        ],
    }
    return json.dumps(payload, indent=2)
