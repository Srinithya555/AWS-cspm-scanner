"""
IAM checks operating on NORMALIZED data (see cspm/collectors.py for how raw
boto3 responses get turned into this shape). Rules never touch boto3 or
AWS directly — this separation means every rule here is testable with
plain Python dicts, no AWS credentials or mocking framework required.

Expected input shapes:

    policies: [
        {
            "policy_name": str,
            "attached_to": [str, ...],   # user/role/group names or ARNs
            "statements": [
                {"effect": "Allow"|"Deny", "action": [str,...] or "*", "resource": [str,...] or "*"}
            ],
        },
        ...
    ]

    users: [
        {
            "username": str,
            "is_root": bool,
            "has_console_password": bool,
            "mfa_enabled": bool,
            "access_keys": [{"key_id": str, "age_days": int, "last_used_days_ago": int|None}],
        },
        ...
    ]

NOTE ON CIS REFERENCES: control numbers cited below correspond to the
general CIS AWS Foundations Benchmark structure, but CIS revises section
numbering across benchmark versions (1.2, 1.3, 1.4, 1.5...). Verify the
exact control ID against whichever version you're mapping to before citing
it in a compliance report — the SECURITY REASONING here is what matters
and is version-independent; the section number is a convenience pointer,
not a guarantee.
"""
from cspm.models import Finding, Severity


def check_full_admin_policy(policies: list) -> list:
    findings = []
    for p in policies:
        for stmt in p.get("statements", []):
            if stmt.get("effect") != "Allow":
                continue
            action = stmt.get("action")
            resource = stmt.get("resource")
            action_is_wildcard = action == "*" or (isinstance(action, list) and "*" in action)
            resource_is_wildcard = resource == "*" or (isinstance(resource, list) and "*" in resource)
            if action_is_wildcard and resource_is_wildcard:
                findings.append(Finding(
                    resource_type="iam_policy",
                    resource_id=p["policy_name"],
                    rule_id="IAM-001",
                    severity=Severity.CRITICAL,
                    title="Policy grants full administrative access (Action:* Resource:*)",
                    description=(
                        f"Policy '{p['policy_name']}' attached to {p.get('attached_to', [])} "
                        "allows every action on every resource. Anyone/anything holding this "
                        "policy has unrestricted account access."
                    ),
                    remediation=(
                        "Scope the policy to specific actions and resource ARNs following "
                        "least privilege. Use IAM Access Analyzer to identify the minimum "
                        "permissions actually used before narrowing."
                    ),
                    cis_reference="CIS AWS Foundations Benchmark 1.16-equivalent (verify version)",
                ))
    return findings


def check_wildcard_action_scoped_resource(policies: list) -> list:
    """Action:* but resource is scoped — still risky, lower severity than full admin."""
    findings = []
    for p in policies:
        for stmt in p.get("statements", []):
            if stmt.get("effect") != "Allow":
                continue
            action = stmt.get("action")
            resource = stmt.get("resource")
            action_is_wildcard = action == "*" or (isinstance(action, list) and "*" in action)
            resource_is_wildcard = resource == "*" or (isinstance(resource, list) and "*" in resource)
            if action_is_wildcard and not resource_is_wildcard:
                findings.append(Finding(
                    resource_type="iam_policy",
                    resource_id=p["policy_name"],
                    rule_id="IAM-002",
                    severity=Severity.HIGH,
                    title="Policy grants wildcard actions on a scoped resource",
                    description=(
                        f"Policy '{p['policy_name']}' allows ALL actions against resource(s) "
                        f"{resource}. Even scoped to specific resources, unrestricted actions "
                        "(including delete/modify permissions APIs on that resource) exceed "
                        "what most roles genuinely need."
                    ),
                    remediation="Enumerate the specific actions actually required and list them explicitly.",
                    cis_reference="CIS AWS Foundations Benchmark 1.16-equivalent (verify version)",
                ))
    return findings


def check_root_account_access_keys(users: list) -> list:
    findings = []
    for u in users:
        if u.get("is_root") and u.get("access_keys"):
            findings.append(Finding(
                resource_type="iam_user",
                resource_id="root",
                rule_id="IAM-003",
                severity=Severity.CRITICAL,
                title="Root account has active access keys",
                description=(
                    "The AWS account root user has programmatic access keys. Root should "
                    "never have access keys — root has unrestricted, non-scopeable "
                    "permissions and cannot be constrained by any IAM policy."
                ),
                remediation="Delete root access keys immediately. Use IAM roles/users for all programmatic access.",
                cis_reference="CIS AWS Foundations Benchmark 1.4-equivalent (verify version)",
            ))
    return findings


def check_console_user_without_mfa(users: list) -> list:
    findings = []
    for u in users:
        if u.get("has_console_password") and not u.get("mfa_enabled") and not u.get("is_root"):
            findings.append(Finding(
                resource_type="iam_user",
                resource_id=u["username"],
                rule_id="IAM-004",
                severity=Severity.HIGH,
                title="Console user has no MFA enabled",
                description=(
                    f"User '{u['username']}' can sign in to the console with just a "
                    "password. Without MFA, a leaked/phished password is immediately "
                    "sufficient for account takeover."
                ),
                remediation="Enforce MFA via IAM policy condition (aws:MultiFactorAuthPresent) and require enrollment.",
                cis_reference="CIS AWS Foundations Benchmark 1.10-equivalent (verify version)",
            ))
    return findings


def check_stale_access_keys(users: list, max_age_days: int = 90) -> list:
    findings = []
    for u in users:
        for key in u.get("access_keys", []):
            if key.get("age_days", 0) > max_age_days:
                findings.append(Finding(
                    resource_type="iam_user",
                    resource_id=u["username"],
                    rule_id="IAM-005",
                    severity=Severity.MEDIUM,
                    title=f"Access key older than {max_age_days} days",
                    description=(
                        f"User '{u['username']}' has access key '{key['key_id']}' that is "
                        f"{key['age_days']} days old. Long-lived credentials increase the "
                        "window of exposure if ever leaked."
                    ),
                    remediation="Rotate access keys regularly; prefer IAM roles with temporary credentials over long-lived keys where possible.",
                    cis_reference="CIS AWS Foundations Benchmark 1.14-equivalent (verify version)",
                ))
    return findings


def check_unused_access_keys(users: list, unused_threshold_days: int = 90) -> list:
    findings = []
    for u in users:
        for key in u.get("access_keys", []):
            last_used = key.get("last_used_days_ago")
            if last_used is not None and last_used > unused_threshold_days:
                findings.append(Finding(
                    resource_type="iam_user",
                    resource_id=u["username"],
                    rule_id="IAM-006",
                    severity=Severity.LOW,
                    title=f"Access key unused for {last_used} days",
                    description=(
                        f"User '{u['username']}' has an access key not used in "
                        f"{last_used} days. Unused credentials should be deactivated — "
                        "they provide no value and only add attack surface."
                    ),
                    remediation="Deactivate or delete access keys with no recent usage.",
                    cis_reference="CIS AWS Foundations Benchmark 1.13-equivalent (verify version)",
                ))
    return findings


ALL_IAM_RULES = [
    check_full_admin_policy,
    check_wildcard_action_scoped_resource,
    check_root_account_access_keys,
    check_console_user_without_mfa,
    check_stale_access_keys,
    check_unused_access_keys,
]


def run_iam_rules(policies: list, users: list) -> list:
    findings = []
    for rule in ALL_IAM_RULES:
        if rule in (check_root_account_access_keys, check_console_user_without_mfa,
                    check_stale_access_keys, check_unused_access_keys):
            findings.extend(rule(users))
        else:
            findings.extend(rule(policies))
    return findings
