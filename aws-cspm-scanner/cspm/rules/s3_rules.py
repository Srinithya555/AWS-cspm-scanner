"""
S3 checks on normalized bucket data:

    buckets: [
        {
            "name": str,
            "block_public_acls": bool,
            "block_public_policy": bool,
            "ignore_public_acls": bool,
            "restrict_public_buckets": bool,
            "acl_grants_all_users": bool,          # ACL grants to "AllUsers" group
            "acl_grants_authenticated_users": bool, # ACL grants to "AuthenticatedUsers" group
            "default_encryption_enabled": bool,
            "versioning_enabled": bool,
            "access_logging_enabled": bool,
        },
        ...
    ]
"""
from cspm.models import Finding, Severity


def check_public_via_acl(buckets: list) -> list:
    findings = []
    for b in buckets:
        if b.get("acl_grants_all_users"):
            findings.append(Finding(
                resource_type="s3_bucket", resource_id=b["name"], rule_id="S3-001",
                severity=Severity.CRITICAL,
                title="Bucket ACL grants access to 'AllUsers' (fully public)",
                description=f"Bucket '{b['name']}' has an ACL grant to the AllUsers group, "
                             "making it readable/writable (depending on the grant) by anyone "
                             "on the internet, unauthenticated.",
                remediation="Remove the public ACL grant. Enable S3 Block Public Access at the bucket and account level.",
                cis_reference="CIS AWS Foundations Benchmark 2.1-equivalent (verify version)",
            ))
        if b.get("acl_grants_authenticated_users"):
            findings.append(Finding(
                resource_type="s3_bucket", resource_id=b["name"], rule_id="S3-002",
                severity=Severity.HIGH,
                title="Bucket ACL grants access to 'AuthenticatedUsers' (any AWS account)",
                description=f"Bucket '{b['name']}' grants access to the AuthenticatedUsers "
                             "group — this is NOT limited to your organization, it means any "
                             "AWS account, anywhere, which is a common and dangerous "
                             "misunderstanding of this ACL group's scope.",
                remediation="Remove the grant; use bucket policies scoped to specific principals instead of ACL groups.",
                cis_reference="CIS AWS Foundations Benchmark 2.1-equivalent (verify version)",
            ))
    return findings


def check_block_public_access_disabled(buckets: list) -> list:
    findings = []
    for b in buckets:
        disabled_settings = [
            name for name in (
                "block_public_acls", "block_public_policy",
                "ignore_public_acls", "restrict_public_buckets",
            ) if not b.get(name, False)
        ]
        if disabled_settings:
            findings.append(Finding(
                resource_type="s3_bucket", resource_id=b["name"], rule_id="S3-003",
                severity=Severity.HIGH,
                title="S3 Block Public Access not fully enabled",
                description=f"Bucket '{b['name']}' has these Block Public Access settings "
                             f"disabled: {disabled_settings}. This is the primary safety net "
                             "against accidental public exposure.",
                remediation="Enable all four Block Public Access settings unless the bucket "
                             "is intentionally serving public content (e.g. static website "
                             "hosting), in which case document the exception explicitly.",
                cis_reference="CIS AWS Foundations Benchmark 2.1.5-equivalent (verify version)",
            ))
    return findings


def check_default_encryption(buckets: list) -> list:
    findings = []
    for b in buckets:
        if not b.get("default_encryption_enabled"):
            findings.append(Finding(
                resource_type="s3_bucket", resource_id=b["name"], rule_id="S3-004",
                severity=Severity.MEDIUM,
                title="Default encryption not enabled",
                description=f"Bucket '{b['name']}' has no default server-side encryption "
                             "configured. Objects uploaded without an explicit encryption "
                             "header are stored unencrypted at rest.",
                remediation="Enable default encryption (SSE-S3 or SSE-KMS) at the bucket level.",
                cis_reference="CIS AWS Foundations Benchmark 2.1.1-equivalent (verify version)",
            ))
    return findings


def check_versioning(buckets: list) -> list:
    findings = []
    for b in buckets:
        if not b.get("versioning_enabled"):
            findings.append(Finding(
                resource_type="s3_bucket", resource_id=b["name"], rule_id="S3-005",
                severity=Severity.LOW,
                title="Versioning not enabled",
                description=f"Bucket '{b['name']}' does not have versioning enabled, so "
                             "accidental deletes/overwrites (or a ransomware-style mass "
                             "encryption of objects) cannot be recovered from.",
                remediation="Enable versioning; pair with MFA Delete for high-value buckets.",
                cis_reference="Not a standalone CIS control in most versions — general AWS best practice",
            ))
    return findings


def check_access_logging(buckets: list) -> list:
    findings = []
    for b in buckets:
        if not b.get("access_logging_enabled"):
            findings.append(Finding(
                resource_type="s3_bucket", resource_id=b["name"], rule_id="S3-006",
                severity=Severity.LOW,
                title="Access logging not enabled",
                description=f"Bucket '{b['name']}' has no access logging configured. "
                             "During an incident, there is no record of who accessed which "
                             "objects and when.",
                remediation="Enable S3 server access logging or CloudTrail data events for this bucket.",
                cis_reference="Not a standalone CIS control in most versions — general AWS best practice",
            ))
    return findings


ALL_S3_RULES = [
    check_public_via_acl,
    check_block_public_access_disabled,
    check_default_encryption,
    check_versioning,
    check_access_logging,
]


def run_s3_rules(buckets: list) -> list:
    findings = []
    for rule in ALL_S3_RULES:
        findings.extend(rule(buckets))
    return findings
