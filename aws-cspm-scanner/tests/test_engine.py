import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cspm.engine import run_scan, compute_risk_score, group_by_severity
from cspm.models import Severity

FIXTURE_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "fixtures", "sample_account.json")


class TestRunScan:
    def test_scan_against_sample_fixture_produces_expected_finding_count(self):
        with open(FIXTURE_PATH) as f:
            data = json.load(f)
        findings = run_scan(data)
        # This number should only change if the fixture or rules change —
        # pinning it catches accidental regressions in either.
        assert len(findings) == 25

    def test_empty_account_data_produces_no_findings(self):
        findings = run_scan({})
        assert findings == []

    def test_clean_resources_produce_no_findings(self):
        clean_data = {
            "iam_policies": [{"policy_name": "p1", "attached_to": [], "statements": [
                {"effect": "Allow", "action": ["s3:GetObject"], "resource": ["arn:aws:s3:::b/*"]}
            ]}],
            "iam_users": [{"username": "alice", "is_root": False, "has_console_password": True,
                           "mfa_enabled": True, "access_keys": [{"key_id": "k1", "age_days": 5, "last_used_days_ago": 1}]}],
            "s3_buckets": [{"name": "b1", "block_public_acls": True, "block_public_policy": True,
                            "ignore_public_acls": True, "restrict_public_buckets": True,
                            "acl_grants_all_users": False, "acl_grants_authenticated_users": False,
                            "default_encryption_enabled": True, "versioning_enabled": True,
                            "access_logging_enabled": True}],
            "security_groups": [{"group_id": "sg1", "group_name": "g", "ip_permissions": [
                {"ip_protocol": "tcp", "from_port": 443, "to_port": 443, "cidr_ranges": ["10.0.0.0/16"], "ipv6_cidr_ranges": []}
            ]}],
        }
        assert run_scan(clean_data) == []


class TestRiskScore:
    def test_score_caps_at_100(self):
        from cspm.models import Finding
        findings = [Finding("x", "x", "X-1", Severity.CRITICAL, "t", "d", "r") for _ in range(10)]
        assert compute_risk_score(findings) == 100

    def test_score_zero_for_no_findings(self):
        assert compute_risk_score([]) == 0

    def test_score_sums_severities(self):
        from cspm.models import Finding
        findings = [
            Finding("x", "x", "X-1", Severity.HIGH, "t", "d", "r"),   # 20
            Finding("x", "x", "X-2", Severity.MEDIUM, "t", "d", "r"), # 10
        ]
        assert compute_risk_score(findings) == 30


class TestGrouping:
    def test_group_by_severity_buckets_correctly(self):
        from cspm.models import Finding
        findings = [
            Finding("x", "x", "X-1", Severity.CRITICAL, "t", "d", "r"),
            Finding("x", "x", "X-2", Severity.LOW, "t", "d", "r"),
        ]
        groups = group_by_severity(findings)
        assert len(groups[Severity.CRITICAL]) == 1
        assert len(groups[Severity.LOW]) == 1
        assert len(groups[Severity.HIGH]) == 0
