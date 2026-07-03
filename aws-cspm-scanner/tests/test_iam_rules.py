import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cspm.rules.iam_rules import (
    check_full_admin_policy, check_wildcard_action_scoped_resource,
    check_root_account_access_keys, check_console_user_without_mfa,
    check_stale_access_keys, check_unused_access_keys,
)
from cspm.models import Severity


class TestFullAdminPolicy:
    def test_flags_wildcard_action_and_resource(self):
        policies = [{"policy_name": "p1", "attached_to": [], "statements": [
            {"effect": "Allow", "action": "*", "resource": "*"}
        ]}]
        findings = check_full_admin_policy(policies)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_does_not_flag_scoped_policy(self):
        policies = [{"policy_name": "p1", "attached_to": [], "statements": [
            {"effect": "Allow", "action": ["s3:GetObject"], "resource": ["arn:aws:s3:::b/*"]}
        ]}]
        assert check_full_admin_policy(policies) == []

    def test_ignores_deny_statements(self):
        policies = [{"policy_name": "p1", "attached_to": [], "statements": [
            {"effect": "Deny", "action": "*", "resource": "*"}
        ]}]
        assert check_full_admin_policy(policies) == []


class TestWildcardActionScopedResource:
    def test_flags_wildcard_action_scoped_resource(self):
        policies = [{"policy_name": "p1", "attached_to": [], "statements": [
            {"effect": "Allow", "action": "*", "resource": ["arn:aws:s3:::b/*"]}
        ]}]
        findings = check_wildcard_action_scoped_resource(policies)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_does_not_double_flag_full_wildcard(self):
        """Full admin (both wildcards) should be caught by IAM-001, not IAM-002."""
        policies = [{"policy_name": "p1", "attached_to": [], "statements": [
            {"effect": "Allow", "action": "*", "resource": "*"}
        ]}]
        assert check_wildcard_action_scoped_resource(policies) == []


class TestRootAccessKeys:
    def test_flags_root_with_keys(self):
        users = [{"username": "root", "is_root": True, "access_keys": [{"key_id": "k1"}]}]
        findings = check_root_account_access_keys(users)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_root_without_keys_not_flagged(self):
        users = [{"username": "root", "is_root": True, "access_keys": []}]
        assert check_root_account_access_keys(users) == []

    def test_non_root_with_keys_not_flagged_by_this_rule(self):
        users = [{"username": "alice", "is_root": False, "access_keys": [{"key_id": "k1"}]}]
        assert check_root_account_access_keys(users) == []


class TestConsoleUserWithoutMFA:
    def test_flags_console_user_no_mfa(self):
        users = [{"username": "bob", "is_root": False, "has_console_password": True, "mfa_enabled": False}]
        findings = check_console_user_without_mfa(users)
        assert len(findings) == 1

    def test_does_not_flag_user_with_mfa(self):
        users = [{"username": "alice", "is_root": False, "has_console_password": True, "mfa_enabled": True}]
        assert check_console_user_without_mfa(users) == []

    def test_does_not_flag_root_here(self):
        """Root is handled by a dedicated, more specific check (access keys), not this one."""
        users = [{"username": "root", "is_root": True, "has_console_password": True, "mfa_enabled": False}]
        assert check_console_user_without_mfa(users) == []

    def test_does_not_flag_programmatic_only_user(self):
        users = [{"username": "deploy-bot", "is_root": False, "has_console_password": False, "mfa_enabled": False}]
        assert check_console_user_without_mfa(users) == []


class TestStaleAccessKeys:
    def test_flags_key_older_than_threshold(self):
        users = [{"username": "u1", "access_keys": [{"key_id": "k1", "age_days": 120}]}]
        findings = check_stale_access_keys(users, max_age_days=90)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_does_not_flag_recent_key(self):
        users = [{"username": "u1", "access_keys": [{"key_id": "k1", "age_days": 10}]}]
        assert check_stale_access_keys(users, max_age_days=90) == []

    def test_boundary_exactly_at_threshold_not_flagged(self):
        """Strictly greater-than threshold, not >=."""
        users = [{"username": "u1", "access_keys": [{"key_id": "k1", "age_days": 90}]}]
        assert check_stale_access_keys(users, max_age_days=90) == []


class TestUnusedAccessKeys:
    def test_flags_unused_key(self):
        users = [{"username": "u1", "access_keys": [{"key_id": "k1", "last_used_days_ago": 200}]}]
        findings = check_unused_access_keys(users, unused_threshold_days=90)
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW

    def test_never_used_key_not_crashed_on_none(self):
        """last_used_days_ago=None means never used — must not crash, and current
        implementation intentionally does not flag it via THIS rule (a None last-used
        is arguably worse and could be a separate future rule)."""
        users = [{"username": "u1", "access_keys": [{"key_id": "k1", "last_used_days_ago": None}]}]
        assert check_unused_access_keys(users, unused_threshold_days=90) == []
