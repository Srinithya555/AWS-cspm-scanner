import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cspm.rules.s3_rules import (
    check_public_via_acl, check_block_public_access_disabled,
    check_default_encryption, check_versioning, check_access_logging,
)
from cspm.models import Severity


def _bucket(**overrides):
    base = {
        "name": "test-bucket",
        "block_public_acls": True, "block_public_policy": True,
        "ignore_public_acls": True, "restrict_public_buckets": True,
        "acl_grants_all_users": False, "acl_grants_authenticated_users": False,
        "default_encryption_enabled": True, "versioning_enabled": True,
        "access_logging_enabled": True,
    }
    base.update(overrides)
    return base


class TestPublicViaACL:
    def test_flags_all_users_grant(self):
        findings = check_public_via_acl([_bucket(acl_grants_all_users=True)])
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_flags_authenticated_users_grant(self):
        findings = check_public_via_acl([_bucket(acl_grants_authenticated_users=True)])
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_clean_bucket_not_flagged(self):
        assert check_public_via_acl([_bucket()]) == []


class TestBlockPublicAccess:
    def test_flags_any_disabled_setting(self):
        findings = check_block_public_access_disabled([_bucket(block_public_acls=False)])
        assert len(findings) == 1

    def test_all_enabled_not_flagged(self):
        assert check_block_public_access_disabled([_bucket()]) == []

    def test_all_disabled_still_one_finding_per_bucket(self):
        """One finding per bucket even if all 4 settings are off, not 4 findings."""
        findings = check_block_public_access_disabled([_bucket(
            block_public_acls=False, block_public_policy=False,
            ignore_public_acls=False, restrict_public_buckets=False,
        )])
        assert len(findings) == 1


class TestEncryption:
    def test_flags_no_encryption(self):
        findings = check_default_encryption([_bucket(default_encryption_enabled=False)])
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_encrypted_not_flagged(self):
        assert check_default_encryption([_bucket()]) == []


class TestVersioning:
    def test_flags_no_versioning(self):
        findings = check_versioning([_bucket(versioning_enabled=False)])
        assert len(findings) == 1

    def test_versioned_not_flagged(self):
        assert check_versioning([_bucket()]) == []


class TestLogging:
    def test_flags_no_logging(self):
        findings = check_access_logging([_bucket(access_logging_enabled=False)])
        assert len(findings) == 1

    def test_logged_not_flagged(self):
        assert check_access_logging([_bucket()]) == []
