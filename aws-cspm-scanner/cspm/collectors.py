"""
Fetches raw data from AWS via boto3 and normalizes it into the plain-dict
shapes documented in each cspm/rules/*.py module. This is the ONLY module
in this project that touches boto3/AWS directly — every rule and the
engine itself only ever see normalized dicts, which is why they're testable
without any AWS credentials (see the offline demo and test suite).

Requires AWS credentials configured (env vars, ~/.aws/credentials, or an
IAM role if run from EC2/Lambda) with at least these read-only permissions:
    iam:ListPolicies, iam:GetPolicyVersion, iam:ListUsers,
    iam:ListMFADevices, iam:ListAccessKeys, iam:GetAccessKeyLastUsed,
    iam:ListLoginProfiles
    s3:ListAllMyBuckets, s3:GetBucketAcl, s3:GetBucketPolicyStatus,
    s3:GetPublicAccessBlock, s3:GetEncryptionConfiguration,
    s3:GetBucketVersioning, s3:GetBucketLogging
    ec2:DescribeSecurityGroups

IMPORTANT: this module was written against the boto3 API but could not be
executed in the environment this project was built in (no network access
to install boto3 or call real AWS APIs). Treat this as reviewed-carefully-
but-unverified code — run it against a real (ideally sandbox/non-prod) AWS
account and fix whatever boto3 quirks surface before relying on it. The
rules and engine (the actual security logic) ARE fully tested — see
tests/ and fixtures/ — this collector module is comparatively the least
proven part of the project, and the README says so explicitly.
"""
import boto3
from datetime import datetime, timezone


def collect_iam_policies(iam_client=None) -> list:
    iam = iam_client or boto3.client("iam")
    normalized = []

    paginator = iam.get_paginator("list_policies")
    for page in paginator.paginate(Scope="Local"):  # customer-managed only; add "AWS" for managed too
        for policy in page["Policies"]:
            version = iam.get_policy_version(
                PolicyArn=policy["Arn"], VersionId=policy["DefaultVersionId"]
            )
            doc = version["PolicyVersion"]["Document"]
            statements = doc["Statement"] if isinstance(doc["Statement"], list) else [doc["Statement"]]

            entities = iam.list_entities_for_policy(PolicyArn=policy["Arn"])
            attached_to = (
                [u["UserName"] for u in entities.get("PolicyUsers", [])]
                + [r["RoleName"] for r in entities.get("PolicyRoles", [])]
                + [g["GroupName"] for g in entities.get("PolicyGroups", [])]
            )

            normalized.append({
                "policy_name": policy["PolicyName"],
                "attached_to": attached_to,
                "statements": [
                    {
                        "effect": s.get("Effect"),
                        "action": s.get("Action"),
                        "resource": s.get("Resource"),
                    }
                    for s in statements
                ],
            })
    return normalized


def collect_iam_users(iam_client=None) -> list:
    iam = iam_client or boto3.client("iam")
    normalized = []
    now = datetime.now(timezone.utc)

    for user in iam.list_users()["Users"]:
        username = user["UserName"]

        try:
            iam.get_login_profile(UserName=username)
            has_console_password = True
        except iam.exceptions.NoSuchEntityException:
            has_console_password = False

        mfa_devices = iam.list_mfa_devices(UserName=username)["MFADevices"]

        access_keys = []
        for key in iam.list_access_keys(UserName=username)["AccessKeyMetadata"]:
            age_days = (now - key["CreateDate"]).days
            last_used_info = iam.get_access_key_last_used(AccessKeyId=key["AccessKeyId"])
            last_used_date = last_used_info.get("AccessKeyLastUsed", {}).get("LastUsedDate")
            last_used_days_ago = (now - last_used_date).days if last_used_date else None
            access_keys.append({
                "key_id": key["AccessKeyId"],
                "age_days": age_days,
                "last_used_days_ago": last_used_days_ago,
            })

        normalized.append({
            "username": username,
            "is_root": False,  # root is handled separately; ListUsers never returns root
            "has_console_password": has_console_password,
            "mfa_enabled": len(mfa_devices) > 0,
            "access_keys": access_keys,
        })
    return normalized


def collect_s3_buckets(s3_client=None) -> list:
    s3 = s3_client or boto3.client("s3")
    normalized = []

    for bucket in s3.list_buckets()["Buckets"]:
        name = bucket["Name"]

        acl = s3.get_bucket_acl(Bucket=name)
        acl_all_users = any(
            g["Grantee"].get("URI", "").endswith("global/AllUsers")
            for g in acl["Grants"]
        )
        acl_authenticated = any(
            g["Grantee"].get("URI", "").endswith("global/AuthenticatedUsers")
            for g in acl["Grants"]
        )

        from botocore.exceptions import ClientError
        try:
            pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "NoSuchPublicAccessBlockConfiguration":
                pab = {}
            else:
                raise

        try:
            s3.get_bucket_encryption(Bucket=name)
            encrypted = True
        except ClientError:
            encrypted = False

        versioning = s3.get_bucket_versioning(Bucket=name)
        versioning_enabled = versioning.get("Status") == "Enabled"

        logging_config = s3.get_bucket_logging(Bucket=name)
        logging_enabled = "LoggingEnabled" in logging_config

        normalized.append({
            "name": name,
            "block_public_acls": pab.get("BlockPublicAcls", False),
            "block_public_policy": pab.get("BlockPublicPolicy", False),
            "ignore_public_acls": pab.get("IgnorePublicAcls", False),
            "restrict_public_buckets": pab.get("RestrictPublicBuckets", False),
            "acl_grants_all_users": acl_all_users,
            "acl_grants_authenticated_users": acl_authenticated,
            "default_encryption_enabled": encrypted,
            "versioning_enabled": versioning_enabled,
            "access_logging_enabled": logging_enabled,
        })
    return normalized


def collect_security_groups(ec2_client=None) -> list:
    ec2 = ec2_client or boto3.client("ec2")
    normalized = []

    paginator = ec2.get_paginator("describe_security_groups")
    for page in paginator.paginate():
        for sg in page["SecurityGroups"]:
            perms = []
            for perm in sg.get("IpPermissions", []):
                perms.append({
                    "ip_protocol": perm.get("IpProtocol"),
                    "from_port": perm.get("FromPort"),
                    "to_port": perm.get("ToPort"),
                    "cidr_ranges": [r["CidrIp"] for r in perm.get("IpRanges", [])],
                    "ipv6_cidr_ranges": [r["CidrIpv6"] for r in perm.get("Ipv6Ranges", [])],
                })
            normalized.append({
                "group_id": sg["GroupId"],
                "group_name": sg.get("GroupName", ""),
                "ip_permissions": perms,
            })
    return normalized


def collect_all() -> dict:
    return {
        "iam_policies": collect_iam_policies(),
        "iam_users": collect_iam_users(),
        "s3_buckets": collect_s3_buckets(),
        "security_groups": collect_security_groups(),
    }
