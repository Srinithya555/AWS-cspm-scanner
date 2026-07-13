# AWS Cloud Security Posture Scanner (mini-CSPM)

Scans an AWS account's IAM policies/users, S3 buckets, and EC2 security
groups for common misconfigurations, scores overall risk, and produces a
report mapped to CIS AWS Foundations Benchmark-style controls.



## Design rules - never touch AWS directly

The architecture deliberately separates **data collection** (boto3 calls,
in `cspm/collectors.py`) from **security logic** (`cspm/rules/*.py`,
`cspm/engine.py`). Rules operate on plain, normalized Python dicts — they
have zero AWS SDK dependency. This is why:

- Every rule is unit-testable with hand-built dicts, no AWS account or
  mocking framework needed
- The same rules could run against a different cloud's data (Azure/GCP)
  if someone wrote a collector that normalized to the same shape
- You can develop and test 100% of the security logic offline, which is
  exactly how this project was built and verified — see "Testing status"
  below

```
┌──────────────┐     normalized dicts       ┌──────────────┐     findings     ┌──────────┐
│ collectors.py│ ────────────────────────▶ │ rules/*.py   │ ───────────────▶ │ engine.py│ ──▶ report.py
│ (boto3, live)│                            │ (pure logic) │                  │(aggregate)│
└──────────────┘                            └──────────────┘                  └──────────┘
       ▲
       │ OR, for testing/demo:
┌──────────────┐
│ fixtures/*.json (same normalized shape, no AWS needed)
└──────────────┘
```

## Setup

```bash
git clone <your-fork-url>
cd aws-cspm-scanner
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

## Try it immediately — no AWS account needed

```bash
python scripts/demo_offline.py
```

Runs the full rule engine against `fixtures/sample_account.json`, a
hand-built account snapshot with a deliberate mix of clean and
misconfigured resources (full-admin IAM policy, public S3 bucket, SSH
open to the world, a security group with literally everything open, plus
several clean resources that should produce zero findings — useful for
confirming the scanner doesn't false-positive on good configurations).

## Running against a real AWS account

```bash
python scripts/run_scan.py                       # text report to stdout
python scripts/run_scan.py --json --output report.json
```

Requires AWS credentials (`aws configure`, environment variables, or an
IAM role) with these **read-only** permissions:

```
iam:ListPolicies, iam:GetPolicyVersion, iam:ListEntitiesForPolicy,
iam:ListUsers, iam:GetLoginProfile, iam:ListMFADevices,
iam:ListAccessKeys, iam:GetAccessKeyLastUsed
s3:ListAllMyBuckets, s3:GetBucketAcl, s3:GetPublicAccessBlock,
s3:GetBucketEncryption, s3:GetBucketVersioning, s3:GetBucketLogging
ec2:DescribeSecurityGroups
```

**Run this against a sandbox/non-production account first.** These are
all read-only calls, but IAM/S3 APIs across many resources can add up —
verify rate limits and IAM permissions are scoped correctly for your
account before pointing it at production.

## Running the tests

```bash
pytest tests/ -v
```

46 tests across IAM, S3, and Security Group rules plus the engine/risk
scoring, including boundary tests (e.g. a key exactly at the 90-day
threshold is NOT flagged — only strictly older) and negative tests (clean
resources produce zero findings, so the rules aren't just "always fire").

## Screenshots

### Offline scan against sample account data
![Offline scan demo](screenshots/demo-offline-scan.png)
`python scripts/demo_offline.py` — risk score 100/100 across 25 findings,
including a full-admin IAM policy (`Action:* Resource:*`) and root
account access keys, each with a specific fix and a CIS Benchmark
reference.

## Offline scan demo

<details>
<summary>Click to expand full scan output (25 findings)</summary>

```
========================================================================
AWS CLOUD SECURITY POSTURE REPORT
========================================================================

Risk score: 100/100  (25 findings)

[91m--- CRITICAL (7) ---[0m
  [IAM-001] iam_policy:LegacyFullAdminPolicy ù Policy grants full administrative access (Action:* Resource:*)
      Policy 'LegacyFullAdminPolicy' attached to ['deploy-bot'] allows every action on every resource. Anyone/anything holding this policy has unrestricted account access.
      Fix: Scope the policy to specific actions and resource ARNs following least privilege. Use IAM Access Analyzer to identify the minimum permissions actually used before narrowing.
      Reference: CIS AWS Foundations Benchmark 1.16-equivalent (verify version)

  [IAM-003] iam_user:root ù Root account has active access keys
      The AWS account root user has programmatic access keys. Root should never have access keys ù root has unrestricted, non-scopeable permissions and cannot be constrained by any IAM policy.
      Fix: Delete root access keys immediately. Use IAM roles/users for all programmatic access.
      Reference: CIS AWS Foundations Benchmark 1.4-equivalent (verify version)

  [S3-001] s3_bucket:public-website-assets ù Bucket ACL grants access to 'AllUsers' (fully public)
      Bucket 'public-website-assets' has an ACL grant to the AllUsers group, making it readable/writable (depending on the grant) by anyone on the internet, unauthenticated.
      Fix: Remove the public ACL grant. Enable S3 Block Public Access at the bucket and account level.
      Reference: CIS AWS Foundations Benchmark 2.1-equivalent (verify version)

  [SG-001] security_group:sg-0abc111ssh ù SSH (port 22) open to the entire internet
      Security group 'sg-0abc111ssh' (legacy-bastion) allows SSH from 0.0.0.0/0 or ::/0. This is one of the most common initial-access vectors in real breaches ù automated scanners find and brute-force these within minutes of exposure.
      Fix: Restrict SSH access to specific known IP ranges (office VPN, bastion host) or remove direct exposure entirely in favor of Session Manager / a VPN.
      Reference: CIS AWS Foundations Benchmark 5.2/5.3-equivalent (verify version)

  [SG-001] security_group:sg-0ghi333all ù SSH (port 22) open to the entire internet
      Security group 'sg-0ghi333all' (misconfigured-catchall) allows SSH from 0.0.0.0/0 or ::/0. This is one of the most common initial-access vectors in real breaches ù automated scanners find and brute-force these within minutes of exposure.
      Fix: Restrict SSH access to specific known IP ranges (office VPN, bastion host) or remove direct exposure entirely in favor of Session Manager / a VPN.
      Reference: CIS AWS Foundations Benchmark 5.2/5.3-equivalent (verify version)

  [SG-001] security_group:sg-0ghi333all ù RDP (port 3389) open to the entire internet
      Security group 'sg-0ghi333all' (misconfigured-catchall) allows RDP from 0.0.0.0/0 or ::/0. This is one of the most common initial-access vectors in real breaches ù automated scanners find and brute-force these within minutes of exposure.
      Fix: Restrict RDP access to specific known IP ranges (office VPN, bastion host) or remove direct exposure entirely in favor of Session Manager / a VPN.
      Reference: CIS AWS Foundations Benchmark 5.2/5.3-equivalent (verify version)

  [SG-003] security_group:sg-0ghi333all ù All ports/protocols open to the entire internet
      Security group 'sg-0ghi333all' allows ALL traffic (any port, any protocol) from 0.0.0.0/0 or ::/0 ù every service on any instance using this group is directly exposed.
      Fix: Replace with specific rules for only the ports/protocols actually needed.
      Reference: CIS AWS Foundations Benchmark 5.1-equivalent (verify version)

[91m--- HIGH (10) ---[0m
  [IAM-002] iam_policy:S3WildcardActions ù Policy grants wildcard actions on a scoped resource
      Policy 'S3WildcardActions' allows ALL actions against resource(s) ['arn:aws:s3:::data-bucket/*']. Even scoped to specific resources, unrestricted actions (including delete/modify permissions APIs on that resource) exceed what most roles genuinely need.
      Fix: Enumerate the specific actions actually required and list them explicitly.
      Reference: CIS AWS Foundations Benchmark 1.16-equivalent (verify version)

  [IAM-004] iam_user:contractor-bob ù Console user has no MFA enabled
      User 'contractor-bob' can sign in to the console with just a password. Without MFA, a leaked/phished password is immediately sufficient for account takeover.
      Fix: Enforce MFA via IAM policy condition (aws:MultiFactorAuthPresent) and require enrollment.
      Reference: CIS AWS Foundations Benchmark 1.10-equivalent (verify version)

  [S3-003] s3_bucket:public-website-assets ù S3 Block Public Access not fully enabled
      Bucket 'public-website-assets' has these Block Public Access settings disabled: ['block_public_acls', 'block_public_policy', 'ignore_public_acls', 'restrict_public_buckets']. This is the primary safety net against accidental public exposure.
      Fix: Enable all four Block Public Access settings unless the bucket is intentionally serving public content (e.g. static website hosting), in which case document the exception explicitly.
      Reference: CIS AWS Foundations Benchmark 2.1.5-equivalent (verify version)

  [SG-002] security_group:sg-0def222db ù PostgreSQL (port 5432) open to the entire internet
      Security group 'sg-0def222db' allows direct internet access to a PostgreSQL port. Databases should never be directly internet-reachable ù access should go through an application layer or a bastion/VPN.
      Fix: Restrict to the application tier's security group only; remove public CIDR ranges.
      Reference: General AWS security best practice (not a specific CIS numbered control)

  [SG-002] security_group:sg-0ghi333all ù MySQL (port 3306) open to the entire internet
      Security group 'sg-0ghi333all' allows direct internet access to a MySQL port. Databases should never be directly internet-reachable ù access should go through an application layer or a bastion/VPN.
      Fix: Restrict to the application tier's security group only; remove public CIDR ranges.
      Reference: General AWS security best practice (not a specific CIS numbered control)

  [SG-002] security_group:sg-0ghi333all ù PostgreSQL (port 5432) open to the entire internet
      Security group 'sg-0ghi333all' allows direct internet access to a PostgreSQL port. Databases should never be directly internet-reachable ù access should go through an application layer or a bastion/VPN.
      Fix: Restrict to the application tier's security group only; remove public CIDR ranges.
      Reference: General AWS security best practice (not a specific CIS numbered control)

  [SG-002] security_group:sg-0ghi333all ù MSSQL (port 1433) open to the entire internet
      Security group 'sg-0ghi333all' allows direct internet access to a MSSQL port. Databases should never be directly internet-reachable ù access should go through an application layer or a bastion/VPN.
      Fix: Restrict to the application tier's security group only; remove public CIDR ranges.
      Reference: General AWS security best practice (not a specific CIS numbered control)

  [SG-002] security_group:sg-0ghi333all ù MongoDB (port 27017) open to the entire internet
      Security group 'sg-0ghi333all' allows direct internet access to a MongoDB port. Databases should never be directly internet-reachable ù access should go through an application layer or a bastion/VPN.
      Fix: Restrict to the application tier's security group only; remove public CIDR ranges.
      Reference: General AWS security best practice (not a specific CIS numbered control)

  [SG-002] security_group:sg-0ghi333all ù Redis (port 6379) open to the entire internet
      Security group 'sg-0ghi333all' allows direct internet access to a Redis port. Databases should never be directly internet-reachable ù access should go through an application layer or a bastion/VPN.
      Fix: Restrict to the application tier's security group only; remove public CIDR ranges.
      Reference: General AWS security best practice (not a specific CIS numbered control)

  [SG-002] security_group:sg-0ghi333all ù Elasticsearch (port 9200) open to the entire internet
      Security group 'sg-0ghi333all' allows direct internet access to a Elasticsearch port. Databases should never be directly internet-reachable ù access should go through an application layer or a bastion/VPN.
      Fix: Restrict to the application tier's security group only; remove public CIDR ranges.
      Reference: General AWS security best practice (not a specific CIS numbered control)

[93m--- MEDIUM (3) ---[0m
  [IAM-005] iam_user:root ù Access key older than 90 days
      User 'root' has access key 'AKIAROOTKEYEXAMPLE1' that is 400 days old. Long-lived credentials increase the window of exposure if ever leaked.
      Fix: Rotate access keys regularly; prefer IAM roles with temporary credentials over long-lived keys where possible.
      Reference: CIS AWS Foundations Benchmark 1.14-equivalent (verify version)

  [IAM-005] iam_user:deploy-bot ù Access key older than 90 days
      User 'deploy-bot' has access key 'AKIADEPLOYKEYEXAMPLE' that is 210 days old. Long-lived credentials increase the window of exposure if ever leaked.
      Fix: Rotate access keys regularly; prefer IAM roles with temporary credentials over long-lived keys where possible.
      Reference: CIS AWS Foundations Benchmark 1.14-equivalent (verify version)

  [S3-004] s3_bucket:public-website-assets ù Default encryption not enabled
      Bucket 'public-website-assets' has no default server-side encryption configured. Objects uploaded without an explicit encryption header are stored unencrypted at rest.
      Fix: Enable default encryption (SSE-S3 or SSE-KMS) at the bucket level.
      Reference: CIS AWS Foundations Benchmark 2.1.1-equivalent (verify version)

[94m--- LOW (5) ---[0m
  [IAM-006] iam_user:contractor-bob ù Access key unused for 180 days
      User 'contractor-bob' has an access key not used in 180 days. Unused credentials should be deactivated ù they provide no value and only add attack surface.
      Fix: Deactivate or delete access keys with no recent usage.
      Reference: CIS AWS Foundations Benchmark 1.13-equivalent (verify version)

  [S3-005] s3_bucket:public-website-assets ù Versioning not enabled
      Bucket 'public-website-assets' does not have versioning enabled, so accidental deletes/overwrites (or a ransomware-style mass encryption of objects) cannot be recovered from.
      Fix: Enable versioning; pair with MFA Delete for high-value buckets.
      Reference: Not a standalone CIS control in most versions ù general AWS best practice

  [S3-005] s3_bucket:backup-archive ù Versioning not enabled
      Bucket 'backup-archive' does not have versioning enabled, so accidental deletes/overwrites (or a ransomware-style mass encryption of objects) cannot be recovered from.
      Fix: Enable versioning; pair with MFA Delete for high-value buckets.
      Reference: Not a standalone CIS control in most versions ù general AWS best practice

  [S3-006] s3_bucket:public-website-assets ù Access logging not enabled
      Bucket 'public-website-assets' has no access logging configured. During an incident, there is no record of who accessed which objects and when.
      Fix: Enable S3 server access logging or CloudTrail data events for this bucket.
      Reference: Not a standalone CIS control in most versions ù general AWS best practice

  [S3-006] s3_bucket:backup-archive ù Access logging not enabled
      Bucket 'backup-archive' has no access logging configured. During an incident, there is no record of who accessed which objects and when.
      Fix: Enable S3 server access logging or CloudTrail data events for this bucket.
      Reference: Not a standalone CIS control in most versions ù general AWS best practice


```

</details>

### Test suite
![pytest passing](screenshots/pytest-passing.png)
`pytest tests/ -v` — all 46 tests passing across IAM, S3, and Security
Group rules plus the engine and risk-scoring logic.

## What each rule set checks

**IAM** — full-admin policies (`Action:* Resource:*`), wildcard actions on
scoped resources, root account access keys, console users without MFA,
stale (>90 day) access keys, unused (>90 day) access keys.

**S3** — public ACL grants (AllUsers / AuthenticatedUsers — the latter is
commonly misunderstood as "my org" when it actually means "any AWS
account"), Block Public Access disabled, missing default encryption,
versioning disabled, access logging disabled.

**Security Groups** — SSH/RDP open to 0.0.0.0/0 or ::/0, database ports
(MySQL/Postgres/MSSQL/MongoDB/Redis/Elasticsearch) open to the world, and
the "everything open" catch-all misconfiguration (protocol -1 or full
0-65535 port range on an open CIDR).

## Testing status

- ✅ **Covered by the test suite**: all rule logic, the risk-scoring engine,
  and the report generator — the offline demo runs against the fixture
  and every one of the 25 findings is correct, and, just as importantly,
  the clean resources in the same fixture produce ZERO findings (a
  scanner that never says "this is fine" isn't trustworthy). All 46 unit
  tests pass.
- ⚠️ **Needs a live test before trusting it in production**:
  `cspm/collectors.py` (the boto3 integration) - Run against a
  real AWS account yet. It's written against the documented boto3 API
  shapes, but boto3 has enough edge cases (pagination quirks, exception
  class names, response key casing) that I'd expect some debugging on
  first run against a real account — that's normal, not a sign something
  is fundamentally wrong. Run `python scripts/run_scan.py` against a
  sandbox account, not production, and fix whatever surfaces.

## Limitations

- Risk scoring is a simple weighted sum, not a calibrated probability —
  useful as a relative trend line (is this account's score improving scan
  over scan), not as an absolute "37% chance of breach" figure.
- CIS references are approximate — CIS revises control numbering across
  benchmark versions (1.2 → 1.5+), so treat the cited numbers as pointers
  to verify against your target version, not as guaranteed-current
  citations. The security reasoning behind each rule doesn't change; the
  exact section number might.
- Doesn't cover every AWS service — this is IAM/S3/EC2-SG only. Natural
  next additions: RDS public accessibility, CloudTrail coverage gaps,
  Lambda function URL auth, KMS key policies.
- No pagination testing against accounts with hundreds of policies/buckets
  — the collector code paginates where boto3 supports it, but this
  hasn't been load-tested.

## License

MIT — see [LICENSE](./LICENSE).
