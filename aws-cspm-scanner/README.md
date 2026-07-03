# AWS Cloud Security Posture Scanner (mini-CSPM)

Scans an AWS account's IAM policies/users, S3 buckets, and EC2 security
groups for common misconfigurations, scores overall risk, and produces a
report mapped to CIS AWS Foundations Benchmark-style controls.

## Design: rules never touch AWS directly

The architecture deliberately separates **data collection** (boto3 calls,
in `cspm/collectors.py`) from **security logic** (`cspm/rules/*.py`,
`cspm/engine.py`). Rules operate on plain, normalized Python dicts — they
have zero AWS SDK dependency. This is why:

- Every rule is unit-testable with hand-built dicts, no AWS account or
  mocking framework needed
- The same rules could run against a different cloud's data (Azure/GCP)
  if someone wrote a collector that normalized to the same shape
- You can develop and test 100% of the security logic offline, which is
  exactly how this project was built and verified — see "What I actually
  tested" below

```
┌──────────────┐     normalized dicts      ┌──────────────┐     findings     ┌──────────┐
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
  and I've confirmed every one of the 25 findings is correct and, just as
  importantly, that the clean resources in the same fixture produce ZERO
  findings (a scanner that never says "this is fine" isn't trustworthy).
  All 46 unit tests pass.
- ⚠️ **Needs a live test before you trust it in production**:
  `cspm/collectors.py` (the boto3 integration) hasn't been run against a
  real AWS account yet. It's written against the documented boto3 API
  shapes, but boto3 has enough edge cases (pagination quirks, exception
  class names, response key casing) that I'd expect some debugging on
  first run against a real account — that's normal, not a sign something
  is fundamentally wrong. Run `python scripts/run_scan.py` against a
  sandbox account, not production, and fix whatever surfaces.

## Known limitations

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
