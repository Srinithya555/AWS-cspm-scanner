"""
Runs the full scan engine against the sample fixture — no AWS credentials,
no boto3, no network required. This is how to see the tool work
immediately, and how the actual policy/rule logic was verified during
development (see README's "what I verified" section).

Run: python scripts/demo_offline.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cspm.engine import run_scan
from cspm.report import print_text_report

FIXTURE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "fixtures", "sample_account.json"
)


def main():
    with open(FIXTURE_PATH) as f:
        account_data = json.load(f)

    findings = run_scan(account_data)
    print_text_report(findings)


if __name__ == "__main__":
    main()
