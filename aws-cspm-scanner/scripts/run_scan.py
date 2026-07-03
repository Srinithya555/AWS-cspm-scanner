"""
Runs a real scan against your AWS account. Requires AWS credentials
configured (aws configure, environment variables, or an IAM role) with the
read-only permissions listed in cspm/collectors.py's module docstring.

Run: python scripts/run_scan.py [--json] [--output report.json]
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cspm.collectors import collect_all
from cspm.engine import run_scan
from cspm.report import print_text_report, to_json_report


def main():
    parser = argparse.ArgumentParser(description="Scan the current AWS account for security misconfigurations.")
    parser.add_argument("--json", action="store_true", help="Output JSON instead of a text report")
    parser.add_argument("--output", help="Write the report to this file instead of stdout")
    args = parser.parse_args()

    print("Collecting AWS account data (this calls IAM/S3/EC2 read-only APIs)...", file=sys.stderr)
    account_data = collect_all()

    findings = run_scan(account_data)

    if args.json:
        output = to_json_report(findings)
        if args.output:
            with open(args.output, "w") as f:
                f.write(output)
            print(f"JSON report written to {args.output}", file=sys.stderr)
        else:
            print(output)
    else:
        print_text_report(findings)

    has_critical = any(f.severity.name == "CRITICAL" for f in findings)
    sys.exit(1 if has_critical else 0)


if __name__ == "__main__":
    main()
