"""
upload_identity_fixtures.py – local identity-plane demo.

Uploads committed CloudTrail fixtures to the identity S3 bucket and emits a
GuardDuty-shaped finding through EventBridge. The real CloudTrail/GuardDuty
services are not required; the S3 and EventBridge paths are the same ones the
Terraform wiring uses in AWS.

Usage:
    python src/identity_fixture/upload_identity_fixtures.py \
        --endpoint-url http://localhost:4566
"""

import argparse
import json
import os
from datetime import datetime, timezone

import boto3

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
FIXTURES = os.path.join(REPO_ROOT, "tests", "fixtures")


def _client(service: str, endpoint_url: str):
    return boto3.client(
        service,
        endpoint_url=endpoint_url,
        aws_access_key_id="mock",  # nosec B106
        aws_secret_access_key="mock",  # nosec B106
        region_name="us-east-1",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Upload identity detection fixtures.")
    parser.add_argument("--endpoint-url", default="http://localhost:4566")
    parser.add_argument("--account-id", default="000000000000")
    parser.add_argument(
        "--date",
        default=datetime.now(timezone.utc).strftime("%Y/%m/%d"),
        help="CloudTrail key date path (YYYY/MM/DD).",
    )
    parser.add_argument(
        "--skip-brute-force",
        action="store_true",
        help="Only upload the main trail fixture; skip the five failed console logins.",
    )
    args = parser.parse_args()

    s3 = _client("s3", args.endpoint_url)
    events = _client("events", args.endpoint_url)
    bucket = f"ot-identity-raw-{args.account_id}"

    fixture_path = os.path.join(FIXTURES, "cloudtrail", "sample_trail.json")
    with open(fixture_path, encoding="utf-8") as handle:
        trail = json.load(handle)
    key = f"AWSLogs/{args.account_id}/CloudTrail/us-east-1/{args.date}/sample_trail.json"
    s3.put_object(Bucket=bucket, Key=key, Body=json.dumps(trail), ContentType="application/json")
    print(f"[OK] CloudTrail fixture uploaded: s3://{bucket}/{key}")

    if not args.skip_brute_force:
        failures_path = os.path.join(FIXTURES, "cloudtrail", "console_failures.json")
        with open(failures_path, encoding="utf-8") as handle:
            failures = json.load(handle)
        failures_key = (
            f"AWSLogs/{args.account_id}/CloudTrail/us-east-1/{args.date}/console_failures.json"
        )
        s3.put_object(
            Bucket=bucket,
            Key=failures_key,
            Body=json.dumps(failures),
            ContentType="application/json",
        )
        print(f"[OK] Failed-login fixture uploaded: s3://{bucket}/{failures_key}")

    guardduty_path = os.path.join(FIXTURES, "guardduty", "finding.json")
    with open(guardduty_path, encoding="utf-8") as handle:
        finding = json.load(handle)
    response = events.put_events(
        Entries=[
            {
                "Source": "aws.guardduty",
                "DetailType": "GuardDuty Finding",
                "Detail": json.dumps(finding["detail"]),
            }
        ]
    )
    print(f"[OK] GuardDuty finding emitted: {response['Entries'][0].get('EventId')}")


if __name__ == "__main__":
    main()
