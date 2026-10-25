"""
upload_kubernetes_fixtures.py – local Kubernetes-plane demo.

Uploads the committed audit EventList fixture to the K8s S3 bucket and sends a
Falco shell event to the Falco SQS queue. This exercises the same paths used by
Fluent Bit and Falcosidekick in a real cluster.

Usage:
    python src/kubernetes_fixture/upload_kubernetes_fixtures.py \
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
        # LocalStack mock credentials, never used against AWS.
        aws_access_key_id="mock",  # nosec B106
        aws_secret_access_key="mock",  # nosec B106
        region_name="us-east-1",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Upload Kubernetes detection fixtures.")
    parser.add_argument("--endpoint-url", default="http://localhost:4566")
    parser.add_argument("--account-id", default="000000000000")
    parser.add_argument(
        "--date",
        default=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        help="S3 date prefix for the audit fixture.",
    )
    args = parser.parse_args()

    s3 = _client("s3", args.endpoint_url)
    sqs = _client("sqs", args.endpoint_url)

    bucket = f"ot-k8s-raw-{args.account_id}"
    audit_path = os.path.join(FIXTURES, "kubernetes", "audit_events.json")
    with open(audit_path, encoding="utf-8") as handle:
        audit = json.load(handle)
    key = f"audit/{args.date}/audit_events.json"
    s3.put_object(Bucket=bucket, Key=key, Body=json.dumps(audit), ContentType="application/json")
    print(f"[OK] Kubernetes audit fixture uploaded: s3://{bucket}/{key}")

    falco_path = os.path.join(FIXTURES, "kubernetes", "falco_shell.json")
    with open(falco_path, encoding="utf-8") as handle:
        falco = json.load(handle)
    queue_url = f"{args.endpoint_url}/000000000000/ot-falco-events-queue"
    sqs.send_message(QueueUrl=queue_url, MessageBody=json.dumps(falco))
    print(f"[OK] Falco event sent to {queue_url}")


if __name__ == "__main__":
    main()
