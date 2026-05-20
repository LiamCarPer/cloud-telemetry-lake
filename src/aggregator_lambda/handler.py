"""
handler.py – OT Incident Aggregator Lambda

Triggered by DynamoDB Streams on the ot_detections table.
For each batch of INSERT records, it:
  1. Deserialises the DynamoDB AttributeValue maps to plain Python dicts.
  2. Delegates report construction to report_builder (NIST SP 800-61 format).
  3. Writes the resulting JSON report to the S3 reports bucket.
  4. Publishes a concise SNS notification for SOC alerting.
"""

import json
import logging
import os

import boto3
from boto3.dynamodb.types import TypeDeserializer

from report_builder import build_report

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# LocalStack / AWS endpoint resolution
# ---------------------------------------------------------------------------

endpoint_url = os.environ.get("AWS_ENDPOINT_URL")

if endpoint_url and ("localhost" in endpoint_url or "127.0.0.1" in endpoint_url):
    localstack_hostname = os.environ.get("LOCALSTACK_HOSTNAME")
    if localstack_hostname:
        endpoint_url = (
            endpoint_url
            .replace("localhost", localstack_hostname)
            .replace("127.0.0.1", localstack_hostname)
        )
        os.environ["AWS_ENDPOINT_URL"] = endpoint_url
elif not endpoint_url and os.environ.get("LOCALSTACK_HOSTNAME"):
    endpoint_url = f"http://{os.environ['LOCALSTACK_HOSTNAME']}:4566"
    os.environ["AWS_ENDPOINT_URL"] = endpoint_url

_client_kwargs = dict(
    endpoint_url=endpoint_url,
    aws_access_key_id="mock",
    aws_secret_access_key="mock",
    region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
)

s3_client = boto3.client("s3", **_client_kwargs)
sns_client = boto3.client("sns", **_client_kwargs)

# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------

REPORTS_BUCKET = os.environ.get("REPORTS_BUCKET")
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")

# ---------------------------------------------------------------------------
# DynamoDB AttributeValue deserialiser
# ---------------------------------------------------------------------------

_deserializer = TypeDeserializer()


def _unmarshal(dynamo_map: dict) -> dict:
    """Convert a DynamoDB AttributeValue map to a plain Python dict."""
    return {k: _deserializer.deserialize(v) for k, v in dynamo_map.items()}


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------

def lambda_handler(event, context):
    records = event.get("Records", [])
    logger.info(f"Received {len(records)} DynamoDB Stream record(s).")

    detections = []
    for record in records:
        # Only process new writes; ignore MODIFY / REMOVE
        if record.get("eventName") != "INSERT":
            continue

        new_image = record.get("dynamodb", {}).get("NewImage")
        if not new_image:
            continue

        try:
            det = _unmarshal(new_image)
            detections.append(det)
        except Exception as exc:
            logger.error(f"Failed to deserialise stream record: {exc}")
            continue

    if not detections:
        logger.info("No INSERT detections in batch — nothing to aggregate.")
        return {"statusCode": 200, "body": "No detections to process."}

    logger.info(f"Aggregating {len(detections)} detection(s) into an incident report.")

    # Build the NIST SP 800-61 IR report
    report = build_report(detections)
    incident_id = report["incident_id"]

    # ------------------------------------------------------------------
    # 1. Write IR report to S3 reports bucket
    # ------------------------------------------------------------------
    report_key = f"incidents/{incident_id}.json"
    try:
        s3_client.put_object(
            Bucket=REPORTS_BUCKET,
            Key=report_key,
            Body=json.dumps(report, indent=2, default=str),
            ContentType="application/json",
        )
        logger.info(f"Incident report written: s3://{REPORTS_BUCKET}/{report_key}")
    except Exception as exc:
        logger.error(f"Failed to write incident report to S3: {exc}")
        raise

    # ------------------------------------------------------------------
    # 2. Publish SNS notification
    # ------------------------------------------------------------------
    subject = (
        f"[{report['severity']}] OT Incident {incident_id[:8].upper()} – "
        f"{len(detections)} Detection(s) | "
        f"Techniques: {', '.join(report['mitre_techniques'])}"
    )
    notification_payload = json.dumps(
        {
            "incident_id": incident_id,
            "severity": report["severity"],
            "detection_count": report["detection_count"],
            "mitre_techniques": report["mitre_techniques"],
            "affected_assets": report["affected_assets"],
            "nist_phase": report["nist_phase"],
            "report_s3_uri": f"s3://{REPORTS_BUCKET}/{report_key}",
            "created_at": report["created_at"],
        },
        default=str,
    )

    try:
        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject,
            Message=notification_payload,
        )
        logger.info(f"SNS notification published: {subject}")
    except Exception as exc:
        # Non-fatal: the S3 report was already written; log and continue.
        logger.error(f"Failed to publish SNS notification: {exc}")

    return {
        "statusCode": 200,
        "body": json.dumps({"incident_id": incident_id, "report_key": report_key}),
    }
