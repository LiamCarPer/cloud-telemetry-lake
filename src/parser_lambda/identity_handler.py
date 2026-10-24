"""
identity_handler.py – identity detection plane.

Two event sources, one detection model:
  * SQS messages from S3 ObjectCreated events carrying CloudTrail log files.
  * SQS messages from an EventBridge rule carrying GuardDuty findings.

Both paths write detections to the shared ot_detections table with
`detection_domain = "identity"`, stage normalized records for Athena, and
report per-message failures back to SQS.
"""

import os
import sys

# Same LocalStack bundling workaround as handler.py (shared deployment zip).
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'python'))

import json
import logging
import shutil
import tempfile
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import awswrangler as wr
import boto3
import pandas as pd

from log_parser_toolkit.api import parse_stream
from log_parser_toolkit.analyzer.identity_rules import IdentitySecurityAnalyzer
from log_parser_toolkit.analyzer.severity import get_severity
from log_parser_toolkit.analyzer.state_store import DynamoDBStateStore
from log_parser_toolkit.detections import generate_event_id, normalize_for_parquet
from log_parser_toolkit.guardduty import normalize_guardduty_event
from log_parser_toolkit.parsers import get_parser

logger = logging.getLogger()
logger.setLevel(logging.INFO)

endpoint_url = os.environ.get("AWS_ENDPOINT_URL")
if endpoint_url and ("localhost" in endpoint_url or "127.0.0.1" in endpoint_url):
    localstack_hostname = os.environ.get("LOCALSTACK_HOSTNAME")
    if localstack_hostname:
        endpoint_url = endpoint_url.replace("localhost", localstack_hostname).replace("127.0.0.1", localstack_hostname)
        os.environ["AWS_ENDPOINT_URL"] = endpoint_url
elif not endpoint_url and os.environ.get("LOCALSTACK_HOSTNAME"):
    endpoint_url = f"http://{os.environ['LOCALSTACK_HOSTNAME']}:4566"
    os.environ["AWS_ENDPOINT_URL"] = endpoint_url

if endpoint_url:
    session = boto3.Session(
        aws_access_key_id="mock",  # nosec B106
        aws_secret_access_key="mock",  # nosec B106
        region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
    )
    s3_client = boto3.client("s3", endpoint_url=endpoint_url, aws_access_key_id="mock", aws_secret_access_key="mock", region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))  # nosec B106
    dynamodb = boto3.resource("dynamodb", endpoint_url=endpoint_url, aws_access_key_id="mock", aws_secret_access_key="mock", region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))  # nosec B106
else:
    session = boto3.Session()
    s3_client = boto3.client("s3")
    dynamodb = boto3.resource("dynamodb")

IDENTITY_BUCKET = os.environ.get("IDENTITY_BUCKET")
STAGED_BUCKET = os.environ.get("STAGED_BUCKET")
DLQ_BUCKET = os.environ.get("DLQ_BUCKET")

try:
    MAX_OBJECT_BYTES = int(os.environ.get("MAX_OBJECT_BYTES", "104857600"))
except ValueError:
    MAX_OBJECT_BYTES = 104857600

state_store = DynamoDBStateStore()
analyzer = IdentitySecurityAnalyzer(state_store=state_store)
detections_table = dynamodb.Table("ot_detections")


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _event_date(timestamp: Optional[str]) -> str:
    if timestamp:
        try:
            parsed = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
            return parsed.date().isoformat()
        except ValueError:
            pass
    return datetime.now(timezone.utc).date().isoformat()


def _stage_rows(rows, source: str) -> None:
    if not rows:
        return
    for row in rows:
        row["source"] = source
        row["date"] = _event_date(row.get("timestamp"))
    rows = normalize_for_parquet(rows)
    frame = pd.DataFrame(rows)
    for column in frame.columns:
        if frame[column].dtype == object:
            frame[column] = frame[column].astype(str)
    wr.s3.to_parquet(
        df=frame,
        path=f"s3://{STAGED_BUCKET}/parsed/",
        dataset=True,
        partition_cols=["date", "source"],
        boto3_session=session,
    )


def _write_dlq(rows, original_key: str, source: str) -> bool:
    if not DLQ_BUCKET:
        logger.error("DLQ_BUCKET is not configured; cannot park failed identity records.")
        return False
    key = (
        f"identity/source={source}/date={_event_date(None)}/"
        f"{os.path.basename(original_key)}_failed.json"
    )
    try:
        body = "\n".join(json.dumps(row, default=str, sort_keys=True) for row in rows)
        s3_client.put_object(Bucket=DLQ_BUCKET, Key=key, Body=body, ContentType="application/json")
        return True
    except Exception as exc:
        logger.error(f"Failed to write identity DLQ object s3://{DLQ_BUCKET}/{key}: {exc}")
        return False


def _write_detection(row: Dict[str, Any], alert: Dict[str, Any], original_key: str, index: int) -> None:
    reason = alert.get("alert_reason", "IDENTITY_ANOMALY")
    timestamp = row.get("timestamp") or _now()
    src_ip = row.get("source_ip") or "unknown"
    host = row.get("host") or row.get("user_name") or row.get("user_arn") or src_ip
    identifier = src_ip if src_ip != "unknown" else host
    correlator = f"{reason.replace(' ', '_')}#{identifier}"
    event_hash = generate_event_id(original_key, timestamp, reason, index)

    item = {
        "incident_correlator": correlator,
        "timestamp": f"{timestamp}#{event_hash}",
        "event_timestamp": timestamp,
        "severity": alert.get("severity") or get_severity(reason),
        "host": str(host)[:512],
        "src_ip": str(src_ip)[:128],
        "alert_reason": reason,
        "details": alert.get("details", ""),
        "original_key": original_key,
        "detection_domain": "identity",
    }
    for field in ("mitre_technique", "mitre_framework", "mitre_tactic", "guardduty_type", "guardduty_severity"):
        value = alert.get(field) or row.get(field)
        if value:
            item[field] = str(value)

    detections_table.put_item(Item=item)


# ---------------------------------------------------------------------------
# CloudTrail S3 path
# ---------------------------------------------------------------------------

def _process_cloudtrail_object(s3_record: Dict[str, Any]) -> bool:
    s3_data = s3_record.get("s3", {})
    bucket = s3_data.get("bucket", {}).get("name")
    key = s3_data.get("object", {}).get("key")
    if not bucket or not key:
        logger.warning(f"CloudTrail S3 record missing bucket/key: {s3_record}")
        return False

    key = urllib.parse.unquote_plus(key)
    if IDENTITY_BUCKET and bucket != IDENTITY_BUCKET:
        logger.error(f"Refusing CloudTrail object from {bucket}; expected {IDENTITY_BUCKET}.")
        return False

    try:
        size = int(s3_data.get("object", {}).get("size", 0) or 0)
    except (TypeError, ValueError):
        size = 0
    if size > MAX_OBJECT_BYTES:
        logger.error(f"CloudTrail object {key} is {size} bytes, above MAX_OBJECT_BYTES={MAX_OBJECT_BYTES}.")
        return False

    work_dir = tempfile.mkdtemp(prefix="ot-identity-")
    path = os.path.join(work_dir, os.path.basename(key))
    try:
        s3_client.download_file(bucket, key, path)
        with open(path, "rb") as handle:
            if handle.read(2) == b"\x1f\x8b":
                gz_path = path + ".gz"
                os.replace(path, gz_path)
                path = gz_path

        failed_rows = []
        valid_rows = []
        try:
            parser = get_parser("cloudtrail", path)
            with parser as stream:
                for row in parse_stream(stream.parse(), [analyzer]):
                    if row.get("error"):
                        failed_rows.append({
                            "raw_line": row.get("raw_line"),
                            "error": row.get("error"),
                            "original_key": key,
                        })
                    else:
                        valid_rows.append(row)
        except Exception as exc:
            logger.error(f"CloudTrail parser failed for {key}: {exc}")
            failed_rows.append({"raw_line": f"entire file failed: {key}", "error": str(exc), "original_key": key})

        record_ok = True
        for row in valid_rows:
            for index, alert in enumerate(row.get("alerts", [])):
                try:
                    _write_detection(row, alert, key, index)
                except Exception as exc:
                    logger.error(f"Failed to write identity detection for {key}: {exc}")
                    record_ok = False

        if failed_rows:
            record_ok = _write_dlq(failed_rows, key, "cloudtrail") and record_ok

        try:
            _stage_rows(valid_rows, "cloudtrail")
        except Exception as exc:
            logger.error(f"Failed to stage CloudTrail records from {key}: {exc}")
            record_ok = False

        return record_ok
    except Exception as exc:
        logger.error(f"Failed to process CloudTrail object s3://{bucket}/{key}: {exc}")
        return False
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# GuardDuty EventBridge path
# ---------------------------------------------------------------------------

def _process_guardduty_event(event: Dict[str, Any]) -> bool:
    if not event.get("detail"):
        logger.warning("GuardDuty event has no detail field.")
        return False

    row = normalize_guardduty_event(event)
    alert = {
        "alert_reason": row["alert_reason"],
        "details": row["details"],
        "severity": row["severity"],
        "mitre_tactic": row.get("mitre_tactic"),
        "mitre_framework": "enterprise",
        "guardduty_type": row["guardduty_type"],
        "guardduty_severity": row["guardduty_severity"],
    }
    original_key = (event.get("detail") or {}).get("id") or event.get("id") or row["timestamp"]

    try:
        _write_detection(row, alert, original_key, 0)
        _stage_rows([row], "guardduty")
        return True
    except Exception as exc:
        logger.error(f"Failed to process GuardDuty finding {original_key}: {exc}")
        return False


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------

def lambda_handler(event, context):
    records = event.get("Records", [])
    logger.info(f"Identity detector received {len(records)} SQS record(s).")
    batch_item_failures = []

    for record in records:
        message_id = record.get("messageId")
        try:
            body = json.loads(record.get("body", "{}"))
        except Exception as exc:
            logger.error(f"Failed to parse identity SQS body: {exc}")
            if message_id:
                batch_item_failures.append({"itemIdentifier": message_id})
            continue

        # S3 emits a test event when a notification is configured; acknowledge it.
        if body.get("Event") == "s3:TestEvent":
            continue

        if body.get("source") == "aws.guardduty" or body.get("detail-type") == "GuardDuty Finding":
            ok = _process_guardduty_event(body)
        else:
            s3_records = body.get("Records", [])
            if not s3_records:
                logger.warning("Identity message contained neither an S3 event nor a GuardDuty finding.")
                ok = False
            else:
                ok = True
                for s3_record in s3_records:
                    if not _process_cloudtrail_object(s3_record):
                        ok = False

        if not ok and message_id:
            logger.warning(f"Marking identity message {message_id} as failed for retry.")
            batch_item_failures.append({"itemIdentifier": message_id})

    if batch_item_failures:
        logger.warning(f"Reporting {len(batch_item_failures)} identity batch item failure(s).")
    return {"batchItemFailures": batch_item_failures}
