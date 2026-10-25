"""
kubernetes_handler.py – Kubernetes audit + Falco detection plane.

Two event sources:
  * S3 ObjectCreated events carrying Kubernetes audit EventList files or Falco
    JSON output.
  * SQS messages from Falcosidekick (raw Falco JSON).

Detections go to the shared ot_detections table with
`detection_domain = "kubernetes"` and `mitre_framework = "containers"`.
"""

import os
import sys

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

from log_parser_toolkit.analyzer.kubernetes_rules import KubernetesSecurityAnalyzer
from log_parser_toolkit.analyzer.severity import get_severity
from log_parser_toolkit.api import parse_stream
from log_parser_toolkit.detections import generate_event_id, normalize_for_parquet
from log_parser_toolkit.falco import normalize_falco_event
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

K8S_BUCKET = os.environ.get("K8S_BUCKET")
STAGED_BUCKET = os.environ.get("STAGED_BUCKET")
DLQ_BUCKET = os.environ.get("DLQ_BUCKET")

try:
    MAX_OBJECT_BYTES = int(os.environ.get("MAX_OBJECT_BYTES", "104857600"))
except ValueError:
    MAX_OBJECT_BYTES = 104857600

analyzer = KubernetesSecurityAnalyzer()
detections_table = dynamodb.Table("ot_detections")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _event_date(timestamp: Optional[str]) -> str:
    if timestamp:
        try:
            return datetime.fromisoformat(str(timestamp).replace("Z", "+00:00")).date().isoformat()
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
        return False
    key = f"kubernetes/source={source}/date={_event_date(None)}/{os.path.basename(original_key)}_failed.json"
    try:
        body = "\n".join(json.dumps(row, default=str, sort_keys=True) for row in rows)
        s3_client.put_object(Bucket=DLQ_BUCKET, Key=key, Body=body, ContentType="application/json")
        return True
    except Exception as exc:
        logger.error(f"Failed to write Kubernetes DLQ object {key}: {exc}")
        return False


def _write_detection(row: Dict[str, Any], alert: Dict[str, Any], original_key: str, index: int) -> None:
    reason = alert.get("alert_reason", "K8S_ANOMALY")
    timestamp = row.get("timestamp") or _now()
    # Audit logs emit multiple stages for one request (same auditID). Use the
    # request-received time and audit ID so the stages collapse to one row.
    stable_timestamp = row.get("request_received_timestamp") or timestamp
    hash_seed = row.get("audit_id") or timestamp
    src_ip = row.get("source_ip") or "unknown"
    host = (
        row.get("host")
        or row.get("pod")
        or row.get("workload")
        or row.get("username")
        or src_ip
    )
    identifier = src_ip if src_ip != "unknown" else host
    correlator = f"{reason.replace(' ', '_')}#{identifier}"
    event_hash = generate_event_id(original_key, hash_seed, reason, index)

    item = {
        "incident_correlator": correlator,
        "timestamp": f"{stable_timestamp}#{event_hash}",
        "event_timestamp": stable_timestamp,
        "severity": alert.get("severity") or get_severity(reason),
        "host": str(host)[:512],
        "src_ip": str(src_ip)[:128],
        "alert_reason": reason,
        "details": alert.get("details", ""),
        "original_key": original_key,
        "detection_domain": "kubernetes",
        "mitre_framework": alert.get("mitre_framework") or "containers",
    }
    for field in (
        "mitre_technique", "mitre_tactic", "namespace", "resource", "subresource",
        "verb", "username", "falco_rule", "falco_priority", "container_image", "workload",
    ):
        value = alert.get(field) or row.get(field)
        if value:
            item[field] = str(value)

    detections_table.put_item(Item=item)


def _process_falco_event(event: Dict[str, Any]) -> bool:
    row = normalize_falco_event(event)
    alert = {
        "alert_reason": row["alert_reason"],
        "details": row["details"],
        "severity": row["severity"],
        "mitre_technique": row.get("mitre_technique"),
        "mitre_framework": "containers",
        "mitre_tactic": row.get("mitre_tactic"),
        "falco_rule": row.get("falco_rule"),
        "falco_priority": row.get("falco_priority"),
    }
    original_key = f"falco:{row['alert_reason']}:{row['timestamp']}"
    try:
        _write_detection(row, alert, original_key, 0)
        _stage_rows([row], "falco")
        return True
    except Exception as exc:
        logger.error(f"Failed to process Falco event {row['alert_reason']}: {exc}")
        return False


def _process_s3_object(s3_record: Dict[str, Any]) -> bool:
    s3_data = s3_record.get("s3", {})
    bucket = s3_data.get("bucket", {}).get("name")
    key = s3_data.get("object", {}).get("key")
    if not bucket or not key:
        return False
    key = urllib.parse.unquote_plus(key)

    if K8S_BUCKET and bucket != K8S_BUCKET:
        logger.error(f"Refusing Kubernetes object from {bucket}; expected {K8S_BUCKET}.")
        return False

    try:
        size = int(s3_data.get("object", {}).get("size", 0) or 0)
    except (TypeError, ValueError):
        size = 0
    if size > MAX_OBJECT_BYTES:
        logger.error(f"Kubernetes object {key} is {size} bytes, above MAX_OBJECT_BYTES={MAX_OBJECT_BYTES}.")
        return False

    is_falco = "falco" in key.lower()
    source = "falco" if is_falco else "k8s_audit"
    parser_name = "falco" if is_falco else "kubernetes_audit"

    work_dir = tempfile.mkdtemp(prefix="ot-k8s-")
    path = os.path.join(work_dir, os.path.basename(key))
    record_ok = True
    try:
        s3_client.download_file(bucket, key, path)
        with open(path, "rb") as handle:
            if handle.read(2) == b"\x1f\x8b":
                gz_path = path + ".gz"
                os.replace(path, gz_path)
                path = gz_path

        failed_rows = []
        valid_rows = []
        parsed_rows = []
        try:
            parser = get_parser(parser_name, path)
            with parser as stream:
                if is_falco:
                    parsed_rows = [row for row in stream.parse()]
                else:
                    parsed_rows = list(parse_stream(stream.parse(), [analyzer]))
        except Exception as exc:
            logger.error(f"Kubernetes parser failed for {key}: {exc}")
            failed_rows.append({"raw_line": f"entire file failed: {key}", "error": str(exc), "original_key": key})
            parsed_rows = []

        for row in parsed_rows:
            if row.get("error"):
                failed_rows.append({"raw_line": row.get("raw_line"), "error": row.get("error"), "original_key": key})
                continue
            if is_falco:
                normalized = normalize_falco_event({
                    "time": row.get("timestamp"),
                    "rule": row.get("rule"),
                    "priority": row.get("priority"),
                    "source": row.get("source"),
                    "hostname": row.get("hostname"),
                    "output": row.get("message"),
                    "output_fields": {
                        "k8s.ns.name": row.get("namespace"),
                        "k8s.pod.name": row.get("pod"),
                        "container.name": row.get("container"),
                        "proc.name": row.get("process"),
                        "proc.cmdline": row.get("command"),
                        "fd.name": row.get("file"),
                        "user.name": row.get("user"),
                        "fd.sip": row.get("source_ip"),
                    },
                })
                valid_rows.append(normalized)
                alert = {
                    "alert_reason": normalized["alert_reason"],
                    "details": normalized["details"],
                    "severity": normalized["severity"],
                    "mitre_technique": normalized.get("mitre_technique"),
                    "mitre_framework": "containers",
                    "mitre_tactic": normalized.get("mitre_tactic"),
                    "falco_rule": normalized.get("falco_rule"),
                    "falco_priority": normalized.get("falco_priority"),
                }
                try:
                    _write_detection(normalized, alert, key, 0)
                except Exception as exc:
                    logger.error(f"Failed to write Falco detection for {key}: {exc}")
                    record_ok = False
            else:
                valid_rows.append(row)
                for index, alert in enumerate(row.get("alerts", [])):
                    try:
                        _write_detection(row, alert, key, index)
                    except Exception as exc:
                        logger.error(f"Failed to write Kubernetes detection for {key}: {exc}")
                        record_ok = False

        if failed_rows:
            record_ok = _write_dlq(failed_rows, key, source) and record_ok
        try:
            _stage_rows(valid_rows, source)
        except Exception as exc:
            logger.error(f"Failed to stage Kubernetes records from {key}: {exc}")
            record_ok = False
        return record_ok
    except Exception as exc:
        logger.error(f"Failed to process Kubernetes object s3://{bucket}/{key}: {exc}")
        return False
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


def lambda_handler(event, context):
    records = event.get("Records", [])
    logger.info(f"Kubernetes detector received {len(records)} SQS record(s).")
    batch_item_failures = []

    for record in records:
        message_id = record.get("messageId")
        try:
            body = json.loads(record.get("body", "{}"))
        except Exception as exc:
            logger.error(f"Failed to parse Kubernetes SQS body: {exc}")
            if message_id:
                batch_item_failures.append({"itemIdentifier": message_id})
            continue

        if body.get("Event") == "s3:TestEvent":
            continue

        if body.get("rule") and body.get("priority"):
            ok = _process_falco_event(body)
        else:
            s3_records = body.get("Records", [])
            if not s3_records:
                logger.warning("Kubernetes message contained neither an S3 event nor a Falco event.")
                ok = False
            else:
                ok = True
                for s3_record in s3_records:
                    if not _process_s3_object(s3_record):
                        ok = False

        if not ok and message_id:
            batch_item_failures.append({"itemIdentifier": message_id})

    return {"batchItemFailures": batch_item_failures}
