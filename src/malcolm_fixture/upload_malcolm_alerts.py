"""
upload_malcolm_alerts.py – Malcolm NDR Fixture Uploader

Generates a realistic batch of Suricata EVE-format alert records (as produced
by Malcolm NDR during OT network analysis) and uploads them directly to the
raw telemetry S3 bucket under the `source=malcolm` partition.

The existing ot-log-parser-lambda handles this path natively:
  - Key prefix `source=malcolm/date=YYYY-MM-DD/` is extracted as partition metadata.
  - Records are parsed through the JSON log path in the Log Parser Toolkit.
  - Nested fields (e.g., `alert`) are flattened to JSON strings for Parquet staging.

Usage:
    python upload_malcolm_alerts.py [--endpoint-url http://localhost:4566]
"""

import argparse
import gzip
import json
import os
import sys
import uuid
from datetime import datetime, timezone

import boto3


# ---------------------------------------------------------------------------
# Suricata EVE alert fixture data
# ---------------------------------------------------------------------------

FIXTURE_ALERTS = [
    {
        "event_type": "alert",
        "src_ip": "172.24.0.10",
        "src_port": 4444,
        "dest_ip": "172.21.0.10",
        "dest_port": 502,
        "proto": "TCP",
        "in_iface": "eth3",
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 2024897,
            "rev": 4,
            "signature": "ET SCADA Modbus Unauthorized Function Code from External Host",
            "category": "SCADA/ICS Attack",
            "severity": 1,
        },
        "flow": {"pkts_toserver": 5, "pkts_toclient": 3, "bytes_toserver": 330, "bytes_toclient": 240},
    },
    {
        "event_type": "alert",
        "src_ip": "172.24.0.10",
        "src_port": 4444,
        "dest_ip": "172.21.0.10",
        "dest_port": 502,
        "proto": "TCP",
        "in_iface": "eth3",
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 2024901,
            "rev": 2,
            "signature": "ET SCADA Modbus Write Single Register Attempt (FC 6)",
            "category": "SCADA/ICS Attack",
            "severity": 1,
        },
        "flow": {"pkts_toserver": 2, "pkts_toclient": 1, "bytes_toserver": 132, "bytes_toclient": 66},
    },
    {
        "event_type": "alert",
        "src_ip": "172.24.0.10",
        "src_port": 5555,
        "dest_ip": "172.22.0.10",
        "dest_port": 102,
        "proto": "TCP",
        "in_iface": "eth3",
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 2034020,
            "rev": 1,
            "signature": "ET SCADA S7comm PLC Read/Write Coils – Lateral Movement",
            "category": "SCADA/ICS Lateral Movement",
            "severity": 2,
        },
        "flow": {"pkts_toserver": 8, "pkts_toclient": 6, "bytes_toserver": 528, "bytes_toclient": 396},
    },
    {
        "event_type": "alert",
        "src_ip": "172.24.0.10",
        "src_port": 6666,
        "dest_ip": "172.21.0.10",
        "dest_port": 502,
        "proto": "TCP",
        "in_iface": "eth3",
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 2024910,
            "rev": 3,
            "signature": "ET SCADA Modbus Exception Response Flood – Brute Force/Scan",
            "category": "SCADA/ICS Reconnaissance",
            "severity": 1,
        },
        "flow": {"pkts_toserver": 20, "pkts_toclient": 20, "bytes_toserver": 1320, "bytes_toclient": 1320},
    },
]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def build_payload() -> bytes:
    """Serialise fixture alerts as newline-delimited JSON and gzip-compress."""
    now = datetime.now(timezone.utc)
    lines = []
    for alert in FIXTURE_ALERTS:
        record = {
            "timestamp": now.strftime("%Y-%m-%dT%H:%M:%S.%f+0000"),
            "flow_id": int(uuid.uuid4().int & 0x7FFFFFFFFFFFFFFF),
            "host": "malcolm-ndr",
            "environment": "production",
            **alert,
        }
        lines.append(json.dumps(record))

    raw_bytes = "\n".join(lines).encode("utf-8")
    return gzip.compress(raw_bytes)


def upload(endpoint_url: str) -> None:
    account_id = "000000000000"  # LocalStack default
    bucket = f"ot-telemetry-raw-{account_id}"
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    filename = f"malcolm-{uuid.uuid4().hex[:8]}.json"
    key = f"source=malcolm/date={date_str}/{filename}"

    payload = build_payload()

    client = boto3.client(
        "s3",
        endpoint_url=endpoint_url,
        aws_access_key_id="mock",
        aws_secret_access_key="mock",
        region_name="us-east-1",
    )

    client.put_object(
        Bucket=bucket,
        Key=key,
        Body=payload,
        ContentType="application/json",
        ContentEncoding="gzip",
    )
    print(f"[OK] Uploaded {len(FIXTURE_ALERTS)} Suricata EVE alerts.")
    print(f"     s3://{bucket}/{key}  ({len(payload)} bytes, gzipped)")


def main() -> None:
    parser = argparse.ArgumentParser(description="Upload Malcolm NDR fixture alerts to the raw S3 bucket.")
    parser.add_argument(
        "--endpoint-url",
        default=os.environ.get("AWS_ENDPOINT_URL", "http://localhost:4566"),
        help="LocalStack (or AWS) endpoint URL.",
    )
    args = parser.parse_args()
    upload(args.endpoint_url)


if __name__ == "__main__":
    main()
