import os
import sys

print(f"DEBUG: sys.path is: {sys.path}")
print(f"DEBUG: cwd is: {os.getcwd()}")
try:
    if os.path.exists('/opt'):
        print(f"DEBUG: /opt contents: {os.listdir('/opt')}")
        if os.path.exists('/opt/python'):
            print(f"DEBUG: /opt/python contents: {os.listdir('/opt/python')[:10]}")
    else:
        print("DEBUG: /opt does not exist")
except Exception as e:
    print(f"DEBUG: Error listing /opt: {e}")

# Append bundled dependencies path to sys.path before importing them
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'python'))

import json
import urllib.parse
import logging
from datetime import datetime
import boto3
import pandas as pd
import awswrangler as wr

from log_parser_toolkit.parsers import get_parser
from log_parser_toolkit.api import parse_stream
from log_parser_toolkit.analyzer.state_store import DynamoDBStateStore
from log_parser_toolkit.analyzer.middleware import StatefulSecurityAnalyzer

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Determine endpoints for LocalStack if present
endpoint_url = os.environ.get("AWS_ENDPOINT_URL")
if endpoint_url and ("localhost" in endpoint_url or "127.0.0.1" in endpoint_url):
    localstack_hostname = os.environ.get("LOCALSTACK_HOSTNAME")
    if localstack_hostname:
        endpoint_url = endpoint_url.replace("localhost", localstack_hostname).replace("127.0.0.1", localstack_hostname)
        os.environ["AWS_ENDPOINT_URL"] = endpoint_url
elif not endpoint_url and os.environ.get("LOCALSTACK_HOSTNAME"):
    endpoint_url = f"http://{os.environ['LOCALSTACK_HOSTNAME']}:4566"
    os.environ["AWS_ENDPOINT_URL"] = endpoint_url

# Create configured boto3 session
if endpoint_url:
    logger.info(f"Using custom endpoint URL: {endpoint_url}")
    session = boto3.Session(
        aws_access_key_id="mock",
        aws_secret_access_key="mock",
        region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
    )
    s3_client = boto3.client("s3", endpoint_url=endpoint_url, aws_access_key_id="mock", aws_secret_access_key="mock", region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))
    dynamodb = boto3.resource("dynamodb", endpoint_url=endpoint_url, aws_access_key_id="mock", aws_secret_access_key="mock", region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))
else:
    session = boto3.Session()
    s3_client = boto3.client("s3")
    dynamodb = boto3.resource("dynamodb")

# Initialize persistent DynamoDB clients
state_store = DynamoDBStateStore()
analyzer = StatefulSecurityAnalyzer(state_store=state_store)
detections_table = dynamodb.Table("ot_detections")

def lambda_handler(event, context):
    logger.info(f"Received event: {json.dumps(event)}")
    
    staged_bucket = os.environ.get("STAGED_BUCKET")
    dlq_bucket = os.environ.get("DLQ_BUCKET")
    
    if not staged_bucket or not dlq_bucket:
        raise ValueError("STAGED_BUCKET and DLQ_BUCKET environment variables must be set.")
        
    records = event.get("Records", [])
    logger.info(f"Processing {len(records)} SQS records.")
    
    for record in records:
        try:
            body = json.loads(record.get("body", "{}"))
        except Exception as e:
            logger.error(f"Failed to parse SQS message body as JSON: {e}")
            continue
            
        s3_records = body.get("Records", [])
        for s3_record in s3_records:
            s3_data = s3_record.get("s3", {})
            bucket_name = s3_data.get("bucket", {}).get("name")
            object_key = s3_data.get("object", {}).get("key")
            
            if not bucket_name or not object_key:
                logger.warning(f"S3 record missing bucket name or object key: {s3_record}")
                continue
                
            object_key = urllib.parse.unquote_plus(object_key)
            logger.info(f"Processing file: s3://{bucket_name}/{object_key}")
            
            temp_path = f"/tmp/{os.path.basename(object_key)}"
            try:
                s3_client.download_file(bucket_name, object_key, temp_path)
            except Exception as e:
                logger.error(f"Failed to download file s3://{bucket_name}/{object_key} to {temp_path}: {e}")
                continue
                
            # Parse source and date from the S3 key structure
            parts = object_key.split('/')
            source = "unknown"
            date_str = datetime.utcnow().strftime("%Y-%m-%d")
            
            for part in parts:
                if part.startswith("date="):
                    date_str = part.split('=')[1]
                elif part.startswith("source="):
                    source = part.split('=')[1]
                elif "=" not in part and part != parts[-1]:
                    source = part
                    
            if len(parts) > 1 and source == "unknown" and "=" not in parts[0]:
                source = parts[0]
                
            logger.info(f"Extracted partition values - Source: {source}, Date: {date_str}")
            
            # Select parser format based on file naming/structure
            lower_key = object_key.lower()
            if lower_key.endswith('.csv') or 'windows' in lower_key:
                log_format = "windows"
            elif 'web' in lower_key or 'apache' in lower_key or 'nginx' in lower_key:
                log_format = "web"
            elif lower_key.endswith('.json') or lower_key.endswith('.jsonl') or 'json' in lower_key:
                log_format = "json"
            else:
                log_format = "linux"
                
            logger.info(f"Selected log parser format: {log_format}")
            
            valid_records = []
            failed_records = []
            
            try:
                parser_instance = get_parser(log_format, temp_path)
                with parser_instance as parser:
                    # Stream logs and execute security analyzer pipeline
                    analyzed_stream = parse_stream(parser.parse(), [analyzer])
                    
                    for row in analyzed_stream:
                        if row.get("error"):
                            failed_records.append({
                                "raw_line": row.get("raw_line"),
                                "error": row.get("error"),
                                "source": source,
                                "date": date_str,
                                "original_key": object_key
                            })
                        else:
                            row["source"] = source
                            row["date"] = date_str
                            row["original_key"] = object_key
                            
                            # Route alerts to DynamoDB detections table
                            alerts = row.get("alerts", [])
                            if alerts:
                                for alert in alerts:
                                    ip_or_host = row.get("ip") or row.get("hostname") or source or "unknown"
                                    timestamp_str = row.get("timestamp") or datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
                                    
                                    alert_reason = alert.get("alert_reason", "Generic Anomaly")
                                    correlator = f"{alert_reason.replace(' ', '_')}#{ip_or_host}"
                                    
                                    # Map severity
                                    severity = "LOW"
                                    if alert_reason in ["SSH Brute Force", "Windows Brute Force", "OT Siemens S7comm PLC State Change", "Known Malicious IP"]:
                                        severity = "HIGH"
                                    elif alert_reason in ["Privilege Escalation", "OT Modbus Write Command", "Web Directory Scanning"]:
                                        severity = "MEDIUM"
                                        
                                    try:
                                        detections_table.put_item(
                                            Item={
                                                "incident_correlator": correlator,
                                                "timestamp": timestamp_str,
                                                "severity": severity,
                                                "host": row.get("hostname") or source or "unknown",
                                                "src_ip": row.get("ip") or "unknown",
                                                "alert_reason": alert_reason,
                                                "details": alert.get("details", ""),
                                                "original_key": object_key
                                            }
                                        )
                                        logger.info(f"Recorded alert in DynamoDB: {correlator}")
                                    except Exception as db_err:
                                        logger.error(f"Failed to write detection record to DynamoDB: {db_err}")
                            
                            # Flatten complex structures to prevent Parquet schema mismatch
                            for k, v in list(row.items()):
                                if isinstance(v, (dict, list)):
                                    row[k] = json.dumps(v)
                            valid_records.append(row)
            except Exception as e:
                logger.error(f"Parser execution failed for file {object_key}: {e}")
                failed_records.append({
                    "raw_line": f"Entire file failed parsing: {object_key}",
                    "error": str(e),
                    "source": source,
                    "date": date_str,
                    "original_key": object_key
                })
                
            if failed_records:
                logger.warning(f"Found {len(failed_records)} unparseable records. Routing to DLQ.")
                dlq_key = f"unparseable/date={date_str}/source={source}/{os.path.basename(object_key)}_failed.json"
                try:
                    dlq_content = "\n".join([json.dumps(r) for r in failed_records])
                    s3_client.put_object(
                        Bucket=dlq_bucket,
                        Key=dlq_key,
                        Body=dlq_content,
                        ContentType="application/json"
                    )
                    logger.info(f"Successfully uploaded failed records to s3://{dlq_bucket}/{dlq_key}")
                except Exception as e:
                    logger.error(f"Failed to upload failed records to DLQ bucket: {e}")
                    
            if valid_records:
                logger.info(f"Found {len(valid_records)} valid records. Writing to staged bucket.")
                try:
                    df = pd.DataFrame(valid_records)
                    for col in df.columns:
                        if df[col].dtype == object:
                            df[col] = df[col].astype(str)
                            
                    wr.s3.to_parquet(
                        df=df,
                        path=f"s3://{staged_bucket}/parsed/",
                        dataset=True,
                        partition_cols=["date", "source"],
                        boto3_session=session
                    )
                    logger.info(f"Successfully wrote Parquet file to s3://{staged_bucket}/parsed/")
                except Exception as e:
                    logger.error(f"Failed to write Parquet files to staged bucket: {e}")
                    
            if os.path.exists(temp_path):
                os.remove(temp_path)
                
    return {
        "statusCode": 200,
        "body": json.dumps("Processing complete.")
    }
