import os
import sys

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
else:
    session = boto3.Session()
    s3_client = boto3.client("s3")

def lambda_handler(event, context):
    logger.info(f"Received event: {json.dumps(event)}")
    
    staged_bucket = os.environ.get("STAGED_BUCKET")
    dlq_bucket = os.environ.get("DLQ_BUCKET")
    
    if not staged_bucket or not dlq_bucket:
        raise ValueError("STAGED_BUCKET and DLQ_BUCKET environment variables must be set.")
        
    records = event.get("Records", [])
    logger.info(f"Processing {len(records)} SQS records.")
    
    for record in records:
        # S3 notifications are wrapped in the SQS body
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
                
            # URL decode the key
            object_key = urllib.parse.unquote_plus(object_key)
            logger.info(f"Processing file: s3://{bucket_name}/{object_key}")
            
            # Download file to /tmp
            temp_path = f"/tmp/{os.path.basename(object_key)}"
            try:
                s3_client.download_file(bucket_name, object_key, temp_path)
            except Exception as e:
                logger.error(f"Failed to download file s3://{bucket_name}/{object_key} to {temp_path}: {e}")
                continue
                
            # Parse source and date from the S3 key structure
            # e.g., source=ot_gateway/date=2026-05-19/log.json
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
            
            # Parse logs streamingly
            valid_records = []
            failed_records = []
            
            try:
                parser_instance = get_parser(log_format, temp_path)
                with parser_instance as parser:
                    for row in parser.parse():
                        if row.get("error"):
                            # Capture failed log lines
                            failed_records.append({
                                "raw_line": row.get("raw_line"),
                                "error": row.get("error"),
                                "source": source,
                                "date": date_str,
                                "original_key": object_key
                            })
                        else:
                            # Flatten/structure for Parquet columns
                            row["source"] = source
                            row["date"] = date_str
                            row["original_key"] = object_key
                            # Ensure none of the fields are complex structures (nested dicts/lists) for standard parquet
                            # If they are alerts or lists, JSON serialize them
                            for k, v in list(row.items()):
                                if isinstance(v, (dict, list)):
                                    row[k] = json.dumps(v)
                            valid_records.append(row)
            except Exception as e:
                logger.error(f"Parser execution failed for file {object_key}: {e}")
                # Treat the whole file as unparseable
                failed_records.append({
                    "raw_line": f"Entire file failed parsing: {object_key}",
                    "error": str(e),
                    "source": source,
                    "date": date_str,
                    "original_key": object_key
                })
                
            # Handle unparseable records (Route to DLQ bucket)
            if failed_records:
                logger.warning(f"Found {len(failed_records)} unparseable records. Routing to DLQ bucket.")
                dlq_key = f"unparseable/date={date_str}/source={source}/{os.path.basename(object_key)}_failed.json"
                try:
                    # Write failed records as a JSON line file in DLQ
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
                    
            # Handle valid records (Convert and write as Parquet to Staged bucket)
            if valid_records:
                logger.info(f"Found {len(valid_records)} valid records. Writing to staged bucket.")
                try:
                    df = pd.DataFrame(valid_records)
                    
                    # Convert column types to string if they are mixed to prevent Parquet schema mismatch
                    for col in df.columns:
                        if df[col].dtype == object:
                            df[col] = df[col].astype(str)
                            
                    # Write as Parquet partitioned by date and source
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
                    
            # Clean up temp file
            if os.path.exists(temp_path):
                os.remove(temp_path)
                
    return {
        "statusCode": 200,
        "body": json.dumps("Processing complete.")
    }
