import os
import sys
import boto3
import awswrangler as wr
import pandas as pd
import json

def get_boto3_session():
    endpoint_url = os.environ.get("AWS_ENDPOINT_URL", "http://localhost:4566")
    session = boto3.Session(
        aws_access_key_id="mock",
        aws_secret_access_key="mock",
        region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
    )
    return session, endpoint_url

def main():
    print("--- Security Data Lake Analytics CLI ---")
    session, endpoint_url = get_boto3_session()
    
    staged_bucket = "ot-telemetry-staged-000000000000"
    path = f"s3://{staged_bucket}/parsed/"
    
    print(f"Reading telemetry from {path} (Endpoint: {endpoint_url})...")
    try:
        df = wr.s3.read_parquet(
            path=path,
            dataset=True,
            boto3_session=session
        )
    except Exception as e:
        print(f"Error reading Parquet files: {e}")
        print("Ensure LocalStack is running and the parser Lambda has staged data.")
        sys.exit(1)
        
    if df.empty:
        print("Data lake staged parquet partition is empty.")
        return
        
    # Align DataFrame columns defensively to match the Glue Catalog Schema
    expected_cols = [
        "timestamp", "hostname", "process", "pid", "message", "ip", "raw_line", "error",
        "alert_type", "source_ip", "dest_ip", "mitre_id", "description", "flow_id",
        "host", "environment", "event_type", "src_ip", "src_port", "dest_port",
        "proto", "in_iface", "alert", "flow", "date", "source"
    ]
    for col in expected_cols:
        if col not in df.columns:
            df[col] = None

    print(f"Successfully loaded {len(df)} telemetry logs.\n")

    
    # Query 1: High-severity OT anomalies over time
    print("=== QUERY 1: High-Severity OT Anomalies Over Time ===")
    # Filter for anomalies
    ot_anomalies = df[
        (df["alert_type"].isin(["CROSS_ZONE_VIOLATION", "UNAUTHORIZED_MODBUS_WRITE", "OT_BRUTE_FORCE_SCAN"])) |
        (df["message"].str.contains("anomaly|violation", case=False, na=False))
    ]
    if not ot_anomalies.empty:
        summary = ot_anomalies.groupby(["date", "source"]).size().reset_index(name="anomaly_count")
        summary = summary.sort_values(by=["date", "anomaly_count"], ascending=[False, False])
        print(summary.to_string(index=False))
    else:
        print("No high-severity OT anomalies found.")
    print()
    
    # Query 2: Top noisy hosts
    print("=== QUERY 2: Top Noisy Hosts ===")
    df["host_identifier"] = df["hostname"].fillna(df["host"]).fillna("unknown")
    noisy_hosts = df.groupby("host_identifier").size().reset_index(name="log_count")
    noisy_hosts = noisy_hosts.sort_values(by="log_count", ascending=False).head(10)
    print(noisy_hosts.to_string(index=False))
    print()
    
    # Query 3: SCADA TTP Patterns (Malcolm logs)
    print("=== QUERY 3: SCADA TTP Patterns (Malcolm NDR) ===")
    if "source" in df.columns:
        malcolm_df = df[df["source"] == "malcolm"].copy()
    else:
        malcolm_df = pd.DataFrame()
        
    if not malcolm_df.empty:
        # Extract alert json fields
        def parse_alert_sig(alert_str):
            try:
                alert_dict = json.loads(alert_str) if isinstance(alert_str, str) else alert_str
                return alert_dict.get("signature")
            except:
                return None
                
        def parse_alert_cat(alert_str):
            try:
                alert_dict = json.loads(alert_str) if isinstance(alert_str, str) else alert_str
                return alert_dict.get("category")
            except:
                return None
                
        if "alert" in malcolm_df.columns:
            malcolm_df["scada_signature"] = malcolm_df["alert"].apply(parse_alert_sig)
            malcolm_df["scada_category"] = malcolm_df["alert"].apply(parse_alert_cat)
            
            scada_patterns = malcolm_df[malcolm_df["scada_category"].str.contains("SCADA", case=False, na=False)]
            if not scada_patterns.empty:
                cols = ["timestamp", "src_ip", "dest_ip", "scada_signature", "scada_category"]
                existing_cols = [c for c in cols if c in scada_patterns.columns]
                print(scada_patterns[existing_cols].to_string(index=False))
            else:
                print("No SCADA alerts matched in Malcolm telemetry.")
        else:
            print("Malcolm alerts did not contain alert details field.")
    else:
        print("No Malcolm NDR telemetry found.")
        
if __name__ == "__main__":
    main()
