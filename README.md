# Cloud Telemetry Lake (OT Security Lab Integration)

[![Infrastructure](https://img.shields.io/badge/Infrastructure-Terraform-blueviolet?logo=terraform)](https://www.terraform.io/)
[![Environment](https://img.shields.io/badge/LocalStack-Community-blue?logo=localstack)](https://localstack.cloud/)
[![Pipeline](https://img.shields.io/badge/Telemetry-Fluent%20Bit-orange?logo=fluentbit)](https://fluentbit.io/)
[![Analytics](https://img.shields.io/badge/Ingestion-AWS%20Lambda%20%26%20Pandas-yellow?logo=aws-lambda)](https://aws.amazon.com/lambda/)

An end-to-end industrial cybersecurity telemetry pipeline that ingests, parses, analyzes, and archives logs generated from a simulated Operational Technology (OT) network segmented according to the **Purdue Reference Model**. 

This system collects raw network traffic drops and Intrusion Detection System (IDS) alerts from the OT Gateway, processes them serverless-ly in real-time, stores stateful correlation logs, and stages long-term data for security analytics.

---

## Architecture Flowchart

Below is the telemetry ingestion and parsing pipeline flow:

```mermaid
graph TD
    subgraph OT Security Lab (Docker)
        A[OT Attacker - 172.24.0.10] -- Unauthorized Modbus/TCP --> B(OT Gateway - 172.24.0.2 / 172.21.0.2)
        C[PLCs / HMI - 172.21.0.10] <. Blocked Zone Traffic .> B
        B -- Writes Logs --> D[alerts.json & iptables.log]
        E[Fluent Bit Daemon] -- Tails & Gzips logs --> F(LocalStack S3 Raw Bucket)
    end

    subgraph Serverless Telemetry Lake (AWS LocalStack)
        F -- S3 Put Event Notification --> G[SQS Ingest Queue]
        G -- Trigger --> H[Lambda Log Parser]
        H -- Write Alerts --> I[(DynamoDB ot_detections)]
        H -- Write Staged Parquet --> J(S3 Staged Bucket)
    end
    
    style A fill:#f9f,stroke:#333,stroke-width:2px
    style B fill:#bbf,stroke:#333,stroke-width:2px
    style E fill:#f96,stroke:#333,stroke-width:2px
    style H fill:#ff9,stroke:#333,stroke-width:2px
    style I fill:#dfd,stroke:#333,stroke-width:2px
    style J fill:#dfd,stroke:#333,stroke-width:2px
```

---

## Core Features

*   **Purdue Model Network Simulation:** Contains simulated networks for Level 4/5 (IT/Attacker), Level 3 (Operations Gateway), and Level 1/2 (Control Zone with Modbus PLCs).
*   **IDS Scapy Monitoring:** Gateway runs custom Python IDS rule listeners detecting:
    *   `CROSS_ZONE_VIOLATION`: Direct communication attempts bypassing Level 3 boundary rules.
    *   `UNAUTHORIZED_MODBUS_WRITE`: Out-of-bounds Modbus register command writes.
    *   `OT_BRUTE_FORCE_SCAN`: Excessive Modbus exceptions indicating scanner activity.
*   **Firewall Log Sniffing:** Emulates kernel iptables packet drop entries for cross-zone policy blocks.
*   **Structured Gzip Log Shipping:** Fluent Bit ships compressed log frames directly to AWS S3.
*   **Serverless Ingestion Pipeline:** AWS SQS triggers a Python-based Lambda handler that parses incoming payloads dynamically.
*   **Analytical Storage:** Processes logs into partitioned, snappy-compressed **Apache Parquet** format and stores stateful attack metadata in DynamoDB.

---

## LocalStack & Engineering Workarounds

To achieve a production-grade deployment within the LocalStack Community Edition, several architectural workarounds were implemented:
1.  **Fat-Zip Dependency Packaging:** Due to community LocalStack limits mounting external Lambda Layers to `/opt`, dependencies like `pandas` and `awswrangler` are packaged directly inside the function's deployment archive under `python/` and loaded dynamically via `sys.path` injection.
2.  **S3-Based Lambda Deployment:** Since the fat-zip size (~60MB) exceeds AWS API direct payload upload limits (50MB), Terraform uploads the deployment archive to S3 first (`aws_s3_object`) and provisions the function by reference (`s3_bucket`/`s3_key`).
3.  **Dynamic Gzip Magic-Byte Inspection:** Fluent Bit wraps compressed uploads in a Gzip stream while retaining a `.json` key extension. The Lambda handler checks the first two magic bytes (`\x1f\x8b`) of each file at runtime and automatically appends a `.gz` extension to trigger raw decompression correctly.

---

## Getting Started

### 1. Prerequisites
Ensure you have the following installed:
*   [Docker](https://www.docker.com/) & Docker Compose V2
*   [Terraform](https://www.terraform.io/)
*   [AWS CLI](https://aws.amazon.com/cli/) (with local endpoint configuration or `awslocal` wrapper)

### 2. Deploy Infrastructure
Initialize and deploy the AWS infrastructure using LocalStack:
```bash
# Start LocalStack Community container
docker run -d --name localstack -p 4566:4566 -p 4571:4571 localstack/localstack

# Apply Terraform manifests
cd terraform
terraform init
terraform apply -auto-approve
```

### 3. Spin Up the OT Security Lab
Start the simulated industrial environment:
```bash
cd ../ot-security-lab/lab-environment
docker compose up -d
```

Apply the zone firewall boundaries:
```bash
# Apply firewall scripts to the gateway
docker cp network-config/firewall-rules.sh ot_gateway:/firewall-rules.sh
docker exec ot_gateway chmod +x /firewall-rules.sh
docker exec ot_gateway /firewall-rules.sh
```

### 4. Start Background Detectors on Gateway
Start the mock packet drop sniffer and the alert sensors on the `ot_gateway` container:
```bash
# Start packet sniffer and IDS rule sensors in the background
docker exec -d ot_gateway python3 /scripts/sniffer.py
docker exec -d ot_gateway python3 /detection/rules/cross_zone_traffic.py
docker exec -d ot_gateway python3 /detection/rules/modbus_anomaly.py
docker exec -d ot_gateway python3 /detection/rules/ot_brute_force.py
docker exec -d ot_gateway python3 /detection/rules/process_safety_violation.py
```

### 5. Run the Attack Simulation
Execute the simulated attacker actions from the `ot_attacker` container:
```bash
docker exec -it ot_attacker python3 /attacker/simulate_attack.py
```

---

## Verification & Results

Once the simulation completes, logs are shipped to the raw S3 bucket, SQS triggers the ingestion Lambda, and the pipeline executes:

### 1. Verify DynamoDB Alert Storage
Query the `ot_detections` table to inspect captured high-severity alert metadata:
```bash
AWS_ACCESS_KEY_ID=mock AWS_SECRET_ACCESS_KEY=mock AWS_DEFAULT_REGION=us-east-1 \
aws --endpoint-url=http://localhost:4566 dynamodb scan --table-name ot_detections
```
**Expected Output Includes:**
*   `CROSS_ZONE_VIOLATION#ot_sensor`
*   `UNAUTHORIZED_MODBUS_WRITE#ot_sensor`
*   `OT_BRUTE_FORCE_SCAN#ot_sensor`

### 2. Verify Partitioned Parquet Storage
List the staged S3 bucket to verify that telemetry records are partitioned and archived:
```bash
AWS_ACCESS_KEY_ID=mock AWS_SECRET_ACCESS_KEY=mock AWS_DEFAULT_REGION=us-east-1 \
aws --endpoint-url=http://localhost:4566 s3 ls s3://ot-telemetry-staged-000000000000 --recursive
```
**Expected Parquet Output Keys:**
*   `parsed/date=2026-05-20/source=iptables/<UUID>.snappy.parquet`
*   `parsed/date=2026-05-20/source=ot_sensor/<UUID>.snappy.parquet`