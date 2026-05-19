Product Requirements Document (PRD)

Product: OT Telemetry Data Lake & Detection-as-Code on AWS
Owner: Liam Carvajal
Status: Draft
Last Updated: 2026-05-19
1. Overview
1.1 Summary

Build a cloud-based OT telemetry platform that ingests security and operational data from a Purdue-modeled OT lab and Malcolm NDR stack into an AWS data lake on S3. The pipeline evolves from direct S3 triggers to an SQS-buffered architecture, normalizing and enriching data using serverless detection-as-code (Lambda + DynamoDB), and exposing it for hunting via Glue/Athena and optional visualization via Grafana.
1.2 Problem Statement

Current OT security lab and NDR pipelines are entirely on-prem / local, limiting:

    Demonstration of AWS-native logging and analytics skills.

    Realistic hybrid OT→Cloud threat detection and incident response.

    Alignment with modern Blue Team expectations for cloud data lakes and serverless detection.

We need a production-style but cost-efficient architecture that shows cloud-native ingestion, normalization, correlation, and investigation workflows for OT environments using AWS primitives and open-source tooling.
1.3 Goals & Non‑Goals

Goals

    G1: Ingest OT and NDR telemetry into an AWS S3 data lake in near real time via OSS shippers, using SQS for batching and failure isolation.

    G2: Normalize/enrich logs using serverless detection-as-code built on the existing Log Parser Toolkit, saving curated data as Parquet.

    G3: Persist detections and transient correlation state in DynamoDB using atomic counters and TTL.

    G4: Provide analysts with SQL-based hunting via Glue Data Catalog + Athena and optional visualization via Grafana over Athena.

    G5: Automatically generate NIST-style incident reports and trigger SNS alerts from correlated detections.

Non‑Goals (explicitly out of scope)

    NG1: Production multi-account Lake Formation governance; we focus on a single-account, lab-grade but secure setup.

    NG2: Complex Spark-based ETL pipelines; we use Lambda, lightweight transformations, and simple JSON/Parquet.

    NG3: Real customer data ingestion; this is strictly lab-generated OT and synthetic traffic.

1.4 Success Metrics

    Functional:

        ≥ 95% of OT-lab and Malcolm log sources successfully land in the S3 “raw” zone within 30 seconds of generation.

        P95 end-to-end detection latency (log generated → detection written to DynamoDB) ≤ 5 seconds under lab load.

    Reliability:

        Pipeline achieves ≥ 99% successful Lambda execution rate over 7-day test periods.

    Security:

        All S3 buckets encrypted; IAM roles scoped by least privilege; no public buckets or security findings in AWS security tools.

    Usability:

        Analysts can run ad-hoc Athena queries over normalized logs and detections with a median query time under 10 seconds for common hunts.

2. Users, Actors, and Use Cases
2.1 Actors / Personas

    Security Engineer / Detection Engineer (primary)
    Develops and tunes detection rules, validates coverage against OT attack simulations, and extends the parser/detection-as-code.

    SOC Analyst / Threat Hunter
    Uses Athena and Grafana dashboards to investigate incidents, pivot across OT and NDR telemetry, and consume NIST-style IR reports.

    Platform / Cloud Engineer (you)
    Owns IaC, AWS security posture, and operation of the data lake and serverless detection pipeline.

    System Services

        Fluent Bit / other shippers in OT lab.

        Malcolm NDR components.

        AWS services: S3, SQS, Lambda, DynamoDB, Glue, Athena, SNS.

2.2 Primary Use Cases

    UC1 – OT Telemetry Ingestion
    OT lab components emit logs and NDR alerts; shippers batch and upload them to S3 “raw”, triggering parser Lambdas.

    UC2 – Detection-as-Code on Ingest
    Lambda functions stream-process S3 objects using the Log Parser Toolkit, emit normalized events to S3 “staged”, and write detection records/state to DynamoDB.

    UC3 – Threat Hunting & Investigation
    Analysts query normalized Parquet logs via Athena and view detections/metrics in Grafana dashboards.

    UC4 – Automated Incident Report Generation
    DynamoDB Streams triggers an incident Lambda that correlates detections, invokes the NIST report generator, and uploads reports into S3 “reports”.

3. Scope & Feature Breakdown
3.1 In Scope (Initial Release)

    S3-based Telemetry Lake

        Raw/staged/reports buckets and a Dead Letter Queue (DLQ) bucket with secure configuration and sensible partitioning (e.g., source/date=YYYY/MM/DD).

    Serverless Parsing & Normalization

        One or more Lambda functions that:

            Consume batches from an SQS queue (triggered by S3 events).

            Use Log Parser Toolkit to parse and enrich logs.

            Write curated Parquet artifacts to S3 “staged” and route malformed logs to the DLQ.

    Detection & State Persistence

        DynamoDB tables for detection records and rolling-window state.

        Log Parser Toolkit middleware updated to support a DynamoDB state backend.

    Incident Grouping & Reporting

        DynamoDB Streams → Lambda that groups detections into incidents and calls NIST report generator (from Malcolm pipeline), storing outputs in S3 “reports”.

    Glue & Athena Integration

        Glue database and external tables (or crawlers) for normalized logs and detections.

        Validated example Athena queries for common OT hunts.

    Basic Grafana Integration (Optional but Targeted)

        Lightweight Grafana dashboard running locally or via ECS.

        Queries Athena directly for visualizations.

    Infrastructure as Code

        Terraform/OpenTofu modules for all AWS resources (S3, SQS, IAM, Lambda, DynamoDB, Glue, Athena, SNS, CloudWatch logging).

        Basic static scanning (Checkov/tfsec).

3.2 Out of Scope (Initial Release)

    Automated Lake Formation fine-grained table-level governance.

    Multi-region replication and disaster recovery.

    Fully managed CI/CD pipelines (manual terraform apply is acceptable initially; can be added later).

4. Functional Requirements
4.1 S3 Telemetry Lake

    FR1: Create three S3 buckets:

        ot-telemetry-raw-<account-id> for ingest from OT lab and Malcolm.

        ot-telemetry-staged-<account-id> for normalized/enriched logs.

        ot-telemetry-reports-<account-id> for incident reports.

    FR2: Buckets must:

        Use SSE-S3 encryption at rest and TLS in transit.

        Deny public access via bucket policies and account-level blocking.

        Optionally, apply lifecycle policies to transition older logs to cheaper storage classes.

    FR3: S3 “raw” must emit event notifications on ObjectCreated events to an SQS queue. A parser Lambda then consumes these events in batches for improved scalability and failure isolation. (Note: Initial PoC supported direct S3 event processing; final design evolved to S3 -> SQS -> Lambda).

4.2 OT & NDR Ingestion

    FR4: OT Lab components use Fluent Bit (or equivalent) to:

        Tail iptables, syslog, OT detection logs.

        Serialize as JSON lines.

        Periodically upload to S3 “raw” with keys including source and date partitions.

    FR5: Malcolm SOAR pipeline:

        Compresses normalized Suricata/Zeek alerts into gzip’d JSON or Parquet.

        Uploads files to ot-telemetry-raw-<account-id>/malcolm/date=....

4.3 Parser & Detection Lambda

    FR6: Parser Lambda:

        Consumes event batches from the SQS queue triggered by S3 “raw” object creation.

        Streams S3 object content line-by-line (no full-file in-memory).

        Invokes parse_stream from Log Parser Toolkit with a configured middleware stack.

        Writes curated Parquet artifacts to S3 “staged” (partitioned by date/source) for optimized Athena scanning.

        Routes malformed or unparseable logs to a dedicated DLQ bucket.

        For any record marked as a detection, writes a corresponding row into ot_detections DynamoDB table.

    FR7: Log Parser Toolkit must support:

        A pluggable state backend with DynamoDB implementation.

        Middleware functions for:

            Rolling-window correlation.

            Threat-intel enrichment (AbuseIPDB).

            Protocol-aware OT anomaly classification.

4.4 Detection Storage & State

    FR8: DynamoDB ot_detections table:

        Stores detection ID, timestamp, severity, source, host, OT asset identifiers, and link to S3 evidence.

        Enables querying by severity and time windows via GSI(s).

    FR9: DynamoDB ot_detection_state table:

        Maintains state required for rolling-window logic (e.g., repeated failures, scan patterns) using atomic counters (UpdateItem).

        Uses DynamoDB Time To Live (TTL) to automatically expire short-lived window state.

4.5 Incident Grouping & Report Generation

    FR10: Enable DynamoDB Streams on ot_detections and configure an incident-aggregator Lambda as consumer.

    FR11: incident-aggregator Lambda:

        Groups detections by correlation ID/time window.

        Invokes existing NIST report generator library (from Malcolm pipeline) with detection bundle.

        Writes generated IR artifacts to ot-telemetry-reports-<account-id>/incidents/<id>.json (and optional HTML/PDF).

        Publishes an alert to an SNS topic to notify the SOC of a new incident.

4.6 Glue & Athena

    FR12: Create Glue database ot_telemetry and tables (via crawlers or DDL) for:

        Normalized logs in S3 “staged”.

        Detection records (either directly from DynamoDB via exports or from S3 copies).

    FR13: Configure Athena workgroup(s) for querying ot_telemetry tables.

    FR14: Provide documented example queries and saved queries for:

        High-severity OT anomalies over time.

        Top noisy hosts.

        OT-specific TTP patterns (e.g., illegal Modbus function codes).

4.7 Grafana Integration (Optional/Phase 2)

    FR15: Deploy a lightweight Grafana instance (e.g., local Docker container or ECS Fargate).

    FR16: Configure the Athena data source in Grafana to query the ot_telemetry database.

    FR17: Configure 1–2 basic dashboards for:

        Detections over time by severity.

        Top speaking OT assets / communications.

5. Non‑Functional Requirements

    Security

        All IAM roles follow least privilege.

        All data encrypted at rest (SSE-S3, DynamoDB SSE) and in transit (HTTPS).

        No public S3 buckets.

    Performance

        Parser Lambda cold start ≤ a few seconds; warm-start processing throughput suited for at least 10k events/min within lab.

        Athena queries on recent data return in ≤ 10 seconds for typical filters.

    Scalability

        Architecture should scale with increased OT log volume simply by adjusting Lambda memory/concurrency and S3 usage; no redesign required.

    Cost

        All core services must remain within AWS Free Tier or near-negligible monthly cost by using light lab volumes (small buckets, minimal Glue use, single small OpenSearch domain).

    Operability

        CloudWatch logs/metrics configured for Lambda, S3 errors, and DynamoDB throttling with basic alarms.

        Terraform plan/apply should deploy the entire stack in < 20 minutes.

6. Architecture Overview
6.1 High-Level Components

    Data Producers

        OT Lab (Dockerized Purdue model) emitting logs.

        Malcolm NDR stack emitting alerts and flow/metadata.

    Ingestion & Storage

        Fluent Bit / Python scripts pushing batched logs to ot-telemetry-raw.

        S3 “raw” → S3 Event Notifications → SQS queue.

    Processing & Detection

        Parser Lambda consumes SQS batches (Log Parser Toolkit library + middleware).

        Writes curated Parquet to S3 “staged” and malformed logs to DLQ.

        DynamoDB for detection/event state (using TTL and atomic counters).

    Analytics & Consumption

        S3 “staged” + Glue + Athena for SQL-based hunting.

        Optional Grafana dashboard over Athena.

    IR & Reporting

        DynamoDB Streams → incident Lambda → NIST report generator → S3 “reports”.

        SNS topic for incident alerting.

6.2 Data Zones

Align with AWS best practice for data lake zones:

    Raw zone: ot-telemetry-raw – minimal or no transformation, per-source partitioning.

    Processed/Staged zone: ot-telemetry-staged – normalized/enriched Parquet.

    Curated zone: ot-telemetry-reports – incident-level artifacts and reports.

7. Data Model (High-Level)
7.1 Normalized Log Schema (S3 Staged)

Fields (Parquet):

    timestamp, source, host, zone, event_type, severity

    src_ip, src_port, dest_ip, dest_port, protocol

    OT-specific: plc_id, register, function_code, value, etc.

    raw_log_ref (S3 key of original event).

7.2 Detection Record Schema (DynamoDB)

    PK: pk = incident_correlator or host#src_ip.

    SK: sk = ISO8601 timestamp.

    Attributes:

        severity, event_type, rules_triggered (list), message

        source, host, zone, OT asset identifiers

        s3_evidence_key

        ti_matches (AbuseIPDB values, etc.)

8. Dependencies & Integration

    Existing codebases:

        OT-Security-Lab (Docker, iptables logs, Modbus anomaly detections).

        Log Parser Toolkit (Python, generator/middleware-based parsing).

        Malcolm NDR pipeline (Suricata, Arkime, Python SOAR + NIST reports).

    AWS services:

        S3, SQS, Lambda, DynamoDB, Glue, Athena, SNS, CloudWatch.

    OSS tooling:

        Fluent Bit or similar log shipper.

        Terraform/OpenTofu.

        Checkov/tfsec for IaC linting.

9. Rollout Plan / Phases

    Phase 1 – Skeleton

        Buckets, IAM, one parser Lambda.

        Manual upload of sample OT logs → verify S3→SQS→Lambda→S3 staged path.

    Phase 2 – OT Lab Integration

        Add Fluent Bit to OT lab, stream logs to S3 “raw”.

        Implement detection writes to DynamoDB.

    Phase 3 – NDR & Incidents

        Wire Malcolm to S3 “raw”.

        Add DynamoDB Streams + incident Lambda + NIST report generation.

    Phase 4 – Analytics Layer

        Glue catalog + Athena tables/views.

        A few saved queries and optionally a Grafana dashboard.

10. Risks & Open Questions

    Grafana hosting: need to decide whether to run Grafana locally for demos or host it lightweight in ECS Fargate to minimize costs.

    DynamoDB throttling: high write rates from parser Lambda could require provisioning adjustments; mitigated by lab-scale load and/or buffered writes.

    Schema evolution: changes in OT/ND R log formats may require Glue table updates and migration logic; keep schemas additive and minimize breaking changes.

    Complex detection correlation: initial incident grouping will be intentionally simple (time- and asset-based), with room to grow into richer correlation rules.