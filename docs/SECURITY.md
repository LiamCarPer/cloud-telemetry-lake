# Security design and residual risk

This document is the engineering counterpart to [`SECURITY.md`](../SECURITY.md):
what the stack protects, how, what is verified, and what is deliberately left
for a production account.

## Scope and assumptions

- **Data**: synthetic OT telemetry from the lab and Suricata EVE fixtures.
  No customer data, no real plant traffic.
- **Runtime**: LocalStack Community emulation. IAM policy *enforcement* is a
  LocalStack paid-tier feature, so the policies here are reviewed and linted,
  not proven by denied calls.
- **Trust boundaries**: OT gateway/Fluent Bit → S3 raw; S3 → SQS → parser
  Lambda; Lambda → DynamoDB/S3 staged; DynamoDB Streams → aggregator Lambda;
  aggregator → S3 reports/SNS; CI → repository (no deploy credentials).
- **Adversary model**: malformed or oversized telemetry, a compromised
  producer writing to the wrong bucket/prefix, credential leakage from the
  repository or Lambda environment, and supply-chain compromise of a CI
  action or Python dependency. Physical/OT process attacks are out of scope.

## Threat model

| Threat | Control | Residual risk |
| :-- | :-- | :-- |
| Attacker ships a huge object to exhaust Lambda `/tmp` or timeout | `MAX_OBJECT_BYTES` check on the S3 event size; oversized objects retry then land in the SQS DLQ | Event size is trusted from the S3 notification; queue policy pins the source bucket and account |
| Object arrives from an unexpected bucket | Parser refuses any bucket other than `RAW_BUCKET` | Would alert only via Lambda error/DLQ alarm |
| Credential/API key committed to git | `.gitignore` for env/keys, gitleaks in CI, secret value lives only in Secrets Manager | A key pasted into an unrelated file can still evade regexes; rotate immediately if leaked |
| API key visible in Terraform state or Lambda env | Secret *container* only in Terraform; Lambda receives the secret ARN; value set out of band | Anyone with `lambda:GetFunctionConfiguration` sees the ARN, not the value; state does not contain the key |
| Stolen Lambda credentials | Scoped identity policies + permissions boundary; no `Scan`, `DeleteItem`, wildcard logs or unused bucket reads | LocalStack does not enforce IAM; production must verify with IAM Access Analyzer / policy simulator |
| Identity attack (root use, no-MFA login, key creation, IAM changes, log tampering) | CloudTrail management-event rules and GuardDuty finding normalization feed the same detections and NIST reports | Seven management-event rules only; no data events or benign baseline; CloudTrail/GuardDuty services are not exercised locally |
| Kubernetes identity/runtime attack (exec, privileged pods, RBAC escalation, runtime shell) | Audit-log rules, Falco event normalization and a kind audit lab feed the same detections/reports | Eight audit rules; no admission/posture; Falco is fixture/SQS-tested; EKS managed audit delivery is documented only |
| Data at rest read from S3/SQS/DynamoDB | SSE-KMS with a CMK; bucket public-access block; TLS-only bucket policy | One CMK for the lab; production should split data/logs/secrets keys |
| Poison message loops forever | SQS redrive after 3 receives; aggregator stream retries capped at 3 with bisect + on-failure DLQ | Parser's S3 DLQ stores unparseable lines but does not alarm directly; DLQ depth alarm covers SQS |
| Pipeline silently stops | Alarms on Lambda errors/throttles, queue age, DLQ depth → ops SNS topic | No paging integration in the lab; email subscription is optional |
| Malicious CI dependency/action | Actions pinned to SHAs, read-only `GITHUB_TOKEN`, Dependabot, dependency review, pip-audit, Checkov, Bandit, gitleaks | No SBOM or artifact signing; no OIDC deploy role yet |

## IAM design

- Six execution roles: parser, aggregator, identity detector, Kubernetes
  detector, vulnerability processor and vulnerability reporter. The parser can
  read raw objects, write staged Parquet and DLQ records, write detections, and
  read/update the state table. The aggregator can read the detection stream,
  write reports and publish incident alerts. The identity detector can read
  CloudTrail objects and consume the identity/GuardDuty queues. The Kubernetes
  detector can read audit objects, consume the K8s/Falco queues, write
  detections and stage Kubernetes records. The vulnerability processor can read
  scanner/inventory objects, write staged/DLQ objects, and manage the
  vulnerability/CVE/cache tables. The reporter can query the findings table and
  `status-index`, write `remediation/*`, and publish to its topic.
- All six roles attach `ot-lambda-permissions-boundary`, a deny-by-default
  ceiling that lists only the services and actions the functions need.
- Log permissions are scoped to the six function log groups, not
  `arn:aws:logs:*:*:*`.
- `dynamodb:Scan` and `dynamodb:DeleteItem` were removed; the parser never
  used them. `dynamodb:BatchGetItem` was added because the state store does
  use it (it was missing before). The vulnerability reporter uses
  `dynamodb:Query` on `status-index`; a static test fails if `Scan` returns.
- Queue/resource policies pin `aws:SourceArn` and `aws:SourceAccount`.
- **Trust policies do not carry `aws:SourceAccount` conditions.** Lambda
  execution-role trust does not support those condition keys; adding them
  would be cargo cult. The boundary plus scoped policies are the controls.

## Secrets lifecycle

1. **Provision** — `terraform apply` creates the secret container
   `ot-telemetry/abuseipdb`, encrypted with the CMK. No version is created, so
   no value enters state.
2. **Seed** — an operator runs `make seed-secret` with `ABUSEIPDB_API_KEY` in
   their shell, or the AWS CLI `put-secret-value` against real AWS.
3. **Read** — the parser Lambda reads the secret at cold start and caches it
   in memory. If the read fails or the secret is absent, enrichment is
   disabled and the pipeline continues (fail closed, not fail open).
4. **Rotate** — put a new version with `put-secret-value`; new Lambda
   environments pick it up at cold start. Force a refresh by updating a
   function environment variable or redeploying. There is no rotation Lambda
   yet; that is the next step for production.
5. **Revoke** — disable/delete the secret version and rotate the upstream
   AbuseIPDB key.

## Encryption

| Service | Configuration |
| :-- | :-- |
| S3 (raw, staged, reports, DLQ, identity, Kubernetes, vulnerability) | SSE-KMS with `alias/ot-telemetry`, bucket keys enabled |
| SQS (ingest, ingest DLQ, aggregator DLQ, identity, GuardDuty, K8s, Falco, vulnerability) | SSE-KMS with the same CMK |
| DynamoDB (detections, state, vulnerabilities, CVEs, enrichment cache) | SSE-KMS with the same CMK; PITR enabled |
| CloudWatch Logs | CMK-encrypted log groups, 14-day retention |
| Secrets Manager | CMK-encrypted secret |
| SNS (incident, ops, vulnerability reports) | SSE with the AWS-managed SNS key |
| Lambda environment variables | Encrypted with the CMK (`kms_key_arn`) |

**Tradeoff:** one CMK keeps key-policy review simple in a lab. Production
should use separate keys for data, logs and secrets so a key-policy mistake or
deletion has a smaller blast radius.

## Monitoring and response

| Alarm | Meaning |
| :-- | :-- |
| `ot-parser-errors` | Parser invocations failing; detections may be delayed |
| `ot-parser-throttles` | Concurrency cap reached; ingestion is falling behind |
| `ot-aggregator-errors` | Detections are not becoming incident reports |
| `ot-ingest-queue-age` | Oldest message older than 5 minutes |
| `ot-ingest-dlq-depth` | Messages exhausted retries |
| `ot-vuln-processor-errors` | Vulnerability processor failing; scanner findings may be lost |
| `ot-vuln-queue-age` | Scanner exports waiting more than 10 minutes |
| `ot-vuln-dlq-depth` | Vulnerability exports exhausted retries |
| `ot-vuln-report-errors` | Remediation reporter failing; scheduled reports may not arrive |
| Aggregator stream on-failure | Failed stream batches delivered to `ot-aggregator-dlq` |

All alarms publish to `ot-ops-alerts`. Set `ops_alert_email` to receive mail
in a real account. The incident topic remains separate for SOC-facing alerts.
`ot-ops-alerts-sink` (SQS) is a LocalStack verification target so alarm
delivery can be proven without email credentials (`make alarm-test`).

## Identity detection plane

- **CloudTrail (management events):** the trail is gated by
  `enable_cloudtrail` because LocalStack supports CloudTrail only on its
  Ultimate tier. Logs land in `ot-identity-raw-<account>` → identity queue →
  identity Lambda. Seven rules cover root use, console login without MFA,
  access-key creation, IAM policy changes, CloudTrail tampering, GuardDuty
  tampering and console brute force.
- **GuardDuty:** the detector is gated by `enable_guardduty` because LocalStack
  does not emulate it. Findings flow through an EventBridge rule → SQS →
  identity Lambda and are normalized with finding type, severity,
  principal/resource, remote IP and ATT&CK tactic. GuardDuty is a managed
  detector; the repo does not claim custom GuardDuty rule authoring.
- **Shared model:** detections carry `detection_domain = "identity"`. Reports
  separate `mitre_techniques_by_framework = {ics, enterprise}` and list
  `mitre_tactics` separately. GuardDuty findings have tactics but no invented
  technique IDs.
- **Local verification:** the real services are not run locally. The S3 path is
  exercised with committed CloudTrail fixtures and the EventBridge path with a
  GuardDuty-shaped `put-events` call. The trail/detector resources are
  Terraform-validated only.

## Kubernetes detection plane

- **Audit logs:** API-server audit policy → Fluent Bit → `ot-k8s-raw-<account>`
  → SQS → Kubernetes Lambda. Eight rules cover exec/attach, privileged pods,
  sensitive hostPath mounts, cluster-admin bindings, secret access,
  service-account tokens, anonymous access, RBAC changes and admission-webhook
  tampering.
- **Runtime:** Falco/Falcosidekick JSON → SQS → the same Lambda. Falco owns the
  runtime rules; the pipeline normalizes rule/priority/namespace/pod/process
  and maps selected rules to ATT&CK for Containers techniques.
- **EKS:** GuardDuty EKS Runtime Monitoring findings flow through the existing
  GuardDuty path and are tagged `kubernetes` / `containers`. EKS audit-log
  delivery through CloudWatch Logs → Firehose is documented as a production
  integration, not built locally.
- **Lab proof:** `lab/kubernetes/` runs a kind cluster with API-server audit
  logging, demo attack manifests and a Fluent Bit S3 shipper. The live run
  produced exec, secret, privileged-pod, hostPath, cluster-admin and
  service-account-token detections. It also exposed two tuning bugs:
  `kubectl exec` is logged with verb `get` and two stages per `auditID`, and
  anonymous `/readyz` probes must be excluded. Both are fixed and
  regression-tested.
- **Not implemented:** admission policy (Kyverno/OPA), image scanning,
  network policy, service mesh, multi-cluster, live Falco DaemonSet.

## Vulnerability management plane

- **Ingestion:** Nessus `.nessus` XML and Qualys VM XML/JSON arrive in
  `ot-vuln-raw-<account>` and flow through SQS to the vulnerability processor.
  XML parsing rejects `<!DOCTYPE` and `<!ENTITY` declarations before calling
  `ElementTree`, preventing external-entity expansion without adding a
  dependency that is absent from the Lambda bundle.
- **Normalization and dedup:** source rows are keyed by scanner, asset, plugin,
  port and protocol. The report key is asset + primary CVE + port + protocol,
  so the same issue from Nessus and Qualys becomes one remediation item with a
  merged source list and evidence. Findings without a CVE or with different
  ports remain separate; this is documented as a heuristic.
- **Enrichment:** EPSS comes from FIRST with a DynamoDB TTL cache; KEV comes
  from the public CISA catalog. Both calls fail open with a warning, and a
  missing EPSS value is recorded as missing rather than fabricated. A missing
  CVSS value is estimated from scanner severity and marked `cvss_estimated`.
- **Scoring and SLA:** `40% CVSS + 30% EPSS + 30% asset criticality + 10%
  KEV/exploit bonus`, buckets `CRITICAL >= 80`, `HIGH >= 60`, `MEDIUM >= 40`,
  `LOW < 40`, and SLA due dates of 7/30/90/180 days. The score components are
  stored on every finding so a prioritization decision can be explained.
- **Lifecycle:** `first_seen` is the earliest scanner observation and never
  moves forward; `last_seen` never moves backward; `accepted` and
  `false_positive` statuses survive re-scans. Findings are never closed
  automatically, and there is no reconciliation job.
- **Storage and reporting:** findings live in `ot_vulnerabilities` with
  `asset-index`, `priority-index`, `status-index` and `scan-index`; CVE lookup
  is `ot_vulnerability_cves`; enrichment cache is `ot_enrichment_cache`.
  The reporter queries `status-index` rather than scanning, writes
  JSON/CSV/Markdown to the reports bucket, and publishes a summary to
  `ot-vuln-reports`. The daily schedule is gated by `enable_vuln_reports`.
- **IAM:** separate ingest and report roles, both with the permissions boundary.
  The processor can read the scanner bucket, write staged/DLQ objects and
  manage only the three vulnerability tables. The reporter can query the
  findings table/index, write `remediation/*`, and publish to its topic.
- **Not implemented:** NVD/CPE fallback, CMDB integration, automatic closure or
  reconciliation, patch automation, and a scanner API pull. The inventory is a
  single S3 CSV/JSON object.

## CI/CD supply chain

- Every action is pinned to a **full commit SHA** with a version comment;
  Dependabot proposes updates.
- Workflow token permissions are `contents: read`; checkout does not persist
  credentials.
- Jobs: unit tests, `terraform fmt`/`validate`, gitleaks (secret history),
  Bandit (Python SAST), pip-audit (dependency CVEs), Checkov (Terraform),
  dependency review on pull requests.
- Checkov skips are explicit and justified in `.checkov.yaml`; they are
  accepted lab risks or annotation limitations, not silent suppressions.

**Not implemented:** OIDC-based deployment to AWS, remote Terraform state with
locking, SBOM generation, artifact signing/provenance, and branch protection
as code. Adding an OIDC deploy role without a real AWS account would be
untested configuration, so it is listed here instead.

## Production baseline (not in this stack)

| Control | Why it is missing here |
| :-- | :-- |
| Security Hub, AWS Config rules, IAM Access Analyzer | Not implemented by LocalStack Community; require a real account |
| EKS audit-log delivery (CloudWatch Logs → Firehose → S3) | Documented production integration; no EKS cluster is created. |
| Admission policy (Kyverno/OPA) and posture (kube-bench/Trivy/Kubescape) | Separate preventive/posture products; out of scope for this detection plane. |
| Live Falco/Tetragon DaemonSet | Falco events are fixture/SQS-tested; a live eBPF DaemonSet was not added. |
| SCP guardrails and permission-set boundaries | Organizations-level, outside a single lab account |
| VPC endpoints for S3/SQS/DynamoDB/Secrets Manager | Lambda runs outside a VPC in the lab |
| AWS WAF / public ingress controls | No public ingress exists |
| Automated secret rotation Lambda | Runbook first; rotation is a follow-up project |
| Break-glass role and incident-response playbook | Organizational process, not infrastructure |

## Verification

```bash
make test                 # 136 unit tests, including security invariants
make validate             # terraform fmt/validate
make security             # bandit, pip-audit, checkov
make seed-secret          # requires ABUSEIPDB_API_KEY in the shell
make identity-demo        # CloudTrail fixtures + a GuardDuty EventBridge event
make k8s-demo             # Kubernetes audit + Falco fixtures
make vuln-demo            # Nessus/Qualys + inventory fixtures
make vuln-report          # JSON/CSV/Markdown remediation report
aws --endpoint-url=http://localhost:4566 cloudwatch describe-alarms
aws --endpoint-url=http://localhost:4566 secretsmanager describe-secret \
  --secret-id ot-telemetry/abuseipdb
```

The unit suite includes `tests/test_security_invariants.py`, which fails if a
wildcard log resource, `dynamodb:Scan`/`DeleteItem`, a plaintext secret
variable, a missing permissions boundary, or a missing failure alarm is
reintroduced.

## Live verification (2026-10-25, LocalStack 4.14.0)

- `terraform apply` completed with the security resources in place: KMS alias,
  Secrets Manager secret, permissions boundary, 16 queues, 17 alarms, 6 Lambda
  functions, 7 S3 buckets, encrypted log groups, S3 versioning/lifecycle, and
  SSE-KMS/SQS/DynamoDB settings.
- The parser processed a gzipped Malcolm fixture (4 records → staged Parquet)
  and a sensor event that produced 2 detection records.
- The aggregator produced deterministic, window-anchored reports. The verified
  report contained `mitre_techniques = ["T0831", "T0886"]`, populated
  `affected_assets.source_ips`, and matching `window_start`/`window_end`; SNS
  delivered the notification to the subscribed queue.
- A forced cold start logged `Loaded AbuseIPDB API key from Secrets Manager`,
  proving the secret path (the earlier failure was from a cold start before the
  secret was seeded).
- `make alarm-test` moved `ot-ingest-dlq-depth` to `ALARM` and delivered the
  state-change notification to `ot-ops-alerts-sink`.
- `make identity-demo` produced 6 identity detections: 4 from CloudTrail
  (root + no-MFA, access-key creation, CloudTrail tampering), 1 stateful
  console brute-force detection after 5 failed logins, and 1 normalized
  GuardDuty finding. Staged partitions included `source=cloudtrail` and
  `source=guardduty`; the CloudTrail report exposed `T1078.004`, `T1098.001`,
  `T1562.008` under the `enterprise` framework with tactics `TA0001`, `TA0003`,
  `TA0005`.
- The state-store live run exposed and fixed a real bug: `ttl` is a DynamoDB
  reserved word, so the original `SET ttl = :ttl` update failed silently. It now
  uses `ExpressionAttributeNames` (`#ttl`, `#hits`) with a regression test.
- `make k8s-demo` produced 9 Kubernetes detections: 7 audit rules, 1 Falco
  runtime event and 1 GuardDuty EKS finding. Staged partitions included
  `source=k8s_audit`, `source=falco` and `source=guardduty`; the audit report
  exposed `containers` techniques `T1098`, `T1552.007`, `T1562.001`, `T1609`,
  `T1611` with tactics `TA0001`–`TA0006`.
- The optional kind lab shipped a real API-server audit log through Fluent Bit
  to S3 and produced live `K8S_POD_EXEC`, `K8S_SECRET_ACCESS`,
  `K8S_PRIVILEGED_POD`, `K8S_SENSITIVE_HOSTPATH` and
  `K8S_CLUSTER_ADMIN_BINDING` detections. It exposed and fixed two tuning
  bugs: `kubectl exec` is logged with verb `get` and two stages sharing an
  `auditID`, and anonymous `/readyz` probes must be excluded.
- `make vuln-demo` produced 9 normalized findings from the committed Nessus and
  Qualys fixtures. The report contained 6 deduplicated remediation items:
  4 critical, 2 high, 3 medium, 4 KEV-flagged, and 2 SLA breaches. Staged
  Parquet landed under `vulnerabilities/scan_date=2026-10-25/source=nessus`
  and `source=qualys`; the CVE table held 9 rows. A second upload with a later
  date preserved `first_seen` (including Qualys `FIRST_FOUND`) and advanced
  `last_seen`; no finding was closed. The deployed reporter wrote
  `remediation/<id>/report.{json,csv,md}` plus `remediation/latest/` and SNS
  delivered a `[VULN] 9 open / 4 critical / 2 high` summary to
  `ot-vuln-report-sink`.

**Not verified locally:** IAM policy enforcement (paid LocalStack feature),
the CloudTrail, GuardDuty and EKS managed services (CloudTrail/GuardDuty are
gated and fixture/EventBridge-tested; EKS audit-log delivery is documented
only), live Falco/Tetragon, admission policy/posture tooling, DynamoDB PITR
status/restore, and the other production-baseline services. These remain stated
limitations rather than claims.
