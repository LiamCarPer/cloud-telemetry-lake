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
| Data at rest read from S3/SQS/DynamoDB | SSE-KMS with a CMK; bucket public-access block; TLS-only bucket policy | One CMK for the lab; production should split data/logs/secrets keys |
| Poison message loops forever | SQS redrive after 3 receives; aggregator stream retries capped at 3 with bisect + on-failure DLQ | Parser's S3 DLQ stores unparseable lines but does not alarm directly; DLQ depth alarm covers SQS |
| Pipeline silently stops | Alarms on Lambda errors/throttles, queue age, DLQ depth → ops SNS topic | No paging integration in the lab; email subscription is optional |
| Malicious CI dependency/action | Actions pinned to SHAs, read-only `GITHUB_TOKEN`, Dependabot, dependency review, pip-audit, Checkov, Bandit, gitleaks | No SBOM or artifact signing; no OIDC deploy role yet |

## IAM design

- Two execution roles, one per function. The parser can read raw objects,
  write staged Parquet and DLQ records, write detections, and read/update the
  state table. The aggregator can read the detection stream, write reports and
  publish incident alerts.
- Both roles attach `ot-lambda-permissions-boundary`, a deny-by-default
  ceiling that lists only the services and actions either function needs.
- Log permissions are scoped to the two function log groups, not
  `arn:aws:logs:*:*:*`.
- `dynamodb:Scan` and `dynamodb:DeleteItem` were removed; the parser never
  used them. `dynamodb:BatchGetItem` was added because the state store does
  use it (it was missing before).
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
| S3 (raw, staged, reports, DLQ) | SSE-KMS with `alias/ot-telemetry`, bucket keys enabled |
| SQS (ingest, ingest DLQ, aggregator DLQ) | SSE-KMS with the same CMK |
| DynamoDB (detections, state) | SSE-KMS with the same CMK; PITR enabled |
| CloudWatch Logs | CMK-encrypted log groups, 14-day retention |
| Secrets Manager | CMK-encrypted secret |
| SNS (incident, ops) | SSE with the AWS-managed SNS key |
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
| Aggregator stream on-failure | Failed stream batches delivered to `ot-aggregator-dlq` |

All alarms publish to `ot-ops-alerts`. Set `ops_alert_email` to receive mail
in a real account. The incident topic remains separate for SOC-facing alerts.
`ot-ops-alerts-sink` (SQS) is a LocalStack verification target so alarm
delivery can be proven without email credentials (`make alarm-test`).

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
| CloudTrail with log-file validation + KMS | LocalStack Ultimate-tier only |
| GuardDuty, Security Hub, AWS Config rules, IAM Access Analyzer | Not implemented by LocalStack Community; require a real account |
| SCP guardrails and permission-set boundaries | Organizations-level, outside a single lab account |
| VPC endpoints for S3/SQS/DynamoDB/Secrets Manager | Lambda runs outside a VPC in the lab |
| AWS WAF / public ingress controls | No public ingress exists |
| Automated secret rotation Lambda | Runbook first; rotation is a follow-up project |
| Break-glass role and incident-response playbook | Organizational process, not infrastructure |

## Verification

```bash
make test                 # 57 unit tests, including security invariants
make validate             # terraform fmt/validate
make security             # bandit, pip-audit, checkov
make seed-secret          # requires ABUSEIPDB_API_KEY in the shell
aws --endpoint-url=http://localhost:4566 cloudwatch describe-alarms
aws --endpoint-url=http://localhost:4566 secretsmanager describe-secret \
  --secret-id ot-telemetry/abuseipdb
```

The unit suite includes `tests/test_security_invariants.py`, which fails if a
wildcard log resource, `dynamodb:Scan`/`DeleteItem`, a plaintext secret
variable, a missing permissions boundary, or a missing failure alarm is
reintroduced.

## Live verification (2026-10-19, LocalStack 4.14.0)

- `terraform apply` completed with the security resources in place: KMS alias,
  Secrets Manager secret, permissions boundary, 5 queues, 5 alarms, encrypted
  log groups, S3 versioning/lifecycle, and SSE-KMS/SQS/DynamoDB settings.
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

**Not verified locally:** IAM policy enforcement (paid LocalStack feature),
DynamoDB PITR status/restore (LocalStack does not report it), CloudTrail and
the other production-baseline services. These remain stated limitations rather
than claims.
