# Security policy

## Reporting a vulnerability

Please do **not** open a public issue for a security problem. Use the
repository's **Security → Report a vulnerability** flow (GitHub private
vulnerability reporting) so the report stays private. Include the affected
file or resource, reproduction steps, and impact.

This is a portfolio/lab project maintained by one person. Reports are
acknowledged on a best-effort basis, normally within three business days.

## Scope

The repository processes **synthetic lab telemetry** and deploys to
LocalStack Community. It is not a production service. Do not point it at
production data, real OT networks, or a real AWS account with sensitive
workloads without completing the production hardening items in
[`docs/SECURITY.md`](docs/SECURITY.md).

## Security controls at a glance

| Area | Implementation |
| :-- | :-- |
| IAM | Per-function roles, scoped resource ARNs, a permissions boundary, no wildcard log resources, no unused `Scan`/`DeleteItem` |
| Secrets | AbuseIPDB key stored in Secrets Manager behind a customer-managed KMS key; no secret value in git or Terraform state; `make seed-secret` for the lab |
| Encryption | SSE-KMS for S3, SQS and DynamoDB; CMK-encrypted CloudWatch Logs and Secrets Manager; TLS-only S3 bucket policy |
| Monitoring | CloudWatch alarms for Lambda errors/throttles, queue age, and DLQ depth, routed to an operations SNS topic |
| Identity | CloudTrail management-event rules and GuardDuty finding normalization feed the shared detections and NIST reports; the real services are gated because LocalStack does not implement them |
| Kubernetes | Audit-log rules and Falco event normalization feed a dedicated detector; a kind audit lab proves the live path, while EKS managed logging is documented as a production integration |
| Pipeline | GitHub Actions pinned to commit SHAs, read-only token permissions, gitleaks, Checkov, Bandit, pip-audit, Dependabot, dependency review |

## Known limitations

- CloudTrail and GuardDuty are implemented in Terraform behind
  `enable_cloudtrail` / `enable_guardduty`, but LocalStack Community does not
  implement the services. Their ingestion paths are exercised with CloudTrail
  fixtures and GuardDuty-shaped EventBridge events; the real services are not
  run locally.
- Kubernetes detection covers eight audit rules plus Falco normalization. It
  does not include admission policy, image scanning, network policy, service
  mesh or multi-cluster management. The kind audit lab is optional and manual;
  EKS managed audit-log delivery is documented, not built.
- Security Hub, AWS Config, IAM Access Analyzer, SCPs and VPC endpoints remain
  out of scope and are documented as the production baseline.
- LocalStack Community does not enforce IAM policies. Policies are reviewed,
  linted and unit-guarded, but their enforcement is not exercised locally.
- Secret rotation is a documented manual runbook, not an automated rotation
  Lambda.
- The stack uses LocalStack `mock` credentials by default; they are never
  valid AWS credentials.

See [`docs/SECURITY.md`](docs/SECURITY.md) for the threat model, control
matrix and residual risks.
