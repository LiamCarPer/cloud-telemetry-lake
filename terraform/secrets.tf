# ==============================================================================
# Secrets Manager – AbuseIPDB API key
# ==============================================================================
# Terraform creates the secret container only. The secret *value* is never
# placed in Terraform configuration or state; it is stored out of band:
#
#   aws secretsmanager put-secret-value \
#     --secret-id ot-telemetry/abuseipdb \
#     --secret-string '{"api_key":"<key>"}'
#
# `make seed-secret` wraps that command for the local lab. The parser Lambda
# reads the secret at cold start and fails closed (enrichment disabled) if it
# is missing.

resource "aws_secretsmanager_secret" "abuseipdb" {
  name                    = "ot-telemetry/abuseipdb"
  description             = "AbuseIPDB API key used by the parser Lambda for threat-intel enrichment"
  kms_key_id              = aws_kms_key.telemetry.arn
  recovery_window_in_days = 0 # lab teardown; use 7-30 in production

  tags = {
    Environment = var.environment
    Project     = "ot-telemetry"
  }
}
