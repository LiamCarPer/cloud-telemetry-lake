output "raw_bucket_name" {
  value       = aws_s3_bucket.telemetry_buckets["raw"].id
  description = "The name of the raw logs S3 bucket."
}

output "staged_bucket_name" {
  value       = aws_s3_bucket.telemetry_buckets["staged"].id
  description = "The name of the staged logs S3 bucket."
}

output "dlq_bucket_name" {
  value       = aws_s3_bucket.telemetry_buckets["dlq"].id
  description = "The name of the DLQ S3 bucket."
}

output "reports_bucket_name" {
  value       = aws_s3_bucket.telemetry_buckets["reports"].id
  description = "The name of the reports S3 bucket."
}

output "sqs_queue_url" {
  value       = aws_sqs_queue.ingest_queue.id
  description = "The URL of the ingest SQS queue."
}

output "sqs_queue_arn" {
  value       = aws_sqs_queue.ingest_queue.arn
  description = "The ARN of the ingest SQS queue."
}

output "sqs_dlq_url" {
  value       = aws_sqs_queue.ingest_dlq.id
  description = "The URL of the ingest dead-letter queue (messages that fail after retries)."
}

output "lambda_arn" {
  value       = aws_lambda_function.parser_lambda.arn
  description = "The ARN of the parser Lambda function."
}

output "aggregator_lambda_arn" {
  value       = aws_lambda_function.aggregator_lambda.arn
  description = "The ARN of the incident aggregator Lambda function."
}

output "sns_topic_arn" {
  value       = aws_sns_topic.incident_alerts.arn
  description = "The ARN of the OT incident alerts SNS topic."
}

output "incident_notifications_queue_url" {
  value       = aws_sqs_queue.incident_notifications.id
  description = "The URL of the SQS queue subscribed to the SNS incident alerts topic (for LocalStack verification)."
}

output "kms_key_alias" {
  value       = aws_kms_alias.telemetry.name
  description = "Alias of the customer-managed KMS key used for telemetry data, logs and secrets."
}

output "abuseipdb_secret_arn" {
  value       = aws_secretsmanager_secret.abuseipdb.arn
  description = "ARN of the Secrets Manager secret holding the AbuseIPDB API key (value is set out of band)."
}

output "ops_alerts_topic_arn" {
  value       = aws_sns_topic.ops_alerts.arn
  description = "ARN of the SNS topic receiving operational CloudWatch alarms."
}

output "ops_alerts_sink_url" {
  value       = aws_sqs_queue.ops_alerts_sink.id
  description = "URL of the SQS queue subscribed to the operations alarm topic (for LocalStack verification)."
}

output "parser_log_group" {
  value       = aws_cloudwatch_log_group.parser.name
  description = "CloudWatch log group for the parser Lambda."
}

output "aggregator_log_group" {
  value       = aws_cloudwatch_log_group.aggregator.name
  description = "CloudWatch log group for the incident aggregator Lambda."
}

output "identity_bucket_name" {
  value       = aws_s3_bucket.telemetry_buckets["identity"].bucket
  description = "S3 bucket for CloudTrail log delivery and identity fixtures."
}

output "identity_queue_url" {
  value       = aws_sqs_queue.identity_ingest.id
  description = "SQS queue carrying CloudTrail objects to the identity detector."
}

output "guardduty_queue_url" {
  value       = aws_sqs_queue.guardduty_queue.id
  description = "SQS queue carrying GuardDuty findings from EventBridge."
}

output "identity_lambda_arn" {
  value       = aws_lambda_function.identity.arn
  description = "ARN of the cloud identity detection Lambda."
}

output "cloudtrail_trail_arn" {
  value       = var.enable_cloudtrail ? aws_cloudtrail.identity[0].arn : null
  description = "CloudTrail trail ARN (null when enable_cloudtrail is false)."
}

output "guardduty_detector_id" {
  value       = var.enable_guardduty ? aws_guardduty_detector.identity[0].id : null
  description = "GuardDuty detector ID (null when enable_guardduty is false)."
}
