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

output "lambda_arn" {
  value       = aws_lambda_function.parser_lambda.arn
  description = "The ARN of the parser Lambda function."
}
