# ==============================================================================
# Incident Aggregator Lambda – ot-incident-aggregator
# ==============================================================================
# Triggered by DynamoDB Streams on ot_detections. Groups incoming detection
# INSERT events into a single NIST SP 800-61 incident report, writes the
# report to the S3 reports bucket, and publishes an SNS notification.
#
# Deployment pattern follows the same S3-staged approach used for the parser
# Lambda to remain compatible with LocalStack Community Edition constraints.
# ==============================================================================

data "archive_file" "aggregator_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../src/aggregator_lambda"
  output_path = "${path.module}/../aggregator_lambda.zip"
}

resource "aws_s3_object" "aggregator_zip_upload" {
  bucket = aws_s3_bucket.telemetry_buckets["raw"].id
  key    = "aggregator_lambda.zip"
  source = data.archive_file.aggregator_zip.output_path
  etag   = filemd5(data.archive_file.aggregator_zip.output_path)
}

resource "aws_lambda_function" "aggregator_lambda" {
  s3_bucket                      = aws_s3_bucket.telemetry_buckets["raw"].id
  s3_key                         = aws_s3_object.aggregator_zip_upload.key
  function_name                  = "ot-incident-aggregator"
  role                           = aws_iam_role.aggregator_lambda_exec.arn
  handler                        = "handler.lambda_handler"
  runtime                        = "python3.12"
  timeout                        = 60
  memory_size                    = 256
  reserved_concurrent_executions = var.lambda_reserved_concurrency
  source_code_hash               = data.archive_file.aggregator_zip.output_base64sha256

  environment {
    variables = {
      REPORTS_BUCKET          = aws_s3_bucket.telemetry_buckets["reports"].id
      SNS_TOPIC_ARN           = aws_sns_topic.incident_alerts.arn
      INCIDENT_WINDOW_SECONDS = "300"
      AWS_ENDPOINT_URL        = var.localstack_endpoint
    }
  }

  kms_key_arn = aws_kms_key.telemetry.arn

  dead_letter_config {
    target_arn = aws_sqs_queue.aggregator_dlq.arn
  }

  depends_on = [aws_cloudwatch_log_group.aggregator]

  tags = {
    Environment = var.environment
    Project     = "ot-telemetry"
  }
}

resource "aws_lambda_event_source_mapping" "dynamodb_stream_trigger" {
  event_source_arn               = aws_dynamodb_table.ot_detections.stream_arn
  function_name                  = aws_lambda_function.aggregator_lambda.arn
  starting_position              = "LATEST"
  batch_size                     = 10
  enabled                        = true
  maximum_retry_attempts         = 3
  bisect_batch_on_function_error = true

  destination_config {
    on_failure {
      destination_arn = aws_sqs_queue.aggregator_dlq.arn
    }
  }
}
