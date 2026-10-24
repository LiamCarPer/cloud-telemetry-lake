# ==============================================================================
# Identity detection plane
# ==============================================================================
# CloudTrail logs arrive through S3 -> SQS. GuardDuty findings arrive through
# EventBridge -> SQS. Both are consumed by the identity detector Lambda, which
# shares the deployed parser artifact but has its own execution role.
#
# LocalStack Community does not implement CloudTrail (Ultimate-only) or
# GuardDuty, so the trail and detector are gated behind variables. The bucket,
# queues, EventBridge rule and Lambda remain available for fixture/event tests.

# ------------------------------------------------------------------------------
# Queues
# ------------------------------------------------------------------------------

resource "aws_sqs_queue" "identity_dlq" {
  name                              = "ot-identity-dlq"
  kms_master_key_id                 = aws_kms_key.telemetry.arn
  kms_data_key_reuse_period_seconds = 300
}

resource "aws_sqs_queue" "identity_ingest" {
  name                              = "ot-identity-ingest-queue"
  receive_wait_time_seconds         = 10
  visibility_timeout_seconds        = 240 # >= identity Lambda timeout (120s) plus margin
  kms_master_key_id                 = aws_kms_key.telemetry.arn
  kms_data_key_reuse_period_seconds = 300

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.identity_dlq.arn
    maxReceiveCount     = 3
  })
}

resource "aws_sqs_queue" "guardduty_dlq" {
  name                              = "ot-guardduty-dlq"
  kms_master_key_id                 = aws_kms_key.telemetry.arn
  kms_data_key_reuse_period_seconds = 300
}

resource "aws_sqs_queue" "guardduty_queue" {
  name                              = "ot-guardduty-queue"
  receive_wait_time_seconds         = 10
  visibility_timeout_seconds        = 240
  kms_master_key_id                 = aws_kms_key.telemetry.arn
  kms_data_key_reuse_period_seconds = 300

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.guardduty_dlq.arn
    maxReceiveCount     = 3
  })
}

resource "aws_sqs_queue_policy" "identity_ingest" {
  queue_url = aws_sqs_queue.identity_ingest.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "s3.amazonaws.com" }
        Action    = "sqs:SendMessage"
        Resource  = aws_sqs_queue.identity_ingest.arn
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = aws_s3_bucket.telemetry_buckets["identity"].arn
          }
          StringEquals = {
            "aws:SourceAccount" = local.account_id
          }
        }
      }
    ]
  })
}

resource "aws_sqs_queue_policy" "guardduty_queue" {
  queue_url = aws_sqs_queue.guardduty_queue.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "events.amazonaws.com" }
        Action    = "sqs:SendMessage"
        Resource  = aws_sqs_queue.guardduty_queue.arn
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = aws_cloudwatch_event_rule.guardduty.arn
          }
          StringEquals = {
            "aws:SourceAccount" = local.account_id
          }
        }
      }
    ]
  })
}

# ------------------------------------------------------------------------------
# Ingestion wiring
# ------------------------------------------------------------------------------

resource "aws_s3_bucket_notification" "identity" {
  bucket = aws_s3_bucket.telemetry_buckets["identity"].id

  queue {
    queue_arn = aws_sqs_queue.identity_ingest.arn
    events    = ["s3:ObjectCreated:*"]
  }

  depends_on = [aws_sqs_queue_policy.identity_ingest]
}

resource "aws_cloudwatch_event_rule" "guardduty" {
  name        = "ot-guardduty-findings"
  description = "Route GuardDuty findings to the identity detection queue"

  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
  })

  tags = {
    Environment = var.environment
    Project     = "ot-telemetry"
  }
}

resource "aws_cloudwatch_event_target" "guardduty" {
  rule      = aws_cloudwatch_event_rule.guardduty.name
  target_id = "ot-guardduty-queue"
  arn       = aws_sqs_queue.guardduty_queue.arn

  depends_on = [aws_sqs_queue_policy.guardduty_queue]
}

# ------------------------------------------------------------------------------
# Gated real-AWS services
# ------------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "cloudtrail" {
  count = var.enable_cloudtrail ? 1 : 0

  name              = "/aws/cloudtrail/ot-telemetry-trail"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.telemetry.arn

  tags = {
    Environment = var.environment
    Project     = "ot-telemetry"
  }
}

resource "aws_iam_role" "cloudtrail_cloudwatch" {
  count = var.enable_cloudtrail ? 1 : 0

  name = "ot-cloudtrail-cloudwatch-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = "sts:AssumeRole"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
      }
    ]
  })
}

resource "aws_iam_policy" "cloudtrail_cloudwatch" {
  count = var.enable_cloudtrail ? 1 : 0

  name        = "ot-cloudtrail-cloudwatch-policy"
  description = "Allow CloudTrail to write trail events to CloudWatch Logs"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.cloudtrail[0].arn}:*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "cloudtrail_cloudwatch" {
  count = var.enable_cloudtrail ? 1 : 0

  role       = aws_iam_role.cloudtrail_cloudwatch[0].name
  policy_arn = aws_iam_policy.cloudtrail_cloudwatch[0].arn
}

resource "aws_cloudtrail" "identity" {
  count = var.enable_cloudtrail ? 1 : 0

  name                          = "ot-telemetry-trail"
  s3_bucket_name                = aws_s3_bucket.telemetry_buckets["identity"].id
  kms_key_id                    = aws_kms_key.telemetry.arn
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  enable_logging                = true

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail[0].arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_cloudwatch[0].arn

  depends_on = [
    aws_s3_bucket_policy.tls_enforcement,
    aws_iam_role_policy_attachment.cloudtrail_cloudwatch,
  ]
}

resource "aws_guardduty_detector" "identity" {
  count = var.enable_guardduty ? 1 : 0

  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}

# ------------------------------------------------------------------------------
# Identity Lambda and IAM
# ------------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "identity" {
  name              = "/aws/lambda/ot-identity-detector"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.telemetry.arn

  tags = {
    Environment = var.environment
    Project     = "ot-telemetry"
  }
}

resource "aws_iam_role" "identity_lambda_exec" {
  name                 = "ot-identity-lambda-exec-role"
  permissions_boundary = aws_iam_policy.lambda_permissions_boundary.arn

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = "sts:AssumeRole"
        Effect    = "Allow"
        Principal = { Service = "lambda.amazonaws.com" }
      }
    ]
  })
}

resource "aws_iam_policy" "identity_lambda_policy" {
  name        = "ot-identity-lambda-policy"
  description = "Least-privilege policy for the cloud identity detection Lambda"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "WriteFunctionLogs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.identity.arn}:*"
      },
      {
        Sid      = "UseTelemetryKeyViaAwsServices"
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey*", "kms:DescribeKey"]
        Resource = aws_kms_key.telemetry.arn
        Condition = {
          StringLike = {
            "kms:ViaService" = [
              "s3.${var.aws_region}.amazonaws.com",
              "sqs.${var.aws_region}.amazonaws.com",
              "dynamodb.${var.aws_region}.amazonaws.com",
              "logs.${var.aws_region}.amazonaws.com",
              "lambda.${var.aws_region}.amazonaws.com",
            ]
          }
        }
      },
      {
        Sid    = "ConsumeIdentityQueues"
        Effect = "Allow"
        Action = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"]
        Resource = [
          aws_sqs_queue.identity_ingest.arn,
          aws_sqs_queue.guardduty_queue.arn,
        ]
      },
      {
        Sid      = "ReadCloudTrailObjects"
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "${aws_s3_bucket.telemetry_buckets["identity"].arn}/*"
      },
      {
        Sid      = "WriteStagedTelemetry"
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:GetObject", "s3:ListBucket"]
        Resource = [aws_s3_bucket.telemetry_buckets["staged"].arn, "${aws_s3_bucket.telemetry_buckets["staged"].arn}/*"]
      },
      {
        Sid      = "WriteDeadLetterRecords"
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = [aws_s3_bucket.telemetry_buckets["dlq"].arn, "${aws_s3_bucket.telemetry_buckets["dlq"].arn}/*"]
      },
      {
        Sid      = "WriteIdentityDetections"
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem"]
        Resource = [aws_dynamodb_table.ot_detections.arn, "${aws_dynamodb_table.ot_detections.arn}/index/*"]
      },
      {
        Sid      = "ManageDetectionWindowState"
        Effect   = "Allow"
        Action   = ["dynamodb:BatchGetItem", "dynamodb:UpdateItem"]
        Resource = aws_dynamodb_table.ot_detection_state.arn
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "identity_lambda_policy_attach" {
  role       = aws_iam_role.identity_lambda_exec.name
  policy_arn = aws_iam_policy.identity_lambda_policy.arn
}

resource "aws_lambda_function" "identity" {
  s3_bucket        = aws_s3_bucket.telemetry_buckets["raw"].id
  s3_key           = aws_s3_object.lambda_zip_upload.key
  function_name    = "ot-identity-detector"
  role             = aws_iam_role.identity_lambda_exec.arn
  handler          = "identity_handler.lambda_handler"
  runtime          = "python3.12"
  timeout          = 120
  memory_size      = 512
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  reserved_concurrent_executions = var.lambda_reserved_concurrency

  environment {
    variables = {
      IDENTITY_BUCKET  = aws_s3_bucket.telemetry_buckets["identity"].id
      STAGED_BUCKET    = aws_s3_bucket.telemetry_buckets["staged"].id
      DLQ_BUCKET       = aws_s3_bucket.telemetry_buckets["dlq"].id
      AWS_ENDPOINT_URL = var.localstack_endpoint
      MAX_OBJECT_BYTES = tostring(var.max_object_bytes)
    }
  }

  kms_key_arn = aws_kms_key.telemetry.arn

  depends_on = [aws_cloudwatch_log_group.identity]

  tags = {
    Environment = var.environment
    Project     = "ot-telemetry"
  }
}

resource "aws_lambda_event_source_mapping" "identity_ingest" {
  event_source_arn        = aws_sqs_queue.identity_ingest.arn
  function_name           = aws_lambda_function.identity.arn
  batch_size              = 5
  enabled                 = true
  function_response_types = ["ReportBatchItemFailures"]
}

resource "aws_lambda_event_source_mapping" "identity_guardduty" {
  event_source_arn        = aws_sqs_queue.guardduty_queue.arn
  function_name           = aws_lambda_function.identity.arn
  batch_size              = 10
  enabled                 = true
  function_response_types = ["ReportBatchItemFailures"]
}

# ------------------------------------------------------------------------------
# Monitoring
# ------------------------------------------------------------------------------

resource "aws_cloudwatch_metric_alarm" "identity_errors" {
  alarm_name          = "ot-identity-errors"
  alarm_description   = "The identity detector is failing; CloudTrail/GuardDuty detections may be lost."
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = aws_lambda_function.identity.function_name }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.ops_alerts.arn]
  ok_actions          = [aws_sns_topic.ops_alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "identity_queue_age" {
  alarm_name          = "ot-identity-queue-age"
  alarm_description   = "CloudTrail telemetry has been waiting in the identity queue for more than five minutes."
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateAgeOfOldestMessage"
  dimensions          = { QueueName = aws_sqs_queue.identity_ingest.name }
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 300
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.ops_alerts.arn]
  ok_actions          = [aws_sns_topic.ops_alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "identity_dlq_depth" {
  alarm_name          = "ot-identity-dlq-depth"
  alarm_description   = "CloudTrail identity messages exhausted retries."
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  dimensions          = { QueueName = aws_sqs_queue.identity_dlq.name }
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.ops_alerts.arn]
  ok_actions          = [aws_sns_topic.ops_alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "guardduty_dlq_depth" {
  alarm_name          = "ot-guardduty-dlq-depth"
  alarm_description   = "GuardDuty findings exhausted retries."
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  dimensions          = { QueueName = aws_sqs_queue.guardduty_dlq.name }
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.ops_alerts.arn]
  ok_actions          = [aws_sns_topic.ops_alerts.arn]
}
