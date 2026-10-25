# ==============================================================================
# Kubernetes detection plane
# ==============================================================================
# Audit logs: kubectl/API audit EventList files -> S3 -> SQS -> Lambda.
# Runtime: Falco/Falcosidekick JSON -> SQS -> the same Lambda.
#
# K8s runs outside LocalStack. The S3 and SQS paths are fully testable; no
# managed EKS resources are created here (documented as the production path).

resource "aws_sqs_queue" "k8s_dlq" {
  name                              = "ot-k8s-dlq"
  kms_master_key_id                 = aws_kms_key.telemetry.arn
  kms_data_key_reuse_period_seconds = 300
}

resource "aws_sqs_queue" "k8s_ingest" {
  name                              = "ot-k8s-ingest-queue"
  receive_wait_time_seconds         = 10
  visibility_timeout_seconds        = 240
  kms_master_key_id                 = aws_kms_key.telemetry.arn
  kms_data_key_reuse_period_seconds = 300

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.k8s_dlq.arn
    maxReceiveCount     = 3
  })
}

resource "aws_sqs_queue" "falco_dlq" {
  name                              = "ot-falco-dlq"
  kms_master_key_id                 = aws_kms_key.telemetry.arn
  kms_data_key_reuse_period_seconds = 300
}

resource "aws_sqs_queue" "falco_events" {
  name                              = "ot-falco-events-queue"
  receive_wait_time_seconds         = 10
  visibility_timeout_seconds        = 240
  kms_master_key_id                 = aws_kms_key.telemetry.arn
  kms_data_key_reuse_period_seconds = 300

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.falco_dlq.arn
    maxReceiveCount     = 3
  })
}

resource "aws_sqs_queue_policy" "k8s_ingest" {
  queue_url = aws_sqs_queue.k8s_ingest.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "s3.amazonaws.com" }
        Action    = "sqs:SendMessage"
        Resource  = aws_sqs_queue.k8s_ingest.arn
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = aws_s3_bucket.telemetry_buckets["kubernetes"].arn
          }
          StringEquals = {
            "aws:SourceAccount" = local.account_id
          }
        }
      }
    ]
  })
}

resource "aws_s3_bucket_notification" "kubernetes" {
  bucket = aws_s3_bucket.telemetry_buckets["kubernetes"].id

  queue {
    queue_arn = aws_sqs_queue.k8s_ingest.arn
    events    = ["s3:ObjectCreated:*"]
  }

  depends_on = [aws_sqs_queue_policy.k8s_ingest]
}

resource "aws_cloudwatch_log_group" "kubernetes" {
  name              = "/aws/lambda/ot-kubernetes-detector"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.telemetry.arn

  tags = {
    Environment = var.environment
    Project     = "ot-telemetry"
  }
}

resource "aws_iam_role" "kubernetes_lambda_exec" {
  name                 = "ot-kubernetes-lambda-exec-role"
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

resource "aws_iam_policy" "kubernetes_lambda_policy" {
  name        = "ot-kubernetes-lambda-policy"
  description = "Least-privilege policy for the Kubernetes audit/Falco detector"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "WriteFunctionLogs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.kubernetes.arn}:*"
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
        Sid    = "ConsumeKubernetesQueues"
        Effect = "Allow"
        Action = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"]
        Resource = [
          aws_sqs_queue.k8s_ingest.arn,
          aws_sqs_queue.falco_events.arn,
        ]
      },
      {
        Sid      = "SendFailedBatchesToDlq"
        Effect   = "Allow"
        Action   = ["sqs:SendMessage"]
        Resource = [aws_sqs_queue.k8s_dlq.arn, aws_sqs_queue.falco_dlq.arn]
      },
      {
        Sid      = "ReadKubernetesObjects"
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "${aws_s3_bucket.telemetry_buckets["kubernetes"].arn}/*"
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
        Sid      = "WriteKubernetesDetections"
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem"]
        Resource = [aws_dynamodb_table.ot_detections.arn, "${aws_dynamodb_table.ot_detections.arn}/index/*"]
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "kubernetes_lambda_policy_attach" {
  role       = aws_iam_role.kubernetes_lambda_exec.name
  policy_arn = aws_iam_policy.kubernetes_lambda_policy.arn
}

resource "aws_lambda_function" "kubernetes" {
  s3_bucket        = aws_s3_bucket.telemetry_buckets["raw"].id
  s3_key           = aws_s3_object.lambda_zip_upload.key
  function_name    = "ot-kubernetes-detector"
  role             = aws_iam_role.kubernetes_lambda_exec.arn
  handler          = "kubernetes_handler.lambda_handler"
  runtime          = "python3.12"
  timeout          = 120
  memory_size      = 512
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  reserved_concurrent_executions = var.lambda_reserved_concurrency

  environment {
    variables = {
      K8S_BUCKET       = aws_s3_bucket.telemetry_buckets["kubernetes"].id
      STAGED_BUCKET    = aws_s3_bucket.telemetry_buckets["staged"].id
      DLQ_BUCKET       = aws_s3_bucket.telemetry_buckets["dlq"].id
      AWS_ENDPOINT_URL = var.localstack_endpoint
      MAX_OBJECT_BYTES = tostring(var.max_object_bytes)
    }
  }

  kms_key_arn = aws_kms_key.telemetry.arn

  dead_letter_config {
    target_arn = aws_sqs_queue.k8s_dlq.arn
  }

  depends_on = [aws_cloudwatch_log_group.kubernetes]

  tags = {
    Environment = var.environment
    Project     = "ot-telemetry"
  }
}

resource "aws_lambda_event_source_mapping" "k8s_ingest" {
  event_source_arn        = aws_sqs_queue.k8s_ingest.arn
  function_name           = aws_lambda_function.kubernetes.arn
  batch_size              = 5
  enabled                 = true
  function_response_types = ["ReportBatchItemFailures"]
}

resource "aws_lambda_event_source_mapping" "falco_events" {
  event_source_arn        = aws_sqs_queue.falco_events.arn
  function_name           = aws_lambda_function.kubernetes.arn
  batch_size              = 10
  enabled                 = true
  function_response_types = ["ReportBatchItemFailures"]
}

resource "aws_cloudwatch_metric_alarm" "kubernetes_errors" {
  alarm_name          = "ot-kubernetes-errors"
  alarm_description   = "The Kubernetes detector is failing; audit/Falco detections may be lost."
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = aws_lambda_function.kubernetes.function_name }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.ops_alerts.arn]
  ok_actions          = [aws_sns_topic.ops_alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "k8s_queue_age" {
  alarm_name          = "ot-k8s-queue-age"
  alarm_description   = "Kubernetes audit logs have been waiting in the queue for more than five minutes."
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateAgeOfOldestMessage"
  dimensions          = { QueueName = aws_sqs_queue.k8s_ingest.name }
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 300
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.ops_alerts.arn]
  ok_actions          = [aws_sns_topic.ops_alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "k8s_dlq_depth" {
  alarm_name          = "ot-k8s-dlq-depth"
  alarm_description   = "Kubernetes audit messages exhausted retries."
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  dimensions          = { QueueName = aws_sqs_queue.k8s_dlq.name }
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.ops_alerts.arn]
  ok_actions          = [aws_sns_topic.ops_alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "falco_dlq_depth" {
  alarm_name          = "ot-falco-dlq-depth"
  alarm_description   = "Falco runtime events exhausted retries."
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  dimensions          = { QueueName = aws_sqs_queue.falco_dlq.name }
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.ops_alerts.arn]
  ok_actions          = [aws_sns_topic.ops_alerts.arn]
}
