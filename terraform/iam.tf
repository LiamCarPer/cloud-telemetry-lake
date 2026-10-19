# ==============================================================================
# IAM – parser Lambda
# ==============================================================================
# Trust policies intentionally contain no aws:SourceArn/aws:SourceAccount
# conditions: Lambda execution-role trust does not support those keys. The
# controls against over-privilege are the scoped identity policies below and
# the permissions boundary attached to both roles.
# ==============================================================================

resource "aws_iam_role" "lambda_exec" {
  name                 = "ot-parser-lambda-exec-role"
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

resource "aws_iam_policy" "lambda_policy" {
  name        = "ot-parser-lambda-policy"
  description = "Least-privilege policy for the OT parser Lambda"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "WriteFunctionLogs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.parser.arn}:*"
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
              "secretsmanager.${var.aws_region}.amazonaws.com",
              "lambda.${var.aws_region}.amazonaws.com",
            ]
          }
        }
      },
      {
        Sid      = "ConsumeIngestQueue"
        Effect   = "Allow"
        Action   = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"]
        Resource = aws_sqs_queue.ingest_queue.arn
      },
      {
        Sid      = "ReadRawTelemetry"
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "${aws_s3_bucket.telemetry_buckets["raw"].arn}/*"
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
        Sid      = "WriteDetections"
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
      {
        Sid      = "ReadThreatIntelSecret"
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = aws_secretsmanager_secret.abuseipdb.arn
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_policy_attach" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = aws_iam_policy.lambda_policy.arn
}

# ==============================================================================
# IAM – incident aggregator Lambda
# ==============================================================================

resource "aws_iam_role" "aggregator_lambda_exec" {
  name                 = "ot-aggregator-lambda-exec-role"
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

resource "aws_iam_policy" "aggregator_lambda_policy" {
  name        = "ot-aggregator-lambda-policy"
  description = "Least-privilege policy for the OT incident aggregator Lambda"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "WriteFunctionLogs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.aggregator.arn}:*"
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
              "logs.${var.aws_region}.amazonaws.com",
              "lambda.${var.aws_region}.amazonaws.com",
            ]
          }
        }
      },
      {
        Sid      = "ReadDetectionStream"
        Effect   = "Allow"
        Action   = ["dynamodb:GetRecords", "dynamodb:GetShardIterator", "dynamodb:DescribeStream", "dynamodb:ListStreams"]
        Resource = "${aws_dynamodb_table.ot_detections.arn}/stream/*"
      },
      {
        Sid      = "WriteIncidentReports"
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = "${aws_s3_bucket.telemetry_buckets["reports"].arn}/incidents/*"
      },
      {
        Sid      = "PublishIncidentAlerts"
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.incident_alerts.arn
      },
      {
        Sid      = "SendFailedBatchesToDlq"
        Effect   = "Allow"
        Action   = ["sqs:SendMessage"]
        Resource = aws_sqs_queue.aggregator_dlq.arn
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "aggregator_policy_attach" {
  role       = aws_iam_role.aggregator_lambda_exec.name
  policy_arn = aws_iam_policy.aggregator_lambda_policy.arn
}

# ==============================================================================
# Permissions boundary – maximum permissions for either Lambda role
# ==============================================================================
# This is a ceiling, not a grant. It exists so a future policy edit cannot
# silently expand a function into unrelated services or destructive actions.

resource "aws_iam_policy" "lambda_permissions_boundary" {
  name        = "ot-lambda-permissions-boundary"
  description = "Maximum permissions for OT telemetry Lambda execution roles"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket",
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes",
          "sqs:SendMessage",
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:BatchGetItem",
          "dynamodb:UpdateItem",
          "dynamodb:Query",
          "dynamodb:GetRecords",
          "dynamodb:GetShardIterator",
          "dynamodb:DescribeStream",
          "dynamodb:ListStreams",
          "sns:Publish",
          "secretsmanager:GetSecretValue",
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey*",
          "kms:DescribeKey",
        ]
        Resource = concat(
          [for bucket in aws_s3_bucket.telemetry_buckets : bucket.arn],
          [for bucket in aws_s3_bucket.telemetry_buckets : "${bucket.arn}/*"],
          [
            aws_cloudwatch_log_group.parser.arn,
            "${aws_cloudwatch_log_group.parser.arn}:*",
            aws_cloudwatch_log_group.aggregator.arn,
            "${aws_cloudwatch_log_group.aggregator.arn}:*",
          ],
          [
            aws_sqs_queue.ingest_queue.arn,
            aws_sqs_queue.ingest_dlq.arn,
            aws_sqs_queue.aggregator_dlq.arn,
            aws_sqs_queue.incident_notifications.arn,
          ],
          [
            aws_dynamodb_table.ot_detections.arn,
            "${aws_dynamodb_table.ot_detections.arn}/index/*",
            "${aws_dynamodb_table.ot_detections.arn}/stream/*",
            aws_dynamodb_table.ot_detection_state.arn,
          ],
          [
            aws_sns_topic.incident_alerts.arn,
            aws_sns_topic.ops_alerts.arn,
          ],
          [
            aws_secretsmanager_secret.abuseipdb.arn,
            aws_kms_key.telemetry.arn,
          ],
        )
      }
    ]
  })
}
