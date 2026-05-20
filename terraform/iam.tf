resource "aws_iam_role" "lambda_exec" {
  name = "ot-parser-lambda-exec-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_policy" "lambda_policy" {
  name        = "ot-parser-lambda-policy"
  description = "IAM policy for the OT Parser Lambda function with least privilege access"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # CloudWatch Logs
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      # SQS Ingestion Queue
      {
        Effect = "Allow"
        Action = [
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes"
        ]
        Resource = aws_sqs_queue.ingest_queue.arn
      },
      # S3 Raw Bucket (Read-only)
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.telemetry_buckets["raw"].arn,
          "${aws_s3_bucket.telemetry_buckets["raw"].arn}/*"
        ]
      },
      # S3 Staged Bucket (Write/Read)
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:ListBucket",
          "s3:GetObject"
        ]
        Resource = [
          aws_s3_bucket.telemetry_buckets["staged"].arn,
          "${aws_s3_bucket.telemetry_buckets["staged"].arn}/*"
        ]
      },
      # S3 DLQ Bucket (Write)
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject"
        ]
        Resource = [
          aws_s3_bucket.telemetry_buckets["dlq"].arn,
          "${aws_s3_bucket.telemetry_buckets["dlq"].arn}/*"
        ]
      },
      # DynamoDB Detections & State (Write/Read)
      {
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:UpdateItem",
          "dynamodb:DeleteItem",
          "dynamodb:Query",
          "dynamodb:Scan"
        ]
        Resource = [
          aws_dynamodb_table.ot_detections.arn,
          "${aws_dynamodb_table.ot_detections.arn}/index/*",
          aws_dynamodb_table.ot_detection_state.arn
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_policy_attach" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = aws_iam_policy.lambda_policy.arn
}

# ==============================================================================
# IAM – Incident Aggregator Lambda
# ==============================================================================

resource "aws_iam_role" "aggregator_lambda_exec" {
  name = "ot-aggregator-lambda-exec-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_policy" "aggregator_lambda_policy" {
  name        = "ot-aggregator-lambda-policy"
  description = "Least-privilege policy for the OT Incident Aggregator Lambda"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # CloudWatch Logs
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      # DynamoDB Streams – read-only access to the ot_detections stream
      {
        Effect = "Allow"
        Action = [
          "dynamodb:GetRecords",
          "dynamodb:GetShardIterator",
          "dynamodb:DescribeStream",
          "dynamodb:ListStreams"
        ]
        Resource = "${aws_dynamodb_table.ot_detections.arn}/stream/*"
      },
      # S3 Raw Bucket – read the aggregator zip (for deployment reference)
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "${aws_s3_bucket.telemetry_buckets["raw"].arn}/*"
      },
      # S3 Reports Bucket – write IR report artifacts
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.telemetry_buckets["reports"].arn,
          "${aws_s3_bucket.telemetry_buckets["reports"].arn}/*"
        ]
      },
      # SNS – publish incident alerts to the SOC topic
      {
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.incident_alerts.arn
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "aggregator_policy_attach" {
  role       = aws_iam_role.aggregator_lambda_exec.name
  policy_arn = aws_iam_policy.aggregator_lambda_policy.arn
}
