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
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_policy_attach" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = aws_iam_policy.lambda_policy.arn
}
