# Dead-letter queue for messages the parser cannot process after retries.
# Transient failures are selectively retried via ReportBatchItemFailures.
resource "aws_sqs_queue" "ingest_dlq" {
  name = "ot-log-ingest-dlq"
}

resource "aws_sqs_queue" "ingest_queue" {
  name                       = "ot-log-ingest-queue"
  receive_wait_time_seconds  = 10
  visibility_timeout_seconds = 360 # >= parser Lambda timeout (180s) plus margin

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.ingest_dlq.arn
    maxReceiveCount     = 3
  })
}

resource "aws_sqs_queue_policy" "ingest_queue_policy" {
  queue_url = aws_sqs_queue.ingest_queue.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
        Action   = "sqs:SendMessage"
        Resource = aws_sqs_queue.ingest_queue.arn
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = aws_s3_bucket.telemetry_buckets["raw"].arn
          }
        }
      }
    ]
  })
}

resource "aws_s3_bucket_notification" "bucket_notification" {
  bucket = aws_s3_bucket.telemetry_buckets["raw"].id

  queue {
    queue_arn = aws_sqs_queue.ingest_queue.arn
    events    = ["s3:ObjectCreated:*"]
  }

  depends_on = [aws_sqs_queue_policy.ingest_queue_policy]
}
