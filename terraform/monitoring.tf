# ==============================================================================
# Monitoring – log groups, alarms and the operations topic
# ==============================================================================
# Alarms target the operational topic, not the incident topic: a broken
# pipeline is an engineering problem, not a security incident. Both are
# separate so on-call routing can differ.

resource "aws_cloudwatch_log_group" "parser" {
  name              = "/aws/lambda/ot-log-parser-lambda"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.telemetry.arn

  tags = {
    Environment = var.environment
    Project     = "ot-telemetry"
  }
}

resource "aws_cloudwatch_log_group" "aggregator" {
  name              = "/aws/lambda/ot-incident-aggregator"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.telemetry.arn

  tags = {
    Environment = var.environment
    Project     = "ot-telemetry"
  }
}

# ---------------------------------------------------------------------------
# Pipeline health alarms
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_metric_alarm" "parser_errors" {
  alarm_name          = "ot-parser-errors"
  alarm_description   = "The parser Lambda is returning errors; detections may be delayed or lost."
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = aws_lambda_function.parser_lambda.function_name }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.ops_alerts.arn]
  ok_actions          = [aws_sns_topic.ops_alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "aggregator_errors" {
  alarm_name          = "ot-aggregator-errors"
  alarm_description   = "The incident aggregator is failing; detections are not becoming reports."
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = aws_lambda_function.aggregator_lambda.function_name }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.ops_alerts.arn]
  ok_actions          = [aws_sns_topic.ops_alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "ingest_queue_age" {
  alarm_name          = "ot-ingest-queue-age"
  alarm_description   = "Telemetry has been waiting in the ingest queue for more than five minutes."
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateAgeOfOldestMessage"
  dimensions          = { QueueName = aws_sqs_queue.ingest_queue.name }
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 300
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.ops_alerts.arn]
  ok_actions          = [aws_sns_topic.ops_alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "ingest_dlq_depth" {
  alarm_name          = "ot-ingest-dlq-depth"
  alarm_description   = "Messages have failed processing repeatedly and landed in the ingest DLQ."
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  dimensions          = { QueueName = aws_sqs_queue.ingest_dlq.name }
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.ops_alerts.arn]
  ok_actions          = [aws_sns_topic.ops_alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "parser_throttles" {
  alarm_name          = "ot-parser-throttles"
  alarm_description   = "The parser Lambda is being throttled; ingestion is falling behind."
  namespace           = "AWS/Lambda"
  metric_name         = "Throttles"
  dimensions          = { FunctionName = aws_lambda_function.parser_lambda.function_name }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.ops_alerts.arn]
  ok_actions          = [aws_sns_topic.ops_alerts.arn]
}
