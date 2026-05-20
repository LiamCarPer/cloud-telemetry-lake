# ==============================================================================
# SNS Topic – OT Incident Alerts
# ==============================================================================
# Publishes a notification to the SOC for every new incident report generated
# by the ot-incident-aggregator Lambda.
#
# NOTE: In production, add email/SMS/PagerDuty subscriptions here.
# For LocalStack Community validation, an SQS queue is subscribed below as
# a stand-in delivery target that can be polled and inspected via CLI.
# ==============================================================================

resource "aws_sns_topic" "incident_alerts" {
  name = "ot-incident-alerts"

  tags = {
    Environment = var.environment
    Project     = "ot-telemetry"
  }
}

# ------------------------------------------------------------------
# SQS delivery target (LocalStack Community verification stand-in)
# ------------------------------------------------------------------
# Subscribes an SQS queue to the SNS topic so notification delivery
# can be verified end-to-end via `aws sqs receive-message` without
# requiring real AWS email/SMS credentials.

resource "aws_sqs_queue" "incident_notifications" {
  name                      = "ot-incident-notifications"
  message_retention_seconds = 86400 # 24h retention for inspection
  visibility_timeout_seconds = 30

  tags = {
    Environment = var.environment
    Project     = "ot-telemetry"
  }
}

resource "aws_sns_topic_subscription" "incident_sqs_target" {
  topic_arn = aws_sns_topic.incident_alerts.arn
  protocol  = "sqs"
  endpoint  = aws_sqs_queue.incident_notifications.arn
}

resource "aws_sqs_queue_policy" "incident_notifications_policy" {
  queue_url = aws_sqs_queue.incident_notifications.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "sns.amazonaws.com" }
        Action    = "sqs:SendMessage"
        Resource  = aws_sqs_queue.incident_notifications.arn
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = aws_sns_topic.incident_alerts.arn
          }
        }
      }
    ]
  })
}
