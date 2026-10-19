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
  name              = "ot-incident-alerts"
  kms_master_key_id = "alias/aws/sns"

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
  name                       = "ot-incident-notifications"
  message_retention_seconds  = 86400 # 24h retention for inspection
  visibility_timeout_seconds = 30
  sqs_managed_sse_enabled    = true

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
          StringEquals = {
            "aws:SourceAccount" = local.account_id
          }
        }
      }
    ]
  })
}

# ------------------------------------------------------------------
# Operations alarms topic (pipeline health, not security incidents)
# ------------------------------------------------------------------

resource "aws_sns_topic" "ops_alerts" {
  name              = "ot-ops-alerts"
  kms_master_key_id = "alias/aws/sns"

  tags = {
    Environment = var.environment
    Project     = "ot-telemetry"
  }
}

resource "aws_sns_topic_subscription" "ops_email" {
  count     = var.ops_alert_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.ops_alerts.arn
  protocol  = "email"
  endpoint  = var.ops_alert_email
}

# LocalStack verification stand-in: lets `make alarm-test` prove that an alarm
# state change reaches the operations topic without real email credentials.
resource "aws_sqs_queue" "ops_alerts_sink" {
  name                    = "ot-ops-alerts-sink"
  sqs_managed_sse_enabled = true

  tags = {
    Environment = var.environment
    Project     = "ot-telemetry"
  }
}

resource "aws_sns_topic_subscription" "ops_sqs_target" {
  topic_arn = aws_sns_topic.ops_alerts.arn
  protocol  = "sqs"
  endpoint  = aws_sqs_queue.ops_alerts_sink.arn
}

resource "aws_sqs_queue_policy" "ops_alerts_sink" {
  queue_url = aws_sqs_queue.ops_alerts_sink.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "sns.amazonaws.com" }
        Action    = "sqs:SendMessage"
        Resource  = aws_sqs_queue.ops_alerts_sink.arn
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = aws_sns_topic.ops_alerts.arn
          }
          StringEquals = {
            "aws:SourceAccount" = local.account_id
          }
        }
      }
    ]
  })
}

resource "aws_sns_topic_policy" "ops_alerts_cloudwatch" {
  arn = aws_sns_topic.ops_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowCloudWatchAlarmsToPublish"
        Effect    = "Allow"
        Principal = { Service = "cloudwatch.amazonaws.com" }
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.ops_alerts.arn
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = local.account_id
          }
        }
      }
    ]
  })
}
