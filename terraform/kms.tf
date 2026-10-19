# ==============================================================================
# KMS – customer-managed key for telemetry data, logs and secrets
# ==============================================================================
# One lab key keeps key-policy review simple. In production, split data,
# logs and secrets into separate keys so their blast radii and rotation
# schedules can differ.

resource "aws_kms_key" "telemetry" {
  description             = "CMK for OT telemetry data, logs and secrets"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowAccountAdministration"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${local.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid    = "AllowAwsServicesViaService"
        Effect = "Allow"
        Principal = {
          Service = [
            "s3.amazonaws.com",
            "sqs.amazonaws.com",
            "dynamodb.amazonaws.com",
            "logs.${var.aws_region}.amazonaws.com",
            "secretsmanager.amazonaws.com",
            "lambda.amazonaws.com",
          ]
        }
        Action   = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey*", "kms:DescribeKey"]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:CallerAccount" = local.account_id
          }
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
    ]
  })

  tags = {
    Environment = var.environment
    Project     = "ot-telemetry"
  }
}

resource "aws_kms_alias" "telemetry" {
  name          = "alias/ot-telemetry"
  target_key_id = aws_kms_key.telemetry.key_id
}
