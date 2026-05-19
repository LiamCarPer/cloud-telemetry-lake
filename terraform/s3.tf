data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  bucket_names = {
    raw     = "ot-telemetry-raw-${local.account_id}"
    staged  = "ot-telemetry-staged-${local.account_id}"
    reports = "ot-telemetry-reports-${local.account_id}"
    dlq     = "ot-telemetry-dlq-${local.account_id}"
  }
}

resource "aws_s3_bucket" "telemetry_buckets" {
  for_each      = local.bucket_names
  bucket        = each.value
  force_destroy = true # Convenient for development / clean testing
}

resource "aws_s3_bucket_server_side_encryption_configuration" "sse" {
  for_each = aws_s3_bucket.telemetry_buckets
  bucket   = each.value.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "pab" {
  for_each = aws_s3_bucket.telemetry_buckets
  bucket   = each.value.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "tls_enforcement" {
  for_each = aws_s3_bucket.telemetry_buckets
  bucket   = each.value.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnforceTLSOnly"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          each.value.arn,
          "${each.value.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}
