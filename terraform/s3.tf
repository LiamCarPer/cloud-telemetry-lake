data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  bucket_names = {
    raw           = "ot-telemetry-raw-${local.account_id}"
    staged        = "ot-telemetry-staged-${local.account_id}"
    reports       = "ot-telemetry-reports-${local.account_id}"
    dlq           = "ot-telemetry-dlq-${local.account_id}"
    identity      = "ot-identity-raw-${local.account_id}"
    kubernetes    = "ot-k8s-raw-${local.account_id}"
    vulnerability = "ot-vuln-raw-${local.account_id}"
  }
}

resource "aws_s3_bucket" "telemetry_buckets" {
  for_each      = local.bucket_names
  bucket        = each.value
  force_destroy = var.force_destroy
}

resource "aws_s3_bucket_server_side_encryption_configuration" "sse" {
  for_each = aws_s3_bucket.telemetry_buckets
  bucket   = each.value.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.telemetry.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "telemetry" {
  for_each = aws_s3_bucket.telemetry_buckets
  bucket   = each.value.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "raw" {
  bucket = aws_s3_bucket.telemetry_buckets["raw"].id

  rule {
    id     = "raw-retention"
    status = "Enabled"
    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    expiration {
      days = 90
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "staged" {
  bucket = aws_s3_bucket.telemetry_buckets["staged"].id

  rule {
    id     = "abort-incomplete-uploads"
    status = "Enabled"
    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "reports" {
  bucket = aws_s3_bucket.telemetry_buckets["reports"].id

  rule {
    id     = "athena-results-retention"
    status = "Enabled"
    filter {
      prefix = "athena-results/"
    }

    expiration {
      days = 30
    }
  }

  rule {
    id     = "abort-incomplete-uploads"
    status = "Enabled"
    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "dlq" {
  bucket = aws_s3_bucket.telemetry_buckets["dlq"].id

  rule {
    id     = "dlq-retention"
    status = "Enabled"
    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    expiration {
      days = 90
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "identity" {
  bucket = aws_s3_bucket.telemetry_buckets["identity"].id

  rule {
    id     = "identity-retention"
    status = "Enabled"
    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    expiration {
      days = 365
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "kubernetes" {
  bucket = aws_s3_bucket.telemetry_buckets["kubernetes"].id

  rule {
    id     = "k8s-audit-retention"
    status = "Enabled"
    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    expiration {
      days = 180
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "vulnerability" {
  bucket = aws_s3_bucket.telemetry_buckets["vulnerability"].id

  rule {
    id     = "vulnerability-retention"
    status = "Enabled"
    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    expiration {
      days = 365
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
    Statement = concat(
      [
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
      ],
      each.key == "identity" && var.enable_cloudtrail ? [
        {
          Sid       = "AWSCloudTrailAclCheck"
          Effect    = "Allow"
          Principal = { Service = "cloudtrail.amazonaws.com" }
          Action    = "s3:GetBucketAcl"
          Resource  = each.value.arn
          Condition = {
            StringEquals = {
              "aws:SourceAccount" = local.account_id
            }
          }
        },
        {
          Sid       = "AWSCloudTrailWrite"
          Effect    = "Allow"
          Principal = { Service = "cloudtrail.amazonaws.com" }
          Action    = "s3:PutObject"
          Resource  = "${each.value.arn}/AWSLogs/${local.account_id}/*"
          Condition = {
            StringEquals = {
              "s3:x-amz-acl"      = "bucket-owner-full-control"
              "aws:SourceAccount" = local.account_id
            }
          }
        },
      ] : []
    )
  })
}
