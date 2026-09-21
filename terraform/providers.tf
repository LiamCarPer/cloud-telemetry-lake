terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  access_key                  = var.localstack_endpoint != "" ? "mock" : null
  secret_key                  = var.localstack_endpoint != "" ? "mock" : null
  region                      = var.aws_region
  s3_use_path_style           = var.localstack_endpoint != ""
  skip_credentials_validation = var.localstack_endpoint != ""
  skip_metadata_api_check     = var.localstack_endpoint != ""

  # When localstack_endpoint is empty (real AWS), no endpoints block is
  # rendered and the provider resolves the standard regional endpoints.
  dynamic "endpoints" {
    for_each = var.localstack_endpoint != "" ? [1] : []
    content {
      s3       = var.localstack_endpoint
      sqs      = var.localstack_endpoint
      sns      = var.localstack_endpoint
      lambda   = var.localstack_endpoint
      iam      = var.localstack_endpoint
      logs     = var.localstack_endpoint
      dynamodb = var.localstack_endpoint
      sts      = var.localstack_endpoint
    }
  }
}
