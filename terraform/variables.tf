variable "aws_region" {
  type        = string
  description = "The AWS region to deploy to."
  default     = "us-east-1"
}

variable "environment" {
  type        = string
  description = "The deployment environment (e.g. dev, prod)"
  default     = "dev"
}

variable "enable_analytics" {
  type        = bool
  description = "Enable AWS Glue Catalog and Athena resources. Set to false when deploying on LocalStack Community Edition."
  default     = false
}

variable "localstack_endpoint" {
  type        = string
  description = "Endpoint used for LocalStack Community emulation. Set to an empty string to deploy against real AWS, where the regional endpoints and the default credential chain are used instead."
  default     = "http://localhost:4566"
}

variable "force_destroy" {
  type        = bool
  description = "Allow Terraform to destroy non-empty S3 buckets. Convenient for disposable lab environments; set to false in production."
  default     = true
}

variable "log_retention_days" {
  type        = number
  description = "Retention period for Lambda CloudWatch log groups."
  default     = 14
}

variable "ops_alert_email" {
  type        = string
  description = "Optional email address subscribed to the operations alarm topic. Leave empty to skip the subscription."
  default     = ""
}

variable "max_object_bytes" {
  type        = number
  description = "Maximum raw object size the parser will download. Larger objects are retried and then sent to the ingest DLQ."
  default     = 104857600
}

variable "lambda_reserved_concurrency" {
  type        = number
  description = "Reserved concurrency for each Lambda function, capping blast radius and cost in the lab."
  default     = 5
}

variable "enable_cloudtrail" {
  type        = bool
  description = "Create the multi-region CloudTrail trail. Requires real AWS; LocalStack Community only supports CloudTrail on the Ultimate tier, so the identity bucket and queue are still created for fixture testing."
  default     = false
}

variable "enable_guardduty" {
  type        = bool
  description = "Create the GuardDuty detector. GuardDuty is not emulated by LocalStack; the EventBridge rule and queue remain available for local finding simulation."
  default     = false
}

