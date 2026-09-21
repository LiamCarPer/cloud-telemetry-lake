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

variable "abuseipdb_api_key" {
  type        = string
  description = "Optional AbuseIPDB API key. When set, the parser Lambda enriches public IPs with threat-intelligence scores; when empty, enrichment is skipped."
  default     = ""
  sensitive   = true
}

