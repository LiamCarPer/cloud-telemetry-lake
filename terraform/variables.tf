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
