variable "region" {
  description = "AWS region"
  type        = string
  default     = "eu-central-1"
}

variable "aws_account_id" {
  description = "AWS Account ID of the caller"
  type        = string
  default     = "<PROPER_AWS_ACCOUNT_ID>"
}