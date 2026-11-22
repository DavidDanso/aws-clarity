variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "app_name" {
  type    = string
  default = "aws-clarity"
}

variable "lambda_timeout" {
  type    = number
  default = 120
}

variable "lambda_memory" {
  type    = number
  default = 1769
}

variable "log_retention_days" {
  type    = number
  default = 14
}

# Usage & cost safeguards (free built-in AWS controls)
variable "scans_enabled" {
  type        = bool
  description = "Emergency kill-switch: set to false to stop accepting new scans without destroying the app."
  default     = true
}

variable "scan_cooldown_seconds" {
  type        = number
  description = "Minimum seconds between repeated full scans for the same role ARN."
  default     = 15
}

variable "max_concurrent_scans" {
  type        = number
  description = "Maximum number of full account scans permitted to run simultaneously."
  default     = 3
}

variable "api_throttle_rate_limit" {
  type        = number
  description = "API Gateway steady-state requests per second across the prod stage."
  default     = 2
}

variable "api_throttle_burst_limit" {
  type        = number
  description = "API Gateway burst request ceiling across the prod stage."
  default     = 10
}

variable "lambda_reserved_concurrency" {
  type        = number
  description = "Optional Lambda reserved concurrency (-1 = unreserved; set e.g. 20 on accounts with >=100 concurrency)."
  default     = -1
}

variable "dynamodb_read_capacity" {
  type        = number
  description = "Provisioned DynamoDB read capacity units (Always-Free tier includes 25 RCU across the account)."
  default     = 10
}

variable "dynamodb_write_capacity" {
  type        = number
  description = "Provisioned DynamoDB write capacity units (Always-Free tier includes 25 WCU across the account)."
  default     = 10
}
