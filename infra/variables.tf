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
  default = 512
}

variable "log_retention_days" {
  type    = number
  default = 14
}
