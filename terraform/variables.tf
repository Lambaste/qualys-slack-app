variable "qualy_secret_name" {
  description = "Name of the Qualys password secret"
  type        = string
}

variable "slack_secret_name" {
  description = "Name of the Slack app secret"
  type        = string
}

variable "qualy_secret_arn" {
  description = "ARN of the Qualys password secret"
  type        = string
}

variable "slack_secret_arn" {
  description = "ARN of the Slack app secret"
  type        = string
}
