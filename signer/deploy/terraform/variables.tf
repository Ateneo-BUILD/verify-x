variable "region" {
  description = "The policy's [runtime] aws_region."
  type        = string
}

variable "site" {
  description = "The policy's [runtime] site: the heartbeat's Site dimension, the names here, and the ledger prefix unless ledger_prefix is set."
  type        = string
}

variable "ledger_prefix" {
  description = "The policy's [runtime] ledger_prefix, if it sets one."
  type        = string
  default     = null
}

variable "ledger_bucket" {
  description = "The policy's [runtime] ledger_bucket: a new bucket, since Object Lock is turned on only when one is made."
  type        = string
}

variable "alert_email" {
  description = "Where alerts and the daily summary go. AWS mails a confirmation link first."
  type        = string
}

variable "metric_namespace" {
  description = "The policy's [runtime] metric_namespace."
  type        = string
  default     = "CL03Signer"
}

variable "retain_days" {
  description = "Object Lock's default retention; the signer writes each object with its policy's ledger_retain_days (400 by default) itself."
  type        = number
  default     = 400
}
