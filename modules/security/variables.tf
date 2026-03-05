###############################################################################
# SECURITY MODULE — INPUT VARIABLES
###############################################################################

variable "cluster_name" {
  description = "Name of the EKS cluster (used for resource naming)"
  type        = string
}

# Enable/disable GuardDuty threat detection.
# Production: always true. Dev: optional (can save ~$5/month if disabled).
variable "enable_guardduty" {
  description = "Enable Amazon GuardDuty for threat detection"
  type        = bool
  default     = true
}

# How often GuardDuty publishes UPDATED findings (new findings are always immediate).
# "FIFTEEN_MINUTES" — Most responsive (recommended for production)
# "ONE_HOUR"        — Good balance of responsiveness and cost
# "SIX_HOURS"       — Lowest processing cost, highest latency
variable "guardduty_finding_frequency" {
  description = "GuardDuty finding publishing frequency (FIFTEEN_MINUTES, ONE_HOUR, SIX_HOURS)"
  type        = string
  default     = "SIX_HOURS"
}

# Enable/disable AWS Config for compliance monitoring.
# Production: always true. Dev: optional.
variable "enable_config" {
  description = "Enable AWS Config for configuration compliance monitoring"
  type        = bool
  default     = true
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}
