###############################################################################
# SECRETS MANAGER MODULE — INPUT VARIABLES
# =============================================================================
# These variables control which secrets are created and their values.
# All credential variables are marked as `sensitive = true` to prevent
# them from appearing in terraform plan/apply output.
###############################################################################

# Prefix for secret and KMS key names.
variable "name_prefix" {
  description = "Prefix for resource names (typically the cluster name)"
  type        = string
}

# =============================================================================
# API KEY
# =============================================================================

variable "create_api_secret" {
  description = "Whether to create an API key secret"
  type        = bool
  default     = false
}

variable "api_key" {
  description = "API key value"
  type        = string
  default     = ""
  sensitive   = true
}

# =============================================================================
# COMMON
# =============================================================================

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}
