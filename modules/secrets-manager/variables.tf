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
# DATABASE CREDENTIALS
# =============================================================================

variable "create_db_secret" {
  description = "Whether to create a database credentials secret"
  type        = bool
  default     = false # Disabled by default — opt-in
}

variable "db_username" {
  description = "Database username"
  type        = string
  default     = ""
  sensitive   = true # Hidden from terraform output
}

variable "db_password" {
  description = "Database password"
  type        = string
  default     = ""
  sensitive   = true
}

variable "db_engine" {
  description = "Database engine type (postgres, mysql, aurora-postgresql, etc.)"
  type        = string
  default     = "postgres"
}

variable "db_host" {
  description = "Database hostname or endpoint"
  type        = string
  default     = ""
}

variable "db_port" {
  description = "Database port number"
  type        = number
  default     = 5432
}

variable "db_name" {
  description = "Database name"
  type        = string
  default     = ""
}

# =============================================================================
# API KEYS
# =============================================================================

variable "create_api_secret" {
  description = "Whether to create an API keys secret"
  type        = bool
  default     = false
}

variable "api_key" {
  description = "API key value"
  type        = string
  default     = ""
  sensitive   = true
}

variable "api_secret" {
  description = "API secret value"
  type        = string
  default     = ""
  sensitive   = true
}

# =============================================================================
# APPLICATION CONFIGURATION
# =============================================================================

variable "create_app_config_secret" {
  description = "Whether to create an application config secret"
  type        = bool
  default     = false
}

variable "app_config" {
  description = "Application config as key-value pairs (stored as JSON)"
  type        = map(string)
  default     = {}
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
