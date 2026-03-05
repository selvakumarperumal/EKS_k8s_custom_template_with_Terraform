###############################################################################
# SECRETS MANAGER MODULE — OUTPUTS
# =============================================================================
# Outputs conditional values — returns empty string if secret is not created.
# This prevents errors in the root module when secrets are disabled.
###############################################################################

# =============================================================================
# KMS KEY
# =============================================================================

output "kms_key_id" {
  description = "ID of the KMS key used for secrets encryption"
  value       = var.create_api_secret ? aws_kms_key.secrets[0].id : ""
}

output "kms_key_arn" {
  description = "ARN of the KMS key used for secrets encryption"
  value       = var.create_api_secret ? aws_kms_key.secrets[0].arn : ""
}

# =============================================================================
# SECRET ARNs AND NAMES
# =============================================================================

output "api_secret_arn" {
  description = "ARN of the API keys secret"
  value       = var.create_api_secret ? aws_secretsmanager_secret.api_keys[0].arn : ""
}

output "api_secret_name" {
  description = "Name of the API keys secret"
  value       = var.create_api_secret ? aws_secretsmanager_secret.api_keys[0].name : ""
}

# =============================================================================
# IAM POLICY
# =============================================================================

# ARN of the read-only secrets policy — attach to IRSA roles for pod access
output "read_secrets_policy_arn" {
  description = "ARN of the IAM policy for reading secrets"
  value       = var.create_api_secret ? aws_iam_policy.read_secrets[0].arn : ""
}

output "read_secrets_policy_name" {
  description = "Name of the IAM policy for reading secrets"
  value       = var.create_api_secret ? aws_iam_policy.read_secrets[0].name : ""
}
