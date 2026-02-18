###############################################################################
# SECRETS MANAGER MODULE — MAIN CONFIGURATION
# =============================================================================
# This module creates AWS Secrets Manager resources for securely storing
# sensitive data like database credentials, API keys, and app configuration.
#
# WHAT IS AWS SECRETS MANAGER?
# ────────────────────────────────────────────────────────────────────────
# Secrets Manager is a managed service that stores, rotates, and retrieves
# secrets (passwords, API keys, tokens). Key benefits over hardcoding:
#   - Secrets are encrypted at rest with KMS
#   - Access is controlled by IAM policies
#   - Automatic rotation is supported
#   - Audit trail via CloudTrail
#   - No secrets in source code or environment variables
#
# HOW PODS ACCESS THESE SECRETS:
# ────────────────────────────────────────────────────────────────────────
# Option 1: External Secrets Operator (K8s controller syncs to K8s Secrets)
# Option 2: CSI Secrets Store Driver (mounts secrets as files in pods)
# Option 3: AWS SDK in application code (directly calls Secrets Manager API)
#
# All options use IRSA (from the EKS module) for secure IAM authentication.
#
# CONDITIONAL CREATION:
# ────────────────────────────────────────────────────────────────────────
# Each secret is created ONLY if its corresponding flag is true:
#   create_db_secret         → Database credentials
#   create_api_secret        → API keys
#   create_app_config_secret → Application configuration
#
# count = var.create_X_secret ? 1 : 0
#   → count = 1: resource IS created
#   → count = 0: resource is NOT created (skipped entirely)
###############################################################################


# =============================================================================
# KMS KEY FOR SECRETS ENCRYPTION
# =============================================================================
# A DEDICATED KMS key for encrypting secrets in Secrets Manager.
# This is SEPARATE from the EKS KMS key because:
#   1. Different services should use different keys (key separation)
#   2. Different access policies may be needed
#   3. Key rotation schedules might differ
#   4. If one key is compromised, the other secrets are still safe
#
# CONDITIONAL: Only created if at least one secret is enabled.
# The || (OR) operator means: create if ANY secret is enabled.
# =============================================================================
resource "aws_kms_key" "secrets" {
  # Create only if at least one secret type is enabled
  count                   = var.create_db_secret || var.create_api_secret || var.create_app_config_secret ? 1 : 0
  description             = "KMS key for Secrets Manager encryption"
  deletion_window_in_days = 7    # 7-day grace period before permanent deletion
  enable_key_rotation     = true # Auto-rotate key material annually

  tags = merge(
    var.tags,
    {
      Name = "${var.name_prefix}-secrets-kms"
    }
  )
}

# Human-friendly alias for the KMS key
resource "aws_kms_alias" "secrets" {
  count         = var.create_db_secret || var.create_api_secret || var.create_app_config_secret ? 1 : 0
  name          = "alias/${var.name_prefix}-secrets"
  target_key_id = aws_kms_key.secrets[0].key_id # [0] because it's a count resource
}


# =============================================================================
# SECRET: DATABASE CREDENTIALS
# =============================================================================
# Stores database connection information as a JSON object.
# Typical format: { username, password, engine, host, port, dbname }
#
# recovery_window_in_days = 7:
#   After deletion, the secret is RECOVERABLE for 7 days.
#   This prevents accidental permanent deletion.
#   Set to 0 for immediate deletion (not recommended for production).
#
# kms_key_id: Encrypts the secret with our dedicated KMS key
#   (not the default AWS-managed key)
# =============================================================================
resource "aws_secretsmanager_secret" "db_credentials" {
  count                   = var.create_db_secret ? 1 : 0 # Only if DB secret enabled
  name                    = "${var.name_prefix}-db-credentials"
  description             = "Database credentials for ${var.name_prefix}"
  kms_key_id              = aws_kms_key.secrets[0].id # Encrypt with our KMS key
  recovery_window_in_days = 7                         # 7-day recovery window

  tags = merge(
    var.tags,
    {
      Name = "${var.name_prefix}-db-credentials"
      Type = "database" # Identifies the secret type for filtering
    }
  )
}

# The actual secret VALUE (stored as a JSON string)
# jsonencode() converts a Terraform map to a JSON string:
# { "username": "admin", "password": "xxx", "engine": "postgres", ... }
resource "aws_secretsmanager_secret_version" "db_credentials" {
  count     = var.create_db_secret ? 1 : 0
  secret_id = aws_secretsmanager_secret.db_credentials[0].id
  secret_string = jsonencode({
    username = var.db_username # Database username
    password = var.db_password # Database password
    engine   = var.db_engine   # e.g., "postgres", "mysql"
    host     = var.db_host     # Database hostname
    port     = var.db_port     # e.g., 5432
    dbname   = var.db_name     # Database name
  })
}


# =============================================================================
# SECRET: API KEYS
# =============================================================================
# Stores API key/secret pairs for external service integration.
# Examples: Stripe API key, SendGrid key, GitHub token, etc.
# =============================================================================
resource "aws_secretsmanager_secret" "api_keys" {
  count                   = var.create_api_secret ? 1 : 0
  name                    = "${var.name_prefix}-api-keys"
  description             = "API keys for ${var.name_prefix}"
  kms_key_id              = aws_kms_key.secrets[0].id
  recovery_window_in_days = 7

  tags = merge(
    var.tags,
    {
      Name = "${var.name_prefix}-api-keys"
      Type = "api"
    }
  )
}

resource "aws_secretsmanager_secret_version" "api_keys" {
  count     = var.create_api_secret ? 1 : 0
  secret_id = aws_secretsmanager_secret.api_keys[0].id
  secret_string = jsonencode({
    api_key    = var.api_key    # The API key value
    api_secret = var.api_secret # The API secret value
  })
}


# =============================================================================
# SECRET: APPLICATION CONFIGURATION
# =============================================================================
# Stores application configuration as key-value pairs.
# This is useful for feature flags, environment-specific settings, etc.
# that you don't want to hardcode in ConfigMaps.
#
# var.app_config is a map(string), so jsonencode produces:
# { "LOG_LEVEL": "info", "FEATURE_FLAG": "true", "APP_ENV": "production" }
# =============================================================================
resource "aws_secretsmanager_secret" "app_config" {
  count                   = var.create_app_config_secret ? 1 : 0
  name                    = "${var.name_prefix}-app-config"
  description             = "Application configuration for ${var.name_prefix}"
  kms_key_id              = aws_kms_key.secrets[0].id
  recovery_window_in_days = 7

  tags = merge(
    var.tags,
    {
      Name = "${var.name_prefix}-app-config"
      Type = "application"
    }
  )
}

resource "aws_secretsmanager_secret_version" "app_config" {
  count         = var.create_app_config_secret ? 1 : 0
  secret_id     = aws_secretsmanager_secret.app_config[0].id
  secret_string = jsonencode(var.app_config) # Entire map → JSON string
}


# =============================================================================
# IAM POLICY — LEAST-PRIVILEGE SECRET READING
# =============================================================================
# This IAM policy grants READ-ONLY access to the secrets we created.
# It follows the principle of least privilege:
#   ✅ GetSecretValue   — Read the actual secret value
#   ✅ DescribeSecret   — Get secret metadata (name, ARN, etc.)
#   ❌ PutSecretValue   — Cannot modify secrets
#   ❌ DeleteSecret     — Cannot delete secrets
#   ❌ CreateSecret     — Cannot create new secrets
#
# The policy also grants KMS decrypt permissions because the secrets
# are encrypted with our custom KMS key. Without KMS access, even with
# Secrets Manager permissions, the secret value can't be decrypted.
#
# USAGE: Attach this policy to IRSA roles for pods that need secret access.
# Example:
#   1. Create an IAM role with this policy attached
#   2. Annotate a K8s ServiceAccount with the role ARN
#   3. Pods using that ServiceAccount can read the secrets
# =============================================================================
resource "aws_iam_policy" "read_secrets" {
  count       = var.create_db_secret || var.create_api_secret || var.create_app_config_secret ? 1 : 0
  name_prefix = "${var.name_prefix}-read-secrets-"
  description = "Allow reading secrets from Secrets Manager"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue", # Read the secret value
          "secretsmanager:DescribeSecret"  # Get secret metadata
        ]
        # Resource: Only the specific secrets we created (not ALL secrets!)
        # concat() combines the conditional lists into one list
        Resource = concat(
          var.create_db_secret ? [aws_secretsmanager_secret.db_credentials[0].arn] : [],
          var.create_api_secret ? [aws_secretsmanager_secret.api_keys[0].arn] : [],
          var.create_app_config_secret ? [aws_secretsmanager_secret.app_config[0].arn] : []
        )
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",    # Decrypt the secret value
          "kms:DescribeKey" # Get KMS key metadata
        ]
        Resource = [aws_kms_key.secrets[0].arn] # Only our KMS key
      }
    ]
  })

  tags = var.tags
}
