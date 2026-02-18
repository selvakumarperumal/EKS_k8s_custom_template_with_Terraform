###############################################################################
# SECURITY MODULE — MAIN CONFIGURATION (NEW — Not in Reference)
# =============================================================================
# This module adds AWS-native security monitoring services that detect
# threats and configuration compliance issues AFTER your infrastructure
# is deployed. Think of it as your security operations center (SOC).
#
# WHAT THIS MODULE CREATES:
# ────────────────────────────────────────────────────────────────────────
# 1. Amazon GuardDuty — Continuous threat detection
#    - Analyzes EKS audit logs for malicious Kubernetes API calls
#    - Monitors VPC Flow Logs for network-based attacks
#    - Detects malware on EKS workloads
#    - Identifies cryptocurrency mining on worker nodes
#    - Flags compromised credentials and unauthorized access
#
# 2. AWS Config Rules — Configuration compliance monitoring
#    - Checks if EKS logging is enabled
#    - Verifies cluster is not publicly accessible
#    - Monitors security group configurations
#
# DEFENSE IN DEPTH:
# ────────────────────────────────────────────────────────────────────────
# Our template has multiple security layers:
#
#   Layer 1: Network (VPC, NACLs, Security Groups)
#     → Prevents unauthorized network access
#
#   Layer 2: Identity (IAM roles, IRSA)
#     → Controls who can do what
#
#   Layer 3: Encryption (KMS, encrypted EBS, secrets encryption)
#     → Protects data at rest
#
#   Layer 4: Logging (CloudWatch, VPC Flow Logs, control plane logs)
#     → Records everything for audit
#
#   Layer 5: Detection (GuardDuty, Config Rules) ← THIS MODULE
#     → Alerts you to active threats and misconfigurations
#
# COST:
# ────────────────────────────────────────────────────────────────────────
# GuardDuty:  ~$4-5/GB of data analyzed (first 30 days free)
# Config:     ~$0.003/rule evaluation + $0.003/config item recorded
# For a small EKS cluster: ~$10-30/month total
###############################################################################


# =============================================================================
# AMAZON GUARDDUTY
# =============================================================================
# GuardDuty is an intelligent threat detection service that uses machine
# learning, anomaly detection, and threat intelligence feeds to identify
# threats in your AWS environment.
#
# DATA SOURCES GuardDuty analyzes:
#   1. CloudTrail Management Events — API calls to AWS services
#   2. VPC Flow Logs — Network traffic patterns
#   3. DNS Logs — DNS query patterns
#   4. EKS Audit Logs — Kubernetes API calls
#   5. S3 Data Events — S3 object-level API activity
#
# IMPORTANT: GuardDuty does NOT read your data or interfere with
# your applications. It only analyzes metadata (logs, flow logs, etc.)
# to detect suspicious patterns.
#
# FINDING TYPES:
#   - Recon:EC2/PortProbeUnprotectedPort (port scanning)
#   - UnauthorizedAccess:IAMUser/MaliciousIPCaller (compromised creds)
#   - CryptoCurrency:EC2/BitcoinTool.B!DNS (mining detection)
#   - Kubernetes:K8sDNS/SuccessfullyCreated (suspicious K8s activity)
# =============================================================================
resource "aws_guardduty_detector" "main" {
  count = var.enable_guardduty ? 1 : 0 # Only create if enabled

  enable = true # Activate the detector (starts analyzing data immediately)

  # ---------------------------------------------------------------------------
  # FINDING PUBLISHING FREQUENCY
  # ---------------------------------------------------------------------------
  # How often GuardDuty publishes updated findings:
  #   "FIFTEEN_MINUTES" — Most responsive (recommended for production)
  #   "ONE_HOUR"        — Good balance of responsiveness and cost
  #   "SIX_HOURS"       — Lowest frequency, highest latency
  #
  # Note: NEW findings are always published immediately.
  # This setting only affects UPDATES to existing findings.
  # ---------------------------------------------------------------------------
  finding_publishing_frequency = "FIFTEEN_MINUTES"

  tags = merge(
    var.tags,
    {
      Name = "${var.cluster_name}-guardduty"
    }
  )
}

# ---------------------------------------------------------------------------
# GUARDDUTY FEATURE: EKS AUDIT LOG MONITORING
# ---------------------------------------------------------------------------
# Uses the modern aws_guardduty_detector_feature resource (replaces the
# deprecated datasources block). When enabled, GuardDuty analyzes
# Kubernetes API audit logs from EKS to detect suspicious activity like:
#   - Unauthorized kubectl exec into pods
#   - Creation of privileged containers
#   - Anomalous API calls (unusual times, unusual users)
#   - Access from known malicious IPs
#   - Credential exfiltration attempts
# ---------------------------------------------------------------------------
resource "aws_guardduty_detector_feature" "eks_audit_logs" {
  count       = var.enable_guardduty ? 1 : 0
  detector_id = aws_guardduty_detector.main[0].id
  name        = "EKS_AUDIT_LOGS"
  status      = "ENABLED"
}

# ---------------------------------------------------------------------------
# GUARDDUTY FEATURE: EKS RUNTIME MONITORING
# ---------------------------------------------------------------------------
# Monitors the operating system-level events on EKS nodes to detect
# runtime threats such as:
#   - Process injection attacks
#   - Suspicious file access patterns
#   - Unexpected network connections from containers
#   - Privilege escalation attempts
# ---------------------------------------------------------------------------
resource "aws_guardduty_detector_feature" "eks_runtime_monitoring" {
  count       = var.enable_guardduty ? 1 : 0
  detector_id = aws_guardduty_detector.main[0].id
  name        = "EKS_RUNTIME_MONITORING"
  status      = "ENABLED"
}

# ---------------------------------------------------------------------------
# GUARDDUTY FEATURE: MALWARE PROTECTION
# ---------------------------------------------------------------------------
# GuardDuty can scan EBS volumes attached to EKS nodes for malware
# when it detects suspicious activity. This runs ONLY when triggered
# by a GuardDuty finding (not continuously), so it doesn't impact
# normal performance.
# ---------------------------------------------------------------------------
resource "aws_guardduty_detector_feature" "malware_protection" {
  count       = var.enable_guardduty ? 1 : 0
  detector_id = aws_guardduty_detector.main[0].id
  name        = "EBS_MALWARE_PROTECTION"
  status      = "ENABLED"
}


# =============================================================================
# AWS CONFIG — CONFIGURATION RECORDER
# =============================================================================
# AWS Config continuously records and evaluates your resource configurations.
# It answers the question: "Are my resources configured according to
# security best practices?"
#
# HOW IT WORKS:
# 1. Config Recorder tracks changes to your AWS resources
# 2. Config Rules evaluate if resources comply with your policies
# 3. Non-compliant resources are flagged for remediation
#
# EXAMPLE:
#   Rule: "EKS clusters must have logging enabled"
#   Check: Config evaluates if enabled_cluster_log_types is set
#   Result: COMPLIANT or NON_COMPLIANT
# =============================================================================

# ------- IAM ROLE FOR CONFIG -------
# AWS Config needs an IAM role to:
#   - Read configurations of your AWS resources
#   - Write configuration snapshots to S3
#   - Send notifications to SNS
resource "aws_iam_role" "config" {
  count       = var.enable_config ? 1 : 0
  name_prefix = "${var.cluster_name}-config-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "config.amazonaws.com" # AWS Config service
      }
    }]
  })

  tags = var.tags
}

# Attach the AWS-managed policy for Config
# This policy grants Config read access to all supported resource types
resource "aws_iam_role_policy_attachment" "config" {
  count      = var.enable_config ? 1 : 0
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
  role       = aws_iam_role.config[0].name
}

# ------- CONFIG RECORDER -------
# The recorder tracks configuration changes for specified resource types.
# recording_group.all_supported = true means it records ALL supported resources.
resource "aws_config_configuration_recorder" "main" {
  count    = var.enable_config ? 1 : 0
  name     = "${var.cluster_name}-config-recorder"
  role_arn = aws_iam_role.config[0].arn

  recording_group {
    all_supported = true # Record all supported resource types
  }
}


# =============================================================================
# AWS CONFIG RULES — EKS SECURITY COMPLIANCE
# =============================================================================
# Config Rules are automated checks that evaluate your resource
# configurations against security best practices.
#
# MANAGED RULES: AWS provides pre-built rules for common checks.
# CUSTOM RULES: You can create your own rules using Lambda functions.
#
# We use managed rules for EKS security compliance.
# =============================================================================

# ------- RULE 1: EKS Cluster Logging Enabled -------
# Checks: Are all 5 control plane log types enabled?
# Why: Logging is essential for security auditing, incident response,
#      and compliance (SOC 2, PCI DSS, HIPAA all require audit logging)
resource "aws_config_config_rule" "eks_cluster_logging" {
  count = var.enable_config ? 1 : 0
  name  = "${var.cluster_name}-eks-logging-enabled"

  source {
    owner             = "AWS"                         # AWS-managed rule
    source_identifier = "EKS_CLUSTER_LOGGING_ENABLED" # Rule identifier
  }

  # This rule applies to EKS clusters specifically
  scope {
    compliance_resource_types = ["AWS::EKS::Cluster"]
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

# ------- RULE 2: EKS Endpoint Public Access Disabled -------
# Checks: Is the EKS API server publicly accessible?
# Why: Public API endpoints increase the attack surface.
#      For maximum security, disable public access and use VPN.
#
# NOTE: This rule will flag our cluster as NON_COMPLIANT because
# we have public access enabled. This is intentional for development.
# In production, you should disable public access.
resource "aws_config_config_rule" "eks_endpoint_no_public_access" {
  count = var.enable_config ? 1 : 0
  name  = "${var.cluster_name}-eks-no-public-endpoint"

  source {
    owner             = "AWS"
    source_identifier = "EKS_ENDPOINT_NO_PUBLIC_ACCESS"
  }

  scope {
    compliance_resource_types = ["AWS::EKS::Cluster"]
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

# ------- RULE 3: EKS Secrets Encrypted -------
# Checks: Are Kubernetes secrets encrypted with a KMS key?
# Why: Without encryption, secrets in etcd are stored as base64
#      (easily decoded). KMS encryption adds envelope encryption.
resource "aws_config_config_rule" "eks_secrets_encrypted" {
  count = var.enable_config ? 1 : 0
  name  = "${var.cluster_name}-eks-secrets-encrypted"

  source {
    owner             = "AWS"
    source_identifier = "EKS_SECRETS_ENCRYPTED"
  }

  scope {
    compliance_resource_types = ["AWS::EKS::Cluster"]
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}
