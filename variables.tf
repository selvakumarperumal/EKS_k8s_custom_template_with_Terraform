###############################################################################
# INPUT VARIABLES
# =============================================================================
# This file defines ALL input variables for the root module. Variables allow
# you to customize the infrastructure without modifying the code itself.
#
# HOW VARIABLES WORK:
# -------------------
# 1. Variables are declared here with type, description, default, and validation
# 2. Values can be set in terraform.tfvars, CLI flags, or environment variables
# 3. Variables without defaults MUST be provided at runtime
# 4. Sensitive variables are redacted from Terraform output
#
# VARIABLE PRECEDENCE (lowest to highest):
# 1. Default value in this file
# 2. terraform.tfvars or *.auto.tfvars files
# 3. -var-file=<path> CLI flag
# 4. -var='key=value' CLI flag
# 5. TF_VAR_<name> environment variable
###############################################################################


# =============================================================================
# GENERAL CONFIGURATION
# =============================================================================

# -----------------------------------------------------------------------------
# AWS REGION
# -----------------------------------------------------------------------------
# The AWS region where ALL resources will be provisioned. Choose a region
# close to your users for lower latency, or one that meets compliance
# requirements (e.g., eu-west-1 for GDPR).
#
# VALIDATION: Must match the AWS region format (e.g., us-east-1, eu-west-2)
# -----------------------------------------------------------------------------
variable "aws_region" {
  description = "AWS region where all resources will be created"
  type        = string      # Must be a string (not a number, list, etc.)
  default     = "us-east-1" # N. Virginia — most services available here

  # Validation ensures the value matches the AWS region naming pattern:
  # 2-4 letters (continent) + dash + region-name + dash + number
  # Examples: us-east-1, ap-southeast-2, eu-central-1
  validation {
    condition     = can(regex("^[a-z]{2,4}-[a-z]+-[0-9]$", var.aws_region))
    error_message = "AWS region must be a valid format like 'us-east-1' or 'eu-west-2'."
  }
}

# -----------------------------------------------------------------------------
# CLUSTER NAME
# -----------------------------------------------------------------------------
# This name is used as a prefix for most resources (VPC, subnets, security
# groups, etc.) to ensure unique, identifiable names. It also becomes the
# EKS cluster name visible in the AWS Console.
#
# IMPORTANT: Changing this after deployment will recreate ALL resources!
# This is because the name is embedded in resource identifiers and ARNs.
# -----------------------------------------------------------------------------
variable "cluster_name" {
  description = "Name of the EKS cluster — used as prefix for all resources"
  type        = string
  default     = "eks-secure-cluster"

  # Validation ensures the name follows AWS naming conventions:
  # - Only lowercase letters, numbers, and hyphens
  # - 3 to 40 characters long
  # - Must start with a letter
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,39}$", var.cluster_name))
    error_message = "Cluster name must be 3-40 characters, start with a letter, and contain only lowercase letters, numbers, and hyphens."
  }
}

# -----------------------------------------------------------------------------
# KUBERNETES VERSION
# -----------------------------------------------------------------------------
# The Kubernetes version for the EKS cluster. AWS supports the latest 4
# minor versions at any time (e.g., 1.28, 1.29, 1.30, 1.31).
#
# UPGRADE STRATEGY:
# - EKS supports in-place cluster upgrades (one minor version at a time)
# - Always test upgrades in a non-production environment first
# - Node groups will auto-upgrade when you update this value
# -----------------------------------------------------------------------------
variable "kubernetes_version" {
  description = "Kubernetes version for the EKS cluster (e.g., '1.31')"
  type        = string
  default     = "1.31"

  # Validate format: must be X.Y where X is 1 and Y is 25-39
  # This prevents accidentally setting an unsupported version
  validation {
    condition     = can(regex("^1\\.(2[5-9]|3[0-9])$", var.kubernetes_version))
    error_message = "Kubernetes version must be in format '1.XX' where XX is 25-39."
  }
}

# -----------------------------------------------------------------------------
# ENVIRONMENT
# -----------------------------------------------------------------------------
# Labels the deployment environment. This value is used in tags and can
# drive conditional logic (e.g., different instance sizes for prod vs dev).
# -----------------------------------------------------------------------------
variable "environment" {
  description = "Deployment environment name (used in tags and resource naming)"
  type        = string
  default     = "development"

  # Only allow known environment names to prevent typos
  validation {
    condition     = contains(["development", "staging", "production"], var.environment)
    error_message = "Environment must be one of: development, staging, production."
  }
}


# =============================================================================
# NETWORKING CONFIGURATION
# =============================================================================

# -----------------------------------------------------------------------------
# VPC CIDR BLOCK
# -----------------------------------------------------------------------------
# The CIDR block defines the IP address range for the entire VPC.
# 10.0.0.0/16 provides 65,536 IP addresses (10.0.0.0 to 10.0.255.255).
#
# SIZING GUIDE:
# /16 = 65,536 IPs — Recommended for production EKS clusters
# /20 = 4,096 IPs  — Suitable for small dev/test environments
# /24 = 256 IPs    — Too small for EKS (each pod consumes an IP!)
#
# WHY /16? Each EKS node reserves IPs for pods. A t3.medium can host ~17 pods,
# each needing its own IP. With 4 nodes × 17 pods = 68 IPs just for pods.
# A /16 gives plenty of room for growth.
# -----------------------------------------------------------------------------
variable "vpc_cidr" {
  description = "CIDR block for the VPC (e.g., '10.0.0.0/16' = 65,536 IPs)"
  type        = string
  default     = "10.0.0.0/16"

  # Validate that the CIDR is in a valid private IP range (RFC 1918)
  # Private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "VPC CIDR must be a valid CIDR block (e.g., '10.0.0.0/16')."
  }
}

# -----------------------------------------------------------------------------
# PRIVATE SUBNETS
# -----------------------------------------------------------------------------
# Private subnets have NO direct internet access. They reach the internet
# through a NAT Gateway (for outbound traffic like pulling container images).
#
# EKS WORKER NODES should be in private subnets for security.
# Each subnet is in a different AZ for high availability.
#
# SIZING: /24 = 254 usable IPs per subnet (AWS reserves 5)
# Three /24 subnets = 762 usable IPs for worker nodes and pods
# -----------------------------------------------------------------------------
variable "private_subnets" {
  description = "CIDR blocks for private subnets (one per AZ, for EKS worker nodes)"
  type        = list(string) # A list of strings, e.g., ["10.0.1.0/24", "10.0.2.0/24"]
  default     = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
}

# -----------------------------------------------------------------------------
# PUBLIC SUBNETS
# -----------------------------------------------------------------------------
# Public subnets have direct internet access via the Internet Gateway.
# Used for:
#   - NAT Gateway(s) (placed in public subnets to provide outbound internet)
#   - Load Balancers (ALB/NLB for exposing services to the internet)
#   - Bastion hosts (if needed for SSH access)
#
# DO NOT place EKS worker nodes in public subnets unless absolutely necessary.
# -----------------------------------------------------------------------------
variable "public_subnets" {
  description = "CIDR blocks for public subnets (one per AZ, for load balancers and NAT)"
  type        = list(string)
  default     = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]
}


# =============================================================================
# EKS SECURITY CONFIGURATION
# =============================================================================

# -----------------------------------------------------------------------------
# API SERVER PUBLIC ACCESS CIDRs
# -----------------------------------------------------------------------------
# Controls which IP addresses can reach the EKS API server over the internet.
#
# SECURITY BEST PRACTICE:
# - Set this to your office/VPN CIDR(s) instead of "0.0.0.0/0"
# - Example: ["203.0.113.0/24"] for a specific network
# - For maximum security, set endpoint_public_access = false and use only
#   private access via VPN/Direct Connect
#
# DEFAULT: ["0.0.0.0/0"] allows access from anywhere — change this in production!
# -----------------------------------------------------------------------------
variable "public_access_cidrs" {
  description = "List of CIDR blocks that can access the EKS API server endpoint (restrict in production!)"
  type        = list(string)
  default     = ["0.0.0.0/0"] # ⚠️ CHANGE THIS IN PRODUCTION
}

# -----------------------------------------------------------------------------
# ENABLE PUBLIC ENDPOINT
# -----------------------------------------------------------------------------
# When true, the EKS API server is reachable from the internet
# (filtered by public_access_cidrs above).
#
# For maximum security, set to false and access the cluster only via
# VPN, Direct Connect, or a bastion host within the VPC.
# -----------------------------------------------------------------------------
variable "enable_public_endpoint" {
  description = "Enable public access to the EKS API server endpoint"
  type        = bool
  default     = true # Set to false for private-only clusters
}

# -----------------------------------------------------------------------------
# ENABLE PRIVATE ENDPOINT
# -----------------------------------------------------------------------------
# When true, the EKS API server is reachable from within the VPC.
# This should ALWAYS be true — it enables nodes to communicate with
# the control plane via private networking.
# -----------------------------------------------------------------------------
variable "enable_private_endpoint" {
  description = "Enable private access to the EKS API server endpoint (should always be true)"
  type        = bool
  default     = true # Always keep this true
}


# =============================================================================
# OPTIONAL PAID AWS SERVICES
# =============================================================================
# The following services incur additional AWS charges. They are all DISABLED
# by default. Enable only what you need — see docs/COST_OPTIMIZATION.md for
# kube-native alternatives (Prometheus, Grafana, ELK, Falco, etc.).
#
# COST SUMMARY (approximate monthly for a small cluster):
#   CloudWatch Logs (cluster logging):  ~$5-10/mo
#   VPC Flow Logs:                      ~$5/mo
#   Detailed Monitoring:                ~$2.10/instance/mo
#   GuardDuty:                          ~$5-15/mo
#   AWS Config:                         ~$3-5/mo
#   Secrets Manager:                    ~$0.40/secret/mo
# =============================================================================

# -----------------------------------------------------------------------------
# ENABLE EKS CONTROL PLANE LOGGING (CloudWatch)
# -----------------------------------------------------------------------------
# Sends EKS control plane logs (API, audit, authenticator, controller manager,
# scheduler) to CloudWatch Logs.
#
# COST: ~$5-10/month depending on API request volume.
#
# KUBE-NATIVE ALTERNATIVE: Use Falco + ELK/Loki for Kubernetes audit logging.
#   → Falco: Runtime security and audit events
#   → Loki/ELK: Centralized log aggregation
#   → These run inside the cluster at no AWS service cost.
# -----------------------------------------------------------------------------
variable "enable_cluster_logging" {
  description = "Enable EKS control plane logging to CloudWatch (~$5-10/mo). Alternative: Falco + ELK/Loki"
  type        = bool
  default     = false
}

# -----------------------------------------------------------------------------
# ENABLE VPC FLOW LOGS
# -----------------------------------------------------------------------------
# Records all network traffic in the VPC and sends to CloudWatch Logs.
# Useful for network forensics, anomaly detection, and compliance.
#
# COST: ~$5/month for a small cluster (charged per GB ingested).
#
# KUBE-NATIVE ALTERNATIVE:
#   → Cilium Hubble: Network observability with flow logs and service maps
#   → Calico: Network policy engine with flow log export
#   → Both are free, open-source, and provide richer K8s-native visibility.
# -----------------------------------------------------------------------------
variable "enable_vpc_flow_logs" {
  description = "Enable VPC Flow Logs to CloudWatch (~$5/mo). Alternative: Cilium Hubble or Calico"
  type        = bool
  default     = false
}

# -----------------------------------------------------------------------------
# ENABLE DETAILED EC2 MONITORING
# -----------------------------------------------------------------------------
# 1-minute CloudWatch metrics for EC2 instances (default is 5-minute/free).
#
# COST: ~$2.10/instance/month.
#
# KUBE-NATIVE ALTERNATIVE:
#   → Prometheus + node_exporter: Sub-second metrics (free, more granular)
#   → Grafana dashboards: Beautiful visualization
#   → Metrics Server: Built-in K8s metrics for HPA autoscaling
# -----------------------------------------------------------------------------
variable "enable_detailed_monitoring" {
  description = "Enable 1-minute EC2 CloudWatch metrics (~$2/instance/mo). Alternative: Prometheus + Grafana"
  type        = bool
  default     = false
}

# -----------------------------------------------------------------------------
# ENABLE GUARDDUTY
# -----------------------------------------------------------------------------
# Amazon GuardDuty is a threat detection service that continuously monitors
# for malicious activity and unauthorized behavior in your AWS account.
#
# COST: ~$5-15/month (first 30 days free).
#
# KUBE-NATIVE ALTERNATIVE:
#   → Falco: Runtime threat detection for containers (CNCF project)
#   → KubeArmor: Real-time container security enforcement
#   → Both are free, open-source, and deeply K8s-aware.
# -----------------------------------------------------------------------------
variable "enable_guardduty" {
  description = "Enable Amazon GuardDuty for threat detection (~$5-15/mo). Alternative: Falco"
  type        = bool
  default     = false
}

# -----------------------------------------------------------------------------
# ENABLE AWS CONFIG
# -----------------------------------------------------------------------------
# AWS Config records and evaluates your resource configurations against
# compliance rules.
#
# COST: ~$3-5/month.
#
# KUBE-NATIVE ALTERNATIVE:
#   → OPA/Gatekeeper: Policy enforcement for Kubernetes resources
#   → Kyverno: K8s-native policy management
#   → Polaris: Best practices for K8s workload configuration
#   → All are free and operate within Kubernetes.
# -----------------------------------------------------------------------------
variable "enable_aws_config" {
  description = "Enable AWS Config for compliance monitoring (~$3-5/mo). Alternative: OPA/Kyverno"
  type        = bool
  default     = false
}


# =============================================================================
# SECRETS MANAGER CONFIGURATION (Optional)
# =============================================================================
# These variables control the optional Secrets Manager module.
# Set the enable_* variables to `true` to create the corresponding secrets.
# Only provide credential values when the corresponding secret is enabled.
# =============================================================================

# --- Database Secret ---
variable "enable_db_secret" {
  description = "Create a Secrets Manager secret for database credentials"
  type        = bool
  default     = false
}

variable "db_username" {
  description = "Database username (only used when enable_db_secret = true)"
  type        = string
  default     = ""
  sensitive   = true # Redacted from terraform plan/apply output
}

variable "db_password" {
  description = "Database password (only used when enable_db_secret = true)"
  type        = string
  default     = ""
  sensitive   = true # Redacted from terraform plan/apply output
}

variable "db_engine" {
  description = "Database engine type (e.g., 'postgres', 'mysql', 'aurora-postgresql')"
  type        = string
  default     = "postgres"
}

variable "db_host" {
  description = "Database hostname or endpoint"
  type        = string
  default     = ""
}

variable "db_port" {
  description = "Database port number (PostgreSQL: 5432, MySQL: 3306)"
  type        = number
  default     = 5432
}

variable "db_name" {
  description = "Database name"
  type        = string
  default     = ""
}

# --- API Secret ---
variable "enable_api_secret" {
  description = "Create a Secrets Manager secret for API keys"
  type        = bool
  default     = false
}

variable "api_key" {
  description = "API key value (only used when enable_api_secret = true)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "api_secret" {
  description = "API secret value (only used when enable_api_secret = true)"
  type        = string
  default     = ""
  sensitive   = true
}

# --- Application Config Secret ---
variable "enable_app_config_secret" {
  description = "Create a Secrets Manager secret for application configuration"
  type        = bool
  default     = false
}

variable "app_config" {
  description = "Application config as key-value pairs (stored as JSON in Secrets Manager)"
  type        = map(string) # Example: { "LOG_LEVEL" = "info", "FEATURE_FLAG" = "true" }
  default     = {}
  sensitive   = true # Entire map is treated as sensitive
}
