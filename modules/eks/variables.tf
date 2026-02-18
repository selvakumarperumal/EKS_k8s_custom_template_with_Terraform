###############################################################################
# EKS MODULE — INPUT VARIABLES
# =============================================================================
# Variables that control the EKS cluster and node group configuration.
# These are set by the root module (main.tf) which passes outputs from
# the VPC and IAM modules.
###############################################################################


# =============================================================================
# CLUSTER IDENTIFICATION
# =============================================================================

# The name of the EKS cluster — appears in AWS Console and kubectl config.
variable "cluster_name" {
  description = "Name of the EKS cluster"
  type        = string
}

# Kubernetes version — must be supported by EKS (check AWS docs).
# Only minor versions are specified (e.g., "1.31", not "1.31.2").
# EKS manages the patch version automatically.
variable "kubernetes_version" {
  description = "Kubernetes version to use for the EKS cluster"
  type        = string
  default     = "1.31"
}


# =============================================================================
# NETWORKING
# =============================================================================

# The VPC ID where the cluster will be deployed.
# This comes from module.vpc.vpc_id in the root module.
variable "vpc_id" {
  description = "VPC ID where the cluster will be deployed"
  type        = string
}

# The subnet IDs for the cluster and node groups.
# These should be PRIVATE subnets for security.
# Comes from module.vpc.private_subnets in the root module.
variable "subnet_ids" {
  description = "List of private subnet IDs for the cluster and node groups"
  type        = list(string)
}


# =============================================================================
# IAM ROLES
# =============================================================================

# ARN of the IAM role for the EKS cluster (control plane).
# Comes from module.iam.cluster_role_arn.
variable "cluster_role_arn" {
  description = "ARN of the IAM role for the EKS cluster to assume"
  type        = string
}

# ARN of the IAM role for the node groups (worker instances).
# Comes from module.iam.node_group_role_arn.
variable "node_role_arn" {
  description = "ARN of the IAM role for worker node EC2 instances"
  type        = string
}


# =============================================================================
# API SERVER ACCESS CONTROL
# =============================================================================

# Whether the API server is accessible from the public internet.
# If true, anyone (filtered by public_access_cidrs) can reach the API.
# If false, API is only accessible from within the VPC.
variable "endpoint_public_access" {
  description = "Enable public API server endpoint access"
  type        = bool
  default     = true
}

# Whether the API server is accessible from within the VPC.
# This should ALWAYS be true — nodes communicate with the API internally.
variable "endpoint_private_access" {
  description = "Enable private API server endpoint access (always recommended)"
  type        = bool
  default     = true
}

# CIDRs that can access the public API endpoint.
# Restrict this to your IP/VPN range for production security.
variable "public_access_cidrs" {
  description = "CIDR blocks that can access the public API endpoint"
  type        = list(string)
  default     = ["0.0.0.0/0"] # ⚠️ Restrict in production
}


# =============================================================================
# NODE GROUPS
# =============================================================================

# Map of node group configurations. Each key is a node group name,
# and the value is an object with the node group settings.
#
# Using optional() for fields that aren't always needed:
# - capacity_type defaults to "ON_DEMAND" if not specified
# - disk_size defaults to 20 GiB if not specified
# - taints defaults to empty (no taints)
variable "node_groups" {
  description = "Map of node group configurations (key = group name)"
  type = map(object({
    instance_types = list(string)          # e.g., ["t3.medium"]
    desired_size   = number                # Starting node count
    min_size       = number                # Min for autoscaler
    max_size       = number                # Max for autoscaler
    capacity_type  = optional(string)      # "ON_DEMAND" or "SPOT"
    disk_size      = optional(number)      # EBS volume size in GiB
    labels         = optional(map(string)) # Kubernetes node labels
    taints = optional(list(object({        # Kubernetes node taints
      key    = string
      value  = string
      effect = string # NO_SCHEDULE, PREFER_NO_SCHEDULE, NO_EXECUTE
    })))
    tags                = optional(map(string)) # Additional AWS tags
    additional_userdata = optional(string)      # Custom bootstrap script
  }))
}


# =============================================================================
# ADDON VERSIONS
# =============================================================================
# Leave empty ("") to use the latest compatible version for the K8s version.
# Specify a version string to pin to a specific addon version.

variable "coredns_version" {
  description = "Version of CoreDNS addon (empty = latest compatible)"
  type        = string
  default     = ""
}

variable "kube_proxy_version" {
  description = "Version of kube-proxy addon (empty = latest compatible)"
  type        = string
  default     = ""
}

variable "vpc_cni_version" {
  description = "Version of VPC CNI addon (empty = latest compatible)"
  type        = string
  default     = ""
}


# =============================================================================
# IRSA (IAM Roles for Service Accounts)
# =============================================================================

# Whether to create the OIDC provider for IRSA.
# This is strongly recommended for all production clusters.
variable "enable_irsa" {
  description = "Enable OIDC provider for IAM Roles for Service Accounts"
  type        = bool
  default     = true
}


# =============================================================================
# OPTIONAL PAID SERVICES
# =============================================================================

# Whether to enable EKS control plane logging to CloudWatch Logs.
# When disabled, no CloudWatch log group is created and the cluster's
# enabled_cluster_log_types is set to empty.
# KUBE-NATIVE ALTERNATIVE: Falco + ELK/Loki
variable "enable_cluster_logging" {
  description = "Enable EKS control plane logging to CloudWatch (incurs additional cost)"
  type        = bool
  default     = false
}

# Whether to enable 1-minute (detailed) CloudWatch monitoring on EC2 nodes.
# When disabled, uses free 5-minute basic monitoring.
# KUBE-NATIVE ALTERNATIVE: Prometheus + node_exporter + Grafana
variable "enable_detailed_monitoring" {
  description = "Enable detailed (1-min) EC2 monitoring (incurs additional cost)"
  type        = bool
  default     = false
}


# =============================================================================
# COMMON TAGS
# =============================================================================

variable "tags" {
  description = "Tags to apply to all resources in this module"
  type        = map(string)
  default     = {}
}
