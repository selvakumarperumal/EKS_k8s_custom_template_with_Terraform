###############################################################################
# VPC MODULE — INPUT VARIABLES
# =============================================================================
# These variables define the inputs that the VPC module accepts.
# They are set by the calling module (main.tf in the root).
#
# Each variable has:
#   - description: What the variable does (shown in `terraform plan`)
#   - type: The data type (string, list, bool, map, etc.)
#   - default: Optional default value (if not provided by the caller)
###############################################################################


# =============================================================================
# NAMING AND IDENTIFICATION
# =============================================================================

# Prefix for all resource names. This ensures resources from different
# clusters don't collide when deployed in the same AWS account.
# Example: If name_prefix = "eks-prod", the VPC will be named "eks-prod-vpc"
variable "name_prefix" {
  description = "Prefix for resource names (typically the cluster name)"
  type        = string # Must be a string
  # No default — this is REQUIRED (caller must provide it)
}


# =============================================================================
# VPC CONFIGURATION
# =============================================================================

# The IP address range for the entire VPC.
# All subnets must fit within this range.
# Example: 10.0.0.0/16 allows subnets like 10.0.1.0/24, 10.0.2.0/24, etc.
variable "vpc_cidr" {
  description = "CIDR block for the VPC (e.g., '10.0.0.0/16')"
  type        = string
}

# The list of Availability Zones to use. Must match the number of subnets.
# Example: ["us-east-1a", "us-east-1b", "us-east-1c"]
variable "azs" {
  description = "List of availability zones for subnet placement"
  type        = list(string) # A list of strings
}


# =============================================================================
# SUBNET CONFIGURATION
# =============================================================================

# CIDR blocks for private subnets. One subnet per AZ for high availability.
# Worker nodes will be placed in these subnets.
variable "private_subnets" {
  description = "List of private subnet CIDR blocks (one per AZ)"
  type        = list(string)
}

# CIDR blocks for public subnets. One subnet per AZ.
# NAT Gateway and load balancers will be placed here.
variable "public_subnets" {
  description = "List of public subnet CIDR blocks (one per AZ)"
  type        = list(string)
}


# =============================================================================
# NAT GATEWAY CONFIGURATION
# =============================================================================

# Whether to create a NAT Gateway for private subnet internet access.
# If false, private subnets will have NO outbound internet connectivity.
# This means nodes can't pull container images or connect to external APIs.
variable "enable_nat_gateway" {
  description = "Enable NAT Gateway for private subnet outbound internet access"
  type        = bool
  default     = true # Almost always true for EKS clusters
}

# Whether to use a single NAT Gateway (cost saving) or one per AZ (HA).
# - true:  1 NAT Gateway (~$33/month + data charges) — all AZs share it
# - false: 3 NAT Gateways (~$99/month + data charges) — one per AZ
#
# Production: Set to false for high availability
# Development: Set to true to save money
variable "single_nat_gateway" {
  description = "Use a single NAT Gateway (true) or one per AZ (false for HA)"
  type        = bool
  default     = true
}


# =============================================================================
# SUBNET TAGS (Required for EKS)
# =============================================================================

# Additional tags for public subnets.
# EKS requires specific tags to identify subnets for load balancer placement:
#   kubernetes.io/role/elb = "1"          → Place public ALBs here
#   kubernetes.io/cluster/<name> = shared → This cluster can use these subnets
variable "public_subnet_tags" {
  description = "Additional tags for public subnets (include EKS-required tags)"
  type        = map(string) # Key-value pairs: { "tag_key" = "tag_value" }
  default     = {}          # Empty by default — caller should provide EKS tags
}

# Additional tags for private subnets.
# EKS requires these for internal load balancer discovery:
#   kubernetes.io/role/internal-elb = "1" → Place internal NLBs/ALBs here
variable "private_subnet_tags" {
  description = "Additional tags for private subnets (include EKS-required tags)"
  type        = map(string)
  default     = {}
}


# =============================================================================
# OPTIONAL: VPC FLOW LOGS
# =============================================================================

# Whether to enable VPC Flow Logs. When enabled, creates a CloudWatch log
# group, IAM role, and flow log resource.
# KUBE-NATIVE ALTERNATIVE: Cilium Hubble, Calico network flow logs
variable "enable_flow_logs" {
  description = "Enable VPC Flow Logs to CloudWatch (incurs additional cost)"
  type        = bool
  default     = false
}


# =============================================================================
# COMMON TAGS
# =============================================================================

# Tags applied to ALL resources created by this module.
# These are merged with resource-specific tags using merge().
variable "tags" {
  description = "Tags to apply to all resources in this module"
  type        = map(string)
  default     = {}
}
