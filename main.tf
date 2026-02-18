###############################################################################
# MAIN CONFIGURATION — ROOT MODULE ORCHESTRATION
# =============================================================================
# This is the "brain" of the Terraform project. It ties together all the
# custom modules (VPC, IAM, EKS, Secrets Manager, Security) and passes
# configuration between them.
#
# MODULE DEPENDENCY FLOW:
#
#   ┌──────────────────────────────────────────┐
#   │            Data Sources                   │
#   │  (AZs, Caller Identity)                  │
#   └──────────────┬───────────────────────────┘
#                  │
#     ┌────────────▼────────────┐
#     │       VPC Module        │  ← Creates networking layer first
#     └────────────┬────────────┘
#                  │
#     ┌────────────▼────────────┐
#     │       IAM Module        │  ← Creates roles (no VPC dependency)
#     └────────────┬────────────┘
#                  │
#     ┌────────────▼────────────┐
#     │       EKS Module        │  ← Needs VPC + IAM outputs
#     └────────────┬────────────┘
#                  │
#     ┌────────────▼────────────┐
#     │  Secrets Manager Module │  ← Independent, but logically after EKS
#     └────────────┬────────────┘
#                  │
#     ┌────────────▼────────────┐
#     │    Security Module      │  ← Monitors the deployed infrastructure
#     └────────────────────────-┘
#
# HOW TO READ THIS FILE:
# ----------------------
# Each `module` block below is like a function call. We pass "arguments"
# (input variables) and receive "return values" (outputs) that we can
# use in other modules.
###############################################################################


# =============================================================================
# DATA SOURCES
# =============================================================================
# Data sources fetch information from AWS that we need for configuration.
# Unlike resources, data sources DON'T create anything — they just read.
# =============================================================================

# -----------------------------------------------------------------------------
# AVAILABILITY ZONES
# -----------------------------------------------------------------------------
# Fetches the list of available AZs in the selected region.
# For us-east-1, this returns: ["us-east-1a", "us-east-1b", "us-east-1c", ...]
#
# "state = available" filters out AZs that are under maintenance or
# not yet launched.
#
# WHY: We need AZ names to distribute subnets across them for HA.
# If an AZ goes down, the cluster survives on the remaining AZs.
# -----------------------------------------------------------------------------
data "aws_availability_zones" "available" {
  state = "available" # Only return AZs that are fully operational
}

# -----------------------------------------------------------------------------
# CALLER IDENTITY
# -----------------------------------------------------------------------------
# Returns information about the AWS identity making the API calls:
#   - account_id: The 12-digit AWS account number
#   - arn: The ARN of the caller (user/role)
#   - user_id: The unique identifier of the calling entity
#
# WHY: Used in IAM policies and KMS key policies that need the account ID.
# Also useful for auditing — you can verify you're deploying to the right account.
# -----------------------------------------------------------------------------
data "aws_caller_identity" "current" {}


# =============================================================================
# MODULE: VPC (Virtual Private Cloud)
# =============================================================================
# Creates the entire networking foundation:
#   - VPC with DNS support
#   - 3 Public subnets (for ALB, NAT Gateway)
#   - 3 Private subnets (for EKS worker nodes)
#   - Internet Gateway (for public subnet internet access)
#   - NAT Gateway (for private subnet outbound internet)
#   - Route tables with proper associations
#   - Network ACLs (additional network-level firewall)
#   - VPC Flow Logs (network traffic logging for auditing)
#
# SECURITY: Worker nodes are in private subnets with NO direct internet access.
# They reach the internet only through the NAT Gateway for pulling images.
# =============================================================================
module "vpc" {
  # ---------------------------------------------------------------------------
  # SOURCE
  # ---------------------------------------------------------------------------
  # Points to the local module directory. Terraform will read all .tf files
  # in this directory and treat them as a self-contained module.
  # ---------------------------------------------------------------------------
  source = "./modules/vpc"

  # ---------------------------------------------------------------------------
  # MODULE INPUTS
  # ---------------------------------------------------------------------------
  # These map to the variables defined in modules/vpc/variables.tf.
  # The module uses these values to create networking resources.
  # ---------------------------------------------------------------------------

  name_prefix = var.cluster_name # All VPC resources will be prefixed with the cluster name
  vpc_cidr    = var.vpc_cidr     # e.g., "10.0.0.0/16" — the VPC IP range

  # slice() takes elements 0-2 from the AZ list, giving us exactly 3 AZs.
  # This ensures subnets are distributed across 3 different fault domains.
  # Even if the region has 6 AZs, we only use 3 to match our subnet count.
  azs = slice(data.aws_availability_zones.available.names, 0, 3)

  private_subnets = var.private_subnets # ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = var.public_subnets  # ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]

  enable_nat_gateway = true # Required for private subnets to reach internet
  single_nat_gateway = true # Use ONE NAT instead of one-per-AZ (cost saving for dev)
  # For production: set single_nat_gateway = false for HA NAT (one per AZ)

  # VPC Flow Logs — OPTIONAL (~$5/mo). Alternative: Cilium Hubble, Calico
  enable_flow_logs = var.enable_vpc_flow_logs

  # ---------------------------------------------------------------------------
  # EKS-REQUIRED SUBNET TAGS
  # ---------------------------------------------------------------------------
  # These tags are NOT just labels — EKS uses them to discover which subnets
  # it can place resources in:
  #
  # "kubernetes.io/role/elb" = "1"
  #   → Tells the AWS Load Balancer Controller: "Place public-facing ALBs here"
  #
  # "kubernetes.io/cluster/${cluster_name}" = "shared"
  #   → Tells EKS: "This subnet belongs to my cluster"
  #   → "shared" means multiple clusters CAN share these subnets
  #   → "owned" means only THIS cluster uses them
  # ---------------------------------------------------------------------------
  public_subnet_tags = {
    "kubernetes.io/role/elb"                    = "1"      # Public LBs go here
    "kubernetes.io/cluster/${var.cluster_name}" = "shared" # Cluster ownership
  }

  # "kubernetes.io/role/internal-elb" = "1"
  #   → Tells the Load Balancer Controller: "Place internal ALBs/NLBs here"
  #   → Internal LBs are for service-to-service communication
  private_subnet_tags = {
    "kubernetes.io/role/internal-elb"           = "1"      # Internal LBs go here
    "kubernetes.io/cluster/${var.cluster_name}" = "shared" # Cluster ownership
  }

  # Common tags applied to all VPC resources
  tags = {
    Environment = var.environment
    Terraform   = "true"
    Module      = "vpc"
  }
}


# =============================================================================
# MODULE: IAM (Identity and Access Management)
# =============================================================================
# Creates IAM roles with least-privilege permissions:
#   - EKS Cluster Role: Allows the EKS service to manage the control plane
#   - Node Group Role: Allows EC2 instances to function as EKS worker nodes
#
# SECURITY: Uses managed policies (AWS best practices) instead of inline
# policies. No wildcard permissions are granted.
#
# NOTE: This module has NO dependency on VPC — it can be created in parallel.
# However, the EKS module depends on both VPC and IAM outputs.
# =============================================================================
module "iam" {
  source = "./modules/iam"

  cluster_name = var.cluster_name # Used as prefix for role names

  tags = {
    Environment = var.environment
    Terraform   = "true"
    Module      = "iam"
  }
}


# =============================================================================
# MODULE: EKS (Elastic Kubernetes Service)
# =============================================================================
# Creates the EKS cluster and managed node groups:
#   - KMS key for envelope encryption of Kubernetes secrets
#   - CloudWatch log group for control plane audit logging
#   - Security groups for cluster and nodes (tight ingress/egress)
#   - EKS cluster with encryption, logging, and access configuration
#   - OIDC provider for IRSA (IAM Roles for Service Accounts)
#   - EKS addons (CoreDNS, kube-proxy, VPC CNI)
#   - Launch templates with IMDSv2 enforcement, encrypted EBS
#   - Managed node groups with auto-scaling configuration
#
# DEPENDS ON: VPC (for subnet IDs) + IAM (for role ARNs)
# =============================================================================
module "eks" {
  source = "./modules/eks"

  # ---------------------------------------------------------------------------
  # CLUSTER CONFIGURATION
  # ---------------------------------------------------------------------------
  cluster_name       = var.cluster_name           # EKS cluster name
  kubernetes_version = var.kubernetes_version     # e.g., "1.31"
  vpc_id             = module.vpc.vpc_id          # OUTPUT from VPC module
  subnet_ids         = module.vpc.private_subnets # Nodes in private subnets

  # IAM roles from the IAM module — the EKS service assumes these roles
  cluster_role_arn = module.iam.cluster_role_arn    # For the EKS control plane
  node_role_arn    = module.iam.node_group_role_arn # For EC2 worker nodes

  # ---------------------------------------------------------------------------
  # API SERVER ACCESS
  # ---------------------------------------------------------------------------
  # Controls how the Kubernetes API server is accessible:
  #   - endpoint_public_access: Can you reach kubectl from the internet?
  #   - endpoint_private_access: Can nodes reach the API within the VPC?
  #   - public_access_cidrs: Which IPs can access the public endpoint?
  # ---------------------------------------------------------------------------
  endpoint_public_access  = var.enable_public_endpoint  # Default: true
  endpoint_private_access = var.enable_private_endpoint # Default: true (always keep true)
  public_access_cidrs     = var.public_access_cidrs     # Default: ["0.0.0.0/0"]

  # Enable IRSA — maps K8s ServiceAccounts to IAM roles
  # This is THE recommended way for pods to access AWS services securely.
  # Without this, you'd need to use node instance profiles (less secure).
  enable_irsa = true

  # OPTIONAL PAID SERVICES — disabled by default
  # Enable these if you want AWS-managed logging/monitoring.
  # Otherwise use kube-native alternatives (Prometheus, Grafana, ELK).
  enable_cluster_logging     = var.enable_cluster_logging     # CloudWatch logs (~$5-10/mo)
  enable_detailed_monitoring = var.enable_detailed_monitoring # 1-min metrics (~$2/instance/mo)

  # ---------------------------------------------------------------------------
  # NODE GROUP CONFIGURATION
  # ---------------------------------------------------------------------------
  # Defines the worker node pools. Each node group is a set of EC2 instances
  # that run your Kubernetes pods.
  #
  # We define TWO node groups:
  # 1. "general" — ON_DEMAND instances for critical workloads
  # 2. "spot"    — SPOT instances for cost-optimized, fault-tolerant workloads
  # ---------------------------------------------------------------------------
  node_groups = {

    # -------------------------------------------------------------------------
    # GENERAL NODE GROUP (ON-DEMAND)
    # -------------------------------------------------------------------------
    # These are reliable, always-available instances. Use for:
    #   - Production workloads
    #   - Stateful applications (databases, caches)
    #   - Critical system components
    #
    # ON_DEMAND instances are never interrupted by AWS.
    # -------------------------------------------------------------------------
    general = {
      instance_types = ["t3.medium"] # 2 vCPU, 4 GiB RAM — good for most workloads
      desired_size   = 2             # Start with 2 nodes
      min_size       = 2             # Never scale below 2 (HA)
      max_size       = 4             # Allow scaling up to 4 under load
      capacity_type  = "ON_DEMAND"   # Guaranteed availability
      disk_size      = 20            # 20 GiB EBS volume per node

      # Labels are key-value pairs attached to nodes in Kubernetes.
      # Pods can use nodeSelector or nodeAffinity to target specific nodes.
      labels = {
        role = "general" # Use: nodeSelector: { role: general }
      }

      tags = {
        NodeGroup = "general"
      }
    }

    # -------------------------------------------------------------------------
    # SPOT NODE GROUP (COST-OPTIMIZED)
    # -------------------------------------------------------------------------
    # SPOT instances are unused EC2 capacity at up to 90% discount.
    # AWS can reclaim them with 2 minutes notice (interruption).
    #
    # Use for:
    #   - Batch processing, CI/CD runners
    #   - Stateless, fault-tolerant workloads
    #   - Development/testing environments
    #
    # IMPORTANT: We set a taint ("spot=true:NoSchedule") so that pods are
    # NOT scheduled on spot nodes by default. Only pods that explicitly
    # tolerate this taint will be placed here.
    #
    # Multiple instance types increase the chances of getting capacity.
    # -------------------------------------------------------------------------
    spot = {
      instance_types = ["t3.medium", "t3a.medium"] # Multiple types for availability
      desired_size   = 1                           # Start with 1 spot node
      min_size       = 1                           # Minimum 1 spot node
      max_size       = 3                           # Scale up to 3 under load
      capacity_type  = "SPOT"                      # Use spot pricing (up to 90% discount)
      disk_size      = 20                          # 20 GiB EBS volume

      labels = {
        role = "spot" # Identifies this as a spot node
      }

      # Taints prevent pods from being scheduled on this node unless they
      # have a matching toleration. This prevents critical pods from
      # running on interruptible spot instances.
      #
      # To schedule a pod on spot nodes, add this toleration:
      #   tolerations:
      #   - key: "spot"
      #     operator: "Equal"
      #     value: "true"
      #     effect: "NoSchedule"
      taints = [{
        key    = "spot"        # Taint key
        value  = "true"        # Taint value
        effect = "NO_SCHEDULE" # Pods without toleration won't be scheduled
      }]

      tags = {
        NodeGroup = "spot"
      }
    }
  }

  tags = {
    Environment = var.environment
    Terraform   = "true"
    Module      = "eks"
  }

  # ---------------------------------------------------------------------------
  # EXPLICIT DEPENDENCY
  # ---------------------------------------------------------------------------
  # depends_on ensures the IAM module is fully created BEFORE the EKS module.
  # This is needed because EKS needs the IAM roles to exist before it can
  # assume them. Without this, Terraform might try to create the cluster
  # before the roles are ready, causing an error.
  # ---------------------------------------------------------------------------
  depends_on = [module.iam]
}


# =============================================================================
# MODULE: SECRETS MANAGER (Optional)
# =============================================================================
# Creates AWS Secrets Manager secrets for storing sensitive data:
#   - Database credentials (username, password, host, port)
#   - API keys and secrets
#   - Application configuration
#
# Each secret is encrypted with a dedicated KMS key (not the default AWS key).
# A least-privilege IAM policy is created for reading the secrets.
#
# WHY SECRETS MANAGER?
# Instead of hardcoding secrets in environment variables or ConfigMaps,
# store them in Secrets Manager and access them via:
#   - External Secrets Operator (Kubernetes → AWS integration)
#   - AWS SDK in your application code
#   - CSI Secrets Store Driver
# =============================================================================
module "secrets_manager" {
  source = "./modules/secrets-manager"

  name_prefix = var.cluster_name # Secret names will start with the cluster name

  # Toggle which secrets to create (default: all disabled)
  create_db_secret         = var.enable_db_secret
  create_api_secret        = var.enable_api_secret
  create_app_config_secret = var.enable_app_config_secret

  # Database credentials — only used if create_db_secret = true
  db_username = var.db_username # e.g., "admin"
  db_password = var.db_password # e.g., "super-secret-password"
  db_engine   = var.db_engine   # e.g., "postgres"
  db_host     = var.db_host     # e.g., "mydb.cluster-xxx.us-east-1.rds.amazonaws.com"
  db_port     = var.db_port     # e.g., 5432
  db_name     = var.db_name     # e.g., "myapp"

  # API keys — only used if create_api_secret = true
  api_key    = var.api_key    # e.g., "key-abc123"
  api_secret = var.api_secret # e.g., "secret-xyz789"

  # App config — only used if create_app_config_secret = true
  app_config = var.app_config # e.g., { "LOG_LEVEL" = "info" }

  tags = {
    Environment = var.environment
    Terraform   = "true"
    Module      = "secrets-manager"
  }
}


# =============================================================================
# MODULE: SECURITY (NEW — Not in reference)
# =============================================================================
# Adds AWS-native security monitoring services:
#   - Amazon GuardDuty: Threat detection (analyzes EKS audit logs, VPC flow logs)
#   - AWS Config: Configuration compliance monitoring
#
# These services detect security issues AFTER deployment:
#   - Unauthorized API calls
#   - Compromised credentials
#   - Cryptocurrency mining
#   - Non-compliant configurations
#
# COST NOTE: GuardDuty charges per GB of data analyzed. For a small cluster,
# expect ~$5-15/month. AWS Config charges per rule evaluation (~$0.001 each).
# =============================================================================
module "security" {
  source = "./modules/security"

  cluster_name     = var.cluster_name
  enable_guardduty = var.enable_guardduty  # Default: true
  enable_config    = var.enable_aws_config # Default: true

  tags = {
    Environment = var.environment
    Terraform   = "true"
    Module      = "security"
  }
}
