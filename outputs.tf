###############################################################################
# OUTPUTS
# =============================================================================
# Outputs expose important values after `terraform apply` completes.
# They serve multiple purposes:
#   1. Display key information in the terminal (cluster endpoint, etc.)
#   2. Allow other Terraform configurations to reference these values
#   3. Enable automation scripts to extract values (terraform output -json)
#
# SENSITIVE OUTPUTS:
# Values marked as `sensitive = true` are hidden from terminal output.
# You can still access them via: terraform output -json <name>
###############################################################################


# =============================================================================
# VPC OUTPUTS
# =============================================================================
# These outputs expose the networking layer details. Useful for:
#   - Deploying additional resources in the same VPC
#   - Configuring VPN/Direct Connect
#   - Debugging network connectivity issues
# =============================================================================

output "vpc_id" {
  description = "The ID of the VPC (e.g., vpc-0abc123def456)"
  value       = module.vpc.vpc_id
}

output "vpc_cidr_block" {
  description = "The CIDR block of the VPC (e.g., 10.0.0.0/16)"
  value       = module.vpc.vpc_cidr_block
}

output "private_subnet_ids" {
  description = "List of private subnet IDs where EKS worker nodes are deployed"
  value       = module.vpc.private_subnets
}

output "public_subnet_ids" {
  description = "List of public subnet IDs where load balancers and NAT Gateway reside"
  value       = module.vpc.public_subnets
}

output "nat_gateway_public_ips" {
  description = "Public IP(s) of the NAT Gateway(s) — add to allowlists for outbound traffic"
  value       = module.vpc.nat_gateway_public_ips
}


# =============================================================================
# EKS CLUSTER OUTPUTS
# =============================================================================
# These are the most commonly used outputs — you need them to configure
# kubectl and deploy applications to the cluster.
# =============================================================================

output "cluster_name" {
  description = "The name of the EKS cluster"
  value       = module.eks.cluster_name
}

output "cluster_endpoint" {
  description = "The endpoint URL for the EKS API server (used by kubectl)"
  value       = module.eks.cluster_endpoint
}

output "cluster_version" {
  description = "The Kubernetes version running on the cluster"
  value       = module.eks.cluster_version
}

output "cluster_arn" {
  description = "The ARN of the EKS cluster"
  value       = module.eks.cluster_arn
}

# -----------------------------------------------------------------------------
# CERTIFICATE AUTHORITY DATA
# -----------------------------------------------------------------------------
# The base64-encoded certificate data for the cluster. This is needed to
# configure kubectl to trust the cluster's API server.
#
# Marked as SENSITIVE because it's a security credential — exposing it
# could allow someone to craft a trusted connection to your cluster.
# -----------------------------------------------------------------------------
output "cluster_certificate_authority_data" {
  description = "Base64-encoded certificate data for kubectl authentication"
  value       = module.eks.cluster_certificate_authority_data
  sensitive   = true # Hidden from terraform output display
}

# -----------------------------------------------------------------------------
# KUBECTL CONFIGURATION COMMAND
# -----------------------------------------------------------------------------
# This is a convenience output that shows the exact command needed to
# configure kubectl after the cluster is created.
#
# After running `terraform apply`, copy this command and run it to
# add the cluster to your ~/.kube/config file.
# -----------------------------------------------------------------------------
output "configure_kubectl" {
  description = "Command to configure kubectl for this cluster"
  value       = "aws eks update-kubeconfig --region ${var.aws_region} --name ${module.eks.cluster_name}"
}


# =============================================================================
# SECURITY OUTPUTS
# =============================================================================

output "cluster_security_group_id" {
  description = "Security group ID for the EKS cluster control plane"
  value       = module.eks.cluster_security_group_id
}

output "node_security_group_id" {
  description = "Security group ID for the EKS worker nodes"
  value       = module.eks.node_security_group_id
}

output "cluster_kms_key_arn" {
  description = "ARN of the KMS key used for EKS secrets encryption"
  value       = module.eks.kms_key_arn
}

output "oidc_provider_arn" {
  description = "ARN of the OIDC provider for IRSA (IAM Roles for Service Accounts)"
  value       = module.eks.oidc_provider_arn
}


# =============================================================================
# IAM OUTPUTS
# =============================================================================

output "cluster_role_arn" {
  description = "ARN of the IAM role assumed by the EKS cluster service"
  value       = module.iam.cluster_role_arn
}

output "node_group_role_arn" {
  description = "ARN of the IAM role assumed by EKS worker node EC2 instances"
  value       = module.iam.node_group_role_arn
}


# =============================================================================
# LOGGING & MONITORING OUTPUTS
# =============================================================================

output "cloudwatch_log_group_name" {
  description = "Name of the CloudWatch log group for EKS control plane logs"
  value       = module.eks.cloudwatch_log_group_name
}


# =============================================================================
# SECRETS MANAGER OUTPUTS (Conditional)
# =============================================================================
# These outputs are only meaningful when the corresponding secrets are enabled.
# If a secret is not created, the value will be an empty string.
# =============================================================================

output "db_secret_arn" {
  description = "ARN of the database credentials secret in Secrets Manager"
  value       = module.secrets_manager.db_secret_arn
}

output "api_secret_arn" {
  description = "ARN of the API keys secret in Secrets Manager"
  value       = module.secrets_manager.api_secret_arn
}

output "app_config_secret_arn" {
  description = "ARN of the application config secret in Secrets Manager"
  value       = module.secrets_manager.app_config_secret_arn
}

output "read_secrets_policy_arn" {
  description = "ARN of the IAM policy for reading secrets (attach to pod IAM roles)"
  value       = module.secrets_manager.read_secrets_policy_arn
}
