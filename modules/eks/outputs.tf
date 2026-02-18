###############################################################################
# EKS MODULE — OUTPUTS
# =============================================================================
# Outputs from the EKS module expose cluster details needed by:
#   - The root module outputs (for user visibility)
#   - kubectl configuration
#   - Other tools that integrate with EKS (Helm, ArgoCD, etc.)
###############################################################################


# =============================================================================
# CLUSTER IDENTITY
# =============================================================================

output "cluster_id" {
  description = "The unique ID of the EKS cluster"
  value       = aws_eks_cluster.main.id
}

output "cluster_name" {
  description = "The name of the EKS cluster"
  value       = aws_eks_cluster.main.name
}

output "cluster_arn" {
  description = "The ARN (Amazon Resource Name) of the EKS cluster"
  value       = aws_eks_cluster.main.arn
}


# =============================================================================
# CLUSTER CONNECTIVITY
# =============================================================================

# The HTTPS endpoint for the Kubernetes API server.
# Used by kubectl, Helm, and other tools to communicate with the cluster.
# Example: "https://ABCDEF0123456789.gr7.us-east-1.eks.amazonaws.com"
output "cluster_endpoint" {
  description = "Endpoint URL for the EKS Kubernetes API server"
  value       = aws_eks_cluster.main.endpoint
}

output "cluster_version" {
  description = "The Kubernetes version running on the cluster"
  value       = aws_eks_cluster.main.version
}

# Certificate authority data — needed for kubectl to trust the API server.
# This is the TLS certificate that proves the API server's identity.
# Marked sensitive because exposing it could enable impersonation attacks.
output "cluster_certificate_authority_data" {
  description = "Base64-encoded CA certificate data for cluster authentication"
  value       = aws_eks_cluster.main.certificate_authority[0].data
  sensitive   = true
}


# =============================================================================
# SECURITY
# =============================================================================

output "cluster_security_group_id" {
  description = "Security group ID for the EKS cluster control plane"
  value       = aws_security_group.cluster.id
}

output "node_security_group_id" {
  description = "Security group ID for the EKS worker nodes"
  value       = aws_security_group.node.id
}

output "kms_key_id" {
  description = "ID of the KMS key used for cluster secrets encryption"
  value       = aws_kms_key.eks.id
}

output "kms_key_arn" {
  description = "ARN of the KMS key used for cluster secrets encryption"
  value       = aws_kms_key.eks.arn
}


# =============================================================================
# OIDC / IRSA
# =============================================================================

# The OIDC issuer URL — used when creating IRSA IAM roles.
# try() gracefully handles the case where OIDC isn't configured.
output "cluster_oidc_issuer_url" {
  description = "The OIDC issuer URL for the EKS cluster"
  value       = try(aws_eks_cluster.main.identity[0].oidc[0].issuer, "")
}

output "oidc_provider_arn" {
  description = "ARN of the OIDC provider for IRSA"
  value       = var.enable_irsa ? aws_iam_openid_connect_provider.cluster[0].arn : ""
}

output "oidc_provider_url" {
  description = "URL of the OIDC provider for IRSA"
  value       = var.enable_irsa ? aws_iam_openid_connect_provider.cluster[0].url : ""
}


# =============================================================================
# LOGGING
# =============================================================================

output "cloudwatch_log_group_name" {
  description = "Name of the CloudWatch log group for control plane logs (empty if disabled)"
  value       = var.enable_cluster_logging ? aws_cloudwatch_log_group.eks[0].name : ""
}


# =============================================================================
# NODE GROUPS
# =============================================================================

output "node_groups" {
  description = "Map of all created node group resources and their attributes"
  value       = aws_eks_node_group.main
}
