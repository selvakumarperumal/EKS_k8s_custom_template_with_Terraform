###############################################################################
# IAM MODULE — OUTPUTS
# =============================================================================
# Exposes IAM role ARNs and names for use by the EKS module.
# The EKS module needs:
#   - cluster_role_arn: To assign the control plane role during cluster creation
#   - node_group_role_arn: To assign the node role to managed node groups
#
# ARN (Amazon Resource Name) is the globally unique identifier for any
# AWS resource. Format: arn:aws:iam::<account-id>:role/<role-name>
###############################################################################


# =============================================================================
# CLUSTER ROLE OUTPUTS
# =============================================================================

# The ARN of the cluster IAM role — passed to aws_eks_cluster.role_arn
output "cluster_role_arn" {
  description = "ARN of the EKS cluster IAM role"
  value       = aws_iam_role.cluster.arn # e.g., "arn:aws:iam::123456789:role/eks-cluster-abc"
}

# The name of the cluster role — useful for additional policy attachments
output "cluster_role_name" {
  description = "Name of the EKS cluster IAM role"
  value       = aws_iam_role.cluster.name
}


# =============================================================================
# NODE GROUP ROLE OUTPUTS
# =============================================================================

# The ARN of the node group role — passed to aws_eks_node_group.node_role_arn
output "node_group_role_arn" {
  description = "ARN of the node group IAM role"
  value       = aws_iam_role.node_group.arn
}

# The name of the node group role — useful for additional policy attachments
# Example: Attaching a custom policy for S3 access or Secrets Manager access
output "node_group_role_name" {
  description = "Name of the node group IAM role"
  value       = aws_iam_role.node_group.name
}
