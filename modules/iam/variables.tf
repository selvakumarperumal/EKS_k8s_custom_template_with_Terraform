###############################################################################
# IAM MODULE — INPUT VARIABLES
# =============================================================================
# Variables for the IAM module. Kept minimal because IAM roles are
# primarily driven by the cluster name (for naming) and tags (for auditing).
###############################################################################

# The EKS cluster name — used as a prefix for IAM role names.
# This ensures roles are uniquely named per cluster.
# Example: "eks-secure-cluster" → role name "eks-secure-cluster-cluster-abc123"
variable "cluster_name" {
  description = "Name of the EKS cluster (used as prefix for IAM role names)"
  type        = string
}

# Tags applied to all IAM resources.
# IAM roles, while global (not region-specific), still support tags for:
#   - Cost allocation (which project owns this role?)
#   - Access control (IAM policies can restrict actions by tag)
#   - Auditing (who created this role and when?)
variable "tags" {
  description = "Tags to apply to all IAM resources"
  type        = map(string)
  default     = {}
}
