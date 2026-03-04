###############################################################################
# DEVELOPMENT ENVIRONMENT VARIABLES
# =============================================================================
# Used for testing, development, and QA.
# Focuses on cost-optimization (single NAT, SPOT instances, minimal nodes).
###############################################################################

environment  = "development"
cluster_name = "eks-dev-cluster"

# Networking - cost optimized
enable_nat_gateway = true
single_nat_gateway = true # Saves cost (~$33/mo instead of ~$100/mo)

# Security & Compliance (Optional for dev to save costs)
enable_guardduty           = false
enable_aws_config          = false
enable_vpc_flow_logs       = false
enable_detailed_monitoring = false
enable_cluster_logging     = false

# Node Groups - Cost optimized (Spot instances, smaller types)
node_groups = {
  spot = {
    desired_size   = 2
    min_size       = 1
    max_size       = 3
    instance_types = ["t3.medium", "t3a.medium"]
    capacity_type  = "SPOT" # Huge cost savings for dev
    disk_size      = 20     # Minimal required
    labels = {
      Environment = "development"
      Type        = "spot"
    }
  }
}
