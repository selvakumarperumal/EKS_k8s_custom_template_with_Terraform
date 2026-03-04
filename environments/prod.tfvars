###############################################################################
# PRODUCTION ENVIRONMENT VARIABLES
# =============================================================================
# Used for live workloads.
# Focuses on high availability, performance, and security.
###############################################################################

environment  = "production"
cluster_name = "eks-prod-cluster"

# Networking - High Availability
enable_nat_gateway = true
single_nat_gateway = false # 1 NAT per AZ for High Availability

# Security & Compliance (Enabled for Prod)
enable_guardduty           = true
enable_aws_config          = true
enable_vpc_flow_logs       = true
enable_detailed_monitoring = false # Enable if 1-min EC2 metrics are needed over 5-min
enable_cluster_logging     = true  # CloudWatch control plane logs

# Node Groups - Performance and Stability
node_groups = {
  general = {
    desired_size   = 3
    min_size       = 3
    max_size       = 10
    instance_types = ["m5.large", "m5a.large"]
    capacity_type  = "ON_DEMAND"
    disk_size      = 50
    labels = {
      Environment = "production"
      Type        = "general"
    }
  }
}
