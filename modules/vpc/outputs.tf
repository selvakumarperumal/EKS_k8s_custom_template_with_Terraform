###############################################################################
# VPC MODULE — OUTPUTS
# =============================================================================
# Outputs expose values from this module to the calling module (root main.tf).
# These values are used to connect the VPC module to other modules (EKS, etc.)
#
# HOW OUTPUTS WORK:
# 1. This module creates resources and exposes their attributes as outputs
# 2. The root module accesses them as: module.vpc.<output_name>
# 3. Example: module.vpc.vpc_id → the VPC's unique identifier
#
# [*] SYNTAX:
# The [*] operator extracts a specific attribute from all instances created
# by count. For example, aws_subnet.public[*].id returns:
#   ["subnet-aaa", "subnet-bbb", "subnet-ccc"]
###############################################################################


# =============================================================================
# VPC OUTPUTS
# =============================================================================

# The VPC ID — needed by almost every AWS resource that lives in the VPC.
# Example usage: Security groups, EKS cluster, RDS instances all need this.
output "vpc_id" {
  description = "The ID of the VPC"
  value       = aws_vpc.main.id # e.g., "vpc-0abc123def456"
}

# The VPC CIDR block — useful for security groups that allow intra-VPC traffic.
output "vpc_cidr_block" {
  description = "The CIDR block of the VPC"
  value       = aws_vpc.main.cidr_block # e.g., "10.0.0.0/16"
}


# =============================================================================
# SUBNET OUTPUTS
# =============================================================================

# List of public subnet IDs — used for ALB, NAT Gateway placement.
output "public_subnets" {
  description = "List of IDs of public subnets"
  value       = aws_subnet.public[*].id # e.g., ["subnet-001", "subnet-002", "subnet-003"]
}

# List of private subnet IDs — used for EKS node group placement.
output "private_subnets" {
  description = "List of IDs of private subnets"
  value       = aws_subnet.private[*].id
}

# Subnet CIDR blocks — useful for security group rules that reference subnets.
output "public_subnet_cidrs" {
  description = "List of CIDR blocks of public subnets"
  value       = aws_subnet.public[*].cidr_block # e.g., ["10.0.101.0/24", ...]
}

output "private_subnet_cidrs" {
  description = "List of CIDR blocks of private subnets"
  value       = aws_subnet.private[*].cidr_block
}


# =============================================================================
# GATEWAY OUTPUTS
# =============================================================================

# Internet Gateway ID — rarely needed externally, but useful for debugging.
output "internet_gateway_id" {
  description = "ID of the Internet Gateway"
  value       = aws_internet_gateway.main.id
}

# NAT Gateway IDs — useful for monitoring and troubleshooting.
output "nat_gateway_ids" {
  description = "List of NAT Gateway IDs"
  value       = aws_nat_gateway.main[*].id
}

# NAT Gateway public IPs — important for allowlisting in external firewalls.
# All outbound traffic from private subnets appears to come from these IPs.
output "nat_gateway_public_ips" {
  description = "List of public IPs of NAT Gateways (add to external allowlists)"
  value       = aws_eip.nat[*].public_ip # e.g., ["54.123.45.67"]
}


# =============================================================================
# ROUTE TABLE OUTPUTS
# =============================================================================

output "public_route_table_id" {
  description = "ID of the public route table"
  value       = aws_route_table.public.id
}

output "private_route_table_ids" {
  description = "List of IDs of private route tables"
  value       = aws_route_table.private[*].id
}


# =============================================================================
# FLOW LOG OUTPUTS (Optional — only when enable_vpc_flow_logs = true)
# =============================================================================

# Flow log ID and log group — useful for monitoring and alerting setup.
output "flow_log_id" {
  description = "ID of the VPC Flow Log (empty if flow logs disabled)"
  value       = var.enable_flow_logs ? aws_flow_log.main[0].id : ""
}

output "flow_log_group_name" {
  description = "Name of the CloudWatch log group for VPC Flow Logs (empty if disabled)"
  value       = var.enable_flow_logs ? aws_cloudwatch_log_group.flow_log[0].name : ""
}
