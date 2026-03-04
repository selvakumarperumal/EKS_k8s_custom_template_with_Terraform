###############################################################################
# TERRAFORM VARIABLE VALUES
# =============================================================================
# This file sets the actual values for the variables defined in variables.tf.
# Terraform automatically loads files named "terraform.tfvars" or
# "*.auto.tfvars" during plan/apply.
#
# USAGE:
#   terraform plan    ← reads this file automatically
#   terraform apply   ← reads this file automatically
#
# OVERRIDE:
#   terraform plan -var="cluster_name=my-cluster"   ← overrides this file
#   terraform plan -var-file="prod.tfvars"          ← uses a different file
#
# SECURITY NOTE:
# This file should NOT contain real passwords or API keys!
# Use environment variables (TF_VAR_db_password) or a secrets manager instead.
# Add this file to .gitignore if it contains any sensitive values.
###############################################################################


# =============================================================================
# GENERAL SETTINGS
# =============================================================================

# AWS region where all resources will be created
# Change to a region closer to your users for lower latency
aws_region = "us-east-1"

# Name of the EKS cluster — used as prefix for all resource names
# Example: "eks-secure-cluster-vpc", "eks-secure-cluster-node-sg"
cluster_name = "eks-secure-cluster"

# Kubernetes version for the EKS cluster
# Run `aws eks describe-addon-versions` to see supported versions
kubernetes_version = "1.31"

# Deployment environment — affects tagging
# Options: "development", "staging", "production"
environment = "development"


# =============================================================================
# NETWORKING
# =============================================================================

# VPC CIDR — the overall IP range for the VPC
# /16 = 65,536 IPs — recommended for EKS (each pod needs an IP)
vpc_cidr = "10.0.0.0/16"

# Private subnets — EKS worker nodes and internal services go here
# 3 subnets = one per AZ = high availability
# /24 = 254 usable IPs per subnet
private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]

# Public subnets — NAT Gateway, ALB, and bastion hosts go here
# The 101/102/103 range is chosen to visually separate from private subnets
public_subnets = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]


# =============================================================================
# EKS SECURITY
# =============================================================================

# CIDRs that can access the EKS API server from the internet
# ⚠️ CHANGE THIS IN PRODUCTION to your office/VPN CIDR!
# Example: ["203.0.113.0/24"] to restrict to your network
public_access_cidrs = ["0.0.0.0/0"]

# Enable public access to the EKS API server
# Set to false for private-only clusters (access via VPN/bastion only)
enable_public_endpoint = true

# Enable private access to the EKS API server
# ALWAYS keep this true — nodes communicate with the API via private endpoint
enable_private_endpoint = true


# =============================================================================
# SECURITY SERVICES
# =============================================================================

# Enable GuardDuty for threat detection on EKS
# Detects: compromised credentials, crypto mining, unauthorized access
enable_guardduty = true

# Enable AWS Config for compliance monitoring
# Checks: log encryption, public endpoint restrictions, security group rules
enable_aws_config = true


# =============================================================================
# SECRETS MANAGER (Optional — disabled by default)
# =============================================================================
# Uncomment and fill in values to create secrets in AWS Secrets Manager.
# These secrets can be consumed by pods using External Secrets Operator.

# enable_db_secret = true
# db_username      = "admin"
# db_password      = "change-me-in-production"
# db_engine        = "postgres"
# db_host          = "mydb.cluster-xxx.us-east-1.rds.amazonaws.com"
# db_port          = 5432
# db_name          = "myapp"

# enable_api_secret = true
# api_key           = "your-api-key"
# api_secret        = "your-api-secret"

# enable_app_config_secret = true
# app_config = {
#   LOG_LEVEL    = "info"
#   FEATURE_FLAG = "true"
#   APP_ENV      = "production"
# }
