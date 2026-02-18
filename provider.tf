###############################################################################
# PROVIDER CONFIGURATION
# =============================================================================
# This file configures the Terraform version constraints, required providers,
# and the AWS provider settings. It is the first file Terraform reads to
# understand which cloud provider to use and how to authenticate.
#
# WHY THIS FILE EXISTS:
# ---------------------
# Terraform is cloud-agnostic — it supports AWS, Azure, GCP, etc. This file
# tells Terraform: "We are using AWS, and here's how to connect to it."
#
# SECURITY NOTES:
# ---------------
# 1. We pin provider versions to prevent unexpected breaking changes
# 2. We use default_tags to ensure every resource is tagged for auditing
# 3. The S3 backend (commented) stores state remotely with encryption
###############################################################################

# =============================================================================
# TERRAFORM BLOCK
# =============================================================================
# The `terraform` block configures Terraform itself — not any specific provider.
# It specifies:
#   - required_version: The minimum Terraform CLI version required
#   - required_providers: Which provider plugins to download and their versions
# =============================================================================
terraform {

  # ---------------------------------------------------------------------------
  # REQUIRED VERSION
  # ---------------------------------------------------------------------------
  # ">= 1.14" means this code requires Terraform CLI version 1.14.0 or newer.
  # This ensures features like `optional()` in variable types, `moved` blocks,
  # and the latest state management improvements are available.
  #
  # WHY PIN VERSIONS?
  # If someone uses an older Terraform version, they might get cryptic errors.
  # This constraint gives them a clear error message instead:
  #   "Error: Unsupported Terraform Core version"
  # ---------------------------------------------------------------------------
  required_version = ">= 1.14"

  # ---------------------------------------------------------------------------
  # REQUIRED PROVIDERS
  # ---------------------------------------------------------------------------
  # Providers are plugins that let Terraform interact with cloud APIs.
  # Each provider has:
  #   - source:  The registry address (registry.terraform.io/hashicorp/aws)
  #   - version: A version constraint to pin compatible versions
  # ---------------------------------------------------------------------------
  required_providers {

    # -------------------------------------------------------------------------
    # AWS PROVIDER
    # -------------------------------------------------------------------------
    # The AWS provider lets Terraform manage AWS resources (VPC, EKS, IAM, etc.)
    #
    # "~> 6.0" means:
    #   ✅ 6.0, 6.1, 6.2, ... 6.32, 6.99 (any 6.x version)
    #   ❌ 7.0 or higher (major version change = potential breaking changes)
    #
    # This is called a "pessimistic version constraint" — it allows patch/minor
    # updates but blocks major version upgrades that might break your code.
    # -------------------------------------------------------------------------
    aws = {
      source  = "hashicorp/aws" # Download from HashiCorp's official registry
      version = "~> 6.0"        # Allow 6.x versions, block 7.0+
    }

    # -------------------------------------------------------------------------
    # TLS PROVIDER
    # -------------------------------------------------------------------------
    # The TLS provider is used to fetch the TLS certificate from the EKS OIDC
    # issuer URL. This certificate thumbprint is required to set up IRSA
    # (IAM Roles for Service Accounts) — a key security feature.
    #
    # Without this provider, we can't securely map Kubernetes ServiceAccounts
    # to AWS IAM roles.
    # -------------------------------------------------------------------------
    tls = {
      source  = "hashicorp/tls" # Official HashiCorp TLS provider
      version = "~> 4.0"        # Allow 4.x versions
    }
  }

  # ---------------------------------------------------------------------------
  # BACKEND CONFIGURATION (S3 — Recommended for Production)
  # ---------------------------------------------------------------------------
  # By default, Terraform stores state locally in `terraform.tfstate`.
  # For production, store it in S3 with:
  #   - Encryption: State files contain sensitive data (ARNs, IPs, etc.)
  #   - Locking: DynamoDB prevents two people from modifying state at once
  #   - Versioning: S3 versioning lets you recover from state corruption
  #
  # UNCOMMENT THE BLOCK BELOW for production use:
  # ---------------------------------------------------------------------------
  # backend "s3" {
  #   bucket         = "your-terraform-state-bucket"    # S3 bucket name
  #   key            = "eks/terraform.tfstate"          # Path within the bucket
  #   region         = "us-east-1"                      # Bucket region
  #   encrypt        = true                             # Encrypt state at rest
  #   dynamodb_table = "terraform-state-lock"           # DynamoDB table for locking
  #   # The DynamoDB table must have a partition key named "LockID" (String type)
  # }
}

# =============================================================================
# AWS PROVIDER CONFIGURATION
# =============================================================================
# This block configures HOW Terraform connects to AWS:
#   - region: Which AWS region to create resources in
#   - default_tags: Tags automatically applied to EVERY resource
#
# AUTHENTICATION:
# Terraform uses the AWS credentials from (in order of priority):
#   1. Environment variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
#   2. Shared credentials file: ~/.aws/credentials
#   3. IAM instance profile (if running on EC2)
#   4. ECS task role (if running in ECS)
#
# NEVER hardcode credentials in Terraform files!
# =============================================================================
provider "aws" {

  # ---------------------------------------------------------------------------
  # REGION
  # ---------------------------------------------------------------------------
  # var.aws_region is defined in variables.tf with a default of "us-east-1".
  # All resources (VPC, EKS, etc.) will be created in this region.
  #
  # EKS is a regional service — the cluster and nodes exist in one region.
  # For multi-region, you'd need separate provider aliases and configurations.
  # ---------------------------------------------------------------------------
  region = var.aws_region

  # ---------------------------------------------------------------------------
  # DEFAULT TAGS
  # ---------------------------------------------------------------------------
  # These tags are AUTOMATICALLY applied to every AWS resource created by this
  # provider. You don't need to specify them in each resource block.
  #
  # WHY USE DEFAULT TAGS?
  #   1. Cost tracking: Filter AWS Cost Explorer by "Project" or "ManagedBy"
  #   2. Security auditing: Quickly identify Terraform-managed resources
  #   3. Compliance: Many organizations require tagging policies
  #   4. Consistency: Prevents forgetting to tag individual resources
  #
  # These tags merge with resource-level tags. If there's a conflict,
  # the resource-level tag wins.
  # ---------------------------------------------------------------------------
  default_tags {
    tags = {
      ManagedBy   = "Terraform"           # Identifies IaC-managed resources
      Project     = "EKS-Custom-Template" # Project identifier for cost tracking
      Environment = var.environment       # dev/staging/production
    }
  }
}
