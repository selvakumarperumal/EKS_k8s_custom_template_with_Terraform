###############################################################################
# IAM MODULE — MAIN CONFIGURATION
# =============================================================================
# This module creates IAM (Identity and Access Management) roles for EKS.
# IAM controls WHO can do WHAT in AWS. EKS needs two roles:
#
# 1. CLUSTER ROLE — Assumed by the EKS service itself
#    The EKS control plane uses this role to:
#    - Manage the Kubernetes API server
#    - Create/manage ENIs for pod networking
#    - Write logs to CloudWatch
#
# 2. NODE GROUP ROLE — Assumed by EC2 worker node instances
#    Worker nodes use this role to:
#    - Register themselves with the EKS cluster
#    - Pull container images from ECR
#    - Assign IPs to pods via the VPC CNI plugin
#
# IAM ROLE ANATOMY:
# ────────────────────────────────────────────────────────────────────────
# An IAM role has TWO parts:
#
# 1. TRUST POLICY (assume_role_policy) — WHO can assume this role
#    "I trust eks.amazonaws.com to use this role"
#
# 2. PERMISSIONS POLICIES (policy_attachment) — WHAT the role can do
#    "This role can create ENIs, write logs, etc."
#
# Think of it like a badge: the trust policy says who can WEAR the badge,
# and the permissions say what the badge UNLOCKS.
# ────────────────────────────────────────────────────────────────────────
#
# SECURITY PRINCIPLE: LEAST PRIVILEGE
# We only attach the minimum AWS-managed policies required for EKS to
# function. No wildcard (*) permissions. No inline policies.
###############################################################################


# =============================================================================
# EKS CLUSTER IAM ROLE
# =============================================================================
# This role is assumed by the EKS service to manage the Kubernetes control plane.
# Without this role, EKS cannot create or manage the cluster.
#
# name_prefix vs name:
# - name_prefix creates a unique name like "eks-secure-cluster-cluster-abcdef"
# - This prevents conflicts when you have multiple clusters in one account
# - The suffix is a random string added by AWS for uniqueness
# =============================================================================
resource "aws_iam_role" "cluster" {
  name_prefix = "${var.cluster_name}-cluster-" # e.g., "eks-secure-cluster-cluster-abc123"

  # ---------------------------------------------------------------------------
  # TRUST POLICY (Who can assume this role?)
  # ---------------------------------------------------------------------------
  # This JSON document says:
  # "The EKS service (eks.amazonaws.com) is ALLOWED to ASSUME this role."
  #
  # When EKS assumes this role, it temporarily gets the permissions from
  # the attached policies (below). This is called STS (Security Token Service).
  #
  # jsonencode() converts a Terraform map/object to a JSON string.
  # This is cleaner than writing raw JSON in heredoc syntax.
  # ---------------------------------------------------------------------------
  assume_role_policy = jsonencode({
    Version = "2012-10-17" # IAM policy version (always use "2012-10-17")
    Statement = [{
      Action = "sts:AssumeRole" # The action: "assume this role"
      Effect = "Allow"          # Allow (not deny)
      Principal = {
        Service = "eks.amazonaws.com" # Only the EKS service can assume this role
        # NOT your user, NOT Lambda, NOT EC2 — ONLY EKS
      }
    }]
  })

  tags = var.tags
}

# =============================================================================
# CLUSTER ROLE — POLICY ATTACHMENTS
# =============================================================================
# AWS provides pre-built "managed policies" for common use cases.
# These are maintained by AWS and automatically updated when new features
# are released. Using managed policies is more secure than writing custom
# policies because they follow the least-privilege principle.
# =============================================================================

# ---------------------------------------------------------------------------
# POLICY: AmazonEKSClusterPolicy
# ---------------------------------------------------------------------------
# This managed policy grants the EKS service permissions to:
#   - Create and manage the Kubernetes API server
#   - Manage cluster networking (ENIs, security groups)
#   - Publish metrics and logs
#   - Manage cluster add-ons
#
# Without this policy, `terraform apply` would fail with:
#   "InvalidParameterException: The role does not have the
#    AmazonEKSClusterPolicy attached"
# ---------------------------------------------------------------------------
resource "aws_iam_role_policy_attachment" "cluster_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.cluster.name # Attach to the cluster role
}

# ---------------------------------------------------------------------------
# POLICY: AmazonEKSVPCResourceController
# ---------------------------------------------------------------------------
# This policy allows the EKS cluster to manage VPC resources like ENIs
# (Elastic Network Interfaces). This is needed for:
#   - Pod networking (each pod gets its own ENI/IP)
#   - Security groups for pods (if using trunk ENIs)
#   - Network policy enforcement
#
# This is especially important when using the VPC CNI plugin, which
# assigns VPC IPs directly to pods for native networking performance.
# ---------------------------------------------------------------------------
resource "aws_iam_role_policy_attachment" "cluster_vpc_resource_controller" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
  role       = aws_iam_role.cluster.name
}


# =============================================================================
# NODE GROUP IAM ROLE
# =============================================================================
# This role is assumed by EC2 instances that serve as EKS worker nodes.
# Each node uses this role to:
#   - Register with the EKS cluster (kubelet talks to the API server)
#   - Pull container images from ECR (Elastic Container Registry)
#   - Assign IP addresses to pods (via VPC CNI plugin)
#
# KEY DIFFERENCE FROM CLUSTER ROLE:
# - Cluster role: Service = eks.amazonaws.com (the EKS control plane)
# - Node role:    Service = ec2.amazonaws.com (the actual EC2 instances)
# =============================================================================
resource "aws_iam_role" "node_group" {
  name_prefix = "${var.cluster_name}-node-" # e.g., "eks-secure-cluster-node-def456"

  # Trust policy: EC2 instances can assume this role
  # When an EC2 instance starts as a worker node, it uses the instance profile
  # to assume this role and get the necessary permissions.
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com" # EC2 instances can assume this role
      }
    }]
  })

  tags = var.tags
}

# =============================================================================
# NODE GROUP ROLE — POLICY ATTACHMENTS
# =============================================================================
# Worker nodes need three managed policies to function correctly.
# Each policy serves a specific purpose — together they provide the
# minimum permissions a node needs to join the cluster and run pods.
# =============================================================================

# ---------------------------------------------------------------------------
# POLICY: AmazonEKSWorkerNodePolicy
# ---------------------------------------------------------------------------
# Allows the kubelet (Kubernetes agent on each node) to:
#   - Communicate with the EKS API server
#   - Get cluster configuration
#   - Report node status and health
#   - Describe EC2 instances and resource for labels
#
# Without this, the kubelet can't register the node with the cluster.
# You'd see nodes stuck in "NotReady" state.
# ---------------------------------------------------------------------------
resource "aws_iam_role_policy_attachment" "node_worker_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.node_group.name
}

# ---------------------------------------------------------------------------
# POLICY: AmazonEKS_CNI_Policy
# ---------------------------------------------------------------------------
# The VPC CNI plugin runs as a DaemonSet on every node. It:
#   - Allocates VPC IP addresses to pods
#   - Creates and manages ENIs attached to the node
#   - Configures pod networking for native VPC performance
#
# This policy grants the CNI plugin permissions to:
#   - CreateNetworkInterface, AttachNetworkInterface
#   - AssignPrivateIpAddresses, ModifyNetworkInterfaceAttribute
#   - Describe and list network interfaces
#
# SECURITY NOTE: In production, consider moving this policy to IRSA
# (IAM Role for Service Accounts) for the aws-node ServiceAccount.
# This follows the principle of least privilege — only the CNI pods
# get this permission, not all processes on the node.
# ---------------------------------------------------------------------------
resource "aws_iam_role_policy_attachment" "node_cni_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.node_group.name
}

# ---------------------------------------------------------------------------
# POLICY: AmazonEC2ContainerRegistryReadOnly
# ---------------------------------------------------------------------------
# Allows nodes to PULL (but NOT push) container images from:
#   - Amazon ECR (Elastic Container Registry) — both public and private
#   - This includes base images, application images, and sidecar images
#
# Without this policy, pods would fail to start with:
#   "Failed to pull image: no basic auth credentials"
#
# READ-ONLY is intentional — nodes should never push images.
# Image pushing should happen in CI/CD pipelines with different credentials.
# ---------------------------------------------------------------------------
resource "aws_iam_role_policy_attachment" "node_registry_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.node_group.name
}
