###############################################################################
# EKS MODULE — MAIN CONFIGURATION
# =============================================================================
# This is the core module that creates the EKS cluster and all its
# supporting resources. This is the most complex module with many
# interconnected components.
#
# WHAT THIS MODULE CREATES (in dependency order):
# ────────────────────────────────────────────────────────────────────────
# 1. KMS Key           — Encrypts Kubernetes secrets at rest
# 2. CloudWatch Logs   — Stores control plane audit logs
# 3. Security Groups   — Network-level access control for cluster & nodes
# 4. EKS Cluster       — The Kubernetes control plane (managed by AWS)
# 5. OIDC Provider     — Enables IRSA (pods assume IAM roles)
# 6. EKS Addons        — CoreDNS, kube-proxy, VPC CNI
# 7. Launch Templates  — EC2 instance configuration for nodes
# 8. Node Groups       — The actual worker EC2 instances
#
# SECURITY FEATURES:
# ────────────────────────────────────────────────────────────────────────
# ✅ KMS encryption for Kubernetes secrets (envelope encryption)
# ✅ All 5 control plane log types enabled (api, audit, authenticator, etc.)
# ✅ Custom security groups with minimal ingress/egress rules
# ✅ IMDSv2 enforced (prevents SSRF credential theft)
# ✅ Encrypted EBS volumes (gp3 with 3000 IOPS)
# ✅ Private node placement (no public IPs on nodes)
# ✅ IRSA enabled (pods get their own IAM roles)
###############################################################################


# =============================================================================
# KMS KEY FOR CLUSTER ENCRYPTION
# =============================================================================
# KMS (Key Management Service) provides encryption keys for data at rest.
# We use a KMS key to enable "envelope encryption" for Kubernetes secrets.
#
# ENVELOPE ENCRYPTION:
# 1. Kubernetes generates a Data Encryption Key (DEK) for each secret
# 2. The DEK encrypts the secret data
# 3. The KMS key encrypts the DEK itself (key-encrypting-key)
# 4. Both the encrypted secret and encrypted DEK are stored in etcd
#
# WHY? Without this, secrets in etcd are stored in base64 (NOT encrypted).
# Anyone with etcd access could read them. With KMS, even etcd access
# doesn't reveal the actual secret values.
#
# enable_key_rotation = true:
#   AWS automatically rotates the key material every year.
#   Old data encrypted with previous key versions can still be decrypted.
#
# deletion_window_in_days = 7:
#   After you delete this key, there's a 7-day grace period before it's
#   permanently destroyed. This prevents accidental data loss.
# =============================================================================
resource "aws_kms_key" "eks" {
  description             = "KMS key for EKS cluster ${var.cluster_name} encryption"
  deletion_window_in_days = 7    # 7-day grace period before permanent deletion
  enable_key_rotation     = true # Auto-rotate key material annually

  tags = merge(
    var.tags,
    {
      Name = "${var.cluster_name}-eks-kms"
    }
  )
}

# KMS alias — a human-friendly name for the KMS key.
# Instead of referencing "key-id-abc123...", you can use "alias/eks-secure-cluster-eks"
# Aliases make it easy to identify keys in the AWS Console.
resource "aws_kms_alias" "eks" {
  name          = "alias/${var.cluster_name}-eks" # e.g., "alias/eks-secure-cluster-eks"
  target_key_id = aws_kms_key.eks.key_id          # Points to the actual key above
}


# =============================================================================
# CLOUDWATCH LOG GROUP FOR EKS CONTROL PLANE LOGS (OPTIONAL)
# =============================================================================
# EKS sends control plane logs to CloudWatch Logs. We pre-create the log
# group so we can control:
#   - Retention period (how long to keep logs)
#   - Encryption (optionally encrypt with KMS)
#   - Access permissions
#
# LOG TYPES WE ENABLE (all 5 when enabled):
# 1. api           — Kubernetes API server requests (who did what?)
# 2. audit         — Detailed audit trail (required for compliance)
# 3. authenticator — Authentication decisions (who logged in?)
# 4. controllerManager — Controller actions (scaling, deployments)
# 5. scheduler     — Pod scheduling decisions (where pods land)
#
# KUBE-NATIVE ALTERNATIVE:
#   → Falco: Runtime security and audit events (CNCF project)
#   → ELK/Loki: Centralized log aggregation
#   → Fluentd/Fluent Bit: Log forwarding
#
# To enable: set enable_cluster_logging = true in terraform.tfvars
# COST: ~$5-10/month depending on API request volume.
# =============================================================================
resource "aws_cloudwatch_log_group" "eks" {
  count             = var.enable_cluster_logging ? 1 : 0
  name              = "/aws/eks/${var.cluster_name}/cluster" # AWS naming convention
  retention_in_days = 30                                     # Keep logs for 30 days (adjust per compliance needs)
  # For production: consider 90 days or 1 year for compliance

  tags = var.tags
}


# =============================================================================
# CLUSTER SECURITY GROUP
# =============================================================================
# This security group is attached to the EKS cluster's ENIs (Elastic Network
# Interfaces) — the network interfaces used by the Kubernetes API server.
#
# SECURITY GROUPS vs NACLs:
# - Security groups are STATEFUL: if you allow inbound TCP/443, the response
#   is automatically allowed outbound (no explicit egress rule needed)
# - NACLs are STATELESS: you need explicit rules for both directions
#
# name_prefix vs name:
# - name_prefix adds a random suffix for uniqueness
# - This prevents "name already exists" errors during updates
#
# lifecycle { create_before_destroy = true }:
# - When Terraform needs to replace this SG, it creates the new one FIRST,
#   then migrates references, then deletes the old one
# - This prevents downtime during updates
# =============================================================================
resource "aws_security_group" "cluster" {
  name_prefix = "${var.cluster_name}-cluster-sg-" # Unique name with random suffix
  description = "Security group for EKS cluster control plane"
  vpc_id      = var.vpc_id # Place in the same VPC as the cluster

  # EGRESS: Allow ALL outbound traffic from the cluster
  # The control plane needs to communicate with:
  #   - Worker nodes (for kubelet commands)
  #   - AWS services (CloudWatch, ELB, ECR, etc.)
  #   - OIDC provider (for IRSA)
  egress {
    from_port   = 0             # All ports
    to_port     = 0             # (0,0 with protocol -1 = all traffic)
    protocol    = "-1"          # All protocols (-1 = any)
    cidr_blocks = ["0.0.0.0/0"] # To any destination
    description = "Allow all outbound traffic"
  }

  tags = merge(
    var.tags,
    {
      Name = "${var.cluster_name}-cluster-sg"
    }
  )

  lifecycle {
    create_before_destroy = true # Avoid downtime during SG replacement
  }
}


# =============================================================================
# NODE SECURITY GROUP
# =============================================================================
# This security group is attached to worker node ENIs. It controls what
# traffic can reach the nodes and what they can send out.
#
# KEY TAG: "kubernetes.io/cluster/${var.cluster_name}" = "owned"
# This tag tells the AWS Load Balancer Controller that this SG is managed
# by the EKS cluster. The controller uses it when creating target groups
# for Services of type LoadBalancer.
# =============================================================================
resource "aws_security_group" "node" {
  name_prefix = "${var.cluster_name}-node-sg-"
  description = "Security group for EKS worker nodes"
  vpc_id      = var.vpc_id

  # EGRESS: Allow ALL outbound traffic from nodes
  # Nodes need unrestricted outbound for:
  #   - Pulling container images (docker.io, ECR, quay.io, etc.)
  #   - DNS resolution (UDP/53)
  #   - Communication with the EKS API server
  #   - Communication with other nodes
  #   - Communication with AWS services (S3, DynamoDB, etc.)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }

  tags = merge(
    var.tags,
    {
      Name                                        = "${var.cluster_name}-node-sg"
      "kubernetes.io/cluster/${var.cluster_name}" = "owned" # Required for LB controller
    }
  )

  lifecycle {
    create_before_destroy = true
  }
}


# =============================================================================
# SECURITY GROUP RULES — INTER-COMPONENT COMMUNICATION
# =============================================================================
# These rules define the allowed communication paths between the EKS
# cluster control plane and the worker nodes. Each rule is defined as
# a separate resource for clarity and modularity.
#
# TRAFFIC FLOWS:
#   Node → Cluster (HTTPS/443):  kubelet → API server
#   Cluster → Node (1025-65535): API server → kubelet (logs, exec, port-forward)
#   Node → Node (all ports):     Pod-to-pod communication, service discovery
# =============================================================================

# ------- RULE 1: Nodes → Cluster API (HTTPS/443) --------
# The kubelet on each node communicates with the Kubernetes API server
# over HTTPS (port 443). This is how nodes:
#   - Report their health status
#   - Watch for pod scheduling decisions
#   - Push container logs
#
# source_security_group_id: Only traffic FROM the node SG is allowed
# security_group_id: The traffic is allowed INTO the cluster SG
resource "aws_security_group_rule" "node_to_cluster" {
  type                     = "ingress"                     # Inbound rule on the cluster SG
  from_port                = 443                           # HTTPS port
  to_port                  = 443                           # Single port
  protocol                 = "tcp"                         # TCP only
  security_group_id        = aws_security_group.cluster.id # Target: cluster SG
  source_security_group_id = aws_security_group.node.id    # Source: node SG
  description              = "Allow nodes to communicate with cluster API"
}

# ------- RULE 2: Cluster API → Nodes (1025-65535) --------
# The EKS control plane needs to communicate with nodes for:
#   - kubectl exec/attach/port-forward (SSH-like tunneling)
#   - Webhook callbacks (validating/mutating admission webhooks)
#   - Logs streaming
#   - Health checks
#
# Port range 1025-65535:
#   - kubelet listens on 10250
#   - Webhooks can listen on various high ports
#   - We open the full range for flexibility
resource "aws_security_group_rule" "cluster_to_node" {
  type                     = "ingress"
  from_port                = 1025
  to_port                  = 65535
  protocol                 = "tcp"
  security_group_id        = aws_security_group.node.id    # Target: node SG
  source_security_group_id = aws_security_group.cluster.id # Source: cluster SG
  description              = "Allow cluster control plane to communicate with nodes"
}

# ------- RULE 3: Node → Node (All ports/protocols) --------
# Pods on different nodes need to communicate freely.
# This enables:
#   - Pod-to-pod networking (via VPC CNI)
#   - Service discovery (CoreDNS, UDP/53)
#   - Health checks between pods
#   - Metrics collection (Prometheus scraping)
#
# self = true: This rule allows traffic FROM the SG TO the same SG.
# All nodes share the same SG, so this effectively allows node-to-node traffic.
resource "aws_security_group_rule" "node_to_node" {
  type              = "ingress"
  from_port         = 0     # All ports
  to_port           = 65535 # All ports
  protocol          = "-1"  # All protocols (TCP, UDP, ICMP)
  security_group_id = aws_security_group.node.id
  self              = true # Traffic from same SG is allowed
  description       = "Allow nodes to communicate with each other"
}


# =============================================================================
# EKS CLUSTER
# =============================================================================
# This is the core resource — it creates the EKS Kubernetes control plane.
# AWS manages the control plane (API server, etcd, controllers, scheduler)
# on your behalf. You don't get direct access to control plane nodes.
#
# COMPONENTS MANAGED BY AWS:
#   - Kubernetes API Server (3 replicas across 3 AZs)
#   - etcd database (where all cluster state is stored)
#   - Controller Manager (handles Deployments, ReplicaSets, etc.)
#   - Scheduler (decides which node runs each pod)
#
# API SERVER ACCESS:
#   - endpoint_public_access: Reachable from the internet (via public_access_cidrs)
#   - endpoint_private_access: Reachable from within the VPC
#   - Best practice: Enable both, restrict public_access_cidrs
#
# ENCRYPTION:
#   - Encrypts Kubernetes secrets stored in etcd using our KMS key
#   - resources = ["secrets"] — currently EKS only supports encrypting secrets
#
# LOGGING:
#   - All 5 log types are enabled for maximum visibility
#   - Logs are sent to the CloudWatch log group we created above
# =============================================================================
resource "aws_eks_cluster" "main" {
  name     = var.cluster_name       # The cluster name visible in AWS Console
  version  = var.kubernetes_version # e.g., "1.31"
  role_arn = var.cluster_role_arn   # IAM role the EKS service assumes

  # ---------------------------------------------------------------------------
  # VPC CONFIGURATION
  # ---------------------------------------------------------------------------
  # Defines the network configuration for the EKS cluster:
  #   - subnet_ids: Where the cluster's ENIs are placed (for API server access)
  #   - endpoint settings: How the API server is accessible
  #   - security_group_ids: Additional SGs for the cluster ENIs
  # ---------------------------------------------------------------------------
  vpc_config {
    subnet_ids              = var.subnet_ids                  # Private subnets for cluster ENIs
    endpoint_public_access  = var.endpoint_public_access      # e.g., true
    endpoint_private_access = var.endpoint_private_access     # e.g., true
    public_access_cidrs     = var.public_access_cidrs         # e.g., ["0.0.0.0/0"]
    security_group_ids      = [aws_security_group.cluster.id] # Our custom cluster SG
  }

  # ---------------------------------------------------------------------------
  # ENCRYPTION CONFIGURATION
  # ---------------------------------------------------------------------------
  # Enables envelope encryption for Kubernetes secrets stored in etcd.
  # Without this, secrets are stored base64-encoded (NOT encrypted).
  # ---------------------------------------------------------------------------
  encryption_config {
    provider {
      key_arn = aws_kms_key.eks.arn # Our dedicated KMS key
    }
    resources = ["secrets"] # Currently only "secrets" is supported by EKS
  }

  # ---------------------------------------------------------------------------
  # CONTROL PLANE LOGGING (OPTIONAL)
  # ---------------------------------------------------------------------------
  # When enable_cluster_logging = true, all 5 log types are enabled:
  #
  # "api"               — API server request logs (GET, POST, DELETE, etc.)
  # "audit"             — Kubernetes audit logs (required for security compliance)
  # "authenticator"     — Authentication logs (IAM-to-Kubernetes mappings)
  # "controllerManager" — Controller manager logs (Deployment scaling, etc.)
  # "scheduler"         — Scheduler logs (pod placement decisions)
  #
  # When disabled (default), no logs are sent to CloudWatch.
  # KUBE-NATIVE ALTERNATIVE: Falco + ELK/Loki
  # ---------------------------------------------------------------------------
  enabled_cluster_log_types = var.enable_cluster_logging ? ["api", "audit", "authenticator", "controllerManager", "scheduler"] : []

  # If logging is enabled, the CloudWatch log group must exist first.
  # Otherwise EKS creates a default one with no retention (logs kept forever = expensive).
  # When logging is disabled, the log group won't be created (count = 0),
  # but depends_on still works correctly — it becomes a no-op dependency.
  depends_on = [
    aws_cloudwatch_log_group.eks
  ]

  tags = var.tags
}


# =============================================================================
# OIDC PROVIDER FOR IRSA (IAM Roles for Service Accounts)
# =============================================================================
# IRSA is a critical security feature that allows Kubernetes pods to
# assume specific IAM roles. Instead of giving ALL pods on a node the
# same IAM permissions (via the node role), each pod can have its own
# fine-grained IAM role.
#
# HOW IRSA WORKS:
# 1. EKS creates an OIDC (OpenID Connect) issuer for the cluster
# 2. We register this OIDC issuer as an Identity Provider in IAM
# 3. We create IAM roles with trust policies that reference the OIDC provider
# 4. Kubernetes ServiceAccounts are annotated with the IAM role ARN
# 5. When a pod uses the ServiceAccount, AWS STS verifies the OIDC token
#    and grants the specific IAM role to that pod
#
# EXAMPLE:
#   Pod "s3-uploader" → ServiceAccount "s3-sa" → IAM Role "s3-write-role"
#   This pod can write to S3, but other pods cannot.
#
# WHY IRSA IS IMPORTANT:
# Without IRSA, you'd have to attach S3 permissions to the NODE ROLE,
# giving ALL pods on ALL nodes S3 write access — a security risk.
# =============================================================================

# Fetch the TLS certificate from the OIDC issuer URL.
# The thumbprint is used to verify that the OIDC provider is authentic
# (prevents man-in-the-middle attacks on token validation).
data "tls_certificate" "cluster" {
  count = var.enable_irsa ? 1 : 0                         # Only if IRSA is enabled
  url   = aws_eks_cluster.main.identity[0].oidc[0].issuer # EKS OIDC URL
}

# Register the EKS OIDC issuer as an IAM Identity Provider.
# This tells IAM: "Trust tokens issued by this EKS cluster."
resource "aws_iam_openid_connect_provider" "cluster" {
  count           = var.enable_irsa ? 1 : 0
  client_id_list  = ["sts.amazonaws.com"] # Standard audience for EKS IRSA
  thumbprint_list = [data.tls_certificate.cluster[0].certificates[0].sha1_fingerprint]
  url             = aws_eks_cluster.main.identity[0].oidc[0].issuer

  tags = merge(
    var.tags,
    {
      Name = "${var.cluster_name}-oidc-provider"
    }
  )
}


# =============================================================================
# EKS ADDONS
# =============================================================================
# EKS addons are essential Kubernetes components managed by AWS.
# Using addons (instead of self-managed) means AWS handles:
#   - Version compatibility with the cluster version
#   - Security patches and updates
#   - Configuration best practices
#
# THE THREE ESSENTIAL ADDONS:
# 1. CoreDNS    — DNS server for Kubernetes service discovery
# 2. kube-proxy — Network proxy implementing Kubernetes Services
# 3. VPC CNI    — Pod networking (assigns VPC IPs to pods)
# =============================================================================

# ---------------------------------------------------------------------------
# ADDON: CoreDNS
# ---------------------------------------------------------------------------
# CoreDNS is the cluster DNS server. When a pod tries to reach a service
# by name (e.g., "mysql-service"), CoreDNS resolves it to the service's
# ClusterIP address.
#
# WITHOUT CoreDNS: Pods would need to use IP addresses instead of names
# (e.g., "10.96.0.15" instead of "mysql-service.default.svc.cluster.local")
#
# depends_on = node_group: CoreDNS needs at least one node to run on.
# If we try to install it before nodes exist, it stays in "Degraded" state.
#
# resolve_conflicts = "OVERWRITE":
# If a previous version of the addon exists with manual modifications,
# this setting overwrites those modifications with the managed version.
# ---------------------------------------------------------------------------
resource "aws_eks_addon" "coredns" {
  cluster_name                = aws_eks_cluster.main.name
  addon_name                  = "coredns"
  addon_version               = var.coredns_version != "" ? var.coredns_version : null # null = latest compatible
  resolve_conflicts_on_create = "OVERWRITE"                                            # Overwrite existing if any
  resolve_conflicts_on_update = "OVERWRITE"                                            # Overwrite during updates

  depends_on = [aws_eks_node_group.main] # Needs nodes to schedule CoreDNS pods

  tags = var.tags
}

# ---------------------------------------------------------------------------
# ADDON: kube-proxy
# ---------------------------------------------------------------------------
# kube-proxy runs as a DaemonSet on every node. It maintains network rules
# (iptables/IPVS) that implement Kubernetes Services.
#
# HOW IT WORKS:
# When a pod sends traffic to a Service (e.g., mysql-service:3306),
# kube-proxy intercepts it and forwards to one of the backend pods.
#
# kube-proxy modes:
#   - iptables (default): Uses kernel iptables rules for routing
#   - IPVS: Uses IP Virtual Server for better performance at scale
#
# This addon does NOT need nodes to start (it's a DaemonSet that waits
# for nodes to appear), so no depends_on is needed.
# ---------------------------------------------------------------------------
resource "aws_eks_addon" "kube_proxy" {
  cluster_name                = aws_eks_cluster.main.name
  addon_name                  = "kube-proxy"
  addon_version               = var.kube_proxy_version != "" ? var.kube_proxy_version : null
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "OVERWRITE"

  tags = var.tags
}

# ---------------------------------------------------------------------------
# ADDON: VPC CNI (Container Network Interface)
# ---------------------------------------------------------------------------
# The VPC CNI plugin is what gives each pod its own VPC IP address.
# This is unique to EKS — other Kubernetes distributions use overlay
# networks that add a layer of encapsulation.
#
# HOW VPC CNI WORKS:
# 1. CNI allocates secondary IPs from the node's ENI
# 2. When more IPs are needed, it creates additional ENIs
# 3. Each pod gets a "real" VPC IP (not a virtual/overlay IP)
# 4. This means pods can communicate directly with VPC resources
#    (RDS, ElastiCache, etc.) without any NAT or encapsulation
#
# BENEFITS:
# ✅ Native VPC networking performance (no overlay overhead)
# ✅ Pods are directly addressable within the VPC
# ✅ Security groups can be applied at the pod level
# ✅ Compatible with VPC Flow Logs for pod traffic visibility
# ---------------------------------------------------------------------------
resource "aws_eks_addon" "vpc_cni" {
  cluster_name                = aws_eks_cluster.main.name
  addon_name                  = "vpc-cni"
  addon_version               = var.vpc_cni_version != "" ? var.vpc_cni_version : null
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "OVERWRITE"

  tags = var.tags
}


# =============================================================================
# LAUNCH TEMPLATE FOR NODE GROUPS
# =============================================================================
# A launch template defines the EC2 instance configuration for worker nodes.
# While EKS managed node groups can use default settings, a custom launch
# template gives us control over security-sensitive settings:
#
#   ✅ EBS encryption (encrypted at rest)
#   ✅ gp3 volumes (better IOPS/throughput than gp2)
#   ✅ IMDSv2 enforcement (prevents SSRF credential theft)
#   ✅ Detailed monitoring (1-minute CloudWatch metrics)
#   ✅ No public IP assignment
#
# for_each = var.node_groups:
#   Creates one launch template per node group.
#   "general" node group → launch template for general nodes
#   "spot" node group → launch template for spot nodes
# =============================================================================
resource "aws_launch_template" "node" {
  for_each = var.node_groups # One template per node group

  name_prefix = "${var.cluster_name}-${each.key}-" # e.g., "eks-...-general-abc123"
  description = "Launch template for ${var.cluster_name} ${each.key} node group"

  # ---------------------------------------------------------------------------
  # BLOCK DEVICE MAPPING (EBS Volume)
  # ---------------------------------------------------------------------------
  # Configures the root EBS volume attached to each node instance.
  #
  # /dev/xvda: The root device name for Amazon Linux 2 (EKS-optimized AMI)
  # gp3: General Purpose SSD v3 — better performance/cost than gp2
  #   - gp2: Burstable, 3000 IOPS baseline for volumes > 1000 GiB
  #   - gp3: Fixed 3000 IOPS and 125 MiB/s throughput regardless of size
  # encrypted: EBS volumes are encrypted at rest using the default AWS KMS key
  # delete_on_termination: Volume is deleted when the instance is terminated
  #   (prevents storage cost leak from orphaned volumes)
  # ---------------------------------------------------------------------------
  block_device_mappings {
    device_name = "/dev/xvda" # Root volume device name

    ebs {
      volume_size           = lookup(each.value, "disk_size", 20) # Default 20 GiB
      volume_type           = "gp3"                               # GP3: 3000 IOPS, 125 MiB/s baseline
      iops                  = 3000                                # 3000 IOPS (gp3 baseline)
      throughput            = 125                                 # 125 MiB/s throughput (gp3 baseline)
      delete_on_termination = true                                # Clean up when instance terminates
      encrypted             = true                                # SECURITY: Encrypt volume at rest
    }
  }

  # ---------------------------------------------------------------------------
  # METADATA OPTIONS (IMDSv2 — CRITICAL SECURITY)
  # ---------------------------------------------------------------------------
  # The Instance Metadata Service (IMDS) provides instance information
  # including IAM credentials. IMDSv2 adds a security layer by requiring
  # a TOKEN for all metadata requests.
  #
  # WHY THIS IS CRITICAL:
  # In 2019, a Capital One breach exploited IMDSv1 through a Server-Side
  # Request Forgery (SSRF) vulnerability. The attacker made the server
  # request its own metadata endpoint, stealing IAM credentials.
  #
  # IMDSv2 prevents this by requiring a PUT request to get a token first.
  # SSRF attacks typically can only make GET requests, blocking the attack.
  #
  # http_tokens = "required":  FORCE IMDSv2 (block IMDSv1 requests)
  # http_put_response_hop_limit = 2: Allow pods to access IMDS through
  #   2 network hops (required for container networking)
  # instance_metadata_tags = "enabled": Allow tags to be accessed via IMDS
  # ---------------------------------------------------------------------------
  metadata_options {
    http_endpoint               = "enabled"  # Enable IMDS
    http_tokens                 = "required" # SECURITY: Enforce IMDSv2 ONLY
    http_put_response_hop_limit = 2          # 2 hops for container networking
    instance_metadata_tags      = "enabled"  # Allow tag access via metadata
  }

  # ---------------------------------------------------------------------------
  # MONITORING (OPTIONAL)
  # ---------------------------------------------------------------------------
  # When true: Enables detailed monitoring (1-minute intervals).
  #   - Costs ~$2.10/instance/month
  #   - Faster autoscaling reactions
  #   - More granular CloudWatch metrics
  # When false (default): Uses free basic monitoring (5-minute intervals).
  #   - KUBE-NATIVE ALTERNATIVE: Prometheus + node_exporter + Grafana
  # ---------------------------------------------------------------------------
  monitoring {
    enabled = var.enable_detailed_monitoring # false by default
  }

  # ---------------------------------------------------------------------------
  # NETWORK INTERFACES
  # ---------------------------------------------------------------------------
  # associate_public_ip_address = false:
  #   SECURITY: Nodes do NOT get public IPs. They're in private subnets
  #   and reach the internet only through the NAT Gateway.
  #
  # security_groups: Attach our custom node security group
  # ---------------------------------------------------------------------------
  network_interfaces {
    associate_public_ip_address = false                        # SECURITY: No public IPs on nodes
    delete_on_termination       = true                         # Clean up ENIs on termination
    security_groups             = [aws_security_group.node.id] # Our node SG
  }

  # ---------------------------------------------------------------------------
  # TAG SPECIFICATIONS
  # ---------------------------------------------------------------------------
  # Tags applied to launched EC2 instances (not just the template itself).
  # This ensures every node instance has proper tags for identification.
  # ---------------------------------------------------------------------------
  tag_specifications {
    resource_type = "instance"
    tags = merge(
      var.tags,
      {
        Name = "${var.cluster_name}-${each.key}-node" # e.g., "eks-...-general-node"
      }
    )
  }

  lifecycle {
    create_before_destroy = true # Create new template before destroying old one
  }

  tags = var.tags
}


# =============================================================================
# EKS MANAGED NODE GROUPS
# =============================================================================
# Managed node groups are the actual EC2 instances that run your pods.
# AWS manages the lifecycle (launching, terminating, updating) of these
# instances based on the configuration we provide.
#
# for_each = var.node_groups:
#   Creates one node group per entry in the map. Our config creates:
#   - "general": 2-4 ON_DEMAND t3.medium instances
#   - "spot": 1-3 SPOT t3.medium/t3a.medium instances
#
# SCALING BEHAVIOR:
#   - min_size: Absolute minimum number of nodes (even during scale-down)
#   - max_size: Maximum number of nodes (ceiling for autoscaler)
#   - desired_size: Starting/current number of nodes
#
# lifecycle { ignore_changes = [desired_size] }:
#   The Cluster Autoscaler modifies desired_size at runtime. If we don't
#   ignore this, `terraform apply` would reset the count back to the
#   original value, undoing the autoscaler's work.
#
# TAINTS:
#   Taints are node properties that REPEL pods. A tainted node only accepts
#   pods that have a matching TOLERATION. This is used to reserve spot nodes
#   for specific workloads that can handle interruptions.
#
# DYNAMIC BLOCK:
#   The `dynamic` block generates multiple `taint` blocks from a list.
#   It's like a for-loop for resource blocks. Each item in the taints list
#   becomes one taint configuration on the node group.
# =============================================================================
resource "aws_eks_node_group" "main" {
  for_each = var.node_groups # One node group per entry

  cluster_name    = aws_eks_cluster.main.name # Which cluster to join
  node_group_name = each.key                  # "general" or "spot"
  node_role_arn   = var.node_role_arn         # IAM role for nodes
  subnet_ids      = var.subnet_ids            # Private subnets
  version         = var.kubernetes_version    # K8s version for nodes

  # ---------------------------------------------------------------------------
  # SCALING CONFIGURATION
  # ---------------------------------------------------------------------------
  scaling_config {
    desired_size = each.value.desired_size # Starting count
    max_size     = each.value.max_size     # Autoscaler ceiling
    min_size     = each.value.min_size     # Autoscaler floor
  }

  instance_types = each.value.instance_types # e.g., ["t3.medium"]
  # lookup() with a default: if capacity_type is not specified, use ON_DEMAND
  capacity_type = lookup(each.value, "capacity_type", "ON_DEMAND")

  # Kubernetes labels applied to all nodes in this group
  labels = lookup(each.value, "labels", {})

  # Dynamic taint blocks — generates 0 or more taint configurations
  # coalesce() returns the first non-null argument; if taints is null, use []
  dynamic "taint" {
    for_each = coalesce(lookup(each.value, "taints", null), [])
    content {
      key    = taint.value.key    # e.g., "spot"
      value  = taint.value.value  # e.g., "true"
      effect = taint.value.effect # e.g., "NO_SCHEDULE"
    }
  }

  # Use our custom launch template (with IMDSv2, encrypted EBS, etc.)
  launch_template {
    id      = aws_launch_template.node[each.key].id             # Template ID
    version = aws_launch_template.node[each.key].latest_version # Always use latest version
  }

  # Merge common tags with node-group-specific tags
  tags = merge(
    var.tags,
    lookup(each.value, "tags", {})
  )

  # Node groups depend on VPC CNI and kube-proxy addons being ready.
  # These addons configure networking that nodes need to join the cluster.
  depends_on = [
    aws_eks_addon.vpc_cni,
    aws_eks_addon.kube_proxy
  ]

  # Ignore desired_size changes from the Cluster Autoscaler.
  # Without this, `terraform apply` would fight with the autoscaler,
  # resetting the node count on every apply.
  lifecycle {
    ignore_changes = [scaling_config[0].desired_size]
  }
}
