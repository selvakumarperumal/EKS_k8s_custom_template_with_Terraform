# 📖 Line-by-Line Code Explanation Guide

This guide provides a high-level walkthrough of every Terraform file and explains key patterns used throughout the codebase. For detailed line-by-line comments, refer to the inline comments in each `.tf` file — every resource has comprehensive documentation.

---

## Root Module Files

### `provider.tf` — Foundation Configuration

**Purpose**: Configures Terraform version, provider versions, and optional state backend.

| Block | What It Does |
|-------|-------------|
| `terraform { required_version }` | Ensures Terraform >= 1.14 is used |
| `required_providers.aws` | Pins AWS provider to ~> 6.0 |
| `required_providers.tls` | Pins TLS provider to ~> 4.0 (for OIDC) |
| `backend "s3"` (commented) | S3 + DynamoDB state management for teams |
| `provider "aws"` | Sets region and default resource tags |

**Key Pattern — Default Tags:**
```hcl
default_tags {
  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}
```
These tags are automatically applied to **every** AWS resource, saving repetitive tag blocks.

---

### `variables.tf` — Input Variables with Validation

**Purpose**: Defines all configurable parameters with type constraints and validation.

**Key Pattern — Validation Blocks:**
```hcl
variable "aws_region" {
  validation {
    condition     = can(regex("^[a-z]{2}-[a-z]+-[0-9]$", var.aws_region))
    error_message = "Region must be a valid AWS region format"
  }
}
```
- `can()` returns true/false without errors
- `regex()` matches patterns
- Together they enforce valid input at `terraform plan` time, before any resources are created

---

### `main.tf` — Module Orchestration

**Purpose**: Calls all 5 modules in dependency order and wires them together.

**Key Pattern — Module Composition:**
```hcl
module "eks" {
  source     = "./modules/eks"
  vpc_id     = module.vpc.vpc_id          # Output from VPC module
  subnet_ids = module.vpc.private_subnets  # Output from VPC module
  cluster_role_arn = module.iam.cluster_role_arn  # Output from IAM module
}
```
Terraform automatically builds a dependency graph from these references.

---

### `outputs.tf` — Exposed Values

**Purpose**: Makes key values available after `terraform apply`.

**Key Pattern — Sensitive Outputs:**
```hcl
output "cluster_certificate_authority_data" {
  value     = module.eks.cluster_certificate_authority_data
  sensitive = true  # Hidden from console output
}
```

---

## Module: VPC (`modules/vpc/`)

### Key Resources

| Resource | Count | Purpose |
|----------|-------|---------|
| `aws_vpc` | 1 | The virtual private cloud |
| `aws_subnet.public` | 3 | One per AZ for load balancers |
| `aws_subnet.private` | 3 | One per AZ for worker nodes |
| `aws_internet_gateway` | 1 | Internet access for public subnets |
| `aws_nat_gateway` | 1 or 3 | Outbound internet for private subnets |
| `aws_network_acl` | 2 | Stateless firewalls (public + private) |
| `aws_flow_log` | 1 | Network traffic recording |

### Key Pattern — Conditional NAT:
```hcl
count = var.single_nat_gateway ? 1 : length(var.public_subnets)
```
- Development: 1 NAT Gateway (saves ~$64/month)
- Production: 3 NAT Gateways (one per AZ for HA)

---

## Module: IAM (`modules/iam/`)

### Key Pattern — Trust Policy:
```hcl
assume_role_policy = jsonencode({
  Statement = [{
    Action    = "sts:AssumeRole"
    Principal = { Service = "eks.amazonaws.com" }
  }]
})
```
- **Trust policy** = WHO can assume the role
- **Permission policies** (attached separately) = WHAT the role can do

---

## Module: EKS (`modules/eks/`)

### Key Resources

| Resource | Purpose |
|----------|---------|
| `aws_kms_key` | Encrypts K8s secrets in etcd |
| `aws_cloudwatch_log_group` | Stores control plane logs |
| `aws_security_group` (x2) | Cluster + node SGs |
| `aws_eks_cluster` | The Kubernetes control plane |
| `aws_iam_openid_connect_provider` | OIDC for IRSA |
| `aws_eks_addon` (x3) | CoreDNS, kube-proxy, VPC CNI |
| `aws_launch_template` | Node EC2 configuration |
| `aws_eks_node_group` | Managed worker nodes |

### Key Pattern — for_each with Maps:
```hcl
resource "aws_eks_node_group" "main" {
  for_each = var.node_groups  # { "general" = {...}, "spot" = {...} }
  node_group_name = each.key  # "general" or "spot"
  instance_types  = each.value.instance_types
}
```

### Key Pattern — Dynamic Blocks:
```hcl
dynamic "taint" {
  for_each = coalesce(lookup(each.value, "taints", null), [])
  content {
    key    = taint.value.key
    effect = taint.value.effect
  }
}
```
Generates 0 or more `taint` blocks from a list variable.

### Key Pattern — Lifecycle Ignore:
```hcl
lifecycle {
  ignore_changes = [scaling_config[0].desired_size]
}
```
Prevents Terraform from fighting with the Cluster Autoscaler.

---

## Module: Secrets Manager (`modules/secrets-manager/`)

### Key Pattern — Conditional Creation:
```hcl
resource "aws_secretsmanager_secret" "db_credentials" {
  count = var.create_db_secret ? 1 : 0  # Create only if flag is true
}
```
Using `count` with a boolean creates (1) or skips (0) the resource.

### Key Pattern — Least-Privilege IAM Policy:
```hcl
Action = [
  "secretsmanager:GetSecretValue",   # ✅ Read only
  "secretsmanager:DescribeSecret"     # ✅ Metadata only
  # ❌ No PutSecretValue, DeleteSecret, CreateSecret
]
Resource = [specific_secret_arns]       # ❌ Not "*"
```

---

## Module: Security (`modules/security/`)

### Key Resources (NEW — Not in Reference)

| Resource | Purpose |
|----------|---------|
| `aws_guardduty_detector` | Threat detection with EKS monitoring |
| `aws_config_configuration_recorder` | Tracks resource configurations |
| `aws_config_config_rule` (x3) | Compliance checks for EKS |

### GuardDuty Detection Coverage:
- CloudTrail management events
- VPC Flow Logs analysis
- DNS query analysis
- EKS audit log monitoring
- Malware scanning on EBS volumes

---

## Common Terraform Patterns Used

| Pattern | Where Used | Purpose |
|---------|-----------|---------|
| `count` | Secrets Manager, Security | Conditional resource creation |
| `for_each` | EKS node groups, launch templates | Multiple similar resources |
| `dynamic` blocks | Node group taints | Variable-length sub-blocks |
| `merge()` | All modules (tags) | Combine tag maps |
| `lookup()` | EKS node groups | Safe map access with defaults |
| `coalesce()` | EKS taints | First non-null value |
| `jsonencode()` | IAM policies, Secrets | Terraform objects → JSON |
| `try()` | EKS outputs | Graceful error handling |
| `lifecycle` | Security groups, node groups | Control resource behavior |
| `depends_on` | EKS cluster, addons | Explicit dependencies |
