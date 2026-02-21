# IAM Module 🔐

This module provisions the Identity and Access Management (IAM) roles required for the EKS cluster. AWS IAM controls *who* can do *what*, providing the bedrock of AWS security through the principle of least privilege.

---

## Architecture Diagram

```mermaid
graph TD
    classDef roleStyle fill:#DD344C,stroke:#fff,stroke-width:2px,color:#fff
    classDef policyStyle fill:#E78F24,stroke:#fff,stroke-width:2px,color:#fff
    classDef serviceStyle fill:#326CE5,stroke:#fff,stroke-width:2px,color:#fff

    subgraph Trust_Relationships ["Who Can Assume These Roles?"]
        EKS["EKS Service - eks.amazonaws.com"]
        EC2["EC2 Service - ec2.amazonaws.com"]
    end

    subgraph IAM_Roles ["IAM Roles Created"]
        ClusterRole["Cluster Role"]
        NodeRole["Node Group Role"]
    end

    subgraph Cluster_Policies ["Cluster Role Policies"]
        P1["AmazonEKSClusterPolicy"]
        P2["AmazonEKSVPCResourceController"]
    end

    subgraph Node_Policies ["Node Group Role Policies"]
        P3["AmazonEKSWorkerNodePolicy"]
        P4["AmazonEKS_CNI_Policy"]
        P5["AmazonEC2ContainerRegistryReadOnly"]
    end

    EKS -- "sts:AssumeRole" --> ClusterRole
    EC2 -- "sts:AssumeRole" --> NodeRole

    P1 -.-> ClusterRole
    P2 -.-> ClusterRole
    P3 -.-> NodeRole
    P4 -.-> NodeRole
    P5 -.-> NodeRole

    class ClusterRole,NodeRole roleStyle
    class P1,P2,P3,P4,P5 policyStyle
    class EKS,EC2 serviceStyle
```

---

## What it Creates 🏗️

| # | Resource | Terraform Type | Purpose |
|---|----------|---------------|---------|
| 1 | **Cluster Role** | `aws_iam_role` | Assumed by the EKS control plane service |
| 2 | **Node Group Role** | `aws_iam_role` | Assumed by EC2 worker node instances |
| 3 | **Cluster Policy Attachments** (×2) | `aws_iam_role_policy_attachment` | Grants cluster management permissions |
| 4 | **Node Policy Attachments** (×3) | `aws_iam_role_policy_attachment` | Grants node registration, CNI, and ECR access |

---

## Detailed Resource Walkthrough

### 1. EKS Cluster Role

The role that the AWS EKS service assumes to manage the control plane.

```hcl
resource "aws_iam_role" "cluster" {
  name_prefix = "${var.cluster_name}-cluster-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "eks.amazonaws.com"   # Only EKS service can assume this role
      }
    }]
  })

  tags = var.tags
}

# Attach AWS-managed policies
resource "aws_iam_role_policy_attachment" "cluster_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.cluster.name
}

resource "aws_iam_role_policy_attachment" "vpc_resource_controller" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
  role       = aws_iam_role.cluster.name
}
```

| Policy | What It Allows |
|--------|---------------|
| `AmazonEKSClusterPolicy` | Manage K8s API server, create load balancers, publish CloudWatch metrics |
| `AmazonEKSVPCResourceController` | Manage ENIs (Elastic Network Interfaces) for pod networking |

---

### 2. Node Group Role

The role that every EC2 worker node assumes when it joins the cluster.

```hcl
resource "aws_iam_role" "node_group" {
  name_prefix = "${var.cluster_name}-node-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"   # Only EC2 instances can assume this role
      }
    }]
  })

  tags = var.tags
}

# Attach AWS-managed policies
resource "aws_iam_role_policy_attachment" "worker_node_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.node_group.name
}

resource "aws_iam_role_policy_attachment" "cni_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.node_group.name
}

resource "aws_iam_role_policy_attachment" "ecr_read_only" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.node_group.name
}
```

| Policy | What It Allows |
|--------|---------------|
| `AmazonEKSWorkerNodePolicy` | Register the node with the EKS cluster, describe cluster resources |
| `AmazonEKS_CNI_Policy` | Manage VPC ENIs to assign pod IPs (VPC CNI plugin) |
| `AmazonEC2ContainerRegistryReadOnly` | **Read-only** access to pull images from ECR (cannot push or delete) |

---

## How IRSA Extends This (Configured in EKS Module)

```mermaid
graph LR
    classDef iamStyle fill:#DD344C,stroke:#fff,stroke-width:2px,color:#fff
    classDef k8sStyle fill:#326CE5,stroke:#fff,stroke-width:2px,color:#fff

    subgraph Without_IRSA ["Without IRSA"]
        AllPods["All Pods"] --> NodeRole2["Node Role - broad permissions"]
    end

    subgraph With_IRSA ["With IRSA - Recommended"]
        PodA["Pod A"] --> RoleA["S3 Read-Only Role"]
        PodB["Pod B"] --> RoleB["DynamoDB Write Role"]
        PodC["Pod C"] --> RoleC["No extra permissions"]
    end

    class NodeRole2,RoleA,RoleB iamStyle
    class AllPods,PodA,PodB,PodC k8sStyle
```

**Without IRSA**: Every pod inherits the broad Node Group Role. **With IRSA** (enabled in the EKS module): Each pod gets only the exact AWS permissions it needs via its Kubernetes ServiceAccount.

---

## Security Principles

- **Least Privilege**: Only AWS-managed policies are attached. No wildcard (`*`) permissions.
- **Read-Only ECR**: Nodes can pull images but cannot push, delete, or modify container images.
- **No Inline Policies**: All permissions come from well-audited AWS-managed policies.
