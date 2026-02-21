# IAM Module 🔐

This module provisions the Identity and Access Management (IAM) roles required for the EKS cluster. AWS IAM controls *who* can do *what*, providing the bedrock of AWS security through the principle of least privilege.

---

## Architecture Diagram

```mermaid
graph TD
    classDef role fill:#DD344C,stroke:#fff,stroke-width:2px,color:#fff
    classDef policy fill:#E78F24,stroke:#fff,stroke-width:2px,color:#fff
    classDef service fill:#326CE5,stroke:#fff,stroke-width:2px,color:#fff

    subgraph Trust_Relationships ["Who Can Assume These Roles?"]
        EKS["EKS Service<br/>(eks.amazonaws.com)"]
        EC2["EC2 Service<br/>(ec2.amazonaws.com)"]
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

    class ClusterRole,NodeRole role
    class P1,P2,P3,P4,P5 policy
    class EKS,EC2 service
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

## Role Details

### 1. EKS Cluster Role

**Who assumes it?** The AWS EKS service itself (`eks.amazonaws.com`).

**What it can do:**
| Policy | Permission Granted |
|--------|--------------------|
| `AmazonEKSClusterPolicy` | Manage Kubernetes API server, create load balancers, publish CloudWatch metrics |
| `AmazonEKSVPCResourceController` | Manage ENIs (Elastic Network Interfaces) in the VPC for pod networking |

**Trust Policy (simplified):**
```json
{
  "Effect": "Allow",
  "Principal": { "Service": "eks.amazonaws.com" },
  "Action": "sts:AssumeRole"
}
```

### 2. Node Group Role

**Who assumes it?** Every EC2 instance that joins the cluster as a worker node (`ec2.amazonaws.com`).

**What it can do:**
| Policy | Permission Granted |
|--------|--------------------|
| `AmazonEKSWorkerNodePolicy` | Register the node with the EKS cluster, describe cluster resources |
| `AmazonEKS_CNI_Policy` | Manage VPC ENIs to assign pod IPs (VPC CNI plugin) |
| `AmazonEC2ContainerRegistryReadOnly` | **Read-only** access to pull images from ECR (cannot push or delete) |

---

## How IRSA Extends This

```mermaid
graph LR
    classDef iam fill:#DD344C,stroke:#fff,stroke-width:2px,color:#fff
    classDef k8s fill:#326CE5,stroke:#fff,stroke-width:2px,color:#fff

    subgraph Without_IRSA ["Without IRSA"]
        AllPods["All Pods"] --> NodeRole2["Node Role<br/>(broad permissions)"]
    end

    subgraph With_IRSA ["With IRSA (Recommended)"]
        PodA["Pod A"] --> RoleA["S3 Read-Only Role"]
        PodB["Pod B"] --> RoleB["DynamoDB Write Role"]
        PodC["Pod C"] --> NodeRole3["No extra permissions"]
    end

    class NodeRole2,RoleA,RoleB iam
    class AllPods,PodA,PodB,PodC k8s
```

Without IRSA, **every pod** inherits the broad Node Group Role permissions. With IRSA (enabled in the EKS module), each pod gets its own fine-grained IAM role via its Kubernetes ServiceAccount. This is the recommended AWS security pattern.

---

## Security Principles

- **Least Privilege**: Only AWS-managed policies are attached. No wildcard (`*`) permissions.
- **Read-Only ECR**: Nodes can pull images but cannot push, delete, or modify container images.
- **No Inline Policies**: All permissions come from well-audited AWS-managed policies, ensuring they stay up to date with AWS best practices.
