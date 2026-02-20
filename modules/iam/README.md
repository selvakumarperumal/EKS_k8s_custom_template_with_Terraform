# IAM Module 🔐

This module provisions the necessary Identity and Access Management (IAM) roles required for the EKS cluster. AWS IAM controls *who* can do *what*, providing the bedrock of AWS security through the principle of least privilege.

## What it Creates 🏗️
1. **EKS Cluster Role (`aws_iam_role.cluster`)**: 
   - Assumed by the EKS control plane service itself (`eks.amazonaws.com`).
   - Allows EKS to manage the Kubernetes API server, handle cluster networking, and publish metrics and logs.
   - Attachments: `AmazonEKSClusterPolicy` and `AmazonEKSVPCResourceController` policies.

2. **Node Group Role (`aws_iam_role.node_group`)**:
   - Assumed by the EC2 worker node instances (`ec2.amazonaws.com`).
   - Allows worker nodes to register themselves with the EKS cluster, pull container images from Elastic Container Registry (ECR), and configure pod networking via VPC CNI.
   - Attachments: `AmazonEKSWorkerNodePolicy`, `AmazonEKS_CNI_Policy`, and `AmazonEC2ContainerRegistryReadOnly`.

## Usage Highlights 💡
- **Least Privilege**: Only required AWS-managed policies are attached, avoiding wildcard permissions.
- **Node Permissions**: The Node Group Role only has read access to ECR (`AmazonEC2ContainerRegistryReadOnly`), ensuring your worker nodes can pull images but not mistakenly overwrite or push them.
