# EKS Module ⚓

This is the core module of the deployment. It is responsible for provisioning the Elastic Kubernetes Service (EKS) cluster, node groups, and all required supporting infrastructure, such as security groups, logging, and addons.

## What it Creates 🏗️
1. **KMS Key (`aws_kms_key`)**: A dedicated KMS key to encrypt Kubernetes secrets natively at rest in `etcd` (Envelope Encryption).
2. **CloudWatch Log Group**: For storing the cluster's control plane audit logs (API requests, authenticator logs, scheduler, etc.).
3. **Security Groups**: 
   - **Cluster SG**: Secures the EKS control plane ENIs.
   - **Node SG**: Secures the worker nodes.
   - **SG Rules**: Granular rules permitting necessary cross-communication between the control plane and nodes.
4. **EKS Cluster (`aws_eks_cluster`)**: The fully-managed Kubernetes control plane.
5. **OIDC Provider (`aws_iam_openid_connect_provider`)**: Enables IAM Roles for Service Accounts (IRSA), allowing individual pods to assume specific IAM roles.
6. **EKS Addons (`aws_eks_addon`)**: 
   - `coredns`: Internal Kubernetes DNS service.
   - `kube-proxy`: Implements Kubernetes Services networking.
   - `vpc-cni`: Allocates native AWS VPC IPs directly to Pods.
7. **Launch Templates (`aws_launch_template`)**: Configures worker nodes with best-practice defaults (IMDSv2, `gp3` encrypted EBS volumes, detailed monitoring).
8. **EKS Managed Node Groups (`aws_eks_node_group`)**: Auto-scaling groups of EC2 worker nodes running your workloads (supporting both ON_DEMAND and SPOT instances).

## Usage Highlights 💡
- **Security First**: Utilizes IMDSv2 (prevents SSRF attacks), envelope encryption for `etcd` secrets, and strictly defined security groups.
- **IRSA Ready**: Includes OIDC configuration, allowing pods to have fine-grained IAM permissions instead of sharing a broad node policy.
- **Performance**: Pre-configured with GP3 encrypted EBS volumes for cost-efficient, high-performance storage on worker nodes.
