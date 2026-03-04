# 🚀 Complete Deployment & Operations Guide

> Step-by-step guide to deploy, access, and manage your EKS cluster using this Terraform template.

---

## 📋 Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [AWS Credentials Setup](#2-aws-credentials-setup)
3. [Bootstrap Remote State (First Time Only)](#3-bootstrap-remote-state-first-time-only)
4. [Deploy the EKS Cluster](#4-deploy-the-eks-cluster)
5. [Access the Cluster from Your Local Machine](#5-access-the-cluster-from-your-local-machine)
6. [Post-Deployment Verification](#6-post-deployment-verification)
7. [Day 2 Operations](#7-day-2-operations)
8. [Cleanup / Destroy](#8-cleanup--destroy)
9. [Troubleshooting](#9-troubleshooting)
10. [Cost Summary](#10-cost-summary)

---

## 1. Prerequisites

Install these tools before proceeding:

| Tool | Required Version | Install Command | Purpose |
|------|-----------------|-----------------|---------|
| **Terraform** | >= 1.14 | [terraform.io/downloads](https://developer.hashicorp.com/terraform/install) | Infrastructure provisioning |
| **AWS CLI** | v2 | [aws.amazon.com/cli](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) | AWS authentication & cluster access |
| **kubectl** | >= 1.28 | [kubernetes.io/docs](https://kubernetes.io/docs/tasks/tools/) | Kubernetes cluster management |
| **Git** | any | `sudo apt install git` | Clone the repository |

### Verify installations

```bash
terraform version   # Should show >= 1.14.x
aws --version       # Should show aws-cli/2.x.x
kubectl version --client  # Should show >= v1.28.x
```

### AWS IAM Permissions

The deploying IAM user/role needs either:
- **Option A (Quick):** `AdministratorAccess` managed policy
- **Option B (Least Privilege):** These managed policies:
  - `AmazonEKSClusterPolicy`
  - `AmazonEKSServicePolicy`
  - `AmazonVPCFullAccess`
  - `IAMFullAccess`
  - `AWSKeyManagementServicePowerUser`
  - `AmazonGuardDutyFullAccess` (if enabling GuardDuty)
  - `AWSConfigRole` (if enabling AWS Config)
  - `SecretsManagerReadWrite` (if enabling Secrets Manager)

---

## 2. AWS Credentials Setup

### Option A: AWS CLI Profile (Recommended)

```bash
# Configure default credentials
aws configure
# Enter:
#   AWS Access Key ID:     <your-access-key>
#   AWS Secret Access Key: <your-secret-key>
#   Default region name:   us-east-1
#   Default output format: json

# Verify identity
aws sts get-caller-identity
```

### Option B: Environment Variables

```bash
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_DEFAULT_REGION="us-east-1"

# Verify
aws sts get-caller-identity
```

### Option C: IAM Role (CI/CD / EC2)

If running from an EC2 instance or CI/CD pipeline, attach an IAM role with the required permissions. No manual credential configuration needed.

---

## 3. Bootstrap Remote State (First Time Only)

> **Skip this step if you're using local state (not recommended for teams).**

The bootstrap module creates an S3 bucket and DynamoDB table for secure, shared Terraform state management.

```bash
# Navigate to bootstrap directory
cd bootstrap/

# Initialize and apply
terraform init
terraform apply

# Note the outputs:
# s3_bucket_name    = "eks-secure-cluster-tf-state-<account-id>"
# dynamodb_table_name = "eks-secure-cluster-tf-locks"
```

After bootstrapping, **uncomment** the S3 backend block in `provider.tf` and update the values:

```hcl
# In provider.tf — uncomment and update:
backend "s3" {
  bucket         = "eks-secure-cluster-tf-state-<your-account-id>"
  key            = "eks/terraform.tfstate"
  region         = "us-east-1"
  encrypt        = true
  dynamodb_table = "eks-secure-cluster-tf-locks"
}
```

Then go back to the root directory:

```bash
cd ..
```

---

## 4. Deploy the EKS Cluster

### Option A: Deploy to Development (Cost-Optimized)

```bash
# Initialize Terraform (downloads providers & modules)
terraform init

# Preview what will be created
terraform plan -var-file="environments/dev.tfvars"

# Deploy (type 'yes' when prompted)
terraform apply -var-file="environments/dev.tfvars"
```

**Dev environment:** Single NAT Gateway, Spot instances only, no GuardDuty/Config — ~$120/mo.

### Option B: Deploy to Production (High Availability)

```bash
terraform init
terraform plan -var-file="environments/prod.tfvars"
terraform apply -var-file="environments/prod.tfvars"
```

**Prod environment:** Multi-AZ NAT, On-Demand instances, GuardDuty + Config + Logging enabled — ~$280/mo.

### Option C: Deploy with Base Defaults

```bash
terraform init
terraform plan
terraform apply
```

Uses the values from `terraform.tfvars` (2 on-demand + 1 spot node, single NAT, GuardDuty + Config enabled).

### Option D: GitHub Actions (CI/CD)

1. Add `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` to GitHub repo **Settings → Secrets → Actions**
2. Go to **Actions** tab → **Deploy EKS Cluster** → **Run workflow**
3. Select environment (`dev`/`prod`) and action (`plan`/`apply`)

### ⏱️ Deployment Time

| Phase | Duration |
|-------|----------|
| `terraform init` | ~30 seconds |
| EKS Cluster creation | ~10-15 minutes |
| Node Groups (nodes joining) | ~5-8 minutes |
| EKS Addons (CoreDNS, etc.) | ~2-3 minutes |
| **Total** | **~18-25 minutes** |

---

## 5. Access the Cluster from Your Local Machine

This is the most important section — how to configure `kubectl` to talk to your new EKS cluster.

### Step 1: Get the kubeconfig Command

After `terraform apply` completes, it outputs a ready-to-use command:

```bash
# Show the configure command
terraform output configure_kubectl
```

This outputs something like:
```
"aws eks update-kubeconfig --region us-east-1 --name eks-secure-cluster"
```

### Step 2: Configure kubectl

Run the command from the output (remove the surrounding quotes):

```bash
aws eks update-kubeconfig --region us-east-1 --name eks-secure-cluster
```

This does the following:
- Creates or updates `~/.kube/config`
- Adds the cluster endpoint, certificate authority, and auth configuration
- Sets the new cluster as the current context

**Expected output:**
```
Added new context arn:aws:eks:us-east-1:<account-id>:cluster/eks-secure-cluster to /home/<user>/.kube/config
```

### Step 3: Verify Cluster Access

```bash
# Check cluster info
kubectl cluster-info

# List worker nodes (should show 2-3 nodes in Ready state)
kubectl get nodes -o wide

# List all pods across all namespaces
kubectl get pods -A

# Check EKS addons
kubectl get pods -n kube-system
```

**Expected output for `kubectl get nodes`:**
```
NAME                             STATUS   ROLES    AGE   VERSION
ip-10-0-1-xxx.ec2.internal      Ready    <none>   5m    v1.31.x
ip-10-0-2-xxx.ec2.internal      Ready    <none>   5m    v1.31.x
ip-10-0-3-xxx.ec2.internal      Ready    <none>   5m    v1.31.x
```

### Step 4: (Optional) Switch Between Clusters

If you manage multiple clusters:

```bash
# List all configured clusters
kubectl config get-contexts

# Switch to a specific cluster
kubectl config use-context arn:aws:eks:us-east-1:<account-id>:cluster/eks-secure-cluster

# Verify current context
kubectl config current-context
```

### Step 5: (Optional) Grant Access to Other Team Members

Other IAM users/roles can access the cluster using EKS Access Entries (configured as `API_AND_CONFIG_MAP` mode):

**Method 1: AWS Console**
1. Go to **EKS → Clusters → eks-secure-cluster → Access**
2. Click **Create access entry**
3. Select the IAM principal (user/role)
4. Choose access policy (e.g., `AmazonEKSClusterAdminPolicy`)

**Method 2: AWS CLI**
```bash
# Grant admin access to another IAM user
aws eks create-access-entry \
  --cluster-name eks-secure-cluster \
  --principal-arn arn:aws:iam::<account-id>:user/<username> \
  --type STANDARD

# Associate admin policy
aws eks associate-access-policy \
  --cluster-name eks-secure-cluster \
  --principal-arn arn:aws:iam::<account-id>:user/<username> \
  --policy-arn arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy \
  --access-scope type=cluster
```

**Method 3: Terraform (Add to main.tf)**
```hcl
resource "aws_eks_access_entry" "team_member" {
  cluster_name  = module.eks.cluster_name
  principal_arn = "arn:aws:iam::<account-id>:user/<username>"
  type          = "STANDARD"
}

resource "aws_eks_access_policy_association" "team_member_admin" {
  cluster_name  = module.eks.cluster_name
  principal_arn = "arn:aws:iam::<account-id>:user/<username>"
  policy_arn    = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
  access_scope {
    type = "cluster"
  }
}
```

Then the team member runs:
```bash
aws eks update-kubeconfig --region us-east-1 --name eks-secure-cluster
kubectl get nodes
```

---

## 6. Post-Deployment Verification

Run these checks after deployment to confirm everything is healthy:

### Cluster Health

```bash
# Cluster info
kubectl cluster-info

# Node status (all should be Ready)
kubectl get nodes

# System pods (all should be Running)
kubectl get pods -n kube-system

# Check EKS addon status
aws eks describe-addon --cluster-name eks-secure-cluster --addon-name coredns --query 'addon.status'
aws eks describe-addon --cluster-name eks-secure-cluster --addon-name kube-proxy --query 'addon.status'
aws eks describe-addon --cluster-name eks-secure-cluster --addon-name vpc-cni --query 'addon.status'
```

### Quick Smoke Test

Deploy a test pod to verify the cluster is functional:

```bash
# Deploy nginx test pod
kubectl run nginx-test --image=nginx:latest --port=80

# Wait for it to be running
kubectl wait --for=condition=Ready pod/nginx-test --timeout=60s

# Check it's running
kubectl get pod nginx-test -o wide

# Clean up
kubectl delete pod nginx-test
```

### Security Verification

```bash
# Verify KMS encryption is active
aws eks describe-cluster --name eks-secure-cluster \
  --query 'cluster.encryptionConfig[0].provider.keyArn'

# Verify OIDC provider exists (for IRSA)
aws eks describe-cluster --name eks-secure-cluster \
  --query 'cluster.identity.oidc.issuer'

# Check GuardDuty status (if enabled)
aws guardduty list-detectors
```

### Terraform Outputs

```bash
# View all outputs
terraform output

# Specific outputs
terraform output cluster_endpoint
terraform output cluster_name
terraform output vpc_id
terraform output configure_kubectl
```

---

## 7. Day 2 Operations

### Scale Node Groups

```bash
# Scale via kubectl (temporary — autoscaler may override)
kubectl scale --replicas=3 deployment/<your-deployment>

# Scale via AWS Console: EKS → Clusters → Node Groups → Edit scaling

# Scale via Terraform (permanent): update node_groups in your .tfvars
# Example in environments/prod.tfvars:
#   general = {
#     ...
#     desired_size = 5
#     max_size     = 10
#     ...
#   }
terraform apply -var-file="environments/prod.tfvars"
```

### Upgrade Kubernetes Version

1. Update `kubernetes_version` in your tfvars:
   ```hcl
   kubernetes_version = "1.32"
   ```
2. Apply:
   ```bash
   terraform plan -var-file="environments/prod.tfvars"
   terraform apply -var-file="environments/prod.tfvars"
   ```
3. EKS upgrades the control plane first, then node groups (rolling update).

### Deploy an Application

```bash
# Create a namespace
kubectl create namespace myapp

# Deploy (example)
kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
  namespace: myapp
spec:
  replicas: 2
  selector:
    matchLabels:
      app: myapp
  template:
    metadata:
      labels:
        app: myapp
    spec:
      containers:
      - name: myapp
        image: nginx:latest
        ports:
        - containerPort: 80
        resources:
          requests:
            cpu: 100m
            memory: 128Mi
          limits:
            cpu: 250m
            memory: 256Mi
      # Use on-demand nodes (avoid spot interruptions)
      nodeSelector:
        role: general
---
apiVersion: v1
kind: Service
metadata:
  name: myapp
  namespace: myapp
spec:
  type: LoadBalancer
  selector:
    app: myapp
  ports:
  - port: 80
    targetPort: 80
EOF

# Get the load balancer URL
kubectl get svc myapp -n myapp -o wide
```

### Install AWS Load Balancer Controller (Recommended)

For production ingress, install the AWS Load Balancer Controller:

```bash
# Install via Helm
helm repo add eks https://aws.github.io/eks-charts
helm repo update

helm install aws-load-balancer-controller eks/aws-load-balancer-controller \
  -n kube-system \
  --set clusterName=eks-secure-cluster \
  --set serviceAccount.create=true \
  --set serviceAccount.name=aws-load-balancer-controller
```

---

## 8. Cleanup / Destroy

> ⚠️ **WARNING:** This permanently deletes ALL cluster resources, including running workloads.

### Step 1: Delete Kubernetes Resources First

```bash
# Delete all user namespaces and resources
kubectl delete all --all --all-namespaces

# Delete any LoadBalancer services (to release AWS ELBs)
kubectl get svc --all-namespaces -o json | \
  jq -r '.items[] | select(.spec.type=="LoadBalancer") | .metadata.namespace + "/" + .metadata.name' | \
  xargs -I {} kubectl delete svc {}
```

### Step 2: Destroy Infrastructure

```bash
# Preview what will be destroyed
terraform plan -destroy -var-file="environments/dev.tfvars"

# Destroy (type 'yes' when prompted)
terraform destroy -var-file="environments/dev.tfvars"
```

### Step 3: (Optional) Destroy Bootstrap Resources

```bash
cd bootstrap/
# Remove lifecycle protection first (edit main.tf: comment out prevent_destroy)
terraform destroy
cd ..
```

### Step 4: Clean Up Local Config

```bash
# Remove the cluster from your kubeconfig
kubectl config delete-context arn:aws:eks:us-east-1:<account-id>:cluster/eks-secure-cluster
kubectl config delete-cluster arn:aws:eks:us-east-1:<account-id>:cluster/eks-secure-cluster
```

---

## 9. Troubleshooting

### Authentication Issues

| Problem | Solution |
|---------|----------|
| `error: You must be logged in to the server` | Run `aws eks update-kubeconfig --region us-east-1 --name eks-secure-cluster` again |
| `could not get token: AccessDeniedException` | Your IAM user/role doesn't have EKS access. Add via Access Entries (see Section 5, Step 5) |
| `Unable to connect to the server` | Check `public_access_cidrs` includes your IP; or use VPN if public endpoint is disabled |

### Node Issues

| Problem | Solution |
|---------|----------|
| Nodes stuck in `NotReady` | Check node IAM role has required policies: `kubectl describe node <node-name>` |
| Nodes not appearing | Check node security group allows traffic from cluster SG on ports 1025-65535 |
| Spot nodes terminated | Normal behavior — AWS reclaimed capacity. Nodes will auto-replace. |

### Addon Issues

| Problem | Solution |
|---------|----------|
| CoreDNS `Degraded` | Wait for nodes to reach `Ready` state first. CoreDNS needs running nodes. |
| VPC CNI errors | Check CNI version compatibility: `aws eks describe-addon-versions --addon-name vpc-cni` |
| DNS not resolving | Check CoreDNS pods: `kubectl get pods -n kube-system -l k8s-app=kube-dns` |

### Terraform Issues

| Problem | Solution |
|---------|----------|
| `terraform init` fails | Check internet connectivity; delete `.terraform/` and retry |
| State lock error | Another process is running. Wait, or force-unlock: `terraform force-unlock <lock-id>` |
| `Error: Unsupported Terraform Core version` | Install Terraform >= 1.14: `terraform version` |
| Provider version error | Delete `.terraform.lock.hcl` and re-run `terraform init` |
| GuardDuty already enabled | Import: `terraform import 'module.security.aws_guardduty_detector.main[0]' <detector-id>` |

---

## 10. Cost Summary

### Development Environment (~$120/mo)

| Component | Monthly Cost |
|-----------|-------------|
| EKS Control Plane | $73 |
| NAT Gateway (single) | $32 |
| EC2 Spot (2x t3.medium) | ~$12 |
| EBS Volumes (gp3) | ~$3 |
| **Total** | **~$120/mo** |

### Production Environment (~$350/mo)

| Component | Monthly Cost |
|-----------|-------------|
| EKS Control Plane | $73 |
| NAT Gateway (3x, multi-AZ) | $96 |
| EC2 On-Demand (3x m5.large) | ~$104 |
| EBS Volumes (gp3, 50GB each) | ~$12 |
| CloudWatch Logs | ~$10 |
| VPC Flow Logs | ~$5 |
| GuardDuty | ~$15 |
| AWS Config | ~$5 |
| **Total** | **~$320/mo** |

> 💡 Use the [AWS Pricing Calculator](https://calculator.aws/) for precise estimates based on your region and usage.

---

## Quick Reference Commands

```bash
# === DEPLOYMENT ===
terraform init                                          # Initialize
terraform plan -var-file="environments/dev.tfvars"      # Preview (dev)
terraform apply -var-file="environments/dev.tfvars"     # Deploy (dev)

# === CLUSTER ACCESS ===
aws eks update-kubeconfig --region us-east-1 --name eks-secure-cluster
kubectl get nodes
kubectl get pods -A

# === MONITORING ===
kubectl top nodes                                       # Node resource usage
kubectl top pods -A                                     # Pod resource usage
kubectl get events --sort-by='.lastTimestamp'            # Recent events

# === DESTROY ===
terraform destroy -var-file="environments/dev.tfvars"   # Tear down (dev)
```
