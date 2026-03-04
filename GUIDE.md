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
8. [AWS Secrets Manager — Managing Secrets](#8-aws-secrets-manager--managing-secrets)
9. [Cleanup / Destroy](#9-cleanup--destroy)
10. [Troubleshooting](#10-troubleshooting)
11. [Cost Summary](#11-cost-summary)

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

## 8. AWS Secrets Manager — Managing Secrets

This template includes a `secrets-manager` module that stores sensitive data (DB credentials, API keys, app config) encrypted with a dedicated KMS key. All secrets are **disabled by default** — you opt-in to each one.

### 8.1 Enable Secrets via Terraform

Add these variables to your `terraform.tfvars` or environment tfvars file:

#### Database Credentials

```hcl
# terraform.tfvars or environments/prod.tfvars
create_db_secret = true
```

Then pass the actual credentials securely via **environment variables** (never commit passwords to files):

```bash
# Set credentials as env vars (they won't appear in terraform plan output)
export TF_VAR_db_username="admin"
export TF_VAR_db_password="YourStr0ng!Password"
export TF_VAR_db_host="mydb.cluster-xxx.us-east-1.rds.amazonaws.com"
export TF_VAR_db_port="5432"
export TF_VAR_db_name="myapp"
export TF_VAR_db_engine="postgres"   # or "mysql", "aurora-postgresql"

# Apply — credentials are marked sensitive, hidden from output
terraform apply -var-file="environments/prod.tfvars"
```

**What gets created:**
- Secret: `eks-secure-cluster-db-credentials` (JSON: `{username, password, engine, host, port, dbname}`)
- KMS key: `alias/eks-secure-cluster-secrets` (dedicated encryption key)
- IAM policy: `eks-secure-cluster-read-secrets-*` (read-only access for pods)

#### Where Do These Database Values Come From?

The Secrets Manager module **stores** credentials — it does NOT create the database itself. Here's where each value comes from:

| Variable | Where It Comes From |
|----------|-------------------|
| `db_username` | You choose it when creating the database |
| `db_password` | You choose it when creating the database |
| `db_host` | The RDS/Aurora **endpoint** (shown in AWS Console after creation) |
| `db_port` | `5432` (PostgreSQL) or `3306` (MySQL) — standard ports |
| `db_name` | The database name you created |
| `db_engine` | `postgres`, `mysql`, `aurora-postgresql`, etc. |

**Option A: You already have a database** — Copy the endpoint from AWS Console → RDS → Your DB → Endpoint, and use the master credentials you set during creation.

**Option B: Create via AWS Console** — Go to AWS Console → RDS → Create Database → Choose PostgreSQL/MySQL → Set master username & password → **Place it in the same VPC as your EKS cluster** → After creation, copy the Endpoint.

**Option C: Create via Terraform** — Add an RDS resource to your `main.tf`:

```hcl
# Add to main.tf — Creates a PostgreSQL database in the same VPC as EKS
resource "aws_db_subnet_group" "main" {
  name       = "${var.cluster_name}-db-subnet"
  subnet_ids = module.vpc.private_subnet_ids   # Same private subnets as EKS nodes
  tags       = { Name = "${var.cluster_name}-db-subnet" }
}

resource "aws_security_group" "rds" {
  name_prefix = "${var.cluster_name}-rds-"
  vpc_id      = module.vpc.vpc_id

  # Allow PostgreSQL traffic ONLY from EKS worker nodes
  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [module.eks.cluster_security_group_id]
  }

  tags = { Name = "${var.cluster_name}-rds-sg" }
}

resource "aws_db_instance" "main" {
  identifier        = "${var.cluster_name}-db"
  engine            = "postgres"
  engine_version    = "16.4"
  instance_class    = "db.t3.micro"    # ~$15/mo (smallest, good for dev)
  allocated_storage = 20               # 20 GB gp3

  db_name  = "myapp"
  username = var.db_username           # From TF_VAR_db_username
  password = var.db_password           # From TF_VAR_db_password

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.rds.id]
  skip_final_snapshot    = true        # Set false for production!

  tags = { Name = "${var.cluster_name}-db" }
}
```

With Option C, the host is auto-generated — use `aws_db_instance.main.endpoint` as output and you only need to set:
```bash
export TF_VAR_db_username="admin"
export TF_VAR_db_password="YourStr0ng!Password"
terraform apply
```

#### API Keys

```hcl
create_api_secret = true
```

```bash
export TF_VAR_api_key="sk-live-abc123..."
export TF_VAR_api_secret="whsec_xyz789..."
terraform apply -var-file="environments/prod.tfvars"
```

Creates: `eks-secure-cluster-api-keys` secret with `{api_key, api_secret}`.

#### Application Configuration

```hcl
create_app_config_secret = true
```

```bash
# Pass as a JSON map
export TF_VAR_app_config='{"LOG_LEVEL":"info","FEATURE_FLAG_NEW_UI":"true","APP_ENV":"production","REDIS_URL":"redis://cache:6379"}'
terraform apply -var-file="environments/prod.tfvars"
```

Creates: `eks-secure-cluster-app-config` secret with your key-value pairs as JSON.

#### Enable All Three at Once

```hcl
# In terraform.tfvars
create_db_secret         = true
create_api_secret        = true
create_app_config_secret = true
```

```bash
# Set ALL env vars, then apply
export TF_VAR_db_username="admin"
export TF_VAR_db_password="S3cur3P@ss!"
# ... (all other TF_VAR_* from above)
terraform apply
```

### 8.2 Verify Secrets Were Created

```bash
# List secrets
aws secretsmanager list-secrets --query 'SecretList[?starts_with(Name, `eks-secure-cluster`)].Name'

# Read a secret value (careful — this outputs the actual secret!)
aws secretsmanager get-secret-value \
  --secret-id eks-secure-cluster-db-credentials \
  --query 'SecretString' --output text | jq .

# Check Terraform outputs
terraform output secrets_manager_db_secret_arn
terraform output secrets_manager_api_secret_arn
terraform output secrets_manager_read_policy_arn
```

### 8.3 How Pods Access Secrets (3 Methods)

All methods use **IRSA** (IAM Roles for Service Accounts) — pods get temporary AWS credentials via their ServiceAccount, not long-lived keys.

#### Method 1: External Secrets Operator (Recommended)

Automatically syncs AWS secrets → Kubernetes Secrets. Best for most use cases.

```bash
# Install External Secrets Operator
helm repo add external-secrets https://charts.external-secrets.io
helm repo update
helm install external-secrets external-secrets/external-secrets \
  -n external-secrets --create-namespace
```

Create an IRSA-enabled ServiceAccount and ExternalSecret:

```yaml
# 1. ServiceAccount with IRSA annotation
apiVersion: v1
kind: ServiceAccount
metadata:
  name: secret-reader
  namespace: myapp
  annotations:
    # Replace with the IRSA role ARN from: terraform output secrets_manager_read_policy_arn
    eks.amazonaws.com/role-arn: "arn:aws:iam::<account-id>:role/<irsa-role>"

---
# 2. SecretStore — tells ESO how to connect to AWS
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: aws-secrets
  namespace: myapp
spec:
  provider:
    aws:
      service: SecretsManager
      region: us-east-1
      auth:
        jwt:
          serviceAccountRef:
            name: secret-reader

---
# 3. ExternalSecret — syncs AWS secret → K8s Secret
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: db-credentials
  namespace: myapp
spec:
  refreshInterval: 1h          # Poll every hour for changes
  secretStoreRef:
    name: aws-secrets
  target:
    name: db-credentials       # K8s Secret name created automatically
  data:
    - secretKey: DB_USERNAME   # K8s Secret key
      remoteRef:
        key: eks-secure-cluster-db-credentials  # AWS Secret name
        property: username                      # JSON field to extract
    - secretKey: DB_PASSWORD
      remoteRef:
        key: eks-secure-cluster-db-credentials
        property: password
    - secretKey: DB_HOST
      remoteRef:
        key: eks-secure-cluster-db-credentials
        property: host
```

Use in your Deployment:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
  namespace: myapp
spec:
  template:
    spec:
      serviceAccountName: secret-reader
      containers:
      - name: myapp
        image: myapp:latest
        envFrom:
        - secretRef:
            name: db-credentials   # Auto-created by ExternalSecret
```

#### Method 2: CSI Secrets Store Driver

Mounts secrets as files inside the pod. Good for apps that read config from files.

```bash
# Install CSI driver
helm repo add secrets-store-csi-driver https://kubernetes-sigs.github.io/secrets-store-csi-driver/charts
helm install csi-secrets-store secrets-store-csi-driver/secrets-store-csi-driver \
  -n kube-system --set syncSecret.enabled=true

# Install AWS provider
kubectl apply -f https://raw.githubusercontent.com/aws/secrets-store-csi-driver-provider-aws/main/deployment/aws-provider-installer.yaml
```

```yaml
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: aws-db-secrets
  namespace: myapp
spec:
  provider: aws
  parameters:
    objects: |
      - objectName: "eks-secure-cluster-db-credentials"
        objectType: "secretsmanager"
        jmesPath:
          - path: username
            objectAlias: db-username
          - path: password
            objectAlias: db-password
---
# In your Deployment pod spec:
# spec:
#   volumes:
#   - name: secrets
#     csi:
#       driver: secrets-store.csi.k8s.io
#       readOnly: true
#       volumeAttributes:
#         secretProviderClass: aws-db-secrets
#   containers:
#   - name: app
#     volumeMounts:
#     - name: secrets
#       mountPath: /mnt/secrets
#       readOnly: true
# Secret files appear at: /mnt/secrets/db-username, /mnt/secrets/db-password
```

#### Method 3: AWS SDK in Application Code

Directly call Secrets Manager API from your app. Best for dynamic secret rotation handling.

```python
# Python example using boto3
import boto3, json

def get_db_credentials():
    client = boto3.client('secretsmanager', region_name='us-east-1')
    response = client.get_secret_value(SecretId='eks-secure-cluster-db-credentials')
    return json.loads(response['SecretString'])

# Usage:
creds = get_db_credentials()
db_url = f"postgresql://{creds['username']}:{creds['password']}@{creds['host']}:{creds['port']}/{creds['dbname']}"
```

```javascript
// Node.js example
const { SecretsManagerClient, GetSecretValueCommand } = require("@aws-sdk/client-secrets-manager");

async function getApiKeys() {
  const client = new SecretsManagerClient({ region: "us-east-1" });
  const response = await client.send(
    new GetSecretValueCommand({ SecretId: "eks-secure-cluster-api-keys" })
  );
  return JSON.parse(response.SecretString);
}

// Usage:
const keys = await getApiKeys();
console.log(keys.api_key, keys.api_secret);
```

> **Important:** For Methods 1 & 2, pods need an IRSA-annotated ServiceAccount. For Method 3, the pod's ServiceAccount also needs IRSA so boto3/SDK gets credentials automatically.

### 8.4 Create an IRSA Role for Secret Access

If you need to create an IRSA role manually (the module outputs the policy ARN):

```bash
# Get the read-secrets policy ARN
POLICY_ARN=$(terraform output -raw secrets_manager_read_policy_arn)

# Get OIDC provider
OIDC_PROVIDER=$(terraform output -raw oidc_provider)

# Create trust policy
cat > /tmp/trust-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Federated": "arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):oidc-provider/${OIDC_PROVIDER}" },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "${OIDC_PROVIDER}:sub": "system:serviceaccount:myapp:secret-reader"
      }
    }
  }]
}
EOF

# Create role and attach policy
aws iam create-role --role-name eks-secret-reader --assume-role-policy-document file:///tmp/trust-policy.json
aws iam attach-role-policy --role-name eks-secret-reader --policy-arn "$POLICY_ARN"

# Annotate your K8s ServiceAccount
kubectl annotate sa secret-reader -n myapp \
  eks.amazonaws.com/role-arn=arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):role/eks-secret-reader
```

### 8.5 Rotate Secrets

```bash
# Update a secret value via CLI
aws secretsmanager put-secret-value \
  --secret-id eks-secure-cluster-db-credentials \
  --secret-string '{"username":"admin","password":"NewP@ssw0rd!","engine":"postgres","host":"mydb.xxx.rds.amazonaws.com","port":"5432","dbname":"myapp"}'

# Or update via Terraform (change the env var and re-apply)
export TF_VAR_db_password="NewP@ssw0rd!"
terraform apply
```

> **Note:** After rotation, External Secrets Operator picks up changes at the next `refreshInterval`. CSI driver requires a pod restart. SDK-based apps pick up changes immediately on next API call.

### 8.6 Secrets Troubleshooting

| Problem | Solution |
|---------|----------|
| `AccessDeniedException` from pod | Verify ServiceAccount has correct IRSA annotation; check IAM policy includes the secret ARN |
| ExternalSecret shows `SecretSyncedError` | Check SecretStore auth; verify OIDC trust policy allows the ServiceAccount |
| Secret value is empty `{}` | Ensure you passed `TF_VAR_*` env vars before `terraform apply` |
| KMS decrypt error | The read-secrets IAM policy already includes `kms:Decrypt`; verify the policy is attached to the IRSA role |
| Secret not found | Check the secret name: `aws secretsmanager list-secrets --query 'SecretList[].Name'` |

---

## 9. Cleanup / Destroy

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

## 10. Troubleshooting

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

## 11. Cost Summary

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
| Secrets Manager (3 secrets) | ~$1.50 |
| **Total** | **~$322/mo** |

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

# === SECRETS ===
aws secretsmanager list-secrets --query 'SecretList[].Name'
aws secretsmanager get-secret-value --secret-id eks-secure-cluster-db-credentials

# === MONITORING ===
kubectl top nodes                                       # Node resource usage
kubectl top pods -A                                     # Pod resource usage
kubectl get events --sort-by='.lastTimestamp'            # Recent events

# === DESTROY ===
terraform destroy -var-file="environments/dev.tfvars"   # Tear down (dev)
```
