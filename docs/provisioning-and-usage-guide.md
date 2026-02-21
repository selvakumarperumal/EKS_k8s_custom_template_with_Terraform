# EKS Cluster: Provisioning & Post-Setup Usage Guide

A hands-on, end-to-end guide — from deploying the infrastructure via GitHub Actions to running your first application on the cluster.

---

## Phase 1: Prerequisites

Ensure the following tools are installed on your **local machine** (for cluster access after provisioning):

| Tool | Install Command | Verify |
|------|-----------------|--------|
| **AWS CLI v2** | [Install Guide](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) | `aws --version` |
| **kubectl** | [Install Guide](https://kubernetes.io/docs/tasks/tools/) | `kubectl version --client` |
| **Helm** (v3) | [Install Guide](https://helm.sh/docs/intro/install/) | `helm version` |

> [!NOTE]
> You do **not** need Terraform installed locally. The GitHub Actions workflow handles all Terraform operations in the cloud.

### Configure AWS Credentials Locally

You still need AWS credentials on your local machine to run `kubectl` and `helm` against the cluster after it's provisioned.

```bash
aws configure
# → Access Key, Secret Key, Region: ap-south-1, Output: json

# Verify
aws sts get-caller-identity
```

---

## Phase 2: Configure GitHub Repository Secrets

The GitHub Actions workflow needs AWS credentials to provision the infrastructure.

1. Go to your GitHub repository.
2. Navigate to **Settings** → **Secrets and variables** → **Actions**.
3. Click **"New repository secret"** and add:

| Secret Name | Value |
|-------------|-------|
| `AWS_ACCESS_KEY_ID` | Your AWS Access Key |
| `AWS_SECRET_ACCESS_KEY` | Your AWS Secret Key |

---

## Phase 3: Bootstrap the Remote State Backend

This is a **one-time local step** to create the S3 bucket and DynamoDB table for remote state storage and locking. This cannot be done via GitHub Actions because the backend must exist *before* the workflow can store state in it.

```bash
cd bootstrap/
terraform init
terraform apply
```

Note the output values (`s3_bucket_name`, `dynamodb_table_name`) and configure the `backend "s3"` block in `provider.tf` if needed.

> [!IMPORTANT]
> This step only needs to be done **once**, ever. After this, all subsequent operations are done via GitHub Actions.

---

## Phase 4: Provision the EKS Cluster via GitHub Actions

### Step 1: Plan (Dry Run)

1. Go to your GitHub repository → **Actions** tab.
2. Select **"Deploy EKS Cluster"** from the left sidebar.
3. Click **"Run workflow"**.
4. Set:
   - **Environment**: `dev`
   - **Action**: `plan`
5. Click **"Run workflow"**.

Review the workflow logs to see what Terraform will create.

### Step 2: Apply (Create the Infrastructure)

1. Go to **Actions** → **Deploy EKS Cluster** → **"Run workflow"**.
2. Set:
   - **Environment**: `dev`
   - **Action**: `apply`
3. Click **"Run workflow"**.

> [!NOTE]
> The `apply` step takes approximately **10-15 minutes**. The EKS control plane provisioning alone takes ~7 minutes.

### Step 3: Verify in AWS Console

After the workflow completes successfully:
- Go to the [EKS Console](https://console.aws.amazon.com/eks/) → you should see `eks-dev-cluster`.
- Go to the [EC2 Console](https://console.aws.amazon.com/ec2/) → you should see the worker node instances running.

---

## Phase 5: Access the EKS Cluster from Your Local Machine

### Step 1: Update kubeconfig

```bash
aws eks update-kubeconfig \
  --region ap-south-1 \
  --name eks-dev-cluster
```

You should see:
```
Added new context arn:aws:eks:ap-south-1:<ACCOUNT_ID>:cluster/eks-dev-cluster to ~/.kube/config
```

### Step 2: Verify Cluster Access

```bash
# Cluster info
kubectl cluster-info

# List nodes
kubectl get nodes -o wide

# List system pods (CoreDNS, kube-proxy, VPC CNI)
kubectl get pods -n kube-system
```

Expected output:
```
NAME                              STATUS   ROLES    AGE   VERSION
ip-10-0-1-xxx.ec2.internal       Ready    <none>   5m    v1.31.x
ip-10-0-2-xxx.ec2.internal       Ready    <none>   5m    v1.31.x
```

---

## Phase 6: Install Helm and Add Repositories

### Install Helm CLI

```bash
# Linux
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

# macOS
brew install helm

# Verify
helm version
```

### Add Common Helm Repositories

```bash
# Bitnami (Nginx, PostgreSQL, Redis, etc.)
helm repo add bitnami https://charts.bitnami.com/bitnami

# Metrics Server (required for kubectl top & HPA)
helm repo add metrics-server https://kubernetes-sigs.github.io/metrics-server/

# Ingress Nginx (for routing external traffic)
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx

# Update all repos
helm repo update
```

---

## Phase 7: Deploy Essential Cluster Components

### 1. Metrics Server

Required for `kubectl top` commands and Horizontal Pod Autoscaler (HPA).

```bash
helm install metrics-server metrics-server/metrics-server \
  --namespace kube-system \
  --set args[0]="--kubelet-preferred-address-types=InternalIP"

# Verify (wait ~30 seconds)
kubectl top nodes
```

### 2. Ingress Nginx Controller

Enables external HTTP/HTTPS traffic routing into your cluster via an AWS Network Load Balancer.

```bash
helm install ingress-nginx ingress-nginx/ingress-nginx \
  --namespace ingress-nginx \
  --create-namespace \
  --set controller.service.type=LoadBalancer \
  --set controller.service.annotations."service\.beta\.kubernetes\.io/aws-load-balancer-type"=nlb \
  --set controller.service.annotations."service\.beta\.kubernetes\.io/aws-load-balancer-scheme"=internet-facing
```

```bash
# Get the external Load Balancer URL (may take 2-3 minutes to provision)
kubectl get svc -n ingress-nginx ingress-nginx-controller
```

---

## Phase 8: Deploy a Sample Application

### Create and Apply the Resources

```bash
kubectl create namespace sample-app

cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-demo
  namespace: sample-app
spec:
  replicas: 2
  selector:
    matchLabels:
      app: nginx-demo
  template:
    metadata:
      labels:
        app: nginx-demo
    spec:
      containers:
      - name: nginx
        image: nginx:alpine
        ports:
        - containerPort: 80
        resources:
          requests:
            cpu: 50m
            memory: 64Mi
          limits:
            cpu: 100m
            memory: 128Mi
---
apiVersion: v1
kind: Service
metadata:
  name: nginx-demo-svc
  namespace: sample-app
spec:
  type: ClusterIP
  selector:
    app: nginx-demo
  ports:
  - port: 80
    targetPort: 80
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: nginx-demo-ingress
  namespace: sample-app
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
spec:
  ingressClassName: nginx
  rules:
  - http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: nginx-demo-svc
            port:
              number: 80
EOF
```

### Verify and Access

```bash
# Check pods
kubectl get pods -n sample-app

# Get the Load Balancer hostname
LB_HOST=$(kubectl get svc -n ingress-nginx ingress-nginx-controller \
  -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')

# Test
curl http://$LB_HOST
# → You should see "Welcome to nginx!"
```

---

## Phase 9: Teardown / Destroy

### Remove App and Helm Releases

```bash
kubectl delete namespace sample-app
helm uninstall ingress-nginx -n ingress-nginx
helm uninstall metrics-server -n kube-system
```

### Destroy the EKS Infrastructure via GitHub Actions

1. Go to **Actions** → **Deploy EKS Cluster** → **"Run workflow"**.
2. Set:
   - **Environment**: `dev`
   - **Action**: `destroy`
3. Click **"Run workflow"**.

> [!CAUTION]
> This permanently destroys the EKS cluster, all node groups, VPC, and associated resources. Back up any data first.

---

## Quick Reference Commands

| Task | Command |
|------|---------|
| List nodes | `kubectl get nodes -o wide` |
| List all pods | `kubectl get pods -A` |
| Get pod logs | `kubectl logs <pod-name> -n <namespace>` |
| Shell into a pod | `kubectl exec -it <pod-name> -n <namespace> -- /bin/sh` |
| List Helm releases | `helm list -A` |
| Upgrade a Helm chart | `helm upgrade <release> <chart> -n <namespace>` |
| View cluster events | `kubectl get events --sort-by=.metadata.creationTimestamp` |
| Check resource usage | `kubectl top nodes` / `kubectl top pods -A` |
| Scale a deployment | `kubectl scale deploy/<name> --replicas=5 -n <namespace>` |
