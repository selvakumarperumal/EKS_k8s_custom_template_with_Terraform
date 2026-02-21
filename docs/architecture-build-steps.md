# 🏗️ Architecture Build Steps

How `terraform apply` builds the entire infrastructure — step by step.
Each step includes the actual HCL code and a D2 architecture diagram (Dracula theme).

---

## Phase 1 — VPC Module

### Step 1 — Create the VPC

```hcl
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags = merge(var.tags, { Name = "${var.name_prefix}-vpc" })
}
```

```d2
direction: down
vars: {
  d2-config: {
    theme-id: 200
  }
}

vpc: VPC 10.0.0.0/16 {
  style.fill: "#44475a"
  style.stroke: "#bd93f9"
  style.font-color: "#f8f8f2"

  dns: "✅ DNS Support + Hostnames Enabled\n65,536 IP addresses" {
    style.fill: "#50fa7b"
    style.font-color: "#282a36"
  }
}
```

> `enable_dns_support` + `enable_dns_hostnames` are **required by EKS** — kubelet uses DNS to register nodes.

---

### Step 2 — Attach Internet Gateway

```hcl
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags = merge(var.tags, { Name = "${var.name_prefix}-igw" })
}
```

```d2
direction: down
vars: {
  d2-config: {
    theme-id: 200
  }
}

internet: 🌐 Internet {
  shape: cloud
  style.fill: "#6272a4"
  style.font-color: "#f8f8f2"
}

vpc: VPC 10.0.0.0/16 {
  style.fill: "#44475a"
  style.stroke: "#bd93f9"

  igw: Internet Gateway {
    style.fill: "#ffb86c"
    style.font-color: "#282a36"
  }
}

internet <-> vpc.igw: Bidirectional {
  style.stroke: "#8be9fd"
}
```

> One IGW per VPC. It's the "front door" — only public subnets use it.

---

### Step 3 — Create Public Subnets (×3)

```hcl
resource "aws_subnet" "public" {
  count                   = length(var.public_subnets)
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnets[count.index]
  availability_zone       = var.azs[count.index]
  map_public_ip_on_launch = true
  tags = merge(var.tags, var.public_subnet_tags, {
    Name = "${var.name_prefix}-public-${var.azs[count.index]}"
    Type = "public"
  })
}
```

```d2
direction: down
vars: {
  d2-config: {
    theme-id: 200
  }
}

internet: 🌐 Internet { shape: cloud; style.fill: "#6272a4" }

vpc: VPC 10.0.0.0/16 {
  style.fill: "#44475a"
  style.stroke: "#bd93f9"

  igw: Internet Gateway { style.fill: "#ffb86c"; style.font-color: "#282a36" }

  az1: AZ-A {
    style.fill: "#282a36"
    style.stroke: "#6272a4"
    pub1: "🟢 Public Subnet\n10.0.101.0/24" { style.fill: "#50fa7b"; style.font-color: "#282a36" }
  }
  az2: AZ-B {
    style.fill: "#282a36"
    style.stroke: "#6272a4"
    pub2: "🟢 Public Subnet\n10.0.102.0/24" { style.fill: "#50fa7b"; style.font-color: "#282a36" }
  }
  az3: AZ-C {
    style.fill: "#282a36"
    style.stroke: "#6272a4"
    pub3: "🟢 Public Subnet\n10.0.103.0/24" { style.fill: "#50fa7b"; style.font-color: "#282a36" }
  }
}

internet <-> vpc.igw
vpc.igw <-> vpc.az1.pub1
vpc.igw <-> vpc.az2.pub2
vpc.igw <-> vpc.az3.pub3
```

> `map_public_ip_on_launch = true` — auto-assigns public IPs. Tagged with `kubernetes.io/role/elb = 1`.

---

### Step 4 — Create Private Subnets (×3)

```hcl
resource "aws_subnet" "private" {
  count             = length(var.private_subnets)
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_subnets[count.index]
  availability_zone = var.azs[count.index]
  tags = merge(var.tags, var.private_subnet_tags, {
    Name = "${var.name_prefix}-private-${var.azs[count.index]}"
    Type = "private"
  })
}
```

```d2
direction: down
vars: {
  d2-config: {
    theme-id: 200
  }
}

internet: 🌐 Internet { shape: cloud; style.fill: "#6272a4" }

vpc: VPC 10.0.0.0/16 {
  style.fill: "#44475a"
  style.stroke: "#bd93f9"

  igw: Internet Gateway { style.fill: "#ffb86c"; style.font-color: "#282a36" }

  az1: AZ-A {
    style.fill: "#282a36"; style.stroke: "#6272a4"
    pub1: "🟢 Public\n10.0.101.0/24" { style.fill: "#50fa7b"; style.font-color: "#282a36" }
    priv1: "🔵 Private\n10.0.1.0/24" { style.fill: "#8be9fd"; style.font-color: "#282a36" }
  }
  az2: AZ-B {
    style.fill: "#282a36"; style.stroke: "#6272a4"
    pub2: "🟢 Public\n10.0.102.0/24" { style.fill: "#50fa7b"; style.font-color: "#282a36" }
    priv2: "🔵 Private\n10.0.2.0/24" { style.fill: "#8be9fd"; style.font-color: "#282a36" }
  }
  az3: AZ-C {
    style.fill: "#282a36"; style.stroke: "#6272a4"
    pub3: "🟢 Public\n10.0.103.0/24" { style.fill: "#50fa7b"; style.font-color: "#282a36" }
    priv3: "🔵 Private\n10.0.3.0/24" { style.fill: "#8be9fd"; style.font-color: "#282a36" }
  }
}

internet <-> vpc.igw
vpc.igw <-> vpc.az1.pub1
vpc.igw <-> vpc.az2.pub2
vpc.igw <-> vpc.az3.pub3
```

> No public IPs. EKS worker nodes live here. Tagged `kubernetes.io/role/internal-elb = 1`.

---

### Step 5 — Create EIP + NAT Gateway

```hcl
resource "aws_eip" "nat" {
  count  = var.enable_nat_gateway ? (var.single_nat_gateway ? 1 : length(var.public_subnets)) : 0
  domain = "vpc"
  depends_on = [aws_internet_gateway.main]
}

resource "aws_nat_gateway" "main" {
  count         = var.enable_nat_gateway ? (var.single_nat_gateway ? 1 : length(var.public_subnets)) : 0
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id
  depends_on    = [aws_internet_gateway.main]
}
```

```d2
direction: down
vars: {
  d2-config: {
    theme-id: 200
  }
}

internet: 🌐 Internet { shape: cloud; style.fill: "#6272a4" }

vpc: VPC 10.0.0.0/16 {
  style.fill: "#44475a"
  style.stroke: "#bd93f9"

  igw: Internet Gateway { style.fill: "#ffb86c"; style.font-color: "#282a36" }
  nat: "NAT Gateway\n+ Elastic IP" { style.fill: "#ffb86c"; style.font-color: "#282a36" }

  az1: AZ-A {
    style.fill: "#282a36"; style.stroke: "#6272a4"
    pub1: "🟢 Public" { style.fill: "#50fa7b"; style.font-color: "#282a36" }
    priv1: "🔵 Private" { style.fill: "#8be9fd"; style.font-color: "#282a36" }
  }
  az2: AZ-B {
    style.fill: "#282a36"; style.stroke: "#6272a4"
    pub2: "🟢 Public" { style.fill: "#50fa7b"; style.font-color: "#282a36" }
    priv2: "🔵 Private" { style.fill: "#8be9fd"; style.font-color: "#282a36" }
  }
}

internet <-> vpc.igw
vpc.nat -> vpc.igw
vpc.az1.priv1 -> vpc.nat: "Outbound only\n0.0.0.0/0 → NAT" { style.stroke: "#f1fa8c" }
vpc.az2.priv2 -> vpc.nat: "Outbound only" { style.stroke: "#f1fa8c" }
```

> `single_nat_gateway = true` → 1 NAT (~$33/mo). Set `false` for HA (1 per AZ, ~$100/mo).

---

### Step 6 — Create Route Tables

```hcl
resource "aws_route_table" "public" { vpc_id = aws_vpc.main.id }

resource "aws_route" "public_internet_gateway" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.main.id
}

resource "aws_route_table" "private" {
  count  = var.single_nat_gateway ? 1 : length(var.private_subnets)
  vpc_id = aws_vpc.main.id
}

resource "aws_route" "private_nat_gateway" {
  count                  = var.enable_nat_gateway ? (var.single_nat_gateway ? 1 : length(var.private_subnets)) : 0
  route_table_id         = aws_route_table.private[count.index].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.main[count.index].id
}
```

> Public: `0.0.0.0/0 → IGW`. Private: `0.0.0.0/0 → NAT`.

---

### Step 7 — Create Public NACL

```hcl
resource "aws_network_acl" "public" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = aws_subnet.public[*].id

  ingress { rule_no = 100; protocol = "tcp"; action = "allow"; cidr_block = "0.0.0.0/0"; from_port = 443; to_port = 443 }
  ingress { rule_no = 200; protocol = "tcp"; action = "allow"; cidr_block = "0.0.0.0/0"; from_port = 80; to_port = 80 }
  ingress { rule_no = 300; protocol = "tcp"; action = "allow"; cidr_block = "0.0.0.0/0"; from_port = 1024; to_port = 65535 }
  ingress { rule_no = 400; protocol = "-1"; action = "allow"; cidr_block = var.vpc_cidr; from_port = 0; to_port = 0 }
  egress  { rule_no = 100; protocol = "-1"; action = "allow"; cidr_block = "0.0.0.0/0"; from_port = 0; to_port = 0 }
}
```

```d2
direction: right
vars: {
  d2-config: {
    theme-id: 200
  }
}

nacl: "🛡️ Public NACL" {
  style.fill: "#bd93f9"
  style.font-color: "#f8f8f2"

  inbound: Inbound Rules {
    style.fill: "#44475a"
    r100: "Rule 100: HTTPS 443 ✅" { style.fill: "#50fa7b"; style.font-color: "#282a36" }
    r200: "Rule 200: HTTP 80 ✅" { style.fill: "#50fa7b"; style.font-color: "#282a36" }
    r300: "Rule 300: Ephemeral 1024-65535 ✅" { style.fill: "#f1fa8c"; style.font-color: "#282a36" }
    r400: "Rule 400: VPC Internal ✅" { style.fill: "#8be9fd"; style.font-color: "#282a36" }
  }
  outbound: Outbound Rules {
    style.fill: "#44475a"
    e100: "Rule 100: ALL outbound ✅" { style.fill: "#50fa7b"; style.font-color: "#282a36" }
  }
}

subnets: "🟢 Public Subnets x3" { style.fill: "#50fa7b"; style.font-color: "#282a36" }
nacl -- subnets: Applied to
```

> NACLs are **stateless** — Rule 300 allows ephemeral response ports.

---

### Step 8 — Create Private NACL

```hcl
resource "aws_network_acl" "private" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = aws_subnet.private[*].id

  ingress { rule_no = 100; protocol = "-1"; action = "allow"; cidr_block = var.vpc_cidr; from_port = 0; to_port = 0 }
  ingress { rule_no = 200; protocol = "tcp"; action = "allow"; cidr_block = "0.0.0.0/0"; from_port = 1024; to_port = 65535 }
  egress  { rule_no = 100; protocol = "-1"; action = "allow"; cidr_block = "0.0.0.0/0"; from_port = 0; to_port = 0 }
}
```

> More restrictive — only VPC-internal traffic and ephemeral response ports allowed inbound.

---

### Step 9 — Enable VPC Flow Logs

```hcl
resource "aws_iam_role" "flow_log" {
  count       = var.enable_flow_logs ? 1 : 0
  name_prefix = "${var.name_prefix}-vpc-flow-log-"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Action = "sts:AssumeRole"; Effect = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" } }]
  })
}

resource "aws_cloudwatch_log_group" "flow_log" {
  count             = var.enable_flow_logs ? 1 : 0
  name              = "/aws/vpc/${var.name_prefix}/flow-logs"
  retention_in_days = 30
}

resource "aws_flow_log" "main" {
  count        = var.enable_flow_logs ? 1 : 0
  vpc_id       = aws_vpc.main.id
  traffic_type = "ALL"
  iam_role_arn    = aws_iam_role.flow_log[0].arn
  log_destination = aws_cloudwatch_log_group.flow_log[0].arn
}
```

```d2
direction: right
vars: {
  d2-config: {
    theme-id: 200
  }
}

vpc: VPC {
  style.fill: "#44475a"
  style.stroke: "#bd93f9"
  traffic: "All Network\nTraffic Metadata" { style.fill: "#6272a4"; style.font-color: "#f8f8f2" }
}

flow: "📊 VPC Flow Logs" { style.fill: "#bd93f9"; style.font-color: "#f8f8f2" }
cw: "☁️ CloudWatch\nRetention: 30 days" { style.fill: "#6272a4"; style.font-color: "#f8f8f2" }

vpc.traffic -> flow: "Src/Dst IP, Port\nProtocol, ACCEPT/REJECT" { style.stroke: "#8be9fd" }
flow -> cw { style.stroke: "#8be9fd" }
```

> `traffic_type = "ALL"` captures accepted + rejected traffic for forensic analysis.

---

## Phase 2 — IAM Module (Parallel with VPC)

### Step 10 — Create Cluster IAM Role

```hcl
resource "aws_iam_role" "cluster" {
  name_prefix = "${var.cluster_name}-cluster-"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Action = "sts:AssumeRole"; Effect = "Allow"
      Principal = { Service = "eks.amazonaws.com" } }]
  })
}

resource "aws_iam_role_policy_attachment" "cluster_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.cluster.name
}

resource "aws_iam_role_policy_attachment" "cluster_vpc_resource_controller" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
  role       = aws_iam_role.cluster.name
}
```

```d2
direction: right
vars: {
  d2-config: {
    theme-id: 200
  }
}

role: "🔴 Cluster IAM Role" {
  style.fill: "#ff5555"
  style.font-color: "#f8f8f2"
  trust: "Trust: eks.amazonaws.com\nOnly EKS service can assume" { style.fill: "#44475a"; style.font-color: "#f8f8f2" }
}

p1: "📜 AmazonEKSClusterPolicy\nManage API server, ENIs, logs" { style.fill: "#ffb86c"; style.font-color: "#282a36" }
p2: "📜 AmazonEKSVPCResourceController\nManage VPC networking" { style.fill: "#ffb86c"; style.font-color: "#282a36" }

role -> p1: Attached { style.stroke: "#f1fa8c" }
role -> p2: Attached { style.stroke: "#f1fa8c" }
```

---

### Step 11 — Create Node Group IAM Role

```hcl
resource "aws_iam_role" "node_group" {
  name_prefix = "${var.cluster_name}-node-"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Action = "sts:AssumeRole"; Effect = "Allow"
      Principal = { Service = "ec2.amazonaws.com" } }]
  })
}

resource "aws_iam_role_policy_attachment" "node_worker_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.node_group.name
}
resource "aws_iam_role_policy_attachment" "node_cni_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.node_group.name
}
resource "aws_iam_role_policy_attachment" "node_registry_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.node_group.name
}
```

```d2
direction: right
vars: {
  d2-config: {
    theme-id: 200
  }
}

role: "🔴 Node Group IAM Role" {
  style.fill: "#ff5555"
  style.font-color: "#f8f8f2"
  trust: "Trust: ec2.amazonaws.com\nOnly EC2 instances can assume" { style.fill: "#44475a"; style.font-color: "#f8f8f2" }
}

p1: "📜 EKSWorkerNodePolicy\nRegister with cluster" { style.fill: "#ffb86c"; style.font-color: "#282a36" }
p2: "📜 EKS_CNI_Policy\nAssign VPC IPs to pods" { style.fill: "#ffb86c"; style.font-color: "#282a36" }
p3: "📜 ECR ReadOnly\nPull container images" { style.fill: "#ffb86c"; style.font-color: "#282a36" }

role -> p1: Attached { style.stroke: "#f1fa8c" }
role -> p2: Attached { style.stroke: "#f1fa8c" }
role -> p3: Attached { style.stroke: "#f1fa8c" }
```

> Without `WorkerNodePolicy`, nodes → `NotReady`. Without `ECR ReadOnly`, pods → `no basic auth credentials`.

---

## Phase 3 — EKS Module (Needs VPC + IAM)

### Step 12 — Create KMS Key

```hcl
resource "aws_kms_key" "eks" {
  description             = "KMS key for EKS cluster ${var.cluster_name} encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  tags = merge(var.tags, { Name = "${var.cluster_name}-eks-kms" })
}

resource "aws_kms_alias" "eks" {
  name          = "alias/${var.cluster_name}-eks"
  target_key_id = aws_kms_key.eks.key_id
}
```

```d2
direction: right
vars: {
  d2-config: {
    theme-id: 200
  }
}

kms: "🔑 KMS Master Key" {
  style.fill: "#ff5555"
  style.font-color: "#f8f8f2"
  rotation: "✅ Auto-rotation yearly" { style.fill: "#44475a"; style.font-color: "#50fa7b" }
  window: "✅ 7-day deletion window" { style.fill: "#44475a"; style.font-color: "#50fa7b" }
}

alias: "Alias: alias/eks-cluster-eks" { style.fill: "#6272a4"; style.font-color: "#f8f8f2" }

secret: K8s Secret { style.fill: "#44475a"; style.font-color: "#f8f8f2" }
dek: Data Encryption Key { style.fill: "#f1fa8c"; style.font-color: "#282a36" }
etcd: "etcd (encrypted)" { shape: cylinder; style.fill: "#ff5555"; style.font-color: "#f8f8f2" }

kms -- alias
secret -> dek: "1. Generate DEK"
dek -> etcd: "2. Encrypt secret"
kms -> dek: "3. Encrypt the DEK" { style.stroke: "#ff79c6" }
```

> Envelope encryption: each secret gets its own DEK. The KMS key encrypts the DEK, not the secret directly.

---

### Step 13 — Create Security Groups

```hcl
resource "aws_security_group" "cluster" {
  name_prefix = "${var.cluster_name}-cluster-sg-"
  vpc_id      = var.vpc_id
  egress { from_port = 0; to_port = 0; protocol = "-1"; cidr_blocks = ["0.0.0.0/0"] }
  lifecycle { create_before_destroy = true }
}

resource "aws_security_group" "node" {
  name_prefix = "${var.cluster_name}-node-sg-"
  vpc_id      = var.vpc_id
  egress { from_port = 0; to_port = 0; protocol = "-1"; cidr_blocks = ["0.0.0.0/0"] }
  lifecycle { create_before_destroy = true }
}
```

### Step 14 — Create Security Group Rules

```hcl
resource "aws_security_group_rule" "node_to_cluster" {
  type = "ingress"; from_port = 443; to_port = 443; protocol = "tcp"
  security_group_id = aws_security_group.cluster.id
  source_security_group_id = aws_security_group.node.id
}

resource "aws_security_group_rule" "cluster_to_node" {
  type = "ingress"; from_port = 1025; to_port = 65535; protocol = "tcp"
  security_group_id = aws_security_group.node.id
  source_security_group_id = aws_security_group.cluster.id
}

resource "aws_security_group_rule" "node_to_node" {
  type = "ingress"; from_port = 0; to_port = 65535; protocol = "-1"
  security_group_id = aws_security_group.node.id
  self = true
}
```

```d2
direction: right
vars: {
  d2-config: {
    theme-id: 200
  }
}

cluster_sg: "🟠 Cluster SG\nControl Plane ENIs" {
  style.fill: "#ffb86c"
  style.font-color: "#282a36"
}

node_sg: "🟠 Node SG\nWorker Node ENIs" {
  style.fill: "#ffb86c"
  style.font-color: "#282a36"
}

node_sg -> cluster_sg: "Port 443\nkubelet → API" { style.stroke: "#50fa7b" }
cluster_sg -> node_sg: "Port 1025-65535\nkubectl exec/logs" { style.stroke: "#8be9fd" }
node_sg -> node_sg: "All ports\npod-to-pod" { style.stroke: "#f1fa8c" }
```

---

### Step 15 — Create EKS Cluster (~10 min)

```hcl
resource "aws_eks_cluster" "main" {
  name     = var.cluster_name
  version  = var.kubernetes_version
  role_arn = var.cluster_role_arn

  vpc_config {
    subnet_ids              = var.subnet_ids
    endpoint_public_access  = var.endpoint_public_access
    endpoint_private_access = var.endpoint_private_access
    public_access_cidrs     = var.public_access_cidrs
    security_group_ids      = [aws_security_group.cluster.id]
  }

  encryption_config {
    provider { key_arn = aws_kms_key.eks.arn }
    resources = ["secrets"]
  }

  enabled_cluster_log_types = var.enable_cluster_logging ? [
    "api", "audit", "authenticator", "controllerManager", "scheduler"
  ] : []

  depends_on = [aws_cloudwatch_log_group.eks]
}
```

```d2
direction: down
vars: {
  d2-config: {
    theme-id: 200
  }
}

admin: "👤 kubectl" { shape: person; style.fill: "#6272a4" }

aws_vpc: "AWS-Managed VPC" {
  style.fill: "#44475a"
  style.stroke: "#6272a4"

  cp: EKS Control Plane {
    style.fill: "#282a36"
    style.stroke: "#ffb86c"

    api: "🟠 API Server\nx3 replicas across 3 AZs" { style.fill: "#ffb86c"; style.font-color: "#282a36" }
    etcd: "etcd\n🔑 KMS encrypted" { shape: cylinder; style.fill: "#ff5555"; style.font-color: "#f8f8f2" }
    cm: "Controller Manager" { style.fill: "#ffb86c"; style.font-color: "#282a36" }
    sched: "Scheduler" { style.fill: "#ffb86c"; style.font-color: "#282a36" }
    api <-> etcd
    api <-> cm
    api <-> sched
  }
}

customer_vpc: "Customer VPC" {
  style.fill: "#44475a"
  style.stroke: "#bd93f9"
  eni: "🟣 EKS-managed ENIs\nin Private Subnets" { style.fill: "#bd93f9"; style.font-color: "#f8f8f2" }
}

admin -> aws_vpc.cp.api: "HTTPS :443" { style.stroke: "#50fa7b" }
aws_vpc.cp.api <-> customer_vpc.eni: "Private Link" { style.stroke: "#ff79c6" }
```

> The longest step (~10 min). AWS provisions 3 API servers across 3 AZs. You don't manage control plane nodes.

---

### Step 16 — Register OIDC Provider (IRSA)

```hcl
data "tls_certificate" "cluster" {
  count = var.enable_irsa ? 1 : 0
  url   = aws_eks_cluster.main.identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "cluster" {
  count           = var.enable_irsa ? 1 : 0
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.cluster[0].certificates[0].sha1_fingerprint]
  url             = aws_eks_cluster.main.identity[0].oidc[0].issuer
}
```

```d2
direction: down
vars: {
  d2-config: {
    theme-id: 200
  }
}

eks: EKS Cluster {
  style.fill: "#44475a"; style.stroke: "#ffb86c"
  api: "🟠 API Server" { style.fill: "#ffb86c"; style.font-color: "#282a36" }
  oidc_url: "OIDC Issuer URL" { style.fill: "#bd93f9"; style.font-color: "#f8f8f2" }
  api -> oidc_url
}

iam: IAM {
  style.fill: "#44475a"; style.stroke: "#ff5555"
  provider: "🟣 OIDC Provider\nRegistered with TLS thumbprint" { style.fill: "#bd93f9"; style.font-color: "#f8f8f2" }
}

pods: Per-Pod Permissions {
  style.fill: "#282a36"; style.stroke: "#6272a4"
  pa: "Pod A → S3 ReadOnly" { style.fill: "#8be9fd"; style.font-color: "#282a36" }
  pb: "Pod B → DynamoDB Write" { style.fill: "#8be9fd"; style.font-color: "#282a36" }
  pc: "Pod C → No extra perms" { style.fill: "#8be9fd"; style.font-color: "#282a36" }
}

eks.oidc_url -> iam.provider: "TLS thumbprint" { style.stroke: "#f1fa8c" }
iam.provider -> pods: "ServiceAccount → IAM Role" { style.stroke: "#50fa7b"; style.stroke-dash: 5 }
```

> Without IRSA: all pods share the Node Role. With IRSA: each pod gets least-privilege IAM.

---

### Step 17 — Install Add-ons

```hcl
resource "aws_eks_addon" "kube_proxy" {
  cluster_name = aws_eks_cluster.main.name
  addon_name   = "kube-proxy"
  resolve_conflicts_on_create = "OVERWRITE"
}

resource "aws_eks_addon" "vpc_cni" {
  cluster_name = aws_eks_cluster.main.name
  addon_name   = "vpc-cni"
  resolve_conflicts_on_create = "OVERWRITE"
}

resource "aws_eks_addon" "coredns" {
  cluster_name = aws_eks_cluster.main.name
  addon_name   = "coredns"
  resolve_conflicts_on_create = "OVERWRITE"
  depends_on   = [aws_eks_node_group.main]
}
```

```d2
direction: down
vars: {
  d2-config: {
    theme-id: 200
  }
}

eks: EKS Cluster {
  style.fill: "#44475a"; style.stroke: "#ffb86c"
  api: "🟠 API Server" { style.fill: "#ffb86c"; style.font-color: "#282a36" }
}

addons: "EKS Managed Add-ons" {
  style.fill: "#282a36"; style.stroke: "#6272a4"

  cni: "🟤 VPC CNI\nAssigns real VPC IPs to pods" { style.fill: "#795548"; style.font-color: "#f8f8f2" }
  kp: "🟤 kube-proxy\nService routing (iptables)" { style.fill: "#795548"; style.font-color: "#f8f8f2" }
  dns: "🟤 CoreDNS\nDNS: my-svc → ClusterIP\n⚠️ Needs nodes first" { style.fill: "#795548"; style.font-color: "#f8f8f2" }
}

eks.api -> addons.cni { style.stroke: "#8be9fd" }
eks.api -> addons.kp { style.stroke: "#8be9fd" }
eks.api -> addons.dns { style.stroke: "#8be9fd" }
```

---

### Step 18 — Create Launch Templates

```hcl
resource "aws_launch_template" "node" {
  for_each    = var.node_groups
  name_prefix = "${var.cluster_name}-${each.key}-"

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size = lookup(each.value, "disk_size", 20)
      volume_type = "gp3"; iops = 3000; throughput = 125
      delete_on_termination = true; encrypted = true
    }
  }
  metadata_options {
    http_endpoint = "enabled"; http_tokens = "required"
    http_put_response_hop_limit = 2; instance_metadata_tags = "enabled"
  }
  network_interfaces {
    associate_public_ip_address = false
    security_groups = [aws_security_group.node.id]
  }
  lifecycle { create_before_destroy = true }
}
```

```d2
direction: down
vars: {
  d2-config: {
    theme-id: 200
  }
}

lt: "📋 Launch Template" {
  style.fill: "#44475a"
  style.stroke: "#bd93f9"

  imds: "✅ IMDSv2 Enforced\nBlocks SSRF credential theft" { style.fill: "#ff5555"; style.font-color: "#f8f8f2" }
  ebs: "✅ EBS: gp3 Encrypted\n3000 IOPS, 125 MiB/s" { style.fill: "#6272a4"; style.font-color: "#f8f8f2" }
  noip: "✅ No Public IP\nPrivate subnets only" { style.fill: "#8be9fd"; style.font-color: "#282a36" }
  sg: "✅ Node Security Group" { style.fill: "#ffb86c"; style.font-color: "#282a36" }
}
```

> `http_tokens = "required"` enforces IMDSv2 — prevents SSRF attacks. `hop_limit = 2` for containers.

---

### Step 19 — Create Node Groups

```hcl
resource "aws_eks_node_group" "main" {
  for_each        = var.node_groups
  cluster_name    = aws_eks_cluster.main.name
  node_group_name = each.key
  node_role_arn   = var.node_role_arn
  subnet_ids      = var.subnet_ids
  version         = var.kubernetes_version

  scaling_config {
    desired_size = each.value.desired_size
    max_size     = each.value.max_size
    min_size     = each.value.min_size
  }

  instance_types = each.value.instance_types
  capacity_type  = lookup(each.value, "capacity_type", "ON_DEMAND")
  labels         = lookup(each.value, "labels", {})

  dynamic "taint" {
    for_each = coalesce(lookup(each.value, "taints", null), [])
    content { key = taint.value.key; value = taint.value.value; effect = taint.value.effect }
  }

  launch_template {
    id      = aws_launch_template.node[each.key].id
    version = aws_launch_template.node[each.key].latest_version
  }

  depends_on = [aws_eks_addon.vpc_cni, aws_eks_addon.kube_proxy]
  lifecycle { ignore_changes = [scaling_config[0].desired_size] }
}
```

```d2
direction: down
vars: {
  d2-config: {
    theme-id: 200
  }
}

customer_vpc: "Customer VPC" {
  style.fill: "#44475a"
  style.stroke: "#bd93f9"

  cp: EKS Control Plane {
    style.fill: "#282a36"; style.stroke: "#ffb86c"
    api: "🟠 API Server" { style.fill: "#ffb86c"; style.font-color: "#282a36" }
  }

  priv_a: "Private Subnet AZ-A" {
    style.fill: "#282a36"; style.stroke: "#6272a4"
    g1: "🔵 t3.medium\nON_DEMAND\nNode 1" { style.fill: "#8be9fd"; style.font-color: "#282a36" }
    g2: "🔵 t3.medium\nON_DEMAND\nNode 2" { style.fill: "#8be9fd"; style.font-color: "#282a36" }
  }

  priv_b: "Private Subnet AZ-B" {
    style.fill: "#282a36"; style.stroke: "#6272a4"
    s1: "🟡 t3.medium\nSPOT — 90% off\nTainted: spot=true" { style.fill: "#f1fa8c"; style.font-color: "#282a36" }
  }
}

customer_vpc.cp.api -> customer_vpc.priv_a.g1: "Port 443" { style.stroke: "#50fa7b" }
customer_vpc.cp.api -> customer_vpc.priv_a.g2: "Port 443" { style.stroke: "#50fa7b" }
customer_vpc.cp.api -> customer_vpc.priv_b.s1: "Port 443" { style.stroke: "#50fa7b" }
```

> `ignore_changes = [desired_size]` prevents Terraform from fighting the Cluster Autoscaler.
> Spot nodes are tainted — pods need a `toleration` to schedule there.

---

## Phase 4 — Secrets Manager Module

### Step 20 — Create Secrets KMS Key

```hcl
resource "aws_kms_key" "secrets" {
  count                   = var.create_db_secret || var.create_api_secret || var.create_app_config_secret ? 1 : 0
  description             = "KMS key for Secrets Manager encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true
}
```

> Separate from EKS KMS key — different blast radius, different access policies.

---

### Step 21 — Create Secrets

```hcl
resource "aws_secretsmanager_secret" "db_credentials" {
  count = var.create_db_secret ? 1 : 0
  name  = "${var.name_prefix}-db-credentials"
  kms_key_id = aws_kms_key.secrets[0].id
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "db_credentials" {
  count     = var.create_db_secret ? 1 : 0
  secret_id = aws_secretsmanager_secret.db_credentials[0].id
  secret_string = jsonencode({
    username = var.db_username; password = var.db_password
    engine = var.db_engine; host = var.db_host
    port = var.db_port; dbname = var.db_name
  })
}
```

```d2
direction: right
vars: {
  d2-config: {
    theme-id: 200
  }
}

sm: "AWS Secrets Manager" {
  style.fill: "#44475a"
  style.stroke: "#ffb86c"

  kms: "🔑 Dedicated KMS Key" { style.fill: "#ff5555"; style.font-color: "#f8f8f2" }
  db: "🟡 DB Credentials\nusername, password\nhost, port, engine" { style.fill: "#f1fa8c"; style.font-color: "#282a36" }
  api: "🟡 API Keys\napi_key, api_secret" { style.fill: "#f1fa8c"; style.font-color: "#282a36" }
  app: "🟡 App Config\nLOG_LEVEL, flags" { style.fill: "#f1fa8c"; style.font-color: "#282a36" }

  kms -> db: Encrypts { style.stroke: "#ff79c6"; style.stroke-dash: 3 }
  kms -> api: Encrypts { style.stroke: "#ff79c6"; style.stroke-dash: 3 }
  kms -> app: Encrypts { style.stroke: "#ff79c6"; style.stroke-dash: 3 }
}
```

---

### Step 22 — Create Read-Only IAM Policy

```hcl
resource "aws_iam_policy" "read_secrets" {
  count = var.create_db_secret || var.create_api_secret || var.create_app_config_secret ? 1 : 0
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow"
        Action = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
        Resource = concat(
          var.create_db_secret ? [aws_secretsmanager_secret.db_credentials[0].arn] : [],
          var.create_api_secret ? [aws_secretsmanager_secret.api_keys[0].arn] : [],
          var.create_app_config_secret ? [aws_secretsmanager_secret.app_config[0].arn] : []
        ) },
      { Effect = "Allow"
        Action = ["kms:Decrypt", "kms:DescribeKey"]
        Resource = [aws_kms_key.secrets[0].arn] }
    ]
  })
}
```

> Only specific secret ARNs (no wildcards). Also grants `kms:Decrypt` — required to read encrypted secrets.

---

## Phase 5 — Security Module

### Step 23 — Enable GuardDuty

```hcl
resource "aws_guardduty_detector" "main" {
  count  = var.enable_guardduty ? 1 : 0
  enable = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}

resource "aws_guardduty_detector_feature" "eks_audit_logs" {
  count = var.enable_guardduty ? 1 : 0
  detector_id = aws_guardduty_detector.main[0].id
  name = "EKS_AUDIT_LOGS"; status = "ENABLED"
}

resource "aws_guardduty_detector_feature" "eks_runtime_monitoring" {
  count = var.enable_guardduty ? 1 : 0
  detector_id = aws_guardduty_detector.main[0].id
  name = "EKS_RUNTIME_MONITORING"; status = "ENABLED"
}

resource "aws_guardduty_detector_feature" "malware_protection" {
  count = var.enable_guardduty ? 1 : 0
  detector_id = aws_guardduty_detector.main[0].id
  name = "EBS_MALWARE_PROTECTION"; status = "ENABLED"
}
```

```d2
direction: down
vars: {
  d2-config: {
    theme-id: 200
  }
}

sources: "Data Sources" {
  style.fill: "#282a36"; style.stroke: "#6272a4"
  vfl: "📊 VPC Flow Logs" { style.fill: "#6272a4"; style.font-color: "#f8f8f2" }
  k8s: "📊 EKS Audit Logs" { style.fill: "#6272a4"; style.font-color: "#f8f8f2" }
  ct: "📊 CloudTrail" { style.fill: "#6272a4"; style.font-color: "#f8f8f2" }
}

gd: "🟣 Amazon GuardDuty" {
  style.fill: "#44475a"; style.stroke: "#bd93f9"
  det: Detector { style.fill: "#bd93f9"; style.font-color: "#f8f8f2" }
  eks_a: "EKS Audit Analysis" { style.fill: "#bd93f9"; style.font-color: "#f8f8f2" }
  rt: "Runtime Monitoring" { style.fill: "#bd93f9"; style.font-color: "#f8f8f2" }
  mal: "Malware Protection" { style.fill: "#bd93f9"; style.font-color: "#f8f8f2" }
  det -> eks_a
  det -> rt
  det -> mal
}

alert: "⚠️ Security Alerts" { style.fill: "#ff5555"; style.font-color: "#f8f8f2" }

sources.vfl -> gd.det { style.stroke: "#8be9fd" }
sources.k8s -> gd.det { style.stroke: "#8be9fd" }
sources.ct -> gd.det { style.stroke: "#8be9fd" }
gd.det -> alert: Findings { style.stroke: "#ff5555" }
```

---

### Step 24 — Enable AWS Config Rules

```hcl
resource "aws_config_configuration_recorder" "main" {
  count    = var.enable_config ? 1 : 0
  role_arn = aws_iam_role.config[0].arn
  recording_group { all_supported = true }
}

resource "aws_config_config_rule" "eks_cluster_logging" {
  count = var.enable_config ? 1 : 0
  name  = "${var.cluster_name}-eks-logging-enabled"
  source { owner = "AWS"; source_identifier = "EKS_CLUSTER_LOGGING_ENABLED" }
  scope { compliance_resource_types = ["AWS::EKS::Cluster"] }
  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "eks_endpoint_no_public_access" {
  count = var.enable_config ? 1 : 0
  name  = "${var.cluster_name}-eks-no-public-endpoint"
  source { owner = "AWS"; source_identifier = "EKS_ENDPOINT_NO_PUBLIC_ACCESS" }
  scope { compliance_resource_types = ["AWS::EKS::Cluster"] }
  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "eks_secrets_encrypted" {
  count = var.enable_config ? 1 : 0
  name  = "${var.cluster_name}-eks-secrets-encrypted"
  source { owner = "AWS"; source_identifier = "EKS_SECRETS_ENCRYPTED" }
  scope { compliance_resource_types = ["AWS::EKS::Cluster"] }
  depends_on = [aws_config_configuration_recorder.main]
}
```

```d2
direction: down
vars: {
  d2-config: {
    theme-id: 200
  }
}

config: "🟣 AWS Config" {
  style.fill: "#44475a"; style.stroke: "#bd93f9"

  rec: "Config Recorder\nTracks all resource changes" { style.fill: "#6272a4"; style.font-color: "#f8f8f2" }
  r1: "EKS Logging Enabled?" { style.fill: "#bd93f9"; style.font-color: "#f8f8f2" }
  r2: "No Public Endpoint?" { style.fill: "#bd93f9"; style.font-color: "#f8f8f2" }
  r3: "Secrets Encrypted?" { style.fill: "#bd93f9"; style.font-color: "#f8f8f2" }
  rec -> r1
  rec -> r2
  rec -> r3
}

c1: "✅ COMPLIANT" { style.fill: "#50fa7b"; style.font-color: "#282a36" }
c2: "⚠️ NON_COMPLIANT\nin dev — OK" { style.fill: "#ffb86c"; style.font-color: "#282a36" }
c3: "✅ COMPLIANT" { style.fill: "#50fa7b"; style.font-color: "#282a36" }

config.r1 -> c1 { style.stroke: "#50fa7b" }
config.r2 -> c2 { style.stroke: "#ffb86c" }
config.r3 -> c3 { style.stroke: "#50fa7b" }
```

---

## ✅ Step 25 — All Resources Complete

```d2
direction: down
vars: {
  d2-config: {
    theme-id: 200
  }
}

admin: "👤 kubectl" { shape: person; style.fill: "#6272a4" }
internet: "🌐 Internet" { shape: cloud; style.fill: "#6272a4" }
clients: "📱 Clients" { shape: person; style.fill: "#6272a4" }

vpc: "Customer VPC: 10.0.0.0/16" {
  style.fill: "#44475a"
  style.stroke: "#bd93f9"

  igw: "🟠 IGW" { style.fill: "#ffb86c"; style.font-color: "#282a36" }

  public: "Public Subnets" {
    style.fill: "#282a36"; style.stroke: "#50fa7b"
    nat: "🟠 NAT GW + EIP" { style.fill: "#ffb86c"; style.font-color: "#282a36" }
    alb: "🟣 Load Balancer" { style.fill: "#bd93f9"; style.font-color: "#f8f8f2" }
  }

  cp: "EKS Control Plane" {
    style.fill: "#282a36"; style.stroke: "#ffb86c"
    api: "🟠 API Server" { style.fill: "#ffb86c"; style.font-color: "#282a36" }
    etcd: "etcd 🔑" { shape: cylinder; style.fill: "#ff5555"; style.font-color: "#f8f8f2" }
    api <-> etcd
  }

  private: "Private Subnets" {
    style.fill: "#282a36"; style.stroke: "#8be9fd"
    g1: "🔵 ON_DEMAND\nNode 1" { style.fill: "#8be9fd"; style.font-color: "#282a36" }
    g2: "🔵 ON_DEMAND\nNode 2" { style.fill: "#8be9fd"; style.font-color: "#282a36" }
    s1: "🟡 SPOT\nNode 1" { style.fill: "#f1fa8c"; style.font-color: "#282a36" }
  }

  nacl: "🛡️ NACLs" { style.fill: "#bd93f9"; style.font-color: "#f8f8f2" }
  sg: "🛡️ Security Groups" { style.fill: "#bd93f9"; style.font-color: "#f8f8f2" }
}

security: "Security Layer" {
  style.fill: "#282a36"; style.stroke: "#bd93f9"
  kms: "🔑 KMS Keys x2" { style.fill: "#ff5555"; style.font-color: "#f8f8f2" }
  gd: "🟣 GuardDuty" { style.fill: "#bd93f9"; style.font-color: "#f8f8f2" }
  cfg: "🟣 Config Rules" { style.fill: "#bd93f9"; style.font-color: "#f8f8f2" }
}

iam: "IAM" {
  style.fill: "#282a36"; style.stroke: "#ff5555"
  cr: "🔴 Cluster Role" { style.fill: "#ff5555"; style.font-color: "#f8f8f2" }
  nr: "🔴 Node Role" { style.fill: "#ff5555"; style.font-color: "#f8f8f2" }
  oidc: "🟣 OIDC/IRSA" { style.fill: "#bd93f9"; style.font-color: "#f8f8f2" }
}

sm: "Secrets Manager" {
  style.fill: "#282a36"; style.stroke: "#f1fa8c"
  secrets: "🟡 DB + API + App" { style.fill: "#f1fa8c"; style.font-color: "#282a36" }
}

admin -> vpc.cp.api: HTTPS { style.stroke: "#50fa7b" }
internet <-> vpc.igw { style.stroke: "#8be9fd" }
clients -> vpc.public.alb { style.stroke: "#8be9fd" }
vpc.public.alb -> vpc.private.g1 { style.stroke: "#8be9fd" }
vpc.cp.api -> vpc.private.g1 { style.stroke: "#50fa7b" }
vpc.cp.api -> vpc.private.g2 { style.stroke: "#50fa7b" }
vpc.private.g1 -> vpc.public.nat { style.stroke: "#f1fa8c" }
vpc.public.nat -> vpc.igw { style.stroke: "#f1fa8c" }
iam.cr -> vpc.cp.api { style.stroke: "#ff5555"; style.stroke-dash: 3 }
iam.nr -> vpc.private.g1 { style.stroke: "#ff5555"; style.stroke-dash: 3 }
security.kms -> vpc.cp.etcd { style.stroke: "#ff79c6"; style.stroke-dash: 3 }
sm.secrets -> vpc.private.g1 { style.stroke: "#f1fa8c"; style.stroke-dash: 3 }
```

---

## Build Summary

| Step | Resource | Module | Time |
|------|----------|--------|------|
| 1 | VPC | VPC | ~10s |
| 2 | Internet Gateway | VPC | ~10s |
| 3 | Public Subnets ×3 | VPC | ~15s |
| 4 | Private Subnets ×3 | VPC | ~15s |
| 5 | EIP + NAT Gateway | VPC | ~2m |
| 6 | Route Tables + Routes | VPC | ~10s |
| 7 | Public NACL (5 rules) | VPC | ~10s |
| 8 | Private NACL (3 rules) | VPC | ~10s |
| 9 | VPC Flow Logs | VPC | ~15s |
| 10 | Cluster IAM Role + 2 Policies | IAM | ~15s |
| 11 | Node IAM Role + 3 Policies | IAM | ~15s |
| 12 | KMS Key + Alias | EKS | ~10s |
| 13 | Cluster Security Group | EKS | ~10s |
| 14 | Node Security Group + 3 Rules | EKS | ~10s |
| 15 | **EKS Cluster** | EKS | **~10m** |
| 16 | OIDC Provider (IRSA) | EKS | ~10s |
| 17 | Add-ons (CNI + proxy + DNS) | EKS | ~2m |
| 18 | Launch Templates ×2 | EKS | ~10s |
| 19 | Node Groups (General + Spot) | EKS | ~3m |
| 20 | Secrets KMS Key | Secrets | ~10s |
| 21 | Secrets (DB + API + App) | Secrets | ~15s |
| 22 | Read-Only IAM Policy | Secrets | ~5s |
| 23 | GuardDuty + 3 Features | Security | ~30s |
| 24 | Config Recorder + 3 Rules | Security | ~15s |
| 25 | **🎉 Architecture Complete** | | **~20m** |
