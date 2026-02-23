<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>EKS Module — Build Steps</title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/dracula.min.css">
  <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box }
    body { background: #282a36; color: #f8f8f2; font-family: 'Segoe UI', system-ui, sans-serif; line-height: 1.7; padding: 2rem }
    .container { max-width: 1000px; margin: 0 auto }
    h1 { color: #bd93f9; font-size: 2.2rem; text-align: center; margin-bottom: .5rem; animation: glow 2s ease-in-out infinite alternate }
    @keyframes glow { from { text-shadow: 0 0 5px #bd93f9 } to { text-shadow: 0 0 20px #bd93f9, 0 0 40px #bd93f966 } }
    .subtitle { color: #6272a4; text-align: center; margin-bottom: 3rem; font-size: 1.1rem }
    .progress-bar { position: fixed; top: 0; left: 0; height: 3px; background: linear-gradient(90deg, #bd93f9, #ff79c6, #50fa7b); z-index: 999; transition: width .3s }
    .phase { margin: 3rem 0; padding: 1.5rem; border-left: 4px solid #ffb86c; background: #1e1f29; border-radius: 0 8px 8px 0; opacity: 0; transform: translateY(30px); transition: all .6s ease }
    .phase.visible { opacity: 1; transform: translateY(0) }
    .phase h2 { color: #ff79c6; font-size: 1.5rem; margin-bottom: 1rem }
    .step { margin: 2rem 0; padding: 1.5rem; background: #44475a; border-radius: 8px; border: 1px solid #6272a4; opacity: 0; transform: translateX(-20px); transition: all .5s ease }
    .step.visible { opacity: 1; transform: translateX(0) }
    .step:hover { border-color: #bd93f9; box-shadow: 0 0 15px #bd93f933 }
    .step h3 { color: #50fa7b; font-size: 1.2rem; margin-bottom: .8rem }
    .step h3 span { color: #6272a4; font-size: .9rem; font-weight: normal }
    .step .note { color: #f1fa8c; font-size: .9rem; margin-top: .8rem; padding: .5rem .8rem; background: #282a36; border-radius: 4px; border-left: 3px solid #f1fa8c }
    .step .explain { color: #f8f8f2; font-size: .9rem; margin-top: .8rem; padding: .8rem; background: #1e1f29; border-radius: 6px; border-left: 3px solid #8be9fd; line-height: 1.6 }
    .step .explain strong { color: #ff79c6 }
    .step .explain code { background: #44475a; padding: 1px 5px; border-radius: 3px; font-size: .85rem }
    pre { background: #282a36 !important; border-radius: 6px; padding: 1rem !important; margin: .8rem 0; overflow-x: auto; border: 1px solid #6272a4 }
    code { font-family: 'Fira Code', 'Consolas', monospace; font-size: .85rem }
    .d2-diagram { margin: 1rem 0; min-height: 100px; display: flex; justify-content: center; align-items: center; background: #282a36; border-radius: 8px; padding: 1rem; border: 1px solid #6272a4; transition: all .8s ease }
    .d2-diagram.loaded { animation: diagramFadeIn .8s ease }
    @keyframes diagramFadeIn { from { opacity: 0; transform: scale(.95) translateY(10px) } to { opacity: 1; transform: scale(1) translateY(0) } }
    .d2-diagram.loading { color: #6272a4; font-style: italic }
    .d2-diagram svg { max-width: 100%; height: auto; transition: transform .4s ease }
    .d2-diagram:hover svg { transform: scale(1.02) translateY(-3px); filter: drop-shadow(0 8px 20px #bd93f933) }
    @keyframes flowData { to { stroke-dashoffset: -16 } }
    .d2-diagram svg path[fill="none"][stroke]:not([stroke="none"]) { stroke-dasharray: 8 8 !important; animation: flowData 0.8s linear infinite }
    .d2-diagram svg g { transform-origin: center; transition: transform 0.2s ease, filter 0.2s ease }
    .d2-diagram svg g:hover { filter: drop-shadow(0 0 8px #bd93f988) }
    .d2-diagram:hover { border-color: #ff79c6; box-shadow: 0 0 20px #ff79c622 }
    .summary { margin: 3rem 0; opacity: 0; transform: translateY(30px); transition: all .6s ease }
    .summary.visible { opacity: 1; transform: translateY(0) }
    .summary table { width: 100%; border-collapse: collapse; font-size: .9rem }
    .summary th { background: #bd93f9; color: #282a36; padding: .6rem; text-align: left }
    .summary td { padding: .5rem .6rem; border-bottom: 1px solid #44475a; transition: background .3s }
    .summary tr:hover { background: #44475a }
    .highlight-row td { color: #ff79c6; font-weight: bold }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: .75rem; font-weight: bold }
    .badge-enc { background: #ff5555; color: #f8f8f2 }
    .badge-sg { background: #8be9fd; color: #282a36 }
    .badge-core { background: #ffb86c; color: #282a36 }
    .badge-addon { background: #50fa7b; color: #282a36 }
    .badge-node { background: #bd93f9; color: #282a36 }
    .var-table { width: 100%; border-collapse: collapse; font-size: .85rem; margin: 1rem 0 }
    .var-table th { background: #6272a4; color: #f8f8f2; padding: .5rem .6rem; text-align: left }
    .var-table td { padding: .4rem .6rem; border-bottom: 1px solid #44475a; color: #f8f8f2 }
    .var-table tr:hover { background: #44475a }
    .var-table code { background: #282a36; padding: 1px 5px; border-radius: 3px; font-size: .8rem; color: #50fa7b }
    .step-number { display: inline-flex; align-items: center; justify-content: center; width: 28px; height: 28px; border-radius: 50%; background: #bd93f9; color: #282a36; font-weight: bold; font-size: .8rem; margin-right: 8px }
  </style>
</head>

<body>
  <div class="container">
    <div class="progress-bar" id="progressBar"></div>
    <h1>⬡ EKS Module</h1>
    <p class="subtitle">The core Kubernetes cluster — control plane, security groups, OIDC, add-ons, and managed node groups</p>

    <div class="explain"
      style="margin-bottom: 3rem; background: #1e1f29; padding: 1.5rem; border-left: 4px solid #ffb86c; border-radius: 8px;">
      <h3 style="color: #ffb86c; margin-bottom: 0.5rem;">⬡ Module Overview</h3>
      This is the <strong>largest and most critical module</strong>. It provisions the EKS cluster, all security groups, OIDC provider for IRSA, managed add-ons, and auto-scaling node groups.
      <ul style="margin-left: 1.5rem; margin-top: 0.5rem; color: #f8f8f2;">
        <li><strong>KMS Key:</strong> Envelope encryption for Kubernetes secrets in etcd</li>
        <li><strong>Security Groups:</strong> Cluster SG + Node SG with minimal inter-component rules</li>
        <li><strong>EKS Cluster:</strong> Managed control plane with 3 redundant API servers (~10 min)</li>
        <li><strong>OIDC Provider:</strong> Enables IRSA — per-pod IAM via ServiceAccounts</li>
        <li><strong>Add-ons:</strong> VPC CNI, kube-proxy, CoreDNS (essential cluster services)</li>
        <li><strong>Launch Templates:</strong> IMDSv2 enforcement, gp3 encrypted EBS, no public IPs</li>
        <li><strong>Node Groups:</strong> ON_DEMAND + SPOT with autoscaler-safe lifecycle rules</li>
      </ul>
      <em style="color: #6272a4; display: block; margin-top: 0.5rem;">📂 Source: <code>modules/eks/main.tf</code> · <code>variables.tf</code> · <code>outputs.tf</code></em>
    </div>

    <div id="content"></div>

    <div class="summary">
      <h2 style="color:#bd93f9;margin-bottom:1rem">📥 Input Variables</h2>
      <table class="var-table">
        <thead><tr><th>Variable</th><th>Type</th><th>Default</th><th>Description</th></tr></thead>
        <tbody>
          <tr><td><code>cluster_name</code></td><td><code>string</code></td><td>—</td><td>Name of the EKS cluster</td></tr>
          <tr><td><code>kubernetes_version</code></td><td><code>string</code></td><td><code>"1.31"</code></td><td>Kubernetes version (minor only, e.g., "1.31")</td></tr>
          <tr><td><code>vpc_id</code></td><td><code>string</code></td><td>—</td><td>VPC ID from <code>module.vpc.vpc_id</code></td></tr>
          <tr><td><code>subnet_ids</code></td><td><code>list(string)</code></td><td>—</td><td>Private subnet IDs from <code>module.vpc.private_subnets</code></td></tr>
          <tr><td><code>cluster_role_arn</code></td><td><code>string</code></td><td>—</td><td>Cluster IAM role ARN from <code>module.iam</code></td></tr>
          <tr><td><code>node_role_arn</code></td><td><code>string</code></td><td>—</td><td>Node group IAM role ARN from <code>module.iam</code></td></tr>
          <tr><td><code>endpoint_public_access</code></td><td><code>bool</code></td><td><code>true</code></td><td>Enable public API server endpoint</td></tr>
          <tr><td><code>endpoint_private_access</code></td><td><code>bool</code></td><td><code>true</code></td><td>Enable private API server endpoint (always recommended)</td></tr>
          <tr><td><code>public_access_cidrs</code></td><td><code>list(string)</code></td><td><code>["0.0.0.0/0"]</code></td><td>CIDRs allowed for public API access ⚠️</td></tr>
          <tr><td><code>node_groups</code></td><td><code>map(object)</code></td><td>—</td><td>Map of node group configs (instance types, scaling, taints, etc.)</td></tr>
          <tr><td><code>enable_irsa</code></td><td><code>bool</code></td><td><code>true</code></td><td>Enable OIDC provider for IAM Roles for Service Accounts</td></tr>
          <tr><td><code>enable_cluster_logging</code></td><td><code>bool</code></td><td><code>false</code></td><td>Enable control plane logging to CloudWatch ($)</td></tr>
          <tr><td><code>enable_detailed_monitoring</code></td><td><code>bool</code></td><td><code>false</code></td><td>Enable 1-min EC2 monitoring ($)</td></tr>
          <tr><td><code>coredns_version</code></td><td><code>string</code></td><td><code>""</code></td><td>CoreDNS addon version (empty = latest)</td></tr>
          <tr><td><code>kube_proxy_version</code></td><td><code>string</code></td><td><code>""</code></td><td>kube-proxy addon version (empty = latest)</td></tr>
          <tr><td><code>vpc_cni_version</code></td><td><code>string</code></td><td><code>""</code></td><td>VPC CNI addon version (empty = latest)</td></tr>
          <tr><td><code>tags</code></td><td><code>map(string)</code></td><td><code>{}</code></td><td>Tags to apply to all resources</td></tr>
        </tbody>
      </table>
    </div>

    <div class="summary">
      <h2 style="color:#bd93f9;margin-bottom:1rem">📤 Outputs</h2>
      <table class="var-table">
        <thead><tr><th>Output</th><th>Description</th></tr></thead>
        <tbody>
          <tr><td><code>cluster_id</code></td><td>Unique ID of the EKS cluster</td></tr>
          <tr><td><code>cluster_name</code></td><td>Name of the EKS cluster</td></tr>
          <tr><td><code>cluster_arn</code></td><td>ARN of the EKS cluster</td></tr>
          <tr><td><code>cluster_endpoint</code></td><td>HTTPS endpoint URL for the Kubernetes API server</td></tr>
          <tr><td><code>cluster_version</code></td><td>Kubernetes version running on the cluster</td></tr>
          <tr><td><code>cluster_certificate_authority_data</code></td><td>Base64-encoded CA cert (sensitive — for kubectl trust)</td></tr>
          <tr><td><code>cluster_security_group_id</code></td><td>Security group ID for the control plane</td></tr>
          <tr><td><code>node_security_group_id</code></td><td>Security group ID for worker nodes</td></tr>
          <tr><td><code>kms_key_id</code> / <code>kms_key_arn</code></td><td>KMS key for cluster secrets encryption</td></tr>
          <tr><td><code>cluster_oidc_issuer_url</code></td><td>OIDC issuer URL for IRSA role creation</td></tr>
          <tr><td><code>oidc_provider_arn</code></td><td>ARN of the OIDC provider for IRSA</td></tr>
          <tr><td><code>cloudwatch_log_group_name</code></td><td>CloudWatch log group for control plane logs</td></tr>
          <tr><td><code>node_groups</code></td><td>Map of all created node group resources</td></tr>
        </tbody>
      </table>
    </div>

    <div class="summary">
      <h2 style="color:#bd93f9;margin-bottom:1rem">Build Summary</h2>
      <table>
        <thead><tr><th>Step</th><th>Resource</th><th>Category</th><th>Time</th></tr></thead>
        <tbody id="summary-table"></tbody>
      </table>
    </div>
  </div>

  <script>
    const STEPS = [
      {
        phase: "Encryption & Logging", steps: [
          {
            title: "Create KMS Key", cat: "enc", time: "~10s",
            hcl: `resource "aws_kms_key" "eks" {
  description             = "KMS key for EKS cluster \${var.cluster_name} encryption"
  deletion_window_in_days = 7                # 7-day grace period before permanent deletion
  enable_key_rotation     = true             # Auto-rotate annually
}

resource "aws_kms_alias" "eks" {
  name          = "alias/\${var.cluster_name}-eks"
  target_key_id = aws_kms_key.eks.key_id
}`,
            d2: `direction: right
vars: { d2-config: { theme-id: 200 } }
kms: "🔑 KMS Master Key\\n(Envelope Encryption)" { shape: hexagon; style.fill: "#ff5555"; style.font-color: "#f8f8f2" }
dek: "🎫 Data Encryption Key\\n(Generated by KMS)" { shape: document; style.fill: "#f1fa8c"; style.font-color: "#282a36" }
k8s: "Kubernetes Secrets" {
  style.fill: "#1e1f29"; style.stroke: "#bd93f9"
  etcd: "🗄️ etcd Database" { shape: cylinder; style.fill: "#44475a"; style.font-color: "#f8f8f2" }
}
kms -> dek: "1. Creates & Encrypts DEK" { style.stroke: "#f8f8f2"; style.stroke-dash: 5 }
dek -> k8s.etcd: "2. Encrypts Secrets Data" { style.stroke: "#f1fa8c"; style.stroke-dash: 5 }`,
            note: "Envelope encryption: KMS encrypts the DEK, not the secret directly.",
            explain: "Without KMS, Kubernetes secrets in etcd are just <strong>base64 encoded</strong> (easily decoded). With envelope encryption, each secret gets a unique <strong>Data Encryption Key (DEK)</strong>, and the KMS master key encrypts the DEK. Even with direct etcd access, secrets remain unreadable without the KMS key. <code>enable_key_rotation</code> rotates the key material annually."
          },
          {
            title: "Create CloudWatch Log Group (Optional)", cat: "enc", time: "~5s",
            hcl: `resource "aws_cloudwatch_log_group" "eks" {
  count             = var.enable_cluster_logging ? 1 : 0
  name              = "/aws/eks/\${var.cluster_name}/cluster"
  retention_in_days = 30     # Keep logs for 30 days (90+ for production/compliance)
  tags              = var.tags
}`,
            d2: `direction: right
vars: { d2-config: { theme-id: 200 } }
eks: "⬡ EKS Control Plane" { shape: hexagon; style.fill: "#ffb86c"; style.font-color: "#282a36" }
cw: "☁️ CloudWatch Logs" {
  style.fill: "#1e1f29"; style.stroke: "#6272a4"; style.stroke-width: 2
  t1: "api — API server requests" { shape: rectangle; style.fill: "#44475a"; style.font-color: "#f8f8f2" }
  t2: "audit — Who did what?" { shape: rectangle; style.fill: "#44475a"; style.font-color: "#f8f8f2" }
  t3: "authenticator — Auth decisions" { shape: rectangle; style.fill: "#44475a"; style.font-color: "#f8f8f2" }
  t4: "controllerManager — Loops" { shape: rectangle; style.fill: "#44475a"; style.font-color: "#f8f8f2" }
  t5: "scheduler — Pod placement" { shape: rectangle; style.fill: "#44475a"; style.font-color: "#f8f8f2" }
}
eks -> cw: "5 Log Types" { style.stroke: "#f8f8f2"; style.stroke-dash: 5 }`,
            note: "All 5 log types: api, audit, authenticator, controllerManager, scheduler.",
            explain: "Pre-creating the log group lets us control <strong>retention period</strong>, <strong>encryption</strong>, and <strong>access permissions</strong>. The 5 log types cover: API calls (what happened?), authentication (who tried?), scheduling (where did pods go?), and controller decisions (why did replicas change?)."
          },
        ]
      },
      {
        phase: "Security Groups (Network Access Control)", steps: [
          {
            title: "Create Cluster + Node Security Groups", cat: "sg", time: "~10s",
            hcl: `resource "aws_security_group" "cluster" {
  name_prefix = "\${var.cluster_name}-cluster-sg-"
  description = "Security group for EKS cluster control plane"
  vpc_id      = var.vpc_id
  lifecycle { create_before_destroy = true }
  tags        = var.tags
}

resource "aws_security_group" "node" {
  name_prefix = "\${var.cluster_name}-node-sg-"
  description = "Security group for EKS worker nodes"
  vpc_id      = var.vpc_id
  egress { from_port = 0; to_port = 0; protocol = "-1"; cidr_blocks = ["0.0.0.0/0"] }
  lifecycle { create_before_destroy = true }
  tags = merge(var.tags, { "kubernetes.io/cluster/\${var.cluster_name}" = "owned" })
}`,
            d2: `direction: right
vars: { d2-config: { theme-id: 200 } }
csg: "🛡️ Cluster SG\\n(Control Plane ENIs)" { shape: hexagon; style.fill: "#ffb86c"; style.font-color: "#282a36" }
nsg: "🛡️ Node SG\\n(EC2 Workers)" { shape: hexagon; style.fill: "#8be9fd"; style.font-color: "#282a36" }
csg <-> nsg: "Controlled Communication" { style.stroke: "#f8f8f2"; style.stroke-dash: 5 }`,
            note: "create_before_destroy prevents downtime during SG updates.",
            explain: "Two security groups define the network boundary: the <strong>Cluster SG</strong> protects the EKS-managed ENIs in your VPC, and the <strong>Node SG</strong> protects EC2 worker instances. The node SG has the <code>kubernetes.io/cluster</code> tag so the AWS LB Controller can discover it for target groups."
          },
          {
            title: "Create Security Group Rules", cat: "sg", time: "~5s",
            hcl: `# Nodes → Cluster: kubelet heartbeats, pod status, logs
resource "aws_security_group_rule" "node_to_cluster" {
  type = "ingress"; from_port = 443; to_port = 443; protocol = "tcp"
  security_group_id        = aws_security_group.cluster.id
  source_security_group_id = aws_security_group.node.id
}

# Cluster → Nodes: kubectl exec, logs, port-forward, webhooks
resource "aws_security_group_rule" "cluster_to_node" {
  type = "ingress"; from_port = 1025; to_port = 65535; protocol = "tcp"
  security_group_id        = aws_security_group.node.id
  source_security_group_id = aws_security_group.cluster.id
}

# Nodes → Nodes: Pod-to-pod, CoreDNS, metrics
resource "aws_security_group_rule" "node_to_node" {
  type = "ingress"; from_port = 0; to_port = 65535; protocol = "-1"
  security_group_id = aws_security_group.node.id; self = true
}`,
            d2: `direction: right
vars: { d2-config: { theme-id: 200 } }
csg: "🛡️ Cluster SG\\n(EKS Control Plane)" { shape: hexagon; style.fill: "#ffb86c"; style.font-color: "#282a36" }
nsg: "🛡️ Node SG\\n(EC2 Worker Nodes)" { shape: hexagon; style.fill: "#8be9fd"; style.font-color: "#282a36" }
nsg -> csg: "Ingress 443 (kubelet → API)" { style.stroke: "#50fa7b"; style.stroke-dash: 5 }
csg -> nsg: "Ingress 1025-65535 (API → kubelet)" { style.stroke: "#bd93f9"; style.stroke-dash: 5 }
nsg -> nsg: "Ingress All (Pod-to-Pod)" { style.stroke: "#f1fa8c"; style.stroke-dash: 5 }`,
            note: "self = true allows node-to-node traffic on all ports for pod networking.",
            explain: "Three rules define all cluster communication: <strong>Nodes → API (443)</strong> for kubelet heartbeats and pod status. <strong>API → Nodes (1025-65535)</strong> for kubectl exec, logs, and port-forward. <strong>Node → Node (all)</strong> for pod-to-pod networking, CoreDNS queries, and metrics scraping. <code>self = true</code> means the SG references itself."
          },
        ]
      },
      {
        phase: "EKS Cluster (The Core — ~10 Minutes)", steps: [
          {
            title: "Create EKS Cluster", cat: "core", time: "~10m", highlight: true,
            hcl: `resource "aws_eks_cluster" "main" {
  name     = var.cluster_name
  version  = var.kubernetes_version       # e.g., "1.31"
  role_arn = var.cluster_role_arn          # From IAM module

  vpc_config {
    subnet_ids              = var.subnet_ids              # Private subnets
    endpoint_public_access  = var.endpoint_public_access  # true (dev) / false (prod)
    endpoint_private_access = var.endpoint_private_access # Always true
    security_group_ids      = [aws_security_group.cluster.id]
  }

  encryption_config {
    provider { key_arn = aws_kms_key.eks.arn }
    resources = ["secrets"]                               # Encrypt K8s secrets in etcd
  }

  # Enable all 5 log types when logging is enabled
  enabled_cluster_log_types = var.enable_cluster_logging ? [
    "api", "audit", "authenticator", "controllerManager", "scheduler"
  ] : []

  depends_on = [aws_cloudwatch_log_group.eks]
}`,
            d2: `direction: left
vars: { d2-config: { theme-id: 200 } }
admin: "💻 kubectl" { shape: rectangle; style.fill: "#44475a"; style.stroke: "#bd93f9" }
aws: "AWS-Managed VPC" {
  style.fill: "#282a36"; style.stroke: "#50fa7b"; style.stroke-width: 2
  cp: "EKS Control Plane" {
    shape: hexagon
    style.fill: "#1e1f29"; style.stroke: "#ffb86c"; style.stroke-width: 2
    api: "API Server x3 AZs" { style.fill: "#ffb86c"; style.font-color: "#282a36" }
    etcd: "etcd (KMS encrypted)" { shape: cylinder; style.fill: "#ff5555"; style.font-color: "#f8f8f2" }
    api <-> etcd: Encrypted
  }
}
customer: "Customer VPC" {
  style.fill: "#282a36"; style.stroke: "#50fa7b"; style.stroke-width: 2
  eni: "EKS-managed ENI" { shape: oval; style.fill: "#bd93f9"; style.font-color: "#f8f8f2" }
  workers: "Worker Nodes" {
    style.fill: "#44475a"; style.stroke: "#6272a4"
    node1: "Node" { shape: rectangle; style.fill: "#ffb86c"; style.font-color: "#282a36" }
    node2: "Node" { shape: rectangle; style.fill: "#ffb86c"; style.font-color: "#282a36" }
  }
}
admin <-> aws.cp: "HTTPS :443" { style.stroke: "#f8f8f2"; style.stroke-dash: 5 }
aws.cp <-> customer.eni: "Private Link" { style.stroke: "#f8f8f2"; style.stroke-width: 2 }
customer.eni <-> customer.workers.node1: "kubelet" { style.stroke: "#f8f8f2"; style.stroke-dash: 5 }
customer.eni <-> customer.workers.node2 { style.stroke: "#f8f8f2"; style.stroke-dash: 5 }`,
            note: "The longest step (~10 min). AWS provisions 3 redundant API servers across 3 AZs.",
            explain: "AWS creates the control plane in their own VPC with <strong>3 redundant API servers</strong> across 3 AZs. It injects <strong>ENIs into your private subnets</strong> so nodes can reach the API privately. <code>encryption_config</code> encrypts all Kubernetes Secrets at rest. The 5 log types cover API calls, authentication, scheduling, and controller decisions."
          },
        ]
      },
      {
        phase: "OIDC Provider (IRSA — Per-Pod IAM)", steps: [
          {
            title: "Register OIDC Provider", cat: "core", time: "~10s",
            hcl: `data "tls_certificate" "cluster" {
  count = var.enable_irsa ? 1 : 0
  url   = aws_eks_cluster.main.identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "cluster" {
  count           = var.enable_irsa ? 1 : 0
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.cluster[0].certificates[0].sha1_fingerprint]
  url             = aws_eks_cluster.main.identity[0].oidc[0].issuer
}`,
            d2: `direction: down
vars: { d2-config: { theme-id: 200 } }
oidc: "🛡️ OIDC Identity Provider\\n(IAM Integration)" { shape: hexagon; style.fill: "#bd93f9"; style.font-color: "#f8f8f2" }
pods: "Kubernetes Namespace" {
  style.fill: "#1e1f29"; style.stroke: "#6272a4"; style.stroke-width: 2
  sa1: "🎫 ServiceAccount (S3 Read)" { shape: document; style.fill: "#44475a"; style.font-color: "#f8f8f2" }
  sa2: "🎫 ServiceAccount (Dynamo Write)" { shape: document; style.fill: "#44475a"; style.font-color: "#f8f8f2" }
  pod1: "📦 App Pod 1" { shape: package; style.fill: "#8be9fd"; style.font-color: "#282a36" }
  pod2: "📦 App Pod 2" { shape: package; style.fill: "#8be9fd"; style.font-color: "#282a36" }
}
oidc -> pods.sa1: "STS AssumeRoleWithWebIdentity" { style.stroke: "#f8f8f2"; style.stroke-dash: 5 }
oidc -> pods.sa2 { style.stroke: "#f8f8f2"; style.stroke-dash: 5 }
pods.sa1 -> pods.pod1: "Mounted Token" { style.stroke: "#bd93f9"; style.stroke-dash: 5 }
pods.sa2 -> pods.pod2: "Mounted Token" { style.stroke: "#bd93f9"; style.stroke-dash: 5 }`,
            note: "Without IRSA all pods share the Node Role. With IRSA each pod gets least-privilege IAM.",
            explain: "IRSA maps a Kubernetes <strong>ServiceAccount</strong> to an <strong>IAM Role</strong> via OIDC federation. When a pod uses that ServiceAccount, AWS STS exchanges the K8s token for temporary IAM credentials. This eliminates the need for access keys in pods. The TLS thumbprint verifies the OIDC issuer identity."
          },
        ]
      },
      {
        phase: "EKS Add-ons (Essential Cluster Services)", steps: [
          {
            title: "Install VPC CNI, kube-proxy, CoreDNS", cat: "addon", time: "~2m",
            hcl: `resource "aws_eks_addon" "vpc_cni" {
  cluster_name = aws_eks_cluster.main.name
  addon_name   = "vpc-cni"
  addon_version = var.vpc_cni_version != "" ? var.vpc_cni_version : null
}

resource "aws_eks_addon" "kube_proxy" {
  cluster_name = aws_eks_cluster.main.name
  addon_name   = "kube-proxy"
  addon_version = var.kube_proxy_version != "" ? var.kube_proxy_version : null
}

resource "aws_eks_addon" "coredns" {
  cluster_name = aws_eks_cluster.main.name
  addon_name   = "coredns"
  addon_version = var.coredns_version != "" ? var.coredns_version : null
  depends_on    = [aws_eks_node_group.main]   # Needs nodes to schedule pods
}`,
            d2: `direction: down
vars: { d2-config: { theme-id: 200 } }
worker: "🖥️ EC2 Worker Node" {
  style.fill: "#1e1f29"; style.stroke: "#6272a4"; style.stroke-width: 2
  cni: "🌐 VPC CNI (DaemonSet)\\nAssigns real VPC IPs to pods" { shape: hexagon; style.fill: "#ffb86c"; style.font-color: "#282a36" }
  kp: "🔀 kube-proxy (DaemonSet)\\nManages iptables/IPVS routing" { shape: hexagon; style.fill: "#8be9fd"; style.font-color: "#282a36" }
  dns: "🔍 CoreDNS (Deployment)\\nCluster DNS resolution" { shape: hexagon; style.fill: "#50fa7b"; style.font-color: "#282a36" }
}
vpc: "🖧 Customer VPC" { shape: package; style.fill: "#44475a"; style.font-color: "#f8f8f2" }
worker.cni -> vpc: "Assigns real IPs to Pods" { style.stroke: "#ffb86c"; style.stroke-dash: 5 }`,
            note: "CoreDNS depends_on node groups — it needs nodes to schedule its pods.",
            explain: "<strong>VPC CNI</strong> runs as a DaemonSet — assigns real VPC IPs to pods (no overlay network). <strong>kube-proxy</strong> manages iptables/IPVS rules for Service routing. <strong>CoreDNS</strong> resolves DNS names (<code>my-svc.namespace.svc.cluster.local</code> → ClusterIP). CoreDNS is a Deployment and needs at least one running node — hence the <code>depends_on</code>."
          },
        ]
      },
      {
        phase: "Node Groups (Worker Compute)", steps: [
          {
            title: "Create Launch Templates", cat: "node", time: "~10s",
            hcl: `resource "aws_launch_template" "node" {
  for_each = var.node_groups

  metadata_options {
    http_tokens                 = "required"  # IMDSv2 enforced (blocks SSRF attacks)
    http_put_response_hop_limit = 2           # 2 hops for containers
  }

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_type = "gp3"           # 3000 baseline IOPS
      encrypted   = true            # Encryption at rest
      iops        = 3000
    }
  }

  network_interfaces {
    associate_public_ip_address = false   # Private subnets only
  }

  monitoring { enabled = var.enable_detailed_monitoring }
}`,
            d2: `direction: right
vars: { d2-config: { theme-id: 200 } }
lt: "📜 EC2 Launch Template" {
  style.fill: "#1e1f29"; style.stroke: "#bd93f9"; style.stroke-width: 2
  imds: "🔐 IMDSv2 Enforced\\n(Blocks SSRF)" { shape: rectangle; style.fill: "#ff5555"; style.font-color: "#f8f8f2" }
  ebs: "💾 gp3 Volumes\\n(Encrypted, 3000 IOPS)" { shape: cylinder; style.fill: "#ffb86c"; style.font-color: "#282a36" }
  net: "🌐 No Public IPs" { shape: rectangle; style.fill: "#8be9fd"; style.font-color: "#282a36" }
}
asg: "⚙️ EKS Node Group (ASG)" { shape: hexagon; style.fill: "#50fa7b"; style.font-color: "#282a36" }
lt -> asg: "Provisions instances" { style.stroke: "#bd93f9"; style.stroke-dash: 5 }`,
            note: "http_tokens = required prevents SSRF credential theft (Capital One breach used IMDSv1).",
            explain: "Launch templates define the <strong>security baseline</strong> for all nodes. <code>http_tokens = required</code> enforces IMDSv2, preventing SSRF attacks that steal credentials from the metadata endpoint. <code>hop_limit = 2</code> is needed because containers are 2 network hops from the metadata service. <code>gp3</code> volumes provide 3000 baseline IOPS with encryption at rest."
          },
          {
            title: "Create Node Groups", cat: "node", time: "~3m",
            hcl: `resource "aws_eks_node_group" "main" {
  for_each     = var.node_groups
  cluster_name = aws_eks_cluster.main.name
  node_role_arn = var.node_role_arn
  subnet_ids    = var.subnet_ids

  scaling_config {
    desired_size = each.value.desired_size
    max_size     = each.value.max_size
    min_size     = each.value.min_size
  }

  capacity_type = lookup(each.value, "capacity_type", "ON_DEMAND")

  launch_template {
    id      = aws_launch_template.node[each.key].id
    version = aws_launch_template.node[each.key].latest_version
  }

  depends_on = [aws_eks_addon.vpc_cni, aws_eks_addon.kube_proxy]

  lifecycle { ignore_changes = [scaling_config[0].desired_size] }
}`,
            d2: `direction: down
vars: { d2-config: { theme-id: 200 } }
api: "⬡ EKS Control Plane" { shape: hexagon; style.fill: "#ffb86c"; style.font-color: "#282a36" }
vpc: "🖧 Customer VPC" {
  style.fill: "#1e1f29"; style.stroke: "#bd93f9"; style.stroke-width: 2
  priv: "🔒 Private Subnets" {
    style.fill: "#282a36"; style.stroke: "#8be9fd"
    g1: "📦 ON_DEMAND Node Group" {
      style.fill: "#44475a"; style.stroke: "#50fa7b"
      n1: "EC2 t3.medium" { shape: rectangle; style.fill: "#50fa7b"; style.font-color: "#282a36" }
      n2: "EC2 t3.medium" { shape: rectangle; style.fill: "#50fa7b"; style.font-color: "#282a36" }
    }
    g2: "📉 SPOT Node Group" {
      style.fill: "#44475a"; style.stroke: "#f1fa8c"
      s1: "EC2 t3.medium (Tainted)" { shape: rectangle; style.fill: "#f1fa8c"; style.font-color: "#282a36" }
    }
  }
}
api -> vpc.priv.g1.n1: "Kubelet Join" { style.stroke: "#f8f8f2"; style.stroke-dash: 5 }
api -> vpc.priv.g1.n2 { style.stroke: "#f8f8f2"; style.stroke-dash: 5 }
api -> vpc.priv.g2.s1 { style.stroke: "#f8f8f2"; style.stroke-dash: 5 }`,
            note: "ignore_changes = [desired_size] prevents Terraform from fighting the Cluster Autoscaler.",
            explain: "Two node groups serve different purposes: <strong>General (ON_DEMAND)</strong> for reliable workloads, and <strong>Spot (up to 90% off)</strong> for fault-tolerant batch jobs. Spot nodes have a <strong>taint</strong> preventing pods from scheduling unless they explicitly tolerate it. <code>lifecycle { ignore_changes }</code> prevents Terraform from overriding autoscaler decisions."
          },
        ]
      },
    ];

    const BADGES = { enc: 'badge-enc', sg: 'badge-sg', core: 'badge-core', addon: 'badge-addon', node: 'badge-node' };
    const BADGE_LABEL = { enc: 'Encryption', sg: 'Security', core: 'Core', addon: 'Add-on', node: 'Compute' };

    let html = '', stepNum = 0, summaryRows = '';
    STEPS.forEach(phase => {
      html += `<div class="phase"><h2>${phase.phase}</h2>`;
      phase.steps.forEach(s => {
        stepNum++;
        html += `<div class="step"><h3><span class="step-number">${stepNum}</span>${s.title} <span><span class="badge ${BADGES[s.cat]}">${BADGE_LABEL[s.cat]}</span> ${s.time}</span></h3>`;
        html += `<pre><code class="language-hcl">${escHtml(s.hcl)}</code></pre>`;
        if (s.d2) html += `<div class="d2-diagram loading" data-d2="${btoa(unescape(encodeURIComponent(s.d2)))}">Loading diagram...</div>`;
        if (s.explain) html += `<div class="explain">${s.explain}</div>`;
        if (s.note) html += `<div class="note">💡 ${s.note}</div>`;
        html += `</div>`;
        summaryRows += `<tr class="${s.highlight?'highlight-row':''}"><td>${stepNum}</td><td>${s.title}</td><td><span class="badge ${BADGES[s.cat]}">${BADGE_LABEL[s.cat]}</span></td><td>${s.time}</td></tr>`;
      });
      html += `</div>`;
    });
    summaryRows += `<tr class="highlight-row"><td></td><td><strong>Total: ~30 resources</strong></td><td></td><td><strong>~17 min</strong></td></tr>`;

    document.getElementById('content').innerHTML = html;
    document.getElementById('summary-table').innerHTML = summaryRows;

    function escHtml(s) { return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }
    hljs.highlightAll();

    document.querySelectorAll('.d2-diagram[data-d2]').forEach(el => {
      const src = decodeURIComponent(escape(atob(el.dataset.d2)));
      fetch('https://kroki.io/d2/svg', { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: src })
        .then(r => { if (!r.ok) throw new Error(r.status); return r.text() })
        .then(svg => { el.innerHTML = svg; el.classList.remove('loading'); el.classList.add('loaded') })
        .catch(e => { el.innerHTML = `<span style="color:#ff5555">Diagram failed: ${e.message}</span>`; el.classList.remove('loading') });
    });

    const observer = new IntersectionObserver((entries) => {
      entries.forEach((entry, i) => {
        if (entry.isIntersecting) { setTimeout(() => entry.target.classList.add('visible'), i * 100); observer.unobserve(entry.target); }
      });
    }, { threshold: 0.1 });
    document.querySelectorAll('.phase, .step, .summary').forEach(el => observer.observe(el));

    window.addEventListener('scroll', () => {
      const h = document.documentElement;
      document.getElementById('progressBar').style.width = (h.scrollTop / (h.scrollHeight - h.clientHeight)) * 100 + '%';
    });
  </script>
</body>

</html>
