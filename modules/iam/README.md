<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>IAM Module — Build Steps</title>
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
    .phase { margin: 3rem 0; padding: 1.5rem; border-left: 4px solid #ff5555; background: #1e1f29; border-radius: 0 8px 8px 0; opacity: 0; transform: translateY(30px); transition: all .6s ease }
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
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: .75rem; font-weight: bold }
    .badge-role { background: #ff5555; color: #f8f8f2 }
    .badge-policy { background: #ffb86c; color: #282a36 }
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
    <h1>🔐 IAM Module</h1>
    <p class="subtitle">Identity and Access Management — least-privilege roles for EKS control plane and worker nodes</p>

    <div class="explain"
      style="margin-bottom: 3rem; background: #1e1f29; padding: 1.5rem; border-left: 4px solid #ff5555; border-radius: 8px;">
      <h3 style="color: #ff5555; margin-bottom: 0.5rem;">🔐 Module Overview</h3>
      This module creates <strong>two IAM roles</strong> with <strong>least-privilege permissions</strong> for EKS:
      <ul style="margin-left: 1.5rem; margin-top: 0.5rem; color: #f8f8f2;">
        <li><strong>Cluster Role</strong> — Assumed by the EKS service (<code>eks.amazonaws.com</code>) to manage the Kubernetes control plane</li>
        <li><strong>Node Group Role</strong> — Assumed by EC2 instances (<code>ec2.amazonaws.com</code>) serving as worker nodes</li>
      </ul>
      <div style="margin-top: 0.8rem; padding: 0.5rem 0.8rem; background: #282a36; border-radius: 4px; border-left: 3px solid #f1fa8c; color: #f1fa8c; font-size: 0.9rem;">
        💡 <strong>IAM Role Anatomy:</strong> Each role has a <em>trust policy</em> (WHO can wear the badge) and <em>permissions policies</em> (WHAT the badge unlocks).
      </div>
      <em style="color: #6272a4; display: block; margin-top: 0.5rem;">📂 Source: <code>modules/iam/main.tf</code> · <code>variables.tf</code> · <code>outputs.tf</code></em>
    </div>

    <div id="content"></div>

    <div class="summary">
      <h2 style="color:#bd93f9;margin-bottom:1rem">📥 Input Variables</h2>
      <table class="var-table">
        <thead><tr><th>Variable</th><th>Type</th><th>Default</th><th>Description</th></tr></thead>
        <tbody>
          <tr><td><code>cluster_name</code></td><td><code>string</code></td><td>—</td><td>Name of the EKS cluster (used as prefix for IAM role names)</td></tr>
          <tr><td><code>tags</code></td><td><code>map(string)</code></td><td><code>{}</code></td><td>Tags to apply to all IAM resources</td></tr>
        </tbody>
      </table>
    </div>

    <div class="summary">
      <h2 style="color:#bd93f9;margin-bottom:1rem">📤 Outputs</h2>
      <table class="var-table">
        <thead><tr><th>Output</th><th>Description</th></tr></thead>
        <tbody>
          <tr><td><code>cluster_role_arn</code></td><td>ARN of the EKS cluster IAM role (passed to <code>aws_eks_cluster.role_arn</code>)</td></tr>
          <tr><td><code>cluster_role_name</code></td><td>Name of the cluster role (for additional policy attachments)</td></tr>
          <tr><td><code>node_group_role_arn</code></td><td>ARN of the node group IAM role (passed to <code>aws_eks_node_group.node_role_arn</code>)</td></tr>
          <tr><td><code>node_group_role_name</code></td><td>Name of the node group role (for additional policy attachments)</td></tr>
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
        phase: "EKS Cluster Role (Control Plane Identity)", steps: [
          {
            title: "Create Cluster IAM Role", cat: "role", time: "~5s",
            hcl: `resource "aws_iam_role" "cluster" {
  name_prefix = "\${var.cluster_name}-cluster-"  # e.g., "eks-secure-cluster-cluster-abc123"

  # TRUST POLICY: Only eks.amazonaws.com can assume this role
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = {
        Service = "eks.amazonaws.com"  # NOT your user, NOT Lambda — ONLY EKS
      }
    }]
  })

  tags = var.tags
}`,
            d2: `direction: down
vars: { d2-config: { theme-id: 200 } }
eks: "⬡ EKS Service\\n(eks.amazonaws.com)" { shape: hexagon; style.fill: "#ffb86c"; style.font-color: "#282a36" }
role: "🔐 Cluster IAM Role" {
  style.fill: "#1e1f29"; style.stroke: "#ff5555"; style.stroke-width: 2
  trust: "Trust Policy:\\neks.amazonaws.com → ALLOW" { shape: document; style.fill: "#44475a"; style.font-color: "#f8f8f2" }
}
eks -> role: "sts:AssumeRole" { style.stroke: "#f8f8f2"; style.stroke-dash: 5 }`,
            note: "Only eks.amazonaws.com can assume this role — not humans, not Lambda, not EC2.",
            explain: "The <strong>trust policy</strong> is the gatekeeper. It says: \"Only the EKS service can wear this badge.\" When EKS creates your cluster, it calls <code>sts:AssumeRole</code> to get temporary credentials with the permissions defined by the attached policies. <code>name_prefix</code> (vs <code>name</code>) adds a random suffix to prevent conflicts across multiple clusters."
          },
          {
            title: "Attach AmazonEKSClusterPolicy", cat: "policy", time: "~5s",
            hcl: `resource "aws_iam_role_policy_attachment" "cluster_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.cluster.name
}`,
            d2: `direction: right
vars: { d2-config: { theme-id: 200 } }
role: "🔐 Cluster Role" { shape: hexagon; style.fill: "#ff5555"; style.font-color: "#f8f8f2" }
policy: "📋 AmazonEKSClusterPolicy" {
  style.fill: "#1e1f29"; style.stroke: "#ffb86c"; style.stroke-width: 2
  p1: "Manage K8s API server" { shape: rectangle; style.fill: "#ffb86c"; style.font-color: "#282a36" }
  p2: "Create/manage ENIs" { shape: rectangle; style.fill: "#ffb86c"; style.font-color: "#282a36" }
  p3: "Publish metrics & logs" { shape: rectangle; style.fill: "#ffb86c"; style.font-color: "#282a36" }
}
role -> policy: "Attached" { style.stroke: "#f1fa8c"; style.stroke-dash: 5 }`,
            note: "Without this policy: \"InvalidParameterException: The role does not have the AmazonEKSClusterPolicy attached\"",
            explain: "This AWS-managed policy grants EKS permissions to <strong>manage the API server</strong>, <strong>create ENIs</strong> for networking, and <strong>publish metrics</strong>. AWS maintains these policies and updates them when new features are released — more secure than writing custom policies."
          },
          {
            title: "Attach AmazonEKSVPCResourceController", cat: "policy", time: "~5s",
            hcl: `resource "aws_iam_role_policy_attachment" "cluster_vpc_resource_controller" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
  role       = aws_iam_role.cluster.name
}`,
            d2: `direction: right
vars: { d2-config: { theme-id: 200 } }
role: "🔐 Cluster Role" { shape: hexagon; style.fill: "#ff5555"; style.font-color: "#f8f8f2" }
policy: "📋 VPCResourceController" {
  style.fill: "#1e1f29"; style.stroke: "#ffb86c"; style.stroke-width: 2
  p1: "Manage pod ENIs" { shape: rectangle; style.fill: "#ffb86c"; style.font-color: "#282a36" }
  p2: "Security groups for pods" { shape: rectangle; style.fill: "#ffb86c"; style.font-color: "#282a36" }
  p3: "Trunk ENI support" { shape: rectangle; style.fill: "#ffb86c"; style.font-color: "#282a36" }
}
role -> policy: "Attached" { style.stroke: "#f1fa8c"; style.stroke-dash: 5 }`,
            note: "Required for VPC CNI pod networking — each pod gets its own ENI/IP.",
            explain: "This policy allows EKS to manage VPC resources like <strong>Elastic Network Interfaces</strong>. The VPC CNI plugin assigns real VPC IPs to pods (no overlay network), which requires creating and managing ENIs. Also needed for <strong>security groups for pods</strong> when using trunk ENIs."
          },
        ]
      },
      {
        phase: "Node Group Role (Worker Node Identity)", steps: [
          {
            title: "Create Node Group IAM Role", cat: "role", time: "~5s",
            hcl: `resource "aws_iam_role" "node_group" {
  name_prefix = "\${var.cluster_name}-node-"  # e.g., "eks-secure-cluster-node-def456"

  # TRUST POLICY: Only EC2 instances can assume this role
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"  # EC2 instances (worker nodes)
      }
    }]
  })

  tags = var.tags
}`,
            d2: `direction: down
vars: { d2-config: { theme-id: 200 } }
ec2: "🖥️ EC2 Instances\\n(ec2.amazonaws.com)" { shape: hexagon; style.fill: "#8be9fd"; style.font-color: "#282a36" }
role: "🔐 Node Group IAM Role" {
  style.fill: "#1e1f29"; style.stroke: "#ff5555"; style.stroke-width: 2
  trust: "Trust Policy:\\nec2.amazonaws.com → ALLOW" { shape: document; style.fill: "#44475a"; style.font-color: "#f8f8f2" }
}
ec2 -> role: "sts:AssumeRole\\n(via Instance Profile)" { style.stroke: "#f8f8f2"; style.stroke-dash: 5 }`,
            note: "Key difference — Cluster role trusts eks.amazonaws.com, Node role trusts ec2.amazonaws.com.",
            explain: "Worker nodes are EC2 instances, so they assume the role via an <strong>instance profile</strong>. When the EC2 instance boots as a Kubernetes node, it uses this role to register with the cluster, pull images, and assign pod IPs. The trust boundary is different from the cluster role — <code>ec2.amazonaws.com</code> instead of <code>eks.amazonaws.com</code>."
          },
          {
            title: "Attach AmazonEKSWorkerNodePolicy", cat: "policy", time: "~5s",
            hcl: `resource "aws_iam_role_policy_attachment" "node_worker_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.node_group.name
}`,
            d2: `direction: right
vars: { d2-config: { theme-id: 200 } }
role: "🔐 Node Role" { shape: hexagon; style.fill: "#ff5555"; style.font-color: "#f8f8f2" }
policy: "📋 EKSWorkerNodePolicy" {
  style.fill: "#1e1f29"; style.stroke: "#ffb86c"; style.stroke-width: 2
  p1: "Register with EKS API" { shape: rectangle; style.fill: "#ffb86c"; style.font-color: "#282a36" }
  p2: "Get cluster config" { shape: rectangle; style.fill: "#ffb86c"; style.font-color: "#282a36" }
  p3: "Report node health" { shape: rectangle; style.fill: "#ffb86c"; style.font-color: "#282a36" }
}
role -> policy: "Attached" { style.stroke: "#f1fa8c"; style.stroke-dash: 5 }`,
            note: "Without this → nodes stuck in NotReady state. Kubelet can't register with the API server.",
            explain: "The kubelet (K8s agent on each node) needs this policy to <strong>communicate with the EKS API server</strong>, <strong>get cluster configuration</strong>, <strong>report node status</strong>, and <strong>describe EC2 instances</strong> for node labels. Without it, nodes appear as <code>NotReady</code>."
          },
          {
            title: "Attach AmazonEKS_CNI_Policy", cat: "policy", time: "~5s",
            hcl: `resource "aws_iam_role_policy_attachment" "node_cni_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.node_group.name
}`,
            d2: `direction: right
vars: { d2-config: { theme-id: 200 } }
role: "🔐 Node Role" { shape: hexagon; style.fill: "#ff5555"; style.font-color: "#f8f8f2" }
policy: "📋 EKS_CNI_Policy" {
  style.fill: "#1e1f29"; style.stroke: "#ffb86c"; style.stroke-width: 2
  p1: "CreateNetworkInterface" { shape: rectangle; style.fill: "#ffb86c"; style.font-color: "#282a36" }
  p2: "AssignPrivateIpAddresses" { shape: rectangle; style.fill: "#ffb86c"; style.font-color: "#282a36" }
  p3: "ModifyNetworkInterface" { shape: rectangle; style.fill: "#ffb86c"; style.font-color: "#282a36" }
}
role -> policy: "Attached" { style.stroke: "#f1fa8c"; style.stroke-dash: 5 }`,
            note: "Production tip: Move this to IRSA for the aws-node ServiceAccount for tighter security.",
            explain: "The VPC CNI plugin runs as a DaemonSet and needs to <strong>create ENIs</strong>, <strong>assign VPC IPs to pods</strong>, and <strong>manage network interfaces</strong>. In production, consider moving this to <strong>IRSA</strong> (IAM Role for Service Accounts) so only the CNI pods get this permission, not all processes on the node."
          },
          {
            title: "Attach EC2ContainerRegistryReadOnly", cat: "policy", time: "~5s",
            hcl: `resource "aws_iam_role_policy_attachment" "node_registry_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.node_group.name
}`,
            d2: `direction: right
vars: { d2-config: { theme-id: 200 } }
node: "🖥️ Worker Node" { shape: hexagon; style.fill: "#8be9fd"; style.font-color: "#282a36" }
ecr: "📦 Amazon ECR" {
  style.fill: "#1e1f29"; style.stroke: "#ffb86c"; style.stroke-width: 2
  pull: "✅ Pull Images (Read)" { shape: rectangle; style.fill: "#50fa7b"; style.font-color: "#282a36" }
  push: "❌ Push Images (Denied)" { shape: rectangle; style.fill: "#ff5555"; style.font-color: "#f8f8f2" }
}
node -> ecr.pull: "docker pull" { style.stroke: "#50fa7b"; style.stroke-dash: 5 }`,
            note: "READ-ONLY — nodes should never push images. Image pushing belongs in CI/CD pipelines.",
            explain: "Allows nodes to <strong>pull (but NOT push)</strong> container images from Amazon ECR. Without this, pods fail with: <code>\"Failed to pull image: no basic auth credentials\"</code>. Read-only is intentional — image pushing should happen in CI/CD pipelines with different credentials."
          },
        ]
      },
    ];

    const BADGES = { role: 'badge-role', policy: 'badge-policy' };
    const BADGE_LABEL = { role: 'IAM Role', policy: 'Policy' };

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
        summaryRows += `<tr><td>${stepNum}</td><td>${s.title}</td><td><span class="badge ${BADGES[s.cat]}">${BADGE_LABEL[s.cat]}</span></td><td>${s.time}</td></tr>`;
      });
      html += `</div>`;
    });
    summaryRows += `<tr style="color:#ff79c6;font-weight:bold"><td></td><td><strong>Total: 7 resources</strong></td><td></td><td><strong>~35s</strong></td></tr>`;

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
