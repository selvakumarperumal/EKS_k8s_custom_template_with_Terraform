<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VPC Module — Build Steps</title>
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
    .phase { margin: 3rem 0; padding: 1.5rem; border-left: 4px solid #50fa7b; background: #1e1f29; border-radius: 0 8px 8px 0; opacity: 0; transform: translateY(30px); transition: all .6s ease }
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
    .badge-net { background: #50fa7b; color: #282a36 }
    .badge-sec { background: #bd93f9; color: #282a36 }
    .badge-rt { background: #ffb86c; color: #282a36 }
    .badge-mon { background: #8be9fd; color: #282a36 }
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
    <h1>🌐 VPC Module</h1>
    <p class="subtitle">Networking foundation for the EKS cluster — subnets, routing, NAT, NACLs, and flow logs</p>

    <div class="explain"
      style="margin-bottom: 3rem; background: #1e1f29; padding: 1.5rem; border-left: 4px solid #50fa7b; border-radius: 8px;">
      <h3 style="color: #50fa7b; margin-bottom: 0.5rem;">🏗️ Module Overview</h3>
      This module provisions the <strong>entire networking foundation</strong> for the EKS cluster.
      It creates a secure, production-grade VPC with public and private subnets across <strong>3 Availability Zones</strong>.
      <ul style="margin-left: 1.5rem; margin-top: 0.5rem; color: #f8f8f2;">
        <li><strong>VPC + IGW:</strong> The isolated network with internet access capability</li>
        <li><strong>Public Subnets (×3):</strong> For NAT Gateway and internet-facing load balancers</li>
        <li><strong>Private Subnets (×3):</strong> Isolated home for EKS worker nodes</li>
        <li><strong>NAT Gateway:</strong> Outbound-only internet access for private subnets</li>
        <li><strong>Route Tables:</strong> Traffic rules directing packets to IGW or NAT</li>
        <li><strong>NACLs:</strong> Stateless subnet-level firewall rules</li>
        <li><strong>Flow Logs:</strong> Network traffic auditing to CloudWatch</li>
      </ul>
      <em style="color: #6272a4; display: block; margin-top: 0.5rem;">📂 Source: <code>modules/vpc/main.tf</code> · <code>variables.tf</code> · <code>outputs.tf</code></em>
    </div>

    <div id="content"></div>

    <div class="summary">
      <h2 style="color:#bd93f9;margin-bottom:1rem">📥 Input Variables</h2>
      <table class="var-table">
        <thead><tr><th>Variable</th><th>Type</th><th>Default</th><th>Description</th></tr></thead>
        <tbody>
          <tr><td><code>name_prefix</code></td><td><code>string</code></td><td>—</td><td>Prefix for resource names (typically the cluster name)</td></tr>
          <tr><td><code>vpc_cidr</code></td><td><code>string</code></td><td>—</td><td>CIDR block for the VPC (e.g., <code>10.0.0.0/16</code>)</td></tr>
          <tr><td><code>azs</code></td><td><code>list(string)</code></td><td>—</td><td>List of availability zones for subnet placement</td></tr>
          <tr><td><code>private_subnets</code></td><td><code>list(string)</code></td><td>—</td><td>List of private subnet CIDR blocks (one per AZ)</td></tr>
          <tr><td><code>public_subnets</code></td><td><code>list(string)</code></td><td>—</td><td>List of public subnet CIDR blocks (one per AZ)</td></tr>
          <tr><td><code>enable_nat_gateway</code></td><td><code>bool</code></td><td><code>true</code></td><td>Enable NAT Gateway for private subnet outbound internet</td></tr>
          <tr><td><code>single_nat_gateway</code></td><td><code>bool</code></td><td><code>true</code></td><td>Use single NAT (<code>true</code> ~$33/mo) or one per AZ (<code>false</code> ~$100/mo HA)</td></tr>
          <tr><td><code>public_subnet_tags</code></td><td><code>map(string)</code></td><td><code>{}</code></td><td>Additional tags for public subnets (include EKS tags)</td></tr>
          <tr><td><code>private_subnet_tags</code></td><td><code>map(string)</code></td><td><code>{}</code></td><td>Additional tags for private subnets (include EKS tags)</td></tr>
          <tr><td><code>enable_flow_logs</code></td><td><code>bool</code></td><td><code>false</code></td><td>Enable VPC Flow Logs to CloudWatch</td></tr>
          <tr><td><code>tags</code></td><td><code>map(string)</code></td><td><code>{}</code></td><td>Tags to apply to all resources</td></tr>
        </tbody>
      </table>
    </div>

    <div class="summary">
      <h2 style="color:#bd93f9;margin-bottom:1rem">📤 Outputs</h2>
      <table class="var-table">
        <thead><tr><th>Output</th><th>Description</th></tr></thead>
        <tbody>
          <tr><td><code>vpc_id</code></td><td>The ID of the VPC</td></tr>
          <tr><td><code>vpc_cidr_block</code></td><td>The CIDR block of the VPC</td></tr>
          <tr><td><code>public_subnets</code></td><td>List of IDs of public subnets</td></tr>
          <tr><td><code>private_subnets</code></td><td>List of IDs of private subnets</td></tr>
          <tr><td><code>public_subnet_cidrs</code></td><td>List of CIDR blocks of public subnets</td></tr>
          <tr><td><code>private_subnet_cidrs</code></td><td>List of CIDR blocks of private subnets</td></tr>
          <tr><td><code>internet_gateway_id</code></td><td>ID of the Internet Gateway</td></tr>
          <tr><td><code>nat_gateway_ids</code></td><td>List of NAT Gateway IDs</td></tr>
          <tr><td><code>nat_gateway_public_ips</code></td><td>List of public IPs of NAT Gateways (for external allowlists)</td></tr>
          <tr><td><code>public_route_table_id</code></td><td>ID of the public route table</td></tr>
          <tr><td><code>private_route_table_ids</code></td><td>List of IDs of private route tables</td></tr>
          <tr><td><code>flow_log_id</code></td><td>ID of the VPC Flow Log (empty if disabled)</td></tr>
          <tr><td><code>flow_log_group_name</code></td><td>CloudWatch log group name for VPC Flow Logs</td></tr>
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
        phase: "Network Foundation", steps: [
          {
            title: "Create the VPC", cat: "net", time: "~10s",
            hcl: `resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr           # e.g., "10.0.0.0/16" — 65,536 IPs
  enable_dns_hostnames = true                   # Required by EKS
  enable_dns_support   = true                   # Required by EKS

  tags = merge(var.tags, {
    Name = "\${var.name_prefix}-vpc"
  })
}`,
            d2: `direction: down
vars: { d2-config: { theme-id: 200 } }
aws: "☁️ AWS Cloud" {
  style.fill: "#1e1f29"; style.stroke: "#ff9900"; style.stroke-width: 2
  vpc: "🖧 Customer VPC\\n10.0.0.0/16" {
    shape: package
    style.fill: "#282a36"; style.stroke: "#50fa7b"; style.stroke-width: 2
    dns: "DNS Resolver (10.0.0.2)" { shape: cylinder; style.fill: "#bd93f9"; style.font-color: "#f8f8f2" }
  }
}`,
            note: "enable_dns_support + enable_dns_hostnames are required by EKS — kubelet uses DNS to register nodes.",
            explain: "The VPC is your <strong>isolated private network</strong> in AWS. The <code>cidr_block</code> defines the IP range — <strong>10.0.0.0/16</strong> gives 65,536 IP addresses. <strong>DNS support</strong> is critical: EKS nodes use internal DNS to discover the API server, and the VPC CNI plugin uses it to resolve AWS service endpoints. Without these flags, nodes fail to join the cluster."
          },
          {
            title: "Attach Internet Gateway", cat: "net", time: "~10s",
            hcl: `resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id    # One IGW per VPC — the "front door"

  tags = merge(var.tags, {
    Name = "\${var.name_prefix}-igw"
  })
}`,
            d2: `direction: right
vars: { d2-config: { theme-id: 200 } }
internet: "🌐 Internet" { shape: cloud; style.fill: "#6272a4"; style.font-color: "#f8f8f2" }
aws: "☁️ AWS Cloud" {
  style.fill: "#1e1f29"; style.stroke: "#ff9900"; style.stroke-width: 2
  igw: "🚪 Internet Gateway" { shape: hexagon; style.fill: "#ffb86c"; style.font-color: "#282a36"; style.stroke-width: 2 }
  vpc: "🖧 Customer VPC" { shape: package; style.fill: "#282a36"; style.stroke: "#50fa7b"; style.stroke-width: 2 }
}
internet <-> aws.igw: "Public Traffic" { style.stroke: "#f8f8f2"; style.stroke-dash: 5 }
aws.igw <-> aws.vpc: "VPC Routing" { style.stroke: "#f8f8f2"; style.stroke-dash: 5 }`,
            note: "One IGW per VPC — horizontally scaled and redundant. Only public subnets use it.",
            explain: "The Internet Gateway is a horizontally-scaled, redundant AWS-managed component. It performs <strong>1:1 NAT</strong> for instances with public IPs. Without it, nothing in your VPC can reach the internet. You only ever need <strong>one per VPC</strong>."
          },
        ]
      },
      {
        phase: "Subnet Architecture (3 AZs)", steps: [
          {
            title: "Create Public Subnets (×3)", cat: "net", time: "~15s",
            hcl: `resource "aws_subnet" "public" {
  count                   = length(var.public_subnets)      # 3 subnets
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnets[count.index]  # e.g., 10.0.101.0/24
  availability_zone       = var.azs[count.index]             # Spread across AZs
  map_public_ip_on_launch = true                             # Auto-assign public IPs

  tags = merge(var.tags, var.public_subnet_tags, {
    Name = "\${var.name_prefix}-public-\${var.azs[count.index]}"
    Type = "public"
  })
}`,
            d2: `direction: down
vars: { d2-config: { theme-id: 200 } }
internet: "🌐 Internet" { shape: cloud; style.fill: "#6272a4"; style.font-color: "#f8f8f2" }
igw: "🚪 IGW" { shape: hexagon; style.fill: "#ffb86c"; style.font-color: "#282a36" }
vpc: "🖧 Customer VPC" {
  style.fill: "#1e1f29"; style.stroke: "#50fa7b"; style.stroke-width: 2
  az1: "🏢 AZ-A" { style.fill: "#282a36"; style.stroke: "#6272a4"; pub1: "🟢 Public Subnet 1\\n10.0.101.0/24" { shape: rectangle; style.fill: "#50fa7b"; style.font-color: "#282a36" } }
  az2: "🏢 AZ-B" { style.fill: "#282a36"; style.stroke: "#6272a4"; pub2: "🟢 Public Subnet 2\\n10.0.102.0/24" { shape: rectangle; style.fill: "#50fa7b"; style.font-color: "#282a36" } }
  az3: "🏢 AZ-C" { style.fill: "#282a36"; style.stroke: "#6272a4"; pub3: "🟢 Public Subnet 3\\n10.0.103.0/24" { shape: rectangle; style.fill: "#50fa7b"; style.font-color: "#282a36" } }
}
internet <-> igw: "In/Out" { style.stroke: "#f8f8f2"; style.stroke-dash: 5 }
igw <-> vpc.az1.pub1 { style.stroke: "#f8f8f2"; style.stroke-dash: 5 }
igw <-> vpc.az2.pub2 { style.stroke: "#f8f8f2"; style.stroke-dash: 5 }
igw <-> vpc.az3.pub3 { style.stroke: "#f8f8f2"; style.stroke-dash: 5 }`,
            note: "map_public_ip_on_launch = true. Tagged kubernetes.io/role/elb = 1 for ALB discovery.",
            explain: "Public subnets are spread across <strong>3 Availability Zones</strong> for fault tolerance. The <code>count</code> loop creates one subnet per AZ. Each <code>/24</code> provides 251 usable IPs (AWS reserves 5). The tag <code>kubernetes.io/role/elb</code> tells the AWS Load Balancer Controller to place public-facing ALBs in these subnets."
          },
          {
            title: "Create Private Subnets (×3)", cat: "net", time: "~15s",
            hcl: `resource "aws_subnet" "private" {
  count             = length(var.private_subnets)
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_subnets[count.index]  # e.g., 10.0.1.0/24
  availability_zone = var.azs[count.index]
  # NOTE: map_public_ip_on_launch NOT set → defaults to false (no public IPs)

  tags = merge(var.tags, var.private_subnet_tags, {
    Name = "\${var.name_prefix}-private-\${var.azs[count.index]}"
    Type = "private"
  })
}`,
            d2: `direction: down
vars: { d2-config: { theme-id: 200 } }
vpc: "🖧 Customer VPC" {
  style.fill: "#1e1f29"; style.stroke: "#50fa7b"; style.stroke-width: 2
  az1: "🏢 AZ-A" {
    style.fill: "#282a36"; style.stroke: "#6272a4"
    pub1: "🟢 Public Subnet" { shape: rectangle; style.fill: "#50fa7b"; style.font-color: "#282a36" }
    priv1: "🔒 Private Subnet\\n10.0.1.0/24" { shape: rectangle; style.fill: "#8be9fd"; style.font-color: "#282a36" }
  }
  az2: "🏢 AZ-B" {
    style.fill: "#282a36"; style.stroke: "#6272a4"
    pub2: "🟢 Public Subnet" { shape: rectangle; style.fill: "#50fa7b"; style.font-color: "#282a36" }
    priv2: "🔒 Private Subnet\\n10.0.2.0/24" { shape: rectangle; style.fill: "#8be9fd"; style.font-color: "#282a36" }
  }
  az3: "🏢 AZ-C" {
    style.fill: "#282a36"; style.stroke: "#6272a4"
    pub3: "🟢 Public Subnet" { shape: rectangle; style.fill: "#50fa7b"; style.font-color: "#282a36" }
    priv3: "🔒 Private Subnet\\n10.0.3.0/24" { shape: rectangle; style.fill: "#8be9fd"; style.font-color: "#282a36" }
  }
}`,
            note: "No public IPs. EKS worker nodes live here. Tagged kubernetes.io/role/internal-elb = 1.",
            explain: "Private subnets have <strong>no route to the Internet Gateway</strong> — they are completely isolated. Worker nodes here can only reach the internet through the NAT Gateway. The tag <code>kubernetes.io/role/internal-elb</code> tells EKS to place internal NLBs here for service-to-service communication."
          },
        ]
      },
      {
        phase: "NAT Gateway (Outbound Internet)", steps: [
          {
            title: "Create EIP + NAT Gateway", cat: "rt", time: "~2m",
            hcl: `resource "aws_eip" "nat" {
  count  = var.enable_nat_gateway ? (var.single_nat_gateway ? 1 : length(var.public_subnets)) : 0
  domain = "vpc"
  depends_on = [aws_internet_gateway.main]
}

resource "aws_nat_gateway" "main" {
  count         = var.enable_nat_gateway ? (var.single_nat_gateway ? 1 : length(var.public_subnets)) : 0
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id
  depends_on    = [aws_internet_gateway.main]
}`,
            d2: `direction: down
vars: { d2-config: { theme-id: 200 } }
internet: "🌐 Internet" { shape: cloud; style.fill: "#6272a4"; style.font-color: "#f8f8f2" }
vpc: "🖧 Customer VPC" {
  style.fill: "#1e1f29"; style.stroke: "#50fa7b"; style.stroke-width: 2
  igw: "🚪 IGW" { shape: hexagon; style.fill: "#ffb86c"; style.font-color: "#282a36" }
  pub: "🟢 Public Subnet" {
    style.fill: "#282a36"; style.stroke: "#50fa7b"
    nat: "🔄 NAT Gateway (with Elastic IP)" { shape: package; style.fill: "#ffb86c"; style.font-color: "#282a36" }
  }
  priv: "🔒 Private Subnets" { shape: rectangle; style.fill: "#8be9fd"; style.font-color: "#282a36" }
}
internet <-> vpc.igw: "Public Route" { style.stroke: "#f8f8f2"; style.stroke-dash: 5 }
vpc.pub.nat -> vpc.igw { style.stroke: "#ffb86c"; style.stroke-dash: 5 }
vpc.priv -> vpc.pub.nat: "Outbound Only" { style.stroke: "#8be9fd"; style.stroke-dash: 5 }`,
            note: "single_nat_gateway = true → 1 NAT (~$33/mo). Set false for HA (1 per AZ, ~$100/mo).",
            explain: "The NAT Gateway translates private IPs to a public Elastic IP for outbound traffic. The <code>count</code> ternary handles two modes: <strong>single NAT</strong> (cheaper, single AZ) or <strong>multi-AZ NAT</strong> (one per AZ for HA). In production, use multi-AZ so private subnets survive an AZ failure. NAT Gateways must be placed in <strong>public subnets</strong> because they need IGW access."
          },
        ]
      },
      {
        phase: "Route Tables (Traffic Rules)", steps: [
          {
            title: "Create Route Tables", cat: "rt", time: "~10s",
            hcl: `# --- Public Route Table ---
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  tags   = merge(var.tags, { Name = "\${var.name_prefix}-public-rt" })
}

resource "aws_route" "public_internet_gateway" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"               # Default route
  gateway_id             = aws_internet_gateway.main.id
}

# --- Private Route Table(s) ---
resource "aws_route_table" "private" {
  count  = var.single_nat_gateway ? 1 : length(var.private_subnets)
  vpc_id = aws_vpc.main.id
}

resource "aws_route" "private_nat_gateway" {
  count                  = var.enable_nat_gateway ? (var.single_nat_gateway ? 1 : length(var.private_subnets)) : 0
  route_table_id         = aws_route_table.private[count.index].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.main[count.index].id
}`,
            d2: `direction: right
vars: { d2-config: { theme-id: 200 } }
igw: "🚪 IGW" { shape: hexagon; style.fill: "#ffb86c"; style.font-color: "#282a36" }
nat: "🔄 NAT Gateway" { shape: package; style.fill: "#ffb86c"; style.font-color: "#282a36" }
pub_rt: "🗺️ Public Route Table" {
  shape: step; style.fill: "#50fa7b"; style.font-color: "#282a36"
  local: "10.0.0.0/16 → Local"
  def: "0.0.0.0/0 → IGW"
}
priv_rt: "🗺️ Private Route Table" {
  shape: step; style.fill: "#8be9fd"; style.font-color: "#282a36"
  local: "10.0.0.0/16 → Local"
  def: "0.0.0.0/0 → NAT"
}
pub_rt -> igw: "Direct Internet" { style.stroke: "#50fa7b"; style.stroke-dash: 5 }
priv_rt -> nat: "Outbound Only" { style.stroke: "#8be9fd"; style.stroke-dash: 5 }`,
            note: "Public → IGW (direct). Private → NAT (outbound only).",
            explain: "Route tables are the traffic rules. <code>0.0.0.0/0</code> is the default route — it catches all traffic not destined for within the VPC. Public subnets send it to the IGW. Private subnets send it to the NAT. With <code>single_nat_gateway = true</code>, one route table serves all 3 private subnets. With <code>false</code>, each gets its own to avoid cross-AZ data charges."
          },
        ]
      },
      {
        phase: "Network ACLs (Subnet Firewall)", steps: [
          {
            title: "Create Public NACL", cat: "sec", time: "~10s",
            hcl: `resource "aws_network_acl" "public" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = aws_subnet.public[*].id

  # Rule 100: Allow HTTPS (443) from anywhere
  ingress { rule_no=100; protocol="tcp"; action="allow"; cidr_block="0.0.0.0/0"; from_port=443; to_port=443 }
  # Rule 200: Allow HTTP (80) for redirects
  ingress { rule_no=200; protocol="tcp"; action="allow"; cidr_block="0.0.0.0/0"; from_port=80; to_port=80 }
  # Rule 300: Allow ephemeral ports (stateless — must allow responses!)
  ingress { rule_no=300; protocol="tcp"; action="allow"; cidr_block="0.0.0.0/0"; from_port=1024; to_port=65535 }
  # Rule 400: Allow all VPC-internal traffic
  ingress { rule_no=400; protocol="-1"; action="allow"; cidr_block=var.vpc_cidr; from_port=0; to_port=0 }
  # Egress: Allow all outbound
  egress  { rule_no=100; protocol="-1"; action="allow"; cidr_block="0.0.0.0/0"; from_port=0; to_port=0 }
}`,
            d2: `direction: right
vars: { d2-config: { theme-id: 200 } }
traffic: "🌐 Inbound Traffic" { shape: cloud; style.fill: "#6272a4"; style.font-color: "#f8f8f2" }
nacl: "🛡️ Public NACL (Stateless)" {
  style.fill: "#1e1f29"; style.stroke: "#bd93f9"; style.stroke-width: 2
  r1: "ALLOW 443 (HTTPS)" { shape: rectangle; style.fill: "#50fa7b"; style.font-color: "#282a36" }
  r2: "ALLOW 80 (HTTP)" { shape: rectangle; style.fill: "#50fa7b"; style.font-color: "#282a36" }
  r3: "ALLOW 1024-65535 (Ephemeral)" { shape: rectangle; style.fill: "#f1fa8c"; style.font-color: "#282a36" }
}
subnets: "🟢 Public Subnets" { shape: package; style.fill: "#282a36"; style.stroke: "#50fa7b" }
traffic -> nacl.r1 { style.stroke: "#f8f8f2"; style.stroke-dash: 5 }
traffic -> nacl.r2 { style.stroke: "#f8f8f2"; style.stroke-dash: 5 }
nacl -> subnets: "Filtered Traffic" { style.stroke: "#bd93f9"; style.stroke-dash: 5 }`,
            note: "NACLs are stateless — Rule 300 allows ephemeral response ports.",
            explain: "NACLs operate at the <strong>subnet level</strong> and are <strong>stateless</strong> — unlike Security Groups which are stateful. This means you must explicitly allow both <strong>request AND response</strong> traffic. Rule 300 (ephemeral ports 1024-65535) allows response packets from outbound connections. Rules are evaluated in <strong>numeric order</strong> — lowest number wins."
          },
          {
            title: "Create Private NACL", cat: "sec", time: "~10s",
            hcl: `resource "aws_network_acl" "private" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = aws_subnet.private[*].id

  # Rule 100: Only allow traffic from within the VPC
  ingress { rule_no=100; protocol="-1"; action="allow"; cidr_block=var.vpc_cidr; from_port=0; to_port=0 }
  # Rule 200: Allow ephemeral ports for NAT return traffic
  ingress { rule_no=200; protocol="tcp"; action="allow"; cidr_block="0.0.0.0/0"; from_port=1024; to_port=65535 }
  # Egress: Allow all outbound
  egress  { rule_no=100; protocol="-1"; action="allow"; cidr_block="0.0.0.0/0"; from_port=0; to_port=0 }
}`,
            d2: `direction: right
vars: { d2-config: { theme-id: 200 } }
traffic: "🌐 Internal / NAT Return" { shape: cloud; style.fill: "#6272a4"; style.font-color: "#f8f8f2" }
nacl: "🛡️ Private NACL (Stateless)" {
  style.fill: "#1e1f29"; style.stroke: "#bd93f9"; style.stroke-width: 2
  r1: "ALLOW 10.0.0.0/16 (VPC Internal)" { shape: rectangle; style.fill: "#8be9fd"; style.font-color: "#282a36" }
  r2: "ALLOW 1024-65535 (NAT Ephemeral)" { shape: rectangle; style.fill: "#f1fa8c"; style.font-color: "#282a36" }
}
subnets: "🔒 Private Subnets" { shape: package; style.fill: "#282a36"; style.stroke: "#8be9fd" }
traffic -> nacl.r1 { style.stroke: "#f8f8f2"; style.stroke-dash: 5 }
nacl -> subnets: "Filtered Traffic" { style.stroke: "#bd93f9"; style.stroke-dash: 5 }`,
            note: "More restrictive — only VPC-internal + ephemeral ports allowed inbound.",
            explain: "Private NACLs only allow traffic originating from <strong>within the VPC</strong> (10.0.0.0/16). No external traffic can reach private subnets directly. The ephemeral port rule allows <strong>return traffic</strong> from NAT Gateway outbound connections (like pulling Docker images from ECR)."
          },
        ]
      },
      {
        phase: "Monitoring & Observability", steps: [
          {
            title: "Enable VPC Flow Logs (Optional)", cat: "mon", time: "~15s",
            hcl: `resource "aws_iam_role" "flow_log" {
  count       = var.enable_flow_logs ? 1 : 0
  name_prefix = "\${var.name_prefix}-vpc-flow-log-"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Action = "sts:AssumeRole"; Effect = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" } }]
  })
}

resource "aws_cloudwatch_log_group" "flow_log" {
  count             = var.enable_flow_logs ? 1 : 0
  name              = "/aws/vpc/\${var.name_prefix}/flow-logs"
  retention_in_days = 30
}

resource "aws_flow_log" "main" {
  count           = var.enable_flow_logs ? 1 : 0
  vpc_id          = aws_vpc.main.id
  traffic_type    = "ALL"
  iam_role_arn    = aws_iam_role.flow_log[0].arn
  log_destination = aws_cloudwatch_log_group.flow_log[0].arn
}`,
            d2: `direction: right
vars: { d2-config: { theme-id: 200 } }
vpc: "🖧 Customer VPC" {
  style.fill: "#1e1f29"; style.stroke: "#50fa7b"; style.stroke-width: 2
  traffic: "🔄 All Network Traffic\\n(ACCEPT & REJECT)" { shape: hexagon; style.fill: "#ff79c6"; style.font-color: "#282a36" }
}
flow: "📉 VPC Flow Logs" { shape: cylinder; style.fill: "#bd93f9"; style.font-color: "#f8f8f2" }
cw: "☁️ CloudWatch\\n(30 Days Retention)" { shape: cloud; style.fill: "#6272a4"; style.font-color: "#f8f8f2" }
vpc.traffic -> flow: "ENI Data" { style.stroke: "#f8f8f2"; style.stroke-dash: 5 }
flow -> cw: "Log Streams" { style.stroke: "#bd93f9"; style.stroke-dash: 5 }`,
            note: "traffic_type = ALL captures accepted + rejected traffic for forensic analysis.",
            explain: "VPC Flow Logs capture metadata about every network connection: <strong>source/destination IP</strong>, <strong>port</strong>, <strong>protocol</strong>, and whether it was <strong>ACCEPTED or REJECTED</strong>. Essential for security forensics, troubleshooting connectivity, and compliance auditing (PCI-DSS, SOC2, HIPAA). Retained for 30 days in CloudWatch (~$5/mo)."
          },
        ]
      },
    ];

    const BADGES = { net: 'badge-net', sec: 'badge-sec', rt: 'badge-rt', mon: 'badge-mon' };
    const BADGE_LABEL = { net: 'Networking', sec: 'Security', rt: 'Routing', mon: 'Monitoring' };

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
    summaryRows += `<tr style="color:#ff79c6;font-weight:bold"><td></td><td><strong>Total: ~20 resources</strong></td><td></td><td><strong>~3 min</strong></td></tr>`;

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
        if (entry.isIntersecting) {
          setTimeout(() => entry.target.classList.add('visible'), i * 100);
          observer.unobserve(entry.target);
        }
      });
    }, { threshold: 0.1 });
    document.querySelectorAll('.phase, .step, .summary').forEach(el => observer.observe(el));

    window.addEventListener('scroll', () => {
      const h = document.documentElement;
      const pct = (h.scrollTop / (h.scrollHeight - h.clientHeight)) * 100;
      document.getElementById('progressBar').style.width = pct + '%';
    });
  </script>
</body>

</html>
