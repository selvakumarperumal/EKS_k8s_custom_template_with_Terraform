import re

with open('docs/architecture-build-steps.html', 'r') as f:
    text = f.read()

diagrams = {
    "Create the VPC": """direction: down
vars: { d2-config: { theme-id: 200 } }
aws: "☁️ AWS Cloud" {
  style.fill: "#1e1f29"; style.stroke: "#ff9900"; style.stroke-width: 2
  vpc: "🖧 Customer VPC\\n10.0.0.0/16" {
    shape: package
    style.fill: "#282a36"; style.stroke: "#50fa7b"; style.stroke-width: 2
    dns: "DNS Resolver" { shape: cylinder; style.fill: "#bd93f9"; style.font-color: "#f8f8f2" }
  }
}""",
    
    "Attach Internet Gateway": """direction: right
vars: { d2-config: { theme-id: 200 } }
internet: "🌐 Internet" { shape: cloud; style.fill: "#6272a4"; style.font-color: "#f8f8f2" }
aws: "☁️ AWS Cloud" {
  style.fill: "#1e1f29"; style.stroke: "#ff9900"; style.stroke-width: 2
  igw: "🚪 Internet Gateway" { shape: hexagon; style.fill: "#ffb86c"; style.font-color: "#282a36"; style.stroke-width: 2 }
  vpc: "🖧 Customer VPC" { shape: package; style.fill: "#282a36"; style.stroke: "#50fa7b"; style.stroke-width: 2 }
}
internet <-> aws.igw: "Public Traffic" { style.stroke: "#f8f8f2"; style.stroke-dash: 5 }
aws.igw <-> aws.vpc: "VPC Routing" { style.stroke: "#f8f8f2"; style.stroke-dash: 5 }""",

    "Create Public Subnets (×3)": """direction: down
vars: { d2-config: { theme-id: 200 } }
internet: "🌐 Internet" { shape: cloud; style.fill: "#6272a4"; style.font-color: "#f8f8f2" }
igw: "🚪 IGW" { shape: hexagon; style.fill: "#ffb86c"; style.font-color: "#282a36" }
vpc: "🖧 Customer VPC" {
  style.fill: "#1e1f29"; style.stroke: "#50fa7b"; style.stroke-width: 2
  az1: "🏢 AZ-A" { style.fill: "#282a36"; style.stroke: "#6272a4"; pub1: "🟢 Public Subnet 1" { shape: rectangle; style.fill: "#50fa7b"; style.font-color: "#282a36" } }
  az2: "🏢 AZ-B" { style.fill: "#282a36"; style.stroke: "#6272a4"; pub2: "🟢 Public Subnet 2" { shape: rectangle; style.fill: "#50fa7b"; style.font-color: "#282a36" } }
  az3: "🏢 AZ-C" { style.fill: "#282a36"; style.stroke: "#6272a4"; pub3: "🟢 Public Subnet 3" { shape: rectangle; style.fill: "#50fa7b"; style.font-color: "#282a36" } }
}
internet <-> igw: "In/Out" { style.stroke: "#f8f8f2"; style.stroke-dash: 5 }
igw <-> vpc.az1.pub1 { style.stroke: "#f8f8f2"; style.stroke-dash: 5 }
igw <-> vpc.az2.pub2 { style.stroke: "#f8f8f2"; style.stroke-dash: 5 }
igw <-> vpc.az3.pub3 { style.stroke: "#f8f8f2"; style.stroke-dash: 5 }""",

    "Create Private Subnets (×3)": """direction: down
vars: { d2-config: { theme-id: 200 } }
vpc: "🖧 Customer VPC" {
  style.fill: "#1e1f29"; style.stroke: "#50fa7b"; style.stroke-width: 2
  az1: "🏢 AZ-A" { 
    style.fill: "#282a36"; style.stroke: "#6272a4"; 
    pub1: "🟢 Public Subnet" { shape: rectangle; style.fill: "#50fa7b"; style.font-color: "#282a36" } 
    priv1: "🔒 Private Subnet" { shape: rectangle; style.fill: "#8be9fd"; style.font-color: "#282a36" } 
  }
  az2: "🏢 AZ-B" { 
    style.fill: "#282a36"; style.stroke: "#6272a4"; 
    pub2: "🟢 Public Subnet" { shape: rectangle; style.fill: "#50fa7b"; style.font-color: "#282a36" } 
    priv2: "🔒 Private Subnet" { shape: rectangle; style.fill: "#8be9fd"; style.font-color: "#282a36" } 
  }
}""",

    "Create EIP + NAT Gateway": """direction: down
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
vpc.priv -> vpc.pub.nat: "Outbound Bound Only" { style.stroke: "#8be9fd"; style.stroke-dash: 5 }""",

    "Create Route Tables": """direction: right
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
priv_rt -> nat: "Outbound Only" { style.stroke: "#8be9fd"; style.stroke-dash: 5 }""",

    "Create Public NACL": """direction: right
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
nacl -> subnets: "Filtered Traffic" { style.stroke: "#bd93f9"; style.stroke-dash: 5 }""",

    "Create Private NACL": """direction: right
vars: { d2-config: { theme-id: 200 } }
traffic: "🌐 Internal / NAT Return" { shape: cloud; style.fill: "#6272a4"; style.font-color: "#f8f8f2" }
nacl: "🛡️ Private NACL (Stateless)" {
  style.fill: "#1e1f29"; style.stroke: "#bd93f9"; style.stroke-width: 2
  r1: "ALLOW 10.0.0.0/16 (VPC Internal)" { shape: rectangle; style.fill: "#8be9fd"; style.font-color: "#282a36" }
  r2: "ALLOW 1024-65535 (NAT Ephemeral)" { shape: rectangle; style.fill: "#f1fa8c"; style.font-color: "#282a36" }
}
subnets: "🔒 Private Subnets" { shape: package; style.fill: "#282a36"; style.stroke: "#8be9fd" }

traffic -> nacl.r1 { style.stroke: "#f8f8f2"; style.stroke-dash: 5 }
nacl -> subnets: "Filtered Traffic" { style.stroke: "#bd93f9"; style.stroke-dash: 5 }""",

    "Enable VPC Flow Logs": """direction: right
vars: { d2-config: { theme-id: 200 } }
vpc: "🖧 Customer VPC" { 
  style.fill: "#1e1f29"; style.stroke: "#50fa7b"; style.stroke-width: 2
  traffic: "🔄 All Network Traffic\\n(ACCEPT & REJECT)" { shape: hexagon; style.fill: "#ff79c6"; style.font-color: "#282a36" }
}
flow: "📉 VPC Flow Logs" { shape: cylinder; style.fill: "#bd93f9"; style.font-color: "#f8f8f2" }
cw: "☁️ CloudWatch\\n(30 Days Retention)" { shape: cloud; style.fill: "#6272a4"; style.font-color: "#f8f8f2" }

vpc.traffic -> flow: "ENI Data" { style.stroke: "#f8f8f2"; style.stroke-dash: 5 }
flow -> cw: "Log Streams" { style.stroke: "#bd93f9"; style.stroke-dash: 5 }""",

    "Create Cluster IAM Role": """direction: down
vars: { d2-config: { theme-id: 200 } }
role: "🔐 Cluster IAM Role" {
  style.fill: "#1e1f29"; style.stroke: "#ff5555"; style.stroke-width: 2
  trust: "Trust Identity: eks.amazonaws.com" { shape: document; style.fill: "#44475a"; style.font-color: "#f8f8f2" }
}
policies: "AWS Managed Policies" {
  style.fill: "#282a36"; style.stroke: "#ffb86c"
  p1: "AmazonEKSClusterPolicy" { shape: rectangle; style.fill: "#ffb86c"; style.font-color: "#282a36" }
  p2: "AmazonEKSVPCResourceController" { shape: rectangle; style.fill: "#ffb86c"; style.font-color: "#282a36" }
}
role -> policies.p1: "Attached" { style.stroke: "#f1fa8c"; style.stroke-dash: 5 }
role -> policies.p2: "Attached" { style.stroke: "#f1fa8c"; style.stroke-dash: 5 }""",

    "Create Node Group IAM Role": """direction: down
vars: { d2-config: { theme-id: 200 } }
role: "🔐 Node Group IAM Role" {
  style.fill: "#1e1f29"; style.stroke: "#ff5555"; style.stroke-width: 2
  trust: "Trust Identity: ec2.amazonaws.com" { shape: document; style.fill: "#44475a"; style.font-color: "#f8f8f2" }
}
policies: "AWS Managed Policies" {
  style.fill: "#282a36"; style.stroke: "#ffb86c"
  p1: "EKSWorkerNodePolicy" { shape: rectangle; style.fill: "#ffb86c"; style.font-color: "#282a36" }
  p2: "EKS_CNI_Policy" { shape: rectangle; style.fill: "#ffb86c"; style.font-color: "#282a36" }
  p3: "ECR ReadOnly" { shape: rectangle; style.fill: "#ffb86c"; style.font-color: "#282a36" }
}
role -> policies.p1 { style.stroke: "#f1fa8c"; style.stroke-dash: 5 }
role -> policies.p2 { style.stroke: "#f1fa8c"; style.stroke-dash: 5 }
role -> policies.p3 { style.stroke: "#f1fa8c"; style.stroke-dash: 5 }""",

    "Create KMS Key": """direction: right
vars: { d2-config: { theme-id: 200 } }
kms: "🔑 KMS Master Key\\n(Envelope Encryption)" { shape: hexagon; style.fill: "#ff5555"; style.font-color: "#f8f8f2" }
dek: "🎫 Data Encryption Key\\n(Generated by KMS)" { shape: document; style.fill: "#f1fa8c"; style.font-color: "#282a36" }
k8s: "Kubernetes Secrets" {
  style.fill: "#1e1f29"; style.stroke: "#bd93f9"
  etcd: "🗄️ etcd Database" { shape: cylinder; style.fill: "#44475a"; style.font-color: "#f8f8f2" }
}

kms -> dek: "1. Creates & Encrypts DEK" { style.stroke: "#f8f8f2"; style.stroke-dash: 5 }
dek -> k8s.etcd: "2. Encrypts Secrets Data" { style.stroke: "#f1fa8c"; style.stroke-dash: 5 }""",

    "Create Security Groups + Rules": """direction: right
vars: { d2-config: { theme-id: 200 } }
csg: "🛡️ Cluster SG\\n(EKS Control Plane)" { shape: hexagon; style.fill: "#ffb86c"; style.font-color: "#282a36" }
nsg: "🛡️ Node SG\\n(EC2 Worker Nodes)" { shape: hexagon; style.fill: "#8be9fd"; style.font-color: "#282a36" }

# Rules
nsg -> csg: "Ingress 443 (kubelet to API)" { style.stroke: "#50fa7b"; style.stroke-dash: 5 }
csg -> nsg: "Ingress 1025-65535 (API to kubelet/exec)" { style.stroke: "#bd93f9"; style.stroke-dash: 5 }
nsg -> nsg: "Ingress All Ports (Pod-to-Pod)" { style.stroke: "#f1fa8c"; style.stroke-dash: 5 }""",

    "Register OIDC Provider (IRSA)": """direction: down
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
pods.sa2 -> pods.pod2: "Mounted Token" { style.stroke: "#bd93f9"; style.stroke-dash: 5 }""",

    "Install EKS Add-ons": """direction: down
vars: { d2-config: { theme-id: 200 } }
worker: "🖥️ EC2 Worker Node" {
  style.fill: "#1e1f29"; style.stroke: "#6272a4"; style.stroke-width: 2
  
  cni: "🌐 VPC CNI (DaemonSet)\\nManages ENIs & VPC IPs" { shape: hexagon; style.fill: "#ffb86c"; style.font-color: "#282a36" }
  kp: "🔀 kube-proxy (DaemonSet)\\nManages iptables routing" { shape: hexagon; style.fill: "#8be9fd"; style.font-color: "#282a36" }
  dns: "🔍 CoreDNS (Deployment)\\nCluster DNS Resolution" { shape: hexagon; style.fill: "#50fa7b"; style.font-color: "#282a36" }
}
vpc: "🖧 Customer VPC" { shape: package; style.fill: "#44475a"; style.font-color: "#f8f8f2" } 
worker.cni -> vpc: "Assigns real IPs to Pods" { style.stroke: "#ffb86c"; style.stroke-dash: 5 }""",

    "Create Launch Templates": """direction: right
vars: { d2-config: { theme-id: 200 } }
admin: "💻 Terraform" { shape: person; style.fill: "#6272a4" }

lt: "📜 EC2 Launch Template" {
  style.fill: "#1e1f29"; style.stroke: "#bd93f9"; style.stroke-width: 2
  imds: "🔐 IMDSv2 Enforced\\n(Blocks SSRF)" { shape: rectangle; style.fill: "#ff5555"; style.font-color: "#f8f8f2" }
  ebs: "💾 gp3 Volumes\\n(Encrypted, 3000 IOPS)" { shape: cylinder; style.fill: "#ffb86c"; style.font-color: "#282a36" }
  net: "🌐 Network Interfaces\\n(No Public IPs)" { shape: rectangle; style.fill: "#8be9fd"; style.font-color: "#282a36" }
}

asg: "⚙️ EKS Node Group (ASG)" { shape: hexagon; style.fill: "#50fa7b"; style.font-color: "#282a36" }

admin -> lt: "Defines Baseline" { style.stroke: "#f8f8f2"; style.stroke-dash: 5 }
lt -> asg: "Used to provision instances" { style.stroke: "#bd93f9"; style.stroke-dash: 5 }""",

    "Create Node Groups": """direction: down
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
api -> vpc.priv.g1.n1: "Kubelet Join (HTTPS)" { style.stroke: "#f8f8f2"; style.stroke-dash: 5 }
api -> vpc.priv.g1.n2 { style.stroke: "#f8f8f2"; style.stroke-dash: 5 }
api -> vpc.priv.g2.s1 { style.stroke: "#f8f8f2"; style.stroke-dash: 5 }""",

    "Create Secrets + KMS Key": """direction: down
vars: { d2-config: { theme-id: 200 } }
sm: "🔐 AWS Secrets Manager" {
  style.fill: "#1e1f29"; style.stroke: "#ffb86c"; style.stroke-width: 2
  
  db: "🗄️ Database Credentials" { shape: document; style.fill: "#f1fa8c"; style.font-color: "#282a36" }
  api: "🔌 External API Keys" { shape: document; style.fill: "#f1fa8c"; style.font-color: "#282a36" }
  app: "⚙️ App Configurations" { shape: document; style.fill: "#f1fa8c"; style.font-color: "#282a36" }
}

kms: "🔑 Custom KMS Key\\n(Dedicated to Secrets)" { shape: hexagon; style.fill: "#ff5555"; style.font-color: "#f8f8f2" }

kms -> sm.db: "Encrypts at rest" { style.stroke: "#ff79c6"; style.stroke-dash: 5 }
kms -> sm.api: "Encrypts at rest" { style.stroke: "#ff79c6"; style.stroke-dash: 5 }
kms -> sm.app: "Encrypts at rest" { style.stroke: "#ff79c6"; style.stroke-dash: 5 }""",

    "Create Read-Only IAM Policy": """direction: right
vars: { d2-config: { theme-id: 200 } }
pod: "📦 Application Pod\\n(via IRSA)" { shape: package; style.fill: "#8be9fd"; style.font-color: "#282a36" }

iam: "🛡️ IAM Policy (Read-Only)" {
  style.fill: "#1e1f29"; style.stroke: "#ff5555"; style.stroke-width: 2
  p1: "ALLOW: secretsmanager:GetSecretValue\\n(Only specific ARNs)" { shape: rectangle; style.fill: "#ffb86c"; style.font-color: "#282a36" }
  p2: "ALLOW: kms:Decrypt\\n(Only dedicated KMS Key)" { shape: rectangle; style.fill: "#ffb86c"; style.font-color: "#282a36" }
}

sm: "🔐 Secrets Vault" { shape: cylinder; style.fill: "#bd93f9"; style.font-color: "#282a36" }

pod -> iam { style.stroke: "#f8f8f2"; style.stroke-dash: 5 }
iam.p1 -> sm: "Read Secret" { style.stroke: "#50fa7b"; style.stroke-dash: 5 }
iam.p2 -> sm: "Decrypt via KMS" { style.stroke: "#50fa7b"; style.stroke-dash: 5 }""",

    "Enable GuardDuty": """direction: right
vars: { d2-config: { theme-id: 200 } }
sources: "📊 Audit & Network Sources" {
  style.fill: "#1e1f29"; style.stroke: "#6272a4"
  vfl: "VPC Flow Logs" { shape: document; style.fill: "#6272a4"; style.font-color: "#f8f8f2" }
  k8s: "EKS Audit Logs" { shape: document; style.fill: "#6272a4"; style.font-color: "#f8f8f2" }
  dns: "Route 53 DNS Logs" { shape: document; style.fill: "#6272a4"; style.font-color: "#f8f8f2" }
}

gd: "🛡️ AWS GuardDuty" {
  style.fill: "#282a36"; style.stroke: "#bd93f9"; style.stroke-width: 2
  det: "🧠 Machine Learning Detector\\n(Updates every 15 min)" { shape: hexagon; style.fill: "#bd93f9"; style.font-color: "#282a36" }
}

alert: "🚨 Security Findings\\n(Crypto mining, Exploit attempts)" { shape: callout; style.fill: "#ff5555"; style.font-color: "#f8f8f2" }

sources.vfl -> gd.det: "Analyzes" { style.stroke: "#f8f8f2"; style.stroke-dash: 5 }
sources.k8s -> gd.det: "Analyzes" { style.stroke: "#f8f8f2"; style.stroke-dash: 5 }
sources.dns -> gd.det: "Analyzes" { style.stroke: "#f8f8f2"; style.stroke-dash: 5 }
gd.det -> alert: "Generates Alerts" { style.stroke: "#ff5555"; style.stroke-dash: 5; style.stroke-width: 2 }""",

    "Enable AWS Config Rules": """direction: right
vars: { d2-config: { theme-id: 200 } }
config: "⚙️ AWS Config Service" {
  style.fill: "#1e1f29"; style.stroke: "#bd93f9"; style.stroke-width: 2
  rec: "📸 Config Snapshot Recorder" { shape: cylinder; style.fill: "#6272a4"; style.font-color: "#f8f8f2" }
  
  rules: "Compliance Rules" {
    style.fill: "#282a36"; style.stroke: "#ffb86c"
    r1: "Is EKS Logging Enabled?" { shape: rectangle; style.fill: "#bd93f9"; style.font-color: "#f8f8f2" }
    r2: "Is Endpoint Private?" { shape: rectangle; style.fill: "#bd93f9"; style.font-color: "#f8f8f2" }
    r3: "Are Secrets Encrypted?" { shape: rectangle; style.fill: "#bd93f9"; style.font-color: "#f8f8f2" }
  }
}

eks: "⬡ EKS Cluster Resources" { shape: package; style.fill: "#44475a"; style.font-color: "#f8f8f2" }

c1: "✅ COMPLIANT" { shape: callout; style.fill: "#50fa7b"; style.font-color: "#282a36" }

eks -> config.rec: "Configuration State Changes" { style.stroke: "#f8f8f2"; style.stroke-dash: 5 }
config.rec -> config.rules: "Evaluates Snapshot" { style.stroke: "#f8f8f2"; style.stroke-dash: 5 }
config.rules -> c1: "Status Dashboard" { style.stroke: "#50fa7b"; style.stroke-dash: 5; style.stroke-width: 2 }"""
}

def update_html():
    for title, d2_code in diagrams.items():
        # Using a regex to find the d2 string for a specific title
        # The structure is roughly title: "...", module: "...", time: "...", hcl: `...`, d2: `...`, note: "..."
        pattern = re.compile(r'(title:\s*"' + re.escape(title) + r'".*?d2:\s*`)(.*?)(`,\s*note:)', re.DOTALL)
        
        match = pattern.search(text)
        if match:
            # We are safe to replace
            pass
        else:
            print(f"Could not find match for title: {title}")

    # Process all
    new_text = text
    for title, d2_code in diagrams.items():
        pattern = re.compile(r'(title:\s*"' + re.escape(title) + r'".*?d2:\s*`)(.*?)(`,\s*note:)', re.DOTALL)
        
        def replacer(m):
            return m.group(1) + d2_code + m.group(3)
        
        new_text = pattern.sub(replacer, new_text)

    with open('docs/architecture-build-steps.html', 'w') as out:
        out.write(new_text)

update_html()
