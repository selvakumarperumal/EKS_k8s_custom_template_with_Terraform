# 🏗️ Architecture Build Steps

How `terraform apply` builds the entire infrastructure — step by step.

---

## Step 1 — Create the VPC

The VPC is your private, isolated network inside AWS. Everything else lives inside it.

```mermaid
graph LR
    classDef vpcStyle fill:#248814,stroke:#fff,stroke-width:2px,color:#fff

    AWS(("AWS Cloud")) --> VPC["VPC\n10.0.0.0/16\n65,536 IPs"]

    class VPC vpcStyle
```

> Terraform: `aws_vpc.main` — Enables DNS support + DNS hostnames (required by EKS).

---

## Step 2 — Attach an Internet Gateway

The Internet Gateway is the "front door" — it connects the VPC to the public internet.

```mermaid
graph LR
    classDef vpcStyle fill:#248814,stroke:#fff,stroke-width:2px,color:#fff
    classDef gwStyle fill:#D86613,stroke:#fff,stroke-width:2px,color:#fff

    Internet(("Internet")) <--> IGW["Internet\nGateway"]
    IGW <--> VPC["VPC"]

    class VPC vpcStyle
    class IGW gwStyle
```

> Terraform: `aws_internet_gateway.main` — One per VPC. Fully managed by AWS.

---

## Step 3 — Create Public Subnets (×3)

One public subnet per Availability Zone for high availability.

```mermaid
graph TD
    classDef vpcStyle fill:#248814,stroke:#fff,stroke-width:2px,color:#fff
    classDef pubStyle fill:#2E86C1,stroke:#fff,stroke-width:2px,color:#fff

    VPC["VPC"] --> PubA["Public Subnet\n10.0.101.0/24\nAZ-A"]
    VPC --> PubB["Public Subnet\n10.0.102.0/24\nAZ-B"]
    VPC --> PubC["Public Subnet\n10.0.103.0/24\nAZ-C"]

    class VPC vpcStyle
    class PubA,PubB,PubC pubStyle
```

> `map_public_ip_on_launch = true` — Instances here get public IPs automatically.
> Tagged with `kubernetes.io/role/elb = 1` so EKS places public load balancers here.

---

## Step 4 — Create Private Subnets (×3)

Worker nodes live here — no direct internet access.

```mermaid
graph TD
    classDef vpcStyle fill:#248814,stroke:#fff,stroke-width:2px,color:#fff
    classDef privStyle fill:#145E88,stroke:#fff,stroke-width:2px,color:#fff

    VPC["VPC"] --> PrivA["Private Subnet\n10.0.1.0/24\nAZ-A"]
    VPC --> PrivB["Private Subnet\n10.0.2.0/24\nAZ-B"]
    VPC --> PrivC["Private Subnet\n10.0.3.0/24\nAZ-C"]

    class VPC vpcStyle
    class PrivA,PrivB,PrivC privStyle
```

> No public IPs. Tagged with `kubernetes.io/role/internal-elb = 1` for internal load balancers.

---

## Step 5 — Create NAT Gateway

NAT Gateway lets private subnets reach the internet (outbound only — for pulling images, DNS, etc.).

```mermaid
graph LR
    classDef pubStyle fill:#2E86C1,stroke:#fff,stroke-width:2px,color:#fff
    classDef gwStyle fill:#D86613,stroke:#fff,stroke-width:2px,color:#fff
    classDef privStyle fill:#145E88,stroke:#fff,stroke-width:2px,color:#fff

    PrivSub["Private Subnet\nWorker Nodes"] -- "Outbound\nonly" --> NAT["NAT\nGateway\nElastic IP"]
    NAT --> PubSub["Public Subnet"]
    PubSub --> IGW(("Internet"))

    class PrivSub privStyle
    class NAT gwStyle
    class PubSub pubStyle
```

> NAT is placed in a public subnet. `single_nat_gateway = true` uses 1 NAT (~$33/mo) instead of 3.

---

## Step 6 — Create Route Tables

Route tables tell traffic where to go.

```mermaid
graph TD
    classDef rtStyle fill:#1ABC9C,stroke:#fff,stroke-width:2px,color:#fff
    classDef gwStyle fill:#D86613,stroke:#fff,stroke-width:2px,color:#fff

    PubRT["Public Route Table\n0.0.0.0/0 → Internet Gateway"] --> IGW["Internet\nGateway"]
    PrivRT["Private Route Table\n0.0.0.0/0 → NAT Gateway"] --> NAT["NAT\nGateway"]

    class PubRT,PrivRT rtStyle
    class IGW,NAT gwStyle
```

> Public subnets → Internet Gateway (direct access).
> Private subnets → NAT Gateway (outbound only).

---

## Step 7 — Create Network ACLs

NACLs are stateless subnet-level firewalls — a second layer of defense.

```mermaid
graph TD
    classDef naclStyle fill:#8C4FFF,stroke:#fff,stroke-width:2px,color:#fff
    classDef pubStyle fill:#2E86C1,stroke:#fff,stroke-width:2px,color:#fff
    classDef privStyle fill:#145E88,stroke:#fff,stroke-width:2px,color:#fff

    PubNACL["Public NACL\nAllow: 80, 443, 1024-65535\nAllow: VPC internal"] --- PubSub["Public\nSubnets"]
    PrivNACL["Private NACL\nAllow: VPC internal only\nAllow: Ephemeral ports"] --- PrivSub["Private\nSubnets"]

    class PubNACL,PrivNACL naclStyle
    class PubSub pubStyle
    class PrivSub privStyle
```

> NACLs are stateless — you must allow both request AND response traffic explicitly.

---

## Step 8 — Enable VPC Flow Logs (Optional)

Captures network traffic metadata for security auditing.

```mermaid
graph LR
    classDef vpcStyle fill:#248814,stroke:#fff,stroke-width:2px,color:#fff
    classDef logStyle fill:#6C757D,stroke:#fff,stroke-width:2px,color:#fff

    VPC["VPC"] -- "ALL traffic\nmetadata" --> FlowLog["VPC\nFlow Logs"]
    FlowLog --> CW["CloudWatch\nLogs"]

    class VPC vpcStyle
    class FlowLog,CW logStyle
```

> Records source/destination IP, port, protocol, and accept/reject decisions. ~$5/month.

---

## Step 9 — Create IAM Cluster Role

EKS needs an IAM role to manage the control plane on your behalf. **This runs in parallel with VPC steps.**

```mermaid
graph LR
    classDef iamStyle fill:#DD344C,stroke:#fff,stroke-width:2px,color:#fff
    classDef policyStyle fill:#E78F24,stroke:#fff,stroke-width:2px,color:#fff

    Role["Cluster IAM Role\nTrust: eks.amazonaws.com"] --> P1["AmazonEKSClusterPolicy"]
    Role --> P2["AmazonEKSVPCResourceController"]

    class Role iamStyle
    class P1,P2 policyStyle
```

> Only the EKS service can assume this role. It grants permissions to manage ENIs, load balancers, and logging.

---

## Step 10 — Create IAM Node Role

Worker nodes need their own IAM role to join the cluster and pull images.

```mermaid
graph LR
    classDef iamStyle fill:#DD344C,stroke:#fff,stroke-width:2px,color:#fff
    classDef policyStyle fill:#E78F24,stroke:#fff,stroke-width:2px,color:#fff

    Role["Node IAM Role\nTrust: ec2.amazonaws.com"] --> P1["AmazonEKSWorkerNodePolicy"]
    Role --> P2["AmazonEKS_CNI_Policy"]
    Role --> P3["EC2ContainerRegistryReadOnly"]

    class Role iamStyle
    class P1,P2,P3 policyStyle
```

> Nodes can register with EKS, assign VPC IPs to pods, and pull container images. Read-only ECR access.

---

## Step 11 — Create KMS Key for Secrets

A KMS key enables envelope encryption for Kubernetes secrets stored in etcd.

```mermaid
graph LR
    classDef kmsStyle fill:#DC3147,stroke:#fff,stroke-width:2px,color:#fff

    KMS["KMS Key\nAuto-rotation: yearly\n7-day deletion window"] --> Alias["Alias:\nalias/eks-cluster-eks"]

    class KMS,Alias kmsStyle
```

> Without KMS, secrets in etcd are just base64-encoded (not encrypted). This key encrypts the Data Encryption Keys.

---

## Step 12 — Create Security Groups

Two security groups control network access for the cluster and nodes.

```mermaid
graph TD
    classDef sgStyle fill:#F58536,stroke:#fff,stroke-width:2px,color:#fff

    CSG["Cluster SG\nProtects control\nplane ENIs"]
    NSG["Node SG\nProtects worker\nnodes"]

    CSG -- "Port 443" --> NSG
    NSG -- "Port 443" --> CSG
    CSG -- "Port 1025-65535" --> NSG
    NSG -- "All ports" --> NSG

    class CSG,NSG sgStyle
```

> Nodes talk to the API on 443. The API reaches nodes on high ports for `kubectl exec/logs`. Nodes talk to each other freely.

---

## Step 13 — Create the EKS Cluster

The core resource — the Kubernetes control plane. **Takes ~10 minutes**.

```mermaid
graph TD
    classDef eksStyle fill:#F58536,stroke:#fff,stroke-width:2px,color:#fff
    classDef inputStyle fill:#6C757D,stroke:#fff,stroke-width:2px,color:#fff

    VPC_ID["VPC + Private Subnets"] --> EKS
    IAM_ROLE["Cluster IAM Role"] --> EKS
    KMS_KEY["KMS Key"] --> EKS
    SG["Cluster Security Group"] --> EKS
    CW_LOG["CloudWatch Log Group"] --> EKS

    EKS["EKS Cluster\nKubernetes Control Plane\nAPI Server + etcd + Controllers"]

    class EKS eksStyle
    class VPC_ID,IAM_ROLE,KMS_KEY,SG,CW_LOG inputStyle
```

> AWS runs 3 API server replicas across 3 AZs. You don't manage control plane nodes — AWS does.

---

## Step 14 — Register OIDC Provider (IRSA)

Enables pods to assume their own IAM roles instead of sharing the node role.

```mermaid
graph LR
    classDef eksStyle fill:#F58536,stroke:#fff,stroke-width:2px,color:#fff
    classDef irsaStyle fill:#8C4FFF,stroke:#fff,stroke-width:2px,color:#fff

    EKS["EKS Cluster"] -- "OIDC Issuer URL" --> OIDC["OIDC Provider\nRegistered in IAM"]
    OIDC -. "Pod → ServiceAccount → IAM Role" .-> Pods(("Fine-grained\npod permissions"))

    class EKS eksStyle
    class OIDC,Pods irsaStyle
```

> Without IRSA, all pods share the Node Role. With IRSA, each pod gets only the permissions it needs.

---

## Step 15 — Install EKS Add-ons

Three essential networking add-ons managed by AWS.

```mermaid
graph TD
    classDef addonStyle fill:#D86613,stroke:#fff,stroke-width:2px,color:#fff

    EKS(("EKS\nCluster")) --> CNI["VPC CNI\nAssigns VPC IPs\nto pods"]
    EKS --> KProxy["kube-proxy\nService routing\niptables rules"]
    EKS --> CoreDNS["CoreDNS\nDNS resolution\ninstalled after nodes"]

    class CNI,KProxy,CoreDNS addonStyle
```

> VPC CNI + kube-proxy install immediately. CoreDNS waits for nodes (it needs somewhere to run).

---

## Step 16 — Create Launch Templates

Defines the EC2 instance configuration for worker nodes — security-hardened.

```mermaid
graph TD
    classDef ltStyle fill:#145E88,stroke:#fff,stroke-width:2px,color:#fff

    LT_GEN["Launch Template: General\nIMDSv2 enforced\ngp3 EBS encrypted\nNo public IP"]
    LT_SPOT["Launch Template: Spot\nIMDSv2 enforced\ngp3 EBS encrypted\nNo public IP"]

    class LT_GEN,LT_SPOT ltStyle
```

> IMDSv2 prevents SSRF credential theft (Capital One breach). Encrypted gp3 volumes with 3000 IOPS baseline.

---

## Step 17 — Create Managed Node Groups

The actual worker EC2 instances that run your pods.

```mermaid
graph TD
    classDef ondemandStyle fill:#145E88,stroke:#fff,stroke-width:2px,color:#fff
    classDef spotStyle fill:#E78F24,stroke:#fff,stroke-width:2px,color:#fff

    subgraph ON_DEMAND ["General - ON_DEMAND"]
        N1["t3.medium\nNode 1"]
        N2["t3.medium\nNode 2"]
    end

    subgraph SPOT ["Spot - UP TO 90% OFF"]
        S1["t3.medium or\nt3a.medium\nNode 1"]
    end

    class N1,N2 ondemandStyle
    class S1 spotStyle
```

> General: 2-4 nodes, never interrupted. Spot: 1-3 nodes, can be reclaimed with 2-min warning.
> Spot nodes are tainted — pods need a toleration to schedule there.

---

## Step 18 — Create Secrets Manager KMS Key

A **separate** KMS key dedicated to encrypting secrets (not the EKS one).

```mermaid
graph LR
    classDef kmsStyle fill:#E78F24,stroke:#fff,stroke-width:2px,color:#fff

    KMS_SM["Secrets KMS Key\nSeparate from EKS key\nDifferent access policy"] --> Alias["Alias:\nalias/eks-cluster-secrets"]

    class KMS_SM,Alias kmsStyle
```

> Key separation: if one key is compromised, the other secrets remain safe.

---

## Step 19 — Create Secrets

Three types of secrets stored in AWS Secrets Manager.

```mermaid
graph TD
    classDef smStyle fill:#E78F24,stroke:#fff,stroke-width:2px,color:#fff
    classDef kmsStyle fill:#DC3147,stroke:#fff,stroke-width:2px,color:#fff

    KMS["Secrets\nKMS Key"] -. "Encrypts" .-> DB["DB Credentials\nusername, password\nhost, port, engine"]
    KMS -. "Encrypts" .-> API["API Keys\napi_key\napi_secret"]
    KMS -. "Encrypts" .-> APP["App Config\nLOG_LEVEL, flags\nenvironment vars"]

    class DB,API,APP smStyle
    class KMS kmsStyle
```

> Each secret is conditionally created via `count` flags. 7-day recovery window prevents accidental deletion.

---

## Step 20 — Create Secrets Read-Only Policy

Least-privilege IAM policy for pods to read secrets.

```mermaid
graph LR
    classDef policyStyle fill:#E78F24,stroke:#fff,stroke-width:2px,color:#fff

    Policy["Read-Only Policy\nGetSecretValue\nDescribeSecret\nkms:Decrypt"] -. "Attach via IRSA" .-> Pod(("App Pod"))

    class Policy policyStyle
```

> Only specific secret ARNs are allowed (no wildcards). Also grants `kms:Decrypt` for the secrets KMS key.

---

## Step 21 — Enable GuardDuty

Continuous threat detection using ML and threat intelligence.

```mermaid
graph TD
    classDef gdStyle fill:#8C4FFF,stroke:#fff,stroke-width:2px,color:#fff

    GD["GuardDuty\nDetector"] --> F1["EKS Audit\nLog Analysis"]
    GD --> F2["Runtime\nMonitoring"]
    GD --> F3["Malware\nProtection"]

    class GD,F1,F2,F3 gdStyle
```

> Analyzes VPC flow logs, EKS audit logs, and DNS queries. Detects crypto mining, compromised credentials, and unauthorized access.

---

## Step 22 — Enable AWS Config Rules

Configuration compliance monitoring — checks if your setup follows best practices.

```mermaid
graph TD
    classDef cfgStyle fill:#8C4FFF,stroke:#fff,stroke-width:2px,color:#fff

    REC["Config\nRecorder"] --> R1["Rule: EKS\nLogging Enabled?"]
    REC --> R2["Rule: No Public\nEndpoint?"]
    REC --> R3["Rule: Secrets\nEncrypted?"]

    class REC,R1,R2,R3 cfgStyle
```

> Config Recorder tracks all resource changes. Rules evaluate compliance automatically.

---

## Full Build Summary

| Step | What Gets Created | Module | Approx Time |
|------|------------------|--------|-------------|
| 1 | VPC | VPC | ~10 sec |
| 2 | Internet Gateway | VPC | ~10 sec |
| 3 | Public Subnets ×3 | VPC | ~15 sec |
| 4 | Private Subnets ×3 | VPC | ~15 sec |
| 5 | NAT Gateway + EIP | VPC | ~2 min |
| 6 | Route Tables | VPC | ~10 sec |
| 7 | Network ACLs | VPC | ~10 sec |
| 8 | VPC Flow Logs | VPC | ~15 sec |
| 9 | Cluster IAM Role + Policies | IAM | ~15 sec |
| 10 | Node IAM Role + Policies | IAM | ~15 sec |
| 11 | KMS Key for EKS | EKS | ~10 sec |
| 12 | Security Groups + Rules | EKS | ~15 sec |
| 13 | **EKS Cluster** | EKS | **~10 min** |
| 14 | OIDC Provider | EKS | ~10 sec |
| 15 | Add-ons (CNI, proxy, DNS) | EKS | ~2 min |
| 16 | Launch Templates | EKS | ~10 sec |
| 17 | Node Groups | EKS | ~3 min |
| 18 | Secrets KMS Key | Secrets | ~10 sec |
| 19 | Secrets (DB, API, App) | Secrets | ~15 sec |
| 20 | Secrets Read Policy | Secrets | ~10 sec |
| 21 | GuardDuty + Features | Security | ~30 sec |
| 22 | Config Rules | Security | ~30 sec |
| | **Total: ~40 resources** | | **~20 min** |

> **Step 13 (EKS Cluster)** alone takes ~10 minutes — AWS provisions 3 redundant API servers across 3 AZs.

---

## Dependency Overview

```mermaid
graph LR
    classDef vpcStyle fill:#248814,stroke:#fff,stroke-width:2px,color:#fff
    classDef iamStyle fill:#DD344C,stroke:#fff,stroke-width:2px,color:#fff
    classDef eksStyle fill:#F58536,stroke:#fff,stroke-width:2px,color:#fff
    classDef smStyle fill:#E78F24,stroke:#fff,stroke-width:2px,color:#fff
    classDef secStyle fill:#8C4FFF,stroke:#fff,stroke-width:2px,color:#fff

    VPC["VPC\nSteps 1-8"] --> EKS["EKS\nSteps 11-17"]
    IAM["IAM\nSteps 9-10"] --> EKS
    SM["Secrets\nSteps 18-20"]
    SEC["Security\nSteps 21-22"]

    class VPC vpcStyle
    class IAM iamStyle
    class EKS eksStyle
    class SM smStyle
    class SEC secStyle
```

> VPC and IAM build in **parallel**. EKS needs both. Secrets Manager and Security are independent.
