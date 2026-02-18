# 🏗️ Architecture Deep Dive

This document provides detailed diagrams explaining how each component works and interconnects.

---

## Module Dependency Graph

```mermaid
graph TD
    Root["📦 Root Module<br/>main.tf"]
    
    Root --> VPC["🌐 VPC Module"]
    Root --> IAM["👤 IAM Module"]
    Root --> EKS["⚙️ EKS Module"]
    Root --> SM["🔑 Secrets Manager"]
    Root --> SEC["🛡️ Security Module"]
    
    VPC -->|vpc_id, subnet_ids| EKS
    IAM -->|cluster_role_arn, node_role_arn| EKS
    
    EKS -->|cluster_name| SM
    EKS -->|cluster_name| SEC
    
    style VPC fill:#4CAF50,color:#fff
    style IAM fill:#FF9800,color:#fff
    style EKS fill:#2196F3,color:#fff
    style SM fill:#9C27B0,color:#fff
    style SEC fill:#F44336,color:#fff
```

**Deployment Order:** VPC → IAM → EKS → Secrets Manager → Security

---

## VPC Architecture

```mermaid
graph TB
    subgraph VPC["VPC 10.0.0.0/16"]
        subgraph AZ1["Availability Zone 1"]
            PubSub1["Public Subnet<br/>10.0.1.0/24"]
            PrivSub1["Private Subnet<br/>10.0.10.0/24"]
        end
        
        subgraph AZ2["Availability Zone 2"]
            PubSub2["Public Subnet<br/>10.0.2.0/24"]
            PrivSub2["Private Subnet<br/>10.0.20.0/24"]
        end
        
        subgraph AZ3["Availability Zone 3"]
            PubSub3["Public Subnet<br/>10.0.3.0/24"]
            PrivSub3["Private Subnet<br/>10.0.30.0/24"]
        end
        
        IGW["Internet Gateway"]
        NAT["NAT Gateway + EIP"]
        
        PubRT["Public Route Table<br/>0.0.0.0/0 → IGW"]
        PrivRT["Private Route Table<br/>0.0.0.0/0 → NAT"]
    end
    
    Internet["🌐 Internet"] --> IGW
    IGW --> PubSub1
    IGW --> PubSub2
    IGW --> PubSub3
    NAT --> PrivRT
    PubSub1 --> NAT
    
    PrivSub1 -.->|VPC Flow Logs| CW["CloudWatch"]
    PrivSub2 -.->|VPC Flow Logs| CW
    PrivSub3 -.->|VPC Flow Logs| CW
```

### Network Security Layers

```mermaid
graph LR
    Traffic["Incoming Traffic"] --> NACL["NACL<br/>(Stateless)"]
    NACL --> SG["Security Group<br/>(Stateful)"]
    SG --> Instance["EC2 / Pod"]
    
    NACL -->|"Rule: DENY ALL<br/>then ALLOW specific"| NACL
    SG -->|"Rule: ALLOW specific<br/>implicit DENY ALL"| SG
```

---

## EKS Cluster Architecture

```mermaid
graph TB
    subgraph ControlPlane["EKS Control Plane (AWS Managed)"]
        API["API Server<br/>(3 replicas, 3 AZs)"]
        ETCD["etcd<br/>(KMS Encrypted)"]
        CM["Controller Manager"]
        SCHED["Scheduler"]
        AUTH["Authenticator"]
    end
    
    subgraph DataPlane["Data Plane (Customer Managed)"]
        subgraph OnDemand["On-Demand Node Group"]
            N1["Node 1<br/>t3.medium"]
            N2["Node 2<br/>t3.medium"]
        end
        
        subgraph Spot["Spot Node Group (Tainted)"]
            S1["Spot Node<br/>t3.medium"]
        end
    end
    
    subgraph Addons["EKS Managed Addons"]
        DNS["CoreDNS"]
        PROXY["kube-proxy"]
        CNI["VPC CNI"]
    end
    
    API --> N1
    API --> N2
    API --> S1
    DNS --> N1
    PROXY --> N1
    PROXY --> N2
    PROXY --> S1
    CNI --> N1
    CNI --> N2
    CNI --> S1
    
    KMS["KMS Key"] -.->|encrypts| ETCD
```

### IRSA (IAM Roles for Service Accounts) Flow

```mermaid
sequenceDiagram
    participant Pod as 🐳 Pod
    participant SA as ServiceAccount
    participant STS as AWS STS
    participant OIDC as OIDC Provider
    participant S3 as AWS S3

    Pod->>SA: 1. Uses annotated ServiceAccount
    SA->>Pod: 2. Injects OIDC token via projected volume
    Pod->>STS: 3. AssumeRoleWithWebIdentity(token)
    STS->>OIDC: 4. Validate OIDC token
    OIDC-->>STS: 5. Token valid for ServiceAccount X
    STS-->>Pod: 6. Temporary AWS credentials
    Pod->>S3: 7. Access S3 with scoped credentials
```

---

## Security Services Architecture

```mermaid
graph TB
    subgraph Monitoring["Security Monitoring Layer"]
        GD["GuardDuty<br/>Threat Detection"]
        CFG["AWS Config<br/>Compliance"]
        FL["VPC Flow Logs<br/>Network Audit"]
        CW["CloudWatch Logs<br/>Control Plane Audit"]
    end
    
    subgraph DataSources["Data Sources"]
        CT["CloudTrail Events"]
        EKSAudit["EKS Audit Logs"]
        DNS["DNS Logs"]
        VPCFlow["VPC Flow Log Data"]
    end
    
    CT --> GD
    EKSAudit --> GD
    DNS --> GD
    VPCFlow --> FL
    
    subgraph Rules["Config Rules"]
        R1["EKS Logging Enabled?"]
        R2["Public Endpoint Disabled?"]
        R3["Secrets Encrypted?"]
    end
    
    CFG --> R1
    CFG --> R2
    CFG --> R3
    
    GD -->|"Findings"| Alert["⚠️ Security Alert"]
    R1 -->|"NON_COMPLIANT"| Alert
```

---

## Encryption Architecture

```mermaid
graph LR
    subgraph KMSKeys["KMS Keys"]
        K1["EKS KMS Key<br/>(secrets encryption)"]
        K2["Secrets Mgr KMS Key<br/>(secrets at rest)"]
        K3["EBS Default Key<br/>(volume encryption)"]
    end
    
    K1 -->|encrypts| ETCD["K8s Secrets in etcd"]
    K2 -->|encrypts| SM["Secrets Manager Secrets"]
    K3 -->|encrypts| EBS["Node EBS Volumes"]
    
    K1 -.->|"Auto-rotate annually"| K1
    K2 -.->|"Auto-rotate annually"| K2
```
