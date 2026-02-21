# Security Module 🛡️

This module enables continuous threat detection and configuration compliance monitoring using AWS-native services. While the VPC, IAM, and EKS modules provide preventive controls, this module acts as the **detection layer** — your automated Security Operations Center (SOC).

---

## Architecture Diagram

```mermaid
graph TD
    classDef source fill:#F58536,stroke:#fff,stroke-width:2px,color:#fff
    classDef detect fill:#8C4FFF,stroke:#fff,stroke-width:2px,color:#fff
    classDef output fill:#DC3147,stroke:#fff,stroke-width:2px,color:#fff

    subgraph Data_Sources ["Data Sources Analyzed"]
        VPCFlow["VPC Flow Logs"]
        K8sAudit["EKS Audit Logs"]
        CloudTrail["CloudTrail Events"]
        DNS["DNS Query Logs"]
        Runtime["Container Runtime Events"]
    end

    subgraph GuardDuty_Engine ["Amazon GuardDuty"]
        ML["Machine Learning"]
        ThreatIntel["Threat Intelligence Feeds"]
        Anomaly["Anomaly Detection"]
    end

    subgraph GuardDuty_Features ["GuardDuty Feature Flags"]
        EKS_Audit["EKS Audit Log Monitoring"]
        EKS_Runtime["EKS Runtime Monitoring"]
        Malware["Malware Protection for EC2"]
    end

    Data_Sources --> GuardDuty_Engine
    GuardDuty_Engine --> Findings((Security Findings))

    EKS_Audit -.-> GuardDuty_Engine
    EKS_Runtime -.-> GuardDuty_Engine
    Malware -.-> GuardDuty_Engine

    class VPCFlow,K8sAudit,CloudTrail,DNS,Runtime source
    class GuardDuty_Engine,ML,ThreatIntel,Anomaly detect
    class Findings output
```

---

## What it Creates 🏗️

| # | Resource | Terraform Type | Purpose |
|---|----------|---------------|---------|
| 1 | **GuardDuty Detector** | `aws_guardduty_detector` | Enables threat detection service |
| 2 | **EKS Audit Log Monitoring** | GuardDuty feature | Analyzes K8s API calls for suspicious patterns |
| 3 | **EKS Runtime Monitoring** | GuardDuty feature | Detects OS-level threats on nodes |
| 4 | **Malware Protection** | GuardDuty feature | Scans EBS volumes when threats are detected |
| 5 | **Config Recorder** | `aws_config_configuration_recorder` | Records resource configuration changes |
| 6 | **Config Delivery Channel** | `aws_config_delivery_channel` | Stores config snapshots in S3 |
| 7 | **Config Rules** (×3) | `aws_config_config_rule` | Compliance checks against EKS best practices |

---

## Threat Detection (GuardDuty)

GuardDuty uses machine learning and AWS threat intelligence to detect threats in real time.

### What It Detects

| Threat Category | Example Findings |
|----------------|-----------------|
| **Unauthorized Access** | API calls from a known malicious IP |
| **Compromised Credentials** | Access keys used from an unusual geolocation |
| **Crypto Mining** | EC2 instance querying cryptocurrency mining pools |
| **Privilege Escalation** | Pod created with `hostNetwork: true` or `privileged: true` |
| **Container Escape** | Process running outside expected container namespace |
| **Data Exfiltration** | Unusual outbound data transfer volume |

---

## Compliance Monitoring (AWS Config)

```mermaid
graph LR
    classDef rule fill:#145E88,stroke:#fff,stroke-width:2px,color:#fff
    classDef pass fill:#248814,stroke:#fff,stroke-width:2px,color:#fff
    classDef fail fill:#DC3147,stroke:#fff,stroke-width:2px,color:#fff

    subgraph Config_Rules ["AWS Config Rules"]
        R1["eks-cluster-logging-enabled"]
        R2["eks-endpoint-no-public-access"]
        R3["eks-secrets-encrypted"]
    end

    R1 --> |Logging ON| Pass1(("COMPLIANT"))
    R1 --> |Logging OFF| Fail1(("NON-COMPLIANT"))

    R2 --> |Private only| Pass2(("COMPLIANT"))
    R2 --> |Public enabled| Fail2(("NON-COMPLIANT"))

    R3 --> |KMS encrypted| Pass3(("COMPLIANT"))
    R3 --> |Not encrypted| Fail3(("NON-COMPLIANT"))

    class R1,R2,R3 rule
    class Pass1,Pass2,Pass3 pass
    class Fail1,Fail2,Fail3 fail
```

| Config Rule | What It Checks | Expected State |
|-------------|---------------|----------------|
| `eks-cluster-logging-enabled` | Are all 5 control plane log types enabled? | COMPLIANT |
| `eks-endpoint-no-public-access` | Is the API server restricted from public access? | COMPLIANT (in prod) |
| `eks-secrets-encrypted` | Are K8s secrets encrypted with a KMS key? | COMPLIANT |

---

## Defense-in-Depth Strategy

This module fits into a multi-layered security architecture:

```mermaid
graph TB
    classDef layer fill:#232F3E,stroke:#fff,stroke-width:1px,color:#fff

    L1["Layer 1: Network<br/>VPC, NACLs, Security Groups"] --> L2
    L2["Layer 2: Identity<br/>IAM Roles, IRSA, OIDC"] --> L3
    L3["Layer 3: Encryption<br/>KMS, Encrypted EBS, Secrets Encryption"] --> L4
    L4["Layer 4: Logging<br/>CloudWatch, VPC Flow Logs, Audit Logs"] --> L5
    L5["Layer 5: Detection ← THIS MODULE<br/>GuardDuty, AWS Config Rules"]

    class L1,L2,L3,L4,L5 layer
```

---

## Cost Considerations

| Service | Approximate Cost | Toggle Variable |
|---------|-----------------|-----------------|
| **GuardDuty** | ~$5-15/mo (30-day free trial) | `enable_guardduty` |
| **AWS Config** | ~$3-5/mo | `enable_aws_config` |

**Kube-native alternatives** (free, open source):
- **Falco** → Runtime threat detection (replaces GuardDuty runtime monitoring)
- **OPA/Kyverno** → Policy enforcement (replaces AWS Config rules)
