# Security Module 🛡️

This module enables continuous threat detection and configuration compliance monitoring using AWS-native services. While the VPC, IAM, and EKS modules provide preventive controls, this module acts as the **detection layer** — your automated Security Operations Center (SOC).

---

## Architecture Diagram

```mermaid
graph TD
    classDef sourceStyle fill:#F58536,stroke:#fff,stroke-width:2px,color:#fff
    classDef detectStyle fill:#8C4FFF,stroke:#fff,stroke-width:2px,color:#fff
    classDef outputStyle fill:#DC3147,stroke:#fff,stroke-width:2px,color:#fff

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

    Data_Sources --> GuardDuty_Engine
    GuardDuty_Engine --> Findings(("Security Findings"))

    class VPCFlow,K8sAudit,CloudTrail,DNS,Runtime sourceStyle
    class GuardDuty_Engine,ML,ThreatIntel,Anomaly detectStyle
    class Findings outputStyle
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

## Detailed Resource Walkthrough

### 1. Amazon GuardDuty

Intelligent threat detection that analyzes metadata to identify suspicious activity.

```hcl
resource "aws_guardduty_detector" "main" {
  count  = var.enable_guardduty ? 1 : 0
  enable = true

  datasources {
    kubernetes {
      audit_logs {
        enable = true   # Monitor K8s API calls
      }
    }

    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true   # Scan EBS when a threat is found
        }
      }
    }
  }
}
```

**What it detects:**

| Threat Category | Example Findings |
|----------------|-----------------|
| **Unauthorized Access** | API calls from a known malicious IP |
| **Compromised Credentials** | Access keys used from an unusual geolocation |
| **Crypto Mining** | EC2 instance querying cryptocurrency mining pools |
| **Privilege Escalation** | Pod created with `hostNetwork: true` or `privileged: true` |
| **Container Escape** | Process running outside expected container namespace |
| **Data Exfiltration** | Unusual outbound data transfer volume |

---

### 2. AWS Config and Compliance Rules

Continuously records resource configurations and evaluates them against best practices.

```hcl
resource "aws_config_configuration_recorder" "main" {
  count    = var.enable_config ? 1 : 0
  name     = "${var.cluster_name}-recorder"
  role_arn = aws_iam_role.config[0].arn

  recording_group {
    all_supported = true
  }
}

# Rule: EKS Cluster Logging must be enabled
resource "aws_config_config_rule" "eks_logging" {
  count = var.enable_config ? 1 : 0
  name  = "${var.cluster_name}-eks-logging-enabled"

  source {
    owner             = "AWS"
    source_identifier = "EKS_CLUSTER_LOGGING_ENABLED"
  }
}

# Rule: EKS endpoint should not be publicly accessible
resource "aws_config_config_rule" "eks_endpoint" {
  count = var.enable_config ? 1 : 0
  name  = "${var.cluster_name}-eks-no-public-endpoint"

  source {
    owner             = "AWS"
    source_identifier = "EKS_ENDPOINT_NO_PUBLIC_ACCESS"
  }
}

# Rule: EKS secrets must be encrypted
resource "aws_config_config_rule" "eks_secrets" {
  count = var.enable_config ? 1 : 0
  name  = "${var.cluster_name}-eks-secrets-encrypted"

  source {
    owner             = "AWS"
    source_identifier = "EKS_SECRETS_ENCRYPTED"
  }
}
```

### Compliance Rule Results

```mermaid
graph LR
    classDef ruleStyle fill:#145E88,stroke:#fff,stroke-width:2px,color:#fff
    classDef passStyle fill:#248814,stroke:#fff,stroke-width:2px,color:#fff
    classDef failStyle fill:#DC3147,stroke:#fff,stroke-width:2px,color:#fff

    R1["eks-cluster-logging-enabled"] --> Pass1(("COMPLIANT"))
    R2["eks-endpoint-no-public-access"] --> Fail2(("NON-COMPLIANT"))
    R3["eks-secrets-encrypted"] --> Pass3(("COMPLIANT"))

    class R1,R2,R3 ruleStyle
    class Pass1,Pass3 passStyle
    class Fail2 failStyle
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
    classDef layerStyle fill:#232F3E,stroke:#fff,stroke-width:1px,color:#fff

    L1["Layer 1: Network - VPC, NACLs, Security Groups"] --> L2
    L2["Layer 2: Identity - IAM Roles, IRSA, OIDC"] --> L3
    L3["Layer 3: Encryption - KMS, Encrypted EBS, Secrets Encryption"] --> L4
    L4["Layer 4: Logging - CloudWatch, VPC Flow Logs, Audit Logs"] --> L5
    L5["Layer 5: Detection - THIS MODULE - GuardDuty, AWS Config Rules"]

    class L1,L2,L3,L4,L5 layerStyle
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
