# Root `main.tf` — Module Orchestration Guide

The root `main.tf` is the **brain** of this Terraform project. It doesn't create any AWS resources directly — instead, it calls the 5 child modules and wires their inputs and outputs together to form a complete, secure EKS cluster.

---

## Module Dependency Flow

Terraform automatically resolves the dependency order based on the data flowing between modules. Here is the exact execution graph:

```mermaid
flowchart TD
    classDef data fill:#8C4FFF,stroke:#fff,stroke-width:2px,color:#fff
    classDef mod fill:#F58536,stroke:#fff,stroke-width:2px,color:#fff
    classDef independent fill:#248814,stroke:#fff,stroke-width:2px,color:#fff

    DS["Data Sources<br/>(AZs, Caller Identity)"]

    DS --> VPC["VPC Module"]
    DS --> IAM["IAM Module"]

    VPC -- "vpc_id, private_subnet_ids" --> EKS["EKS Module"]
    IAM -- "cluster_role_arn, node_role_arn" --> EKS

    EKS --> SM["Secrets Manager Module"]
    EKS --> SEC["Security Module"]

    class DS data
    class VPC,IAM independent
    class EKS,SM,SEC mod
```

> **VPC** and **IAM** have no dependencies on each other — Terraform creates them **in parallel** to save time. The **EKS** module waits for both to finish because it needs their outputs.

---

## What's in This File

### 1. Data Sources

These **read** information from AWS without creating anything.

| Data Source | What It Returns | Used By |
|-------------|----------------|---------|
| `aws_availability_zones.available` | List of healthy AZs in the region (e.g., `ap-south-1a, 1b, 1c`) | VPC module (subnet distribution) |
| `aws_caller_identity.current` | AWS account ID, ARN of the caller | IAM policies, KMS key policies |

---

### 2. VPC Module Call

```mermaid
graph LR
    classDef input fill:#145E88,stroke:#fff,stroke-width:2px,color:#fff
    classDef output fill:#248814,stroke:#fff,stroke-width:2px,color:#fff

    subgraph Inputs ["Inputs Passed In"]
        I1["cluster_name → name_prefix"]
        I2["vpc_cidr → 10.0.0.0/16"]
        I3["azs → slice(AZs, 0, 3)"]
        I4["private/public subnets"]
        I5["EKS subnet tags"]
    end

    VPC["module.vpc"]

    subgraph Outputs ["Outputs Used By EKS"]
        O1["vpc_id"]
        O2["private_subnets"]
    end

    Inputs --> VPC --> Outputs

    class I1,I2,I3,I4,I5 input
    class O1,O2 output
```

**Key detail**: The `slice(data.aws_availability_zones.available.names, 0, 3)` function takes only the first 3 AZs, ensuring we always create exactly 3 subnets regardless of how many AZs the region offers.

**Subnet tags** are functional, not decorative:
- `kubernetes.io/role/elb = 1` → AWS Load Balancer Controller places public ALBs in these subnets.
- `kubernetes.io/role/internal-elb = 1` → Internal NLBs go here.
- `kubernetes.io/cluster/<name> = shared` → Marks the subnet as belonging to this cluster.

---

### 3. IAM Module Call

```mermaid
graph LR
    classDef input fill:#145E88,stroke:#fff,stroke-width:2px,color:#fff
    classDef output fill:#248814,stroke:#fff,stroke-width:2px,color:#fff

    subgraph Inputs ["Inputs"]
        I1["cluster_name"]
    end

    IAM["module.iam"]

    subgraph Outputs ["Outputs Used By EKS"]
        O1["cluster_role_arn"]
        O2["node_group_role_arn"]
    end

    Inputs --> IAM --> Outputs

    class I1 input
    class O1,O2 output
```

This module has **no dependency on VPC**. Terraform creates IAM roles in parallel with networking, cutting provisioning time.

---

### 4. EKS Module Call

This is the largest module call. It consumes outputs from both VPC and IAM.

```mermaid
graph TD
    classDef input fill:#145E88,stroke:#fff,stroke-width:2px,color:#fff
    classDef output fill:#248814,stroke:#fff,stroke-width:2px,color:#fff

    subgraph From_VPC ["From VPC Module"]
        V1["module.vpc.vpc_id"]
        V2["module.vpc.private_subnets"]
    end

    subgraph From_IAM ["From IAM Module"]
        R1["module.iam.cluster_role_arn"]
        R2["module.iam.node_group_role_arn"]
    end

    subgraph Config ["Direct Variables"]
        C1["cluster_name"]
        C2["kubernetes_version"]
        C3["endpoint access settings"]
        C4["node_groups map"]
    end

    EKS["module.eks"]

    From_VPC --> EKS
    From_IAM --> EKS
    Config --> EKS

    subgraph Outputs ["EKS Outputs"]
        O1["cluster_endpoint"]
        O2["cluster_name"]
        O3["oidc_provider_arn"]
    end

    EKS --> Outputs

    class V1,V2,R1,R2,C1,C2,C3,C4 input
    class O1,O2,O3 output
```

**`depends_on = [module.iam]`**: This explicit dependency is necessary because Terraform's implicit dependency tracking doesn't always catch the IAM → EKS relationship (the cluster needs roles to exist before it can assume them).

**Node Groups**: Two node groups are defined inline:

| Group | Type | Instances | Scaling | Taint |
|-------|------|-----------|---------|-------|
| `general` | ON_DEMAND | `t3.medium` | 2→4 | None |
| `spot` | SPOT | `t3.medium`, `t3a.medium` | 1→3 | `spot=true:NoSchedule` |

---

### 5. Secrets Manager Module Call

```mermaid
graph LR
    classDef input fill:#145E88,stroke:#fff,stroke-width:2px,color:#fff
    classDef output fill:#248814,stroke:#fff,stroke-width:2px,color:#fff

    subgraph Inputs ["Inputs"]
        I1["name_prefix"]
        I2["create flags (db/api/app)"]
        I3["credential values"]
    end

    SM["module.secrets_manager"]

    subgraph Outputs ["Outputs"]
        O1["secret_arns"]
        O2["read_policy_arn"]
    end

    Inputs --> SM --> Outputs

    class I1,I2,I3 input
    class O1,O2 output
```

**All secrets are disabled by default**. To create them, set the corresponding `enable_*` flags in `terraform.tfvars`.

**Sensitive variables** (`db_password`, `api_key`, `api_secret`, `app_config`) are marked with `sensitive = true` in `variables.tf`, meaning Terraform redacts their values from `plan` and `apply` output.

---

### 6. Security Module Call

```mermaid
graph LR
    classDef input fill:#145E88,stroke:#fff,stroke-width:2px,color:#fff
    classDef output fill:#248814,stroke:#fff,stroke-width:2px,color:#fff

    subgraph Inputs ["Inputs"]
        I1["cluster_name"]
        I2["enable_guardduty"]
        I3["enable_config"]
    end

    SEC["module.security"]

    subgraph Outputs ["Outputs"]
        O1["guardduty_detector_id"]
        O2["config_recorder_id"]
    end

    Inputs --> SEC --> Outputs

    class I1,I2,I3 input
    class O1,O2 output
```

This module is **independent** of all others and can be created in parallel. It monitors the infrastructure without interfering with it.

---

## Summary: How Data Flows Through the System

```mermaid
graph TD
    classDef data fill:#8C4FFF,stroke:#fff,stroke-width:2px,color:#fff
    classDef flow fill:#145E88,stroke:#fff,stroke-width:2px,color:#fff

    AZ["AZ Data"] --> VPC
    VPC -- "vpc_id" --> EKS
    VPC -- "private_subnet_ids" --> EKS
    IAM -- "cluster_role_arn" --> EKS
    IAM -- "node_group_role_arn" --> EKS
    
    Variables["terraform.tfvars"] --> VPC
    Variables --> IAM
    Variables --> EKS
    Variables --> SM
    Variables --> SEC

    EKS -- "OIDC Provider" --> IRSA["IRSA for Pods"]
    SM -- "read_policy_arn" --> IRSA
    IRSA --> AppPod(("Application Pod"))

    class AZ,Variables data
    class VPC,IAM,EKS,SM,SEC flow
```
