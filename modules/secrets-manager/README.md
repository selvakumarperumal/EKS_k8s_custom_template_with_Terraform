# Secrets Manager Module 🔑

This module sets up AWS Secrets Manager to securely store sensitive data — database credentials, API keys, and application configurations — outside of your source code and Kubernetes manifests.

---

## Architecture Diagram

```mermaid
graph LR
    classDef k8s fill:#326CE5,stroke:#fff,stroke-width:2px,color:#fff
    classDef aws fill:#DC3147,stroke:#fff,stroke-width:2px,color:#fff
    classDef key fill:#E78F24,stroke:#fff,stroke-width:2px,color:#fff

    subgraph EKS_Cluster ["EKS Cluster"]
        Pod(("App Pod"))
        SA["ServiceAccount<br/>(with IRSA annotation)"]
        ESO["External Secrets Operator<br/>(or CSI Driver / SDK)"]
        Pod --> SA --> ESO
    end

    subgraph AWS_SM ["AWS Secrets Manager"]
        DB_Secret[("DB Credentials")]
        API_Secret[("API Keys")]
        App_Secret[("App Config")]
    end

    KMS["Dedicated KMS Key"] -. "Encrypts" .-> AWS_SM
    ESO -- "GetSecretValue" --> AWS_SM

    subgraph IAM_Policy ["Least-Privilege IAM Policy"]
        Read["secretsmanager:GetSecretValue"]
        Decrypt["kms:Decrypt"]
    end

    IAM_Policy -.-> SA

    class Pod,SA,ESO k8s
    class DB_Secret,API_Secret,App_Secret,Read,Decrypt aws
    class KMS key
```

---

## What it Creates 🏗️

| # | Resource | Terraform Type | Condition | Purpose |
|---|----------|---------------|-----------|---------|
| 1 | **KMS Key** | `aws_kms_key` | Always | Dedicated encryption key for secrets |
| 2 | **KMS Alias** | `aws_kms_alias` | Always | Human-readable name for the key |
| 3 | **DB Secret** | `aws_secretsmanager_secret` | `create_db_secret = true` | Stores database credentials |
| 4 | **DB Secret Value** | `aws_secretsmanager_secret_version` | `create_db_secret = true` | JSON with user, pass, host, port, engine |
| 5 | **API Secret** | `aws_secretsmanager_secret` | `create_api_secret = true` | Stores external API keys |
| 6 | **API Secret Value** | `aws_secretsmanager_secret_version` | `create_api_secret = true` | JSON with api_key, api_secret |
| 7 | **App Config Secret** | `aws_secretsmanager_secret` | `create_app_config_secret = true` | Stores app key-value config |
| 8 | **App Config Value** | `aws_secretsmanager_secret_version` | `create_app_config_secret = true` | JSON from config map |
| 9 | **IAM Read Policy** | `aws_iam_policy` | Always | Least-privilege read-only access to secrets |

---

## Secret Structure

Each secret is stored as a JSON document:

### Database Credentials
```json
{
  "username": "admin",
  "password": "super-secret-password",
  "engine": "postgres",
  "host": "mydb.cluster-xxx.rds.amazonaws.com",
  "port": 5432,
  "dbname": "myapp"
}
```

### API Keys
```json
{
  "api_key": "key-abc123",
  "api_secret": "secret-xyz789"
}
```

### Application Config
```json
{
  "LOG_LEVEL": "info",
  "FEATURE_FLAG": "true",
  "APP_ENV": "production"
}
```

---

## How a Pod Retrieves a Secret

```mermaid
sequenceDiagram
    participant Pod as App Pod
    participant SA as K8s ServiceAccount
    participant OIDC as EKS OIDC Provider
    participant IAM as AWS IAM (STS)
    participant SM as Secrets Manager
    participant KMS as KMS

    Pod->>SA: 1. Uses ServiceAccount token
    SA->>OIDC: 2. Present OIDC token
    OIDC->>IAM: 3. Exchange for AWS credentials
    IAM-->>Pod: 4. Temporary credentials returned
    Pod->>SM: 5. GetSecretValue (with temp creds)
    SM->>KMS: 6. Decrypt secret with KMS key
    KMS-->>SM: 7. Decrypted data
    SM-->>Pod: 8. Secret value delivered
```

---

## Conditional Creation

Secrets are **only created when explicitly enabled**. This prevents unnecessary resource creation and cost.

```mermaid
graph TD
    classDef on fill:#248814,stroke:#fff,stroke-width:2px,color:#fff
    classDef off fill:#666,stroke:#fff,stroke-width:2px,color:#fff

    Input["Variable Flags"]
    Input --> DB{"create_db_secret?"}
    Input --> API{"create_api_secret?"}
    Input --> App{"create_app_config_secret?"}

    DB --> |true| DB_Created["DB Secret Created"]
    DB --> |false| DB_Skip["Skipped"]
    API --> |true| API_Created["API Secret Created"]
    API --> |false| API_Skip["Skipped"]
    App --> |true| App_Created["App Config Created"]
    App --> |false| App_Skip["Skipped"]

    class DB_Created,API_Created,App_Created on
    class DB_Skip,API_Skip,App_Skip off
```

---

## Why a Dedicated KMS Key?

This module creates its **own KMS key**, separate from the EKS cluster's KMS key. This follows the principle of **separation of duties**:

| KMS Key | Encrypts | Managed By |
|---------|----------|------------|
| **EKS KMS Key** | Kubernetes secrets in `etcd` | EKS module |
| **Secrets Manager KMS Key** | Application secrets in Secrets Manager | This module |

If one key is compromised, the other remains secure.

---

## Integration Options

| Method | How It Works | Best For |
|--------|-------------|----------|
| **External Secrets Operator** | K8s operator syncs AWS secrets to K8s Secrets | GitOps workflows |
| **CSI Secrets Store Driver** | Mounts secrets as files in the pod filesystem | File-based configs |
| **AWS SDK** | Application code calls `GetSecretValue` directly | Custom logic, rotation |

---

## Cost

| Item | Cost |
|------|------|
| Each secret | ~$0.40/month |
| API calls | $0.05 per 10,000 calls |
| KMS Key | $1.00/month |
