# Secrets Manager Module 🔑

This module sets up AWS Secrets Manager to securely store sensitive data — database credentials, API keys, and application configurations — outside of your source code and Kubernetes manifests.

---

## Architecture Diagram

```mermaid
graph LR
    classDef k8sStyle fill:#326CE5,stroke:#fff,stroke-width:2px,color:#fff
    classDef awsStyle fill:#DC3147,stroke:#fff,stroke-width:2px,color:#fff
    classDef keyStyle fill:#E78F24,stroke:#fff,stroke-width:2px,color:#fff

    subgraph EKS_Cluster ["EKS Cluster"]
        Pod(("App Pod"))
        SA["ServiceAccount with IRSA"]
        ESO["External Secrets Operator"]
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
        ReadAction["secretsmanager:GetSecretValue"]
        DecryptAction["kms:Decrypt"]
    end

    IAM_Policy -.-> SA

    class Pod,SA,ESO k8sStyle
    class DB_Secret,API_Secret,App_Secret,ReadAction,DecryptAction awsStyle
    class KMS keyStyle
```

---

## What it Creates 🏗️

| # | Resource | Terraform Type | Condition | Purpose |
|---|----------|---------------|-----------|---------|
| 1 | **KMS Key** | `aws_kms_key` | Always | Dedicated encryption key for secrets |
| 2 | **KMS Alias** | `aws_kms_alias` | Always | Human-readable name for the key |
| 3 | **DB Secret** | `aws_secretsmanager_secret` | `create_db_secret = true` | Stores database credentials |
| 4 | **API Secret** | `aws_secretsmanager_secret` | `create_api_secret = true` | Stores external API keys |
| 5 | **App Config Secret** | `aws_secretsmanager_secret` | `create_app_config_secret = true` | Stores app key-value config |
| 6 | **IAM Read Policy** | `aws_iam_policy` | Always | Least-privilege read-only access to secrets |

---

## Detailed Resource Walkthrough

### 1. Dedicated KMS Key

A separate KMS key is created exclusively for Secrets Manager, following the principle of **separation of duties** from the EKS cluster's KMS key.

```hcl
resource "aws_kms_key" "secrets" {
  description             = "${var.name_prefix}-secrets-key"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = var.tags
}

resource "aws_kms_alias" "secrets" {
  name          = "alias/${var.name_prefix}-secrets"
  target_key_id = aws_kms_key.secrets.key_id
}
```

| KMS Key | Encrypts | Managed By |
|---------|----------|------------|
| **EKS KMS Key** | Kubernetes secrets in `etcd` | EKS module |
| **Secrets Manager KMS Key** | Application secrets in Secrets Manager | This module |

---

### 2. Secrets (Conditionally Created)

Each secret is only provisioned when its flag is explicitly set to `true`.

```hcl
# Database credentials secret
resource "aws_secretsmanager_secret" "db" {
  count       = var.create_db_secret ? 1 : 0
  name_prefix = "${var.name_prefix}-db-"
  kms_key_id  = aws_kms_key.secrets.arn

  recovery_window_in_days = 7   # Prevents accidental permanent deletion
}

resource "aws_secretsmanager_secret_version" "db" {
  count     = var.create_db_secret ? 1 : 0
  secret_id = aws_secretsmanager_secret.db[0].id

  secret_string = jsonencode({
    username = var.db_username
    password = var.db_password
    engine   = var.db_engine
    host     = var.db_host
    port     = var.db_port
    dbname   = var.db_name
  })
}
```

**Secret JSON structure examples:**

```json
// Database Credentials
{
  "username": "admin",
  "password": "super-secret-password",
  "engine": "postgres",
  "host": "mydb.cluster-xxx.rds.amazonaws.com",
  "port": 5432,
  "dbname": "myapp"
}
```

```json
// API Keys
{ "api_key": "key-abc123", "api_secret": "secret-xyz789" }
```

---

### 3. Least-Privilege IAM Policy

A strict read-only policy that grants access only to the specific secrets and KMS key created by this module.

```hcl
resource "aws_iam_policy" "secrets_read" {
  name_prefix = "${var.name_prefix}-secrets-read-"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowGetSecretValue"
        Effect = "Allow"
        Action = ["secretsmanager:GetSecretValue"]
        Resource = [for s in aws_secretsmanager_secret.db : s.arn]
      },
      {
        Sid    = "AllowKMSDecrypt"
        Effect = "Allow"
        Action = ["kms:Decrypt"]
        Resource = [aws_kms_key.secrets.arn]
      }
    ]
  })
}
```

---

## How a Pod Retrieves a Secret

```mermaid
sequenceDiagram
    participant Pod as App Pod
    participant SA as K8s ServiceAccount
    participant OIDC as EKS OIDC Provider
    participant IAM as AWS IAM
    participant SM as Secrets Manager
    participant KMS as KMS

    Pod->>SA: 1. Uses ServiceAccount token
    SA->>OIDC: 2. Present OIDC token
    OIDC->>IAM: 3. Exchange for AWS credentials
    IAM-->>Pod: 4. Temporary credentials returned
    Pod->>SM: 5. GetSecretValue
    SM->>KMS: 6. Decrypt secret with KMS key
    KMS-->>SM: 7. Decrypted data
    SM-->>Pod: 8. Secret value delivered
```

---

## Conditional Creation

Secrets are **only created when explicitly enabled**:

```mermaid
graph TD
    classDef onStyle fill:#248814,stroke:#fff,stroke-width:2px,color:#fff
    classDef offStyle fill:#666,stroke:#fff,stroke-width:2px,color:#fff

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

    class DB_Created,API_Created,App_Created onStyle
    class DB_Skip,API_Skip,App_Skip offStyle
```

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
