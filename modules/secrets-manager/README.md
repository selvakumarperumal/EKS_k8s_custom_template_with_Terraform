# Secrets Manager Module 🔑

This module sets up AWS Secrets Manager to securely store sensitive data, such as database credentials, API keys, and application configurations, outside of your source code and Kubernetes manifests.

## What it Creates 🏗️
1. **Dedicated KMS Key (`aws_kms_key`)**: A separate KMS key strictly used for encrypting these secrets, providing separation of concerns from the main cluster KMS key.
2. **Secrets (`aws_secretsmanager_secret` & `_version`)**: *Conditionally created depending on variables*.
   - **Database Credentials**: E.g., username, password, host, and port.
   - **API Keys**: E.g., external service tokens.
   - **Application Configuration**: Key-value pairs of sensitive app configurations.
3. **IAM Read Policy (`aws_iam_policy`)**: A strict least-privilege policy. It allows **read-only** access to fetch the secret values and decrypt via the specific KMS key.

## Usage Highlights 💡
- **Integration with Kubernetes**: Pods can retrieve these secrets using tools like the External Secrets Operator or the AWS Secrets Store CSI Driver.
- **Conditional Deployment**: You can enable or disable the creation of specific secrets using the `create_db_secret`, `create_api_secret`, and `create_app_config_secret` boolean variables.
- **Automated Security**: Provides encryption at rest, automatic recovery windows (to prevent accidental deletion), and the ability to integrate with AWS secret rotation features.
