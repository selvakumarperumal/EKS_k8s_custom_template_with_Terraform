# Security Module 🛡️

This module enhances the cluster's security posture by enabling continuous threat detection and configuration compliance monitoring using AWS-native services. While network and IAM layers provide primary defense, this module acts as your Security Operations Center (SOC), actively searching for anomalies and misconfigurations.

## What it Creates 🏗️
1. **Amazon GuardDuty (`aws_guardduty_detector`)**: An intelligent threat detection service that analyzes metadata to identify suspicious activity.
   - **EKS Audit Log Monitoring**: Detects suspicious Kubernetes API calls (like unauthorized `exec` into pods or creation of privileged containers).
   - **EKS Runtime Monitoring**: Detects OS-level threats on worker nodes, such as process injection or crypto-mining.
   - **Malware Protection**: Scans EBS volumes for malware when triggered by a finding.
2. **AWS Config (`aws_config_configuration_recorder`)**: Continuously records resource configurations and evaluates them against best practices.
3. **AWS Config Rules (`aws_config_config_rule`)**: Automated compliance checks, specifically:
   - **EKS Cluster Logging**: Ensures all control plane logs are enabled.
   - **EKS Endpoint Public Access**: Flags if the API server is publicly accessible.
   - **EKS Secrets Encryption**: Verifies that Kubernetes secrets are encrypted with a KMS key.

## Usage Highlights 💡
- **Post-Deployment Security**: This adds an active "Detection" layer to the defense-in-depth strategy.
- **Cost Considerations**: GuardDuty charges based on the volume of logs analyzed. AWS Config charges based on recorded configuration items and rule evaluations. You can toggle these services on or off using the `enable_guardduty` and `enable_config` variables.
