# Bootstrap Module for Terraform State Management 🌱

This directory contains the foundational Terraform code to create an S3 bucket and DynamoDB table for managing Terraform remote state and state-locking securely.

## Why Bootstrap?
Before deploying the main EKS infrastructure, we need a secure and central place to store the `terraform.tfstate` file. Storing state locally is risky, especially when working in a team or CI/CD environment.

## What it Creates 🏗️
1. **S3 Bucket (`aws_s3_bucket`)**: Stores the Terraform state file.
   - **Versioning Enabled**: Keeps a history of all state changes so you can recover if something breaks or corrupts the state.
   - **Encryption at Rest**: Ensures the state file (which may contain sensitive plan data) is AES256 encrypted.
   - **Public Access Blocked**: Guarantees the bucket can never be accidentally exposed to the internet.
   - **Prevent Destroy**: Includes a lifecycle rule to prevent accidental deletion via `terraform destroy`.
2. **DynamoDB Table (`aws_dynamodb_table`)**: Provides state locking.
   - Using the `LockID` hash key, it ensures only one person/process can run Terraform changes at any given time, preventing state corruption from concurrent runs.

## How to Apply
To set up remote state, you must run this bootstrap code **first**:
```bash
cd bootstrap
terraform init
terraform apply
```

After this is applied, you configure the `backend "s3"` block in your main architecture code to point to the newly created S3 Bucket and DynamoDB table.
