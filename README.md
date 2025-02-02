# VaultGlacier – Azure Key Vault Secrets Manager

## Overview
VaultGlacier is a Python and PowerShell-based tool for securely managing Azure Key Vault secrets with GPG encryption and AWS Glacier backup capabilities. It enables you to:

* Pull secrets from **Azure Key Vault**, encrypt them with **GPG**, and archive them in **AWS S3 Glacier** for long-term storage.
* Push secrets back to **Azure Key Vault** securely.

## Features
* **Secure Key Vault Management** – Retrieve and store secrets safely.
* **GPG Encryption** – Protect sensitive data before storage.
* **AWS Glacier Backup** – Long-term archival storage in S3 Glacier.
* **Azure Subscription Support** – Easily switch between multiple Azure subscriptions.
* **Tag Filtering & Wildcards** – Retrieve specific secrets efficiently.
* **Cross-Platform Support** – Works with Python (CLI) and PowerShell.

## Prerequisites

### General Requirements
* Azure Subscription with access to Key Vault.
* Azure CLI installed and authenticated.
* AWS credentials configured for Glacier backup.

### Python-Specific
* Python 3.6+ (3.11 or earlier recommended).
* GPG installed for encryption.
* Required Python packages:
```bash
pip install boto3 python-gnupg
```

### PowerShell-Specific
* PowerShell 7+ installed.
* Azure CLI authentication set up.

## Environment Variables

### Azure Configuration
```bash
export AZURE_SUBSCRIPTION_ID="your-default-subscription-id"
export AZURE_KEYVAULT_NAME="your-keyvault-name"
export GPG_KEY_NAME="your-gpg-key-name"
```

Optional per-environment subscriptions:
```bash
export AZURE_DEV_SUBSCRIPTION_ID="your-dev-subscription-id"
export AZURE_PROD_SUBSCRIPTION_ID="your-prod-subscription-id"
```

### AWS Configuration
```bash
export AWS_ACCESS_KEY_ID="your-aws-access-key"
export AWS_SECRET_ACCESS_KEY="your-aws-secret-key"
export AWS_SESSION_TOKEN="your-session-token"  # optional
export AWS_DEFAULT_REGION="us-east-1"  # defaults to us-east-1 if not set
```

## Usage

### Python CLI

#### Pulling Secrets from Azure Key Vault
Retrieve secrets and encrypt them before archiving to AWS Glacier.

```bash
python script.py --direction pull --vaultname your-vault-name --filename secrets.json --env prod [--tags "Environment==prod"] [--verbose]
```

**Options:**
* **--vaultname** → Specify the vault name (supports wildcards *).
* **--tags** → Filter secrets by tags ("Environment=prod" "Team=DevOps").
* **--filename** → File to store secrets in JSON format.
* **--verbose** → Enable detailed output.

#### Pushing Secrets to Azure Key Vault
Upload secrets from a JSON file back to Azure Key Vault.

```bash
python script.py --direction push --vaultname your-vault-name --filename secrets.json --env prod
```

Subscription switching:
```bash
export AZURE_SUBSCRIPTION_ID="your-subscription-id"
```

### PowerShell CLI

#### Pulling Secrets from Azure Key Vault
```powershell
.\script.ps1 -Direction pull -VaultName 'vaultnamegoeshere' -Tags "Environment=='taggoeshere'" -Filename "output.json"
```

**Options:**
* **-VaultName** → Vault name (supports wildcards *).
* **-Tags** → Filter by tags ("Environment=prod").
* **-Filename** → Output file in JSON format.

#### Pushing Secrets to Azure Key Vault
```powershell
.\script.ps1 -Direction push -VaultName 'vaultnamegoeshere' -Filename "secrets.json"
```

#### Azure Subscription Switching
```powershell
$env:AZURE_SUBSCRIPTION_ID="your_subscription_id"
```
or
```powershell
.\script.ps1 -Subscription 'your_subscription_id'
```

#### Verbose Mode
Enable verbose output:
```powershell
.\script.ps1 -Direction pull -VaultName 'vaultnamegoeshere' -Filename "output.json" -Verbose
```

## Security & Best Practices

### ✔ Secure Data Handling
* GPG encrypts secrets before storage.
* Avoid displaying secret values in logs.
* Enable Azure Key Vault access monitoring.

### ✔ Operational Best Practices
* Use tag filtering for efficient secret management.
* Rotate GPG keys periodically.
* Monitor AWS Glacier storage costs.
* Use Azure CLI authentication to manage access.
* Limit verbose mode usage in production.

### ✔ Error Handling & Debugging
* Enable --verbose mode for additional logs.
* Ensure Azure Key Vault permissions are correctly assigned.
* Verify GPG key and AWS credentials before running the script.

## Future Enhancements
* Multi-cloud support: Extend to Google Cloud secrets management.
* Automated key rotation: Scheduled key lifecycle management.
* Webhook support: Trigger automated secret updates.

## License
This project is open-source and available under the **MIT License**.
