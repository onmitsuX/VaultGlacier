# Azure Key Vault Secrets Manager

## Overview
A robust Python utility to **pull or push secrets** to Azure Key Vault with optional **GPG encryption** and **S3 Glacier backup**, now enhanced with **threading**, **file-based logging**, and **safe log redaction**.

- **Pull** secrets from Azure Key Vault, encrypt them using GPG, and archive them in AWS Glacier for long-term, secure storage.
- **Push** secrets back into Azure Key Vault from a local JSON file with verification.

## Key Features
- **Secure Key Vault Management** – Retrieve, validate, and store secrets safely.
- **GPG Encryption** – Optionally encrypt secrets using a GPG public key before backup or storage.
- **AWS Glacier Backup** – Archive secrets securely to AWS Glacier with metadata stored in Azure Key Vault.
- **Azure Subscription Support** – Automatically select subscriptions using environment-based mappings.
- **Tag & Name Filtering** – Pull only secrets that match a specified tag or contain specific substrings.
- **Threaded Secret Retrieval** – Pull secrets faster using concurrent threading (default: 5 threads).
- **Backup Progress Bar** – Visual real-time feedback when uploading to AWS Glacier.
- **Safe Logging** – Redact sensitive values in logs during push with `--safelog`.
- **Auto-cleanup** – Securely deletes temporary GPG files and encrypted files after upload.
- **Logging to File (Optional)** – Enable `LOG_TO_FILE=1` to write logs to `secrets_manager.log`.
- **Interactive Confirmation Prompt** – Prevent unintentional operations.
- **Robust Logging & Error Handling** – Traceable logs and clean failover handling.

---

## Prerequisites

### General
- Azure Subscription with Key Vault access
- Azure CLI installed and authenticated (`az login`)
- AWS credentials (for Glacier backup)
- GPG installed (if using `--encrypt`)
- Python 3.6+ (Recommended: Python 3.11 or earlier)

### Python Environment Setup
Create and activate a virtual environment:
```bash
python3 -m venv .venv
source .venv/bin/activate  # On Windows use: .venv\Scripts\activate
```

Install required packages:
```bash
pip install boto3 python-gnupg tqdm
```

---

## Environment Variables

### Azure Subscriptions
```bash
export AZURE_DEV_SUBSCRIPTION_ID="your-dev-subscription-id"
export AZURE_PROD_SUBSCRIPTION_ID="your-prod-subscription-id"
# ... other envs as needed
```

### AWS Configuration (Glacier)
```bash
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_SESSION_TOKEN="your-session-token"  # if applicable
export AWS_DEFAULT_REGION="us-east-1"
export GLACIER_VAULT_NAME="your-glacier-vault-name"
```

### GPG Key
```bash
export GPG_KEY_NAME="your-gpg-key-secret-name"
```

### Enable Logging to File
```bash
export LOG_TO_FILE=1
```

---

## Usage

### Pulling Secrets
```bash
python script.py \
  --direction pull \
  --vaultname my-vault \
  --filename secrets.json \
  --env dev \
  [--encrypt] [--backup] [--verbose] [--safelog]
```

### Pushing Secrets
```bash
python script.py \
  --direction push \
  --vaultname my-vault \
  --filename secrets.json \
  --env dev \
  [--verbose] [--safelog]
```

---

## Optional Flags

| Flag       | Description |
|------------|-------------|
| `--encrypt` | Encrypt secrets file with GPG |
| `--backup`  | Upload secrets file to AWS Glacier |
| `--safelog` | Redacts secret values in logs on push |
| `--verbose` | Enable debug-level logging |

---

## Threaded Secret Retrieval
- Secret pulls use concurrent threads with a default max of 5 workers.
- This significantly boosts performance, especially for vaults with 20+ secrets.
- Handled automatically—no flag needed.

---

## Logging to File
To save logs to a file:
```bash
export LOG_TO_FILE=1
```
Logs will be saved to `secrets_manager.log`. Combine with `--verbose` for full tracing.

---

## Safe Logging on Push
Enable safe logging to redact values:
```bash
python script.py --direction push --vaultname myvault --filename secrets.json --env dev --safelog
```
Example log:
```
Set secret: mypassword = ****
```

---

## Security & Best Practices

### Secure Data Handling
- GPG encryption protects files before upload.
- Temporary files and GPG directories are removed after use.
- Sensitive values are redacted when using `--safelog`.

### Operational Practices
- Use tags and filters to reduce scope.
- Rotate GPG keys periodically.
- Monitor AWS Glacier retention costs.
- Avoid `--verbose` in production unless debugging.

---

## License
MIT License

