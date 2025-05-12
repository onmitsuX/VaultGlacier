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
- **.env Support** – Secure environment variable loading with `python-dotenv`.

---

## Prerequisites

### General
- Azure Subscription with Key Vault access
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
pip install -r requirements.txt
```

---

## Environment Variables

#### Using ```.env ``` File
```bash
cp .env.example .env
```
Edit .env with the actual subscription ID values. The script will automatically load them by using **python-dotenv**.


### Azure Subscription IDs
```env
AZURE_DEV_SUBSCRIPTION_ID=your-dev-subscription-id
AZURE_PROD_SUBSCRIPTION_ID=your-prod-subscription-id
AZURE_QA_SUBSCRIPTION_ID=your-qa-subscription-id
AZURE_INFRA_SUBSCRIPTION_ID=your-infra-subscription-id
AZURE_INFRADEV_SUBSCRIPTION_ID=your-infradev-subscription-id
AZURE_MICROSOFT_SUBSCRIPTION_ID=your-microsoft-subscription-id
AZURE_UAT_SUBSCRIPTION_ID=your-uat-subscription-id
```

### AWS Configuration (Glacier)
```env
AWS_ACCESS_KEY_ID=your-aws-access-key
AWS_SECRET_ACCESS_KEY=your-aws-secret-key
AWS_SESSION_TOKEN=your-optional-session-token
AWS_DEFAULT_REGION=us-east-1
GLACIER_VAULT_NAME=your-glacier-vault-name
```

### GPG Key (Encrypt)
```env
GPG_KEY_NAME=your-gpg-key-secret-name
```

### Enable Logging to File
```env
LOG_TO_FILE=1
```

---

## Usage

### Pulling Secrets
```bash
python script.py --direction pull --vaultname my-vault --filename secrets.json --env dev

```

### Pushing Secrets
```bash
python script.py --direction push --vaultname my-vault --filename secrets.json --env dev

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
```env
LOG_TO_FILE=1
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

### Version Control Warning
- Ensure .env is added to .gitignore to avoid leaking credentials:
```bash
echo ".env" >> .gitignore
```

---

## License
MIT License

<hr>


### PowerShell CLI

## Overview
A secure and extensible PowerShell CLI utility to **pull or push secrets** to Azure Key Vault, with optional **GPG encryption** and **AWS Glacier backups**.

---

### Prerequisites

#### PowerShell Dependencies
* PowerShell 7+ installed.
* Azure CLI authentication set up.

---

#### Pulling Secrets from Azure Key Vault
```powershell
.\script.ps1 -Direction pull -VaultName 'vaultnamegoeshere' -Tags "Environment=='taggoeshere'" -Filename "output.json" -Env 'dev'
```
---

#### Options:
- **-VaultName** → Vault name (supports wildcards *).
- **-Tags** → Filter by tags ("Environment=prod").
- **-Filename** → Output file in JSON format.
- **-Env** → Environment to determine Azure subscription (e.g., dev, qa, prod).
- **-SecretNamePattern** → Optional partial secret name match.
- **-Encrypt** → Encrypt output using GPG (requires GPG_KEY_NAME secret).
- **-Backup** → Upload the (encrypted) file to AWS Glacier.
- **-Verbose** → Enables detailed debug output to script.log.
- **-Force** → Skip confirmation prompt before execution.

---

#### Pushing Secrets to Azure Key Vault
```powershell
.\script.ps1 -Direction push -VaultName 'vaultnamegoeshere' -Filename "secrets.json" -Env 'prod' 
```
---

#### Using ```.env``` for Environment Variables
The PowerShell version now supports automatically loading environment variables from a .env file located in the same directory as the script.

```env
AZURE_DEV_SUBSCRIPTION_ID=your-sub-id
AZURE_PROD_SUBSCRIPTION_ID=your-sub-id
GPG_KEY_NAME=your-gpg-key-secret-name
GPG_BASE64_KEY_NAME=your-base64-key-secret-name
AWS_ACCESS_KEY_ID=your-aws-access-key
AWS_SECRET_ACCESS_KEY=your-aws-secret
AWS_DEFAULT_REGION=us-east-1
GLACIER_VAULT_NAME=your-glacier-vault-name

```
These variables will be loaded automatically when you run the script.

---

#### Encryption with GPG (-Encrypt)
To encrypt the secrets file when pulling secrets:

```powershell
.\script.ps1 -Direction pull -VaultName 'vaultnamegoeshere' -Filename 'secrets.json' -Env 'prod' -Encrypt
```
**Encryption Process**
- GPG public key must be stored in Azure Key Vault (ascii-armored format or base64-encoded).
- Set the .env variable GPG_KEY_NAME or GPG_BASE64_KEY_NAME to point to the key's secret name.
- The script:
  - Downloads and imports the key temporarily.
  - Encrypts secrets to: secrets.json-YYYYMMDD_HHMMSS.gpg.
  - Deletes the plaintext file after encryption.

---

#### Backup to AWS Glacier (-Backup)
To automatically back up the pulled (and optionally encrypted) secrets file to AWS Glacier:
```powershell
.\script.ps1 -Direction pull -VaultName 'vaultnamegoeshere' -Filename 'secrets.json' -Env 'prod' -Encrypt -Backup
```

#### Requirements
- AWS credentials must be set via .env:

```.env
AWS_ACCESS_KEY_ID=your-key-id
AWS_SECRET_ACCESS_KEY=your-secret
AWS_DEFAULT_REGION=us-west-2
GLACIER_VAULT_NAME=your-vault-name
```

**Behavior**:
- Uploads encrypted file to Glacier.
- Logs archive ID for tracking.
- Cleans up encrypted and plain files from local disk.

--- 

#### Verbose Mode
Enable detailed output:
```powershell
.\script.ps1 -Direction pull -VaultName 'vaultnamegoeshere' -Filename "output.json" -Env 'prod' -Verbose
```

Logs will be saved to **script.log** and audit actions in **audit.log**.

---

### Security & Best Practices

#### Secure Data Handling
- GPG encryption protects files before storage or upload
- Avoid displaying secret values in logs (unless overridden with ALLOW_SECRET_LOGGING).
- Temporary GPG directories used with cleanup.
- Logs redact secrets unless explicitly allowed.

#### Operational Best Practices
- Use tag filtering and partial name filtering for efficient secret management.
- Rotate GPG keys periodically.
- Monitor AWS Glacier usage and storage cost
- Use Azure CLI authentication and RBAC to manage access.
- Limit verbose mode usage in production.

#### Identity Tracking
- The script logs the current Azure identity (user or service principal) executing the script for audit and compliance purposes.

#### Error Handling & Debugging
- Enable verbose mode for additional logs.
- Try/catch wrappers around Azure and AWS API calls.
- Verify GPG key and AWS credentials before running the script.
- Informative logging for missing subscriptions, failed encryption, or upload errors.

#### Future Enhancements
- Multi-cloud support (GCP Secrets Manager, AWS Secrets Manager)
- Automated key rotation and lifecycle enforcement.
- Webhook triggers or CI/CD integration.
- Integrate via Function App or Lambda function.

#### License
This project is open-source and available under the **MIT License**.

