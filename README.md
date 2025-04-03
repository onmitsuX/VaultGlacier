# VaultGlacier – Azure Key Vault Secrets Manager

### Overview
VaultGlacier is a Python-based tool for securely managing Azure Key Vault secrets with optional GPG encryption and AWS Glacier backup capabilities. It enables you to:

- **Pull** secrets from Azure Key Vault, encrypt them using GPG, and archive them in AWS Glacier for long-term, secure storage.
- **Push** secrets back into Azure Key Vault from a local JSON file with verification.

#### Features
- **Secure Key Vault Management** – Retrieve, validate, and store secrets safely.
- **GPG Encryption** – Protect sensitive data before exporting or archiving.
- **AWS Glacier Backup** – Upload encrypted secrets to AWS Glacier for long-term archival.
- **Azure Subscription Support** – Switch between multiple Azure environments with environment variables.
- **Tag Filtering** – Filter and pull specific secrets based on metadata tags.
- **Command-Line Interface** – Simple and scriptable usage with argparse.
- **Robust Logging** – Informative and debug logging for traceability and error handling.

### Prerequisites

#### General Requirements
- Azure Subscription with access to Key Vault
- Azure CLI installed and authenticated (`az login`)
- AWS credentials configured (for Glacier backup)
- GPG installed (if using `--encrypt`)
- Python virtual environment (`.venv`) is recommended

#### Python-Specific
* Python 3.6+ (3.11 or earlier recommended).
* GPG installed for encryption.
* boto3 (for AWS Glacier backup)
* Required Python packages:
```bash
pip install boto3 python-gnupg
```

#### PowerShell-Specific
* PowerShell 7+ installed.
* Azure CLI authentication set up.

### Environment Variables

#### Azure Configuration
```bash
export GPG_KEY_NAME="your-gpg-key-name"
```

Optional per-environment subscriptions:
```bash
export AZURE_DEV_SUBSCRIPTION_ID="your-dev-subscription-id"
export AZURE_INFRA_SUBSCRIPTION_ID="your-infra-subscription-id"
export AZURE_PROD_SUBSCRIPTION_ID="your-prod-subscription-id"
export AZURE_QA_SUBSCRIPTION_ID="your-qa-subscription-id"
export AZURE_INFRADEV_SUBSCRIPTION_ID="your-infradev-subscription-id"
export AZURE_MICROSOFT_SUBSCRIPTION_ID="your-ms-subscription-id"
export AZURE_UAT_SUBSCRIPTION_ID="your-uat-subscription-id"
```

#### AWS Configuration (for Glacier backup)
```bash
export AWS_ACCESS_KEY_ID="your-aws-access-key"
export AWS_SECRET_ACCESS_KEY="your-aws-secret-key"
export AWS_SESSION_TOKEN="your-session-token"  # optional
export AWS_DEFAULT_REGION="us-east-1"  # defaults to us-east-1 if not set
```

### Installation

Create and activate a virtual environment (recommended):
```bash
python3 -m venv .venv
source .venv/bin/activate
```

## Python CLI

#### Pulling Secrets from Azure Key Vault
Retrieve secrets and optionally encrypt and archive them to AWS Glacier:

```bash
python script.py --direction pull --vaultname your-vault-name --filename secrets.json --env prod [--tags "Environment==prod"] [--encrypt] [--backup] [--verbose]
```

#### Options:
- **--vaultname** → Specify the vault name (supports wildcards *).
- **--tags** → Filter secrets by tags ("Environment=prod" "Team=DevOps").
- **--filename** → File to store secrets in JSON format.
- **--verbose** → Enable detailed output.
- **--encrypt** → Encrypt the secrets file using GPG
- **--backup** → Archive the (encrypted) file to AWS Glacier
- **--verbose** → Enable detailed output


#### Pushing Secrets to Azure Key Vault
Upload secrets from a local JSON file back into Key Vault:

```bash
python script.py --direction push --vaultname your-vault-name --filename secrets.json --env prod [--verbose]
```

#### Azure Subscription Switching:
Handled automatically via environment variable:
```bash
export AZURE_SUBSCRIPTION_ID="your-subscription-id"
```

### Encryption with GPG (--encrypt)
To encrypt the secrets file during a pull operation:

```bash
python script.py --direction pull --vaultname your-vault-name --filename secrets.json --env prod --encrypt
```

#### Requirements:
- You must store your GPG public key in Azure Key Vault as a secret (ASCII-armored, plain-text format).
- Set an environment variable pointing to that secret name:
  ```bash
  export GPG_KEY_NAME="your-gpg-key-secret-name"
  ```
- The script will fetch this key, import it, and use it to encrypt the file as secrets.json-YYYYMMDD_HHMMSS.gpg.
- Tip: If you also use --backup, the encrypted file will be uploaded to AWS Glacier and then deleted locally after upload.


### Backup to AWS Glacier (--backup)
You can automatically back up the pulled secrets file (plain or encrypted) to AWS Glacier:
```bash
python script.py --direction pull --vaultname your-vault-name --filename secrets.json --env prod --encrypt --backup
```

#### Requirements
AWS Credentials must be available as environment variables:
```bash
export AWS_ACCESS_KEY_ID="your-access-key-id"
export AWS_SECRET_ACCESS_KEY="your-secret-access-key"
export AWS_SESSION_TOKEN="your-session-token"        # optional, if using temporary credentials
export AWS_DEFAULT_REGION="us-east-1"                # required for Glacier
```
The file will be uploaded to a pre-configured Glacier vault named:
keyvault-backup

**After upload:**
- The AWS Glacier archive ID and metadata (file name, timestamp, vault name) are saved as a new secret in Azure Key Vault.
- The encrypted (or plain) file will be deleted from disk for security.
- **Pro tip:** Combine --encrypt and --backup to securely archive GPG-encrypted secrets.
  

#### Verbose Mode
Enable detailed debug output for troubleshooting:
```bash
python script.py --direction pull --vaultname your-vault-name --filename secrets.json --env prod --verbose
```


<hr>


## PowerShell CLI

#### Pulling Secrets from Azure Key Vault
```powershell
.\script.ps1 -Direction pull -VaultName 'vaultnamegoeshere' -Tags "Environment=='taggoeshere'" -Filename "output.json"
```

#### Options:
- **-VaultName** → Vault name (supports wildcards *).
- **-Tags** → Filter by tags ("Environment=prod").
- **-Filename** → Output file in JSON format.
- **-Env** → Environment to determine Azure subscription (e.g., dev, qa, prod).
- **-Tags** → Filter secrets by tag (e.g., "Environment==prod").
- **-Encrypt** → Encrypt output using GPG (requires GPG_KEY_NAME secret).
- **-Backup** → Upload the (encrypted) file to AWS Glacier.
- **-Verbose** → Enables detailed debug output to script.log.
- **-Force** → Skip confirmation prompt before execution.


#### Pushing Secrets to Azure Key Vault
```powershell
.\script.ps1 -Direction push -VaultName 'vaultnamegoeshere'  -Filename "secrets.json" -Env 'prod' -Verbose
```

#### Azure Subscription Switching
Handled automatically based on the -Env parameter. Set your environment variables:

```powershell
$env:AZURE_PROD_SUBSCRIPTION_ID="sub-id-here"
$env:AZURE_PROD_SUBSCRIPTION_ID="sub-id-here"
```

### Encryption with GPG (-Encrypt)
To encrypt the secrets file when pulling secrets:

```powershell
.\script.ps1 -Direction pull -VaultName 'vaultnamegoeshere' -Filename 'secrets.json' -Env 'prod' -Encrypt
```

#### Requirements:
- Store your GPG public key (ASCII-armored) as a secret in Azure Key Vault.
- Set the environment variable GPG_KEY_NAME to the name of that Key Vault secret:

```powershell
$env:GPG_KEY_NAME = "your-gpg-public-key-secret-name"
```

The script will:
- Retrieve the key from Azure Key Vault.
- Import it temporarily to a GPG environment.
- Encrypt the pulled secrets into a file named secrets.json-YYYYMMDD_HHMMSS.gpg.


### Backup to AWS Glacier (-Backup)
To automatically back up the pulled (and optionally encrypted) secrets file to AWS Glacier:
```powershell
.\script.ps1 -Direction pull -VaultName 'vaultnamegoeshere' -Filename 'secrets.json' -Env 'prod' -Encrypt -Backup
```

#### Requirements
- AWS credentials must be available in environment variables:
```powershell
$env:AWS_ACCESS_KEY_ID = "your-access-key-id"
$env:AWS_SECRET_ACCESS_KEY = "your-secret-key"
$env:AWS_SESSION_TOKEN = "your-session-token" # if applicable
$env:AWS_DEFAULT_REGION = "us-east-1" # or your desired region
```

After uploading, the script:
- Stores the archive ID and metadata back in Azure Key Vault.
- Deletes the local encrypted and/or plain secrets file to maintain confidentiality.

#### Verbose Mode
Enable detailed output:
```powershell
.\script.ps1 -Direction pull -VaultName 'vaultnamegoeshere' -Filename "output.json" -Env 'prod' -Verbose
```

Logs will be saved to **script.log**


### Security & Best Practices

#### Secure Data Handling
- GPG encryption protects files before storage or upload
- Avoid displaying secret values in logs.
- Temporary GPG directories used with cleanup.

#### Operational Best Practices
- Use tag filtering for efficient secret management.
- Rotate GPG keys periodically.
- Monitor AWS Glacier usage and storage cost
- Use Azure CLI authentication to manage access.
- Limit verbose mode usage in production.

#### Error Handling & Debugging
- Enable verbose mode for additional logs.
- Ensure Azure Key Vault permissions are correctly assigned.
- Verify GPG key and AWS credentials before running the script.
- Informative logging for failures (e.g., missing subscriptions, GPG key import issues)

#### Future Enhancements
- Multi-cloud support (GCP Secrets Manager, AWS Secrets Manager)
- Automated key rotation: Scheduled key lifecycle management.
- Webhook triggers for auto-updates and compliance enforcement
- Terraform module integration

#### License
This project is open-source and available under the **MIT License**.
