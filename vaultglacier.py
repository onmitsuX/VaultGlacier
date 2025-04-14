import json
import subprocess
import argparse
import os
import boto3
import gnupg
import logging
import tempfile
import botocore.exceptions
import shutil
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

# ---------------------------
# Logging Configuration
# ---------------------------
log_handlers = [logging.StreamHandler()]
if os.getenv("LOG_TO_FILE") == "1":
    log_handlers.append(logging.FileHandler("secrets_manager.log"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=log_handlers
)
logger = logging.getLogger(__name__)

# ---------------------------
# Azure Subscription Mapping
# ---------------------------
SUBSCRIPTION_MAP = {
    "dev": os.getenv("AZURE_DEV_SUBSCRIPTION_ID"),
    "qa": os.getenv("AZURE_QA_SUBSCRIPTION_ID"),
    "uat": os.getenv("AZURE_UAT_SUBSCRIPTION_ID"),
    "prod": os.getenv("AZURE_PROD_SUBSCRIPTION_ID"),
    "infra": os.getenv("AZURE_INFRA_SUBSCRIPTION_ID"),
    "infra-dev": os.getenv("AZURE_INFRADEV_SUBSCRIPTION_ID"),
    "microsoft": os.getenv("AZURE_MICROSOFT_SUBSCRIPTION_ID"),
}

class ConfigurationError(Exception):
    pass

# ---------------------------
# Helper Functions
# ---------------------------
def get_subscription_id(environment):
    environment = environment.lower()
    if environment not in SUBSCRIPTION_MAP:
        raise ConfigurationError(f"Invalid environment: {environment}. Valid options: {', '.join(SUBSCRIPTION_MAP.keys())}")
    subscription_id = SUBSCRIPTION_MAP[environment]
    if not subscription_id:
        raise ConfigurationError(f"Subscription ID not set for environment {environment}.")
    return subscription_id

def azure_login_check():
    try:
        subprocess.run(["az", "account", "show"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logger.info("Azure login verified.")
    except subprocess.CalledProcessError:
        logger.warning("Azure login required. Initiating 'az login'...")
        try:
            subprocess.run(["az", "login"], check=True)
            logger.info("Azure login successful!")
        except subprocess.CalledProcessError:
            logger.error("Azure login failed. Please log in manually.")
            exit(1)

# ---------------------------
# Azure Key Vault Manager
# ---------------------------
class AzureKeyVaultManager:
    def __init__(self, vault_name):
        self.vault_name = vault_name
        self._verify_vault_access()

    def _verify_vault_access(self):
        try:
            subprocess.run(["az", "keyvault", "show", "--name", self.vault_name, "--only-show-errors"], check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            if "ResourceNotFound" in str(e.stderr):
                raise ConfigurationError(f"Key vault '{self.vault_name}' not found")
            elif "AuthorizationFailed" in str(e.stderr):
                raise ConfigurationError(f"No access to key vault '{self.vault_name}'")
            else:
                raise ConfigurationError(f"Failed to access key vault: {e.stderr}")

    def get_secret(self, secret_name):
        try:
            result = subprocess.run([
                "az", "keyvault", "secret", "show",
                "--vault-name", self.vault_name,
                "--name", secret_name,
                "--query", "value",
                "-o", "tsv",
                "--only-show-errors"
            ], check=True, capture_output=True, text=True)
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            error_msg = e.stderr if e.stderr else str(e)
            logger.error(f"Failed to get secret {secret_name}: {error_msg}")
            raise

    def list_secrets(self):
        try:
            result = subprocess.run([
                "az", "keyvault", "secret", "list",
                "--vault-name", self.vault_name,
                "--query", "[].name",
                "-o", "json",
                "--only-show-errors"
            ], check=True, capture_output=True, text=True)
            return json.loads(result.stdout)
        except subprocess.CalledProcessError:
            logger.error("Failed to list secrets")
            raise

    def set_secret(self, secret_name, secret_value):
        try:
            clean_secret_name = secret_name.replace("_", "-").lower()
            subprocess.run([
                "az", "keyvault", "secret", "set",
                "--vault-name", self.vault_name,
                "--name", clean_secret_name,
                "--value", secret_value,
                "--output", "none",
                "--only-show-errors"
            ], check=True, capture_output=True, text=True)
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to set secret in Key Vault: {e.stderr.strip()}")
            raise

    def pull_secrets_threaded(self, output_file):
        secrets = self.list_secrets()
        secrets_data = {}

        def fetch(secret_name):
            try:
                return secret_name, self.get_secret(secret_name)
            except Exception:
                return secret_name, None

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(fetch, s): s for s in secrets}
            for f in tqdm(as_completed(futures), total=len(futures), desc="Pulling Secrets"):
                name, value = f.result()
                if value:
                    secrets_data[name] = value

        with open(output_file, 'w') as f:
            json.dump(secrets_data, f, indent=4)

        logger.info(f"Pulled {len(secrets_data)} secrets to {output_file}")
        return output_file

# ---------------------------
# GPG Key Manager
# ---------------------------
class GPGKeyManager:
    def __init__(self):
        self.gpg_home = os.path.join(os.path.expanduser('~'), '.gnupg-temp')
        os.makedirs(self.gpg_home, exist_ok=True)
        os.environ["GNUPGHOME"] = self.gpg_home

        gpg_conf = os.path.join(self.gpg_home, 'gpg.conf')
        with open(gpg_conf, 'w') as f:
            f.write("trust-model always\n")
            f.write("no-tty\n")
            f.write("batch\n")
            f.write("yes\n")

        self.gpg = gnupg.GPG()

    def encrypt_file(self, input_file, gpg_key):
        logger.info("Importing GPG key...")
        import_result = self.gpg.import_keys(gpg_key)
        if not import_result.fingerprints:
            raise ValueError("Failed to import GPG key")

        fingerprint = import_result.fingerprints[0]
        logger.info(f"Successfully imported GPG key with fingerprint: {fingerprint}")

        output_file = f"{input_file}.gpg"

        with open(input_file, 'rb') as f:
            file_data = f.read()

        logger.info("Encrypting file using GPG...")
        encrypted_data = self.gpg.encrypt(file_data, fingerprint, always_trust=True, output=output_file, armor=False)

        if not encrypted_data.ok:
            raise Exception(f"Encryption failed: {encrypted_data.status} - {encrypted_data.stderr}")

        logger.info(f"Successfully encrypted file to: {output_file}")
        return output_file

    def cleanup(self):
        shutil.rmtree(self.gpg_home, ignore_errors=True)

# ---------------------------
# Glacier Manager
# ---------------------------
class GlacierManager:
    def __init__(self, vault_name, key_vault_manager):
        self.vault_name = vault_name
        self.key_vault_manager = key_vault_manager
        try:
            self.glacier_client = boto3.client(
                'glacier',
                aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
                aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
                aws_session_token=os.getenv('AWS_SESSION_TOKEN'),
                region_name=os.getenv('AWS_DEFAULT_REGION', 'us-east-1')
            )
            self.glacier_client.describe_vault(vaultName=self.vault_name)
        except self.glacier_client.exceptions.ResourceNotFoundException:
            logger.info(f"Creating Glacier vault: {self.vault_name}")
            self.glacier_client.create_vault(vaultName=self.vault_name)
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'ExpiredTokenException':
                logger.error("❌ AWS credentials have expired. Please refresh or re-export them.")
            else:
                logger.error(f"❌ Failed to initialize Glacier client: {str(e)}")
            raise

    def upload_to_glacier(self, file_path):
        try:
            if not os.path.exists(file_path):
                logger.error(f"File not found for upload: {file_path}")
                return False

            file_name = Path(file_path).name
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            logger.info(f"Uploading {file_name} to Glacier vault: {self.vault_name}")

            with open(file_path, 'rb') as f:
                file_data = f.read()

            with tqdm(total=len(file_data), unit='B', unit_scale=True, desc="Uploading") as pbar:
                response = self.glacier_client.upload_archive(
                    vaultName=self.vault_name,
                    body=file_data
                )
                pbar.update(len(file_data))

            archive_id = response['archiveId']
            metadata = {
                'archive_id': archive_id,
                'file_name': file_name,
                'timestamp': timestamp,
                'vault_name': self.vault_name
            }
            secret_name = f"glacier-archive-{timestamp}".lower().replace("_", "-")
            self.key_vault_manager.set_secret(secret_name, json.dumps(metadata))
            logger.info(f"✅ Successfully backed up {file_name} to Glacier.")
            logger.info(f"🔐 Archive ID stored in Azure Key Vault as: {secret_name}")
            return True
        except Exception as e:
            logger.error(f"❌ Failed to upload to Glacier: {str(e)}")
            return False

# ---------------------------
# Main Entrypoint
# ---------------------------
def main():
    parser = argparse.ArgumentParser(description="Azure Key Vault Secret Manager")
    parser.add_argument("--direction", required=True, choices=["pull", "push"], help="Direction of sync: pull or push")
    parser.add_argument("--vaultname", required=True, help="Name of the Azure Key Vault")
    parser.add_argument("--filename", required=True, help="Path to output/input JSON file")
    parser.add_argument("--env", required=True, help="Environment name (e.g. dev, prod, etc)")
    parser.add_argument("--tags", help="Optional tag filter in key==value format")
    parser.add_argument("--name", help="Optional partial name match to filter secrets")
    parser.add_argument("--encrypt", action="store_true", help="Encrypt output file with GPG")
    parser.add_argument("--backup", action="store_true", help="Backup to AWS Glacier")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    parser.add_argument("--safelog", action="store_true", help="Redact secret values from logs during push")
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    confirmation = input(f"Are you sure you want to execute a {args.direction} on environment '{args.env}'? (y/n): ").lower()
    if confirmation != 'y':
        print("Aborted by user.")
        exit(0)

    subscription_id = get_subscription_id(args.env)
    subprocess.run(["az", "account", "set", "--subscription", subscription_id], check=True)
    azure_login_check()

    vault = AzureKeyVaultManager(args.vaultname)
    gpg = GPGKeyManager()

    try:
        if args.direction == "pull":
            file_path = vault.pull_secrets_threaded(args.filename)

            if args.encrypt:
                gpg_key = vault.get_secret(os.getenv("GPG_KEY_NAME"))
                file_path = gpg.encrypt_file(file_path, gpg_key)

            if args.backup:
                glacier_vault = os.getenv("GLACIER_VAULT_NAME")
                if not glacier_vault:
                    logger.error("--backup flag used but GLACIER_VAULT_NAME not set.")
                    exit(1)
                glacier = GlacierManager(glacier_vault, vault)
                if glacier.upload_to_glacier(file_path):
                    logger.info("Backup to Glacier successful.")

        elif args.direction == "push":
            with open(args.filename, 'r') as f:
                secrets = json.load(f)
            for name, value in secrets.items():
                vault.set_secret(name, value)
                if args.safelog:
                    logger.info(f"Set secret: {name} = ****")
                else:
                    logger.info(f"Set secret: {name} = {value}")
    finally:
        gpg.cleanup()

if __name__ == "__main__":
    main()
