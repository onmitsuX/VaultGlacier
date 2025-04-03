import json
import subprocess
import argparse
import os
import boto3
import gnupg
import logging
import tempfile
from datetime import datetime
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Subscription Mapping (with UAT included)
SUBSCRIPTION_MAP = {
    "dev": os.getenv("AZURE_DEV_SUBSCRIPTION_ID"),
    "qa": os.getenv("AZURE_QA_SUBSCRIPTION_ID"),
    "uat": os.getenv("AZURE_UAT_SUBSCRIPTION_ID"),
    "prod": os.getenv("AZURE_PROD_SUBSCRIPTION_ID"),
    "infra": os.getenv("AZURE_INFRA_SUBSCRIPTION_ID"),
    "infra-dev": os.getenv("AZURE_INFRADEV_SUBSCRIPTION_ID"),
    "microsoft": os.getenv("AZURE_MICROSOFT_SUBSCRIPTION_ID"),
}

# Standard tag schema
TAG_SCHEMA = ["Environment", "DoesRotate", "Rotation", "VendorDependant"]

class ConfigurationError(Exception):
    """Custom exception for configuration-related errors."""
    pass

def get_subscription_id(environment):
    """Retrieve subscription ID based on environment."""
    environment = environment.lower()
    if environment not in SUBSCRIPTION_MAP:
        raise ConfigurationError(
            f"Invalid environment: {environment}. Valid options: {', '.join(SUBSCRIPTION_MAP.keys())}"
        )

    subscription_id = SUBSCRIPTION_MAP[environment]
    if not subscription_id:
        raise ConfigurationError(
            f"Subscription ID not set for environment {environment}. "
            f"Set AZURE_{environment.upper()}_SUBSCRIPTION_ID environment variable."
        )

    return subscription_id

def azure_login_check():
    """Ensure the user is logged in to Azure."""
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

class AzureKeyVaultManager:
    def __init__(self, vault_name):
        self.vault_name = vault_name
        self._verify_vault_access()

    def _verify_vault_access(self):
        try:
            subprocess.run(
                [
                    "az", "keyvault", "show",
                    "--name", self.vault_name,
                    "--only-show-errors"
                ],
                check=True,
                capture_output=True,
                text=True
            )
        except subprocess.CalledProcessError as e:
            if "ResourceNotFound" in str(e.stderr):
                raise ConfigurationError(f"Key vault '{self.vault_name}' not found")
            elif "AuthorizationFailed" in str(e.stderr):
                raise ConfigurationError(f"No access to key vault '{self.vault_name}'. Check permissions.")
            else:
                raise ConfigurationError(f"Failed to access key vault: {e.stderr}")

    def get_secret(self, secret_name):
        """Get a secret from Azure Key Vault."""
        try:
            result = subprocess.run(
                [
                    "az", "keyvault", "secret", "show",
                    "--vault-name", self.vault_name,
                    "--name", secret_name,
                    "--query", "value",
                    "-o", "tsv",
                    "--only-show-errors"
                ],
                check=True,
                capture_output=True,
                text=True
            )
            if result.stderr:
                raise subprocess.CalledProcessError(1, result.args, result.stdout, result.stderr)
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            error_msg = e.stderr if e.stderr else str(e)
            if "AuthorizationFailed" in error_msg:
                logger.error("Access denied to Key Vault")
            elif "ResourceNotFound" in error_msg:
                logger.error(f"Secret not found: {secret_name}")
            else:
                logger.error("Failed to get secret from Key Vault")
            raise

    def get_secret_tags(self, secret_name):
        """Get tags for a specific secret."""
        try:
            result = subprocess.run(
                [
                    "az", "keyvault", "secret", "show",
                    "--vault-name", self.vault_name,
                    "--name", secret_name,
                    "--query", "tags",
                    "-o", "json",
                    "--only-show-errors"
                ],
                check=True,
                capture_output=True,
                text=True
            )
            if result.stderr:
                raise subprocess.CalledProcessError(1, result.args, result.stdout, result.stderr)
            tags = json.loads(result.stdout) if result.stdout.strip() else {}
            return tags
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to get tags for secret {secret_name}")
            raise

    def set_secret(self, secret_name, secret_value):
        """Set a secret in Azure Key Vault."""
        try:
            result = subprocess.run(
                [
                    "az", "keyvault", "secret", "set",
                    "--vault-name", self.vault_name,
                    "--name", secret_name,
                    "--value", secret_value,
                    "--output", "none",
                    "--only-show-errors"
                ],
                check=True,
                capture_output=True,
                text=True
            )
            if result.stderr:
                raise subprocess.CalledProcessError(1, result.args, result.stdout, result.stderr)
            return True
        except subprocess.CalledProcessError as e:
            logger.error("Failed to set secret in Key Vault")
            raise

    def pull_secrets_to_file(self, output_file, exclude_secrets=None, tag_filter=None):
        """Pull secrets to a JSON file."""
        if exclude_secrets is None:
            exclude_secrets = []
        try:
            secrets_list = self.list_secrets()
            secrets_data = {}
            filtered_count = 0
            total_count = 0
            
            logger.info(f"Found {len(secrets_list)} secrets in vault {self.vault_name}")
            
            for secret_name in secrets_list:
                total_count += 1
                if secret_name not in exclude_secrets:
                    # Get tags for the secret
                    tags = self.get_secret_tags(secret_name)
                    
                    # Apply tag filter if specified
                    if tag_filter:
                        key, value = tag_filter.split("==")
                        if not tags or tags.get(key) != value:
                            logger.debug(f"Skipping secret {secret_name} due to tag filter (expecting {key}=={value})")
                            filtered_count += 1
                            continue
                    
                    value = self.get_secret(secret_name)
                    secrets_data[secret_name] = value
                    
                    if logger.getEffectiveLevel() == logging.DEBUG:
                        logger.debug(f"Secret {secret_name} tags: {tags}")
                else:
                    logger.debug(f"Skipping excluded secret: {secret_name}")
                    filtered_count += 1
            
            with open(output_file, "w") as f:
                json.dump(secrets_data, f, indent=4)
                
            logger.info(f"Pulled {len(secrets_data)} secrets to {output_file}")
            logger.info(f"Filtered out {filtered_count} of {total_count} total secrets")
            
            return output_file
        except Exception as e:
            logger.error(f"Failed to pull secrets to file: {str(e)}")
            raise

    def list_secrets(self):
        """List all secrets in the vault."""
        try:
            result = subprocess.run(
                [
                    "az", "keyvault", "secret", "list",
                    "--vault-name", self.vault_name,
                    "--query", "[].name",
                    "-o", "json",
                    "--only-show-errors"
                ],
                check=True,
                capture_output=True,
                text=True
            )
            if result.stderr:
                raise subprocess.CalledProcessError(1, result.args, result.stdout, result.stderr)
            return json.loads(result.stdout)
        except subprocess.CalledProcessError as e:
            logger.error("Failed to list secrets")
            raise

    def validate_tag_schema(self, tags):
        """Validate tags against the standard schema."""
        missing_tags = [tag for tag in TAG_SCHEMA if tag not in tags]
        if missing_tags:
            logger.warning(f"Missing standard tags: {', '.join(missing_tags)}")
            return False
        return True

class GPGKeyManager:
    def __init__(self):
        # Create a custom GPG home directory for this operation
        self.gpg_home = os.path.join(os.path.expanduser('~'), '.gnupg-temp')
        if not os.path.exists(self.gpg_home):
            os.makedirs(self.gpg_home, mode=0o700)
        
        # Create a gpg.conf file to disable compliance mode
        gpg_conf = os.path.join(self.gpg_home, 'gpg.conf')
        with open(gpg_conf, 'w') as f:
            f.write("no-compliance-mode\n")
            f.write("trust-model always\n")
            f.write("no-tty\n")
            f.write("batch\n")
            f.write("yes\n")

        # Initialize GPG with the correct parameter name
        self.gpg = gnupg.GPG(homedir=self.gpg_home)
        
    def encrypt_file(self, input_file, gpg_key):
        """Encrypt a file using GPG."""
        try:
            # Import the key
            logger.info("Importing GPG key...")
            import_result = self.gpg.import_keys(gpg_key)
            if not import_result.fingerprints:
                raise ValueError("Failed to import GPG key")
            
            fingerprint = import_result.fingerprints[0]
            logger.info(f"Successfully imported GPG key with fingerprint: {fingerprint}")

            # List available keys for verification
            logger.info("Available keys:")
            public_keys = self.gpg.list_keys()
            for key in public_keys:
                logger.info(f"Found key: {key['fingerprint']}")

            # Generate output filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"{input_file}_{timestamp}.gpg"

            # Read file content
            logger.info(f"Reading file {input_file}")
            with open(input_file, 'rb') as f:
                file_data = f.read()

            # Create a temporary file for input
            with tempfile.NamedTemporaryFile(mode='wb', delete=False) as temp_in:
                temp_in.write(file_data)
                temp_in_path = temp_in.name

            try:
                # Use subprocess to call GPG directly
                logger.info("Calling GPG directly...")
                result = subprocess.run([
                    'gpg',
                    '--homedir', self.gpg_home,
                    '--trust-model', 'always',
                    '--batch',
                    '--yes',
                    '--recipient', fingerprint,
                    '--output', output_file,
                    '--encrypt', temp_in_path
                ], check=True, capture_output=True, text=True)

                if result.stderr:
                    logger.debug(f"GPG stderr output: {result.stderr}")

                if not os.path.exists(output_file) or os.path.getsize(output_file) == 0:
                    raise FileNotFoundError(f"Encryption failed: Output file {output_file} was not created or is empty")

                logger.info(f"Successfully encrypted file to {output_file}")
                return output_file

            finally:
                # Clean up temporary file
                if os.path.exists(temp_in_path):
                    os.unlink(temp_in_path)

        except Exception as e:
            logger.error(f"GPG encryption failed: {str(e)}")
            if 'output_file' in locals() and os.path.exists(output_file):
                os.remove(output_file)  # Clean up failed encryption file
            raise

        finally:
            # Clean up the temporary GPG home directory
            if os.path.exists(self.gpg_home):
                import shutil
                shutil.rmtree(self.gpg_home)

class GlacierManager:
    def __init__(self, vault_name, key_vault_manager):
        try:
            self.vault_name = vault_name
            self.key_vault_manager = key_vault_manager
            
            # Initialize Glacier client with credentials
            access_key = os.getenv('AWS_ACCESS_KEY_ID', '')
            secret_key = os.getenv('AWS_SECRET_ACCESS_KEY', '')
            session_token = os.getenv('AWS_SESSION_TOKEN', '')
            region = os.getenv('AWS_DEFAULT_REGION', 'us-east-1')

            logger.info(f"Access Key ID found: {access_key[:4] if access_key else 'Not set'}...")
            logger.info(f"Secret Key found: {'Yes' if secret_key else 'No'}")
            logger.info(f"Session Token found: {'Yes' if session_token else 'No'}")
            logger.info(f"Region: {region}")

            # Initialize the Glacier client
            self.glacier_client = boto3.client(
                'glacier',
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                aws_session_token=session_token,
                region_name=region
            )

            # Verify vault exists
            try:
                self.glacier_client.describe_vault(vaultName=self.vault_name)
                logger.info(f"Found Glacier vault: {self.vault_name}")
            except self.glacier_client.exceptions.ResourceNotFoundException:
                logger.info(f"Creating Glacier vault: {self.vault_name}")
                self.glacier_client.create_vault(vaultName=self.vault_name)

        except Exception as e:
            logger.error(f"Failed to initialize Glacier client: {str(e)}")
            raise

    def upload_to_glacier(self, file_path):
        """Upload file to Glacier vault."""
        try:
            file_name = Path(file_path).name
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            logger.info(f"Uploading {file_name} to Glacier vault: {self.vault_name}")

            # Calculate tree hash
            with open(file_path, 'rb') as f:
                file_data = f.read()

            # Upload archive
            response = self.glacier_client.upload_archive(
                vaultName=self.vault_name,
                body=file_data
            )

            archive_id = response['archiveId']
            
            # Store metadata in Key Vault
            metadata = {
                'archive_id': archive_id,
                'file_name': file_name,
                'timestamp': timestamp,
                'vault_name': self.vault_name
            }
            
            # Store in Key Vault with a structured name
            secret_name = f"glacier-archive-{timestamp}"
            self.key_vault_manager.set_secret(secret_name, json.dumps(metadata))
            
            logger.info(f"Successfully uploaded {file_name} to Glacier vault")
            logger.info(f"Archive ID: {archive_id}")
            logger.info(f"Metadata stored in Key Vault as: {secret_name}")
            
            return True

        except Exception as e:
            logger.error(f"Failed to upload {file_path} to Glacier vault: {str(e)}")
            raise

def main():
    parser = argparse.ArgumentParser(description="Azure Key Vault Secret Manager with GPG Encryption")
    parser.add_argument("--direction", type=str, required=True, choices=["pull", "push"], help="Push or Pull secrets")
    parser.add_argument("--vaultname", type=str, required=True, help="Name of the Azure Key Vault")
    parser.add_argument("--filename", type=str, required=True, help="Filename for secrets")
    parser.add_argument("--env", type=str, required=True, help="Azure environment for subscription selection (prod, qa, uat, infra, infra-dev, dev)")
    parser.add_argument("--backup", action="store_true", help="Backup to Glacier after pulling secrets")
    parser.add_argument("--encrypt", action="store_true", help="Encrypt the secrets file using GPG")
    parser.add_argument("--tags", type=str, help="Filter secrets by tags (format: key==value)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    args = parser.parse_args()

    # Set logging level based on verbose flag
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled")

    try:
        # Validate environment
        subscription_id = get_subscription_id(args.env)

        # Set the active subscription
        subprocess.run(["az", "account", "set", "--subscription", subscription_id], check=True)
        logger.info(f"Using Azure Subscription: {subscription_id}")

        # Verify Azure login
        azure_login_check()

        # Initialize managers
        vault_manager = AzureKeyVaultManager(args.vaultname)
        gpg_manager = GPGKeyManager()

        if args.direction == "pull":
            secrets_file = vault_manager.pull_secrets_to_file(
                args.filename,
                exclude_secrets=[os.getenv("GPG_KEY_NAME")],
                tag_filter=args.tags
            )
            
            logger.info(f"Successfully pulled secrets to {secrets_file}")
            
            if args.encrypt:
                gpg_key_name = os.getenv("GPG_KEY_NAME")
                if not gpg_key_name:
                    raise ConfigurationError("GPG_KEY_NAME environment variable not set")
                
                logger.info(f"Retrieving GPG key from Key Vault: {gpg_key_name}")
                gpg_key = vault_manager.get_secret(gpg_key_name)
                encrypted_file = gpg_manager.encrypt_file(secrets_file, gpg_key)
                
                logger.info(f"Successfully encrypted secrets file to {encrypted_file}")
                
                if args.backup:
                    glacier_manager = GlacierManager("keyvault-backup", vault_manager)
                    glacier_manager.upload_to_glacier(encrypted_file)
                    logger.info(f"Successfully backed up encrypted file to Glacier")
                
                os.remove(encrypted_file)
                logger.info(f"Removed temporary encrypted file: {encrypted_file}")
                os.remove(secrets_file)  # Clean up the unencrypted file
                logger.info(f"Removed temporary secrets file: {secrets_file}")
                
            elif args.backup:
                glacier_manager = GlacierManager("keyvault-backup", vault_manager)
                glacier_manager.upload_to_glacier(secrets_file)
                logger.info(f"Successfully backed up file to Glacier")
                os.remove(secrets_file)  # Clean up after backup
                logger.info(f"Removed temporary secrets file: {secrets_file}")

        elif args.direction == "push":
            try:
                # Load secrets from file
                logger.info(f"Loading secrets from {args.filename}")
                with open(args.filename, "r") as f:
                    secrets = json.load(f)

                # Validate secrets format
                if not isinstance(secrets, dict):
                    raise ValueError("Secrets file must contain a JSON object")

                success_count = 0
                total_secrets = len(secrets)
                
                logger.info(f"Pushing {total_secrets} secrets to {args.vaultname}")
                
                for name, value in secrets.items():
                    try:
                        # Set the secret
                        vault_manager.set_secret(name, value)
                        
                        # Verify the secret was set correctly by reading it back
                        verified_value = vault_manager.get_secret(name)
                        if verified_value == value:
                            logger.info(f"Secret '{name}' successfully set and verified")
                            success_count += 1
                        else:
                            logger.error(f"Secret '{name}' was set but verification failed")
                    except Exception as e:
                        logger.error(f"Failed to set secret '{name}': {str(e)}")

                # Log summary
                logger.info(f"Push operation completed. {success_count}/{total_secrets} secrets successfully set and verified")
                
                if success_count != total_secrets:
                    logger.warning("Some secrets failed to set properly. Please check the logs above for details.")
                else:
                    logger.info("All secrets were successfully set and verified!")

            except json.JSONDecodeError:
                logger.error("Failed to parse secrets file: Invalid JSON format")
                exit(1)
            except Exception as e:
                logger.error(f"Push operation failed: {str(e)}")
                exit(1)

    except Exception as e:
        logger.error(f"Operation failed: {str(e)}")
        exit(1)

if __name__ == "__main__":
    main()
