param(
    [Parameter(Mandatory = $true)][ValidateSet("pull", "push")] [string]$Direction,
    [Parameter(Mandatory = $true)] [string]$VaultName,
    [Parameter(Mandatory = $true)] [string]$Filename,
    [Parameter(Mandatory = $true)] [string]$Env,
    [switch]$Backup,
    [switch]$Encrypt,
    [string]$Tags,
    [switch]$Verbose,
    [switch]$Force
)

# Logging Setup
$LogLevel = if ($Verbose) { "DEBUG" } else { "INFO" }
$LogFile = "script.log"
Function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    if ($Level -eq "DEBUG" -and $LogLevel -ne "DEBUG") { return }
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$Timestamp - $Level - $Message" | Out-File -Append -FilePath $LogFile
}

# Subscription Map
$SubscriptionMap = @{
    "dev"       = $env:AZURE_DEV_SUBSCRIPTION_ID
    "qa"        = $env:AZURE_QA_SUBSCRIPTION_ID
    "uat"       = $env:AZURE_UAT_SUBSCRIPTION_ID
    "prod"      = $env:AZURE_PROD_SUBSCRIPTION_ID
    "infra"     = $env:AZURE_INFRA_SUBSCRIPTION_ID
    "infra-dev" = $env:AZURE_INFRADEV_SUBSCRIPTION_ID
    "microsoft" = $env:AZURE_MICROSOFT_SUBSCRIPTION_ID
}

Function Throw-ConfigurationError {
    param([string]$Message)
    Write-Log -Message $Message -Level "ERROR"
    throw $Message
}

Function Get-SubscriptionId {
    param([string]$Environment)
    $Environment = $Environment.ToLower()
    if (-not $SubscriptionMap.ContainsKey($Environment)) {
        Throw-ConfigurationError "Invalid environment: $Environment. Valid options: $($SubscriptionMap.Keys -join ', ')"
    }
    $SubscriptionId = $SubscriptionMap[$Environment]
    if (-not $SubscriptionId) {
        Throw-ConfigurationError "Subscription ID not set for environment $Environment."
    }
    return $SubscriptionId
}

Function Azure-LoginCheck {
    try {
        if (-not (Get-AzContext)) {
            Write-Log "Logging into Azure..."
            Connect-AzAccount -ErrorAction Stop
        } else {
            Write-Log "Azure session verified."
        }
    } catch {
        Write-Log "Azure login failed. Please log in manually." -Level "ERROR"
        exit 1
    }
}

Function Resolve-VaultName {
    param(
        [string]$VaultNamePattern
    )
    $vaults = Get-AzKeyVault
    $matchedVaults = $vaults | Where-Object { $_.VaultName -like $VaultNamePattern }

    if ($matchedVaults.Count -eq 1) {
        Write-Log "Resolved vault name: $($matchedVaults[0].VaultName)"
        return $matchedVaults[0].VaultName
    } elseif ($matchedVaults.Count -gt 1) {
        Write-Host "Multiple vaults matched pattern '$VaultNamePattern':"
        $i = 1
        foreach ($v in $matchedVaults) {
            Write-Host "$i. $($v.VaultName)"
            $i++
        }
        $selection = Read-Host "Enter the number of the vault you want to use"
        if ($selection -match '^[0-9]+$' -and [int]$selection -ge 1 -and [int]$selection -le $matchedVaults.Count) {
            $chosenVault = $matchedVaults[[int]$selection - 1].VaultName
            Write-Log "User selected vault: $chosenVault"
            return $chosenVault
        } else {
            Throw-ConfigurationError "Invalid selection. Exiting."
        }
    } else {
        Throw-ConfigurationError "No Key Vaults matched the pattern '$VaultNamePattern'"
    }
}

Function Confirm-Action {
    param (
        [string]$Action,
        [string]$VaultName,
        [string]$SubscriptionID
    )
    if ($Force) {
        return $true
    }
    $response = Read-Host ("Are you sure you want to " + $Action + " secrets in the vault '" + $VaultName + "' under subscription '" + $SubscriptionID + "'? [y/n]")
    return $response -match '^[yY]$'
}

class AzureKeyVaultManager {
    [string]$VaultName

    AzureKeyVaultManager([string]$vaultName) {
        $this.VaultName = $vaultName
    }

    [string] GetSecret([string]$Name) {
        return (Get-AzKeyVaultSecret -VaultName $this.VaultName -Name $Name).SecretValueText
    }

    [hashtable] GetSecretTags([string]$Name) {
        return (Get-AzKeyVaultSecret -VaultName $this.VaultName -Name $Name).Tags
    }

    [bool] SetSecret([string]$Name, [string]$Value, [hashtable]$Tags = $null) {
        $Params = @{ VaultName = $this.VaultName; Name = $Name; SecretValue = (ConvertTo-SecureString -String $Value -AsPlainText -Force) }
        if ($Tags) { $Params["Tags"] = $Tags }
        Set-AzKeyVaultSecret @Params | Out-Null
        return $true
    }

    [array] ListSecrets() {
        return (Get-AzKeyVaultSecret -VaultName $this.VaultName) | Select-Object -ExpandProperty Name
    }

    [string] PullSecretsToFile([string]$OutputFile, [array]$ExcludeSecrets, [string]$TagFilter) {
        $Secrets = $this.ListSecrets()
        $SecretsData = @()
        foreach ($Secret in $Secrets) {
            if ($ExcludeSecrets -contains $Secret) { continue }
            $Tags = $this.GetSecretTags($Secret)
            if ($TagFilter) {
                $Parts = $TagFilter -split '=='
                if ($Tags[$Parts[0]] -ne $Parts[1]) { continue }
            }
            $Value = $this.GetSecret($Secret)
            $Entry = @{ name = $Secret; value = $Value; tags = $Tags }
            $SecretsData += $Entry
        }
        $SecretsData | ConvertTo-Json -Depth 5 | Set-Content -Path $OutputFile
        return $OutputFile
    }
}

Function Encrypt-FileWithGPG {
    param(
        [string]$InputFile,
        [string]$GPGKey
    )
    $TempKeyFile = "tempkey.asc"
    $OutputFile = "$InputFile-$(Get-Date -Format yyyyMMdd_HHmmss).gpg"
    $GPGExe = "gpg"

    $GPGKey | Out-File -FilePath $TempKeyFile -Encoding ascii
    & $GPGExe --import $TempKeyFile | Out-Null
    & $GPGExe --yes --batch --trust-model always --output $OutputFile --encrypt --recipient "$GPGKey" $InputFile
    Remove-Item $TempKeyFile
    return $OutputFile
}

Function Upload-ToGlacier {
    param(
        [string]$VaultName,
        [string]$FilePath,
        [AzureKeyVaultManager]$VaultManager
    )
    $Body = Get-Content -Encoding Byte -Path $FilePath
    $Region = $env:AWS_DEFAULT_REGION
    $ArchiveResult = Write-AGArchive -AccountId "-" -VaultName $VaultName -Body $Body -Region $Region
    $Metadata = @{ file = $FilePath; id = $ArchiveResult.ArchiveId; time = (Get-Date).ToString("s") }
    $VaultManager.SetSecret("glacier-archive-$(Get-Date -Format yyyyMMdd_HHmmss)", ($Metadata | ConvertTo-Json -Depth 5))
    Write-Log "File $FilePath uploaded to Glacier as archive ID: $($ArchiveResult.ArchiveId)"
}

# MAIN
$SubscriptionId = Get-SubscriptionId -Environment $Env
Set-AzContext -SubscriptionId $SubscriptionId
Azure-LoginCheck

$ResolvedVaultName = Resolve-VaultName -VaultNamePattern $VaultName
$VaultManager = [AzureKeyVaultManager]::new($ResolvedVaultName)
$ExcludeList = @($env:GPG_KEY_NAME)

$action = if ($Direction -eq 'push') { 'push' } else { 'pull' }
if (-not (Confirm-Action -Action $action -VaultName $ResolvedVaultName -SubscriptionID $SubscriptionId)) {
    Write-Host "Operation cancelled."
    exit 0
}

if ($Direction -eq "pull") {
    $SecretsFile = $VaultManager.PullSecretsToFile($Filename, $ExcludeList, $Tags)
    Write-Log "Secrets pulled to file: $SecretsFile"

    if ($Encrypt) {
        if (-not $env:GPG_KEY_NAME) { Throw-ConfigurationError "GPG_KEY_NAME not set" }
        $GPGKey = $VaultManager.GetSecret($env:GPG_KEY_NAME)
        $EncryptedFile = Encrypt-FileWithGPG -InputFile $SecretsFile -GPGKey $GPGKey
        Write-Log "Encrypted file created: $EncryptedFile"

        if ($Backup) {
            Upload-ToGlacier -VaultName "keyvault-backup" -FilePath $EncryptedFile -VaultManager $VaultManager
        }
        Remove-Item $EncryptedFile, $SecretsFile
    }
    elseif ($Backup) {
        Upload-ToGlacier -VaultName "keyvault-backup" -FilePath $SecretsFile -VaultManager $VaultManager
        Remove-Item $SecretsFile
    }
} elseif ($Direction -eq "push") {
    $Secrets = Get-Content -Raw -Path $Filename | ConvertFrom-Json
    foreach ($Secret in $Secrets) {
        $Key = $Secret.name
        $Value = $Secret.value
        $Tags = $Secret.tags
        $VaultManager.SetSecret($Key, $Value, $Tags)
        $Verify = $VaultManager.GetSecret($Key)
        if ($Verify -eq $Value) {
            Write-Log "Secret '$Key' successfully pushed and verified."
        } else {
            Write-Log "Secret '$Key' verification failed." -Level "ERROR"
        }
    }
}

Write-Log "Script completed successfully."
exit 0 
