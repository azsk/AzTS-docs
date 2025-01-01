<#
.SYNOPSIS
Remediates 'Azure_BackupVault_AuthZ_Enable_MultiUserAuthorization' Control.

.DESCRIPTION
Remediates 'Azure_BackupVault_AuthZ_Enable_MultiUserAuthorization' Control.
Configures Multi-User Authorization (MUA) by linking Resource Guards to Backup Vault(s) in the Subscription.

.PARAMETER SubscriptionId
Specifies the ID of the Subscription to be remediated.

.PARAMETER ExistingResourceGuardId
Specifies the Resource ID of an existing Resource Guard to be used for configuration.

.PARAMETER CreateNewResourceGuards
Switch to create new Resource Guards per location when no existing Resource Guard is available.

.PARAMETER Force
Specifies a forceful remediation without any prompts.

.PARAMETER PerformPreReqCheck
Specifies validation of prerequisites for the command.

.PARAMETER DryRun
Specifies a dry run of the actual remediation.

.PARAMETER FilePath
Specifies the path to the file to be used as input for the remediation.

.PARAMETER AutoRemediation
Switch to enable automated remediation process.

.INPUTS
None. You cannot pipe objects to Set-BackupVaultResourceGuard.

.OUTPUTS
None. Set-BackupVaultResourceGuard does not return anything that can be piped and used as an input to another command.

.EXAMPLE
PS> Set-BackupVaultResourceGuard -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

.EXAMPLE
PS> Set-BackupVaultResourceGuard -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -ExistingResourceGuardId /subscriptions/.../resourceGuards/myResourceGuard

.EXAMPLE
PS> Set-BackupVaultResourceGuard -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -CreateNewResourceGuards

.EXAMPLE
PS> Set-BackupVaultResourceGuard -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\BackupVaultDetails.csv 
#>

function Setup-Prerequisites {
	<#
    .SYNOPSIS
    Checks if the prerequisites are met, else, sets them up.

    .DESCRIPTION
    Checks if the prerequisites are met, else, sets them up.
    Includes installing any required Azure modules.

    .INPUTS
    None. You cannot pipe objects to Setup-Prerequisites.

    .OUTPUTS
    None. Setup-Prerequisites does not return anything that can be piped and used as an input to another command.

    .EXAMPLE
    PS> Setup-Prerequisites

    .LINK
    None
    #>

	# List of required modules
	$requiredModules = @("Az.Accounts", "Az.DataProtection")

	Write-Host "Required modules: $($requiredModules -join ', ')"
	Write-Host $([Constants]::SingleDashLine)
	Write-Host "Checking if the required modules are present..." -ForegroundColor $([Constants]::MessageType.Info)
	Write-Host $([Constants]::SingleDashLine)

	$availableModules = $(Get-Module -ListAvailable $requiredModules -ErrorAction Stop)

	# Check if the required modules are installed
	$requiredModules | ForEach-Object {
		if ($availableModules.Name -notcontains $_) {
			Write-Host "$($_) module is not present." -ForegroundColor $([Constants]::MessageType.Warning)
			Write-Host "Installing [$($_)] module..." -ForegroundColor $([Constants]::MessageType.Info)
			Install-Module -Name $_ -Scope CurrentUser -Repository 'PSGallery' -ErrorAction Stop
			Write-Host "[$($_)] module installed." -ForegroundColor $([Constants]::MessageType.Update)
		}
		else {
			Write-Host "[$($_)] module is present." -ForegroundColor $([Constants]::MessageType.Update)
		}
	}
}

# Function to fetch non-compliant backup vaults
function Get-NonCompliantBackupVaults {
    param (
        [string]$SubscriptionId,
        [string]$FilePath = $null,
        [switch]$AutoRemediation
    )

    $vaults = @()
    $ControlId = "Azure_BackupVault_AuthZ_Enable_MultiUserAuthorization"

    try {
        if ($AutoRemediation -and $Path) {
            # Read from auto-remediation input file
            if (-not (Test-Path -Path $Path)) {
                Write-Host "File containing failing controls details [$($Path)] not found. Skipping remediation..." -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host $([Constants]::SingleDashLine)
                return $null
            }

            Write-Host "Fetching all Backup Vault(s) failing for the [$ControlId] control from [$($Path)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)

            $controlForRemediation = Get-Content -Path $Path | ConvertFrom-Json
            $controls = $controlForRemediation.ControlRemediationList
            $resourceDetails = $controls | Where-Object { $ControlId -eq $_.ControlId }
            $validResources = $resourceDetails.FailedResourceList | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) }

            if(($resourceDetails | Measure-Object).Count -eq 0 -or ($validResources | Measure-Object).Count -eq 0)
            {
                Write-Host "No Backup Vault(s) found in input json file for remediation." -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host $([Constants]::SingleDashLine)
                return
            }
            $vaults = $validResources | ForEach-Object {
                try {
                    $vaultDetail = Get-AzDataProtectionBackupVault `
                        -SubscriptionId $SubscriptionId `
                        -ResourceGroupName $_.ResourceGroupName `
                        -VaultName $_.ResourceName `
                        -ErrorAction Stop

                    $isProtected = $vaultDetail.IsVaultProtectedByResourceGuard -eq $true

                    if (-not $isProtected) {
                        [PSCustomObject]@{
                            ResourceId = $vaultDetail.Id
                            ResourceGroupName = [regex]::Match($vaultDetail.Id, "/resourcegroups/([^/]+)/").Groups[1].Value
                            ResourceName = $vaultDetail.Name
                            Location = $vaultDetail.Location
                            IsVaultProtectedByResourceGuard = $vaultDetail.IsVaultProtectedByResourceGuard
                        }
                    }
                }
                catch {
                    Write-Host "Error fetching vault resource: $($_.ResourceName). Error: $_" -ForegroundColor $([Constants]::MessageType.Error)
                    $null
                }
            } | Where-Object { $null -ne $_ }
        }
        elseif ($FilePath) {
            # Read from input file
            if (-not (Test-Path -Path $FilePath)) {
                Write-Host "ERROR: Input file [$FilePath] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
                return $null
            }

            Write-Host "Fetching all Backup Vault(s) from [$($FilePath)]..." 

            $vaultResources = Import-Csv -LiteralPath $FilePath
            $validVaultResources = $vaultResources | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) }

            $vaults = $validVaultResources | ForEach-Object {
                try {
                    $vaultDetail = Get-AzDataProtectionBackupVault `
                        -SubscriptionId $SubscriptionId `
                        -ResourceGroupName $_.ResourceGroupName `
                        -VaultName $_.ResourceName `
                        -ErrorAction Stop

                    $isProtected = $vaultDetail.IsVaultProtectedByResourceGuard -eq $true

                    if (-not $isProtected) {
                        [PSCustomObject]@{
                            ResourceId = $vaultDetail.Id
                            ResourceGroupName = [regex]::Match($vaultDetail.Id, "/resourcegroups/([^/]+)/").Groups[1].Value
                            ResourceName = $vaultDetail.Name
                            Location = $vaultDetail.Location
                            IsVaultProtectedByResourceGuard = $vaultDetail.IsVaultProtectedByResourceGuard
                        }
                    }
                }
                catch {
                    Write-Host "Error fetching vault resource: $($_.ResourceName). Error: $_" -ForegroundColor $([Constants]::MessageType.Error)
                    $null
                }
            } | Where-Object { $null -ne $_ }
        }
        else {
            # Fetch all backup vaults in the subscription
            $allVaults = Get-AzDataProtectionBackupVault -SubscriptionId $SubscriptionId

            
            # Filter vaults without Resource Guard configuration
            $vaults = $allVaults | Where-Object {
                $false -eq $_.IsVaultProtectedByResourceGuard
            }  | ForEach-Object {
                [PSCustomObject]@{
                    ResourceId = $_.Id
                    ResourceGroupName = [regex]::Match($_.Id, "/resourcegroups/([^/]+)/").Groups[1].Value
                    ResourceName = $_.Name
                    Location = $_.Location
                    IsVaultProtectedByResourceGuard = $_.IsVaultProtectedByResourceGuard
                }
            }
        }

        # Group vaults by location for summary
        $locationSummary = $vaults | Group-Object Location | ForEach-Object {
            @{
                Location = $_.Name
                VaultCount = $_.Count
            }
        }

        return @{
            Vaults = $vaults
            LocationSummary = $locationSummary
        }
    }
    catch {
        Write-Host "Error fetching backup vaults: $_" -ForegroundColor $([Constants]::MessageType.Error)
        return $null
    }
}

# Function to validate Resource Guard
function Validate-ResourceGuard {
    param (
        [string]$ResourceGuardId
    )

    try {
        $resourceGuard = Get-AzResource -ResourceId $ResourceGuardId
        if ($resourceGuard.ResourceType -ne "Microsoft.DataProtection/resourceGuards") {
            throw "Invalid Resource Guard resource type"
        }
        return $true
    }
    catch {
        Write-Host "Invalid Resource Guard ID: $_" -ForegroundColor $([Constants]::MessageType.Error)
        return $false
    }
}

function Set-BackupVaultResourceGuard {
    param (
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionId,

        [Parameter(Mandatory = $false)]
        [string]$ExistingResourceGuardId,

        [Parameter(Mandatory = $false)]
        [switch]$CreateNewResourceGuards,

        [Parameter(Mandatory = $false)]
        [switch]$Force,

        [Parameter(Mandatory = $false)]
        [switch]$DryRun,

        [Parameter(Mandatory = $false)]
        [string]$FilePath,

        [Parameter(Mandatory = $false)]
        [switch]$PerformPreReqCheck,

        [Parameter(Mandatory = $false)]
        [switch]$AutoRemediation,

        [Parameter(Mandatory = $false)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [string]$TimeStamp
    )
    Write-Host $([Constants]::DoubleDashLine)

    # Main remediation logic
    try {
        # Step 0: Prerequisite Check
        if ($PerformPreReqCheck) {
            try {
                Write-Host "[Step 1 of 4] Validate and install the modules required to run the script and validate the user..."
                Write-Host "Setting up prerequisites..." -ForegroundColor $([Constants]::MessageType.Info)
                Setup-Prerequisites
                Write-Host "Completed setting up prerequisites." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
            }
            catch {
                Write-Host "Error occurred while setting up prerequisites. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host $([Constants]::DoubleDashLine)
                return
            }
        }
        else {
            Write-Host "[Step 1 of 4] Validate the user..."
            Write-Host $([Constants]::SingleDashLine)
        }

        # Connect to Azure account
        $context = Get-AzContext

        if ([String]::IsNullOrWhiteSpace($context)) {
            Write-Host "Connecting to Azure account..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            Connect-AzAccount -Subscription $SubscriptionId -ErrorAction Stop | Out-Null
            Write-Host "Connected to Azure account." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
        }

        Write-Host "***To Configure Multi-User Authorization (MUA) on Backup Vaults, Contributor or higher privileges on the Backup Vaults are required.***" -ForegroundColor $([Constants]::MessageType.Warning)

        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 2 of 4] Preparing to fetch Backup Vault(s) without MUA configuration..."
        Write-Host $([Constants]::SingleDashLine)

        # Backup folder for storing logs and remediation details
        $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\BackupVaultResourceGuard"
        if (-not (Test-Path -Path $backupFolderPath)) {
            New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
        }

        # Lists to track remediation and skipped resources
        $logRemediatedResources = @()
        $logSkippedResources = @()

        # Step 2: Fetch non-compliant backup vaults
        $nonCompliantVaults = Get-NonCompliantBackupVaults `
            -SubscriptionId $SubscriptionId `
            -FilePath $FilePath `
            -AutoRemediation:$AutoRemediation

        if (-not $nonCompliantVaults -or $nonCompliantVaults.Vaults.Count -eq 0) {
            Write-Host "No non-compliant backup vaults found." -ForegroundColor $([Constants]::MessageType.Warning)
            return
        }

        Write-Host "Found [$($nonCompliantVaults.Vaults.Count)] Backup Vault(s) with non-compliant MUA configuration." -ForegroundColor $([Constants]::MessageType.Update)

        # Display location summary
        Write-Host "Non-Compliant Backup Vaults Summary:" -ForegroundColor $([Constants]::MessageType.Info)
        $nonCompliantVaults.LocationSummary | Format-Table -AutoSize

        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 3 of 4] Backing up non-compliant Backup Vault(s) details..."
        Write-Host $([Constants]::SingleDashLine)

        if ([String]::IsNullOrWhiteSpace($FilePath))
        {
            # Backing up non-compliant Backup Vault(s) details
            $backupFile = "$($backupFolderPath)\NonCompliantBackupVaults.csv"

            $nonCompliantVaults.Vaults | Export-CSV -Path $backupFile -NoTypeInformation

            Write-Host "Backup Vault(s) details have been backed up to" -NoNewline
            Write-Host " [$($backupFile)]" -ForegroundColor $([Constants]::MessageType.Update)
        }
        else
        {
            Write-Host "Skipped as -FilePath is provided" -ForegroundColor $([Constants]::MessageType.Warning)
        }

        # Stop if it's a dry run
        if ($DryRun) {
            Write-Host $([Constants]::DoubleDashLine)
            Write-Host "[Step 4 of 4] Remediating non-compliant Azure Backup Vaults..."
            Write-Host $([Constants]::SingleDashLine)
            Write-Host "Skipped as -DryRun switch is provided." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::DoubleDashLine)

            Write-Host "Next steps:" -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host "Run the same command with -FilePath $($backupFile) and without -DryRun, configure Resource Guard on Backup Vault(s) listed in the file."
            return
        }

        # Lists to track remediation
        $remediatedVaults = @()
        $skippedVaults = @()
        $createdResourceGuards = @()
        $createdResourceGroups = @()

        # User interaction for remediation method
        Write-Host "Choose a method to configure Multi User Authorization (MUA) on backup vault:" -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "1. Use an existing Resource Guard" -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "2. Create new Resource Guards per location" -ForegroundColor $([Constants]::MessageType.Info)

        $choice = Read-Host "Enter your choice (1 or 2)"

        switch ($choice) {
            "1" {
                # Option 1: Use existing Resource Guard
                $ExistingResourceGuardId = Read-Host "Enter the Resource Guard Resource ID"

                if (-not (Validate-ResourceGuard -ResourceGuardId $ExistingResourceGuardId)) {
                    Write-Host $([Constants]::DoubleDashLine)
                    Write-Host "Resource Guard Validation Failed" -ForegroundColor $([Constants]::MessageType.Error)
                    Write-Host $([Constants]::SingleDashLine)
                    Write-Host "The provided Resource Guard ID is invalid or cannot be accessed." -ForegroundColor $([Constants]::MessageType.Warning)
                    Write-Host "Please ensure:" -ForegroundColor $([Constants]::MessageType.Info)
                    Write-Host "- The Resource Guard ID is correct" -ForegroundColor $([Constants]::MessageType.Info)
                    Write-Host "- You have sufficient permissions to access the Resource Guard (Reader or higher)" -ForegroundColor $([Constants]::MessageType.Info)
                    Write-Host $([Constants]::DoubleDashLine)
                    return
                }

                $continueRemediation = Confirm-Remediation `
                    -ResourceType "Backup Vault(s)" `
                    -ResourceCount $nonCompliantVaults.Vaults.Count `
                    -Force:$Force `
                    -AutoRemediation:$AutoRemediation

                if (-not $continueRemediation) {
                    return 
                }

                $vaultsToRemediate = $nonCompliantVaults.Vaults | Where-Object { 
                    $_.Location -eq (Get-AzResource -ResourceId $ExistingResourceGuardId).Location 
                }

                Write-Host "Remediating $($vaultsToRemediate.Count) vaults using existing Resource Guard as they align with Resource Guard's location" -ForegroundColor $([Constants]::MessageType.Info)
                
                foreach ($vault in $vaultsToRemediate) {                    
                    try {
                        $result = Set-AzDataProtectionResourceGuardMapping -ResourceGroupName $vault.ResourceGroupName -VaultName $vault.ResourceName -SubscriptionId $SubscriptionId -ResourceGuardId $ExistingResourceGuardId


                        $vaultDetail = [PSCustomObject]@{
                            ResourceId = $vault.ResourceId
                            ResourceGroupName = $vault.ResourceGroupName
                            ResourceName = $vault.ResourceName
                            IsVaultProtectedByResourceGuard = $vault.IsVaultProtectedByResourceGuard
                        }

                        if ($result) {
                            $remediatedVaults += $vaultDetail
                            $logRemediatedResources += $vaultDetail
                        }
                        else {
                            $skippedVaults += $vault
                            $logSkippedResources += [PSCustomObject]@{
                                ResourceGroupName = $ResourceGroup
                                ResourceName = $vault.ResourceName
                                Reason = "Failed to link Resource Guard"
                            }
                        }
                    }
                    catch {
                        $skippedVaults += $vault
                        $logSkippedResources += [PSCustomObject]@{
                            ResourceGroupName = $ResourceGroup
                            ResourceName = $vault.ResourceName
                            Reason = "Error during Resource Guard linking: $_"
                        }
                    }
                }
            }
            "2" {
                # Option 2: Create new Resource Guards per location
                $locationGroups = $nonCompliantVaults.Vaults | Group-Object Location
                $DefaultLocation = "eastus"
                # Create a new resource group for the Resource Guard
                $aztsScanner = "azts"             

                # Generate a unique hash using SHA256
                $hashBytes = [System.Text.Encoding]::UTF8.GetBytes($aztsScanner)
                $sha256 = [System.Security.Cryptography.SHA256]::Create()
                $hash = $sha256.ComputeHash($hashBytes)

                # Convert the hash bytes to a hexadecimal string
                $hashString = -join ($hash[0..15] | ForEach-Object { $_.ToString("x2") }) # Use first 15 characters for uniqueness

                # Create the Resource Group name by combining "rg-" with the hash
                $ResourceGroupName = "rg-" + $hashString.ToLower()

                if ($ResourceGroupName.Length -gt 24) {
                    $ResourceGroupName = $ResourceGroupName.Substring(0, 24)
                }
                Write-Host "Generated Resource Group Name: $ResourceGroupName" -ForegroundColor $([Constants]::MessageType.Info)

                # Check if the resource group exists
                $resourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue

                if ($null -eq $resourceGroup) {
                    # Resource group does not exist, create it
                    $newResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $DefaultLocation -ErrorAction Stop
                    Write-Host "Resource group '$ResourceGroupName' created." -ForegroundColor $([Constants]::MessageType.Update)
                    $createdResourceGroups += [PSCustomObject]@{
                        CreatedResourceGroupId = $newResourceGroup.ResourceId
                        CreatedResourceGroupName = $newResourceGroup.ResourceGroupName
                    }
                } else {
                    # Resource group exists
                    Write-Host "Resource group '$ResourceGroupName' already exists." -ForegroundColor $([Constants]::MessageType.Info)
                }

                foreach ($locationGroup in $locationGroups) {
                    try {
                        $aztsScanner = "azts"
                
                        # Concatenate the Resource Group name and Location and azts for unique combination
                        $rgLocationString = $ResourceGroupName + $locationGroup.Name + $aztsScanner                
                
                        # Generate a unique hash using SHA256
                        $hashBytes = [System.Text.Encoding]::UTF8.GetBytes($rgLocationString)
                        $sha256 = [System.Security.Cryptography.SHA256]::Create()
                        $hash = $sha256.ComputeHash($hashBytes)
                
                        # Convert the hash bytes to a hexadecimal string
                        $hashString = -join ($hash[0..15] | ForEach-Object { $_.ToString("x2") }) # Use first 15 characters for uniqueness
                
                        # Create the Resource Guard name by combining "resource-guard-" with the hash
                        $resourceGuardName = "resource-guard-" + $hashString.ToLower()
                
                        if ($resourceGuardName.Length -gt 24) {
                            $resourceGuardName = $resourceGuardName.Substring(0, 24)
                        }
                        Write-Host "Generated Resource Guard Name: $resourceGuardName" -ForegroundColor $([Constants]::MessageType.Info)

                        $resourceGuard = $null
                        
                        # Check if the Resource Guard already exists
                        $resourceGuard = Get-AzDataProtectionResourceGuard `
                            -ResourceGroupName $ResourceGroupName `
                            -Name $resourceGuardName `
                            -ErrorAction SilentlyContinue
                
                        if ($null -eq $resourceGuard) {
                            # Resource Guard does not exist, create it
                            $resourceGuard = New-AzDataProtectionResourceGuard `
                                -Location $locationGroup.Name `
                                -Name $resourceGuardName `
                                -ResourceGroupName $ResourceGroupName `
                                -SubscriptionId $SubscriptionId

                            Write-Host "Resource Guard '$($resourceGuard.Name)' created." -ForegroundColor $([Constants]::MessageType.Update)
                
                            $createdResourceGuards += [PSCustomObject]@{
                                CreatedResourceGuardId = $resourceGuard.Id
                                CreatedResourceGuardName = $resourceGuard.Name
                                CreatedResourceGuardLocation = $locationGroup.Name
                                CreatedResourceGuardStoredInResourceGroup = $ResourceGroupName
                            }
                        } else {
                            # Resource Guard exists
                            Write-Host "Resource Guard '$resourceGuardName' already exists." -ForegroundColor $([Constants]::MessageType.Info)
                        }

                        # Link Resource Guard to vaults in this location
                        foreach ($vault in $locationGroup.Group) {
                            try {
                                $result = Set-AzDataProtectionResourceGuardMapping -ResourceGroupName $vault.ResourceGroupName -VaultName $vault.ResourceName -SubscriptionId $SubscriptionId -ResourceGuardId $resourceGuard.Id
                
                                $vaultDetail = [PSCustomObject]@{
                                    ResourceId = $vault.ResourceId
                                    ResourceGroupName = $vault.ResourceGroupName
                                    ResourceName = $vault.ResourceName
                                    IsVaultProtectedByResourceGuard = $vault.IsVaultProtectedByResourceGuard
                                }
        
                                if ($result) {
                                    $remediatedVaults += $vaultDetail
                                    $logRemediatedResources += $vaultDetail
                                }
                                else {
                                    $skippedVaults += $vault
                                    $logSkippedResources += [PSCustomObject]@{
                                        ResourceGroupName = $VaultResourceGroupName
                                        ResourceName = $vault.ResourceName
                                        Reason = "Failed to link Resource Guard"
                                    }
                                }
                            }
                            catch {
                                $skippedVaults += $vault
                                $logSkippedResources += [PSCustomObject]@{
                                    ResourceGroupName = $VaultResourceGroupName
                                    ResourceName = $vault.ResourceName
                                    Reason = "Error during Resource Guard linking: $_"
                                }
                            }
                        }
                    }
                    catch {
                        Write-Host "Error creating Resource Guard in $Location : $_" -ForegroundColor $([Constants]::MessageType.Error)
                        return $null
                    }
                }
            }
            default {
                Write-Host "Invalid choice. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
                return
            }
        }

        # Remediation Summary
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Remediation Summary:" -ForegroundColor $([Constants]::MessageType.Info)

        # Log remediated vaults
        if ($remediatedVaults.Count -gt 0) {
            Write-Host "Successfully configured Resource Guard on the following Backup Vaults:" -ForegroundColor $([Constants]::MessageType.Update)
            $remediatedVaults | Format-Table
            # Export remediated vaults to a CSV file
            $remediatedFile = "$($backupFolderPath)\RemediatedBackupVaults.csv"
            $remediatedVaults | Export-CSV -Path $remediatedFile -NoTypeInformation

            Write-Host "Remediated vaults details saved to" -NoNewline
            Write-Host " [$remediatedFile]" -ForegroundColor $([Constants]::MessageType.Update)
        }
        
        # Log created Resource Groups
        if ($createdResourceGroups.Count -gt 0) {
            Write-Host "Successfully created the following Resource Groups:" -ForegroundColor $([Constants]::MessageType.Update)
            $createdResourceGroups | Format-Table

            # Export remediated vaults to a CSV file
            $resourceGroupsFile = "$($backupFolderPath)\CreatedResourceGroups.csv"
            $createdResourceGroups | Export-CSV -Path $resourceGroupsFile -NoTypeInformation

            Write-Host "Details of created Resource Groups saved to" -NoNewline
            Write-Host " [$resourceGroupsFile]" -ForegroundColor $([Constants]::MessageType.Update)
        }

        # Log created Resource Guards
        if ($createdResourceGuards.Count -gt 0) {
            Write-Host "Successfully created the following Resource Guards:" -ForegroundColor $([Constants]::MessageType.Update)
            $createdResourceGuards | Format-Table

            # Export created Resource Guards to a CSV file
            $resourceGuardsFile = "$($backupFolderPath)\CreatedResourceGuards.csv"
            $createdResourceGuards | Export-CSV -Path $resourceGuardsFile -NoTypeInformation

            Write-Host "Details of created Resource Guards saved to" -NoNewline
            Write-Host " [$resourceGuardsFile]" -ForegroundColor $([Constants]::MessageType.Update)
        }


        # Log skipped vaults
        if ($skippedVaults.Count -gt 0) {
            Write-Host "Failed to configure Resource Guard on the following Backup Vaults:" -ForegroundColor $([Constants]::MessageType.Error)
            $skippedVaults | Format-Table -Property ResourceName, ResourceGroupName, Location

            # Export skipped vaults to a CSV file
            $skippedFile = "$($backupFolderPath)\SkippedBackupVaults.csv"
            $skippedVaults | Export-CSV -Path $skippedFile -NoTypeInformation

            Write-Host "Skipped vaults details saved to" -NoNewline
            Write-Host " [$skippedFile]" -ForegroundColor $([Constants]::MessageType.Update)
        }

        # Update log file for auto-remediation
        if ($AutoRemediation) {
            $logFile = "LogFiles\" + $TimeStamp + "\log_" + $SubscriptionId + ".json"
            $log = Get-Content -Raw -Path $logFile | ConvertFrom-Json
            
            foreach ($logControl in $log.ControlList) {
                if ($logControl.ControlId -eq $ControlId) {
                    $logControl.RemediatedResources = $logRemediatedResources
                    $logControl.SkippedResources = $logSkippedResources
                }
            }
            
            $log | ConvertTo-Json -Depth 10 | Out-File $logFile
        }

        Write-Host "Use $backupFolderPath file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Info)

        Write-Host "Remediation complete." -ForegroundColor $([Constants]::MessageType.Info)
    } catch {
        Write-Host "Error occurred during remediation: $_" -ForegroundColor $([Constants]::MessageType.Error)
    }
}

function Confirm-Remediation {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ResourceType,
        
        [Parameter(Mandatory = $true)]
        [int]$ResourceCount,
        
        [Parameter(Mandatory = $false)]
        [switch]$Force,
        
        [Parameter(Mandatory = $false)]
        [switch]$AutoRemediation
    )

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 4 of 4] Remediating non-compliant Azure $ResourceType..." 
    Write-Host $([Constants]::SingleDashLine)
    
    if (-not $AutoRemediation) {
        if (-not $Force) {
            $confirmationMessage = "This step will configure Multi-User Authorization (MUA) for all non-compliant [$($ResourceCount)] $ResourceType."
            Write-Host $confirmationMessage -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host "Do you want to Continue? " -ForegroundColor $([Constants]::MessageType.Warning)
        
            $userInput = Read-Host -Prompt "(Y|N)"

            if ($userInput -ne "Y") {
                Write-Host "Multi-User Authorization (MUA) will not be configured on $ResourceType in the Subscription. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
                return $false
            }
        }
        else {
            Write-Host "'Force' flag is provided. Multi-User Authorization (MUA) will be configured on $ResourceType in the Subscription without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
        }
    }

    return $true
}

function Reset-BackupVaultResourceGuard {
    param (
        [String]
        [Parameter(Mandatory = $true, HelpMessage="Specifies the ID of the Subscription that was previously remediated.")]
        $SubscriptionId,

        [Switch]
        [Parameter(HelpMessage="Specifies a forceful roll back without any prompts")]
        $Force,

        [Switch]
        [Parameter(HelpMessage="Specifies validation of prerequisites for the command")]
        $PerformPreReqCheck,

        [String]
        [Parameter(Mandatory = $true, HelpMessage="Specifies the path to the file to be used as input for the roll back")]
        $FilePath
    )

    if ($PerformPreReqCheck) {
        try {
            Write-Host "[Step 1 of 3] Validating and installing the modules required to run the script and validating the user..."
            Write-Host $([Constants]::SingleDashLine)
            Write-Host "Setting up prerequisites..."
            Setup-Prerequisites
        }
        catch {
            Write-Host "Error occurred while setting up prerequisites. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            break
        }
    }
    else {
        Write-Host "[Step 1 of 3] Validating the user..." 
    }  

    # Connect to Azure account
    $context = Get-AzContext

    if ([String]::IsNullOrWhiteSpace($context)) {
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Connecting to Azure account..."
        Connect-AzAccount -Subscription $SubscriptionId -ErrorAction Stop | Out-Null
        Write-Host "Connected to Azure account." -ForegroundColor $([Constants]::MessageType.Update)
    }

    # Setting up context for the current Subscription
    $context = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop
    
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Subscription Name: [$($context.Subscription.Name)]"
    Write-Host "Subscription ID: [$($context.Subscription.SubscriptionId)]"
    Write-Host "Account Name: [$($context.Account.Id)]"
    Write-Host "Account Type: [$($context.Account.Type)]"
    Write-Host $([Constants]::SingleDashLine)

    Write-Host "*** To configure Multi User Authorization(MUA) on backup vault in a Subscription, Contributor or higher privileges on the Subscription is required.***" -ForegroundColor $([Constants]::MessageType.Warning)

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 3] Preparing to fetch all Backup Vault(s)..."
    Write-Host $([Constants]::SingleDashLine)
    
    if (-not (Test-Path -Path $FilePath)) {
        Write-Host "ERROR: Input file - [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        break
    }

    Write-Host "Fetching all Backup Vault(s) from" -NoNewline
    Write-Host " [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Update)
    
    $backupVaultsFilePath = Join-Path $FilePath "RemediatedBackupVaults.csv"
    $createdResourceGroupsPath = Join-Path $FilePath "CreatedResourceGroups.csv"
    $createdResourceGuardsPath = Join-Path $FilePath "CreatedResourceGuards.csv"

    # Track rollback results
    $rolledBackVaults = @()
    $skippedVaults = @()
    $deletedResourceGuards = @()
    $deletedResourceGroups = @()

    # First, remove resource guard mappings from vaults
    if (Test-Path $backupVaultsFilePath) {
        $remediatedVaults = Import-Csv $backupVaultsFilePath
        
        foreach ($vault in $remediatedVaults) {
            try {
                Write-Host "Processing vault: $($vault.ResourceName)" -ForegroundColor $([Constants]::MessageType.Info)
                
                # Get the resource guard mapping
                $proxy = Get-AzDataProtectionResourceGuardMapping `
                    -ResourceGroupName $vault.ResourceGroupName `
                    -VaultName $vault.ResourceName `
                    -SubscriptionId $SubscriptionId

                if ($proxy) {
                    # Unlock the resource guard operation
                    Unlock-AzDataProtectionResourceGuardOperation `
                        -ResourceGroupName $vault.ResourceGroupName `
                        -SubscriptionId $SubscriptionId `
                        -VaultName $vault.ResourceName `
                        -ResourceGuardOperationRequest DisableMUA `
                        -ResourceToBeDeleted $proxy.Id

                    # Remove the resource guard mapping
                    Remove-AzDataProtectionResourceGuardMapping `
                        -ResourceGroupName $vault.ResourceGroupName `
                        -SubscriptionId $SubscriptionId `
                        -VaultName $vault.ResourceName

                    $rolledBackVaults += $vault
                }
            }
            catch {
                Write-Host "Error removing resource guard mapping from vault $($vault.ResourceName): $_" -ForegroundColor $([Constants]::MessageType.Error)
                $skippedVaults += $vault
            }
        }
    }

    # Check if we have both resource guards and resource groups to clean up
    $hasResourceGroups = Test-Path $createdResourceGroupsPath
    $hasResourceGuards = Test-Path $createdResourceGuardsPath

    if ($hasResourceGuards -or $hasResourceGroups) {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 3 of 3] Cleaning up created resources and resource groups..."
        Write-Host $([Constants]::SingleDashLine)

        Write-Host "Choose cleanup option:" -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "1. Delete both Resource Guards and their Resource Groups"
        Write-Host "2. Keep Resource Groups but delete Resource Guards"
        Write-Host "3. Skip cleanup of Resource Guards and Resource Groups"

        $choice = if ($Force) { "1" } else { Read-Host "Enter your choice (1-3)" }

        switch ($choice) {
            "1" {
                if ($hasResourceGroups) {
                    $resourceGroups = Import-Csv $createdResourceGroupsPath
                    foreach ($rg in $resourceGroups) {
                        try {
                            Write-Host "Deleting Resource Group: $($rg.CreatedResourceGroupName)" -ForegroundColor $([Constants]::MessageType.Info)
                            Remove-AzResourceGroup -Name $rg.CreatedResourceGroupName -Force
                            $deletedResourceGroups += $rg
                        }
                        catch {
                            Write-Host "Error deleting Resource Group $($rg.CreatedResourceGroupName): $_" -ForegroundColor $([Constants]::MessageType.Error)
                        }
                    }
                }
            }
            "2" {
                if ($hasResourceGuards) {
                    $resourceGuards = Import-Csv $createdResourceGuardsPath
                    foreach ($guard in $resourceGuards) {
                        try {
                            Write-Host "Deleting Resource Guard: $($guard.CreatedResourceGuardName)" -ForegroundColor $([Constants]::MessageType.Info)
                            Remove-AzDataProtectionResourceGuard `
                                -ResourceGroupName $guard.CreatedResourceGuardStoredInResourceGroup `
                                -Name $guard.CreatedResourceGuardName
                            $deletedResourceGuards += $guard
                        }
                        catch {
                            Write-Host "Error deleting Resource Guard $($guard.CreatedResourceGuardName): $_" -ForegroundColor $([Constants]::MessageType.Error)
                        }
                    }
                }
            }
            "3" {
                Write-Host "Skipping cleanup of Resource Guards and Resource Groups" -ForegroundColor $([Constants]::MessageType.Warning)
            }
            default {
                Write-Host "Invalid choice. Skipping cleanup." -ForegroundColor $([Constants]::MessageType.Error)
            }
        }
    }

    # Rollback Summary
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "Rollback Summary:" -ForegroundColor $([Constants]::MessageType.Info)

    if ($rolledBackVaults.Count -gt 0) {
        Write-Host "Successfully removed Resource Guard mapping from the following Backup Vaults meaning MUA on these vaults is disabled:" -ForegroundColor $([Constants]::MessageType.Update)
        $rolledBackVaults | Format-Table ResourceName, ResourceGroupName
    }

    if ($skippedVaults.Count -gt 0) {
        Write-Host "Failed to disable MUA from the following Backup Vaults:" -ForegroundColor $([Constants]::MessageType.Error)
        $skippedVaults | Format-Table ResourceName, ResourceGroupName
    }

    if ($deletedResourceGuards.Count -gt 0) {
        Write-Host "Successfully deleted the following Resource Guards:" -ForegroundColor $([Constants]::MessageType.Update)
        $deletedResourceGuards | Format-Table CreatedResourceGuardName, CreatedResourceGuardStoredInResourceGroup
    }

    if ($deletedResourceGroups.Count -gt 0) {
        Write-Host "Successfully deleted the following Resource Groups:" -ForegroundColor $([Constants]::MessageType.Update)
        $deletedResourceGroups | Format-Table CreatedResourceGroupName
    }

    Write-Host "Rollback complete." -ForegroundColor $([Constants]::MessageType.Info)
}

# Defines commonly used constants.
class Constants {
    # Defines commonly used colour codes, corresponding to the severity of the log...
    static [Hashtable] $MessageType = @{
        Error   = [System.ConsoleColor]::Red
        Warning = [System.ConsoleColor]::Yellow
        Info    = [System.ConsoleColor]::Cyan
        Update  = [System.ConsoleColor]::Green
        Default = [System.ConsoleColor]::White
    }

    static [String] $DoubleDashLine = "=" * 120
    static [String] $SingleDashLine = "-" * 120
}

# C:\Users\v-rvadeghar\AppData\Local\AzTS\Remediation\Subscriptions\abb5301a_22a4_41f9_9e5f_99badff261f8\202412301157\BackupVaultResourceGuard\NonCompliantBackupVaults.csv