<#
.SYNOPSIS
Remediates 'Azure_BackupVault_DP_Enable_Immutability' Control.

.DESCRIPTION
Remediates 'Azure_BackupVault_DP_Enable_Immutability' Control.
Enables and locks immutability on Backup Vault(s) in the Subscription. 

.PARAMETER SubscriptionId
Specifies the ID of the Subscription to be remediated.

.PARAMETER Force
Specifies a forceful remediation without any prompts.

.Parameter PerformPreReqCheck
Specifies validation of prerequisites for the command.

.PARAMETER DryRun
Specifies a dry run of the actual remediation.

.PARAMETER FilePath
Specifies the path to the file to be used as input for the remediation.

.INPUTS
None. You cannot pipe objects to Set-ImmutabilityForBackupVault.

.OUTPUTS
None. Set-ImmutabilityForBackupVault does not return anything that can be piped and used as an input to another command.

.EXAMPLE
PS> Set-ImmutabilityForBackupVault -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

.EXAMPLE
PS> Set-ImmutabilityForBackupVault -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

.EXAMPLE
PS> Set-ImmutabilityForBackupVault -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetBackupVaultImmutability\BackupVaultDetailsBackUp.csv
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

function Get-BackupVaultDetails {
    param (
        [Parameter(Mandatory = $true)]
        $backupVaultDetails
    )
    return $backupVaultDetails | Select-Object @{N = 'ResourceId'; E = { $_.Id } },
    @{N = 'ResourceGroupName'; E = { 
            if ($_.Id -match '/resourcegroups/([^/]+)') {
                $matches[1]
            }
            else {
                $null
            }
        }
    },
    @{N = 'ImmutabilityState'; E = { $_.ImmutabilityState } },
    @{N = 'ResourceName'; E = { $_.Name } }
}

function Set-ImmutabilityForBackupVault {
    <#
    .SYNOPSIS
    Remediates 'Azure_BackupVault_DP_Enable_Immutability' Control.

    .DESCRIPTION
    Remediates 'Azure_BackupVault_DP_Enable_Immutability' Control.
    Enables and locks immutability on Backup Vault(s) in the Subscription. 

    .PARAMETER SubscriptionId
    Specifies the ID of the Subscription to be remediated.

    .PARAMETER Force
    Specifies a forceful remediation without any prompts.

    .Parameter PerformPreReqCheck
    Specifies validation of prerequisites for the command.

    .PARAMETER DryRun
    Specifies a dry run of the actual remediation.

    .PARAMETER FilePath
    Specifies the path to the file to be used as input for the remediation.

    .INPUTS
    None. You cannot pipe objects to Set-ImmutabilityForBackupVault.

    .OUTPUTS
    None. Set-ImmutabilityForBackupVault does not return anything that can be piped and used as an input to another command.

    .EXAMPLE
    PS> Set-ImmutabilityForBackupVault -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

    .EXAMPLE
    PS> Set-ImmutabilityForBackupVault -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

    .EXAMPLE
    PS> Set-ImmutabilityForBackupVault -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetBackupVaultImmutability\BackupVaultDetailsBackUp.csv

    .LINK
    None
    #>

    param (
        [String]
        [Parameter(ParameterSetName = "DryRun", Mandatory = $true, HelpMessage = "Specifies the ID of the Subscription to be remediated")]
        [Parameter(ParameterSetName = "WetRun", Mandatory = $true, HelpMessage = "Specifies the ID of the Subscription to be remediated")]
        $SubscriptionId,

        [Switch]
        [Parameter(ParameterSetName = "WetRun", HelpMessage = "Specifies a forceful remediation without any prompts")]
        $Force,

        [Switch]
        [Parameter(ParameterSetName = "DryRun", HelpMessage = "Specifies validation of prerequisites for the command")]
        [Parameter(ParameterSetName = "WetRun", HelpMessage = "Specifies validation of prerequisites for the command")]
        $PerformPreReqCheck,

        [Switch]
        [Parameter(ParameterSetName = "DryRun", Mandatory = $true, HelpMessage = "Specifies a dry run of the actual remediation")]
        $DryRun,

        [String]
        [Parameter(ParameterSetName = "WetRun", HelpMessage = "Specifies the path to the file to be used as input for the remediation")]
        $FilePath,

        [String]
        [Parameter(ParameterSetName = "WetRun", HelpMessage = "Specifies the path to the file to be used as input for the remediation when AutoRemediation switch is used")]
        $Path,

        [Switch]        
        [Parameter(ParameterSetName = "WetRun", HelpMessage = "Specifies script is run as a subroutine of AutoRemediation Script")]
        $AutoRemediation,

        [String]        
        [Parameter(ParameterSetName = "WetRun", HelpMessage = "Specifies the time of creation of file to be used for logging remediation details when AutoRemediation switch is used")]
        $TimeStamp
    )

    Write-Host $([Constants]::DoubleDashLine)

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
    
    # Setting up context for the current Subscription.
    $context = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop
    
    if (-not($AutoRemediation)) {
        Write-Host "Subscription Name: [$($context.Subscription.Name)]"
        Write-Host "Subscription ID: [$($context.Subscription.SubscriptionId)]"
        Write-Host "Account Name: [$($context.Account.Id)]"
        Write-Host "Account Type: [$($context.Account.Type)]"
        Write-Host $([Constants]::SingleDashLine)
    }

    Write-Host "To enable and lock immutability for Backup Vault(s) in a Subscription, Contributor or higher privileged role assignment on the Backup Vault is required." -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host $([Constants]::SingleDashLine)

    Write-Host "[Step 2 of 4] Fetch all Backup Vault(s)"
    Write-Host $([Constants]::SingleDashLine)
    
    # list to store Backup Vault details.
    $backupVaultDetails = @()

    # To keep track of remediated and skipped resources    
    $logRemediatedResources = @()    
    $logSkippedResources = @()    

    # Control Id    
    $controlIds = "Azure_BackupVault_DP_Enable_Immutability"

    if ($AutoRemediation) {
        if (-not (Test-Path -Path $Path)) {    
            Write-Host "File containing failing controls details [$($Path)] not found. Skipping remediation..." -ForegroundColor $([Constants]::MessageType.Error)    
            Write-Host $([Constants]::DoubleDashLine)    
            return    
        }
        Write-Host "Fetching all Backup Vault(s) failing for the [$($controlIds)] control from [$($Path)]..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        $controlForRemediation = Get-content -path $Path | ConvertFrom-Json
        $controls = $controlForRemediation.ControlRemediationList
        $resourceDetails = $controls | Where-Object { $controlIds -eq $_.ControlId };

        $validResources = $resourceDetails.FailedResourceList | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) }    

        if (($resourceDetails | Measure-Object).Count -eq 0 -or ($validResources | Measure-Object).Count -eq 0) {     
            Write-Host "No Backup Vault(s) found in input json file for remediation." -ForegroundColor $([Constants]::MessageType.Error)    
            Write-Host $([Constants]::DoubleDashLine)    
            return
        }

        $validResources | ForEach-Object {     
            try {
                $backupVaultResource = Get-AzDataProtectionBackupVault -ResourceGroupName $_.ResourceGroupName -VaultName $_.ResourceName -ErrorAction SilentlyContinue
                $backupVaultDetails += Get-BackupVaultDetails $backupVaultResource
            }
            catch {
                Write-Host "Valid resource ID(s) not found in input JSON file. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host "Skipping the Resource: [$($_.ResourceName)]..." -ForegroundColor $([Constants]::MessageType.Warning)

                $logResource = @{}
                $logResource.Add("ResourceGroupName", ($_.ResourceGroupName))
                $logResource.Add("ResourceName", ($_.ResourceName))
                $logResource.Add("Reason", "Valid resource ID(s) not found in input JSON file.")
                $logSkippedResources += $logResource

                Write-Host $([Constants]::SingleDashLine)
                Write-Host "Error fetching Backup Vault resource: Resource ID: [$($_.ResourceId)]. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            }    
        }    
    }
    else {
        if ([String]::IsNullOrWhiteSpace($FilePath)) {
            Write-Host "Fetching all Backup Vault(s) in Subscription: [$($context.Subscription.SubscriptionId)]" -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
    
            # Get all Backup Vault(s) in a Subscription
            $backupVaultDetails = Get-AzDataProtectionBackupVault -ErrorAction Stop
    
            $backupVaultDetails = Get-BackupVaultDetails $backupVaultDetails
        }
        else {
            if (-not (Test-Path -Path $FilePath)) {
                Write-Host "ERROR: Input file: [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host $([Constants]::DoubleDashLine)	
                return
            }
            Write-Host "Fetching all Backup Vault(s) from [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            $BackupVaults = Import-Csv -LiteralPath $FilePath
    
            $validBackupVaults = $BackupVaults | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) }
    
            $validBackupVaults | ForEach-Object {
                $resourceId = $_.ResourceId
    
                try {                
                    $backupVaultResource = Get-AzDataProtectionBackupVault -ResourceGroupName $_.ResourceGroupName -VaultName $_.ResourceName -ErrorAction SilentlyContinue
                    $backupVaultDetails += Get-BackupVaultDetails $backupVaultResource
                }
                catch {
                    Write-Host "Error fetching Backup Vault(s) resource: Resource ID:  [$($resourceId)]. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                }
            }
        }
    }

    $totalBackupVaults = ($backupVaultDetails | Measure-Object).Count

    if ($totalBackupVaults -eq 0) {
        Write-Host "No Backup Vault(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)	
        return
    }

    Write-Host "Found [$($totalBackupVaults)] Backup Vault(s)." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)
    
    # Backup Vault(s) where immutability is not locked
    $backupVaultsWithoutImmutability = @()

    Write-Host "Separating Backup Vault(s) for which immutability is not locked..." -ForegroundColor $([Constants]::MessageType.Info)
 
    $backupVaultDetails | ForEach-Object {
        $backupVault = $_
        if ($_.ImmutabilityState) {
            if ($_.ImmutabilityState.ToString() -ine "LOCKED") {
                $backupVaultsWithoutImmutability += $backupVault
            }
        } else {
            $backupVaultsWithoutImmutability += $backupVault
        }
    }
 
    $totalBackupVaultsWithoutImmutability = ($backupVaultsWithoutImmutability | Measure-Object).Count
 
    if ($totalBackupVaultsWithoutImmutability -eq 0) {
        Write-Host "No Backup Vault(s) found where immutability is not locked. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)    
        return
    }
 
    Write-Host "Found [$($totalBackupVaultsWithoutImmutability)] Backup Vault(s) where immutability is not locked." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)    
 
    $colsProperty = @{Expression = { $_.ResourceName }; Label = "Resource Name"; Width = 30; Alignment = "left" },
    @{Expression = { $_.ResourceGroupName }; Label = "Resource Group"; Width = 30; Alignment = "left" },
    @{Expression = { $_.ResourceId }; Label = "Resource ID"; Width = 100; Alignment = "left" },
    @{Expression = { $_.ImmutabilityState }; Label = "Immutability State"; Width = 20; Alignment = "left" }
 
    if (-not $AutoRemediation) {
        Write-Host "Backup Vault(s) without Locked Immutability:"
        $backupVaultsWithoutImmutability | Format-Table -Property $colsProperty -Wrap
        Write-Host $([Constants]::SingleDashLine)
    }
 
    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\SetBackupVaultImmutability"
 
    if (-not (Test-Path -Path $backupFolderPath)) {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
  
    Write-Host "[Step 3 of 4] Back up Backup Vault(s) details..."
    Write-Host $([Constants]::SingleDashLine)
 
    if ([String]::IsNullOrWhiteSpace($FilePath)) {
        # Backing up Backup Vault(s) details.
        $backupFile = "$($backupFolderPath)\BackupVaultDetailsBackUp.csv"
        $backupVaultsWithoutImmutability | Export-CSV -Path $backupFile -NoTypeInformation
        Write-Host "Backup Vault(s) details have been backed up to [$($backupFile)]" -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }
    else {
        Write-Host "Skipped as -FilePath is provided" -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }
 
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 4 of 4] Enable and lock immutability on Backup Vault(s) in the Subscription..." 
    if (-not $DryRun) {
        Write-Host $([Constants]::SingleDashLine)
         
        if (-not $Force) {
            Write-Host "Do you want to enable and lock immutability on Backup Vault(s) in the Subscription? " -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host "Note: This action is irreversible. Once locked, immutability cannot be disabled." -ForegroundColor $([Constants]::MessageType.Warning)
            $userInput = Read-Host -Prompt "(Y|N)"
            if ($userInput -ne "Y") {
                Write-Host "Immutability will not be enabled and locked on Backup Vault(s) in the Subscription. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::DoubleDashLine)    
                return
            }
        }
        else {
            Write-Host "'Force' flag is provided. Proceeding to enable and lock immutability on Backup Vault(s) without any prompts..." -ForegroundColor $([Constants]::MessageType.Warning)
        }
 
        # List for storing remediated Backup Vaults(s)
        $backupVaultsRemediated = @()
 
        # List for storing skipped Backup Vaults(s)
        $backupVaultsSkipped = @()
 
        # Enable and lock immutability on each Backup Vault
        # Loop through the list of Backup Vault(s) which needs to be remediated.
        $backupVaultsWithoutImmutability | ForEach-Object {
            $backupVault = $_
            try {
                if (-not $_.ImmutabilityState) {
                    Update-AzDataProtectionBackupVault -ResourceGroupName $_.ResourceGroupName -VaultName $_.ResourceName -ImmutabilityState Unlocked -ErrorAction Stop
                }
                $backupVaultResource = Update-AzDataProtectionBackupVault -ResourceGroupName $_.ResourceGroupName -VaultName $_.ResourceName -ImmutabilityState Locked -ErrorAction Stop   
 
                if ($backupVaultResource.ImmutabilityState -and $backupVaultResource.ImmutabilityState.ToString() -ieq "LOCKED") {
                    $backupVaultsRemediated += $backupVault
                    $logResource = @{}    
                    $logResource.Add("ResourceGroupName", ($_.ResourceGroupName))    
                    $logResource.Add("ResourceName", ($_.ResourceName))    
                    $logRemediatedResources += $logResource    
                }
                else {
                    $backupVaultsSkipped += $backupVault
                    $logResource = @{}    
                    $logResource.Add("ResourceGroupName", ($_.ResourceGroupName))    
                    $logResource.Add("ResourceName", ($_.ResourceName))
                    $logResource.Add("Reason", "Error enabling and locking immutability for Backup Vault: [$($backupVault)]")            
                    $logSkippedResources += $logResource    
                }
                 
            }
            catch {
                $backupVaultsSkipped += $backupVault
                $logResource = @{}    
                $logResource.Add("ResourceGroupName", ($_.ResourceGroupName))    
                $logResource.Add("ResourceName", ($_.ResourceName))    
                $logResource.Add("Reason", "Error enabling and locking immutability for Backup Vault")        
                $logSkippedResources += $logResource                
                Write-Host $([Constants]::SingleDashLine)
            }
        }
 
        Write-Host $([Constants]::DoubleDashLine)
         
         
        if ($AutoRemediation) {
            if ($($backupVaultsRemediated | Measure-Object).Count -gt 0) {
                # Write this to a file.
                $backupVaultsRemediatedFile = "$($backupFolderPath)\RemediatedBackupVaults.csv"
                $backupVaultsRemediated | Export-CSV -Path $backupVaultsRemediatedFile -NoTypeInformation
 
                Write-Host "The information related to Backup Vault(s) where immutability was enabled and locked has been saved to [$($backupVaultsRemediatedFile)]." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
            }
         
            if ($($backupVaultsSkipped | Measure-Object).Count -gt 0) {
                $backupVaultsSkipped | Format-Table -Property $colsProperty -Wrap            
                # Write this to a file.
                $backupVaultsSkippedFile = "$($backupFolderPath)\SkippedBackupVaults.csv"
                $backupVaultsSkipped | Export-CSV -Path $backupVaultsSkippedFile -NoTypeInformation
                Write-Host "The information related to Backup Vault(s) where immutability could not be enabled and locked has been saved to [$($backupVaultsSkippedFile)]." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }
        }
        else {
            Write-Host "Remediation Summary: " -ForegroundColor $([Constants]::MessageType.Info)
            if ($($backupVaultsRemediated | Measure-Object).Count -gt 0) {
                Write-Host "Successfully enabled and locked immutability for the following Backup Vault(s) in the subscription:" -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
                $backupVaultsRemediated | Format-Table -Property $colsProperty -Wrap
 
                # Write this to a file.
                $backupVaultsRemediatedFile = "$($backupFolderPath)\RemediatedBackupVaults.csv"
                $backupVaultsRemediated | Export-CSV -Path $backupVaultsRemediatedFile -NoTypeInformation
 
                Write-Host "This information has been saved to" -NoNewline
                Write-Host " [$($backupVaultsRemediatedFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
                Write-Host "Note: This action is irreversible. Immutability cannot be disabled once locked." -ForegroundColor $([Constants]::MessageType.Info)
            }
         
            if ($($backupVaultsSkipped | Measure-Object).Count -gt 0) {
                Write-Host "Error while enabling and locking immutability for Backup Vault(s) in the subscription:" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host $([Constants]::SingleDashLine)
                $backupVaultsSkipped | Format-Table -Property $colsProperty -Wrap
             
                # Write this to a file.
                $backupVaultsSkippedFile = "$($backupFolderPath)\SkippedBackupVaults.csv"
                $backupVaultsSkipped | Export-CSV -Path $backupVaultsSkippedFile -NoTypeInformation
                Write-Host "This information has been saved to"  -NoNewline
                Write-Host " [$($backupVaultsSkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update)
            }
        }
        if ($AutoRemediation) {
            $logFile = "LogFiles\" + $($TimeStamp) + "\log_" + $($SubscriptionId) + ".json"
            $log = Get-content -Raw -path $logFile | ConvertFrom-Json
            foreach ($logControl in $log.ControlList) {
                if ($logControl.ControlId -eq $controlIds) {
                    $logControl.RemediatedResources = $logRemediatedResources
                    $logControl.SkippedResources = $logSkippedResources
                    $logControl.RollbackFile = $backupVaultsRemediatedFile
                }
            }
            $log | ConvertTo-json -depth 10  | Out-File $logFile
        }
    }
    else {
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Skipped as -DryRun switch is provided." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Next steps:" -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host "Run the same command with -FilePath [$($backupFile)] and without -DryRun, to enable and lock immutability on Backup Vault(s) listed in the file." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)
    }
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