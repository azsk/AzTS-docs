<#
.SYNOPSIS
Remediates 'Azure_RecoveryServicesVault_DP_Enable_Immutability' Control.

.DESCRIPTION
Remediates 'Azure_RecoveryServicesVault_DP_Enable_Immutability' Control.
Immutability must be enabled and locked on Recovery Services Vault. 

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
None. You cannot pipe objects to Set-ImmutabilityForRecoveryServiceVault.

.OUTPUTS
None. Set-ImmutabilityForRecoveryServiceVault does not return anything that can be piped and used as an input to another command.

.EXAMPLE
PS> Set-ImmutabilityForRecoveryServiceVault -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

.EXAMPLE
PS> Set-ImmutabilityForRecoveryServiceVault -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

.EXAMPLE
PS> Set-ImmutabilityForRecoveryServiceVault -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetRecoveryServiceVaultImmutability\RecoveryServiceVaultDetailsBackUp.csv
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
    $requiredModules = @("Az.Accounts", "Az.RecoveryServices")

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

function Get-RecoveryServiceVaultDetails {
    param (
        [Parameter(Mandatory = $true)]
        $RecoveryServiceVaultDetails
    )
    return $RecoveryServiceVaultDetails | Select-Object @{N = 'ResourceId'; E = { $_.Id } },
    @{N = 'ResourceGroupName'; E = { $_.ResourceGroupName } },
    @{N = 'ImmutabilityState'; E = { $_.Properties.ImmutabilitySettings.ImmutabilityState.ToString() } },
    @{N = 'ResourceName'; E = { $_.Name } }
}

function Set-ImmutabilityForRecoveryServiceVault {
    <#
    .SYNOPSIS
    Remediates 'Azure_RecoveryServicesVault_DP_Enable_Immutability' Control.

    .DESCRIPTION
    Remediates 'Azure_RecoveryServicesVault_DP_Enable_Immutability' Control.
    Immutability must be enabled and locked on Recovery Services Vault. 

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
    None. You cannot pipe objects to Set-ImmutabilityForRecoveryServiceVault.

    .OUTPUTS
    None. Set-ImmutabilityForRecoveryServiceVault does not return anything that can be piped and used as an input to another command.

    .EXAMPLE
    PS> Set-ImmutabilityForRecoveryServiceVault -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

    .EXAMPLE
    PS> Set-ImmutabilityForRecoveryServiceVault -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

    .EXAMPLE
    PS> Set-ImmutabilityForRecoveryServiceVault -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetRecoveryServiceVaultImmutability\RecoveryServiceVaultDetailsBackUp.csv

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

    Write-Host "To enable and lock immutability for Recovery Services Vault(s) in a Subscription, Owner or higher privileged role assignment on the Subscription is required." -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host $([Constants]::SingleDashLine)

    Write-Host "[Step 2 of 4] Fetch all Recovery Services Vault(s)"
    Write-Host $([Constants]::SingleDashLine)
    
    # list to store Recovery Services Vault details.
    $RecoveryServiceVaultDetails = @()

    # To keep track of remediated and skipped resources    
    $logRemediatedResources = @()    
    $logSkippedResources = @()    

    # Control Id    
    $controlIds = "Azure_RecoveryServicesVault_DP_Enable_Immutability"

    if ($AutoRemediation) {
        if (-not (Test-Path -Path $Path)) {    
            Write-Host "File containing failing controls details [$($Path)] not found. Skipping remediation..." -ForegroundColor $([Constants]::MessageType.Error)    
            Write-Host $([Constants]::DoubleDashLine)    
            return    
        }
        Write-Host "Fetching all Recovery Services Vault(s) failing for the [$($controlIds)] control from [$($Path)]..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        $controlForRemediation = Get-content -path $Path | ConvertFrom-Json
        $controls = $controlForRemediation.ControlRemediationList
        $resourceDetails = $controls | Where-Object { $controlIds -eq $_.ControlId };

        $validResources = $resourceDetails.FailedResourceList | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) }    

        if (($resourceDetails | Measure-Object).Count -eq 0 -or ($validResources | Measure-Object).Count -eq 0) {     
            Write-Host "No Recovery Services Vault(s) found in input json file for remediation." -ForegroundColor $([Constants]::MessageType.Error)    
            Write-Host $([Constants]::DoubleDashLine)    
            return
        }

        $validResources | ForEach-Object {     
            try {
                $RecoveryServiceVaultResource = Get-AzRecoveryServicesVault -ResourceGroupName $_.ResourceGroupName -Name $_.ResourceName -ErrorAction SilentlyContinue
                $RecoveryServiceVaultDetails += Get-RecoveryServiceVaultDetails $RecoveryServiceVaultResource
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
                Write-Host "Error fetching Recovery Services Vault resource: Resource ID: [$($_.ResourceId)]. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            }    
        }    
    }
    else {
        if ([String]::IsNullOrWhiteSpace($FilePath)) {
            Write-Host "Fetching all Recovery Services Vault(s) in Subscription: [$($context.Subscription.SubscriptionId)]" -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
    
            # Get all Recovery Services Vault(s) in a Subscription
            $RecoveryServiceVaultDetailsForSubscription = Get-AzRecoveryServicesVault -ErrorAction Stop

            # Get Recovery Services Vault(s) properties
            $RecoveryServiceVaultDetailsForSubscription | ForEach-Object {                
    
                try {                
                    $RecoveryServiceVaultResource = Get-AzRecoveryServicesVault -ResourceGroupName $_.ResourceGroupName -Name $_.Name -ErrorAction SilentlyContinue
                    $RecoveryServiceVaultDetails += Get-RecoveryServiceVaultDetails $RecoveryServiceVaultResource
                }
                catch {
                    Write-Host "Error fetching Recovery Services Vault(s) resource: Resource ID:  [$($resourceId)]. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                }
            
            }
        }
        else {
            if (-not (Test-Path -Path $FilePath)) {
                Write-Host "ERROR: Input file: [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host $([Constants]::DoubleDashLine)	
                return
            }
            Write-Host "Fetching all Recovery Services Vault(s) from [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            $RecoveryServiceVaults = Import-Csv -LiteralPath $FilePath
    
            $validRecoveryServiceVaults = $RecoveryServiceVaults | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) }
    
            $validRecoveryServiceVaults | ForEach-Object {
                $resourceId = $_.ResourceId
    
                try {                
                    $RecoveryServiceVaultResource = Get-AzRecoveryServicesVault -ResourceGroupName $_.ResourceGroupName -Name $_.ResourceName -ErrorAction SilentlyContinue
                    $RecoveryServiceVaultDetails += Get-RecoveryServiceVaultDetails $RecoveryServiceVaultResource
                }
                catch {
                    Write-Host "Error fetching Recovery Services Vault(s) resource: Resource ID:  [$($resourceId)]. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                }
            }
        }
    }

    $totalRecoveryServiceVaults = ($RecoveryServiceVaultDetails | Measure-Object).Count

    if ($totalRecoveryServiceVaults -eq 0) {
        Write-Host "No Recovery Services Vault(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)	
        return
    }

    Write-Host "Found [$($totalRecoveryServiceVaults)] Recovery Services Vault(s)." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)
    
    # Recovery Services Vault(s) where immutability is not locked
    $RecoveryServiceVaultsWithoutImmutability = @()

    Write-Host "Separating Recovery Services Vault(s) for which immutability is not locked..." -ForegroundColor $([Constants]::MessageType.Info)
 
    $RecoveryServiceVaultDetails | ForEach-Object {
        $RecoveryServiceVault = $_
        if ($_.ImmutabilityState -ine "LOCKED" -and -not [string]::IsNullOrEmpty($_.ImmutabilityState)  ) {
            $RecoveryServiceVaultsWithoutImmutability += $RecoveryServiceVault
        }
    }
 
    $totalRecoveryServiceVaultsWithoutImmutability = ($RecoveryServiceVaultsWithoutImmutability | Measure-Object).Count
 
    if ($totalRecoveryServiceVaultsWithoutImmutability -eq 0) {
        Write-Host "No Recovery Services Vault(s) found where immutability is not locked. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)    
        return
    }
 
    Write-Host "Found [$($totalRecoveryServiceVaultsWithoutImmutability)] Recovery Services Vault(s) where immutability is not locked." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)    
 
    $colsProperty = @{Expression = { $_.ResourceName }; Label = "Resource Name"; Width = 20; Alignment = "left" },
    @{Expression = { $_.ResourceGroupName }; Label = "Resource Group"; Width = 20; Alignment = "left" },
    @{Expression = { $_.ResourceId }; Label = "Resource ID"; Width = 80; Alignment = "left" },
    @{Expression = { $_.ImmutabilityState }; Label = "Immutability State"; Width = 50; Alignment = "left" }
 
    if (-not $AutoRemediation) {
        Write-Host "Recovery Services Vault(s) without Locked Immutability:"
        $RecoveryServiceVaultsWithoutImmutability | Format-Table -Property $colsProperty -Wrap
        Write-Host $([Constants]::SingleDashLine)
    }
 
    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\SetRecoveryServiceVaultImmutability"
 
    if (-not (Test-Path -Path $backupFolderPath)) {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
  
    Write-Host "[Step 3 of 4] Back up Recovery Services Vault(s) details..."
    Write-Host $([Constants]::SingleDashLine)
 
    if ([String]::IsNullOrWhiteSpace($FilePath)) {
        # Backing up Recovery Services Vault(s) details.
        $backupFile = "$($backupFolderPath)\RecoveryServiceVaultDetailsBackUp.csv"
        $RecoveryServiceVaultsWithoutImmutability | Export-CSV -Path $backupFile -NoTypeInformation
        Write-Host "Recovery Services Vault(s) details have been backed up to [$($backupFile)]" -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }
    else {
        Write-Host "Skipped as -FilePath is provided" -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }
 
    if (-not $DryRun) {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4] Enable and lock immutability on Recovery Services Vault(s) in the Subscription..." 
        Write-Host $([Constants]::SingleDashLine)
         
        if (-not $Force) {
            Write-Host "Do you want to enable and lock immutability on Recovery Services Vault(s) in the Subscription? " -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host "Note: This action is irreversible. Once locked, immutability cannot be disabled." -ForegroundColor $([Constants]::MessageType.Warning)
            $userInput = Read-Host -Prompt "(Y|N)"
            if ($userInput -ne "Y") {
                Write-Host "Immutability will not be enabled and locked on Recovery Services Vault(s) in the Subscription. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::DoubleDashLine)    
                return
            }
        }
        else {
            Write-Host "'Force' flag is provided. Proceeding to enable and lock immutability on Recovery Services Vault(s) without any prompts..." -ForegroundColor $([Constants]::MessageType.Warning)
        }
 
        # List for storing remediated Recovery Services Vaults(s)
        $RecoveryServiceVaultsRemediated = @()
 
        # List for storing skipped Recovery Services Vaults(s)
        $RecoveryServiceVaultsSkipped = @()
 
        # Enable and lock immutability on each Recovery Services Vault
        # Loop through the list of Recovery Services Vault(s) which needs to be remediated.
        $RecoveryServiceVaultsWithoutImmutability | ForEach-Object {
            $RecoveryServiceVault = $_
            try {
                
                # Check if ImmutabilityState is Disabled, and if Disabled first enable and then lock the state       
                if ($RecoveryServiceVault.ImmutabilityState -ieq "Disabled" ) {
                    $RecoveryServiceVaultResource = Update-AzRecoveryServicesVault -ResourceGroupName $_.ResourceGroupName -Name $_.ResourceName -ImmutabilityState Unlocked -ErrorAction Stop 
                   
                    #Updating the immutablity state of resource
                    $RecoveryServiceVault.ImmutabilityState = $RecoveryServiceVaultResource.Properties.ImmutabilitySettings.ImmutabilityState;
                }
                
                
                if ($RecoveryServiceVault.ImmutabilityState -ieq "Unlocked" ) {
                    $RecoveryServiceVaultResource = Update-AzRecoveryServicesVault -ResourceGroupName $_.ResourceGroupName -Name $_.ResourceName -ImmutabilityState Locked -ErrorAction Stop 
                }

 
                if ($RecoveryServiceVaultResource.Properties.ImmutabilitySettings.ImmutabilityState.ToString() -ieq "LOCKED") {
                    $RecoveryServiceVaultsRemediated += $RecoveryServiceVault
                    $logResource = @{}    
                    $logResource.Add("ResourceGroupName", ($_.ResourceGroupName))    
                    $logResource.Add("ResourceName", ($_.ResourceName))    
                    $logRemediatedResources += $logResource    
                }
                else {
                    $RecoveryServiceVaultsSkipped += $RecoveryServiceVault
                    $logResource = @{}    
                    $logResource.Add("ResourceGroupName", ($_.ResourceGroupName))    
                    $logResource.Add("ResourceName", ($_.ResourceName))
                    $logResource.Add("Reason", "Error enabling and locking immutability for Recovery Services Vault: [$($RecoveryServiceVault)]")            
                    $logSkippedResources += $logResource    
                }
                
                 
            }
            catch {
                $RecoveryServiceVaultsSkipped += $RecoveryServiceVault
                $logResource = @{}    
                $logResource.Add("ResourceGroupName", ($_.ResourceGroupName))    
                $logResource.Add("ResourceName", ($_.ResourceName))    
                $logResource.Add("Reason", "Error enabling and locking immutability for Recovery Services Vault")        
                $logSkippedResources += $logResource                
                Write-Host $([Constants]::SingleDashLine)
            }
        }
 
        Write-Host $([Constants]::DoubleDashLine)
         
         
        if ($AutoRemediation) {
            if ($($RecoveryServiceVaultsRemediated | Measure-Object).Count -gt 0) {
                # Write this to a file.
                $RecoveryServiceVaultsRemediatedFile = "$($backupFolderPath)\RemediatedRecoveryServiceVaults.csv"
                $RecoveryServiceVaultsRemediated | Export-CSV -Path $RecoveryServiceVaultsRemediatedFile -NoTypeInformation
 
                Write-Host "The information related to Recovery Services Vault(s) where immutability was enabled and locked has been saved to [$($RecoveryServiceVaultsRemediatedFile)]." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
            }
         
            if ($($RecoveryServiceVaultsSkipped | Measure-Object).Count -gt 0) {
                $RecoveryServiceVaultsSkipped | Format-Table -Property $colsProperty -Wrap            
                # Write this to a file.
                $RecoveryServiceVaultsSkippedFile = "$($backupFolderPath)\SkippedRecoveryServiceVaults.csv"
                $RecoveryServiceVaultsSkipped | Export-CSV -Path $RecoveryServiceVaultsSkippedFile -NoTypeInformation
                Write-Host "The information related to Recovery Services Vault(s) where immutability could not be enabled and locked has been saved to [$($RecoveryServiceVaultsSkippedFile)]." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }
        }
        else {
            Write-Host "Remediation Summary: " -ForegroundColor $([Constants]::MessageType.Info)
            if ($($RecoveryServiceVaultsRemediated | Measure-Object).Count -gt 0) {
                Write-Host "Successfully enabled and locked immutability for the following Recovery Services Vault(s) in the subscription:" -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
                $RecoveryServiceVaultsRemediated | Format-Table -Property $colsProperty -Wrap
 
                # Write this to a file.
                $RecoveryServiceVaultsRemediatedFile = "$($backupFolderPath)\RemediatedRecoveryServiceVaults.csv"
                $RecoveryServiceVaultsRemediated | Export-CSV -Path $RecoveryServiceVaultsRemediatedFile -NoTypeInformation
 
                Write-Host "This information has been saved to" -NoNewline
                Write-Host " [$($RecoveryServiceVaultsRemediatedFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
                Write-Host "Note: This action is irreversible. Immutability cannot be disabled once locked." -ForegroundColor $([Constants]::MessageType.Info)
            }
         
            if ($($RecoveryServiceVaultsSkipped | Measure-Object).Count -gt 0) {
                Write-Host "Error while enabling and locking immutability for Recovery Services Vault(s) in the subscription:" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host $([Constants]::SingleDashLine)
                $RecoveryServiceVaultsSkipped | Format-Table -Property $colsProperty -Wrap
             
                # Write this to a file.
                $RecoveryServiceVaultsSkippedFile = "$($backupFolderPath)\SkippedRecoveryServiceVaults.csv"
                $RecoveryServiceVaultsSkipped | Export-CSV -Path $RecoveryServiceVaultsSkippedFile -NoTypeInformation
                Write-Host "This information has been saved to"  -NoNewline
                Write-Host " [$($RecoveryServiceVaultsSkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update)
            }
        }
        if ($AutoRemediation) {
            $logFile = "LogFiles\" + $($TimeStamp) + "\log_" + $($SubscriptionId) + ".json"
            $log = Get-content -Raw -path $logFile | ConvertFrom-Json
            foreach ($logControl in $log.ControlList) {
                if ($logControl.ControlId -eq $controlIds) {
                    $logControl.RemediatedResources = $logRemediatedResources
                    $logControl.SkippedResources = $logSkippedResources
                    $logControl.RollbackFile = $RecoveryServiceVaultsRemediatedFile
                }
            }
            $log | ConvertTo-json -depth 10  | Out-File $logFile
        }
    }
    else {
        Write-Host "[Step 4 of 4] Enable and lock immutability for Recovery Services Vault(s) in the Subscription." 
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Skipped as -DryRun switch is provided." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Next steps:" -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host "Run the same command with -FilePath [$($backupFile)] and without -DryRun, to enable and lock immutability on Recovery Services Vault(s) listed in the file." -ForegroundColor $([Constants]::MessageType.Warning)
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