<#
.SYNOPSIS
Remediates 'Azure_RecoveryServicesVault_DP_Enable_Soft_Delete' Control.
.DESCRIPTION
Remediates 'Azure_RecoveryServicesVault_DP_Enable_Soft_Delete' Control.
Always-on soft delete must be enabled on Recovery Services Vault. 
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
None. You cannot pipe objects to Set-SoftDeleteForRecoveryServicesVault.
.OUTPUTS
None. Set-SoftDeleteForRecoveryServicesVault does not return anything that can be piped and used as an input to another command.
.EXAMPLE
PS> Set-SoftDeleteForRecoveryServicesVault -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun
.EXAMPLE
PS> Set-SoftDeleteForRecoveryServicesVault -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck
.EXAMPLE
PS> Set-SoftDeleteForRecoveryServicesVault -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetRecoveryServicesVaultsoftDelete\RecoveryServicesVaultDetailsBackUp.csv 
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

function Get-RecoveryServiceVaultDetails {
    param (
        [Parameter(Mandatory = $true)]
        $RecoveryServiceVaultDetails,

        [Parameter(Mandatory = $true)]
        $RecoveryServiceVaultPropertyDetails
    )
    return $RecoveryServiceVaultDetails | Select-Object @{N = 'ResourceId'; E = { $_.Id } },
    @{N = 'ResourceGroupName'; E = { $_.ResourceGroupName } },
    @{N = 'SoftDeleteState'; E = { $RecoveryServiceVaultPropertyDetails.SoftDeleteFeatureState } },
    @{N = 'ResourceName'; E = { $_.Name } }
}

function Set-SoftDeleteForRecoveryServicesVault {
    <#
    .SYNOPSIS
    Remediates 'Azure_RecoveryServicesVault_DP_Enable_Soft_Delete' Control.
    .DESCRIPTION
    Remediates 'Azure_RecoveryServicesVault_DP_Enable_Soft_Delete' Control.
    Always-on soft delete must be enabled on Recovery Services Vault. 
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
    None. You cannot pipe objects to Set-SoftDeleteForRecoveryServicesVault.
    .OUTPUTS
    None. Set-SoftDeleteForRecoveryServicesVault does not return anything that can be piped and used as an input to another command.
    .EXAMPLE
    PS> Set-SoftDeleteForRecoveryServicesVault -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun
    .EXAMPLE
    PS> Set-SoftDeleteForRecoveryServicesVault -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck
    .EXAMPLE
    PS> Set-SoftDeleteForRecoveryServicesVault -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetRecoveryServicesVaultsoftDelete\RecoveryServicesVaultDetailsBackUp.csv
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

    Write-Host "To enable AlwaysOn soft delete for Recovery Services Vault(s) in a Subscription, Contributor or higher privileged role assignment on the Recovery Services Vault(s) is required." -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host $([Constants]::SingleDashLine)

    Write-Host "[Step 2 of 4] Fetch all Recovery Services Vault(s)"
    Write-Host $([Constants]::SingleDashLine)

    # list to store Recovery Services Vault details.
    $RecoveryServicesVaultDetails = @()

    # To keep track of remediated and skipped resources	
    $logRemediatedResources = @()	
    $logSkippedResources = @()	

    # Control Id	
    $controlIds = "Azure_RecoveryServicesVault_DP_Enable_Soft_Delete"

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
                
                $RecoveryServicesVaultResource = Get-AzRecoveryServicesVault -ResourceGroupName $_.ResourceGroupName -Name $_.ResourceName -ErrorAction SilentlyContinue
                     
                # Get Vault property Details
                $vaultProperty = Get-AzRecoveryServicesVaultProperty -VaultId $RecoveryServicesVaultResource.Id
                $RecoveryServicesVaultDetails += Get-RecoveryServiceVaultDetails -RecoveryServiceVaultDetails $RecoveryServicesVaultResource -RecoveryServiceVaultPropertyDetails $vaultProperty
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
                    $RecoveryServiceVaultDetail = $_     
                      
                    # Get Vault property Details
                    $vaultProperty = Get-AzRecoveryServicesVaultProperty -VaultId $_.Id
                    $RecoveryServicesVaultDetails += Get-RecoveryServiceVaultDetails -RecoveryServiceVaultDetails $RecoveryServiceVaultDetail -RecoveryServiceVaultPropertyDetails $vaultProperty
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
            $RecoveryServicesVaults = Import-Csv -LiteralPath $FilePath

            $validRecoveryServicesVaults = $RecoveryServicesVaults | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) }

            $validRecoveryServicesVaults | ForEach-Object {
                $resourceId = $_.ResourceId

                try {
                    
                    $RecoveryServicesVaultResource = Get-AzRecoveryServicesVault -ResourceGroupName $_.ResourceGroupName -Name $_.ResourceName -ErrorAction SilentlyContinue
                     
                    # Get Vault property Details
                    $vaultProperty = Get-AzRecoveryServicesVaultProperty -VaultId $RecoveryServicesVaultResource.ID
                    $RecoveryServicesVaultDetails += Get-RecoveryServiceVaultDetails -RecoveryServiceVaultDetails $RecoveryServicesVaultResource -RecoveryServiceVaultPropertyDetails $vaultProperty
                }
                catch {
                    Write-Host "Error fetching Recovery Services Vault(s) resource: Resource ID:  [$($resourceId)]. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                }
            }
        }
    }

    $totalRecoveryServicesVaults = ($RecoveryServicesVaultDetails | Measure-Object).Count

    if ($totalRecoveryServicesVaults -eq 0) {
        Write-Host "No Recovery Services Vault(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)	
        return
    }

    Write-Host "Found [$($totalRecoveryServicesVaults)] Recovery Services Vault(s)." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)

    # Recovery Services Vault(s) where soft delete is not enabled
    $RecoveryServicesVaultsWithoutSoftDelete = @()
    $expectedSoftDeleteState = "AlwaysOn"

    Write-Host "Separating Recovery Services Vault(s) for which soft delete is not enabled..." -ForegroundColor $([Constants]::MessageType.Info)

    $RecoveryServicesVaultDetails | ForEach-Object {
        $RecoveryServicesVault = $_
        if ($_.SoftDeleteState) {
            if ($_.SoftDeleteState.ToString() -ne $expectedSoftDeleteState) {
                $RecoveryServicesVaultsWithoutSoftDelete += $RecoveryServicesVault
            }
        }
        else {
            $RecoveryServicesVaultsWithoutSoftDelete += $RecoveryServicesVault
        }
    }

    $totalRecoveryServicesVaultsWithoutSoftDelete = ($RecoveryServicesVaultsWithoutSoftDelete | Measure-Object).Count

    if ($totalRecoveryServicesVaultsWithoutSoftDelete -eq 0) {
        Write-Host "No Recovery Services Vault(s) found where soft delete is not enabled. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)	
        return
    }

    Write-Host "Found [$($totalRecoveryServicesVaultsWithoutSoftDelete)] Recovery Services Vault(s) where soft delete is not enabled." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)	

    $colsProperty = @{Expression = { $_.ResourceName }; Label = "Resource Name"; Width = 30; Alignment = "left" },
    @{Expression = { $_.ResourceGroupName }; Label = "Resource Group"; Width = 30; Alignment = "left" },
    @{Expression = { $_.ResourceId }; Label = "Resource ID"; Width = 80; Alignment = "left" },
    @{Expression = { $_.SoftDeleteState }; Label = "Soft Delete State"; Width = 40; Alignment = "left" }

    if (-not $AutoRemediation) {
        Write-Host "Recovery Services Vault(s) without SoftDelete as AlwaysOn:"
        $RecoveryServicesVaultsWithoutSoftDelete | Format-Table -Property $colsProperty -Wrap
        Write-Host $([Constants]::SingleDashLine)
    }

    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\SetRecoveryServicesVaultsoftDelete"

    if (-not (Test-Path -Path $backupFolderPath)) {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }

    Write-Host "[Step 3 of 4] Back up Recovery Services Vault(s) details..."
    Write-Host $([Constants]::SingleDashLine)

    if ([String]::IsNullOrWhiteSpace($FilePath)) {
        # Backing up Recovery Services Vault(s) details.
        $backupFile = "$($backupFolderPath)\RecoveryServicesVaultDetailsBackUp.csv"
        $RecoveryServicesVaultsWithoutSoftDelete | Export-CSV -Path $backupFile -NoTypeInformation
        Write-Host "Recovery Services Vault(s) details have been backed up to [$($backupFile)]" -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }
    else {
        Write-Host "Skipped as -FilePath is provided" -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }

    if (-not $DryRun) {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4] Enable AlwaysOn soft delete on Recovery Services Vault(s) in the Subscription..." 
        Write-Host $([Constants]::SingleDashLine)

        if (-not $Force) {
            Write-Host "Rollback command is not available.`nDo you want to enable AlwaysOn soft delete on Recovery Services Vault(s) in the Subscription? " -ForegroundColor $([Constants]::MessageType.Warning)
            $userInput = Read-Host -Prompt "(Y|N)"
            if ($userInput -ne "Y") {
                Write-Host "AlwaysOn soft delete will not be enabled on Recovery Services Vault(s) in the Subscription. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::DoubleDashLine)	
                return
            }
        }
        else {
            Write-Host "'Force' flag is provided. Proceeding to enable AlwaysOn soft delete on Recovery Services Vault(s) without any prompts..." -ForegroundColor $([Constants]::MessageType.Warning)
        }

        # List for storing remediated Recovery Services Vaults(s)
        $RecoveryServicesVaultsRemidiated = @()

        # List for storing skipped Recovery Services Vaults(s)
        $RecoveryServicesVaultsSkipped = @()

        # Enable AlwaysOn soft delete on each Recovery Services Vault
        # Loop through the list of Recovery Services Vault(s) which needs to be remediated.
        $RecoveryServicesVaultsWithoutSoftDelete | ForEach-Object {
            $RecoveryServicesVault = $_
            try {
                
                $RecoveryServicesVaultResource = Set-AzRecoveryServicesVaultProperty -VaultId $_.ResourceId -SoftDeleteFeatureState AlwaysON -ErrorAction Stop   

                if ($RecoveryServicesVaultResource.SoftDeleteFeatureState.ToString() -eq $expectedSoftDeleteState) {
                    $RecoveryServicesVaultsRemidiated += $RecoveryServicesVault
                    $logResource = @{}	
                    $logResource.Add("ResourceGroupName", ($_.ResourceGroupName))	
                    $logResource.Add("ResourceName", ($_.ResourceName))	
                    $logRemediatedResources += $logResource	
                }
                else {
                    $RecoveryServicesVaultsSkipped += $RecoveryServicesVault
                    $logResource = @{}	
                    $logResource.Add("ResourceGroupName", ($_.ResourceGroupName))	
                    $logResource.Add("ResourceName", ($_.ResourceName))
                    $logResource.Add("Reason", "Error configuring AlwaysOn for Recovery Services Vault: [$($RecoveryServicesVault)]")            
                    $logSkippedResources += $logResource	

                }

            }
            catch {
                $RecoveryServicesVaultsSkipped += $RecoveryServicesVault
                $logResource = @{}	
                $logResource.Add("ResourceGroupName", ($_.ResourceGroupName))	
                $logResource.Add("ResourceName", ($_.ResourceName))	
                $logResource.Add("Reason", "Error configuring AlwaysOn for Recovery Services Vault")    	
                $logSkippedResources += $logResource                
                Write-Host $([Constants]::SingleDashLine)
            }
        }

        Write-Host $([Constants]::DoubleDashLine)


        if ($AutoRemediation) {
            if ($($RecoveryServicesVaultsRemidiated | Measure-Object).Count -gt 0) {
                # Write this to a file.
                # RecoveryServicesVaultDetailsBackUp
                $RecoveryServicesVaultsRemediatedFile = "$($backupFolderPath)\RemediatedRecoveryServicesVaults.csv"
                $RecoveryServicesVaultsRemidiated | Export-CSV -Path $RecoveryServicesVaultsRemediatedFile -NoTypeInformation

                Write-Host "The information related to Recovery Services Vault(s) where AlwaysOn changed has been saved to [$($RecoveryServicesVaultsRemediatedFile)]" -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
            }

            if ($($RecoveryServicesVaultsSkipped | Measure-Object).Count -gt 0) {
                $RecoveryServicesVaultsSkipped | Format-Table -Property $colsProperty -Wrap            
                # Write this to a file.
                $RecoveryServicesVaultsSkippedFile = "$($backupFolderPath)\SkippedRecoveryServicesVaults.csv"
                $RecoveryServicesVaultsSkipped | Export-CSV -Path $RecoveryServicesVaultsSkippedFile -NoTypeInformation
                Write-Host "The information related to Recovery Services Vault(s) where AlwaysOn not changed has been saved to [$($RecoveryServicesVaultsSkippedFile)]" -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }
        }
        else {
            Write-Host "Remediation Summary: " -ForegroundColor $([Constants]::MessageType.Info)
            if ($($RecoveryServicesVaultsRemidiated | Measure-Object).Count -gt 0) {
                Write-Host "Successfully set the AlwaysOn for the following Recovery Services Vault(s) in the subscription:" -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
                $RecoveryServicesVaultsRemidiated | Format-Table -Property $colsProperty -Wrap

                # Write this to a file.
                $RecoveryServicesVaultsRemediatedFile = "$($backupFolderPath)\RemediatedRecoveryServicesVaults.csv"
                $RecoveryServicesVaultsRemidiated | Export-CSV -Path $RecoveryServicesVaultsRemediatedFile -NoTypeInformation

                Write-Host "This information has been saved to" -NoNewline
                Write-Host " [$($RecoveryServicesVaultsRemediatedFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
                Write-Host $([Constants]::SingleDashLine)
            }

            if ($($RecoveryServicesVaultsSkipped | Measure-Object).Count -gt 0) {
                Write-Host "Error while setting up the AlwaysOn in Recovery Services Vault(s) in the subscription:" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host $([Constants]::SingleDashLine)
                $RecoveryServicesVaultsSkipped | Format-Table -Property $colsProperty -Wrap

                # Write this to a file.
                $RecoveryServicesVaultsSkippedFile = "$($backupFolderPath)\SkippedRecoveryServicesVaults.csv"
                $RecoveryServicesVaultsSkipped | Export-CSV -Path $RecoveryServicesVaultsSkippedFile -NoTypeInformation
                Write-Host "This information has been saved to"  -NoNewline
                Write-Host " [$($RecoveryServicesVaultsSkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update)
            }
        }
        if ($AutoRemediation) {
            $logFile = "LogFiles\" + $($TimeStamp) + "\log_" + $($SubscriptionId) + ".json"
            $log = Get-content -Raw -path $logFile | ConvertFrom-Json
            foreach ($logControl in $log.ControlList) {
                if ($logControl.ControlId -eq $controlIds) {
                    $logControl.RemediatedResources = $logRemediatedResources
                    $logControl.SkippedResources = $logSkippedResources
                }
            }
            $log | ConvertTo-json -depth 10  | Out-File $logFile
        }
    }
    else {
        Write-Host "[Step 4 of 4] Set the AlwaysOn for Recovery Services Vault(s) in the Subscription." 
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Skipped as -DryRun switch is provided." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Next steps:" -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host "Run the same command with -FilePath [$($backupFile)] and without -DryRun, to Set AlwaysOn state on Recovery Services Vault(s) listed in the file." -ForegroundColor $([Constants]::MessageType.Warning)
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