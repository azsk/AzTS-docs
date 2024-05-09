<###
# Overview:
    This script is used to remediate Entra ID (formerly AAD) Authentication Extension on Linux VMSS in a Subscription.

# Control ID:
    Azure_VirtualMachineScaleSet_AuthN_Enable_Microsoft_Entra_ID_Auth_Linux

# Display Name:
    Entra ID (formerly AAD) extension must be deployed to the Linux VMSS

# Prerequisites:
    Contributor or higher priviliged role on the Virtual Machine Scale Set(s) is required for remediation.

# Steps performed by the script:
    To remediate:
        1. Validating and installing the modules required to run the script and validating the user.
        2. Get the list of Linux VMSS(s) in a Subscription with Uniform orchestration mode that doesn't have VM Entra ID (formerly AAD) Extension installed.
        3. Back up details of Linux VMSS(s) that are to be remediated.
        4. Install Entra ID (formerly AAD) Authentication Extension on Linux VMSS(s) in the Subscription.

    To validate:
        1. Validate and install the modules required to run the script and validating the user.
        2. Get the list of Linux VMSS(s) with Uniform orchestration mode in a Subscription, the changes made to which previously, are to be validated.
        3. Validate the extension and its provisioning state on all remediated Virtual Machine in the subscription.

    To roll back:
        1. Validate and install the modules required to run the script and validating the user.
        2. Get the list of Linux VMSS(s) with Uniform orchestration mode in a Subscription, the changes made to which previously, are to be rolled back.
        3. Roll back extension on all VMSS(s) in the Subscription.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to add Entra ID (formerly AAD) extension on Virtual Machine Scale Set(s) in the Subscription. Refer `Examples`, below.

    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to remove Entra ID (formerly AAD) extension on Virtual Machine Scale Set(s) in the Subscription. Refer `Examples`, below.

# Examples:
    To remediate:
        1. To review the Virtual Machine Scale Set(s) in a Subscription that will be remediated:
    
           Add-AADAuthExtensionforVMSS -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        2. Configure required Entra ID (formerly AAD) extension on Virtual Machine Scale Set(s) in the Subscription:
       
           Add-AADAuthExtensionforVMSS -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        3. Configure required Entra ID (formerly AAD) extension on Virtual Machine Scale Set(s) in the Subscription, from a previously taken snapshot:
       
           Add-AADAuthExtensionforVMSS -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202205200418\AADAuthExtForLinuxVm\NonCompliantVMs.csv

        To know more about the options supported by the remediation command, execute:
        
        Get-Help Add-AADAuthExtensionforVMSS -Detailed

    To validate the extension:
        1.  Validate required Entra ID (formerly AAD) extension on Virtual Machine Scale Set(s) in the Subscription, from a previously taken snapshot:
            Validate-AADAuthExtensionforVMSS -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202205200418\AADAuthExtForLinuxVm\RemediatedVirtualMachines.csv

    To roll back:
        1. Revert back Entra ID (formerly AAD) extension on Virtual Machine Scale Set(s) in the Subscription, from a previously taken snapshot:
           Remove-AADAuthExtensionforVMSS -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\AADAuthExtForLinuxVm\RemediatedVirtualMachines.csv
       
        To know more about the options supported by the roll back command, execute:
        
        Get-Help ReAdd-AADAuthExtensionforVMSS-Detailed        
###>


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
    $requiredModules = @("Az.Accounts", "Az.Compute", "AzureAD")

    Write-Host "Required modules: $($requiredModules -join ', ')" -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host "Checking if the required modules are present..."

    $availableModules = $(Get-Module -ListAvailable $requiredModules -ErrorAction Stop)

    # Check if the required modules are installed.
    $requiredModules | ForEach-Object {
        if ($availableModules.Name -notcontains $_) {
            Write-Host "Installing [$($_)] module..." -ForegroundColor $([Constants]::MessageType.Info)
            Install-Module -Name $_ -Scope CurrentUser -Repository 'PSGallery' -ErrorAction Stop
            Write-Host "[$($_)] module is installed." -ForegroundColor $([Constants]::MessageType.Update)
        }
        else {
            Write-Host "[$($_)] module is present." -ForegroundColor $([Constants]::MessageType.Update)
        }
    }
    Write-Host "All required modules are present." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)
}


function Add-AADAuthExtensionforVMSS {
    <#
        .SYNOPSIS
        Remediates 'Azure_VirtualMachineScaleSet_AuthN_Enable_Microsoft_Entra_ID_Auth_Linux' Control.

        .DESCRIPTION
        Remediates 'Azure_VirtualMachineScaleSet_AuthN_Enable_Microsoft_Entra_ID_Auth_Linux' Control.
        Entra ID (formerly AAD) extension must be deployed to the Linux VMSS. 
        
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
        
        .PARAMETER SkipBackup
        Specifies that no back up will be taken by the script before remediation.

        .INPUTS
        None. You cannot pipe objects to Add-AADAuthExtensionforVMSS.

        .OUTPUTS
        None. Add-AADAuthExtensionforVMSS does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Add-AADAuthExtensionforVMSS -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Add-AADAuthExtensionforVMSS -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        .EXAMPLE
        PS> Add-AADAuthExtensionforVMSS -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202205200418\AADAuthExtForLinuxVm\NonCompliantVMs.csv

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

        [Switch]
        [Parameter(ParameterSetName = "WetRun", HelpMessage = "Specifies no back up will be taken by the script before remediation")]
        $SkipBackup,

        [String]
        [Parameter(ParameterSetName = "WetRun", HelpMessage = "Specifies the path to the file to be used as input for the remediation")]
        $FilePath
    )

    Write-Host $([Constants]::DoubleDashLine)

    if ($PerformPreReqCheck) {
        try {
            Write-Host "[Step 1 of 4] Validating and installing the modules required to run the script and validating the user..."
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
        Write-Host "[Step 1 of 4] Validating the user... "
    }

    # Connect to Azure account
    $context = Get-AzContext

    if ([String]::IsNullOrWhiteSpace($context)) {
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Connecting to Azure account..."
        Connect-AzAccount -Subscription $SubscriptionId -ErrorAction Stop | Out-Null
        Write-Host "Connected to Azure account." -ForegroundColor $([Constants]::MessageType.Update)
    }

    # Setting up context for the current Subscription.
    $context = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop
    
    Write-Host "Current context has been set to below details: " -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host "Subscription Name: [$($context.Subscription.Name)]"
    Write-Host "Subscription ID: [$($context.Subscription.SubscriptionId)]"
    Write-Host "Account Name: [$($context.Account.Id)]"
    Write-Host "Account Type: [$($context.Account.Type)]"
    Write-Host $([Constants]::SingleDashLine)
        
    Write-Host "***To add Entra ID (formerly AAD) Authentication extension on Linux VMSS(s) in a Subscription, Contributor or higher privileges on the VMSS(s) are required.***" -ForegroundColor $([Constants]::MessageType.Warning)
   
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 4] Preparing to fetch all Virtual Machine Scale Set(s)..."
    Write-Host $([Constants]::SingleDashLine)
    
    # list to store resource details.
    $VMSSDetails = @()

    #Separated Linux VMSS(s)
    $NonCompliantVMSSDetails = @()

    $reqExtPublisher = "Microsoft.Azure.ActiveDirectory"
    $reqExtensionType = "Entra ID (formerly AAD) SSHLoginForLinux"
    $reqExtensionName = "Entra ID (formerly AAD) SSHLoginForLinux"

    # No file path provided as input to the script. Fetch all Virtual Machine Scale Set(s) in the Subscription.
    if ([String]::IsNullOrWhiteSpace($FilePath)) {
        try {
            Write-Host "Fetching all Virtual Machine Scale Set(s) in Subscription: $($context.Subscription.SubscriptionId)" -ForegroundColor $([Constants]::MessageType.Info)

            # Get all Virtual Machine Scale Set(s) in a Subscription
            $VMSSDetails = Get-AzVmss -ErrorAction Stop

            # Seperating required properties
            $VMSSDetails = $VMSSDetails | Select-Object @{N = 'ResourceId'; E = { $_.Id } },
            @{N = 'ResourceGroupName'; E = { $_.ResourceGroupName } },
            @{N = 'ResourceName'; E = { $_.Name } },
            @{N = 'OrchestrationMode'; E = { $_.OrchestrationMode } },
            @{N = 'OsType'; E = { $_.VirtualMachineProfile.StorageProfile.OsDisk.OsType } },
            @{N = 'Extensions'; E = { $_.VirtualMachineProfile.ExtensionProfile.Extensions } }

            Write-Host "Found [$($VMSSDetails.count)] Virtual Machine Scale Set(s) in the subscription..."
            Write-Host $([Constants]::SingleDashLine)                     
            
            Write-Host "Searching non-compliant Linux based Virtual Machine Scale Set(s) with 'Uniform' Orchestration mode..."
            Write-Host $([Constants]::SingleDashLine)
                                                
            $VMSSDetails | ForEach-Object {
                $VMSS = $_
                $VMSS | Add-Member -NotePropertyName isExtPresent -NotePropertyValue $false
                if ($VMSS.OrchestrationMode -eq "Uniform" -and $VMSS.OsType -eq "Linux") {
                    $VMSS.Extensions | ForEach-Object {
                        $VMSSExtension = $_
                        if ($VMSSExtension.Type -eq $reqExtensionType -and $VMSSExtension.Publisher -eq $reqExtPublisher) {
                            $VMSS.isExtPresent = $true
                        }
                    }
                    if (!$VMSS.isExtPresent) {
                        Write-Host "Entra ID (formerly AAD) Extension is not present in Virtual Machine Scale Set [$($VMSS.ResourceName)]..." -ForegroundColor $([Constants]::MessageType.Warning)
                        Write-Host $([Constants]::SingleDashLine)
                        $NonCompliantVMSSDetails += $VMSS
                    }
                    else
                    {
                        Write-Host "Entra ID (formerly AAD) Extension is present in Virtual Machine Scale Set [$($VMSS.ResourceName)]..." -ForegroundColor $([Constants]::MessageType.Warning)
                        Write-Host $([Constants]::SingleDashLine)
                    } 
                }
                else {
                    if ($VMSS.OrchestrationMode -eq "Flexible") {
                        Write-Host "Virtual Machine Scale Set [$($VMSS.ResourceName)] Orchestration type is Flexible. Skipping..." -ForegroundColor $([Constants]::MessageType.Warning)
                        Write-Host $([Constants]::SingleDashLine)
                    }
                    else {
                        Write-Host "Virtual Machine Scale Set [$($VMSS.ResourceName)] OS type is Windows. Skipping..." -ForegroundColor $([Constants]::MessageType.Warning)
                        Write-Host $([Constants]::SingleDashLine)
                    }
                }
            }

        }
        catch {
            Write-Host "Error fetching Virtual Machine Scale Set(s) from the subscription. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
        }    
    }
    else {
        if (-not (Test-Path -Path $FilePath)) {
            Write-Host "ERROR: Input file - $($FilePath) not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
            break
        }
        Write-Host "Fetching all Virtual Machine Scale Set(s) from [$($FilePath)]..." 

        $VMSSResources = Import-Csv -LiteralPath $FilePath
        $validVMSSResources = $VMSSResources | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) }
      
        $validVMSSResources | ForEach-Object {
            $VmssInfo = $_
            try {
                $VMSSResource = Get-AzVmss -ResourceGroupName $_.ResourceGroupName -VMScaleSetName $_.ResourceName -ErrorAction SilentlyContinue

                $VMSSDetails += $VMSSResource  | Select-Object @{N = 'ResourceId'; E = { $_.Id } },
                @{N = 'ResourceGroupName'; E = { $_.ResourceGroupName } },
                @{N = 'ResourceName'; E = { $_.Name } },
                @{N = 'OSType'; E = { $_.VirtualMachineProfile.StorageProfile.OsDisk.OsType } },
                @{N = 'isExtPresent'; E = { $VmssInfo.isExtPresent } } 
            }                                                      
            catch {
                Write-Host "Error fetching Virtual Machine Scale Set(s) resource: Resource ID - $($resourceId). Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            }
        }

        Write-Host "Found [$($VMSSDetails.count)] Virtual Machine Scale Set(s) in the subscription..."
        Write-Host $([Constants]::SingleDashLine)

        Write-Host "Searching non-compliant Linux based Virtual Machine Scale Set(s):" -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
                    
        $VMSSDetails | ForEach-Object {
            $VMInstance = $_
            if ($VMInstance.OSType -eq "Linux") {
                $NonCompliantVMSSDetails += $VMInstance
            }
        }  
    }

    $totalVMSS = ($NonCompliantVMSSDetails | Measure-Object).Count
    
    if ($totalVMSS -eq 0) {
        Write-Host "No Virtual machines Scale Set(s) found without Entra ID (formerly AAD) Extension present. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        break
    }
  
    Write-Host "Found [$($totalVMSS)] Virtual Machine Scale Set(s) without Entra ID (formerly AAD) authentication extension:" -ForegroundColor $([Constants]::MessageType.Update)                             
    Write-Host $([Constants]::SingleDashLine)

    $colsProperty = @{Expression = { $_.ResourceName }; Label = "ResourceName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.ResourceGroupName }; Label = "ResourceGroupName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.ResourceId }; Label = "ResourceId"; Width = 30; Alignment = "left" },
    @{Expression = { $_.OrchestrationMode }; Label = "OrchestrationMode"; Width = 30; Alignment = "left" },
    @{Expression = { $_.OSType }; Label = "OSType"; Width = 30; Alignment = "left" },
    @{Expression = { $_.isExtPresent }; Label = "isExtensionPresent"; Width = 30; Alignment = "left" }
        
    $NonCompliantVMSSDetails | Format-Table -Property $colsProperty -Wrap

    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\AADAuthExtForLinuxVMSS"

    if (-not (Test-Path -Path $backupFolderPath)) {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 4] Backing up Virtual Machine Scale Set(s) details..."
    Write-Host $([Constants]::SingleDashLine)

    if ([String]::IsNullOrWhiteSpace($FilePath)) {
        # Backing up Virtual Machine Scale Set(s) details.
        $backupFile = "$($backupFolderPath)\NonCompliantVMSS.csv"

        $NonCompliantVMSSDetails | Export-CSV -Path $backupFile -NoTypeInformation

        Write-Host "Virtual machines Scale Set(s) details have been backed up to" -NoNewline
        Write-Host " [$($backupFile)]" -ForegroundColor $([Constants]::MessageType.Update)
    }
    else {
        Write-Host "Skipped as -FilePath is provided" -ForegroundColor $([Constants]::MessageType.Warning)
    }

    if (-not $DryRun) {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4] Remediating non compliant Linux Virtual Machine Scale Sets..." 
        Write-Host $([Constants]::SingleDashLine)
        
        if (-not $Force) {
            Write-Host "Found total [$($NonCompliantVMSSDetails.count)] Virtual machines Scale Set(s) where Entra ID (formerly AAD) Extension is not present." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host "This step will add Entra ID (formerly AAD) extension for all non-complaint Virtual Machine Scale Set(s)." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host "Do you want to Continue? " -ForegroundColor $([Constants]::MessageType.Warning)
            
            $userInput = Read-Host -Prompt "(Y|N)"

            if ($userInput -ne "Y") {
                Write-Host "Entra ID (formerly AAD) Extension will not be added  to the Virtual machines Scale Set(s) in the Subscription. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
                break
            }
        }
        else {
            Write-Host "'Force' flag is provided. Entra ID (formerly AAD) extension will be added for Virtual Machine Scale Set(s) in the Subscription without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
        }

        # List for storing remediated Virtual Machines Scale set(s)
        $VMSSRemediated = @()

        # List for storing skipped Virtual Machines Scale Set(s)
        $VMSSSkipped = @()

        Write-Host "Adding Entra ID (formerly AAD) Extension on all non compliant Virtual Machines Scale Set(s)." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)

        # Loop through the list of Virtual Machines Scale Set(s) which needs to be remediated.
        $NonCompliantVMSSDetails | ForEach-Object {
            $VMSS = $_
            $VMSS | Add-Member -NotePropertyName isExtInstalledPostRemediation -NotePropertyValue $false

            Write-Host "Adding Entra ID (formerly AAD) Authentication Extension on [$($_.ResourceName)]." -ForegroundColor $([Constants]::MessageType.Info)
            try {
                # Remediation command starts from here
                $vmssInstance = Get-AzVmss -ResourceGroupName $VMSS.ResourceGroupName -VMScaleSetName $VMSS.ResourceName

                Add-AzVmssExtension -VirtualMachineScaleSet $vmssInstance -Name $reqExtensionName -Publisher $reqExtPublisher -Type $reqExtensionType -TypeHandlerVersion 1.0

                $VMExtension = Update-AzVmss -ResourceGroupName $VMSS.ResourceGroupName -Name $VMSS.ResourceName -VirtualMachineScaleSet $vmssInstance

                $VMExtension.VirtualMachineProfile.ExtensionProfile.Extensions | ForEach-Object {
                    $VMExt = $_
                    if ($VMExt.Publisher -eq $reqExtPublisher) {
                        $VMSS.isExtInstalledPostRemediation = $true
                        $VMSS.isExtPresent = $true
                    }
                }
                if ($VMSS.isExtInstalledPostRemediation = $true) {
                    Write-Host "Successfully installed Entra ID (formerly AAD) Extensions for [$($_.ResourceName)]." -ForegroundColor $([Constants]::MessageType.Update)
                    Write-Host $([Constants]::SingleDashLine)
                    $VMSSRemediated += $VMSS
                }
                else {
                    $VMSSSkipped += $VMSS
                    write-host "Skipping this Virtual Machine Scale Set resource." -foregroundcolor $([constants]::messagetype.warning)
                    write-host $([constants]::singledashline)
                }  
            }
            catch {
                $VMSSSkipped += $VMSS
                Write-Host $([Constants]::SingleDashLine)
                Write-Host "Skipping this Virtual Machine Scale Set resource." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }
        }

        $colsPropertyRemediated = @{Expression = { $_.ResourceName }; Label = "ResourceName"; Width = 30; Alignment = "left" },
        @{Expression = { $_.ResourceGroupName }; Label = "ResourceGroupName"; Width = 30; Alignment = "left" },
        @{Expression = { $_.ResourceId }; Label = "ResourceId"; Width = 30; Alignment = "left" },
        @{Expression = { $_.OSType }; Label = "OSType"; Width = 30; Alignment = "left" },
        @{Expression = { $_.OrchestrationMode }; Label = "OrchestrationMode"; Width = 30; Alignment = "left" },
        @{Expression = { $_.isExtPresent }; Label = "isExtensionPresent"; Width = 30; Alignment = "left" },
        @{Expression = { $_.isExtInstalledPostRemediation }; Label = "isExtInstalledPostRemediation"; Width = 30; Alignment = "left" }
       
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Remediation Summary: " -ForegroundColor $([Constants]::MessageType.Info)

        if ($($VMSSRemediated | Measure-Object).Count -gt 0) {
            Write-Host "Entra ID (formerly AAD) Extension have been installed on following Virtual Machine Scale Set(s) in the subscription:" -ForegroundColor $([Constants]::MessageType.Update)
           
            $VMSSRemediated | Format-Table -Property $colsPropertyRemediated -Wrap

            # Write this to a file.
            $VMSSRemediatedFile = "$($backupFolderPath)\RemediatedVMSS.csv"
            $VMSSRemediated | Export-CSV -Path $VMSSRemediatedFile -NoTypeInformation

            Write-Host "This information has been saved to" -NoNewline
            Write-Host " [$($VMSSRemediatedFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
            Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Info)
        }

        if ($($VMSSSkipped | Measure-Object).Count -gt 0) {
            Write-Host "Error installing Entra ID (formerly AAD) Extension on the following Virtual Machine Scale Set(s) in the subscription: " -ForegroundColor $([Constants]::MessageType.Error)
            $VMSSSkipped | Format-Table -Property $colsProperty -Wrap
            # Write this to a file.
            $VMSSSkippedFile = "$($backupFolderPath)\SkippedVMSS.csv"
            $VMSSSkipped | Export-CSV -Path $VMSSSkippedFile -NoTypeInformation
            Write-Host "This information has been saved to"  -NoNewline
            Write-Host " [$($VMSSSkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update)
        }
    }
    else {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4]  Remediating non compliant Virtual Machines Scale Set(s)..."
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Skipped as -DryRun switch is provided." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)

        Write-Host "Next steps:" -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "Run the same command with -FilePath $($backupFile) and without -DryRun to configure Entra ID (formerly AAD) Extension on Virtual Machine Scale Set(s) listed in the file."
    }
}

function Validate-AADAuthExtensionforVMSS {
    <#
        .SYNOPSIS
        Validates remediation done for 'Azure_VirtualMachineScaleSet_AuthN_Enable_Microsoft_Entra_ID_Auth_Linux' Control.

        .DESCRIPTION
        Validates remediation done for 'Azure_VirtualMachineScaleSet_AuthN_Enable_Microsoft_Entra_ID_Auth_Linux' Control.
        Entra ID (formerly AAD) extension must be deployed to the Linux VMSS. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that was previously remediated.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
      
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the roll back.

        .INPUTS
        None. You cannot pipe objects to Validate-AADAuthExtensionforVMSS.

        .OUTPUTS
        None. Validate-AADAuthExtensionforVMSS does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Validate-AADAuthExtensionforVMSS -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\AADAuthExtForLinuxVm\RemediatedVirtualMachines.csv

        .LINK
        None
    #>

    param (
        [String]
        [Parameter(Mandatory = $true, HelpMessage = "Specifies the ID of the Subscription that was previously remediated.")]
        $SubscriptionId,

        [Switch]
        [Parameter(HelpMessage = "Specifies a forceful roll back without any prompts")]
        $Force,

        [Switch]
        [Parameter(HelpMessage = "Specifies validation of prerequisites for the command")]
        $PerformPreReqCheck,

        [String]
        [Parameter(Mandatory = $true, HelpMessage = "Specifies the path to the file to be used as input for the roll back")]
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

    # Setting up context for the current Subscription.
    $context = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop
    
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Subscription Name: [$($context.Subscription.Name)]"
    Write-Host "Subscription ID: [$($context.Subscription.SubscriptionId)]"
    Write-Host "Account Name: [$($context.Account.Id)]"
    Write-Host "Account Type: [$($context.Account.Type)]"
    Write-Host $([Constants]::SingleDashLine)

    Write-Host "***To validate Entra ID (formerly AAD) Authentication extension on Linux VMSS(s) in a Subscription, Contributor or higher privileges on the VMSS(s) are required.***" -ForegroundColor $([Constants]::MessageType.Warning)
   
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 3] Preparing to fetch all Virtual Machine Scale Set(s)..."
    Write-Host $([Constants]::SingleDashLine)
    
    if (-not (Test-Path -Path $FilePath)) {
        Write-Host "ERROR: Input file - [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        break
    }

    Write-Host "Fetching all Linux Virtual Machine Scale Set(s) from" -NoNewline
    Write-Host " [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Update)
    $VMSSDetails = Import-Csv -LiteralPath $FilePath
    $validVMSSDetails = $VMSSDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) -and ![String]::IsNullOrWhiteSpace($_.ResourceGroupName) -and ![String]::IsNullOrWhiteSpace($_.ResourceName) }

    $totalVMSS = $(($validVMSSDetails | Measure-Object).Count)

    if ($totalVMSS -eq 0) {
        Write-Host "No Virtual Machine Scale Set(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        break
    }

    Write-Host "Found [$(($validVMSSDetails|Measure-Object).Count)] Virtual Machine Scale Set(s)." -ForegroundColor $([Constants]::MessageType.Update)

    $colsProperty = @{Expression = { $_.ResourceName }; Label = "ResourceName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.ResourceGroupName }; Label = "ResourceGroupName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.ResourceId }; Label = "ResourceId"; Width = 30; Alignment = "left" },
    @{Expression = { $_.OSType }; Label = "OSType"; Width = 30; Alignment = "left" },
    @{Expression = { $_.isExtInstalledPostRemediation }; Label = "isExtInstalledPostRemediation"; Width = 30; Alignment = "left" }
        
    $validVMSSDetails | Format-Table -Property $colsProperty -Wrap
    
    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\ValidateExtOnVMSS"

    if (-not (Test-Path -Path $backupFolderPath)) {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
  
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 3] Validating all remediated VMSS(s) in the Subscription..."
    Write-Host $([Constants]::SingleDashLine)

    # List for storing validated Virtual Machine Scale Set(s)
    $VMSSValidated = @()

    # List for storing skipped Virtual Machine Scale Set(s)
    $VMSSSkipped = @()

    $reqExtensionType = "AADSSHLoginForLinux"
    
    Write-Host "Starting validation..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

    $validVMSSDetails | ForEach-Object {
        $vmssdetails = $_
        $VmssExtDetails = @()
        $vmssdetails | Add-Member -NotePropertyName IsVmssValidated -NotePropertyValue $false
        # Getting all classic role assignments.
        $VMSSExtList = [VMSSExtensionList]::new()
        $res = $VMSSExtList.GetVMSSExtensionList($subscriptionId, $vmssdetails.ResourceGroupName, $vmssdetails.ResourceName)
    
        if ($null -ne $res) {
            $res.value | ForEach-Object {
                $resourceId = $_.id
                $extName = $_.name
                $provisioningState = $_.properties.provisioningState
                $publisher = $_.properties.publisher
                $type = $_.properties.type 
                $VmssExtDetails += $_ | Select-Object   @{N = 'Id'; E = { $resourceId } },
                @{N = 'ExtName'; E = { $extName } },
                @{N = 'provisioningState'; E = { $provisioningState } },
                @{N = 'publisher'; E = { $publisher } },
                @{N = 'type'; E = { $type } }
 
            }
            $VmssExtDetails | ForEach-Object {
        
                if ($_.type -eq $reqExtensionType) {
                    if ($_.provisioningState -eq "Succeeded") {
                        $vmssdetails.IsVmssValidated = true
                    }
                }
            }
            if ($IsVmssValidated) {
                $VMSSValidated += $vmssdetails
            }
            else {
                $VMSSSkipped += $vmssdetails
            }
        }

    }

    $colsPropertyValidation = @{Expression = { $_.ResourceName }; Label = "ResourceName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.ResourceGroupName }; Label = "ResourceGroupName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.ResourceId }; Label = "ResourceId"; Width = 30; Alignment = "left" },
    @{Expression = { $_.OSType }; Label = "OSType"; Width = 30; Alignment = "left" },
    @{Expression = { $_.isExtInstalledPostRemediation }; Label = "isExtInstalledPostRemediation"; Width = 30; Alignment = "left" },
    @{Expression = { $_.IsVmssValidated }; Label = "IsRequiredExtensionProvisioningState"; Width = 30; Alignment = "left" }
     
    if ($($VMSSValidated | Measure-Object).Count -gt 0 -or $($VMSSSkipped | Measure-Object).Count -gt 0) {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Validation Summary: " -ForegroundColor $([Constants]::MessageType.Info)
        
        if ($($VMSSValidated | Measure-Object).Count -gt 0) {
            Write-Host "Entra ID (formerly AAD) Extension has been successfully validated on following Virtual Machine Scale Set(s) in the Subscription: " -ForegroundColor $([Constants]::MessageType.Update)
            $VMSSValidated | Format-Table -Property $colsPropertyValidation -Wrap

            # Write this to a file.
            $ValidatedVirtualMachinesFile = "$($backupFolderPath)\ValidatedVMSS.csv"
            $VMSSValidated | Export-CSV -Path $ValidatedVirtualMachinesFile -NoTypeInformation
            Write-Host "This information has been saved to" -NoNewline
            Write-Host " [$($ValidatedVirtualMachinesFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
            Write-Host $([Constants]::SingleDashLine)
        }

        if ($($VMSSSkipped | Measure-Object).Count -gt 0) {
            Write-Host "Following Virtual Machine Scale Set(s) Entra ID (formerly AAD) extension does not have provisioning state as succeeded in the Subscription: " -ForegroundColor $([Constants]::MessageType.Error)
            
            $VMSSSkipped | Format-Table -Property $colsPropertyValidation -Wrap
            
            # Write this to a file.
            $ValidationSkippedVirtualMachineFile = "$($backupFolderPath)\ValidationSkippedVMSS.csv"
            $VMSSSkipped | Export-CSV -Path $ValidationSkippedVirtualMachineFile -NoTypeInformation
            Write-Host "This information has been saved to" -NoNewline
            Write-Host " [$($ValidationSkippedVirtualMachineFile)]" -ForegroundColor $([Constants]::MessageType.Update)  
            Write-Host $([Constants]::SingleDashLine)

            Write-Host "For above VMSS(s), please manually re-install the Entra ID (formerly AAD) extension and check the provisioning state." -ForegroundColor $([Constants]::MessageType.Error)  

        }
    }
}


function Remove-AADAuthExtensionforVMSS {
    <#
        .SYNOPSIS
        Rolls back remediation done for 'Azure_VirtualMachineScaleSet_AuthN_Enable_Microsoft_Entra_ID_Auth_Linux' Control.

        .DESCRIPTION
        Rolls back remediation done for 'Azure_VirtualMachineScaleSet_AuthN_Enable_Microsoft_Entra_ID_Auth_Linux' Control.
        Entra ID (formerly AAD) extension must be deployed to the Linux VMSS. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that was previously remediated.
        
        .PARAMETER Force
        Specifies a forceful roll back without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
      
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the roll back.

        .INPUTS
        None. You cannot pipe objects to Remove-AADAuthExtensionforVMSS.

        .OUTPUTS
        None. Remove-AADAuthExtensionforVMSS does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Remove-AADAuthExtensionforVMSS -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\AADAuthExtForLinuxVm\RemediatedVMSS.csv

        .LINK
        None
    #>

    param (
        [String]
        [Parameter(Mandatory = $true, HelpMessage = "Specifies the ID of the Subscription that was previously remediated.")]
        $SubscriptionId,

        [Switch]
        [Parameter(HelpMessage = "Specifies a forceful roll back without any prompts")]
        $Force,

        [Switch]
        [Parameter(HelpMessage = "Specifies validation of prerequisites for the command")]
        $PerformPreReqCheck,

        [String]
        [Parameter(Mandatory = $true, HelpMessage = "Specifies the path to the file to be used as input for the roll back")]
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

    # Setting up context for the current Subscription.
    $context = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop
    
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Subscription Name: [$($context.Subscription.Name)]"
    Write-Host "Subscription ID: [$($context.Subscription.SubscriptionId)]"
    Write-Host "Account Name: [$($context.Account.Id)]"
    Write-Host "Account Type: [$($context.Account.Type)]"
    Write-Host $([Constants]::SingleDashLine)

    Write-Host "***To remove/uninstall Entra ID (formerly AAD) Authentication extension on Linux VMSS(s) in a Subscription, Contributor or higher privileges on the VMSS(s) are required.***" -ForegroundColor $([Constants]::MessageType.Warning)
   
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 3] Preparing to fetch all Virtual Machine Scale Set(s)..."
    Write-Host $([Constants]::SingleDashLine)
    
    if (-not (Test-Path -Path $FilePath)) {
        Write-Host "ERROR: Input file - [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        break
    }

    $reqExtPublisher = "Microsoft.Azure.ActiveDirectory"

    Write-Host "Fetching all Linux Virtual Machine Scale Set(s) from" -NoNewline
    Write-Host " [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Update)
    $VMSSDetails = Import-Csv -LiteralPath $FilePath

    $validVMSSDetails = $VMSSDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) -and ![String]::IsNullOrWhiteSpace($_.ResourceGroupName) -and ![String]::IsNullOrWhiteSpace($_.ResourceName) }

    $totalVMSS = $(($validVMSSDetails | Measure-Object).Count)

    if ($totalVMSS -eq 0) {
        Write-Host "No Virtual Machine Scale Set(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        break
    }

    Write-Host "Found [$(($validVMSSDetails|Measure-Object).Count)] Virtual Machine Scale Set(s)." -ForegroundColor $([Constants]::MessageType.Update)

    $colsProperty = @{Expression = { $_.ResourceName }; Label = "ResourceName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.ResourceGroupName }; Label = "ResourceGroupName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.ResourceId }; Label = "ResourceId"; Width = 30; Alignment = "left" },
    @{Expression = { $_.OSType }; Label = "OSType"; Width = 30; Alignment = "left" },
    @{Expression = { $_.OrchestrationMode }; Label = "OrchestrationMode"; Width = 30; Alignment = "left" },
    @{Expression = { $_.isExtInstalledPostRemediation }; Label = "isExtInstalledPostRemediation"; Width = 30; Alignment = "left" }
        
    $validVMSSDetails | Format-Table -Property $colsProperty -Wrap
    
    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\RollbackExtOnVMSS"

    if (-not (Test-Path -Path $backupFolderPath)) {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
  
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 3] Rolling back all remediated VMSS(s) in the Subscription..."
    Write-Host $([Constants]::SingleDashLine)

    if ( -not $Force) {
        Write-Host "This will remove the Entra ID (formerly AAD) Authentication Extension from the VMSS(s). Do you want to continue roll back operation?"  -ForegroundColor $([Constants]::MessageType.Warning)
        $userInput = Read-Host -Prompt "(Y|N)"
        if ($userInput -ne "Y") {
            Write-Host "Entra ID (formerly AAD) Authentication Extension will not be rolled back for any VMSS(s) in the Subscription. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
            break
        }
    }
    else {
        Write-Host "'Force' flag is provided. Entra ID (formerly AAD) extension in VMSS(s) will be removed in the Subscription without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
    }

    # List for storing rolled back Virtual Machine Scale Set resource.
    $VMSSRolledBack = @()

    # List for storing skipped rolled back Virtual Machine Scale Set resource.
    $VMSSSkipped = @()

    Write-Host "Starting Roll back operation..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

    $validVMSSDetails | ForEach-Object {
        $VMSS = $_
        $VMSS | Add-Member -NotePropertyName isAADExtRolledback -NotePropertyValue $false
        try {
            
            Write-Host "Rolling back Entra ID (formerly AAD) Authentication Extension on Virtual Machine Scale Set(s) - [$($_.ResourceName)]" -ForegroundColor $([Constants]::MessageType.Info)
            if ($_.isExtInstalledPostRemediation) {
                $vmssInstance = Get-AzVmss -ResourceGroupName $VMSS.ResourceGroupName -VMScaleSetName $VMSS.ResourceName 
                Remove-AzVmssExtension -VirtualMachineScaleSet $vmssInstance -Name 'AADSSHLoginForLinux'
                $VMSSResource = Update-AzVmss -ResourceGroupName $VMSS.ResourceGroupName -Name $VMSS.ResourceName -VirtualMachineScaleSet $vmssInstance
                    
                $VMSSResource.VirtualMachineProfile.ExtensionProfile.Extensions | ForEach-Object {
                    $VMExtension = $_
                    if ($VMExtension.Publisher -eq ($reqExtPublisher)) {
                        $VMSS.isAADExtRolledback = $false
                        $VMSS.isExtPresent = $true
                    }
                }

                if (!$VMSS.isAADExtRolledback) {
                    $VMSS.isAADExtRolledback = $true
                    $VMSS.isExtPresent = $false
                    Write-Host "Successfully uninstalled Entra ID (formerly AAD) Extensions for [$($_.ResourceName)]." -ForegroundColor $([Constants]::MessageType.Update)
                    Write-Host $([Constants]::SingleDashLine)
                    $VMSSRolledBack += $VMSS
                }
                else {
                    $VMSSSkipped += $VMSS
                    write-host "Skipping this Virtual Machine Scale Set resource [$($_.ResourceName)]." -foregroundcolor $([constants]::messagetype.warning)
                    write-host $([constants]::singledashline)
                }
            }
        }
        catch {
            $VMSSSkipped += $VMSS
        }
    }

    $colsPropertyRollBack = @{Expression = { $_.ResourceName }; Label = "ResourceName"; Width = 25; Alignment = "left" },
    @{Expression = { $_.ResourceGroupName }; Label = "ResourceGroupName"; Width = 25; Alignment = "left" },
    @{Expression = { $_.ResourceId }; Label = "ResourceId"; Width = 25; Alignment = "left" },
    @{Expression = { $_.OsType }; Label = "OsType"; Width = 25; Alignment = "left" },
    @{Expression = { $_.OrchestrationMode }; Label = "OrchestrationMode"; Width = 25; Alignment = "left" },
    @{Expression = { $_.isExtPresent }; Label = "isExtPresent"; Width = 25; Alignment = "left" },
    @{Expression = { $_.isAADExtRolledback }; Label = "isAADExtRolledback"; Width = 25; Alignment = "left" }
     
    if ($($VMSSRolledBack | Measure-Object).Count -gt 0 -or $($VMSSSkipped | Measure-Object).Count -gt 0) {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Rollback Summary: " -ForegroundColor $([Constants]::MessageType.Info)
        
        if ($($VMSSRolledBack | Measure-Object).Count -gt 0) {
            Write-Host "Entra ID (formerly AAD) extension is rolled back successfully on following Virtual Machine Scale Set(s) in the Subscription: " -ForegroundColor $([Constants]::MessageType.Update)
            $VMSSRolledBack | Format-Table -Property $colsPropertyRollBack -Wrap

            # Write this to a file.
            $VMSSRolledBackFile = "$($backupFolderPath)\RolledBackVMSS.csv"
            $VMSSRolledBack | Export-CSV -Path $VMSSRolledBackFile -NoTypeInformation
            Write-Host "This information has been saved to" -NoNewline
            Write-Host " [$($VMSSRolledBackFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
            Write-Host $([Constants]::SingleDashLine)
        }

        if ($($VMSSSkipped | Measure-Object).Count -gt 0) {
            Write-Host "Error installing Entra ID (formerly AAD) Extension on following Virtual Machine Scale Set(s) in the Subscription: " -ForegroundColor $([Constants]::MessageType.Warning)
            
            $VMSSSkipped | Format-Table -Property $colsProperty -Wrap
            
            # Write this to a file.
            $VMSSSkippedFile = "$($backupFolderPath)\RollbackSkippedVMSS.csv"
            $VMSSSkipped | Export-CSV -Path $VMSSSkippedFile -NoTypeInformation
            Write-Host "This information has been saved to" -NoNewline
            Write-Host " [$($VMSSSkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update)  
            Write-Host $([Constants]::SingleDashLine)  
        }
    }
}

class VMSSExtensionList {
    [PSObject] GetVMSSExtensionList([string] $subscriptionId, [string] $ResourceGroupName, [string] $ResourceName) {
        $content = $null
        try {
            $armUri = "https://management.azure.com/subscriptions/$($subscriptionId)/resourceGroups/$($ResourceGroupName)/providers/Microsoft.Compute/virtualMachineScaleSets/$($ResourceName)/extensions?api-version=2023-03-01"
            $headers = $this.GetAuthHeader()
            # API to get classic role assignments
            $response = Invoke-WebRequest -Method Get -Uri $armUri -Headers $headers -UseBasicParsing
            $content = ConvertFrom-Json $response.Content
        }
        catch {
            Write-Host "Error occurred while fetching classic role assignment. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
        }
        
        return($content)
    }

    [PSObject] GetAuthHeader() {
        [psobject] $headers = $null
        try {
            $resourceAppIdUri = "https://management.core.windows.net/"
            $rmContext = Get-AzContext
            $authResult = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate(
                $rmContext.Account,
                $rmContext.Environment,
                $rmContext.Tenant,
                [System.Security.SecureString] $null,
                "Never",
                $null,
                $resourceAppIdUri); 
            $header = "Bearer " + $authResult.AccessToken
            $headers = @{"Authorization" = $header; "Content-Type" = "application/json"; }
        }
        catch {
            Write-Host "Error occurred while fetching auth header. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)   
        }
        return($headers)
    }
}

# Defines commonly used constants.
class Constants {
    # Defines commonly used colour codes, corresponding to the severity of the log.
    static [Hashtable] $MessageType = @{
        Error   = [System.ConsoleColor]::Red
        Warning = [System.ConsoleColor]::Yellow
        Info    = [System.ConsoleColor]::Cyan
        Update  = [System.ConsoleColor]::Green
        Default = [System.ConsoleColor]::White
    }

    static [String] $DoubleDashLine = "========================================================================================================================"
    static [String] $SingleDashLine = "------------------------------------------------------------------------------------------------------------------------"

}
