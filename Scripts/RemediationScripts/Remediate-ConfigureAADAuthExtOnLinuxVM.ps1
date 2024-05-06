<###
# Overview:
    This script is used to remediate Entra Id (formerly AAD) Auth Extension on Linux VMs in a Subscription.

# Control ID:
    Azure_VirtualMachine_AuthN_Enable_Microsoft_Entra_ID_Auth_Linux

# Display Name:
    Entra Id (formerly AAD) extension must be deployed to the Linux VM

# Prerequisites:
    Contributor or higher priviliged role on the Virtual Machine(s) is required for remediation.
    Virtual Machine should be in running state.

# Steps performed by the script:
    To remediate:
        1. Validating and installing the modules required to run the script and validating the user.
        2. Get the list of Linux VM(s) in a Subscription that doesn't have VM Entra Id (formerly AAD) Extension installed.
        3. Back up details of Linux VM(s) that are to be remediated.
        4. Remediate Entra Id (formerly AAD) Auth Extension on Linux VM(s) in the Subscription.

    To validate:
        1. Validate and install the modules required to run the script and validating the user.
        2. Get the list of Linux VM(s) in a Subscription, the changes made to which previously, are to be validated.
        3. Validate the extension and its provisioning state on all remediated Virtual Machine in the subscription.

    To roll back:
        1. Validate and install the modules required to run the script and validating the user.
        2. Get the list of Linux VM(s) in a Subscription, the changes made to which previously, are to be rolled back.
        3. Roll back extension on all VM(s) in the Subscription.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to add Entra Id (formerly AAD) extension on Virtual Machine(s) in the Subscription. Refer `Examples`, below.

    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to remove Entra Id (formerly AAD) extension on Virtual Machine(s) in the Subscription. Refer `Examples`, below.

# Examples:
    To remediate:
        1. To review the Virtual Machine(s) in a Subscription that will be remediated:
    
           Add-AADAuthExtensionforVMs -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        2. Configure required Entra Id (formerly AAD) extension on Virtual Machine(s) in the Subscription:
       
           Add-AADAuthExtensionforVMs -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        3. Configure required Entra Id (formerly AAD) extension on Virtual Machine(s) in the Subscription, from a previously taken snapshot:
       
           Add-AADAuthExtensionforVMs -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202205200418\AADAuthExtForLinuxVm\NonCompliantVMs.csv

        To know more about the options supported by the remediation command, execute:
        
        Get-Help Add-AADAuthExtensionforVMs -Detailed

    To validate the extension:
        1.  Validate required Entra Id (formerly AAD) extension on Virtual Machine(s) in the Subscription, from a previously taken snapshot:
            Validate-AADAuthExtensionforVMs -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202205200418\AADAuthExtForLinuxVm\RemediatedVirtualMachines.csv

    To roll back:
        1. Revert back Entra Id (formerly AAD) extension on Virtual Machine(s) in the Subscription, from a previously taken snapshot:
           Remove-AADAuthExtensionforVMs -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\AADAuthExtForLinuxVm\RemediatedVirtualMachines.csv
       
        To know more about the options supported by the roll back command, execute:
        
        Get-Help ReAdd-AADAuthExtensionforVMs-Detailed        
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
    $requiredModules = @("Az.Accounts", "Az.Compute")

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


function Add-AADAuthExtensionforVMs {
    <#
        .SYNOPSIS
        Remediates 'Azure_VirtualMachine_AuthN_Enable_Microsoft_Entra_ID_Auth_Linux' Control.

        .DESCRIPTION
        Remediates 'Azure_VirtualMachine_AuthN_Enable_Microsoft_Entra_ID_Auth_Linux' Control.
        Entra Id (formerly AAD) extension must be deployed to the Linux VM. 
        
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
        None. You cannot pipe objects to Add-AADAuthExtensionforVMs.

        .OUTPUTS
        None. Add-AADAuthExtensionforVMs does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Add-AADAuthExtensionforVMs -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Add-AADAuthExtensionforVMs -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        .EXAMPLE
        PS> Add-AADAuthExtensionforVMs -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202205200418\AADAuthExtForLinuxVm\NonCompliantVMs.csv

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
        
    Write-Host "***To add Entra Id (formerly AAD) Auth extension on Linux VM(s) in a Subscription, Contributor or higher privileges on the VM(s) are required.***" -ForegroundColor $([Constants]::MessageType.Warning)
   
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 4] Preparing to fetch all Virtual Machine(s)..."
    Write-Host $([Constants]::SingleDashLine)
    
    # list to store resource details.
    $VirtualMachineDetails = @()

    #Separated Linux VM(s)
    $LinuxVMDetails = @()

    $reqExtPublisher = "Microsoft.Azure.ActiveDirectory"
    $reqExtensionType = "AADSSHLoginForLinux"
    $reqExtensionName = "AADSSHLoginForLinux"
    
    #PowerState Running
    $vmPowerState = "PowerState/running"

    #ExclusionTags for VM
    $ADBTagKey = "vendor"
    $ADBTagKeyValue = "Databricks"

    # No file path provided as input to the script. Fetch all Virtual Machine(s) in the Subscription.
    if ([String]::IsNullOrWhiteSpace($FilePath)) {
        try {
            Write-Host "Fetching all Virtual Machine(s) in Subscription: $($context.Subscription.SubscriptionId)" -ForegroundColor $([Constants]::MessageType.Info)

            # Get all Virtual Machine(s) in a Subscription
            $VirtualMachineDetails = Get-AzVM -ErrorAction Stop

            # Seperating required properties
            $VirtualMachineDetails = $VirtualMachineDetails | Select-Object @{N = 'ResourceId'; E = { $_.Id } },
            @{N = 'ResourceGroupName'; E = { $_.ResourceGroupName } },
            @{N = 'ResourceName'; E = { $_.Name } },
            @{N = 'OSType'; E = { $_.StorageProfile.OsDisk.OSType } } 
                                                              
            $VirtualMachineDetails | ForEach-Object {
                $VMInstance = $_
                $isVMExcluded = $false
                $VMTagDetails = (Get-AzVM -ResourceGroupName $VMInstance.ResourceGroupName -Name $VMInstance.ResourceName).Tags
                
                $VMTagDetails | ForEach-Object{
                    $vmTag = $_
                    if($vmTag.ContainsKey($ADBTagKey) -and $vmTag.ContainsValue($ADBTagKeyValue))
                    {
                        $isVMExcluded = $true
                    }
                }

                if(-not $isVMExcluded)
                {
                    $VMStatusDetails = Get-AzVM -ResourceGroupName $VMInstance.ResourceGroupName -Name $VMInstance.ResourceName -Status

                    if ($VMInstance.OSType -eq "Linux" -and ($VMStatusDetails.Statuses.code.contains($vmPowerState))) {
                        $LinuxVMDetails += $VMInstance
                        Write-Host "Virtual Machine [$($VMInstance.ResourceName)] is running and OS type is Linux. Adding..." -ForegroundColor $([Constants]::MessageType.Info)
                        Write-Host $([Constants]::SingleDashLine)
                    }
                    else {
                        Write-Host "Virtual Machine [$($VMInstance.ResourceName)] is either stopped/Deallocated or OS type is Windows. Skipping..." -ForegroundColor $([Constants]::MessageType.Warning)
                        Write-Host $([Constants]::SingleDashLine)
                    }
                }
                else
                {
                    Write-Host "Databricks Virtual Machine [$($VMInstance.ResourceName)] is not applicable for this control. Skipping..." -ForegroundColor $([Constants]::MessageType.Warning)
                    Write-Host $([Constants]::SingleDashLine)
                }
            }
        }
        catch {
            Write-Host "Error fetching Virtual Machine(s) from the subscription. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
        }    
    }
    else {
        if (-not (Test-Path -Path $FilePath)) {
            Write-Host "ERROR: Input file - $($FilePath) not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
            break
        }
        Write-Host "Fetching all Virtual Machine(s) from [$($FilePath)]..." 

        $VirtualMachineResources = Import-Csv -LiteralPath $FilePath
        $validVirtualMachineResources = $VirtualMachineResources | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) }
      
        $validVirtualMachineResources | ForEach-Object {
            $resourceId = $_.ResourceId
            try {
                $VirtualMachineResource = Get-AzVM -ResourceGroupName $_.ResourceGroupName -Name $_.ResourceName -ErrorAction SilentlyContinue
            
                $VirtualMachineDetails += $VirtualMachineResource  | Select-Object @{N = 'ResourceId'; E = { $_.Id } },
                @{N = 'ResourceGroupName'; E = { $_.ResourceGroupName } },
                @{N = 'ResourceName'; E = { $_.Name } },
                @{N = 'OSType'; E = { $_.StorageProfile.OsDisk.OSType } } 
            }                                                      
            catch {
                Write-Host "Error fetching Virtual Machine(s) resource: Resource ID - $($resourceId). Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            }
        }
        Write-Host "Validating and Filtering Linux Virtual Machine(s):" -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
                    
        $VirtualMachineDetails | ForEach-Object {
            $VMInstance = $_
            $isVMExcluded = $false
            $VMTagDetails = (Get-AzVM -ResourceGroupName $VMInstance.ResourceGroupName -Name $VMInstance.ResourceName).Tags
            
            $VMTagDetails | ForEach-Object{
                $vmTag = $_
                if($vmTag.ContainsKey($ADBTagKey) -and $vmTag.ContainsValue($ADBTagKeyValue))
                {
                    $isVMExcluded = $true
                }
            }
            if(-not $isVMExcluded)
            {
                $VMStatusDetails = Get-AzVM -ResourceGroupName $VMInstance.ResourceGroupName -Name $VMInstance.ResourceName -Status

                if ($VMInstance.OSType -eq "Linux" -and ($VMStatusDetails.Statuses.code.contains($vmPowerState))) {
                    $LinuxVMDetails += $VMInstance
                    Write-Host "Virtual Machine [$($VMInstance.ResourceName)] is running and OS type is Linux. Adding..." -ForegroundColor $([Constants]::MessageType.Info)
                    Write-Host $([Constants]::SingleDashLine)
                }
                else
                {
                    Write-Host "Virtual Machine [$($VMInstance.ResourceName)] is either Stopped/Deallocated or OS type is Windows. Skipping..." -ForegroundColor $([Constants]::MessageType.Warning)
                    Write-Host $([Constants]::SingleDashLine)
                }
            } 
            else
            {
                    Write-Host "Databricks Virtual Machine [$($VMInstance.ResourceName)] is not applicable for this control. Skipping..." -ForegroundColor $([Constants]::MessageType.Warning)
                    Write-Host $([Constants]::SingleDashLine)
            }
        }  
    }

    $totalVirtualMachines = ($LinuxVMDetails | Measure-Object).Count
    
    if ($totalVirtualMachines -eq 0) {
        Write-Host "No Virtual Machine(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        break
    }
  
    Write-Host "Found [$($totalVirtualMachines)] Virtual Machine(s)." -ForegroundColor $([Constants]::MessageType.Update)
                                                                          
    Write-Host $([Constants]::SingleDashLine)
    
    # list for storing virtual machine(s) where required Entra Id (formerly AAD) Extension is not added. 
    $NonCompliantVMs = @()

    Write-Host "Separating Virtual machine(s) for which Entra Id (formerly AAD) Extension is not added..."

    $LinuxVMDetails | ForEach-Object {
        $VirtualMachine = $_
        $VirtualMachine | Add-Member -NotePropertyName isExtPresent -NotePropertyValue $false
        $IsExtPresent = $false;

        #Getting list of extensions
        $VMExtensions = Get-AzVMExtension -ResourceGroupName $_.ResourceGroupName -VMName $_.ResourceName
        $VMExtensions | ForEach-Object {
            $VMExtension = $_
            if (!$IsExtPresent) {
                if ($VMExtension.ExtensionType -eq ($reqExtensionType)) {
                    $IsExtPresent = $true
                }
            }
        }
        if (!$IsExtPresent) {
            Write-Host "Entra Id (formerly AAD) extension is missing on Virtual Machine [$($VirtualMachine.ResourceName)]." -ForegroundColor $([Constants]::MessageType.Warning)
            $NonCompliantVMs += $VirtualMachine
        }
    }

    $totalNonCompliantVirtualMachines = ($NonCompliantVMs | Measure-Object).Count

    if ($totalNonCompliantVirtualMachines -eq 0) {
        Write-Host "No Virtual machines(s) found without Entra Id (formerly AAD) Extension present. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        break
    }

    Write-Host "Found [$($totalNonCompliantVirtualMachines)] Virtual machines(s) without Entra Id (formerly AAD) Extension:" -ForegroundColor $([Constants]::MessageType.Update)

    $colsProperty = @{Expression = { $_.ResourceName }; Label = "ResourceName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.ResourceGroupName }; Label = "ResourceGroupName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.ResourceId }; Label = "ResourceId"; Width = 50; Alignment = "left" },
    @{Expression = { $_.OSType }; Label = "OSType"; Width = 10; Alignment = "left" },
    @{Expression = { $_.isExtPresent }; Label = "isExtensionPresent"; Width = 10; Alignment = "left" }
        
    $NonCompliantVMs | Format-Table -Property $colsProperty -Wrap

    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\AADAuthExtForLinuxVm"

    if (-not (Test-Path -Path $backupFolderPath)) {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 4] Backing up Virtual machine(s) details..."
    Write-Host $([Constants]::SingleDashLine)

    if ([String]::IsNullOrWhiteSpace($FilePath)) {
        # Backing up Virtual Machine(s) details.
        $backupFile = "$($backupFolderPath)\NonCompliantVMs.csv"

        $NonCompliantVMs | Export-CSV -Path $backupFile -NoTypeInformation

        Write-Host "Virtual machines(s) details have been backed up to" -NoNewline
        Write-Host " [$($backupFile)]" -ForegroundColor $([Constants]::MessageType.Update)
    }
    else {
        Write-Host "Skipped as -FilePath is provided" -ForegroundColor $([Constants]::MessageType.Warning)
    }

    if (-not $DryRun) {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4] Remediating non compliant Azure Linux Virtual machines..." 
        Write-Host $([Constants]::SingleDashLine)
        
        if (-not $Force) {
            Write-Host "Found total [$($NonCompliantVMs.count)] Virtual machines(s) where Entra Id (formerly AAD) Extension is not present." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host "This step will add Entra Id (formerly AAD) extension for all non-complaint Virtual machine(s)." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host "Do you want to Continue? " -ForegroundColor $([Constants]::MessageType.Warning)
            
            $userInput = Read-Host -Prompt "(Y|N)"

            if ($userInput -ne "Y") {
                Write-Host "Entra Id (formerly AAD) Extension will not be added  to the Virtual machines(s) in the Subscription. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
                break
            }
        }
        else {
            Write-Host "'Force' flag is provided. Entra Id (formerly AAD) extension will be added for Virtual machine(s) in the Subscription without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
        }

        # List for storing remediated Virtual Machines(s)
        $VirtualMachinesRemediated = @()

        # List for storing skipped Virtual Machines(s)
        $VirtualMachineSkipped = @()

        Write-Host "Adding Entra Id (formerly AAD) Extension on all non compliant Virtual Machines(s)." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)

        # Loop through the list of Virtual Machines(s) which needs to be remediated.
        $NonCompliantVMs | ForEach-Object {
            $VirtualMachine = $_
            $VirtualMachine | Add-Member -NotePropertyName isExtInstalledPostRemediation -NotePropertyValue $false

            Write-Host "Adding Entra Id (formerly AAD) Auth Extension on [$($_.ResourceName)]." -ForegroundColor $([Constants]::MessageType.Info)
            try {
                Set-AzVMExtension -Publisher $reqExtPublisher -ExtensionType $reqExtensionType -VMName $_.ResourceName -ResourceGroupName $_.ResourceGroupName -Name $reqExtensionName -TypeHandlerVersion 1.0 -ErrorAction SilentlyContinue
                    
                $VMExtension = Get-AzVMExtension -ResourceGroupName $_.ResourceGroupName -VMName $_.ResourceName
                    
                $VMExtension | ForEach-Object {
                    if ($VMExtension.Publisher -contains ($reqExtPublisher)) {
                        $VirtualMachine.isExtInstalledPostRemediation = $true
                        $VirtualMachine.isExtPresent = $true
                    }
                }
                if ($VirtualMachine.isExtInstalledPostRemediation = $true) {
                    Write-Host "Successfully installed Entra Id (formerly AAD) Extensions for [$($_.ResourceName)]." -ForegroundColor $([Constants]::MessageType.Update)
                    Write-Host $([Constants]::SingleDashLine)
                    $VirtualMachinesRemediated += $VirtualMachine
                }
                else {
                    $virtualmachineskipped += $VirtualMachine
                    write-host "Skipping this Virtual Machine resource." -foregroundcolor $([constants]::messagetype.warning)
                    write-host $([constants]::singledashline)
                }  
            }
            catch {
                $VirtualMachineSkipped += $VirtualMachine
                Write-Host $([Constants]::SingleDashLine)
                Write-Host "Skipping this Virtual Machine resource." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }
        }

        $colsPropertyRemediated = @{Expression = { $_.ResourceName }; Label = "ResourceName"; Width = 30; Alignment = "left" },
        @{Expression = { $_.ResourceGroupName }; Label = "ResourceGroupName"; Width = 30; Alignment = "left" },
        @{Expression = { $_.ResourceId }; Label = "ResourceId"; Width = 30; Alignment = "left" },
        @{Expression = { $_.OSType }; Label = "OSType"; Width = 30; Alignment = "left" },
        @{Expression = { $_.isExtPresent }; Label = "isExtensionPresent"; Width = 30; Alignment = "left" },
        @{Expression = { $_.isExtInstalledPostRemediation }; Label = "isExtInstalledPostRemediation"; Width = 30; Alignment = "left" }
       
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Remediation Summary: " -ForegroundColor $([Constants]::MessageType.Info)

        if ($($VirtualMachinesRemediated | Measure-Object).Count -gt 0) {
            Write-Host "Entra Id (formerly AAD) Extension have been installed on following Virtual Machine(s) in the subscription:" -ForegroundColor $([Constants]::MessageType.Update)
           
            $VirtualMachinesRemediated | Format-Table -Property $colsPropertyRemediated -Wrap

            # Write this to a file.
            $VirtualMachinesRemediatedFile = "$($backupFolderPath)\RemediatedVirtualMachines.csv"
            $VirtualMachinesRemediated | Export-CSV -Path $VirtualMachinesRemediatedFile -NoTypeInformation

            Write-Host "This information has been saved to" -NoNewline
            Write-Host " [$($VirtualMachinesRemediatedFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
            Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Info)
        }

        if ($($VirtualMachineSkipped | Measure-Object).Count -gt 0) {
            Write-Host "Error installing Entra Id (formerly AAD) Extension on the following Virtual Machine(s) in the subscription: " -ForegroundColor $([Constants]::MessageType.Error)
            $VirtualMachineSkipped | Format-Table -Property $colsProperty -Wrap
            # Write this to a file.
            $VirtualMachineSkippedFile = "$($backupFolderPath)\SkippedVirtualMachines.csv"
            $VirtualMachineSkipped | Export-CSV -Path $VirtualMachineSkippedFile -NoTypeInformation
            Write-Host "This information has been saved to"  -NoNewline
            Write-Host " [$($VirtualMachineSkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update)
        }
    }
    else {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4]  Remediating non compliant Virtual Machines..."
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Skipped as -DryRun switch is provided." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)

        Write-Host "Next steps:" -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "Run the same command with -FilePath $($backupFile) and without -DryRun to configure Entra Id (formerly AAD) Extension on Virtual Machine(s) listed in the file."
    }
}

function Validate-AADAuthExtensionforVMs {
    <#
        .SYNOPSIS
        Validates remediation done for 'Azure_VirtualMachine_AuthN_Enable_Microsoft_Entra_ID_Auth_Linux' Control.

        .DESCRIPTION
        Validates remediation done for 'Azure_VirtualMachine_AuthN_Enable_Microsoft_Entra_ID_Auth_Linux' Control.
        Entra Id (formerly AAD) extension must be deployed to the Linux VM. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that was previously remediated.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
      
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the roll back.

        .INPUTS
        None. You cannot pipe objects to Validate-AADAuthExtensionforVMs.

        .OUTPUTS
        None. Validate-AADAuthExtensionforVMs does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Validate-AADAuthExtensionforVMs -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\AADAuthExtForLinuxVm\RemediatedVirtualMachines.csv

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

    Write-Host "***To validate Entra Id (formerly AAD) Auth extension on Linux VM(s) in a Subscription, Contributor or higher privileges on the VM(s) are required.***" -ForegroundColor $([Constants]::MessageType.Warning)
   
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 3] Preparing to fetch all Virtual Machine(s)..."
    Write-Host $([Constants]::SingleDashLine)
    
    if (-not (Test-Path -Path $FilePath)) {
        Write-Host "ERROR: Input file - [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        break
    }

    Write-Host "Fetching all Linux Virtual Machine(s) from" -NoNewline
    Write-Host " [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Update)
    $VirtualMachineDetails = Import-Csv -LiteralPath $FilePath

    $validVirtualMachineDetails = $VirtualMachineDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) -and ![String]::IsNullOrWhiteSpace($_.ResourceGroupName) -and ![String]::IsNullOrWhiteSpace($_.ResourceName) }

    $totalVirtualMachines = $(($validVirtualMachineDetails | Measure-Object).Count)

    if ($totalVirtualMachines -eq 0) {
        Write-Host "No Virtual Machine(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        break
    }

    Write-Host "Found [$(($validVirtualMachineDetails|Measure-Object).Count)] Virtual Machine(s)." -ForegroundColor $([Constants]::MessageType.Update)

    $colsProperty = @{Expression = { $_.ResourceName }; Label = "ResourceName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.ResourceGroupName }; Label = "ResourceGroupName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.ResourceId }; Label = "ResourceId"; Width = 50; Alignment = "left" },
    @{Expression = { $_.OSType }; Label = "OSType"; Width = 50; Alignment = "left" },
    @{Expression = { $_.isExtInstalledPostRemediation }; Label = "isExtInstalledPostRemediation"; Width = 50; Alignment = "left" }
        
    $validVirtualMachineDetails | Format-Table -Property $colsProperty -Wrap
    
    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\ValidateExtOnVirtualMachines"

    if (-not (Test-Path -Path $backupFolderPath)) {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
  
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 3] Validating Provisioning state of all remediated VMs(s) in the Subscription..."
    Write-Host $([Constants]::SingleDashLine)

    # List for storing validated Virtual Machine(s)
    $VirtualMachinesValidated = @()

    # List for storing skipped Virtual Machine(s)
    $VirtualMachinesSkipped = @()

    $reqExtensionType = "AADSSHLoginForLinux"

    Write-Host "Starting validation..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

    $validVirtualMachineDetails | ForEach-Object {
        $VirtualMachine = $_
        $VirtualMachine | Add-Member -NotePropertyName isExtProvStateValidated -NotePropertyValue $false
        try {
            
            Write-Host "Validating Virtual Machine Entra Id (formerly AAD) extension- [$($_.ResourceName)]" -ForegroundColor $([Constants]::MessageType.Info)
            if ($_.isExtInstalledPostRemediation) {
                $VMExtensions = Get-AzVMExtension -ResourceGroupName $_.ResourceGroupName -VMName $_.ResourceName
                    
                $VMExtensions | ForEach-Object {
                    $VMExtension = $_
                    if (!$VirtualMachine.isExtProvStateValidated) {
                        if ($VMExtension.ExtensionType -eq ($reqExtensionType)) {
                            if ($VMExtension.ProvisioningState -eq "Succeeded") {
                                $VirtualMachine.isExtProvStateValidated = $true
                            }
                        }
                    }
                }
                if ($VirtualMachine.isExtProvStateValidated) {
                    Write-Host "Virtual Machine Entra Id (formerly AAD) extension provisiong state validated for - [$($VirtualMachine.ResourceName)]" -ForegroundColor $([Constants]::MessageType.Update)
                    $VirtualMachinesValidated += $VirtualMachine
                }
                else {
                    Write-Host "Virtual Machine Entra Id (formerly AAD) extension provisiong state is not validated for - [$($VirtualMachine.ResourceName)]" -ForegroundColor $([Constants]::MessageType.Warning)
                    $VirtualMachinesSkipped += $VirtualMachine
                }
            }
        }
        catch {
            $VirtualMachinesSkipped += $VirtualMachine
        }
    }

    $colsPropertyValidation = @{Expression = { $_.ResourceName }; Label = "ResourceName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.ResourceGroupName }; Label = "ResourceGroupName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.ResourceId }; Label = "ResourceId"; Width = 50; Alignment = "left" },
    @{Expression = { $_.isExtInstalledPostRemediation }; Label = "isExtInstalledPostRemediation"; Width = 50; Alignment = "left" },
    @{Expression = { $_.isExtProvStateValidated }; Label = "isExtProvStateValidated"; Width = 50; Alignment = "left" }
     
    if ($($VirtualMachinesValidated | Measure-Object).Count -gt 0 -or $($VirtualMachineSkipped | Measure-Object).Count -gt 0) {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Validation Summary: " -ForegroundColor $([Constants]::MessageType.Info)
        
        if ($($VirtualMachinesValidated | Measure-Object).Count -gt 0) {
            Write-Host "Entra Id (formerly AAD) Extension provisiong state has been successfully validated on following Virtual Machine(s) in the Subscription: " -ForegroundColor $([Constants]::MessageType.Update)
            $VirtualMachinesValidated | Format-Table -Property $colsPropertyValidation -Wrap

            # Write this to a file.
            $ValidatedVirtualMachinesFile = "$($backupFolderPath)\ValidatedVirtualMachines.csv"
            $VirtualMachinesValidated | Export-CSV -Path $ValidatedVirtualMachinesFile -NoTypeInformation
            Write-Host "This information has been saved to" -NoNewline
            Write-Host " [$($ValidatedVirtualMachinesFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
            Write-Host $([Constants]::SingleDashLine)
        }

        if ($($VirtualMachinesSkipped | Measure-Object).Count -gt 0) {
            Write-Host "Following Virtual Machine(s) Entra Id (formerly AAD) extension does not have provisioning state as succeeded in the Subscription: " -ForegroundColor $([Constants]::MessageType.Error)
            
            $VirtualMachinesSkipped | Format-Table -Property $colsPropertyValidation -Wrap
            
            # Write this to a file.
            $ValidationSkippedVirtualMachineFile = "$($backupFolderPath)\ValidationSkippedVirtualMachines.csv"
            $VirtualMachinesSkipped | Export-CSV -Path $ValidationSkippedVirtualMachineFile -NoTypeInformation
            Write-Host "This information has been saved to" -NoNewline
            Write-Host " [$($ValidationSkippedVirtualMachineFile)]" -ForegroundColor $([Constants]::MessageType.Update)  
            Write-Host $([Constants]::SingleDashLine)

            Write-Host "For above VM(s), please manually re-install the Entra Id (formerly AAD) extension and check the provisioning state." -ForegroundColor $([Constants]::MessageType.Error)  

        }
    }
}


function Remove-AADAuthExtensionforVMs {
    <#
        .SYNOPSIS
        Rolls back remediation done for 'Azure_VirtualMachine_AuthN_Enable_Microsoft_Entra_ID_Auth_Linux' Control.

        .DESCRIPTION
        Rolls back remediation done for 'Azure_VirtualMachine_AuthN_Enable_Microsoft_Entra_ID_Auth_Linux' Control.
        Entra Id (formerly AAD) extension must be deployed to the Linux VM. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that was previously remediated.
        
        .PARAMETER Force
        Specifies a forceful roll back without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
      
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the roll back.

        .INPUTS
        None. You cannot pipe objects to Remove-AADAuthExtensionforVMs.

        .OUTPUTS
        None. Remove-AADAuthExtensionforVMs does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Remove-AADAuthExtensionforVMs -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\AADAuthExtForLinuxVm\RemediatedVirtualMachines.csv

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

    Write-Host "***To remove/uninstall Entra Id (formerly AAD) Auth extension on Linux VM(s) in a Subscription, Contributor or higher privileges on the VM(s) are required.***" -ForegroundColor $([Constants]::MessageType.Warning)
   
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 3] Preparing to fetch all Virtual Machine(s)..."
    Write-Host $([Constants]::SingleDashLine)
    
    if (-not (Test-Path -Path $FilePath)) {
        Write-Host "ERROR: Input file - [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        break
    }

    $reqExtPublisher = "Microsoft.Azure.ActiveDirectory"
    $reqExtensionType = "AADSSHLoginForLinux"
    $reqExtensionName = "AADSSHLoginForLinux"

    Write-Host "Fetching all Linux Virtual Machine(s) from" -NoNewline
    Write-Host " [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Update)
    $VirtualMachineDetails = Import-Csv -LiteralPath $FilePath

    $validVirtualMachineDetails = $VirtualMachineDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) -and ![String]::IsNullOrWhiteSpace($_.ResourceGroupName) -and ![String]::IsNullOrWhiteSpace($_.ResourceName) }

    $totalVirtualMachines = $(($validVirtualMachineDetails | Measure-Object).Count)

    if ($totalVirtualMachines -eq 0) {
        Write-Host "No Virtual Machine(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        break
    }

    Write-Host "Found [$(($validVirtualMachineDetails|Measure-Object).Count)] Virtual Machine(s)." -ForegroundColor $([Constants]::MessageType.Update)

    $colsProperty = @{Expression = { $_.ResourceName }; Label = "ResourceName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.ResourceGroupName }; Label = "ResourceGroupName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.ResourceId }; Label = "ResourceId"; Width = 30; Alignment = "left" },
    @{Expression = { $_.OSType }; Label = "OSType"; Width = 30; Alignment = "left" },
    @{Expression = { $_.isExtInstalledPostRemediation }; Label = "isExtInstalledPostRemediation"; Width = 30; Alignment = "left" }
        
    $validVirtualMachineDetails | Format-Table -Property $colsProperty -Wrap
    
    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\RollbackExtOnVirtualMachines"

    if (-not (Test-Path -Path $backupFolderPath)) {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
  
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 3] Rolling back all remediated VMs(s) in the Subscription..."
    Write-Host $([Constants]::SingleDashLine)

    if ( -not $Force) {
        Write-Host "This will remove the Entra Id (formerly AAD) Auth Extension from the VM(s). Do you want to continue roll back operation?"  -ForegroundColor $([Constants]::MessageType.Warning)
        $userInput = Read-Host -Prompt "(Y|N)"
        if ($userInput -ne "Y") {
            Write-Host "Entra Id (formerly AAD) Auth Extension will not be rolled back for any VM(s) in the Subscription. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
            break
        }
    }
    else {
        Write-Host "'Force' flag is provided. Entra Id (formerly AAD) extension in VM(s) will be removed in the Subscription without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
    }

    # List for storing rolled back Virtual Machine resource.
    $VirtualMachinesRolledBack = @()

    # List for storing skipped rolled back Virtual Machine resource.
    $VirtualMachineSkipped = @()

    Write-Host "Starting Roll back operation..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

    $validVirtualMachineDetails | ForEach-Object {
        $VirtualMachine = $_
        $VirtualMachine | Add-Member -NotePropertyName isAADExtRolledback -NotePropertyValue $false
        try {
            
            Write-Host "Rolling back Entra Id (formerly AAD) Ext on Virtual Machine(s) - [$($_.ResourceName)]" -ForegroundColor $([Constants]::MessageType.Info)
            if ($_.isExtInstalledPostRemediation) {
                $VirtualMachineResource = Remove-AzVMExtension -ResourceGroupName $_.ResourceGroupName -VMName $_.ResourceName -Name AADSSHLoginForLinux -Force
        
                $VMExtensions = Get-AzVMExtension -ResourceGroupName $_.ResourceGroupName -VMName $_.ResourceName
                    
                $VMExtensions | ForEach-Object {
                    $VMExtension = $_
                    if ($VMExtension.Publisher -contains ($reqExtPublisher)) {
                        $VirtualMachine.isAADExtRolledback = $false
                        $VirtualMachine.isExtPresent = $true
                    }
                }

                if (!$VirtualMachine.isAADExtRolledback) {
                    $VirtualMachine.isAADExtRolledback = $true
                    $VirtualMachine.isExtPresent = $false
                    Write-Host "Successfully uninstalled Entra Id (formerly AAD) Extensions for [$($_.ResourceName)]." -ForegroundColor $([Constants]::MessageType.Update)
                    Write-Host $([Constants]::SingleDashLine)
                    $VirtualMachinesRolledBack += $VirtualMachine
                }
                else {
                    $VirtualMachineSkipped += $VirtualMachine
                    write-host "Skipping this Virtual Machine resource [$($_.ResourceName)]." -foregroundcolor $([constants]::messagetype.warning)
                    write-host $([constants]::singledashline)
                }
            }
        }
        catch {
            $VirtualMachineSkipped += $VirtualMachine
        }
    }

    $colsPropertyRollBack = @{Expression = { $_.ResourceName }; Label = "ResourceName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.ResourceGroupName }; Label = "ResourceGroupName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.ResourceId }; Label = "ResourceId"; Width = 30; Alignment = "left" },
    @{Expression = { $_.OsType }; Label = "OsType"; Width = 30; Alignment = "left" },
    @{Expression = { $_.isAADExtRolledback }; Label = "isAADExtRolledback"; Width = 30; Alignment = "left" },
    @{Expression = { $_.isExtPresent }; Label = "isExtPresent"; Width = 30; Alignment = "left" }
     
    if ($($VirtualMachinesRolledBack | Measure-Object).Count -gt 0 -or $($VirtualMachineSkipped | Measure-Object).Count -gt 0) {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Rollback Summary: " -ForegroundColor $([Constants]::MessageType.Info)
        
        if ($($VirtualMachinesRolledBack | Measure-Object).Count -gt 0) {
            Write-Host "Entra Id (formerly AAD) extension is rolled back successfully on following Virtual Machine(s) in the Subscription: " -ForegroundColor $([Constants]::MessageType.Update)
            $VirtualMachinesRolledBack | Format-Table -Property $colsPropertyRollBack -Wrap

            # Write this to a file.
            $VirtualMachinesRolledBackFile = "$($backupFolderPath)\RolledBackVirtualMachines.csv"
            $VirtualMachinesRolledBack | Export-CSV -Path $VirtualMachinesRolledBackFile -NoTypeInformation
            Write-Host "This information has been saved to" -NoNewline
            Write-Host " [$($VirtualMachinesRolledBackFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
            Write-Host $([Constants]::SingleDashLine)
        }

        if ($($VirtualMachineSkipped | Measure-Object).Count -gt 0) {
            Write-Host "Error installing Entra Id (formerly AAD) Extension on following Virtual Machine(s) in the Subscription: " -ForegroundColor $([Constants]::MessageType.Warning)
            
            $VirtualMachineSkipped | Format-Table -Property $colsProperty -Wrap
            
            # Write this to a file.
            $VirtualMachineSkippedFile = "$($backupFolderPath)\RollbackSkippedVirtualMachine.csv"
            $VirtualMachineSkipped | Export-CSV -Path $VirtualMachineSkippedFile -NoTypeInformation
            Write-Host "This information has been saved to" -NoNewline
            Write-Host " [$($VirtualMachineSkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update)  
            Write-Host $([Constants]::SingleDashLine)  
        }
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
