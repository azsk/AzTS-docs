<###
# Overview:
    This script is used to remediate GuestConfiguration on Virtual Machine in a Subscription.

# Control ID:
    Azure_VirtualMachine_SI_Deploy_GuestConfig_Extension

# Display Name:
    Guest Configuration extension must be deployed to the VM using Azure Policy assignment.

# Prerequisites:
    1.Contributor or higher priviliged role on the Virtual Machine(s) is required for remediation.
    2. VM should be in running state.

# Steps performed by the script:
    To remediate:
        1. Validating and installing the modules required to run the script and validating the user.
        2. Get the list of Virtual Machine(s) in a Subscription that does not have Guest Configuration Extension present and system managed identity is disabled on VM.
        3. Back up details of Virtual Machine(s) that are to be remediated.
        4. Remediate Guest Configuration Extension and system managed identity on Virtual Machine(s) in the Subscription.

    To validate:
        1. Validating and installing the modules required to run the script and validating the user.
        2. Get the list of Virtual Machine(s) in a Subscription that does not have Guest Configuration Extension with Provisioning state succeeded and system managed identity is enabled on VM.
        3. Back up details of Virtual Machine(s) that are to be remediated.

    To roll back:
        1. Validate and install the modules required to run the script and validating the user.
        2. Get the list of Virtual Machine(s) in a Subscription, the changes made to which previously, are to be rolled back.
        3. Roll back port on all Virtual Machine(s) in the Subscription.



# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to remediate Guest Configuration Extension and system managed identity on Virtual Machine(s) in the Subscription. Refer `Examples`, below.

    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to remove access to security scanner identity on all Virtual Machine(s) in the Subscription. Refer `Examples`, below.

# Examples:
    To remediate:
        1. To review the Virtual Machine(s) in a Subscription that will be remediated:
    
           Install-VMGuestConfigEnableMI -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        2. Install Guest Configuration Extension on Virtual Machine(s) in the Subscription:
       
           Install-VMGuestConfigEnableMI -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        3. Install Guest Configuration Extension on Virtual Machine(s) in the Subscription, from a previously taken snapshot:
       
           Install-VMGuestConfigEnableMI -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202205200418\VirtualMachineGuestConfigExtension\NonCompliantVMGuestConfigAndMI.csv

        To know more about the options supported by the remediation command, execute:
        
        Get-Help Install-VMGuestConfigEnableMI -Detailed

    To validate:
        1. Validate Guest Configuration Extension and System Assigned MI on Virtual Machine(s) in the Subscription, from a previously taken snapshot:
           Validate-VMGuestConfigExtAndMI -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\VirtualMachineGuestConfigExtension\RemediatedVirtualMachine.csv
        
    To roll back:
        1. Revert back Guest Configuration Extension on Virtual Machine(s) in the Subscription, from a previously taken snapshot:
           Uninstall-GuestConfigExtDisableMI -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\VirtualMachineGuestConfigExtension\RemediatedVirtualMachine.csv
       
        To know more about the options supported by the roll back command, execute:
        
        Get-Help Uninstall-GuestConfigExtDisableMI-Detailed        
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


function Install-VMGuestConfigEnableMI {
    <#
        .SYNOPSIS
        Remediates 'Azure_VirtualMachine_SI_Deploy_GuestConfig_Extension' Control.

        .DESCRIPTION
        Remediates 'Azure_VirtualMachine_SI_Deploy_GuestConfig_Extension' Control.
        Install Guest Configuration Extension and enable System Assigned Managed Identity on Virtual Machine(s). 
        
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

        .PARAMETER Path
        Specifies the path to the file to be used as input for the remediation when AutoRemediation switch is used. 

        .INPUTS
        None. You cannot pipe objects to Install-VMGuestConfigEnableMI.

        .OUTPUTS
        None. Install-VMGuestConfigEnableMI does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Install-VMGuestConfigEnableMI -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Install-VMGuestConfigEnableMI -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        .EXAMPLE
        PS> Install-VMGuestConfigEnableMI -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202205200418\VirtualMachineGuestConfigExtension\NonCompliantVMGuestConfigAndMI.csv

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
    Write-Host "***To install Guest Configuration Extension and enable System Assigned Managed Identity on Virtual Machine(s) in a Subscription, Contributor or higher privileges  are required.***" -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 4] Preparing to fetch all Virtual Machine(s)..."
    Write-Host $([Constants]::SingleDashLine)
    
    # list to store resource details.   
    $VirtualMachineDetails = @()

    # To keep track of remediated and skipped resources
    $logRemediatedResources = @()
    $logSkippedResources = @()
    $vmPowerState = "PowerState/running"
     
    $ADBTagKey = "vendor"
    $ADBTagKeyValue = "Databricks"
     
    $AKSTagKey = "orchestrator"
    $AKSTagKeyValue = "kubernetes"

   

    # No file path provided as input to the script. Fetch all Virtual Machine(s) in the Subscription.
    if ([String]::IsNullOrWhiteSpace($FilePath)) {
        try {
            Write-Host "Fetching all Virtual Machine(s) in Subscription: $($context.Subscription.SubscriptionId)" -ForegroundColor $([Constants]::MessageType.Info)

            # Get all Virtual Machine(s) in a Subscription VirtualMachineDetails
            $VMDetails = Get-AzVM -ErrorAction Stop

            # Seperating required properties
            $VMDetails = $VMDetails | Select-Object @{N = 'ResourceId'; E = { $_.Id } },
            @{N = 'ResourceGroupName'; E = { $_.ResourceGroupName } },
            @{N = 'ResourceName'; E = { $_.Name } },
            @{N = 'OsType'; E = { $_.StorageProfile.OsDisk.OsType } }



            #Seperating VM with running state only
            $VMDetails | ForEach-Object {                
                $VMDetail = Get-AzVM -ResourceGroupName $_.ResourceGroupName -Name $_.ResourceName                
                $VMTags = $VMDetail.Tags
                #fetching VM status
                $VMStatusDetails = Get-AzVM -ResourceGroupName $_.ResourceGroupName -Name $_.ResourceName -Status
               
                if ($VMStatusDetails.Statuses.code.contains($vmPowerState)) {                        
                    #checking for tags
                    if (!(( $VMTags.ContainsKey($ADBTagKey) -and $VMTags.ContainsValue($ADBTagKeyValue)) -or ( $VMTags.ContainsKey($AKSTagKey) -and $VMTags.ContainsValue($AKSTagKeyValue)))) {
                        $VirtualMachineDetails += $_
                    }
                    else {
                        $logSkippedResources += $logResource
                    }
                }
                else {
                    $logSkippedResources += $logResource
                }
            }

        }
        catch {
            Write-Host "Error fetching Virtual Machine(s) from the subscription. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            $logResource = @{}
            $logResource.Add("SubscriptionID", ($SubscriptionId))
            $logResource.Add("Reason", "Error fetching Virtual Machine(s) information from the subscription.")    
            $logSkippedResources += $logResource
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
        $VirtualMachineDetails = $validVirtualMachineResources 
    }
    

    $totalVirtualMachine = ($VirtualMachineDetails | Measure-Object).Count

    if ($totalVirtualMachine -eq 0) {
        Write-Host "No Virtual Machine(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        break
    }
  
    Write-Host "Found [$($totalVirtualMachine)] Virtual Machine(s)." -ForegroundColor $([Constants]::MessageType.Update)
                                                                          
    Write-Host $([Constants]::SingleDashLine)
    
    # list for storing Virtual Machine(s) where required Guest Configuration is not installed
    $NonCompliantVirtualMachineGuestExt = @()


    Write-Host "Separating Virtual Machine(s) for which Guest Configuration is not installed on VM with disabled System Assigned MI..."

    $VirtualMachineDetails | ForEach-Object {
        
        if ([String]::IsNullOrWhiteSpace($FilePath)) {
            $_ | Add-Member -NotePropertyName isSystemAssignedManagedIdentityPresent -NotePropertyValue $false
            $_ | Add-Member -NotePropertyName isGuestConfigurationExtensionPresent -NotePropertyValue $false
        }
        $VirtualMachine = $_
        $_.isGuestConfigurationExtensionPresent = [System.Convert]::ToBoolean($_.isGuestConfigurationExtensionPresent)
        $_.isSystemAssignedManagedIdentityPresent = [System.Convert]::ToBoolean($_.isSystemAssignedManagedIdentityPresent)


        $IsExtPresent = $true;
        #Getting list of extensions
        if (!$_.isGuestConfigurationExtensionPresent ) {
            $VMExtension = Get-AzVMExtension -ResourceGroupName $_.ResourceGroupName -VMName $_.ResourceName
            $VMExtension | ForEach-Object {
                if ($IsExtPresent) {           
                    if ($VMExtension.Publisher -contains ("Microsoft.GuestConfiguration")) {
                        $IsExtPresent = $true;
                    }
                    else {
                        $NonCompliantVirtualMachineGuestExt += $VirtualMachine
                        $IsExtPresent = $false;
                    }
                }
            }
        }
        if ($IsExtPresent) {
            $_.isGuestConfigurationExtensionPresent = $true
        }

        #Checking if System Managed Identity is present 
        if (!$_.isSystemAssignedManagedIdentityPresent  ) {
            $VMDetail = Get-AzVM -ResourceGroupName $_.ResourceGroupName -Name $_.ResourceName

            if ($VMDetail.Identity.Type -contains "SystemAssignedUserAssigned" -or $VMDetail.Identity.Type -contains "SystemAssigned") {
                $_.isSystemAssignedManagedIdentityPresent = $true
            }
            else {
                $NonCompliantVirtualMachineGuestExt += $VirtualMachine
            }
        }
    }
   
    $totalNonCompliantVirtualMachineGuestExt = ($NonCompliantVirtualMachineGuestExt | Measure-Object).Count

    if ($totalNonCompliantVirtualMachineGuestExt -eq 0) {
        Write-Host "No VirtualMachine found without Guest Configuration Extension and System Assigned Managed Identity disabled.. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        break
    }

    Write-Host "Found [$($totalNonCompliantVirtualMachineGuestExt)] Virtual Machine(s) non compliant for Guest Configuration Extension or System Assigned Managed Identity not installed:" -ForegroundColor $([Constants]::MessageType.Update)

    $colsProperty = @{Expression = { $_.ResourceName }; Label = "ResourceName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.ResourceGroupName }; Label = "ResourceGroupName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.ResourceId }; Label = "ResourceId"; Width = 50; Alignment = "left" },
    @{Expression = { $_.OsType }; Label = "OsType"; Width = 10; Alignment = "left" },
    @{Expression = { $_.isSystemAssignedManagedIdentityPresent }; Label = "isSystemAssignedManagedIdentityPresent"; Width = 10; Alignment = "left" },
    @{Expression = { $_.isGuestConfigurationExtensionPresent }; Label = "isGuestConfigurationExtensionPresent"; Width = 10; Alignment = "left" ; }

        
    $NonCompliantVirtualMachineGuestExt | Format-Table -Property $colsProperty -Wrap

    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\VirtualMachineGuestConfigExtension"

    if (-not (Test-Path -Path $backupFolderPath)) {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 4] Backing up Virtual Machine(s) details..."
    Write-Host $([Constants]::SingleDashLine)

    if ([String]::IsNullOrWhiteSpace($FilePath)) {
        # Backing up Virtual Machine(s) details.
        $backupFile = "$($backupFolderPath)\NonCompliantVMGuestConfigAndMI.csv"

        $NonCompliantVirtualMachineGuestExt | Export-CSV -Path $backupFile -NoTypeInformation

        Write-Host "Virtual Machine(s) details have been backed up to" -NoNewline
        Write-Host " [$($backupFile)]" -ForegroundColor $([Constants]::MessageType.Update)
    }
    else {
        Write-Host "Skipped as -FilePath is provided" -ForegroundColor $([Constants]::MessageType.Warning)
    }

    if (-not $DryRun) {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4] Remediating non compliant Azure Virtual Machine(s)..." 
        Write-Host $([Constants]::SingleDashLine)
        
         
        if (-not $Force) {
            Write-Host "Found total [$($totalNonCompliantVirtualMachineGuestExt)] Virtual Machine(s) without Guest Configuration Extension. " -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host "This step will install Guest Configuration Extension for all non-compliant [$($totalNonCompliantVirtualMachineGuestExt)] Virtual Machine(s)." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host "Do you want to Continue? " -ForegroundColor $([Constants]::MessageType.Warning)
            
            $userInput = Read-Host -Prompt "(Y|N)"

            if ($userInput -ne "Y") {
                Write-Host "Guest Configuration Extension will not be installed on Virtual Machine(s) with System Assigned MI in the Subscription. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
                break
            }
        }
        else {
            Write-Host "'Force' flag is provided. Guest Configuration Extension will be installed on Virtual Machine(s) with System Assigned MI in the Subscription without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
        }
        

        # List for storing remediated Virtual Machine(s)
        $VirtualMachineRemediated = @()

        # List for storing skipped Virtual Machine(s)
        $VirtualMachineSkipped = @()

        Write-Host "Installing Guest Configuration Extension on Virtual Machine(s) with System Assigned MI ." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)

        # Loop through the list of VirtualMachine(s) which needs to be remediated.
        $NonCompliantVirtualMachineGuestExt | ForEach-Object {
            $isGuestConfigurationExtInstallSuccessful = $false
            $isManagedIdentityInstallSuccessful = $false

            $VirtualMachine = $_
            $VirtualMachine | Add-Member -NotePropertyName isGuestConfigurationInstalledByRemediation -NotePropertyValue $false
            $VirtualMachine | Add-Member -NotePropertyName isSystemManagedIdenityInstalledByRemediation -NotePropertyValue $false
            $_.isSystemAssignedManagedIdentityPresent = [System.Convert]::ToBoolean($_.isSystemAssignedManagedIdentityPresent)
            $_.isGuestConfigurationExtensionPresent = [System.Convert]::ToBoolean($_.isGuestConfigurationExtensionPresent)

            try {                
                #checking the System Assigned Managed Identity
                $VMResponse = @()                    
                if (!$_.isSystemAssignedManagedIdentityPresent) {
                    Write-Host "Installing System Assigned Managed Idenity on [$($_.ResourceName)]." -ForegroundColor $([Constants]::MessageType.Info)
                    $VMDetail = Get-AzVM -ResourceGroupName $_.ResourceGroupName -Name $_.ResourceName
                    $VMResponse = Update-AzVM -ResourceGroupName $_.ResourceGroupName -VM $VMDetail  -IdentityType SystemAssigned
                    if ($VMResponse.IsSuccessStatusCode) {
                        $isManagedIdentityInstallSuccessful = $true

                    }

                }
                else {
                    $isManagedIdentityInstallSuccessful = $true

                }

                if (!$_.isGuestConfigurationExtensionPresent) {
                    Write-Host "Installing Guest Configuration on [$($_.ResourceName)]." -ForegroundColor $([Constants]::MessageType.Info)

                    #check os type before installing
                    if ($_.OsType -ieq "Windows") {
                        $VirtualMachineResources = Set-AzVMExtension -Publisher 'Microsoft.GuestConfiguration' -ExtensionType 'ConfigurationforWindows' -TypeHandlerVersion 1.0 -Name 'AzurePolicyforWindows' -ResourceGroupName $_.ResourceGroupName  -VMName $_.ResourceName -EnableAutomaticUpgrade $true;
                    }
                    else {
                        $VirtualMachineResources = Set-AzVMExtension -Publisher 'Microsoft.GuestConfiguration' -ExtensionType 'ConfigurationForLinux' -Name 'AzurePolicyforLinux' -TypeHandlerVersion 1.0 -ResourceGroupName $_.ResourceGroupName -VMName $_.ResourceName -EnableAutomaticUpgrade $true;
                    }

                    if ($VirtualMachineResources.IsSuccessStatusCode) {
                        $isGuestConfigurationExtInstallSuccessful = $true
                    }
                }
                else {
                    $isGuestConfigurationExtInstallSuccessful = $true
                } 

                if ($isGuestConfigurationExtInstallSuccessful -and $isManagedIdentityInstallSuccessful) {

                    if (!$_.isSystemAssignedManagedIdentityPresent) {
                        $VirtualMachine.isSystemManagedIdenityInstalledByRemediation = $true
                    }
                    if (!$_.isGuestConfigurationExtensionPresent) {
                        $VirtualMachine.isGuestConfigurationInstalledByRemediation = $true
                    }
                    
                    $VirtualMachineRemediated += $VirtualMachine
                    Write-Host "Successfully installed Guest Configuration Extension with System Assigned MI for the resource [$($_.ResourceName)]." -ForegroundColor $([Constants]::MessageType.Update)
                    Write-Host $([Constants]::SingleDashLine)
                }
                else {
                    if ($isGuestConfigurationExtInstallSuccessful) {
                        $VirtualMachine.isGuestConfigurationInstalledByRemediation = $true
                    }
                    else {
                        $VirtualMachine.isGuestConfigurationInstalledByRemediation = $false

                    }
                    if ($isManagedIdentityInstallSuccessful) {
                        $VirtualMachine.isSystemManagedIdenityInstalledByRemediation = $true
                    }
                    else {
                        $VirtualMachine.isSystemManagedIdenityInstalledByRemediation = $false
                    }

                    $VirtualMachineSkipped += $VirtualMachine                    
                    Write-Host "Skipping this Virtual Machine resource." -ForegroundColor $([Constants]::MessageType.Warning)
                    Write-Host $([Constants]::SingleDashLine)
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
        @{Expression = { $_.ResourceId }; Label = "ResourceId"; Width = 50; Alignment = "left" },
        @{Expression = { $_.OsType }; Label = "OsType"; Width = 10; Alignment = "left" },
        @{Expression = { $_.isSystemAssignedManagedIdentityPresent }; Label = "isSystemAssignedManagedIdentityPresent"; Width = 10; Alignment = "left" },
        @{Expression = { $_.isGuestConfigurationExtensionPresent }; Label = "isGuestConfigurationExtensionPresent"; Width = 10; Alignment = "left" },
        @{Expression = { $_.isGuestConfigurationInstalledByRemediation }; Label = "isGuestConfigurationInstalledByRemediation"; Width = 10; Alignment = "left" }

        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Remediation Summary: " -ForegroundColor $([Constants]::MessageType.Info)

        if ($($VirtualMachineRemediated | Measure-Object).Count -gt 0) {
            Write-Host "Guest Configuration Extension installed on the following Virtual Machine(s) with enabled System Assigned MI in the subscription:" -ForegroundColor $([Constants]::MessageType.Update)
           
            $VirtualMachineRemediated | Format-Table -Property $colsPropertyRemediated -Wrap

            # Write this to a file.
            $VirtualMachineRemediatedFile = "$($backupFolderPath)\RemediatedVirtualMachine.csv"
            $VirtualMachineRemediated | Export-CSV -Path $VirtualMachineRemediatedFile -NoTypeInformation

            Write-Host "This information has been saved to" -NoNewline
            Write-Host " [$($VirtualMachineRemediatedFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
            Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host "To validate run the command Validate-VMGuestConfigExtAndMI with -FilePath $($VirtualMachineRemediatedFile) , after sometime to check the status of Guest Configuration Extension installation and System Assigned MI." -ForegroundColor $([Constants]::MessageType.Info)
        }

        if ($($VirtualMachineSkipped | Measure-Object).Count -gt 0) {
            Write-Host "Error while installing Guest Configuration Extension on the following Virtual Machine(s) with System Assigned MI in the subscription: " -ForegroundColor $([Constants]::MessageType.Error)
            $VirtualMachineSkipped | Format-Table -Property $colsProperty -Wrap
            # Write this to a file.
            $VirtualMachineSkippedFile = "$($backupFolderPath)\SkippedVirtualMachine.csv"
            $VirtualMachineSkipped | Export-CSV -Path $VirtualMachineSkippedFile -NoTypeInformation
            Write-Host "This information has been saved to"  -NoNewline
            Write-Host " [$($VirtualMachineSkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update)
        }
    }
    else {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "[Step 4 of 4]  Remediating non compliant Azure Virtual Machine..."
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Skipped as -DryRun switch is provided." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)

        Write-Host "Next steps:" -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host "Run the same command with -FilePath $($backupFile) and without -DryRun, install Guest Configuration Extension on VirtualMachine(s) listed in the file."
    }
}

function Uninstall-GuestConfigExtDisableMI {
    <#
        .SYNOPSIS
        Rolls back remediation done for 'Azure_VirtualMachine_SI_Deploy_GuestConfig_Extension' Control.

        .DESCRIPTION
        Rolls back remediation done for 'Azure_VirtualMachine_SI_Deploy_GuestConfig_Extension' Control.
        Install Guest Configuration Extension for Virtual Machine. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that was previously remediated.
        
        .PARAMETER Force
        Specifies a forceful roll back without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
      
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the roll back.

        .INPUTS
        None. You cannot pipe objects to Uninstall-GuestConfigExtDisableMI.

        .OUTPUTS
        None. Uninstall-GuestConfigExtDisableMI does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Uninstall-GuestConfigExtDisableMI -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\VirtualMachineGuestConfigExtension\NonCompliantVMGuestConfigAndMI.csv

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

    Write-Host "*** To Uninstall Guest Configuration Extension on Virtual Machine and to disable System Assigned MI in a Subscription, Contributor or higher privileges  are required***" -ForegroundColor $([Constants]::MessageType.Warning)

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 3] Preparing to fetch all Virtual Machine(s)..."
    Write-Host $([Constants]::SingleDashLine)
    
    if (-not (Test-Path -Path $FilePath)) {
        Write-Host "ERROR: Input file - [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        break
    }

    Write-Host "Fetching all Virtual Machine(s) from" -NoNewline
    Write-Host " [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Update)
    $VirtualMachineDetails = Import-Csv -LiteralPath $FilePath

    $validVirtualMachineDetails = $VirtualMachineDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) -and ![String]::IsNullOrWhiteSpace($_.ResourceGroupName) -and ![String]::IsNullOrWhiteSpace($_.ResourceName) }

    $totalVirtualMachine = $(($validVirtualMachineDetails | Measure-Object).Count)

    if ($totalVirtualMachine -eq 0) {
        Write-Host "No Virtual Machine(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        break
    }

    Write-Host "Found [$(($totalVirtualMachine|Measure-Object).Count)] Virtual Machine(s)." -ForegroundColor $([Constants]::MessageType.Update)

    $colsProperty = @{Expression = { $_.ResourceName }; Label = "ResourceName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.ResourceGroupName }; Label = "ResourceGroupName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.ResourceId }; Label = "ResourceId"; Width = 50; Alignment = "left" },
    @{Expression = { $_.OsType }; Label = "OsType"; Width = 10; Alignment = "left" },
    @{Expression = { $_.isSystemAssignedManagedIdentityPresent }; Label = "isSystemAssignedManagedIdentityPresent"; Width = 10; Alignment = "left" },
    @{Expression = { $_.isGuestConfigurationExtensionPresent }; Label = "isGuestConfigurationExtensionPresent"; Width = 10; Alignment = "left" },
    @{Expression = { $_.isGuestConfigurationInstalledByRemediation }; Label = "isGuestConfigurationInstalledByRemediation"; Width = 10; Alignment = "left" },
    @{Expression = { $_.isSystemManagedIdenityInstalledByRemediation }; Label = "isSystemManagedIdenityInstalledByRemediation"; Width = 10; Alignment = "left" }  

        
    $validVirtualMachineDetails | Format-Table -Property $colsProperty -Wrap
    
    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\Rollback"

    if (-not (Test-Path -Path $backupFolderPath)) {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
  
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 3] Rolling back Guest Configuration Extension for all Virtual Machine(s) with System Assigned MI in the Subscription..."
    Write-Host $([Constants]::SingleDashLine)

    if ( -not $Force) {
        Write-Host "Do you want to continue roll back operation?"  -ForegroundColor $([Constants]::MessageType.Warning)
        $userInput = Read-Host -Prompt "(Y|N)"

        if ($userInput -ne "Y") {
            Write-Host "Guest Configuration Extension and System Assigned MI will not be rolled back for any Virtual Machine(s) in the Subscription. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
            break
        }
    }
    else {
        Write-Host "'Force' flag is provided. Guest Configuration Extension and System Assigned MI will be rolled back for any Virtual Machine(s) in the Subscription without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
    }

    # List for storing rolled back Virtual Machine resource.
    $VirtualMachineRolledBack = @()

    # List for storing skipped rolled back Virtual Machine resource.
    $VirtualMachineForGuestConfigExtensionSkipped = @()
    $VirtualMachineForManagedIdentitySkipped = @()
    $IsManagedIdentityRolledback = $false;
    $IsGuestConfigurationExtensionRolledback = $false;



    Write-Host "Starting Roll back operation..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

    $validVirtualMachineDetails | ForEach-Object {
        $VirtualMachine = $_
        $SkippedUserAssignedIdentitiesKeys = @()
        $VirtualMachine | Add-Member -NotePropertyName isGuestConfigExtensionRolledback -NotePropertyValue $false
        $VirtualMachine | Add-Member -NotePropertyName isSystemManagedIdenityRolledback -NotePropertyValue $false
        $VirtualMachine | Add-Member -NotePropertyName skippedUserAssignedIdentitiesKeys -NotePropertyValue "-"
        $_.isGuestConfigurationInstalledByRemediation = [System.Convert]::ToBoolean($_.isGuestConfigurationInstalledByRemediation)
        $_.isSystemManagedIdenityInstalledByRemediation = [System.Convert]::ToBoolean($_.isSystemManagedIdenityInstalledByRemediation)


        try {
            
            
            if ($_.isGuestConfigurationInstalledByRemediation -or $_.isSystemManagedIdenityInstalledByRemediation) {
               
                if ($_.isGuestConfigurationInstalledByRemediation) {
                    Write-Host "Rolling back Guest Configuration Extension on Virtual Machine(s) - [$($_.ResourceName)]" -ForegroundColor $([Constants]::MessageType.Info)

                    if ($_.OsType -ieq "Windows") {
                        $VirtualMachineResource = Remove-AzVMExtension -ResourceGroupName $_.ResourceGroupName -VMName  $_.ResourceName -Name 'AzurePolicyforWindows'
                    }
                    else {
                        $VirtualMachineResource = Remove-AzVMExtension -ResourceGroupName $_.ResourceGroupName -VMName  $_.ResourceName -Name 'AzurePolicyforLinux'
                    }

                    if ($VirtualMachineResource.IsSuccessStatusCode) {
                        $IsGuestConfigurationExtensionRolledback = $true
                    }
                }
                else {
                    $IsGuestConfigurationExtensionRolledback = $true
                }
                if ($_.isSystemManagedIdenityInstalledByRemediation) {
                    Write-Host "Rolling back System Assigned MI on Virtual Machine(s) - [$($_.ResourceName)]" -ForegroundColor $([Constants]::MessageType.Info)

                    $VMDetail = Get-AzVM -ResourceGroupName $_.ResourceGroupName -Name $_.ResourceName
                    $UserAssignedIdentityKey = $VMDetail.Identity.UserAssignedIdentities.Keys -split (' ')
                    #key add in excel
                    try {
                        #removing all the identity 
                        $VirtualMachineIdentityResponse = Update-AzVM -ResourceGroupName $_.ResourceGroupName -VM $VMDetail  -IdentityType "None"
                        $IsManagedIdentityRolledback = $VirtualMachineIdentityResponse.IsSuccessStatusCode                       
                        if ($IsManagedIdentityRolledback) {
                            #Reassigning all the User Managed Identity
                            $UserAssignedIdentityKey | ForEach-Object {
                                Write-Host $UserAssignedIdentityKey
                                  
                                $VirtualMachineIdentityResponse = Update-AzVM -ResourceGroupName $_.ResourceGroupName -VM $VMDetail  -IdentityType "UserAssigned" -IdentityId $UserAssignedIdentityKey
                                if (!$VirtualMachineIdentityResponse.IsSuccessStatusCode) {
                                    $IsManagedIdentityRolledback = $false;
                                }
                                else {
                                    $SkippedUserAssignedIdentitiesKeys += " " + $UserAssignedIdentityKey
                                }
                                   
                            }
                        }
                    }
                    catch {
                        $VirtualMachineForManagedIdentitySkipped += $VirtualMachine
                    }
                }
                else {
                    $IsManagedIdentityRolledback = $true
                }

                
        
                if ($IsGuestConfigurationExtensionRolledback -and $IsManagedIdentityRolledback) {
                    Write-Host "Succesfully rolled back Guest Configuration Extension and System Assigned MI on VirtualMachine(s) - [$($_.ResourceName)]" -ForegroundColor $([Constants]::MessageType.Update)
                    Write-Host $([Constants]::SingleDashLine) 
                    if ($_.isGuestConfigurationInstalledByRemediation) {
                        $VirtualMachine.isGuestConfigurationInstalledByRemediation = $false
                        $VirtualMachine.isGuestConfigExtensionRolledback = $true
                    }
                    if ($_.isSystemManagedIdenityInstalledByRemediation) {
                        $VirtualMachine.isSystemManagedIdenityRolledback = $true;
                        $VirtualMachine.isSystemManagedIdenityInstalledByRemediation = $false;
                    }
                    $VirtualMachineRolledBack += $VirtualMachine    
                }
                elseif (!$VirtualMachineResource.IsSuccessStatusCode) {
                    $VirtualMachine.isGuestConfigExtensionRolledback = $false
                    $VirtualMachineForGuestConfigExtensionSkipped += $VirtualMachine

                }
                elseif (!IsManagedIdentityRolledback) {
                    $VirtualMachine.isSystemManagedIdenityRolledback = $false
                    $VirtualMachine.skippedUserAssignedIdentitiesKeys = $SkippedUserAssignedIdentitiesKeys

                    $VirtualMachineForManagedIdentitySkipped += $VirtualMachine
                }
               
            }
            
        }
        catch {
            $VirtualMachineForGuestConfigExtensionSkipped += $VirtualMachine
        }
    }

    $colsPropertyRollBack = @{Expression = { $_.ResourceName }; Label = "ResourceName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.ResourceGroupName }; Label = "ResourceGroupName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.ResourceId }; Label = "ResourceId"; Width = 50; Alignment = "left" },
    @{Expression = { $_.isSystemAssignedManagedIdentityPresent }; Label = "isSystemAssignedManagedIdentityPresent"; Width = 10; Alignment = "left" },
    @{Expression = { $_.isGuestConfigurationExtensionPresent }; Label = "isGuestConfigurationExtensionPresent"; Width = 10; Alignment = "left" },
    @{Expression = { $_.isGuestConfigurationInstalledByRemediation }; Label = "isGuestConfigurationInstalledByRemediation"; Width = 10; Alignment = "left" },
    @{Expression = { $_.isGuestConfigExtensionRolledback }; Label = "isGuestConfigExtensionRolledback"; Width = 10; Alignment = "left" },
    @{Expression = { $_.isSystemManagedIdenityInstalledByRemediation }; Label = "isSystemManagedIdenityInstalledByRemediation"; Width = 10; Alignment = "left" },
    @{Expression = { $_.isSystemManagedIdenityRolledback }; Label = "isSystemManagedIdenityRolledback"; Width = 10; Alignment = "left" },
    @{Expression = { $_.skippedUserAssignedIdentitiesKeys }; Label = "skippedUserAssignedIdentitiesKeys"; Width = 10; Alignment = "left" }


    if ($($VirtualMachineRolledBack | Measure-Object).Count -gt 0 -or $($VirtualMachineForGuestConfigExtensionSkipped | Measure-Object).Count -gt 0 -or $($VirtualMachineForManagedIdentitySkipped | Measure-Object).Count -gt 0) {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Rollback Summary: " -ForegroundColor $([Constants]::MessageType.Info)
        
        if ($($VirtualMachineRolledBack | Measure-Object).Count -gt 0) {
            Write-Host "Guest Configuration Extension is rolled back successfully on following Virtual Machine(s) in the Subscription: " -ForegroundColor $([Constants]::MessageType.Update)
            $VirtualMachineRolledBack | Format-Table -Property $colsPropertyRollBack -Wrap

            # Write this to a file.
            $VirtualMachineRolledBackFile = "$($backupFolderPath)\RolledBackVirtualMachine.csv"
            $VirtualMachineRolledBack | Export-CSV -Path $VirtualMachineRolledBackFile -NoTypeInformation
            Write-Host "This information has been saved to" -NoNewline
            Write-Host " [$($VirtualMachineRolledBackFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
            Write-Host $([Constants]::SingleDashLine)
        }

        if ($($VirtualMachineForGuestConfigExtensionSkipped | Measure-Object).Count -gt 0) {
            Write-Host "Error uninstalling Guest Configuration on following Virtual Machine(s) in the Subscription: " -ForegroundColor $([Constants]::MessageType.Warning)
            
            $VirtualMachineForGuestConfigExtensionSkipped | Format-Table -Property $colsProperty -Wrap
            
            # Write this to a file.
            $VirtualMachineForGuestConfigExtensionSkippedFile = "$($backupFolderPath)\RollbackSkippedVMForGuestConfigExt.csv"
            $VirtualMachineForGuestConfigExtensionSkipped | Export-CSV -Path $VirtualMachineForGuestConfigExtensionSkippedFile -NoTypeInformation
            Write-Host "This information has been saved to" -NoNewline
            Write-Host " [$($VirtualMachineForGuestConfigExtensionSkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update)  
            Write-Host $([Constants]::SingleDashLine)

        }

        if ($($VirtualMachineForManagedIdentitySkipped | Measure-Object).Count -gt 0) {
            Write-Host "Error uninstalling Guest Configuration on following Virtual Machine(s) in the Subscription: " -ForegroundColor $([Constants]::MessageType.Warning)
            
            $VirtualMachineForManagedIdentitySkipped | Format-Table -Property $colsProperty -Wrap
            
            # Write this to a file.
            $VirtualMachineForManagedIdentitySkippedFile = "$($backupFolderPath)\RollbackSkippedVMForMI.csv"
            $VirtualMachineForManagedIdentitySkipped | Export-CSV -Path $VirtualMachineForManagedIdentitySkippedFile -NoTypeInformation
            Write-Host "This information has been saved to" -NoNewline
            Write-Host " [$($VirtualMachineForManagedIdentitySkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update)  
            Write-Host $([Constants]::SingleDashLine)

        }
    }
}

function Validate-VMGuestConfigExtAndMI {
    <#
        .SYNOPSIS
        Validate remediation done for 'Azure_VirtualMachine_SI_Deploy_GuestConfig_Extension' Control.

        .DESCRIPTION
        Validate remediation done for 'Azure_VirtualMachine_SI_Deploy_GuestConfig_Extension' Control.
        Validate  Guest Configuration extension is installed with provisioning state Succedded on Virtual Machine with system-assigned managed identity.
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that was previously remediated.
         
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
      
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the validate.

        .INPUTS
        None. You cannot pipe objects to Uninstall-GuestConfigExtDisableMI.

        .OUTPUTS
        None. Uninstall-GuestConfigExtDisableMI does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Uninstall-GuestConfigExtDisableMI -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\VirtualMachineGuestConfigExtension\NonCompliantVMGuestConfigAndMI.csv

        .LINK
        None
    #>

    param (
        [String]
        [Parameter(Mandatory = $true, HelpMessage = "Specifies the ID of the Subscription that was previously remediated.")]
        $SubscriptionId,

        [Switch]
        [Parameter(HelpMessage = "Specifies validation of prerequisites for the command")]
        $PerformPreReqCheck,

        [String]
        [Parameter(Mandatory = $true, HelpMessage = "Specifies the path to the file to be used as input for the validate")]
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

    Write-Host "*** To install Guest Configuration Extension on Virtual Machine and to enable System Assigned MI in a Subscription, Contributor or higher privileges  are required***" -ForegroundColor $([Constants]::MessageType.Warning)

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 2 of 3] Preparing to fetch all Virtual Machine(s)..."
    Write-Host $([Constants]::SingleDashLine)
    
    if (-not (Test-Path -Path $FilePath)) {
        Write-Host "ERROR: Input file - [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        break
    }

    Write-Host "Fetching all Virtual Machine(s) from" -NoNewline
    Write-Host " [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Update)
    $VirtualMachineDetails = Import-Csv -LiteralPath $FilePath

    $validVirtualMachineDetails = $VirtualMachineDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) -and ![String]::IsNullOrWhiteSpace($_.ResourceGroupName) -and ![String]::IsNullOrWhiteSpace($_.ResourceName) }

    $totalVirtualMachine = $(($validVirtualMachineDetails | Measure-Object).Count)

    if ($totalVirtualMachine -eq 0) {
        Write-Host "No Virtual Machine(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        break
    }

    Write-Host "Found [$(($totalVirtualMachine|Measure-Object).Count)] Virtual Machine(s)." -ForegroundColor $([Constants]::MessageType.Update)

    $colsProperty = @{Expression = { $_.ResourceName }; Label = "ResourceName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.ResourceGroupName }; Label = "ResourceGroupName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.ResourceId }; Label = "ResourceId"; Width = 50; Alignment = "left" },
    @{Expression = { $_.OsType }; Label = "OsType"; Width = 10; Alignment = "left" },    
    @{Expression = { $_.isSystemAssignedManagedIdentityPresent }; Label = "isSystemAssignedManagedIdentityPresent"; Width = 10; Alignment = "left" },
    @{Expression = { $_.isGuestConfigurationExtensionPresent }; Label = "isGuestConfigurationExtensionPresent"; Width = 10; Alignment = "left" },
    @{Expression = { $_.isGuestConfigurationInstalledByRemediation }; Label = "isGuestConfigurationInstalledByRemediation"; Width = 10; Alignment = "left" },
    @{Expression = { $_.isSystemManagedIdenityInstalledByRemediation }; Label = "isSystemManagedIdenityInstalledByRemediation"; Width = 10; Alignment = "left" }  

        
    $validVirtualMachineDetails | Format-Table -Property $colsProperty -Wrap
    
    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\Validate"

    if (-not (Test-Path -Path $backupFolderPath)) {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
  
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 3 of 3] Validating Guest Configuration Extension for all Virtual Machine(s) in the Subscription..."
              

    # List for storing Validated Virtual Machine resource.
    $VirtualMachineValidated = @()

    # List for storing skipped Validated Virtual Machine resource.
    $VirtualMachineForGuestConfigExtensionSkipped = @()
    $VirtualMachineForManagedIdentitySkipped = @()
    $IsManagedIdentityValidated = $false;
    $IsGuestConfigurationExtensionValidated = $false;



    Write-Host "Starting Validation operation..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

    $validVirtualMachineDetails | ForEach-Object {
        $VirtualMachine = $_
        $SkippedUserAssignedIdentitiesKeys = @()
        $VirtualMachine | Add-Member -NotePropertyName isGuestConfigExtPresentPostValidation -NotePropertyValue $false
        $VirtualMachine | Add-Member -NotePropertyName isSystemManagedIdenityPresentPostValidation -NotePropertyValue $false
        $_.isGuestConfigurationInstalledByRemediation = [System.Convert]::ToBoolean($_.isGuestConfigurationInstalledByRemediation)
        $_.isSystemManagedIdenityInstalledByRemediation = [System.Convert]::ToBoolean($_.isSystemManagedIdenityInstalledByRemediation)


        try {
            
            if ($_.isGuestConfigurationInstalledByRemediation -or $_.isSystemManagedIdenityInstalledByRemediation) {
                
                if ($_.isGuestConfigurationInstalledByRemediation) {
                    Write-Host "Validating Guest Configuration Extension on Virtual Machine(s) - [$($_.ResourceName)]" -ForegroundColor $([Constants]::MessageType.Info)
                       
                    $IsExtPresent = $true;
                    #Getting list of extensions
                    $VMExtension = Get-AzVMExtension -ResourceGroupName $_.ResourceGroupName -VMName $_.ResourceName
                    $VMExtension | ForEach-Object {
                        if ($IsExtPresent) {           
                            if ($VMExtension.Publisher -contains ("Microsoft.GuestConfiguration")) { 
                                if ($VMExtension.ProvisioningState -eq "Succeeded") {                                       
                                    $logSkippedResources += $logResource
                                    $IsExtPresent = $true;
                                }
                            }
                            else {
                                $NonCompliantVirtualMachineGuestExt += $VirtualMachine
                                $IsExtPresent = $flase;

                            }
                        }
                    }
                        
                    if ($IsExtPresent) {
                        $IsGuestConfigurationExtensionValidated = $true
                    }
                }
                else {

                    $IsGuestConfigurationExtensionValidated = $true
                }
                if ($_.isSystemManagedIdenityInstalledByRemediation) {
                    Write-Host "Validating System Assigned MI on Virtual Machine(s) - [$($_.ResourceName)]" -ForegroundColor $([Constants]::MessageType.Info)

                    $VMDetail = Get-AzVM -ResourceGroupName $_.ResourceGroupName -Name $_.ResourceName
                    if ($VMDetail.Identity.Type -contains "SystemAssignedUserAssigned" -or $VMDetail.Identity.Type -contains "SystemAssigned") {
                        $_.isSystemAssignedManagedIdentityPresent = $true
                        $IsManagedIdentityValidated = $true
                    }
                    else {
                        $NonCompliantVirtualMachineGuestExt += $VirtualMachine
                    }
                }
                else {
                    $IsManagedIdentityValidated = $true
                }

                
        
                if ($IsGuestConfigurationExtensionValidated -and $IsManagedIdentityValidated) {
                    Write-Host "Succesfully validated Guest Configuration Extension and System Assigned MI on VirtualMachine(s) - [$($_.ResourceName)]" -ForegroundColor $([Constants]::MessageType.Update)
                    Write-Host $([Constants]::SingleDashLine) 
                    if ($_.isGuestConfigurationInstalledByRemediation) {
                        $VirtualMachine.isGuestConfigExtPresentPostValidation = $true
                    }
                    if ($_.isSystemManagedIdenityInstalledByRemediation) {
                        $VirtualMachine.isSystemManagedIdenityPresentPostValidation = $true;
                         
                    }
                    $VirtualMachineValidated += $VirtualMachine    
                }
                if (!$IsGuestConfigurationExtensionValidated) {
                    $VirtualMachine.isGuestConfigExtPresentPostValidation = $false
                    $VirtualMachineForGuestConfigExtensionSkipped += $VirtualMachine

                }
                if (!$IsManagedIdentityValidated) {
                    $VirtualMachine.isSystemManagedIdenityPresentPostValidation = $false
                    $VirtualMachine.skippedUserAssignedIdentitiesKeys = $SkippedUserAssignedIdentitiesKeys
                    $VirtualMachineForManagedIdentitySkipped += $VirtualMachine
                }
               
            }            
        }
        catch {
            $VirtualMachineForGuestConfigExtensionSkipped += $VirtualMachine
        }
    }

    $colsPropertyValidate = @{Expression = { $_.ResourceName }; Label = "ResourceName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.ResourceGroupName }; Label = "ResourceGroupName"; Width = 30; Alignment = "left" },
    @{Expression = { $_.ResourceId }; Label = "ResourceId"; Width = 50; Alignment = "left" },
    @{Expression = { $_.isGuestConfigurationInstalledByRemediation }; Label = "isGuestConfigurationInstalledByRemediation"; Width = 50; Alignment = "left" },
    @{Expression = { $_.isGuestConfigExtPresentPostValidation }; Label = "isGuestConfigExtPresentPostValidation"; Width = 20; Alignment = "left" },
    @{Expression = { $_.isSystemManagedIdenityInstalledByRemediation }; Label = "isSystemManagedIdenityInstalledByRemediation"; Width = 20; Alignment = "left" },
    @{Expression = { $_.isSystemManagedIdenityPresentPostValidation }; Label = "isSystemManagedIdenityPresentPostValidation"; Width = 20; Alignment = "left" },
    @{Expression = { $_.skippedUserAssignedIdentitiesKeys }; Label = "skippedUserAssignedIdentitiesKeys"; Width = 20; Alignment = "left" }


    if ($($VirtualMachineValidated | Measure-Object).Count -gt 0 -or $($VirtualMachineForGuestConfigExtensionSkipped | Measure-Object).Count -gt 0 -or $($VirtualMachineForManagedIdentitySkipped | Measure-Object).Count -gt 0) {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Validation Summary: " -ForegroundColor $([Constants]::MessageType.Info)
        
        if ($($VirtualMachineValidated | Measure-Object).Count -gt 0) {
            Write-Host "Guest Configuration Extension and System Assigned MI is Validated successfully on following Virtual Machine(s) in the Subscription: " -ForegroundColor $([Constants]::MessageType.Update)
            $VirtualMachineValidated | Format-Table -Property $colsPropertyValidate -Wrap

            # Write this to a file.
            $VirtualMachineValidatedFile = "$($backupFolderPath)\ValidatedVirtualMachine.csv"
            $VirtualMachineValidated | Export-CSV -Path $VirtualMachineValidatedFile -NoTypeInformation
            Write-Host "This information has been saved to" -NoNewline
            Write-Host " [$($VirtualMachineValidatedFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
            Write-Host $([Constants]::SingleDashLine)
        }

        if ($($VirtualMachineForGuestConfigExtensionSkipped | Measure-Object).Count -gt 0) {
            Write-Host "Error validating Guest Configuration on following Virtual Machine(s) in the Subscription: " -ForegroundColor $([Constants]::MessageType.Warning)
            
            $VirtualMachineForGuestConfigExtensionSkipped | Format-Table -Property $colsProperty -Wrap
            
            # Write this to a file.
            $VirtualMachineForGuestConfigExtensionSkippedFile = "$($backupFolderPath)\ValidationSkippedVirtualMachineForGuestConfigExtension.csv"
            $VirtualMachineForGuestConfigExtensionSkipped | Export-CSV -Path $VirtualMachineForGuestConfigExtensionSkippedFile -NoTypeInformation
            Write-Host "This information has been saved to" -NoNewline
            Write-Host " [$($VirtualMachineForGuestConfigExtensionSkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update)  
            Write-Host $([Constants]::SingleDashLine)

        }

        if ($($VirtualMachineForManagedIdentitySkipped | Measure-Object).Count -gt 0) {
            Write-Host "Error validating System Assigned MI on following Virtual Machine(s) in the Subscription: " -ForegroundColor $([Constants]::MessageType.Warning)
            
            $VirtualMachineForManagedIdentitySkipped | Format-Table -Property $colsProperty -Wrap
            
            # Write this to a file.
            $VirtualMachineForManagedIdentitySkippedFile = "$($backupFolderPath)\ValidationSkippedVirtualMachineForManagedIdentity.csv"
            $VirtualMachineForManagedIdentitySkipped | Export-CSV -Path $VirtualMachineForManagedIdentitySkippedFile -NoTypeInformation
            Write-Host "This information has been saved to" -NoNewline
            Write-Host " [$($VirtualMachineForManagedIdentitySkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update)  
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
