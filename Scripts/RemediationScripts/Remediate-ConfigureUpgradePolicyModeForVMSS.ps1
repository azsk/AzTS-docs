<###
# Overview:
    This script is used to set required Upgrade policy mode for Virtual Machine Scale Set in a Subscription.

# Control ID:
    Azure_VirtualMachineScaleSet_SI_Enforce_Automatic_Upgrade_Policy

# Display Name:
    Enforce Automatic Upgrade policy in VMSS

# Prerequisites:
    1. Contributor or higher privileges on the Virtual machine scale sets in a Subscription.
    2. Must be connected to Azure with an authenticated account.

# Steps performed by the script:
    To remediate:
        1. Validate and install the modules required to run the script.
        2. Get the list of Virtual machine scale sets in a Subscription that doesn't have upgrade policy mode as Automatic.
        3. Back up details of Virtual machine scale sets that are to be remediated.
        4. Set upgrade policy mode as 'Automatic' on the all Virtual machine scale sets in the Subscription.

    To roll back:
        1. Validate and install the modules required to run the script.
        2. Get the list of Virtual machine scale sets in a Subscription, the changes made to which previously, are to be rolled back.
        3. Reset Set upgrade policy mode on the all Virtual machine scale sets in the Subscription from backed up data.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to configure uprade policy mode in all Virtual machine scale sets in the Subscription. Refer `Examples`, below.

    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to Enable Upgrade policy mode in all Virtual machine scale sets in the Subscription. Refer `Examples`, below.
        4. Please note that for Virtual machine scale sets with upgrade policy mode as Rolling, rollback is not possible using this BRS.

# Examples:
    To remediate:
        1. To review the Virtual machine scale sets in a Subscription that will be remediated:
           Configure-UpgradePolicyMode -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        2. To configure uprade policy mode on all Virtual machine scale sets in a Subscription:
           Configure-UpgradePolicyMode -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        3. To configure uprade policy mode on all Virtual machine scale sets in a Subscription, from a previously taken snapshot:
           Configure-UpgradePolicyMode -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\configureUpgradePolicyModeForVMSS\VMSSwithoutAutomaticUpgradePolicyModeForVMSS.csv

        4. To configure uprade policy mode on all Virtual machine scale sets in a Subscription without taking back up before actual remediation:
           Configure-UpgradePolicyMode -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -SkipBackup

        To know more about the options supported by the remediation command, execute:
        Get-Help Configure-UpgradePolicyMode -Detailed

    To roll back:
        1. To reset Upgrade policy mode of all Virtual machine scale sets in a Subscription, from a previously taken snapshot:
           Reset-UpgradePolicyMode -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\configureUpgradePolicyModeForVMSS\RemediatedVMSS.csv
        
        2. To reset Upgrade policy mode of all Virtual machine scale sets in a Subscription, from a previously taken snapshot:
           Reset-UpgradePolicyMode -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\configureUpgradePolicyModeForVMSS\RemediatedVMSS.csv

        To know more about the options supported by the roll back command, execute:
        Get-Help Reset-UpgradePolicyMode -Detailed        
###>

function Setup-Prerequisites
{
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

    Write-Host "Required modules: $($requiredModules -join ', ')"
    Write-Host $([Constants]::SingleDashLine)    
    Write-Host "Checking if the required modules are present..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

    $availableModules = $(Get-Module -ListAvailable $requiredModules -ErrorAction Stop)

    # Check if the required modules are installed.
    $requiredModules | ForEach-Object {
        if ($availableModules.Name -notcontains $_)
        {
            Write-Host "[$($_)] module is not present." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host "Installing [$($_)] module..." -ForegroundColor $([Constants]::MessageType.Info)
            Install-Module -Name $_ -Scope CurrentUser -Repository 'PSGallery' -ErrorAction Stop
            Write-Host "[$($_)] module installed." -ForegroundColor $([Constants]::MessageType.Update)
        }
        else
        {
            Write-Host "[$($_)] module is present." -ForegroundColor $([Constants]::MessageType.Update)
        }
    }
}

function Configure-UpgradePolicyMode
{
    <#
        .SYNOPSIS
        Remediates 'Azure_VirtualMachineScaleSet_SI_Enforce_Automatic_Upgrade_Policy' Control.

        .DESCRIPTION
        Remediates 'Azure_VirtualMachineScaleSet_SI_Enforce_Automatic_Upgrade_Policy' Control.
        Enforce Automatic Upgrade policy in VMSS. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription to be remediated.
        
        .PARAMETER Force
        Specifies a forceful remediation without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
        
        .PARAMETER DryRun
        Specifies a dry run of the actual remediation.

        .PARAMETER SkipBackup
        Specifies that no back up will be taken by the script before remediation.
        
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the remediation.

        .PARAMETER Path
        Specifies the path to the file to be used as input for the remediation when AutoRemediation switch is used.

        .PARAMETER AutoRemediation
        Specifies script is run as a subroutine of AutoRemediation Script.

        .PARAMETER TimeStamp
        Specifies the time of creation of file to be used for logging remediation details when AutoRemediation switch is used.

        .INPUTS
        None. You cannot pipe objects to Configure-UpgradePolicyMode.

        .OUTPUTS
        None. Configure-UpgradePolicyMode does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Configure-UpgradePolicyMode -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Configure-UpgradePolicyMode -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        .EXAMPLE
        PS> Configure-UpgradePolicyMode -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\configureUpgradePolicyModeForVMSS\VMSSwithoutAutomaticUpgradePolicyModeForVMSS.csv

        .LINK
        None
    #>

    param (
        [String]
        [Parameter(ParameterSetName = "DryRun", Mandatory = $true, HelpMessage="Specifies the ID of the Subscription to be remediated")]
        [Parameter(ParameterSetName = "WetRun", Mandatory = $true, HelpMessage="Specifies the ID of the Subscription to be remediated")]
        $SubscriptionId,

        [Switch]
        [Parameter(ParameterSetName = "WetRun", HelpMessage="Specifies a forceful remediation without any prompts")]
        $Force,

        [Switch]
        [Parameter(ParameterSetName = "DryRun", HelpMessage="Specifies validation of prerequisites for the command")]
        [Parameter(ParameterSetName = "WetRun", HelpMessage="Specifies validation of prerequisites for the command")]
        $PerformPreReqCheck,

        [Switch]
        [Parameter(ParameterSetName = "DryRun", Mandatory = $true, HelpMessage="Specifies a dry run of the actual remediation")]
        $DryRun,

        [Switch]
        [Parameter(ParameterSetName = "WetRun", HelpMessage="Specifies no back up will be taken by the script before remediation")]
        $SkipBackup,

        [String]
        [Parameter(ParameterSetName = "WetRun", HelpMessage="Specifies the path to the file to be used as input for the remediation")]
        $FilePath,

        [String]
        [Parameter(ParameterSetName = "WetRun", HelpMessage="Specifies the path to the file to be used as input for the remediation when AutoRemediation switch is used")]
        $Path,

        [Switch]
        [Parameter(ParameterSetName = "WetRun", HelpMessage="Specifies script is run as a subroutine of AutoRemediation Script")]
        $AutoRemediation,

        [String]
        [Parameter(ParameterSetName = "WetRun", HelpMessage="Specifies the time of creation of file to be used for logging remediation details when AutoRemediation switch is used")]
        $TimeStamp
    )

    Write-Host $([Constants]::DoubleDashLine)
    if ($PerformPreReqCheck)
    {
        try
        {
            Write-Host "[Step 1 of 5] Validate and install the modules required to run the script and validate the user"
            Write-Host $([Constants]::SingleDashLine)
            Write-Host "Setting up prerequisites..." -ForegroundColor $([Constants]::MessageType.Info)	
            Write-Host $([Constants]::SingleDashLine)
            Setup-Prerequisites
            Write-Host "Completed setting up prerequisites." -ForegroundColor $([Constants]::MessageType.Update)	
            Write-Host $([Constants]::SingleDashLine)
        }
        catch
        {
            Write-Host "Error occurred while setting up prerequisites. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)            
            Write-Host $([Constants]::DoubleDashLine)
            return
        }
    }
    else
    {
        Write-Host "[Step 1 of 5] Validate the user"
        Write-Host $([Constants]::SingleDashLine)
    }

    # Connect to Azure account
    $context = Get-AzContext

    if ([String]::IsNullOrWhiteSpace($context))
    {
        Write-Host "Connecting to Azure account..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        Connect-AzAccount -Subscription $SubscriptionId -ErrorAction Stop | Out-Null
        Write-Host "Connected to Azure account." -ForegroundColor $([Constants]::MessageType.Update)        
        Write-Host $([Constants]::SingleDashLine)
    }
      # Setting up context for the current Subscription.
      $context = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop
    

    if(-not($AutoRemediation))	
    {
        Write-Host "Subscription Name: [$($context.Subscription.Name)]"
        Write-Host "Subscription ID: [$($context.Subscription.SubscriptionId)]"
        Write-Host "Account Name: [$($context.Account.Id)]"
        Write-Host "Account Type: [$($context.Account.Type)]"
        Write-Host $([Constants]::SingleDashLine)
    }

    Write-Host "To configure uprade policy mode on Virtual machine scale sets in a Subscription, Contributor or higher privileges on the Virtual machine scale sets are required." -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "[Step 2 of 5] Fetch all Virtual machine scale sets"
    Write-Host $([Constants]::SingleDashLine)
    $vmssResources = @()

    # To keep track of remediated and skipped resources
    $logRemediatedResources = @()
    $logSkippedResources=@()
    
    # Control Id
    $controlIds = "Azure_VirtualMachineScaleSet_SI_Enforce_Automatic_Upgrade_Policy"

    if($AutoRemediation)
    {
        if(-not (Test-Path -Path $Path))
        {
            Write-Host "File containing failing controls details [$($Path)] not found. Skipping remediation..." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::DoubleDashLine)
            return
        }
        Write-Host "Fetching all Virtual machine scale sets failing for the [$($controlIds)] control from [$($Path)]..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        $controlForRemediation = Get-content -path $Path | ConvertFrom-Json
        $controls = $controlForRemediation.ControlRemediationList
        $resourceDetails = $controls | Where-Object { $controlIds -eq $_.ControlId };
        $validResources = $resourceDetails.FailedResourceList | Where-Object {![String]::IsNullOrWhiteSpace($_.ResourceName)}

        if(($resourceDetails | Measure-Object).Count -eq 0 -or ($validResources | Measure-Object).Count -eq 0)
        {
            Write-Host "No Virtual machine scale sets found in input json file for remediation." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::DoubleDashLine)
            return
        } 

        $validResources | ForEach-Object { 
            try
            {
                $name = $_.ResourceName
                $resourceGroupName = $_.ResourceGroupName
                $vmss = Get-AzVMSS -VMScaleSetName $name -ResourceGroupName $resourceGroupName -ErrorAction SilentlyContinue
                $vmssResources = $vmssResources + $vmss
            }
            catch
            {
                Write-Host "Valid resource id(s) not found in input json file. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host "Skipping the Resource: [$($_.ResourceName)]..." -ForegroundColor $([Constants]::MessageType.Warning)
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                $logResource.Add("ResourceName",($_.ResourceName))
                $logResource.Add("Reason","Valid resource id(s) not found in input json file.")    
                $logSkippedResources += $logResource
                Write-Host $([Constants]::SingleDashLine)
            }
        }
    }
    else
    {
        # No file path provided as input to the script. Fetch all Virtual machine scale sets in the Subscription.
        if ([String]::IsNullOrWhiteSpace($FilePath))
        {
            Write-Host "Fetching all Virtual machine scale sets in Subscription: [$($context.Subscription.SubscriptionId)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)

            # Get all VMSS in the Subscription
            $vmssResources = Get-AzVMSS -ErrorAction SilentlyContinue
            $totalvmssResources = ($vmssResources | Measure-Object).Count
        
        }
        else
        {
            if (-not (Test-Path -Path $FilePath))
            {
                Write-Host "Input file - [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host $([Constants]::DoubleDashLine)
                return
            }

            Write-Host "Fetching all Virtual machine scale sets(s) from [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            $vmssResourcesFromFile = Import-Csv -LiteralPath $FilePath
            $validvmssResources = $vmssResourcesFromFile | Where-Object { ![String]::IsNullOrWhiteSpace($_.Name)-and ![String]::IsNullOrWhiteSpace($_.ResourceGroupName)}
    
            $validvmssResources | ForEach-Object {
                $resourceGroupName = $_.ResourceGroupName        
                $name = $_.Name
                try
                {
                    $vmssResources += (Get-AzVMSS -ResourceGroupName $resourceGroupName -VMScaleSetName $name -ErrorAction SilentlyContinue) 

                }
                catch
                {
                    Write-Host "Error fetching Virtual Machine Scale Set: [$($name)]. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                    Write-Host "Skipping this Virtual Machine Scale Set..." -ForegroundColor $([Constants]::MessageType.Warning)
                }
            }
        }
    }
    
    $totalvmssResources = ($vmssResources | Measure-Object).Count

    if ($totalvmssResources -eq 0)
    {
        Write-Host "No Virtual machine scale sets found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        Write-Host $([Constants]::DoubleDashLine)
        return
    }

    Write-Host "Found [$($totalvmssResources)] Virtual Machine Scale Set(s)." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)
 
    # Includes Virtual machine scale sets where Upgrade policy mode is Automatic 
    $vmssWithRequiredUpgradePolicyMode= @()

    # Includes Virtual machine scale sets where Upgrade policy mode is Enabled  
    $vmssWithoutRequiredUpgradePolicyMode= @()
    $requiredUpgradePolicyMode = "Automatic"
    $applicableOrchestrationMode = "Uniform"

    # Includes Virtual machine scale sets that were skipped during remediation. There were errors remediating them.
    $vmssSkipped = @()

    Write-Host "[Step 3 of 5] Fetching Virtual machine scale sets"
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Separating Virtual Machine Scale Set(s) for which Upgrade policy mode is not [$($requiredUpgradePolicyMode)] and orchestration mode is [$($applicableOrchestrationMode)]  ..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    $vmssResources | ForEach-Object {  
        $vmssResource = $_  
        if($_.OrchestrationMode -eq $applicableOrchestrationMode)
        {
            if($_.UpgradePolicy.Mode -ne $requiredUpgradePolicyMode){
            $vmssWithoutRequiredUpgradePolicyMode += $vmssResource | Select-Object @{N='Name';E={$_.Name}},
                                                    @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                    @{N='OrchestrationMode';E={$_.OrchestrationMode}},
                                                    @{N='UpgradePolicyMode';E={$_.UpgradePolicy.Mode}}
           }
           else
           {
            $vmssWithRequiredUpgradePolicyMode += $vmssResource | Select-Object @{N='Name';E={$_.Name}},
                                                    @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                    @{N='OrchestrationMode';E={$_.OrchestrationMode}},
                                                    @{N='UpgradePolicyMode';E={$_.UpgradePolicy.Mode}}
           }

            $logResource = @{}
            $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
            $logResource.Add("ResourceName",($_.Name))
            $logResource.Add("Reason","Upgrade policy mode is already [$($requiredUpgradePolicyMode)] in Virtual Machine Scale Set.")    
            $logSkippedResources += $logResource
            
        }
        else{
            Write-Host "Skipping Virtual Machine Scale Set [$($_.Name)] as Orchestration type is not [$($applicableOrchestrationMode)]..." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
        }
    }

    $totalVMSSWithoutRequiredUpgradePolicyMode = ($vmssWithoutRequiredUpgradePolicyMode | Measure-Object).Count
     
    if ($totalVMSSWithoutRequierdUpgradePolicyMode  -eq 0)
    {
        Write-Host "No Virtual Machine Scale Set found where upgrade policy mode is not [$($requiredUpgradePolicyMode)] and Orchestration type is [$($applicableOrchestrationMode)].. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)	
        
        if($AutoRemediation -and ($vmssResources |Measure-Object).Count -gt 0) 
        {
            $logFile = "LogFiles\"+ $($TimeStamp) + "\log_" + $($SubscriptionId) +".json"
            $log =  Get-content -Raw -path $logFile | ConvertFrom-Json
            foreach($logControl in $log.ControlList){
                if($logControl.ControlId -eq $controlIds){
                    $logControl.RemediatedResources=$logRemediatedResources
                    $logControl.SkippedResources=$logSkippedResources
                }
            }
            $log | ConvertTo-json -depth 10  | Out-File $logFile
        }	

        return
    }

    Write-Host "Found [$($totalVMSSWithoutRequiredUpgradePolicyMode)] Virtual machine scale sets where Upgrade policy mode is not [$($requiredUpgradePolicyMode)]." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)	
     
    if(-not($AutoRemediation))
    {
        Write-Host "Following Virtual machine scale sets will be remediated :" -ForegroundColor $([Constants]::MessageType.Info)
        $colsProperty =     @{Expression={$_.Name};Label="Name";Width=20;Alignment="left"},
                            @{Expression={$_.ResourceGroupName};Label="Resource Group";Width=20;Alignment="left"},
                            @{Expression={$_.OrchestrationMode};Label="Orchestration Mode";Width=20;Alignment="left"},
                            @{Expression={$_.UpgradePolicyMode};Label="Upgrade Policy Mode";Width=20;Alignment="left"}

        $vmssWithoutRequiredUpgradePolicyMode | Format-Table -Property $colsProperty -Wrap
        Write-Host $([Constants]::SingleDashLine)
    }

    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\VMSSUpgradePolicyMode"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
    Write-Host "[Step 4 of 5] Backing up Virtual Machine Scale Set(s) details"
    Write-Host $([Constants]::SingleDashLine)
    if ([String]::IsNullOrWhiteSpace($FilePath))
    {        
        if(-not $SkipBackup)
        {
            # Backing up Virtual Machine Scale Set details.
            $backupFile = "$($backupFolderPath)\VMSSwithoutRequiredUpgradePolicyModeForVMSS.csv"
            $vmssWithoutRequiredUpgradePolicyMode | Export-CSV -Path $backupFile -NoTypeInformation
            Write-Host "Virtual Machine Scale Set(s) details have been successfully backed up to [$($backupFile)]" -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
        }
    }
    else
    {
        Write-Host "Skipped as -FilePath is provided" -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }
  
    
    if (-not $DryRun)
    {  
        # Here AutoRemediation switch is used as there is no need to take user input at BRS level if user has given consent to proceed with the remediation in AutoRemediation Script.
        if(-not $AutoRemediation)
        {

            Write-Host "Upgrade Policy Mode will be set as $($requiredUpgradePolicyMode) on all Virtual Machine Scale Set(s) listed for remediation." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
            if (-not $Force)
            {
                Write-Host "Do you want to set $($requiredUpgradePolicyMode) uprade policy mode for all Virtual Machine Scale Set(s)? " -ForegroundColor $([Constants]::MessageType.Warning) 
                Write-Host "Note: Please note that for Virtual machine scale sets with upgrade policy mode as Rolling, rollback using this script is not possible" -ForegroundColor $([Constants]::MessageType.Warning) 

                $userInput = Read-Host -Prompt "(Y|N)" 
                Write-Host $([Constants]::SingleDashLine)
                if($userInput -ne "Y")
                {
                    Write-Host "Upgrade policy mode will not be changed for any Virtual Machine Scale Set(s). Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
                    Write-Host $([Constants]::DoubleDashLine)
                    return
                }
                else
                {
                    Write-Host "Upgrade policy mode will be set as '$($requiredUpgradePolicyMode)' for all Virtual Machine Scale Set(s)" -ForegroundColor $([Constants]::MessageType.Update)
                    Write-Host $([Constants]::SingleDashLine)
                }
            }
            else
            {
                Write-Host "'Force' flag is provided. Upgrade policy mode will be set as '$($requiredUpgradePolicyMode)' for all Virtual Machine Scale Set(s) without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }
        }

        Write-Host "[Step 5 of 5] Configuring Upgrade policy mode $($requiredUpgradePolicyMode) for Virtual Machine Scale Set(s)"
        Write-Host $([Constants]::SingleDashLine)
        # To hold results from the remediation.
        $vmssRemediated = @()
    
        # Remediate VMSS by setting upgrade policy mode as required mode
        $vmssWithoutRequiredUpgradePolicyMode | ForEach-Object {
            $vmss = $_
            $name = $_.Name;
            $resourceGroupName = $_.ResourceGroupName; 
            $upgradePolicyModeBeforeRemed = $_.UpgradePolicyMode;

            # Holds the list of Virtual machine scale sets where Upgrade policy mode change is skipped
            $vmssSkipped = @()
            try
            {   
                Write-Host "Setting Upgrade policy mode as $($requiredUpgradePolicyMode) for Virtual Machine Scale Set : [$name]." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
                $vmssResponse = Update-AzVmss -UpgradePolicyMode $requiredUpgradePolicyMode -ResourceGroupName $resourceGroupName -VMScaleSetName $name

                if ($vmssResponse.UpgradePolicy.Mode -ne $requiredUpgradePolicyMode)
                {
                    $vmssSkipped += $vmss
                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                    $logResource.Add("ResourceName",($_.Name))
                    $logResource.Add("Reason", "Error while setting Upgrade policy mode for Virtual Machine Scale Set")
                    $logSkippedResources += $logResource    
                }
                else
                {
                    $vmssRemediated += $vmss | Select-Object @{N='Name';E={$name}},
                                                                        @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                        @{N='UpgradePolicyModeBeforeRemediation';E={$upgradePolicyModeBeforeRemed}},
                                                                        @{N='UpgradePolicyModeAfterRemediation';E={$vmssResponse.UpgradePolicy.Mode}}

                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                    $logResource.Add("ResourceName",($_.name))
                    $logRemediatedResources += $logResource
 
                }
            }
            catch
            {
                $vmssSkipped += $vmss
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                $logResource.Add("ResourceName",($_.name))
                $logResource.Add("Reason", "Error while setting upgrade policy mode for Virtual Machine Scale Set")
                $logSkippedResources += $logResource 
            }
        }

        $totalRemediatedVMSS = ($vmssRemediated | Measure-Object).Count
         

        if ($totalRemediatedVMSS -eq ($vmssWithoutRequiredUpgradePolicyMode | Measure-Object).Count)
        {
            Write-Host "Upgrade policy mode changed to [$($requiredUpgradePolicyMode)] for all [$($totalVMSSWithoutRequiredUpgradePolicyMode)] Virtual machine scale set(s) ." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
        }
        else
        {
            Write-Host "Upgrade policy mode changed to [$($requiredUpgradePolicyMode)] for [$($totalRemediatedVMSS)] out of [$($totalVMSSWithoutRequiredUpgradePolicyMode)] Virtual machine scale set(s)" -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
        }

        $colsProperty = @{Expression={$_.Name};Label="Name";Width=20;Alignment="left"},
                        @{Expression={$_.ResourceGroupName};Label="Resource Group";Width=20;Alignment="left"},
                        @{Expression={$_.UpgradePolicyModeBeforeRemediation};Label="Upgrade Policy Mode(Before Remediation)";Width=20;Alignment="left"},
                        @{Expression={$_.UpgradePolicyModeAfterRemediation};Label="Upgrade Policy Mode(After Remediation)";Width=20;Alignment="left"}
  
        if($AutoRemediation)
        {
            if ($($vmssRemediated | Measure-Object).Count -gt 0)
            {
                # Write this to a file.
                $vmssRemediatedFile = "$($backupFolderPath)\RemediatedVMSSUpgradePolicyMode.csv"
                $vmssRemediated| Export-CSV -Path $vmssRemediatedFile -NoTypeInformation
                Write-Host "The information related to Virtual Machine Scale Set(s) where upgrade policy mode is successfully updated has been saved to [$($vmssRemediatedFile)]. Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }

            if ($($vmssSkipped | Measure-Object).Count -gt 0)
            {   
                # Write this to a file.
                $vmssSkippedFile = "$($backupFolderPath)\SkippedVMSSUpgradePolicyMode.csv"
                $vmssSkipped | Export-CSV -Path $vmssSkippedFile -NoTypeInformation
                Write-Host "The information related to Virtual Machine Scale Set(s) where upgrade policy mode is not set as [$($requiredUpgradePolicyMode)] has been saved to [$($vmssSkippedFile)]." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }
        }
        else
        {
            Write-Host "Remediation Summary:" -ForegroundColor $([Constants]::MessageType.Info)
        
            if ($($vmssRemediated | Measure-Object).Count -gt 0)
            {
                Write-Host "Successfully set upgrade policy mode to '$($requiredUpgradePolicyMode)' on the following Virtual machine scale set(s) in the subscription:" -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
                $vmssRemediated | Format-Table -Property $colsProperty -Wrap

                # Write this to a file.
                $vmssRemediatedFile = "$($backupFolderPath)\RemediatedVMSSUpgradePolicyMode.csv"
                $vmssRemediated| Export-CSV -Path $vmssRemediatedFile -NoTypeInformation
                Write-Host $([Constants]::SingleDashLine)
                Write-Host "This information has been saved to [$($vmssRemediatedFile)]"
                Write-Host $([Constants]::SingleDashLine)
                Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Info)
                Write-Host $([Constants]::SingleDashLine)
            }

            if ($($vmssSkipped | Measure-Object).Count -gt 0)
            {
                Write-Host "Error changing upgrade policy mode for following Virtual machine scale set(s):" -ForegroundColor $([Constants]::MessageType.Error)
                $vmssSkipped | Format-Table -Property $colsProperty -Wrap
                Write-Host $([Constants]::SingleDashLine)
                # Write this to a file.
                $vmssSkippedFile = "$($backupFolderPath)\SkippedVMSSUpgradePolicyMode.csv"
                $vmssSkipped | Export-CSV -Path $vmssSkippedFile -NoTypeInformation
                Write-Host $([Constants]::SingleDashLine)
                Write-Host "This information has been saved to [$($vmssSkippedFile)]"
                Write-Host $([Constants]::SingleDashLine)
            }
        }

        if($AutoRemediation)
        {
            $logFile = "LogFiles\"+ $($TimeStamp) + "\log_" + $($SubscriptionId) +".json"
            $log =  Get-content -Raw -path $logFile | ConvertFrom-Json
            foreach($logControl in $log.ControlList){
                if($logControl.ControlId -eq $controlIds){
                    $logControl.RemediatedResources=$logRemediatedResources
                    $logControl.SkippedResources=$logSkippedResources 
                    $logControl.RollbackFile = $vmssRemediatedFile
                }
            }
            
            $log | ConvertTo-json -depth 10  | Out-File $logFile
        }
    }
    else
    {
        Write-Host "[Step 5 of 5] Setting '$($requiredUpgradePolicyMode)' upgrade policy mode for Virtual machine scale sets(s)"
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Skipped as -DryRun switch is provided." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)

        Write-Host "Next steps: " -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Run the same command with -FilePath $($backupFile) and without -DryRun, to configure uprade policy mode for all Virtual machine scale set(s) listed in the file." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
    }   
}

function Reset-UpgradePolicyMode
{
     <#
        .SYNOPSIS
        Rolls back remediation done for 'Azure_VirtualMachineScaleSet_SI_Enforce_Automatic_Upgrade_Policy' Control.

        .DESCRIPTION
        Rolls back remediation done for 'Azure_VirtualMachineScaleSet_SI_Enforce_Automatic_Upgrade_Policy' Control.
        Resets Upgrade policy mode for all Virtual machine scale sets in the Subscription. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that was previously remediated.
        
        .PARAMETER Force
        Specifies a forceful roll back without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
        
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the roll back.

        .INPUTS
        None. You cannot pipe objects to Reset-UpgradePolicyMode.

        .OUTPUTS
        None. Reset-UpgradePolicyMode does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Reset-UpgradePolicyMode -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\VMSSUpgradePolicyMode\RemediatedVMSS.csv

        .EXAMPLE
        PS> Reset-UpgradePolicyMode -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\VMSSUpgradePolicyMode\RemediatedVMSS.csv

        .LINK
        None
    #>

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

    Write-Host $([Constants]::DoubleDashLine)
    if ($PerformPreReqCheck)
    {
        try
        {
            Write-Host "[Step 1 of 4] Validate and install the modules required to run the script and validate the user"
            Write-Host $([Constants]::SingleDashLine)
            Write-Host "Setting up prerequisites..." -ForegroundColor $([Constants]::MessageType.Info)	
            Write-Host $([Constants]::SingleDashLine)
            Setup-Prerequisites
            Write-Host "Completed setting up prerequisites"	
            Write-Host $([Constants]::SingleDashLine)
        }
        catch
        {
            Write-Host "Error occurred while setting up prerequisites. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::DoubleDashLine)	
            return
        }
    }
    else
    {
        Write-Host "[Step 1 of 4] Validate the user" 
        Write-Host $([Constants]::SingleDashLine) 
    }  

    # Connect to Azure account
    $context = Get-AzContext

    if ([String]::IsNullOrWhiteSpace($context))
    {
        
        Write-Host "Connecting to Azure account..."
        Write-Host $([Constants]::SingleDashLine)
        Connect-AzAccount -Subscription $SubscriptionId -ErrorAction Stop | Out-Null
        Write-Host "Connected to Azure account." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }
    else
    {
        # Setting up context for the current Subscription.
        $context = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop
    }

    
    Write-Host "Subscription Name: [$($context.Subscription.Name)]"
    Write-Host "Subscription ID: [$($context.Subscription.SubscriptionId)]"
    Write-Host "Account Name: [$($context.Account.Id)]"
    Write-Host "Account Type: [$($context.Account.Type)]"
    Write-Host $([Constants]::SingleDashLine)

    # Note about the required access required for remediation

    Write-Host "To reset upgrade policy mode for Virtual machine scale set(s) in a Subscription, Contributor or higher privileges on the Virtual machine scale set(s) are required." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "[Step 2 of 4] Preparing to fetch Virtual machine scale set(s)"
    Write-Host $([Constants]::SingleDashLine)
    if (-not (Test-Path -Path $FilePath))
    {
        Write-Host "Input file - [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        Write-Host $([Constants]::DoubleDashLine)
        return
    }

    Write-Host "Fetching all Virtual machine scale set(s) from [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
       
    $vmssFromFile = Import-Csv -LiteralPath $FilePath
    $validVMSS = $vmssFromFile | Where-Object { ![String]::IsNullOrWhiteSpace($_.Name) }
    
    $vmss = @()
    $vmssList = @()
    $requiredUpgradePolicyMode = "Automatic"
    $applicableOrchestrationMode = "Uniform"


    $validVMSS | ForEach-Object {
        $vmssres = $_
        $Name = $_.Name
        $resourceGroupName = $_.ResourceGroupName
        $upgradePolicyModeBeforeRemediation = $_.UpgradePolicyModeBeforeRemediation
        $upgradePolicyModeAfterRemediation = $_.UpgradePolicyModeAfterRemediation

        try
        {
            $vmssList = ( Get-AzVMSS -VMScaleSetName $Name  -ResourceGroupName $resourceGroupName -ErrorAction SilentlyContinue) 
            $vmss += $vmssList | Select-Object @{N='Name';E={$name}},
                                                            @{N='ResourceGroupName';E={$resourceGroupName}},
                                                            @{N='CurrentUpgradePolicyMode';E={$_.UpgradePolicy.Mode}},
                                                            @{N='PreviousUpgradePolicyMode';E={$upgradePolicyModeBeforeRemediation}}
                                                                
        }
        catch
        {
            Write-Host "Error fetching Virtual machine scale set : [$($serverName)]. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host "Skipping this Virtual machine scale set..." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
        }
    }
        
    # Includes Virtual machine scale sets
    $vmssWithoutRequiredUpgradePolicyMode = @()
 
    Write-Host "[Step 3 of 4] Fetching Virtual machine scale sets"
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Separating Virtual machine scale sets where upgrade policy mode is not $($requiredUpgradePolicyMode)..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    $vmss | ForEach-Object {
        $res = $_        
            if(($res.CurrentUpgradePolicyMode -ne $upgradePolicyModeBeforeRemediation) -and ($res.CurrentUpgradePolicyMode -ne "Rolling"))
            {
                $vmssWithoutRequiredUpgradePolicyMode += $res
            }
            else
            {
                Write-Host "Skipping Virtual machine scale set $($res.Name)..." -ForegroundColor $([Constants]::MessageType.Warning)
            }
    }

    $totalVmssWithoutRequiredUpgradePolicyMode = ($vmssWithoutRequiredUpgradePolicyMode | Measure-Object).Count
     
    if ($totalVmssWithoutRequiredUpgradePolicyMode  -eq 0)
    {
        Write-Host "No Virtual machine scale sets found where Upgrade policy mode need to be changed.. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)
        return
    }
    
    Write-Host "Found [$($totalVmssWithoutRequiredUpgradePolicyMode)] Virtual machine scale sets " -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)	
    
     # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\ConfigureVMSSUpgradePolicyMode"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    } 
    
    if (-not $Force)
    {
        Write-Host "Do you want to reset upgrade policy mode for all Virtual machine scale set(s)?" -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
            
        $userInput = Read-Host -Prompt "(Y|N)"
        Write-Host $([Constants]::SingleDashLine)
        if($userInput -ne "Y")
        {
            Write-Host "Upgrade policy mode will not be reset for any of the Virtual machine scale set(s). Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::DoubleDashLine)
            return
        }
    }
    else
    {
        Write-Host "'Force' flag is provided. Upgrade policy mode will be reset for all of the Virtual machine scale set(s) without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
        Write-Host $([Constants]::SingleDashLine)
    }
 
    Write-Host "[Step 4 of 4] Resetting Upgrade policy mode for Virtual machine scale set(s)"
    Write-Host $([Constants]::SingleDashLine)
    # Includes Virtual machine scale set(s), to which, previously made changes were successfully rolled back.
    $vmssRolledBack = @()

    # Includes Virtual machine scale set(s) that were skipped during roll back. There were errors rolling back the changes made previously.
    $vmssSkipped = @()

   
     # Roll back by resetting Upgrade policy mode 
        $vmssWithoutRequiredUpgradePolicyMode | ForEach-Object {
            $res = $_
            $Name = $_.Name
            $resourceGroupName = $_.ResourceGroupName
            $currentUpgradePolicyMode = $_.CurrentUpgradePolicyMode
            $previousUpgradePolicyMode = $_.PreviousUpgradePolicyMode
           
            try
            {  
                
                Write-Host "Resetting Upgrade policy mode for Virtual machine scale set : [$Name]" -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)

                $vmssResponse = Update-AzVmss -UpgradePolicyMode $previousUpgradePolicyMode -ResourceGroupName $resourceGroupName -VMScaleSetName $name

                if ($vmssResponse.UpgradePolicy.Mode -ne $previousUpgradePolicyMode)
                {
                    $vmssSkipped += $res
                       
                }
                else
                {
                    $vmssRolledBack += $res | Select-Object @{N='Name';E={$Name}},
                                                                        @{N='ResourceGroupName';E={$resourceGroupName}}, 
                                                                        @{N='UpgradePolicyModeBeforeRollback';E={$currentUpgradePolicyMode}},
                                                                        @{N='UpgradePolicyModeAfterRollback';E={$vmssResponse.UpgradePolicy.Mode}}
                }
            }
            catch
            {
                $vmssSkipped += $res
            }
       }
    
    $totalVMSSRolledBack = ($vmssRolledBack | Measure-Object).Count

    if ($totalVMSSRolledBack -eq $totalVmssWithoutRequiredUpgradePolicyMode)
    {
        Write-Host "Upgrade policy mode reset for all [$($totalVmssWithoutRequiredUpgradePolicyMode)] Virtual machine scale set(s) ." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }
    else
    {
        Write-Host "Upgrade policy mode reset for [$($totalVMSSRolledBack)] out of [$($totalVmssWithoutRequiredUpgradePolicyMode)] Virtual machine scale sets(s)" -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }
    
    Write-Host "Rollback Summary:" -ForegroundColor $([Constants]::MessageType.Info)
    
    $colsProperty = @{Expression={$_.Name};Label="Name";Width=20;Alignment="left"},
                    @{Expression={$_.ResourceGroupName};Label="Resrouce Group";Width=20;Alignment="left"},
                    @{Expression={$_.UpgradePolicyModeAfterRollback};Label="Upgrade policy mode After Rollback";Width=20;Alignment="left"},
                    @{Expression={$_.UpgradePolicyModeBeforeRollback};Label="Upgrade policy mode Before Rollback";Width=20;Alignment="left"}
        

    if ($($vmssRolledBack | Measure-Object).Count -gt 0)
    {
        Write-Host "Reset Upgrade policy mode completed for below Virtual machine scale set(s):" -ForegroundColor $([Constants]::MessageType.Update)
        $vmssRolledBack | Format-Table -Property $colsProperty -Wrap
        Write-Host $([Constants]::SingleDashLine)

        # Write this to a file.
        $vmssRolledBackFile = "$($backupFolderPath)\RolledBackVMSS.csv"
        $vmssRolledBack| Export-CSV -Path $vmssRolledBackFile -NoTypeInformation
        Write-Host "This information has been saved to [$($vmssRolledBackFile)]"
        Write-Host $([Constants]::SingleDashLine)
    }

    if ($($vmssSkipped | Measure-Object).Count -gt 0)
    {
        Write-Host "Error resetting Upgrade policy mode for following Virtual machine scale set(s):" -ForegroundColor $([Constants]::MessageType.Error)
        $vmssSkipped | Format-Table -Property $colsProperty -Wrap
        Write-Host $([Constants]::SingleDashLine)
        
        # Write this to a file.
        $vmssSkippedFile = "$($backupFolderPath)\RollbackSkippedVMSS.csv"
        $vmssSkipped | Export-CSV -Path $vmssSkippedFile -NoTypeInformation
        Write-Host "This information has been saved to [$($vmssSkippedFile)]"
        Write-Host $([Constants]::SingleDashLine)
    }   
   
}

# Defines commonly used constants.
class Constants
{
    
    # Defines commonly used colour codes, corresponding to the severity of the log.
    static [Hashtable] $MessageType = @{
        Error = [System.ConsoleColor]::Red
        Warning = [System.ConsoleColor]::Yellow
        Info = [System.ConsoleColor]::Cyan
        Update = [System.ConsoleColor]::Green
        Default = [System.ConsoleColor]::White
    }

    static [String] $DoubleDashLine = "========================================================================================================================"
    static [String] $SingleDashLine = "------------------------------------------------------------------------------------------------------------------------"
}