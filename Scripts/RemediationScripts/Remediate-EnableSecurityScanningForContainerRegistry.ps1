<###
# Overview:
    This script is used to grant access to security scanner identity for image scans on Container Registry in a Subscription.

# Control ID:
    Azure_ContainerRegistry_Config_Enable_Security_Scanning

# Display Name:
    Security scanner identity must be granted access to Container Registry for image scans.

# Prerequisites:
    Reader or higher priviliged role on the subscription is required to fetch role assignment details.
    Owner or higher priviliged role on the Container Registry(s) is required for remediation.

# Steps performed by the script:
    To remediate:
        1. Validating and installing the modules required to run the script and validating the user.
        2. Get the list of Container Registry(s) in a Subscription that do not have access to security scanner identity for image scan.
        3. Back up details of Container Registry(s) that are to be remediated.
        4. Grant access to security scanner identity for image scans on Container Registry(s) in the Subscription.

    To roll back:
        1. Validate and install the modules required to run the script and validating the user.
        2. Get the list of Container Registry(s) in a Subscription, the changes made to which previously, are to be rolled back.
        3. Remove access to security scanner identity on all Container Registry(s) in the Subscription.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to grant access to security scanner identity for image scans on Container Registry(s) in the Subscription. Refer `Examples`, below.

    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to remove access to security scanner identity on all Container Registry(s) in the Subscription. Refer `Examples`, below.

# Examples:
    To remediate:
        1. To review the Container Registry(s) in a Subscription that will be remediated:
    
           Enable-SecurityScanningIdentityForContainerRegistry -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -ObjectId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        2. To grant access to security scanner identity for image scans on Container Registry(s) in the Subscription:
       
           Enable-SecurityScanningIdentityForContainerRegistry -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -ObjectId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        3. To grant access to security scanner identity for image scans on Container Registry(s) in the Subscription, from a previously taken snapshot:
       
           Enable-SecurityScanningIdentityForContainerRegistry -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -ObjectId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\EnableSecurityScanningIdentityForContainerRegistry\ContainerRegistryWithoutSecurityScanningEnabled.csv

        To know more about the options supported by the remediation command, execute:
        
        Get-Help Enable-SecurityScanningIdentityForContainerRegistry -Detailed

    To roll back:
        1. To remove access from security scanner identity for image scans on Container Registry(s) in the Subscription, from a previously taken snapshot:
           Disable-SecurityScanningIdentityForContainerRegistry -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\EnableSecurityScanningIdentityForContainerRegistry\RemediatedContainerRegistry.csv
       
        To know more about the options supported by the roll back command, execute:
        
        Get-Help Disable-SecurityScanningIdentityForContainerRegistry -Detailed        
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
    $requiredModules = @("Az.Accounts", "Az.Resources")

    Write-Host "Required modules: $($requiredModules -join ', ')"
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Checking if the required modules are present..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

    $availableModules = $(Get-Module -ListAvailable $requiredModules -ErrorAction Stop)

    # Check if the required modules are installed.
    $requiredModules | ForEach-Object {
        if ($availableModules.Name -notcontains $_)
        {
            Write-Host "$($_) module is not present." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host "Installing $($_) module..." -ForegroundColor $([Constants]::MessageType.Info)
            Install-Module -Name $_ -Scope CurrentUser -Repository 'PSGallery' -ErrorAction Stop
            Write-Host "$($_) module installed." -ForegroundColor $([Constants]::MessageType.Update)
        }
        else
        {
            Write-Host "$($_) module is present." -ForegroundColor $([Constants]::MessageType.Update)
        }
    }
    Write-Host $([Constants]::SingleDashLine)
}


function Enable-SecurityScanningIdentityForContainerRegistry
{
    <#
        .SYNOPSIS
        Remediates 'Azure_ContainerRegistry_Config_Enable_Security_Scanning' Control.

        .DESCRIPTION
        Remediates 'Azure_ContainerRegistry_Config_Enable_Security_Scanning' Control.
        Grant access to security scanner identity for image scans on Container Registry(s) in the Subscription. 
        
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

        .PARAMETER Path
        Specifies the path to the file to be used as input for the remediation when AutoRemediation switch is used.

        .PARAMETER AutoRemediation
        Specifies script is run as a subroutine of AutoRemediation Script.

        .PARAMETER TimeStamp
        Specifies the time of creation of file to be used for logging remediation details when AutoRemediation switch is used.

        .INPUTS
        None. You cannot pipe objects to Enable-SecurityScanningIdentityForContainerRegistry.

        .OUTPUTS
        None. Enable-SecurityScanningIdentityForContainerRegistry does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Enable-SecurityScanningIdentityForContainerRegistry -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -ObjectId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Enable-SecurityScanningIdentityForContainerRegistry -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -ObjectId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        .EXAMPLE
        PS> Enable-SecurityScanningIdentityForContainerRegistry -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -ObjectId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\EnableSecurityScanningIdentityForContainerRegistry\ContainerRegistryWithoutSecurityScanningEnabled.csv

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

        [String]
        [Parameter(ParameterSetName = "DryRun", Mandatory = $true, HelpMessage="Specifies the Object Id of the AAD Identity to be assigned as a reader role")]
        [Parameter(ParameterSetName = "WetRun", Mandatory = $true, HelpMessage="Specifies the Object Id of the AAD Identity to be assigned as a reader role")]
        $ObjectId,

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
            Write-Host "[Step 1 of 3] Validating and installing the modules required to run the script and validating the user"
            Write-Host $([Constants]::SingleDashLine)
            Write-Host "Setting up prerequisites..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            Setup-Prerequisites
            Write-Host "Completed setting up prerequisites." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
        }
        catch
        {
            Write-Host "Error occurred while setting up prerequisites. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::SingleDashLine)
            return
        }
    }
    else
    {
        Write-Host "[Step 1 of 3] Validating the user" 
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

    Write-Host "Checking if [$($context.Account.Id)] is allowed to run this script..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

	
    $currentLoginRoleAssignments = Get-AzRoleAssignment -SignInName $context.Account.Id

    if(($currentLoginRoleAssignments | Where-Object { $_.Scope -like "/providers/Microsoft.Management/managementGroups*" -or $_.Scope -eq "/subscriptions/$($SubscriptionId)"}| Measure-Object).Count -eq 0 )
    {
        Write-Host "Current $($context.Account.Type) [$($context.Account.Id)] does not have required permissions. At least Reader or higher priviliged role on the subscription is required to fetch role assignment details." -ForegroundColor $([Constants]::MessageType.Error)
        Write-Host $([Constants]::SingleDashLine)
        return;
    }
    else
    {
        Write-Host "Current $($context.Account.Type) [$($context.Account.Id)] has the required role on subscription [$($SubscriptionId)]." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }

   
    Write-Host "[Step 2 of 4] Fetch all Container Registry(s)"
    Write-Host $([Constants]::SingleDashLine)
    
    # list to store Container details.
    $containerRegistryDetails = @()

    # To keep track of remediated and skipped resources
    $logRemediatedResources = @()
    $logSkippedResources=@()

    # Control Id
    $controlIds = "Azure_ContainerRegistry_Config_Enable_Security_Scanning"

    if($AutoRemediation)
    {
        if(-not (Test-Path -Path $Path))
        {
            Write-Host "Error: File containing failing controls details [$($Path)] not found. Skipping remediation..." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::SingleDashLine)
            return
        }
        Write-Host "Fetching all Container Registry(s) failing for the [$($controlIds)] control from [$($Path)]..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        $controlForRemediation = Get-content -path $Path | ConvertFrom-Json
        $controls = $controlForRemediation.ControlRemediationList
        $resourceDetails = $controls | Where-Object { $controlIds -eq $_.ControlId };
        $validResources = $resourceDetails.FailedResourceList | Where-Object {![String]::IsNullOrWhiteSpace($_.ResourceId)}
        if(($resourceDetails | Measure-Object).Count -eq 0 -or ($validResources | Measure-Object).Count -eq 0)
        {
            Write-Host "No Container Registry(s) found in input json file for remediation." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::SingleDashLine)
            return
        }
        $validResources | ForEach-Object { 
            try
            {
                $containerRegistryResource =  Get-AzResource -ResourceType Microsoft.ContainerRegistry/registries -ResourceGroupName $_.ResourceGroupName -Name $_.ResourceName -ErrorAction SilentlyContinue
                $containerRegistryDetails += $containerRegistryResource  | Select-Object @{N='ResourceId';E={$_.ResourceId}},
                                                                            @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                            @{N='ResourceName';E={$_.ResourceName}},
                                                                            @{N='ObjectId';E={$ObjectId}}
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
                return
            }
        }
    }
    else {
        # No file path provided as input to the script. Fetch all Container Registry(s) in the Subscription.
        if ([String]::IsNullOrWhiteSpace($FilePath))
        {
            Write-Host "Fetching all Container Registry(s) in Subscription: [$($context.Subscription.SubscriptionId)]..." -ForegroundColor $([Constants]::MessageType.Info)

            # Get all Container Registry(s) in a Subscription
            $containerRegistryDetails =  Get-AzResource -ResourceType Microsoft.ContainerRegistry/registries -ErrorAction Stop

            # Seperating required properties
            $containerRegistryDetails = $containerRegistryDetails | Select-Object @{N='ResourceId';E={$_.ResourceId}},
                                                                            @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                            @{N='ResourceName';E={$_.Name}},
                                                                            @{N='ObjectId';E={$ObjectId}}
        }
        else
        {
            if (-not (Test-Path -Path $FilePath))
            {
                Write-Host "Input file: [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host $([Constants]::SingleDashLine)
                return
            }

            Write-Host "Fetching all Container Registry(s) from [$($FilePath)]..." 
            Write-Host $([Constants]::SingleDashLine)
            $containerRegistryResources = Import-Csv -LiteralPath $FilePath
            $validcontainerRegistryResources = $containerRegistryResources| Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) }
            
            $validcontainerRegistryResources| ForEach-Object {
                $resourceId = $_.ResourceId

                try
                {
                    $containerRegistryResource =  Get-AzResource -ResourceType Microsoft.ContainerRegistry/registries -ResourceGroupName $_.ResourceGroupName -Name $_.ResourceName -ErrorAction SilentlyContinue
                    
                    $containerRegistryDetails += $containerRegistryResource  | Select-Object @{N='ResourceId';E={$_.ResourceId}},
                                                                            @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                            @{N='ResourceName';E={$_.Name}},
                                                                            @{N='ObjectId';E={$ObjectId}}
                }
                catch
                {
                    Write-Host "Error while fetching Container Registry(s) resource: Resource ID: [$($resourceId)]. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                    Write-Host "Skipping this Container Registry..." -ForegroundColor $([Constants]::MessageType.Warning)
                    Write-Host $([Constants]::SingleDashLine)
                }
            }
        }
    }

    $totalContainerRegistry = ($containerRegistryDetails| Measure-Object).Count

    if ($totalContainerRegistry -eq 0)
    {
        Write-Host "No Container Registry(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
        return
    }
  
    Write-Host "Found [$($totalContainerRegistry)] Container Registry(s)." -ForegroundColor $([Constants]::MessageType.Update)                                                         
    Write-Host $([Constants]::SingleDashLine)

    # List for storing role assignment details.
    $roleAssignmentDetails = @()

    # List for storing sub level secuirty scanning identity role assignment details.
    $subLevelRoleAssignmentDetails = @()

    Write-Host "Fetching role assignments of central security scanner identity..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

    try
    {
        # Fetching central role assignment.
        $centralReaderAccounts = Get-AzRoleAssignment -ObjectId $ObjectId  -RoleDefinitionName "Reader" -ErrorAction Stop
        Write-Host "Successfully fetched role assignments of central security scanner identity." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }
    catch
    {
        Write-Host "Error occured while fetching security scanning role assignment(s). Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        Write-Host $([Constants]::SingleDashLine)
        $containerRegistryDetails | ForEach-Object
        {
            $logResource = @{}
            $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
            $logResource.Add("ResourceName",($_.ResourceName))
            $logResource.Add("Reason","Error occured while fetching security scanning role assignment(s)")    
            $logSkippedResources += $logResource
            Write-Host $([Constants]::SingleDashLine)
        }
        if($AutoRemediation) 
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
        return;
    }

    if((($centralReaderAccounts| Measure-Object).Count) -eq 0)
    {
        Write-Host "No central security scanner role assignment found." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }
    else
    {
        Write-Host "Found [$(($centralReaderAccounts| Measure-Object).Count)] central security scanner role assignment(s)." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }
   
    # list for storing Container Registry(s) for which central security scanner role is not assigned.
    $containerRegistryWithoutSecurityScanningEnabled = @()
    #$containerRegidstryWithSecurityScanningEnabled = @()

    Write-Host "Separating Container Registry(s) for which access is not granted to security scanner identity..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

    #seperating the sub level role assignments.
    $subLevelRoleAssignmentDetails = $centralReaderAccounts | Where-Object {$_.Scope -eq "/subscriptions/$($SubscriptionId)"}

    if(($subLevelRoleAssignmentDetails| Measure-Object).Count -eq 0)
    {
        $containerRegistryDetails | ForEach-Object {
            $containerRegistry = $_
            $CentralReaderAccount = $centralReaderAccounts | Where-Object {$_.Scope -eq $containerRegistry.ResourceId -or(($_.Scope).Split('/').Count -eq 5 -and ($_.Scope).Split('/')[4] -eq $containerRegistry.ResourceGroupName -and $_.Scope -notlike "/providers/Microsoft.Management/managementGroups*")}

            if(($centralReaderAccount | Measure-Object).count -eq 0)
            {
                $containerRegistryWithoutSecurityScanningEnabled += $containerRegistry
            }
            else 
            {
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                $logResource.Add("ResourceName",($_.ResourceName))
                $logResource.Add("Reason","Security Scanning is enabled for the Container Registry.")    
                $logSkippedResources += $logResource
            }
        }        
    }
   
    $totalContainerRegistryWithoutSecurityScanningEnabled  = ($containerRegistryWithoutSecurityScanningEnabled | Measure-Object).Count

    if ($totalContainerRegistryWithoutSecurityScanningEnabled  -eq 0)
    {
        Write-Host "No Container Registry(s) found for granting access to security scanner identity for image scans. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
        if($AutoRemediation -and $totalContainerRegistry -gt 0)
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

    Write-Host "Found [$($totalContainerRegistryWithoutSecurityScanningEnabled)] Container Registry(s) for which access is not granted to security scanner identity." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)
    $colsProperty = @{Expression={$_.ResourceName};Label="ResourceName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceGroupName};Label="ResourceGroupName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceId};Label="ResourceId";Width=100;Alignment="left"}
        
    if(-not $AutoRemediation)
    {
        Write-Host "Container Registry(s) without security scanning enabled is as follows:"
        $containerRegistryWithoutSecurityScanningEnabled | Format-Table -Property $colsProperty -Wrap
        Write-Host $([Constants]::SingleDashLine)
    }

    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\EnableSecurityScanningIdentityForContainerRegistry"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
    Write-Host "[Step 3 of 4] Back up Container Registry(s) details"
    Write-Host $([Constants]::SingleDashLine)

    if ([String]::IsNullOrWhiteSpace($FilePath))
    {     
        # Backing up Container Registry(s) details.
        $backupFile = "$($backupFolderPath)\ContainerRegistryWithoutSecurityScanningEnabled.csv"

        $containerRegistryWithoutSecurityScanningEnabled | Export-CSV -Path $backupFile -NoTypeInformation

        Write-Host "Container Registry(s) details have been backed up to" -NoNewline
        Write-Host " [$($backupFile)]" -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }
    else
    {
        Write-Host "Skipped as -FilePath is provided." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }

    if (-not $DryRun)
    {
        Write-Host "[Step 4 of 4] Grant access to security scanner identity for image scans on Container Registry(s) in the Subscription." 
        Write-Host $([Constants]::SingleDashLine)
        
        if(-not $AutoRemediation)
        {
            if (-not $Force)
            {
                Write-Host "Do you want to grant access to security scanner identity for image scans on Container Registry(s) in the Subscription? " -ForegroundColor $([Constants]::MessageType.Warning)
                
                $userInput = Read-Host -Prompt "(Y|N)"
                Write-Host $([Constants]::SingleDashLine)
                if($userInput -ne "Y")
                {
                    Write-Host "Access is not granted to security scanner identity for image scans on Container Registry(s) in the Subscription. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
                    Write-Host $([Constants]::SingleDashLine)
                    return
                }
                Write-Host "User has provided consent to grant access to security scanner for image scans on Container Registry(s)." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
            }
            else
            {
                Write-Host "'Force' flag is provided. Access will be granted to security scanner identity for image scans on Container Registry(s) in the Subscription without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }
        }

        # List for storing remediated Container Registry(s)
        $containerRegistryRemediated = @()

        # List for storing skipped Container Registry(s)
        $containerRegistrySkipped = @()

        Write-Host "Creating role assignment with reader role for security scanner identity for image scanning on Container Registry(s)..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        # Loop through the list of Container Registry(s) which needs to be remediated.
        $containerRegistryWithoutSecurityScanningEnabled | ForEach-Object {
            $containerRegistry = $_
            try
            {
                $roleAssignment = New-AzRoleAssignment -Scope $_.ResourceId -ObjectId $ObjectId -RoleDefinitionName "Reader" 
                if($null -ne $roleAssignment)
                {
                    $containerRegistryRemediated += $containerRegistry
                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                    $logResource.Add("ResourceName",($_.ResourceName))
                    $logRemediatedResources += $logResource
                }
                else
                {
                    $containerRegistrySkipped += $containerRegistry
                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                    $logResource.Add("ResourceName",($_.ResourceName))
                    $logResource.Add("Reason","Not able to assign 'Reader' role to Security Scanner Identity over the container registry.")    
                    $logSkippedResources += $logResource
                }
            }
            catch
            {
                $containerRegistrySkipped += $containerRegistry
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                $logResource.Add("ResourceName",($_.ResourceName))
                $logResource.Add("Reason","Error encountered while assigning 'Reader' role to Security Scanner Identity over the container registry.")    
                $logSkippedResources += $logResource
            }
        }

        Write-Host $([Constants]::DoubleDashLine)
        if($AutoRemediation)
        {
            if ($($ContainerRegistryRemediated | Measure-Object).Count -gt 0)
            {
                # Write this to a file.
                $ContainerRegistryRemediatedFile = "$($backupFolderPath)\RemediatedContainerRegistry.csv"
                $ContainerRegistryRemediated | Export-CSV -Path $ContainerRegistryRemediatedFile -NoTypeInformation
                Write-Host "The container registry(s) where the access is granted to the security scanner identity is saved to [$($ContainerRegistryRemediatedFile)]." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }

            if ($($ContainerRegistrySkipped | Measure-Object).Count -gt 0)
            {
                # Write this to a file.
                $ContainerRegistrySkippedFile = "$($backupFolderPath)\SkippedContainerRegistry.csv"
                $ContainerRegistrySkipped | Export-CSV -Path $ContainerRegistrySkippedFile -NoTypeInformation
                Write-Host "The container registry(s) where the access is not granted to the security scanner identity is saved to [$($ContainerRegistrySkippedFile)]." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
            }
        }
        else
        {
            Write-Host "Remediation Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)
        
            if ($($ContainerRegistryRemediated | Measure-Object).Count -gt 0)
            {
                Write-Host "Access is successfully granted to security scanner identity for image scans on the following Container Registry(s) in the subscription:" -ForegroundColor $([Constants]::MessageType.Update)
            
                $ContainerRegistryRemediated | Format-Table -Property $colsProperty -Wrap
                Write-Host $([Constants]::SingleDashLine)
                # Write this to a file.
                $ContainerRegistryRemediatedFile = "$($backupFolderPath)\RemediatedContainerRegistry.csv"
                $ContainerRegistryRemediated | Export-CSV -Path $ContainerRegistryRemediatedFile -NoTypeInformation

                Write-Host "This information has been saved to [$($ContainerRegistryRemediatedFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
                Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }

            if ($($ContainerRegistrySkipped | Measure-Object).Count -gt 0)
            {
                Write-Host "Error granting access to security scanner identity for image scans on the following Container Registry(s)in the subscription:" -ForegroundColor $([Constants]::MessageType.Error)
                $ContainerRegistrySkipped | Format-Table -Property $colsProperty -Wrap
                Write-Host $([Constants]::SingleDashLine)
                # Write this to a file.
                $ContainerRegistrySkippedFile = "$($backupFolderPath)\SkippedContainerRegistry.csv"
                $ContainerRegistrySkipped | Export-CSV -Path $ContainerRegistrySkippedFile -NoTypeInformation
                Write-Host "This information has been saved to [$($ContainerRegistrySkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
            }
        }
    }
    else
    {
        Write-Host "[Step 4 of 4] Grant access to security scanner identity for image scans on Container Registry(s) in the Subscription"
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Skipped as -DryRun switch is provided." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)

        Write-Host "Next steps:" -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host "Run the same command with -FilePath $($backupFile) and without -DryRun, to grant access to security scanner identity for image scans on Container Registry(s) listed in the file." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }
}

function Disable-SecurityScanningIdentityForContainerRegistry
{
    <#
        .SYNOPSIS
        Rolls back remediation done for 'Azure_ContainerRegistry_Config_Enable_Security_Scanning' Control.

        .DESCRIPTION
        Rolls back remediation done for 'Azure_ContainerRegistry_Config_Enable_Security_Scanning' Control.
        Remove access to security scanner identity for image scans on Container Registry(s) in the Subscription. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that was previously remediated.
        
        .PARAMETER Force
        Specifies a forceful roll back without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.

        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the roll back.

        .INPUTS
        None. You cannot pipe objects to Disable-SecurityScanningIdentityForContainerRegistry.

        .OUTPUTS
        None. Disable-SecurityScanningIdentityForContainerRegistry does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Disable-SecurityScanningIdentityForContainerRegistry -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\EnableSecurityScanningIdentityForContainerRegistry\RemediatedContainerRegistry.csv

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

    if ($PerformPreReqCheck)
    {
        try
        {
            Write-Host "[Step 1 of 3] Validating and installing the modules required to run the script and validating the user"
            Write-Host $([Constants]::SingleDashLine)
            Write-Host "Setting up prerequisites..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            Setup-Prerequisites
            Write-Host "Completed setting up prerequisites." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
        }
        catch
        {
            Write-Host "Error occurred while setting up prerequisites. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::SingleDashLine)
            return
        }
    }
    else
    {
        Write-Host "[Step 1 of 3] Validating the user" 
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
    
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Subscription Name: [$($context.Subscription.Name)]"
    Write-Host "Subscription ID: [$($context.Subscription.SubscriptionId)]"
    Write-Host "Account Name: [$($context.Account.Id)]"
    Write-Host "Account Type: [$($context.Account.Type)]"
    Write-Host $([Constants]::SingleDashLine)

    Write-Host "Checking if [$($context.Account.Id)] is allowed to run this script..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

    $currentLoginRoleAssignments = Get-AzRoleAssignment -SignInName $context.Account.Id

    if(($currentLoginRoleAssignments | Where-Object { $_.Scope -like "/providers/Microsoft.Management/managementGroups*" -or $_.Scope -eq "/subscriptions/$($SubscriptionId)"}| Measure-Object).Count -eq 0 )
    {
        Write-Host "Current $($context.Account.Type) [$($context.Account.Id)] does not have required permissions. At least Reader or higher priviliged role on the subscription is required to fetch role assignment details." -ForegroundColor $([Constants]::MessageType.Error)
        Write-Host $([Constants]::SingleDashLine)
        return;
    }
    else
    {
        Write-Host "Current $($context.Account.Type) [$($context.Account.Id)] has the required role on subscription [$($SubscriptionId)]." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }

    Write-Host "[Step 2 of 3] Fetch all Container Registry(s)"
    Write-Host $([Constants]::SingleDashLine)
    
    if (-not (Test-Path -Path $FilePath))
    {
        Write-Host "Input file: [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        Write-Host $([Constants]::SingleDashLine)
        return
    }

    Write-Host "Fetching all Container Registry(s) from [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)
    $containerRegistryDetails = Import-Csv -LiteralPath $FilePath

    $validcontainerRegistryDetails = $containerRegistryDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) -and ![String]::IsNullOrWhiteSpace($_.ResourceGroupName) -and ![String]::IsNullOrWhiteSpace($_.ResourceName) }

    $totalContainerRegistry = $(($validcontainerRegistryDetails|Measure-Object).Count)

    if ($totalContainerRegistry -eq 0)
    {
        Write-Host "No Container Registry(s) found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        return
    }

    Write-Host "Found [$(($validcontainerRegistryDetails|Measure-Object).Count)] Container Registry(s)." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)

    $colsProperty = @{Expression={$_.ResourceName};Label="ResourceName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceGroupName};Label="ResourceGroupName";Width=30;Alignment="left"},
                    @{Expression={$_.ResourceId};Label="ResourceId";Width=100;Alignment="left"}
    
    Write-Host "The Container Registry(s) are as follows:"
    $validcontainerRegistryDetails | Format-Table -Property $colsProperty -Wrap
    Write-Host $([Constants]::SingleDashLine)
    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\DisableSecurityScanningIdentityForContainerRegistry"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
 
    Write-Host "[Step 3 of 3] Remove access to security scanner identity on all Container Registry(s) in the Subscription"
    Write-Host $([Constants]::SingleDashLine)

    if( -not $Force)
    {
        
        Write-Host "Do you want to remove access for security scanner identity on all Container Registry(s) mentioned in the file? "  -ForegroundColor $([Constants]::MessageType.Warning)
        $userInput = Read-Host -Prompt "(Y|N)"
        Write-Host $([Constants]::SingleDashLine)
        if($userInput -ne "Y")
        {
            Write-Host "User has not provided consent to remove security scanner identity access for image scans on Container Registry(s) in the Subscription. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
            return
        }

        Write-Host "User has provided consent to remove access for security scanner identity for image scans on Container Registry(s) in the Subscription." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }
    else
    {
        Write-Host "'Force' flag is provided. Access will be removed from security scanner identity for image scans on Container Registry(s) in the Subscription without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }

    # List for storing rolled back Container Registry resource.
    $ContainerRegistryRolledBack = @()

    # List for storing skipped rolled back Container Registry resource.
    $ContainerRegistrySkipped = @()

    $validcontainerRegistryDetails | ForEach-Object {
        $containerRegistry = $_
        try
        {
            Remove-AzRoleAssignment -Scope $_.ResourceId -ObjectId $_.ObjectId  -RoleDefinitionName "Reader" 
            $RoleAssignment = Get-AzRoleAssignment -Scope $_.ResourceId -ObjectId $_.ObjectId -RoleDefinitionName "Reader"
            
            if($null -eq $RoleAssignment)
            {
                $ContainerRegistryRolledBack += $containerRegistry    
            }
            else
            {
                $containerRegistrySkipped += $containerRegistry
            }
        }
        catch
        {
            $containerRegistrySkipped += $containerRegistry
        }
    }

    if ($($ContainerRegistryRolledBack | Measure-Object).Count -gt 0 -or $($ContainerRegistrySkipped | Measure-Object).Count -gt 0)
    {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Rollback Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)
        
        if ($($ContainerRegistryRolledBack | Measure-Object).Count -gt 0)
        {
            Write-Host "Access is successfully removed for security scanner identity on following Container Registry(s) in the Subscription:" -ForegroundColor $([Constants]::MessageType.Update)
            $ContainerRegistryRolledBack | Format-Table -Property $colsProperty -Wrap
            Write-Host $([Constants]::SingleDashLine)
            # Write this to a file.
            $ContainerRegistryRolledBackFile = "$($backupFolderPath)\RolledBackContainerRegistry.csv"
            $ContainerRegistryRolledBack | Export-CSV -Path $ContainerRegistryRolledBackFile -NoTypeInformation
            Write-Host "This information has been saved to [$($ContainerRegistryRolledBackFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
            Write-Host $([Constants]::SingleDashLine)
        }

        if ($($ContainerRegistrySkipped | Measure-Object).Count -gt 0)
        {
            Write-Host "Error removing access for security scanner identity on following Container Registry(s) in the Subscription:" -ForegroundColor $([Constants]::MessageType.Error)
            $ContainerRegistrySkipped | Format-Table -Property $colsProperty -Wrap
            Write-Host $([Constants]::SingleDashLine)
            # Write this to a file.
            $ContainerRegistrySkippedFile = "$($backupFolderPath)\RollbackSkippedContainerRegistry.csv"
            $ContainerRegistrySkipped | Export-CSV -Path $ContainerRegistrySkippedFile -NoTypeInformation
            Write-Host "This information has been saved to [$($ContainerRegistrySkippedFile)]" -ForegroundColor $([Constants]::MessageType.Update) 
            Write-Host $([Constants]::SingleDashLine)
        }
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
