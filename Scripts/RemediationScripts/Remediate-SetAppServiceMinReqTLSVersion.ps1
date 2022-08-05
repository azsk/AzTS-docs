<###
# Overview:
    This script is used to set required TLS version for App Services in a Subscription.

# Control ID:
    Azure_AppService_DP_Use_Secure_TLS_Version

# Display Name:
    Use Approved TLS Version in App Service.

# Prerequisites:
    1. Contributor or higher privileges on the App Services in a Subscription.
    2. Must be connected to Azure with an authenticated account.

# Steps performed by the script:
    To remediate:
        1. Validate and install the modules required to run the script.
        2. Get the list of App Services in a Subscription that do not use the required TLS version for the production slot or for any of the non-production slots.
        3. Back up details of App Services that are to be remediated.
        4. Set the required TLS version on the production slot and all non-production slots in all App Services in the Subscription.

    To roll back:
        1. Validate and install the modules required to run the script.
        2. Get the list of App Services in a Subscription, the changes made to which previously, are to be rolled back.
        3. Set the previous TLS versions on the production slot and all non-production slots in all App Services in the Subscription.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to set the required TLS version on the production slot and all non-production slots in all App Services in the Subscription. Refer `Examples`, below.

    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to set the previous TLS versions on the production slot and all non-production slots in all App Services in the Subscription. Refer `Examples`, below.

# Examples:
    To remediate:
        1. To review the App Services in a Subscription that will be remediated:
           Set-AppServiceRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        2. To set minimum required TLS version on the production slot and all non-production slots of all App Services in a Subscription:
           Set-AppServiceRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        3. To set minimum required TLS version on the production slot and all non-production slots of all App Services in a Subscription, from a previously taken snapshot:
           Set-AppServiceRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetMinTLSVersionForAppServices\AppServicesWithoutMinReqTLSVersion.csv

        4. To set minimum required TLS version on the production slot and all non-production slots of all App Services in a Subscription without taking back up before actual remediation:
           Set-AppServiceRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -SkipBackup

        To know more about the options supported by the remediation command, execute:
        Get-Help Set-AppServiceRequiredTLSVersion -Detailed

    To roll back:
        1. To reset minimum required TLS version on the production slot and all non-production slots of all App Services in a Subscription, from a previously taken snapshot:
           Reset-AppServiceRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetMinTLSVersionForAppServices\RemediatedAppServices.csv
        
        2. To reset minimum required TLS version on the production slot of all App Services in a Subscription, from a previously taken snapshot:
           Reset-AppServiceRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -ExcludeNonProductionSlots -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetMinTLSVersionForAppServices\RemediatedAppServices.csv

        To know more about the options supported by the roll back command, execute:
        Get-Help Reset-AppServiceRequiredTLSVersion -Detailed        
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
    $requiredModules = @("Az.Accounts", "Az.Websites", "Az.Resources", "Azure")
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

function Set-AppServiceRequiredTLSVersion
{
    <#
        .SYNOPSIS
        Remediates 'Azure_AppService_DP_Use_Secure_TLS_Version' Control.

        .DESCRIPTION
        Remediates 'Azure_AppService_DP_Use_Secure_TLS_Version' Control.
        Sets the required TLS version on the production slot and all non-production slots in all App Services in the Subscription. 
        
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

        .INPUTS
        None. You cannot pipe objects to Set-AppServiceRequiredTLSVersion.

        .OUTPUTS
        None. Set-AppServiceRequiredTLSVersion does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Set-AppServiceRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Set-AppServiceRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        .EXAMPLE
        PS> Set-AppServiceRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetMinTLSVersionForAppServices\AppServicesWithoutMinReqTLSVersion.csv

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
        $Path,

        [Switch]
        $AutoRemediation,

        [String]
        $TimeStamp
    )

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 1 of 4] Preparing to set required TLS version for App Services in Subscription: [$($SubscriptionId)]"
    Write-Host $([Constants]::SingleDashLine)

    if ($PerformPreReqCheck)
    {
        try
        {
            Write-Host "Setting up prerequisites..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            Setup-Prerequisites
            Write-Host "Completed setting up prerequisites" -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
        }
        catch
        {
            Write-Host "Error occurred while setting up prerequisites. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            return
        }
    }

    # Connect to Azure account
    $context = Get-AzContext

    if ([String]::IsNullOrWhiteSpace($context))
    {
        Write-Host "No active Azure login session found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        return
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

    Write-Host "To Set Minimum TLS version for App Services in a Subscription, Contributor or higher privileges on the App Services are required." -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "[Step 2 of 4] Preparing to fetch all App Services..."
    Write-Host $([Constants]::SingleDashLine)

    $appServicesResourceType = "Microsoft.Web/sites"
    $appServiceResources = @()

    # To keep track of remediated and skipped resources
    $logRemediatedResources = @()
    $logSkippedResources=@()

    $controlIds = "Azure_AppService_DP_Use_Secure_TLS_Version"

    # No file path provided as input to the script. Fetch all App Services in the Subscription.
    if($AutoRemediation)
    {
        if(-not (Test-Path -Path $Path))
        {
            Write-Host "File containing failing controls details [$($Path)] not found. Skipping remediation..." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::SingleDashLine)
            return
        }
        Write-Host "Fetching all App Services failing for the [$($controlIds)] control from [$($Path)]..." -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        $controlForRemediation = Get-content -path $Path | ConvertFrom-Json
        $controls = $controlForRemediation.ControlRemediationList
        $resourceDetails = $controls | Where-Object { $controlIds -eq $_.ControlId };
        $validResources = $resourceDetails.FailedResourceList | Where-Object {![String]::IsNullOrWhiteSpace($_.ResourceId)}
        if(($resourceDetails | Measure-Object).Count -eq 0 -or ($validResources | Measure-Object).Count -eq 0)
        {
            Write-Host "No app service(s) found in input json file for remediation." -ForegroundColor $([Constants]::MessageType.Error)
            Write-Host $([Constants]::SingleDashLine)
            return
        }
        $validResources | ForEach-Object { 
            try
            {
                $appServiceResource = Get-AzResource -ResourceId $_.ResourceId -ErrorAction SilentlyContinue
                $appServiceResources += $appServiceResource
            }
            catch
            {
                Write-Host "Valid resource id(s) not found in input json file. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host "WARNING: Skipping the Resource [$($_.ResourceName)]..."
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                $logResource.Add("ResourceName",($_.ResourceName))
                $logResource.Add("Reason","Valid resource id(s) not found in input json file.")    
                $logSkippedResources += $logResource
                Write-Host $([Constants]::SingleDashLine)
            }
        }
    }
    else{
        # No file path provided as input to the script. Fetch all App Services in the Subscription.
        if ([String]::IsNullOrWhiteSpace($FilePath))
        {
            Write-Host "Fetching all App Services in Subscription: [$($context.Subscription.SubscriptionId)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            # Get all App Services in a Subscription
            $appServiceResources = Get-AzResource -ResourceType $appServicesResourceType -ErrorAction Stop
        }
        else
        {
            if (-not (Test-Path -Path $FilePath))
            {
                Write-Host "Input file [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
                return
            }

            Write-Host "Fetching all App Services from [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            $appServiceDetails = Import-Csv -LiteralPath $FilePath
            $validAppServiceDetails = $appServiceDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) }
            
            $validAppServiceDetails | ForEach-Object {
                $resourceId = $_.ResourceId

                try
                {
                    $appServiceResource = Get-AzResource -ResourceId $resourceId -ErrorAction SilentlyContinue
                    $appServiceResources += $appServiceResource
                }
                catch
                {
                    Write-Host "Fetching App Service resource: Resource ID - [$($resourceId)]. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                    Write-Host "Skipping this App Service resource..." -ForegroundColor $([Constants]::MessageType.Warning)
                }
            }
        }
    }
    $totalAppServices = ($appServiceResources | Measure-Object).Count

    if ($totalAppServices -eq 0)
    {
        Write-Host "No App Services found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        return
    }
  
    Write-Host "Found [$($totalAppServices)] App Service(s)." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)

    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\SetMinTLSVersionForAppServices"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
    

    $requiredMinTLSVersion = 1.2
    # $appServicesWithoutReqMinTLSVersion = @()
    # Includes App Services where Minimum required TLS version is set to 1.2+ on all slots - production slot and all non-production slots.
    $appServicesWithReqMinTLSVersion = @()

    # Includes App Services where Minimum required TLS version is not set to 1.2+ on all slots - production slot or one or more non-production slots.
    $appServicesWithoutReqMinTLSVersion = @()

    # Includes App Services that were skipped during remediation. There were errors remediating them.
    $appServicesSkipped = @()

    Write-Host "[Step 3 of 4] Fetching all App Service configurations"
    Write-Host $([Constants]::SingleDashLine)

    $appServiceResources | ForEach-Object {
        $appServiceResource = $_
        $resourceId = $_.ResourceId
        $resourceGroupName = $_.ResourceGroupName
        $resourceName = $_.ResourceName
        try
        {
            Write-Host "Fetching App Service configuration: Resource ID: [$($resourceId)], Resource Group Name: [$($resourceGroupName)], Resource Name: [$($resourceName)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            $minTLSVersionSetOnProductionSlot = $(Get-AzWebApp -ResourceGroupName $resourceGroupName -Name $appServiceResource.Name -ErrorAction SilentlyContinue).SiteConfig.MinTLSVersion
            $isMinTLSVersionSetOnProductionSlot = ($minTLSVersionSetOnProductionSlot -ge $requiredMinTLSVersion)
            Write-Host "App Service Configurations successfully fetched" -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
            Write-Host "Fetching non-production slot configurations for App Service: Resource ID: [$($resourceId)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            $nonProductionSlotConfigurations = (Get-AzWebAppSlot -ResourceGroupName $resourceGroupName -Name $resourceName)
            Write-Host "App Service non-production slot configuration successfully fetched" -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
            $nonProductionSlotsWithoutMinReqTLSVersion = @()
            $nonProductionSlotsWithoutMinReqTLSVersionStr = [String]::Empty
            $nonProductionSlotsWithoutMinReqTLSVersionDictionary = @()
            $isMinTLSVersionSetOnAllNonProductionSlots = $true;
            foreach($slot in $nonProductionSlotConfigurations){
                #$isMinTLSVersionSetOnAllNonProductionSlots = $true;
                $slotName = $slot.name.Split('/')[1]
                $resource = Get-AzWebAppSlot -ResourceGroupName $resourceGroupName -Name $resourceName -Slot $slotName
                if($resource.SiteConfig.MinTlsVersion -lt $requiredMinTLSVersion)
                {
                    $nonProductionSlotsWithoutMinReqTLSVersion += $slot
                    $isMinTLSVersionSetOnAllNonProductionSlots = $false
                    $nonProductionSlotsWithoutMinReqTLSVersionDictionary += [PSCustomObject]@{
                        "SlotName" = $slot.Name;
                        "MinTLSVersion" = $resource.SiteConfig.MinTlsVersion;
                    }
                }
            }
            if ($isMinTLSVersionSetOnProductionSlot -and $isMinTLSVersionSetOnAllNonProductionSlots)
            {
                $appServicesWithReqMinTLSVersion += $appServiceResource
                Write-Host "Minimum TLS Version is set on the production slot and all non-production slots in the App Service. Resource ID: [$($resourceId)]" -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host "Skipping this App Service..." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                $logResource.Add("ResourceName",($_.ResourceName))
                $logResource.Add("Reason","Minimum TLS Version is set on the production slot and all non-production slots in the App Service.")    
                $logSkippedResources += $logResource
            }
            else 
            {
                if (-not $isMinTLSVersionSetOnProductionSlot)
                {
                    Write-Host "Minimum TLS Version is not set on the production slot." -ForegroundColor $([Constants]::MessageType.Warning)
                    Write-Host $([Constants]::SingleDashLine)
                }

                if(-not $isMinTLSVersionSetOnAllNonProductionSlots){
                    $nonProductionSlotsWithoutMinReqTLSVersion = $nonProductionSlotsWithoutMinReqTLSVersion.Name
                    $nonProductionSlotsWithoutMinReqTLSVersionStr = $($nonProductionSlotsWithoutMinReqTLSVersion -join ', ')
                    Write-Host "Minimum TLS Version is not set on these non-production slots: [$($nonProductionSlotsWithoutMinReqTLSVersionStr)]" -ForegroundColor $([Constants]::MessageType.Warning)
                    Write-Host $([Constants]::SingleDashLine)
                }
                $appServiceWithoutReqMinTLSVersion = $appServiceResource | Select-Object @{N='ResourceID';E={$resourceId}},
                                                                                @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                                @{N='ResourceName';E={$resourceName}},
                                                                                @{N='IsMinTLSVersionSetOnProductionSlot';E={$isMinTLSVersionSetOnProductionSlot}},
                                                                                @{N='IsMinTLSVersionSetOnAllNonProductionSlots';E={$isMinTLSVersionSetOnAllNonProductionSlots}},
                                                                                @{N='NonProductionSlotsWithoutMinReqTLSVersion';E={$nonProductionSlotsWithoutMinReqTLSVersion}},
                                                                                @{N='MinTLSVersionSetOnProductionSlot';E={$minTLSVersionSetOnProductionSlot}}

                foreach($pair in $nonProductionSlotsWithoutMinReqTLSVersionDictionary)
                {
                    $appServiceWithoutReqMinTLSVersion | Add-Member -NotePropertyName $pair.SlotName -NotePropertyValue $pair.MinTLSVersion
                }

                $appServicesWithoutReqMinTLSVersion += $appServiceWithoutReqMinTLSVersion
            }
   
        }
        catch
        {
            $appServicesSkipped += $appServiceResource
            Write-Host "Error fetching App Service configuration: Resource ID: [$($resourceId)], Resource Group Name: [$($resourceGroupName)], Resource Name: [$($resourceName)]. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            $logResource = @{}
            $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
            $logResource.Add("ResourceName",($_.ResourceName))
            $logResource.Add("Reason","Encountered error while fetching app service configuration")    
            $logSkippedResources += $logResource
            Write-Host "Skipping this resource..." -ForegroundColor $([Constants]::MessageType.Warning)
        }
    }
    $totalAppServicesWithoutReqMinTLSVersion = ($appServicesWithoutReqMinTLSVersion | Measure-Object).Count

    if ($totalAppServicesWithoutReqMinTLSVersion -eq 0)
    {
        Write-Host "No App Service(s) found having minimum TLS version less than required minimum TLS version. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)
        if($AutoRemediation -and ($appServicesWithReqMinTLSVersion|Measure-Object).Count -gt 0) 
        {
            $logFile = "LogFiles\"+ $($TimeStamp) + "\log_" + $($SubscriptionId) +".json"
            $log =  Get-content -Raw -path $logFile | ConvertFrom-Json
            foreach($logControl in $log.ControlList){
                if($logControl.ControlId -eq $controlIds){
                    $logControl.RemediatedResources=$logRemediatedResources
                    $logControl.SkippedResources=$logSkippedResources
                }
            }
            $log | ConvertTo-json -depth 100  | Out-File $logFile
        }
        return
    }

    Write-Host "Found [$($totalAppServicesWithoutReqMinTLSVersion)] out of [$($totalAppServices)] App Service(s) having minimum TLS version less than required minimum TLS version." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)
    
    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\SetMinTLSVersionForAppServices"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }

    if (-not $DryRun)
    {
        if(-not $SkipBackup)
        {
            Write-Host "Backing up App Services details to [$($backupFolderPath)]..." -ForegroundColor $([Constants]::MessageType.Info)
            $backupFile = "$($backupFolderPath)\AppServicesWithoutReqMinTLSVersion.csv"
            $appServicesWithoutReqMinTLSVersion | Export-CSV -Path $backupFile -NoTypeInformation
            Write-Host "App Services details have been backed up to [$($backupFile)]" -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
        }
        Write-Host "Minimum required TLS Version will be set on the production slot and all non-production slots for all App Services." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
        if(-not $AutoRemediation)
        {
            if (-not $Force)
            {
                Write-Host "Do you want to set minimum required TLS Version on the production slot and all non-production slots for all App Services? " -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
                
                $userInput = Read-Host -Prompt "(Y|N)"
                Write-Host $([Constants]::SingleDashLine)
                if($userInput -ne "Y")
                {
                    Write-Host "Minimum required TLS Version will not be set for any App Service. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
                    Write-Host $([Constants]::SingleDashLine)
                    return
                }
                Write-Host "User has provided consent to set minimum required TLS Version on the production slot and all non-production slots for all App Services" -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
            }
            else
            {
                Write-Host "'Force' flag is provided. Minimum required TLS Version will be set on the production slot and all non-production slots for all App Services without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }
        }

        Write-Host $([Constants]::SingleDashLine)
        Write-Host "`[Step 4 of 4] Setting minimum required TLS Version for App Services"
        Write-Host $([Constants]::SingleDashLine)
        # To hold results from the remediation.
        $appServicesRemediated = @()
        $appServicesSkipped = @()

        $appServicesWithoutReqMinTLSVersion | ForEach-Object {
            $appService = $_
            $resourceId = $_.ResourceID
            $resourceGroupName = $_.ResourceGroupName
            $resourceName = $_.ResourceName
            $isMinTLSVersionSetOnProductionSlot = $_.IsMinTLSVersionSetOnProductionSlot
            $isMinTLSVersionSetOnAllNonProductionSlots = $_.IsMinTLSVersionSetOnAllNonProductionSlots
            $nonProductionSlotsWithoutMinReqTLSVersion = $_.NonProductionSlotsWithoutMinReqTLSVersion

            Write-Host "Setting minimum required TLS Version for App Service: Resource ID: [$($resourceId)], Resource Group Name: [$($resourceGroupName)], Resource Name: [$($resourceName)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            $nonProductionSlotsWithoutMinReqTLSVersionStr = $nonProductionSlotsWithoutMinReqTLSVersion -join ','
            $isMinTLSVersionSetOnProductionSlotPostRemediation = $isMinTLSVersionSetOnProductionSlot
            
            # Reset the status further down, as appropriate.
            $appService | Add-Member -NotePropertyName NonProductionSlotsSkipped -NotePropertyValue $nonProductionSlotsWithoutMinReqTLSVersionStr
            $appService | Add-Member -NotePropertyName isMinTLSVersionSetOnProductionSlotPostRemediation -NotePropertyValue $isMinTLSVersionSetOnProductionSlotPostRemediation

            # If minimum required TLS version is not disabled on the production slot
            if (-not [System.Convert]::ToBoolean($isMinTLSVersionSetOnProductionSlot))
            {
                try
                {
                    Write-Host "Setting minimum required TLS version on the production slot..." -ForegroundColor $([Constants]::MessageType.Info)
                    Write-Host $([Constants]::SingleDashLine)
                    $resource = Get-AzWebApp -ResourceGroupName $resourceGroupName -Name $resourceName
                    $resource.SiteConfig.MinTlsVersion = $requiredMinTLSVersion
                    # Holding output of set command to avoid unnecessary logs.
                    $temp = $resource | Set-AzWebApp -ErrorAction SilentlyContinue
                    $isMinTLSVersionSetOnProductionSlot = $(Get-AzWebApp -ResourceGroupName $resourceGroupName -Name $resourceName).SiteConfig.MinTlsVersion

                    if ($isMinTLSVersionSetOnProductionSlot -ge $requiredMinTLSVersion)
                    {
                        $appService.isMinTLSVersionSetOnProductionSlotPostRemediation = $true
                        # $logResource = @{}
                        # $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                        # $logResource.Add("ResourceName",($_.ResourceName))
                        # $logRemediatedResources += $logResource
                        Write-Host "Successfully set the minimum required TLS version on the production slot." -ForegroundColor $([Constants]::MessageType.Update)
                        Write-Host $([Constants]::SingleDashLine)
                    }
                    else
                    {
                        $appServicesSkipped += $appService
                        $logResource = @{}
                        $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                        $logResource.Add("ResourceName",($_.ResourceName))
                        $logResource.Add("Reason", "Error while setting the minimum required TLS version on the production slot. Skipping this App Service. Minimum required TLS version will not be disabled for any of the non-production slots.")
                        $logSkippedResources += $logResource
                        Write-Host "Error while setting the minimum required TLS version on the production slot." -ForegroundColor $([Constants]::MessageType.Error)
                        Write-Host "Skipping this App Service. Minimum required TLS version will not be disabled for any of the non-production slots." -ForegroundColor $([Constants]::MessageType.Warning)
                        Write-Host $([Constants]::SingleDashLine)
                        return
                    }
                }
                catch
                {
                    $appServicesSkipped += $appService
                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                    $logResource.Add("ResourceName",($_.ResourceName))
                    $logResource.Add("Reason", "Error while setting the minimum required TLS version on the production slot. Skipping this App Service. Minimum required TLS version will not be disabled for any of the non-production slots.")
                    $logSkippedResources += $logResource
                    Write-Host "Error while setting the minimum required TLS version on the production slot." -ForegroundColor $([Constants]::MessageType.Error)
                    Write-Host "Skipping this App Service. Minimum required TLS version will not be disabled for any of the non-production slots." -ForegroundColor $([Constants]::MessageType.Warning)
                    Write-Host $([Constants]::SingleDashLine)
                    return
                }
            }

            
            $nonProductionSlotsSkipped = @()
            $nonProductionSlotsSkippedStr = [String]::Empty

            if (-not [System.Convert]::ToBoolean($isMinTLSVersionSetOnAllNonProductionSlots))
            {
                foreach ($slot in $nonProductionSlotsWithoutMinReqTLSVersion.Split(','))
                {
                    # Slot names are of the form: app-service-name/slot-name
                    $slotName = $slot.Split('/')[1]
                    try
                    {
                        Write-Host "Setting minimum required TLS version on the non-production slot: $($slot)..." -ForegroundColor $([Constants]::MessageType.Info)
                        Write-Host $([Constants]::SingleDashLine)
                        $resource = Get-AzWebAppSlot -ResourceGroupName $resourceGroupName -Name $resourceName -Slot $slotName
                        $resource.SiteConfig.MinTlsVersion = $requiredMinTLSVersion
                        
                        # Holding output of set command to avoid unnecessary logs.
                        $temp = $resource | Set-AzWebAppSlot -ErrorAction SilentlyContinue
                        $isMinReqTLSVersionSetOnNonProductionSlot = $(Get-AzWebAppSlot -ResourceGroupName $resourceGroupName -Name $resourceName -Slot $slotName).SiteConfig.MinTlsVersion
                        if($isMinReqTLSVersionSetOnNonProductionSlot -ge $requiredMinTLSVersion){
                            Write-Host "Successfully set the minimum required TLS version on the non-production slot." -ForegroundColor $([Constants]::MessageType.Update)
                            Write-Host $([Constants]::SingleDashLine)
                        }else{
                            $nonProductionSlotsSkipped += $slot
                            Write-Host "Error while setting the minimum required TLS version on the non-production slot." -ForegroundColor $([Constants]::MessageType.Error)
                            Write-Host $([Constants]::SingleDashLine)
                        }
                        
                    }
                    catch
                    {
                        $nonProductionSlotsSkipped += $slot
                        Write-Host "Error while setting the minimum required TLS version on the non-production slot." -ForegroundColor $([Constants]::MessageType.Error)
                        Write-Host $([Constants]::SingleDashLine)
                    }
                }
            }
            
            $nonProductionSlotsSkippedStr = $nonProductionSlotsSkipped -join ','
            $appService.NonProductionSlotsSkipped = $nonProductionSlotsSkippedStr

            if ($($nonProductionSlotsSkipped | Measure-Object).Count -eq 0)
            {
                $appService.isMinTLSVersionSetOnAllNonProductionSlots = $true
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                $logResource.Add("ResourceName",($_.ResourceName))
                $logRemediatedResources += $logResource
                $appServicesRemediated += $appService
                Write-Host "Successfully set the minimum required TLS version on production and all non-production slots for the App Service." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
            }
            else
            {
                $appServicesSkipped += $appService
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                $logResource.Add("ResourceName",($_.ResourceName))
                $logResource.Add("Reason", "Error while setting the minimum required TLS version on these non-production slots: [$($nonProductionSlotsSkippedStr)]")
                $logSkippedResources += $logResource
                Write-Host "Error while setting the minimum required TLS version for these non-production slots: [$($nonProductionSlotsSkippedStr)]" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host $([Constants]::SingleDashLine)
                
            }
        }

        # Write-Host $([Constants]::SingleDashLine)

        if (($appServicesRemediated | Measure-Object).Count -eq $totalAppServicesWithoutReqMinTLSVersion)
        {
            Write-Host "Successfully set the minimum required TLS version on the production slot and all non-production slots for all [$($totalAppServicesWithoutReqMinTLSVersion)] App Service(s)." -ForegroundColor $([Constants]::MessageType.Update)
            
        }
        else
        {
            Write-Host "Minimum required TLS version is successfully set on the production slot and all non-production slots for [$($($appServicesRemediated | Measure-Object).Count)] out of [$($totalAppServicesWithoutReqMinTLSVersion)] App Service(s)." -ForegroundColor $([Constants]::MessageType.Warning)
        }

        $colsProperty = @{Expression={$_.ResourceId};Label="Resource ID";Width=40;Alignment="left"},
                        @{Expression={$_.ResourceGroupName};Label="Resource Group Name";Width=20;Alignment="left"},
                        @{Expression={$_.ResourceName};Label="Resource Name";Width=20;Alignment="left"},
                        @{Expression={$_.isMinTLSVersionSetOnProductionSlot};Label="Is minimum required TLS version set on the production slot - Prior to remediation?";Width=20;Alignment="left"},
                        @{Expression={$_.isMinTLSVersionSetOnProductionSlotPostRemediation};Label="Is minimum required TLS version set on the production slot - Post remediation?";Width=20;Alignment="left"},
                        @{Expression={$_.isMinTLSVersionSetOnAllNonProductionSlots};Label="Is minimum required TLS version set on all the non-production slots?";Width=20;Alignment="left"},
                        @{Expression={$_.nonProductionSlotsWithoutMinReqTLSVersion};Label="Non-production slots without minimum required TLS Version - Prior to remediation";Width=40;Alignment="left"},
                        @{Expression={$_.NonProductionSlotsSkipped};Label="Non-production slots  without minimum required TLS Version - Post remediation";Width=40;Alignment="left"}

        Write-Host $([Constants]::DoubleDashLine)
        if($AutoRemediation){
            if ($($appServicesRemediated | Measure-Object).Count -gt 0)
            {
                # Write this to a file.
                $appServicesRemediatedFile = "$($backupFolderPath)\RemediatedAppServicesForMinReqTLSVersion.csv"
                $appServicesRemediated | Export-CSV -Path $appServicesRemediatedFile -NoTypeInformation
                Write-Host "The information related to App Service(s) where minimum required TLS version is successfully set has been saved to [$($appServicesRemediatedFile)]. Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }

            if ($($appServicesSkipped | Measure-Object).Count -gt 0)
            {   
                # Write this to a file.
                $appServicesSkippedFile = "$($backupFolderPath)\SkippedAppServicesForMinReqTLSVersion.csv"
                $appServicesSkipped | Export-CSV -Path $appServicesSkippedFile -NoTypeInformation
                Write-Host "The information related to App Service(s) where minimum required TLS version is not set has been saved to [$($appServicesSkippedFile)]" -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }
        }else{
            Write-Host "Remediation Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)
        
            if ($($appServicesRemediated | Measure-Object).Count -gt 0)
            {
                
                Write-Host "Successfully set minimum required TLS version for the following App Service(s):" -ForegroundColor $([Constants]::MessageType.Update)
                $appServicesRemediated | Format-Table -Property $colsProperty -Wrap
                Write-Host $([Constants]::SingleDashLine)
                # Write this to a file.
                $appServicesRemediatedFile = "$($backupFolderPath)\RemediatedAppServicesForMinReqTLSVersion.csv"
                $appServicesRemediated | Export-CSV -Path $appServicesRemediatedFile -NoTypeInformation
                Write-Host "This information has been saved to [$($appServicesRemediatedFile)]" -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }

            if ($($appServicesSkipped | Measure-Object).Count -gt 0)
            {
                Write-Host "Error while setting the minimum required TLS Version for the following App Service(s):" -ForegroundColor $([Constants]::MessageType.Error)
                $appServicesSkipped | Format-Table -Property $colsProperty -Wrap
                Write-Host $([Constants]::SingleDashLine)
                # Write this to a file.
                $appServicesSkippedFile = "$($backupFolderPath)\SkippedAppServicesForMinReqTLSVersion.csv"
                $appServicesSkipped | Export-CSV -Path $appServicesSkippedFile -NoTypeInformation 
                Write-Host "This information has been saved to [$($appServicesSkippedFile)]" -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }
        }
        if($AutoRemediation){
            $logFile = "LogFiles\"+ $($TimeStamp) + "\log_" + $($SubscriptionId) +".json"
            $log =  Get-content -Raw -path $logFile | ConvertFrom-Json
            foreach($logControl in $log.ControlList){
                if($logControl.ControlId -eq $controlIds){
                    $logControl.RemediatedResources=$logRemediatedResources
                    $logControl.SkippedResources=$logSkippedResources
                    $logControl.RollbackFile = $appServicesRemediatedFile
                }
            }
            $log | ConvertTo-json -depth 100  | Out-File $logFile
        }
    }
    else
    {
        Write-Host "[Step 3 of 3] Backing up App Services details"
        Write-Host $([Constants]::SingleDashLine)
        # Backing up App Services details.
        $backupFile = "$($backupFolderPath)\AppServicesWithoutReqMinTLSVersion.csv"
        $appServicesWithoutReqMinTLSVersion | Export-CSV -Path $backupFile -NoTypeInformation
        Write-Host "Next steps:" -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host "App Services details have been backed up to [$($backupFile)]. Please review before remediating them." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host "Run the same command with -FilePath $($backupFile) and without -DryRun, to set minimum required TLS Version for all App Services (across the production slot and all non-production slots) listed in the file." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }
}

function Reset-AppServiceRequiredTLSVersion
{
    <#
        .SYNOPSIS
        Rolls back remediation done for 'Azure_AppService_DP_Use_Secure_TLS_Version' Control.

        .DESCRIPTION
        Rolls back remediation done for 'Azure_AppService_DP_Use_Secure_TLS_Version' Control.
        Resets Minimum TLS Version on the production slot and all non-production slots in all App Services in the Subscription. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that was previously remediated.
        
        .PARAMETER Force
        Specifies a forceful roll back without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
        
        .Parameter ExcludeNonProductionSlots
        Specifies exclusion of non-production slots from roll back.
        
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the roll back.

        .INPUTS
        None. You cannot pipe objects to Reset-AppServiceRequiredTLSVersion.

        .OUTPUTS
        None. Reset-AppServiceRequiredTLSVersion does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Reset-AppServiceRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetMinTLSVersionForAppServices\RemediatedAppServices.csv

        .EXAMPLE
        PS> Reset-AppServiceRequiredTLSVersion -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -ExcludeNonProductionSlots -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\SetMinTLSVersionForAppServices\RemediatedAppServices.csv

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

        [Switch]
        [Parameter(HelpMessage="Specifies exclusion of non-production slots from roll back")]
        $ExcludeNonProductionSlots,

        [String]
        [Parameter(Mandatory = $true, HelpMessage="Specifies the path to the file to be used as input for the roll back")]
        $FilePath
    )

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 1 of 3] Preparing to reset minimum TLS version on App Services in Subscription: [$($SubscriptionId)]"
    Write-Host $([Constants]::SingleDashLine)

    if ($PerformPreReqCheck)
    {
        try
        {
            Write-Host "Setting up prerequisites..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            Setup-Prerequisites
            Write-Host "Completed setting up prerequisites" -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
        }
        catch
        {
            Write-Host "Error occurred while setting up prerequisites. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
            return
        }
    }

    # Connect to Azure account
    $context = Get-AzContext

    if ([String]::IsNullOrWhiteSpace($context))
    {
        Write-Host "No active Azure login session found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        return
    }

    # Setting up context for the current Subscription.
    $context = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop
    
    Write-Host "Subscription Name: [$($context.Subscription.Name)]"
    Write-Host "Subscription ID: [$($context.Subscription.SubscriptionId)]"
    Write-Host "Account Name: [$($context.Account.Id)]"
    Write-Host "Account Type: [$($context.Account.Type)]"
    Write-Host $([Constants]::SingleDashLine)

    Write-Host "To Reset Minimum TLS version for for App Services in a Subscription, Contributor or higher privileges on the App Services are required." -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "[Step 2 of 3] Preparing to fetch all App Services"
    Write-Host $([Constants]::SingleDashLine)
    
    if (-not (Test-Path -Path $FilePath))
    {
        Write-Host "Input file: [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        return
    }

    Write-Host "Fetching all App Services from [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

    $appServiceDetails = Import-Csv -LiteralPath $FilePath
    $validAppServiceDetails = $appServiceDetails | Where-Object { ![String]::IsNullOrWhiteSpace($_.ResourceId) -and ![String]::IsNullOrWhiteSpace($_.ResourceGroupName) -and ![String]::IsNullOrWhiteSpace($_.ResourceName) }

    $totalAppServices = $(($validAppServiceDetails|Measure-Object).Count)

    if ($totalAppServices -eq 0)
    {
        Write-Host "No App Services found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        return
    }

    Write-Host "Found [$($totalAppServices)] App Service(s)." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)
    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\SetMinTLSVersionForAppServices"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }

    Write-Host "Minimum TLS Version will be reset on the following App Service(s):"
    $validAppServiceDetails | Select-Object @{N="Resource Id"; E={$_.ResourceId}}, @{N="Resource Group Name"; E={$_.ResourceGroupName}}, @{N="Resource Name"; E={$_.ResourceName}}| Format-Table -AutoSize -Wrap
    Write-Host $([Constants]::SingleDashLine)
    $slotsBeingRolledBackMessage = "production slot"

    if ($ExcludeNonProductionSlots)
    {
        Write-Host "'ExcludeNonProductionSlots' flag is provided. Non-production slots will be excluded from the rollback." -ForegroundColor $([Constants]::MessageType.Warning)
    }
    else
    {
        $slotsBeingRolledBackMessage += " and all non-production slots"
        Write-Host "'ExcludeNonProductionSlots' flag is not provided. Minimum TLS Version will be reset on ALL mentioned non-production slots in addition to the production slot." -ForegroundColor $([Constants]::MessageType.Warning)
    }
    Write-Host $([Constants]::SingleDashLine)

    if (-not $Force)
    {
        Write-Host "Do you want to reset minimum TLS Version on the $($slotsBeingRolledBackMessage) for all App Services? " -NoNewline
            
        $userInput = Read-Host -Prompt "(Y|N)"
        Write-Host $([Constants]::SingleDashLine)
        if($userInput -ne "Y")
        {
            Write-Host "Minimum TLS Version will not be reset for any App Service. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
            return
        }
        Write-Host "User has provided consent to reset minimum TLS Version on the $($slotsBeingRolledBackMessage) for all App Services." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }
    else
    {
        Write-Host "'Force' flag is provided. Minimum TLS Version will be reset on the $($slotsBeingRolledBackMessage) for all mentioned App Services without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
        Write-Host $([Constants]::SingleDashLine)
    }

    Write-Host "[Step 3 of 3] Resetting Minimum TLS Version for App Service" 
    Write-Host $([Constants]::SingleDashLine)

    # Includes App Services, to which, previously made changes were successfully rolled back.
    $appServicesRolledBack = @()

    # Includes App Services that were skipped during roll back. There were errors rolling back the changes made previously.
    $appServicesSkipped = @()

    $requiredMinTLSVersion = 1.2

    $validAppServiceDetails | ForEach-Object {
        $appService = $_
        $resourceId = $appService.ResourceId
        $resourceGroupName = $appService.ResourceGroupName
        $resourceName = $appService.ResourceName
        $nonProdSlots = $appService.NonProductionSlotsWithoutMinReqTLSVersion
        $isMinTLSVersionSetOnProductionSlot = $appService.isMinTLSVersionSetOnProductionSlotPostRemediation
        $minTLSVersionSetOnProductionSlot = $appService.MinTLSVersionSetOnProductionSlot

        try
        {
            Write-Host "Fetching App Service configuration: Resource ID: [$($resourceId)], Resource Group Name: [$($resourceGroupName)], Resource Name: [$($resourceName)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)

            if ($isMinTLSVersionSetOnProductionSlot -eq $false)
            {
                Write-Host "Minimum required TLS version was not set on the production slot during remediation." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host "Skipping this App Service. If required, manually change TLS Version on the non-production slots." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
                return
            }

            if ($isMinTLSVersionSetOnProductionSlot)
            {
                $resource = Get-AzWebApp -ResourceGroupName $resourceGroupName -Name $resourceName
                $resource.SiteConfig.MinTlsVersion = $minTLSVersionSetOnProductionSlot
            
                # Holding output of set command to avoid unnecessary logs.
                $temp = $resource | Set-AzWebApp -ErrorAction SilentlyContinue
                $minTLSVersionOnProductionSlot = $(Get-AzWebApp -ResourceGroupName $resourceGroupName -Name $resourceName).SiteConfig.MinTlsVersion
                if([String]::IsNullOrWhiteSpace($minTLSVersionOnProductionSlot))
                {
                    $appServicesSkipped += $appService
                    Write-Host "Error encountered while fetching App Service details." -ForegroundColor $([Constants]::MessageType.Error)
                    Write-Host "Skipping this App Service. If required, manually reset minimum required TLS Version on the non-production slots." -ForegroundColor $([Constants]::MessageType.Warning)
                    return
                }
                if ($minTLSVersionOnProductionSlot -ne $minTLSVersionSetOnProductionSlot)
                {
                    $appServicesSkipped += $appService
                    Write-Host "Mininum TLS version is changed on the producation slot of this App Service post remediation." -ForegroundColor $([Constants]::MessageType.Warning)
                    Write-Host "Skipping this App Service. If required, manually reset minimum required TLS Version on the non-production slots." -ForegroundColor $([Constants]::MessageType.Warning)
                    return
                }
            }

            Write-Host "Successfully rolled back changes on the production slot." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)

            # Reset the states further below, as appropriate.
            $appService | Add-Member -NotePropertyName IsMinTLSVersionSetOnAnyNonProductionSlots -NotePropertyValue $false
            $appService | Add-Member -NotePropertyName NonProductionSlotsWithMinReqTLSVersion -NotePropertyValue ([String]::Empty)

            Write-Host "Fetching non-production slot configurations for App Service: Resource ID: [$($resourceId)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)

            $nonProductionSlotConfigurations = @()
            $nonProductionSlotsWithMinReqTLSVersion =@()
            $nonProductionSlotsWithoutMinReqTLSVersion =@()
            $isMinReqTLSVersionSetOnAnyNonProductionSlots = $false
            if ([String]::IsNullOrWhiteSpace($nonProdSlots))
            {
                $isNonProdSlotAvailable = $false
            }
            else
            {
                $isNonProdSlotAvailable = $true
                foreach ($slot in $nonProdSlots.Split(' '))
                {
                    $nonProductionSlotConfiguration = Get-AzWebAppSlot -ResourceGroupName $resourceGroupName -Name $resourceName -Slot $slot.Split('/')[1]
                    $nonProductionSlotConfigurations += $nonProductionSlotConfiguration
                    if($nonProductionSlotConfiguration.SiteConfig.MinTlsVersion -eq $requiredMinTLSVersion)
                    {
                        $nonProductionSlotsWithMinReqTLSVersion += $nonProductionSlotConfiguration.Name
                        $isMinReqTLSVersionSetOnAnyNonProductionSlots = $true
                    }
                    else 
                    {
                        $nonProductionSlotsWithoutMinReqTLSVersion += $nonProductionSlotConfiguration.Name
                    }
                }
            }

            if($($nonProductionSlotsWithoutMinReqTLSVersion|Measure-Object).Count -ne 0)
            {
                $appServicesSkipped += $appService
                Write-Host "Minimum TLS version for these non production slot(s): [$(nonProductionSlotsWithoutMinReqTLSVersion)] is changed post remediation." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host "Skipping this App Service" -ForegroundColor $([Constants]::MessageType.Warning)
                return
            }
            if (-not $isMinReqTLSVersionSetOnAnyNonProductionSlots -or -not $isNonProdSlotAvailable)
            {
                $appServicesRolledBack += $appService
                Write-Host "Successfully rolled back changes on all non-production slots in the App Service." -ForegroundColor $([Constants]::MessageType.Update)
                return
            }

            $appService.IsMinTLSVersionSetOnAnyNonProductionSlots = $true
            $nonProductionSlotsWithMinReqTLSVersionStr = $($nonProductionSlotsWithMinReqTLSVersion -join ', ')
            $appService.NonProductionSlotsWithMinReqTLSVersion = $nonProductionSlotsWithMinReqTLSVersionStr

            $nonProductionSlotsSkipped = $nonProductionSlotsWithMinReqTLSVersion
            $nonProductionSlotsSkippedStr = $($nonProductionSlotsWithMinReqTLSVersion -join ', ')
            $appService.NonProductionSlotsSkipped = $nonProductionSlotsSkippedStr

            Write-Host "Minimum Required TLS Version is set on these non-production slots: [$($nonProductionSlotsWithMinReqTLSVersionStr)]" -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
            $nonProductionSlotsSkipped = @()
            foreach($slot in $nonProductionSlotsWithMinReqTLSVersion)
            {
                # Slot names are of the form: app-service-name/slot-name
                $slotName = $slot.Split('/')[1]

                try
                {
                    Write-Host "Rolling back changes on the non-production slot: $($slot)..." -ForegroundColor $([Constants]::MessageType.Info)
                    Write-Host $([Constants]::SingleDashLine)
                    $resource = Get-AzWebAppSlot -ResourceGroupName $resourceGroupName -Name $resourceName -Slot $slotName
                    $resource.SiteConfig.MinTlsVersion = $appService.$slot
                    
                    # Holding output of set command to avoid unnecessary logs.
                    $temp = $resource | Set-AzWebAppSlot -ErrorAction SilentlyContinue
                    $minTLSVersionForNonProductionSlot = $(Get-AzWebAppSlot -ResourceGroupName $resourceGroupName -Name $resourceName -Slot $slotName).SiteConfig.MinTlsVersion

                    $isMinTLSVersionRolledBackOnNonProductionSlot = ($minTLSVersionForNonProductionSlot -eq $appService.$slot)
                    if($isMinTLSVersionRolledBackOnNonProductionSlot){
                        Write-Host "Successfully rolled back changes on the non-production slot." -ForegroundColor $([Constants]::MessageType.Update)
                        Write-Host $([Constants]::SingleDashLine)
                    }else{
                        $nonProductionSlotsSkipped += $slot
                        Write-Host "Error while rolling back changes on the non-production slot." -ForegroundColor $([Constants]::MessageType.Error)
                        Write-Host $([Constants]::SingleDashLine)
                    }
                    
                }
                catch
                {
                    $nonProductionSlotsSkipped += $slot
                    Write-Host "Error while rolling back changes on the non-production slot." -ForegroundColor $([Constants]::MessageType.Error)
                    Write-Host $([Constants]::SingleDashLine)
                }
            }
            $nonProductionSlotsSkippedStr = $nonProductionSlotsSkipped -join ','

            $isMinTLSVersionSetOnProductionSlot = ($(Get-AzWebApp -ResourceGroupName $resourceGroupName -Name $resourceName).SiteConfig.MinTlsVersion -ge $requiredMinTLSVersion)
            $appService.IsMinTLSVersionSetOnProductionSlot = $isMinTLSVersionSetOnProductionSlot

            $appService.NonProductionSlotsWithMinReqTLSVersion = $nonProductionSlotsSkippedStr
            $appService.NonProductionSlotsSkipped = $nonProductionSlotsSkippedStr
            
            if ($($nonProductionSlotsSkipped | Measure-Object).Count -eq 0)
            {
                $appService.IsMinTLSVersionSetOnAnyNonProductionSlots = $false
                $appServicesRolledBack += $appService | Select-Object @{N='ResourceID';E={$_.ResourceId}},
                                                                        @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                        @{N='ResourceName';E={$_.ResourceName}},
                                                                        @{N='IsMinTLSVersionSetOnProductionSlot';E={$_.IsMinTLSVersionSetOnProductionSlot}},
                                                                        @{N='IsMinTLSVersionSetOnAnyNonProductionSlots';E={$_.IsMinTLSVersionSetOnAnyNonProductionSlots}},
                                                                        @{N='NonProductionSlotsWithoutMinReqTLSVersion';E={$_.NonProductionSlotsWithoutMinReqTLSVersion}},
                                                                        @{N='NonProductionSlotsSkipped';E={$_.NonProductionSlotsSkipped}}
            }
            else
            {
                $appServicesSkipped += $appService | Select-Object @{N='ResourceID';E={$_.ResourceId}},
                                                                        @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                        @{N='ResourceName';E={$_.ResourceName}},
                                                                        @{N='IsMinTLSVersionSetOnProductionSlot';E={$_.IsMinTLSVersionSetOnProductionSlot}},
                                                                        @{N='IsMinTLSVersionSetOnAnyNonProductionSlots';E={$_.IsMinTLSVersionSetOnAnyNonProductionSlots}},
                                                                        @{N='NonProductionSlotsWithoutMinReqTLSVersion';E={$_.NonProductionSlotsWithoutMinReqTLSVersion}},
                                                                        @{N='NonProductionSlotsSkipped';E={$_.NonProductionSlotsSkipped}}
            }
        }
        catch
        {
            $appServicesSkipped += $appService | Select-Object @{N='ResourceID';E={$resourceId}},
                                                                @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                @{N='ResourceName';E={$resourceName}},
                                                                @{N='IsMinTLSVersionSetOnProductionSlot';E={$isMinTLSVersionSetOnProductionSlot}},
                                                                @{N='IsMinTLSVersionSetOnAnyNonProductionSlots';E={$isMinTLSVersionSetOnAnyNonProductionSlots}},
                                                                @{N='NonProductionSlotsWithoutMinReqTLSVersion';E={$nonProductionSlotsWithoutMinReqTLSVersion}},
                                                                @{N='NonProductionSlotsSkipped';E={$nonProductionSlotsSkipped}}
        }
    }

    if (($appServicesSkipped | Measure-Object).Count -eq 0)
    {
        Write-Host "Minimum TLS Version successfully reset on the $($slotsBeingRolledBackMessage) for all [$($totalAppServices)] App Service(s)." -ForegroundColor $([Constants]::MessageType.Update)
    }
    else
    {
        Write-Host "Minimum TLS Version successfully reset on the $($slotsBeingRolledBackMessage) for [$($($appServicesRolledBack | Measure-Object).Count)] out of [$($totalAppServices)] App Service(s)" -ForegroundColor $([Constants]::MessageType.Warning)
    }

    $colsProperty = @{Expression={$_.ResourceId};Label="Resource ID";Width=40;Alignment="left"},
                    @{Expression={$_.ResourceGroupName};Label="Resource Group Name";Width=20;Alignment="left"},
                    @{Expression={$_.ResourceName};Label="Resource Name";Width=20;Alignment="left"},
                    @{Expression={$_.IsMinTLSVersionSetOnProductionSlot};Label="Is minimum required TLS version set on the production slot?";Width=20;Alignment="left"},
                    @{Expression={$_.IsMinTLSVersionSetOnAnyNonProductionSlots};Label="Is minimum required TLS version set on any non-production slot?";Width=20;Alignment="left"},
                    @{Expression={$_.NonProductionSlotsWithoutMinReqTLSVersion};Label="Non-production slots having minimum required TLS version - Prior to rollback";Width=40;Alignment="left"},
                    @{Expression={$_.NonProductionSlotsSkipped};Label="on-production slots having minimum required TLS version - Post rollback";Width=40;Alignment="left"}


    if ($($appServicesRolledBack | Measure-Object).Count -gt 0 -or $($appServicesSkipped | Measure-Object).Count -gt 0)
    {
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Rollback Summary:" -ForegroundColor $([Constants]::MessageType.Info)
        
        if ($($appServicesRolledBack | Measure-Object).Count -gt 0)
        {
            Write-Host "Minimum TLS Version successfully reset on the following App Service(s):" -ForegroundColor $([Constants]::MessageType.Update)
            $appServicesRolledBack | Format-Table -Property $colsProperty -Wrap -AutoSize
            Write-Host $([Constants]::SingleDashLine)
            # Write this to a file.
            $appServicesRolledBackFile = "$($backupFolderPath)\RolledBackAppServices.csv"
            $appServicesRolledBack | Export-CSV -Path $appServicesRolledBackFile -NoTypeInformation
            Write-Host "Note: This information has been saved to [$($appServicesRolledBackFile)]" -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
        }

        if ($($appServicesSkipped | Measure-Object).Count -gt 0)
        {
            Write-Host "Error resetting minimum TLS Version for the following App Service(s):" -ForegroundColor $([Constants]::MessageType.Error)
            $appServicesSkipped | Format-Table -Property $colsProperty -Wrap -AutoSize
            Write-Host $([Constants]::SingleDashLine)
            # Write this to a file.
            $appServicesSkippedFile = "$($backupFolderPath)\RollbackSkippedAppServices.csv"
            $appServicesSkipped | Export-CSV -Path $appServicesSkippedFile -NoTypeInformation
            Write-Host "Note: This information has been saved to [$($appServicesSkippedFile)]" -ForegroundColor $([Constants]::MessageType.Warning)
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
