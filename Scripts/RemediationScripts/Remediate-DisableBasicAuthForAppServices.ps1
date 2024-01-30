<###
# Overview:
    This script is used to disable Basic Auth for App Services in a Subscription.

# Control ID:
    Azure_AppService_AuthN_FTP_and_SCM_Access_Disable_Basic_Auth

# Display Name:
    AppService must not use basic authentication for FTP and SCM access

# Prerequisites:
    1. Contributor or higher privileges on the App Services in a Subscription.
    2. Must be connected to Azure with an authenticated account.

# Steps performed by the script:
    To remediate:
        1. Validate and install the modules required to run the script.
        2. Get the list of App Services in a Subscription that do not have FTP and SCM basic authentication enabled for the production slot or for any of the non-production slots.
        3. Back up details of App Services that are to be remediated.
        4. Disable FTP and SCM basic authentication on the production slot and all non-production slots in all App Services in the Subscription.

    To roll back:
        1. Validate and install the modules required to run the script.
        2. Get the list of App Services in a Subscription, the changes made to which previously, are to be rolled back.
        3. Enable FTP and SCM basic authentication on the production slot and all non-production slots in all App Services in the Subscription

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to disable FTP and SCM basic authentication on the production slot and all non-production slots in all App Services in the Subscription. Refer `Examples`, below.

    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to enable FTP and SCM basic authentication on the production slot and all non-production slots in all App Services in the Subscription. Refer `Examples`, below.

# Examples:
    To remediate:
        1. To review the App Services in a Subscription that will be remediated:
           Disable-BasicAuthForAppServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        2. To disable disable FTP and SCM basic authentication on the production slot and all non-production slots of all App Services in a Subscription:
           Disable-BasicAuthForAppServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        3. To disable disable FTP and SCM basic authentication on the production slot and all non-production slots of all App Services in a Subscription, from a previously taken snapshot:
           Disable-BasicAuthForAppServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\EnableBasicAuthForAppServices\AppServicesWithoutBasicAuthDisabled.csv

        To know more about the options supported by the remediation command, execute:
        Get-Help Disable-BasicAuthForAppServices -Detailed

    To roll back:
        1. To enable disable FTP and SCM basic authentication on the production slot and all non-production slots of all App Services in a Subscription, from a previously taken snapshot:
           Enable-BasicAuthForAppServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\EnableBasicAuthForAppServices\RemediatedAppServices.csv
        
        To know more about the options supported by the roll back command, execute:
        Get-Help Enable-BasicAuthForAppServices -Detailed        
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
    $requiredModules = @("Az.Accounts", "Az.Resources", "Az.Websites")

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

function Disable-BasicAuthForAppServices
{
    <#
        .SYNOPSIS
        Remediates '' Control.

        .DESCRIPTION
        Remediates 'Azure_AppService_AuthN_FTP_and_SCM_Access_Disable_Basic_Auth' Control.
        AppService must not use basic authentication for FTP and SCM access.
        
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
        None. You cannot pipe objects to Disable-BasicAuthForAppServices.

        .OUTPUTS
        None. Disable-BasicAuthForAppServices does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Disable-BasicAuthForAppServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        .EXAMPLE
        PS> Disable-BasicAuthForAppServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        .EXAMPLE
        PS> Disable-BasicAuthForAppServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202201011212\DisableBasicAuthForAppServices\AppServicesWithoutBasicAuthDisabled.csv

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
    Write-Host "[Step 1 of 4] Prepare to disable Basic Auth for App Services in Subscription: [$($SubscriptionId)]"
    Write-Host $([Constants]::SingleDashLine)

    if ($PerformPreReqCheck)
    {
        try
        {
            Write-Host "Setting up prerequisites..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            Setup-Prerequisites
            Write-Host "Completed setting up prerequisites." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
        }
        catch
        {
            Write-Host "Error occurred while setting up prerequisites. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
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

    Write-Host "To disable Basic Auth for App Services in a Subscription, Contributor or higher privileges on the App Services are required." -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "[Step 2 of 4] Fetch all App Services"
    Write-Host $([Constants]::SingleDashLine)

    $appServicesResourceType = "Microsoft.Web/sites"
    $appServiceResources = @()

    # To keep track of remediated and skipped resources
    $logRemediatedResources = @()
    $logSkippedResources=@()

    # Control Id
    $controlIds = "Azure_AppService_AuthN_FTP_and_SCM_Access_Disable_Basic_Auth"

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
                Write-Host "Valid resource id(s) not found in input json file. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host "Skipping the Resource: [$($_.ResourceName)]..."
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
                Write-Host "Input file: [$($FilePath)] not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
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
                    Write-Host "Fetching App Service resource: Resource ID: [$($resourceId)]. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
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

    # Includes App Services where Basic Auth is disabled on all slots - production slot and all non-production slots.
    $appServicesWithBasicAuthDisabled = @()

    # Includes App Services where Remote Debugging is not disabled on all slots - production slot or one or more non-production slots.
    $appServicesWithoutBasicAuthDisabled = @()

    # Includes App Services that were skipped during remediation. There were errors remediating them.
    $appServicesSkipped = @()

    Write-Host "[Step 3 of 4] Fetch all App Service configurations"
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

            $isFTPBasicAuthDisabledOnProductionSlot = -not (Get-FTPAuthSetting -resourceId $resourceId)
            $isSCMBasicAuthDisabledOnProductionSlot = -not (Get-SCMAuthSetting -resourceId $resourceId)
            $isBasicAuthDisabledOnProductionSlot = $isFTPBasicAuthDisabledOnProductionSlot -and $isSCMBasicAuthDisabledOnProductionSlot

            Write-Host "App Service Configurations successfully fetched." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)

            Write-Host "Fetching non-production slot configurations for App Service: Resource ID: [$($resourceId)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            # Get all non-production slots for this App Service.
            $nonProductionSlotConfigurations = (Get-AzWebAppSlot -ResourceGroupName $resourceGroupName -Name $resourceName)
            Write-Host "App Service non-production slot configuration successfully fetched." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
            $nonProductionSlotsWithoutBasicAuthDisabled = @()
            $nonProductionSlotsWithoutBasicAuthDisabledStr = [String]::Empty
            $nonProductionSlotsWithoutFTPBasicAuthDisabled = @()
            $nonProductionSlotsWithoutFTPBasicAuthDisabledStr = [String]::Empty
            $nonProductionSlotsWithoutSCMBasicAuthDisabled = @()
            $nonProductionSlotsWithoutSCMBasicAuthDisabledStr = [String]::Empty

            $isBasicAuthDisabledOnAllNonProductionSlots = $true;
            foreach($slot in $nonProductionSlotConfigurations){
                #$isBasicAuthDisabledOnAllNonProductionSlots = $true;
                #$slotName = $slot.name.Split('/')[1]
                #$resource = Get-AzWebAppSlot -ResourceGroupName $resourceGroupName -Name $resourceName -Slot $slotName
                #$isBasicAuthDisabled = Get-FTPAuthSetting -resourceId $slot.Id -or Get-SCMAuthSetting -resourceId $slot.Id 
                $isFTPBasicAuthDisabled = -not (Get-FTPAuthSetting -resourceId $slot.Id)
                $isSCMBasicAuthDisabled = -not (Get-SCMAuthSetting -resourceId $slot.Id)

                $isbasicAuthDisabled = $isFTPBasicAuthDisabled -and $isSCMBasicAuthDisabled
                if($isbasicAuthDisabled -eq $false)
                {
                    $slot| Add-Member -NotePropertyName isFTPBasicAuthDisabled -NotePropertyValue $isFTPBasicAuthDisabled
                    $slot| Add-Member -NotePropertyName isSCMBasicAuthDisabled -NotePropertyValue $isSCMBasicAuthDisabled
                  
                    $nonProductionSlotsWithoutBasicAuthDisabled += $slot
                    $isBasicAuthDisabledOnAllNonProductionSlots = $false
                    
                }
                
                if($isFTPBasicAuthDisabled -eq $false)
                {
                    $nonProductionSlotsWithoutFTPBasicAuthDisabled += $slot
                }
                if($isSCMbasicAuthDisabled -eq $false)
                {
                    $nonProductionSlotsWithoutSCMBasicAuthDisabled += $slot
                }
            }
            if ($isBasicAuthDisabledOnProductionSlot -and $isBasicAuthDisabledOnAllNonProductionSlots)
            {
                $appServicesWithBasicAuthDisabled += $appServiceResource
                Write-Host "Basic Auth is disabled on the production slot and all non-production slots in the App Service: Resource ID: [$($resourceId)]" -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host "Skipping App Service $($_.ResourceName)..." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                $logResource.Add("ResourceName",($_.ResourceName))
                $logResource.Add("Reason","Basic Auth is disabled on the production slot and all non-production slots in the App Service.")    
                $logSkippedResources += $logResource
            }
            else 
            {
                if (-not $isBasicAuthDisabledOnProductionSlot)
                {
                    Write-Host "Basic Auth is enabled on the production slot." -ForegroundColor $([Constants]::MessageType.Warning)
                    Write-Host $([Constants]::SingleDashLine)
                }

                if(-not $isBasicAuthDisabledOnAllNonProductionSlots){
                    $nonProductionSlotsWithoutBasicAuthDisabled = $nonProductionSlotsWithoutBasicAuthDisabled.Name
                    $nonProductionSlotsWithoutBasicAuthDisabledStr = $($nonProductionSlotsWithoutBasicAuthDisabled -join ', ')
                    $nonProductionSlotsWithoutFTPBasicAuthDisabled = $nonProductionSlotsWithoutFTPBasicAuthDisabled.Name
                    $nonProductionSlotsWithoutFTPBasicAuthDisabledStr = $($nonProductionSlotsWithoutFTPBasicAuthDisabled -join ', ')
                    $nonProductionSlotsWithoutSCMBasicAuthDisabled = $nonProductionSlotsWithoutSCMBasicAuthDisabled.Name
                    $nonProductionSlotsWithoutSCMBasicAuthDisabledStr = $($nonProductionSlotsWithoutSCMBasicAuthDisabled -join ', ')
                    Write-Host "Basic Auth is enabled on these non-production slots: [$($nonProductionSlotsWithoutBasicAuthDisabledStr)]" -ForegroundColor $([Constants]::MessageType.Warning)
                    Write-Host $([Constants]::SingleDashLine)
                }

                $appServicesWithoutBasicAuthDisabled += $appServiceResource | Select-Object @{N='ResourceID';E={$resourceId}},
                                                                                    @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                                    @{N='ResourceName';E={$resourceName}},
                                                                                    @{N='IsBasicAuthDisabledOnProductionSlot';E={$isBasicAuthDisabledOnProductionSlot}},
                                                                                    @{N='IsFTPBasicAuthDisabledOnProductionSlot';E={$isFTPBasicAuthDisabledOnProductionSlot}},
                                                                                    @{N='IsSCMBasicAuthDisabledOnProductionSlot';E={$isSCMBasicAuthDisabledOnProductionSlot}},
                                                                                    @{N='IsBasicAuthDisabledOnAllNonProductionSlots';E={$isBasicAuthDisabledOnAllNonProductionSlots}},
                                                                                    @{N='NonProductionSlotsWithoutBasicAuthDisabled';E={$nonProductionSlotsWithoutBasicAuthDisabledStr}},
                                                                                    @{N='NonProductionSlotsWithoutFTPBasicAuthDisabled';E={$nonProductionSlotsWithoutFTPBasicAuthDisabledStr}},
                                                                                    @{N='NonProductionSlotsWithoutSCMBasicAuthDisabled';E={$nonProductionSlotsWithoutSCMBasicAuthDisabledStr}}
            }
        }
        catch
        {
            $appServicesSkipped += $appServiceResource
            Write-Host "Error fetching App Service configuration: Resource ID: [$($resourceId)], Resource Group Name: [$($resourceGroupName)], Resource Name: [$($resourceName)]. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
            $logResource = @{}
            $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
            $logResource.Add("ResourceName",($_.ResourceName))
            $logResource.Add("Reason","Encountered error while fetching app service configuration")    
            $logSkippedResources += $logResource
            Write-Host "Skipping this resource..." -ForegroundColor $([Constants]::MessageType.Warning)
        }
    }

    $totalAppServicesWithoutBasicAuthDisabled = ($appServicesWithoutBasicAuthDisabled | Measure-Object).Count

    if ($totalAppServicesWithoutBasicAuthDisabled -eq 0)
    {
        Write-Host "No App Service(s) found with Basic Auth enabled. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)
        if($AutoRemediation -and ($appServicesWithBasicAuthDisabled|Measure-Object).Count -gt 0) 
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

    Write-Host "Found [$($totalAppServicesWithoutBasicAuthDisabled)] out of [$($totalAppServices)] App Service(s) with Basic Authentication enabled." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)
    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\DisableBasicAuthForAppServices"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }

    if (-not $DryRun)
    {
        if(-not $SkipBackup)
        {
            Write-Host "Backing up App Services details to [$($backupFolderPath)]..." -ForegroundColor $([Constants]::MessageType.Info)
            $backupFile = "$($backupFolderPath)\AppServicesWithoutBasicAuthDisabled.csv"
            $appServicesWithoutBasicAuthDisabled | Export-CSV -Path $backupFile -NoTypeInformation
            Write-Host "App Services details have been backed up to [$($backupFile)]." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
        }
        Write-Host "Basic Auth will be disabled on the production slot and all non-production slots for all App Services." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)

        # Here AutoRemediation switch is used as there is no need to take user input at BRS level if user has given consent to proceed with the remediation in AutoRemediation Script.
        if(-not $AutoRemediation)
        {
            if (-not $Force)
            {
                Write-Host "Do you want to disable Basic Auth on the production slot and all non-production slots for all App Services? " -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
                
                $userInput = Read-Host -Prompt "(Y|N)"
                Write-Host $([Constants]::SingleDashLine)
                if($userInput -ne "Y")
                {
                    Write-Host "Basic Auth will not be disabled for any App Service. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
                    Write-Host $([Constants]::SingleDashLine)
                    return
                }
                Write-Host "User has provided consent to disable Basic Auth on the production slot and all non-production slots for all App Services." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
            }
            else
            {
                Write-Host "'Force' flag is provided. BasicAuth will be disabled on the production slot and all non-production slots for all App Services without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }
        }

        Write-Host "[Step 4 of 4] Disable Basic Auth for App Services"
        Write-Host $([Constants]::SingleDashLine)
        # To hold results from the remediation.
        $appServicesRemediated = @()
        $appServicesSkipped = @()

        $appServicesWithoutBasicAuthDisabled | ForEach-Object {
            $appService = $_
            $resourceId = $_.ResourceID
            $resourceGroupName = $_.ResourceGroupName
            $resourceName = $_.ResourceName
            $isBasicAuthDisabledOnProductionSlot = $_.isBasicAuthDisabledOnProductionSlot
            $isBasicAuthDisabledOnAllNonProductionSlots = $_.isBasicAuthDisabledOnAllNonProductionSlots
            $nonProductionSlotsWithoutBasicAuthDisabled = $_.NonProductionSlotsWithoutBasicAuthDisabled

            Write-Host "Disabling Basic Auth for App Service: Resource ID: [$($resourceId)], Resource Group Name: [$($resourceGroupName)], Resource Name: [$($resourceName)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            $nonProductionSlotsWithoutBasicAuthDisabledStr = $nonProductionSlotsWithoutBasicAuthDisabled -join ','
            $isBasicAuthDisabledOnProdSlotPostRemediation = $isBasicAuthDisabledOnProductionSlot
            
            # Reset the status further down, as appropriate.
            $appService | Add-Member -NotePropertyName NonProductionSlotsSkipped -NotePropertyValue $nonProductionSlotsWithoutBasicAuthDisabledStr
            $appService | Add-Member -NotePropertyName IsBasicAuthDisabledOnProductionSlotPostRemediation -NotePropertyValue $isBasicAuthDisabledOnProdSlotPostRemediation

            # If Basic Auth is not disabled on the production slot
            if (-not [System.Convert]::ToBoolean($isBasicAuthDisabledOnProductionSlot))
            {
                try
                {
                    Write-Host "Disabling Basic Auth on the production slot..." -ForegroundColor $([Constants]::MessageType.Info)
                    Write-Host $([Constants]::SingleDashLine)
                    $resource = Get-AzWebApp -ResourceGroupName $resourceGroupName -Name $resourceName
                    
                    $updateFTPBasicAuth = -not (Update-FTPAuthSetting -resourceId $resource.Id -allow $false)
                    $updateSCMBasicAuth = -not (Update-SCMAuthSetting -resourceId $resource.Id -allow $false)

                    $isBasicAuthDisabledOnProductionSlot = $updateFTPBasicAuth -and $updateSCMBasicAuth

                    if ($isBasicAuthDisabledOnProductionSlot)
                    {
                        $appService.IsBasicAuthDisabledOnProductionSlotPostRemediation = $true
                        Write-Host "Successfully disabled basic authentication on the production slot." -ForegroundColor $([Constants]::MessageType.Update)
                        Write-Host $([Constants]::SingleDashLine)
                    }
                    else
                    {
                        $appServicesSkipped += $appService
                        $logResource = @{}
                        $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                        $logResource.Add("ResourceName",($_.ResourceName))
                        $logResource.Add("Reason", "Error disabling basic authentication on the production slot. Skipping this App Service. Basic Auth will not be disabled for any of the non-production slots.")
                        $logSkippedResources += $logResource
                        Write-Host "Error disabling basic authentication on the production slot." -ForegroundColor $([Constants]::MessageType.Error)
                        Write-Host "Skipping this App Service. Basic Auth will not be disabled for any of the non-production slots." -ForegroundColor $([Constants]::MessageType.Warning)
                        Write-Host $([Constants]::SingleDashLine)
                        return;
                    }
                }
                catch
                {
                    $appServicesSkipped += $appService
                    $logResource = @{}
                    $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                    $logResource.Add("ResourceName",($_.ResourceName))
                    $logResource.Add("Reason", "Error disabling Basic Auth  on the production slot. Skipping this App Service. Basic Auth will not be disabled for any of the non-production slots.")
                    $logSkippedResources += $logResource
                    Write-Host "Error disabling Basic auth on the production slot." -ForegroundColor $([Constants]::MessageType.Error)
                    Write-Host "Skipping this App Service. Basic auth will not be disabled for any of the non-production slots." -ForegroundColor $([Constants]::MessageType.Warning)
                    Write-Host $([Constants]::SingleDashLine)
                    return
                }
            }

            # Holds the list of non-production slots without Basic Auth disabled.
            $nonProductionSlotsSkipped = @()
            $nonProductionSlotsSkippedStr = [String]::Empty

            if (-not [System.Convert]::ToBoolean($isBasicAuthDisabledOnAllNonProductionSlots))
            {
                foreach ($slot in $nonProductionSlotsWithoutBasicAuthDisabled.Split(','))
                {
                    $isBasicAuthDisabledOnNonProductionSlot = $false
                    $FTPBasicAuth = $false
                    $SCMBasicAuth = $false

                    # Slot names are of the form: app-service-name/slot-name
                     $slotName = $slot.Split('/')[1]
                    try
                    {
                        Write-Host "Disabling Basic Auth on the non-production slot: [$($slot)]..." -ForegroundColor $([Constants]::MessageType.Info)
                        Write-Host $([Constants]::SingleDashLine)
                        $resource = Get-AzWebAppSlot -ResourceGroupName $resourceGroupName -Name $resourceName -Slot $slotName
                        #$resource.SiteConfig.BasicAuthEnabled = $false
                        
                        # Holding output of set command to avoid unnecessary logs.
                        $FTPBasicAuth = -not (Update-FTPAuthSetting -resourceId $resource.Id -allow $false)
                        $SCMBasicAuth = -not (Update-SCMAuthSetting -resourceId $resource.Id -allow $false)

                        $isBasicAuthDisabledOnNonProductionSlot = $FTPBasicAuth -and $SCMBasicAuth
                       
                        if($isBasicAuthDisabledOnNonProductionSlot){
                            Write-Host "Successfully disabled basic auth on the non-production slot." -ForegroundColor $([Constants]::MessageType.Update)
                            Write-Host $([Constants]::SingleDashLine)
                        }else{
                            $nonProductionSlotsSkipped += $slot
                            Write-Host "Error disabling basic auth on the non-production slot." -ForegroundColor $([Constants]::MessageType.Error)
                            Write-Host $([Constants]::SingleDashLine)
                        }
                        
                    }
                    catch
                    {
                        $nonProductionSlotsSkipped += $slot
                        Write-Host "Error disabling basic auth on the non-production slot." -ForegroundColor $([Constants]::MessageType.Error)
                        Write-Host $([Constants]::SingleDashLine)
                    }
                }
            }
            
            $nonProductionSlotsSkippedStr = $nonProductionSlotsSkipped -join ','
            $appService.NonProductionSlotsSkipped = $nonProductionSlotsSkippedStr

            if ($($nonProductionSlotsSkipped | Measure-Object).Count -eq 0)
            {
                $appService.isBasicAuthDisabledOnAllNonProductionSlots = $true
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                $logResource.Add("ResourceName",($_.ResourceName))
                $logRemediatedResources += $logResource
                $appServicesRemediated += $appService
                Write-Host "Successfully disabled basic auth on production and all non-production slots for the App Service." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
            }
            else
            {
                $appServicesSkipped += $appService
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                $logResource.Add("ResourceName",($_.ResourceName))
                $logResource.Add("Reason", "Error disabling basic auth for these non-production slots: [$($nonProductionSlotsSkippedStr)]")
                $logSkippedResources += $logResource
                Write-Host "Error disabling basic auth for these non-production slots: [$($nonProductionSlotsSkippedStr)]" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host $([Constants]::SingleDashLine)
                
            }
        }

        # Write-Host $([Constants]::SingleDashLine)

        if (($appServicesRemediated | Measure-Object).Count -eq $totalAppServicesWithoutBasicAuthDisabled)
        {
            Write-Host "Basic auth successfully disabled on the production slot and all non-production slots for all [$($totalAppServicesWithoutBasicAuthDisabled)] App Service(s)." -ForegroundColor $([Constants]::MessageType.Update)
            
        }
        else
        {
            Write-Host "Basic auth successfully disabled on the production slot and all non-production slots for [$($($appServicesRemediated | Measure-Object).Count)] out of [$($totalAppServicesWithoutBasicAuthDisabled)] App Service(s)." -ForegroundColor $([Constants]::MessageType.Warning)
        }

        $colsProperty = @{Expression={$_.ResourceId};Label="Resource ID";Width=40;Alignment="left"},
                        @{Expression={$_.ResourceGroupName};Label="Resource Group Name";Width=20;Alignment="left"},
                        @{Expression={$_.ResourceName};Label="Resource Name";Width=20;Alignment="left"},
                        @{Expression={$_.isBasicAuthDisabledOnProductionSlot};Label="Is Basic Auth disabled on the production slot - Prior to remediation?";Width=20;Alignment="left"},
                        @{Expression={$_.IsBasicAuthDisabledOnProductionSlotPostRemediation};Label="Is Basic Auth disabled on the production slot - Post remediation?";Width=20;Alignment="left"},
                        @{Expression={$_.isBasicAuthDisabledOnAllNonProductionSlots};Label="Is Basic Auth disabled on all the non-production slots?";Width=20;Alignment="left"},
                        @{Expression={$_.NonProductionSlotsWithoutBasicAuthDisabled};Label="Non-production slots without Basic Auth disabled - Prior to remediation";Width=40;Alignment="left"},
                        @{Expression={$_.NonProductionSlotsSkipped};Label="Non-production slots without Basic Auth disabled - Post remediation";Width=40;Alignment="left"}

        Write-Host $([Constants]::DoubleDashLine)
        if($AutoRemediation){
            if ($($appServicesRemediated | Measure-Object).Count -gt 0)
            {
                # Write this to a file.
                $appServicesRemediatedFile = "$($backupFolderPath)\RemediatedAppServicesFordisabledBasicAuth.csv"
                $appServicesRemediated | Export-CSV -Path $appServicesRemediatedFile -NoTypeInformation
                Write-Host "The information related to App Service(s) where Basic Auth successfully disabled has been saved to [$($appServicesRemediatedFile)]. Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }

            if ($($appServicesSkipped | Measure-Object).Count -gt 0)
            {   
                # Write this to a file.
                $appServicesSkippedFile = "$($backupFolderPath)\SkippedAppServicesForDisableBasicAuth.csv"
                $appServicesSkipped | Export-CSV -Path $appServicesSkippedFile -NoTypeInformation
                Write-Host "The information related to App Service(s) where Basic Auth not disabled has been saved to [$($appServicesSkippedFile)]." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }
        }else{
            Write-Host "Remediation Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)
        
            if ($($appServicesRemediated | Measure-Object).Count -gt 0)
            {
                
                Write-Host "Basic auth successfully disabled for the following App Service(s):" -ForegroundColor $([Constants]::MessageType.Update)
                $appServicesRemediated | Format-Table -Property $colsProperty -Wrap
                Write-Host $([Constants]::SingleDashLine)
                # Write this to a file.
                $appServicesRemediatedFile = "$($backupFolderPath)\RemediatedAppServicesForDisabledBasicAuth.csv"
                $appServicesRemediated | Export-CSV -Path $appServicesRemediatedFile -NoTypeInformation
                Write-Host "This information has been saved to [$($appServicesRemediatedFile)]." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }

            if ($($appServicesSkipped | Measure-Object).Count -gt 0)
            {
                Write-Host "Error disabling Basic Auth for the following App Service(s):" -ForegroundColor $([Constants]::MessageType.Error)
                $appServicesSkipped | Format-Table -Property $colsProperty -Wrap
                Write-Host $([Constants]::SingleDashLine)
                # Write this to a file.
                $appServicesSkippedFile = "$($backupFolderPath)\SkippedAppServicesForDisableBasicAuth.csv"
                $appServicesSkipped | Export-CSV -Path $appServicesSkippedFile -NoTypeInformation
                Write-Host "This information has been saved to [$($appServicesSkippedFile)]." -ForegroundColor $([Constants]::MessageType.Warning)
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
            $log | ConvertTo-json -depth 10  | Out-File $logFile
        }
    }
    else
    {
        Write-Host "[Step 4 of 4] Back up App Services details"
        Write-Host $([Constants]::SingleDashLine)
        # Backing up App Services details.
        $backupFile = "$($backupFolderPath)\AppServicesWithoutBasicAuthDisabled.csv"
        $appServicesWithoutBasicAuthDisabled | Export-CSV -Path $backupFile -NoTypeInformation
        Write-Host "App Services details have been backed up to [$($backupFile)]. Please review before remediating them." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Next steps: " -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host "Run the same command with -FilePath $($backupFile) and without -DryRun, to disable Basic auth for all App Services (across the production slot and all non-production slots) listed in the file." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }   
}

function Enable-BasicAuthForAppServices
{
    <#
        .SYNOPSIS
        Rolls back remediation done for 'Azure_AppService_AuthN_FTP_and_SCM_Access_Disable_Basic_Auth' Control.

        .DESCRIPTION
        Rolls back remediation done for 'Azure_AppService_AuthN_FTP_and_SCM_Access_Disable_Basic_Auth' Control.
        Enables Basic Auth on the production slot and all non-production slots in all App Services in the Subscription as per input file. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that was previously remediated.
        
        .PARAMETER Force
        Specifies a forceful roll back without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
        
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the roll back.

        .INPUTS
        None. You cannot pipe objects to Enable-BasicAuthForAppServices.

        .OUTPUTS
        None. Enable-BasicAuthForAppServices does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Enable-BasicAuthForAppServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\DisableBasicAuthForAppServices\RemediatedAppServices.csv

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
    Write-Host "[Step 1 of 3] Prepare to enable Basic Auth for App Services in Subscription: [$($SubscriptionId)]"
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
            Write-Host "Error occurred while setting up prerequisites. Error: [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
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

    Write-Host "To enable Basic Auth for App Services in a Subscription, Contributor or higher privileges on the App Services are required." -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "[Step 2 of 3] Fetch all App Services."
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

    $totalAppServices = ($validAppServiceDetails | Measure-Object).Count

    if ($totalAppServices -eq 0)
    {
        Write-Host "No App Services found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        return
    }

    Write-Host "Found [$($totalAppServices)] App Service(s)." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)
    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\EnableBasicAuthForAppServices"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
    
    if (-not $Force)
    {
        Write-Host "Do you want to enable Basic Auth on the production slot and all non-production slots for all App Services? " -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
            
        $userInput = Read-Host -Prompt "(Y|N)"
        Write-Host $([Constants]::SingleDashLine)
        if($userInput -ne "Y")
        {
            Write-Host "Basic Auth will not be enabled for any App Service. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
            return
        }
        Write-Host "User has provided consent to enable Basic Auth on the production slot and all non-production slots for all App Services." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }
    else
    {
        Write-Host "'Force' flag is provided. Basic Auth will be enabled on the production slot and all non-production slots for all App Services without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
        Write-Host $([Constants]::SingleDashLine)
    }

    Write-Host "[Step 3 of 3] Enable Basic Auth for App Services"
    Write-Host $([Constants]::SingleDashLine)
    # Includes App Services, to which, previously made changes were successfully rolled back.
    $appServicesRolledBack = @()

    # Includes App Services that were skipped during roll back. There were errors rolling back the changes made previously.
    $appServicesSkipped = @()

    $validAppServiceDetails | ForEach-Object {
        $appService = $_
        $resourceId = $appService.ResourceId
        $resourceGroupName = $appService.ResourceGroupName
        $resourceName = $appService.ResourceName
        $nonProdSlots = $appService.NonProductionSlotsWithoutBasicAuthDisabled
        $isBasicAuthDisabled = $appService.IsBasicAuthDisabledOnProductionSlotPostRemediation
        $isFTPBasicAuthDisabledOnProductionSlot = $appService.IsFTPBasicAuthDisabledOnProductionSlot	
        $isSCMBasicAuthDisabledOnProductionSlot = $appService.IsSCMBasicAuthDisabledOnProductionSlot

        $nonProductionSlotsWithoutBasicAuthDisabled = $appService.NonProductionSlotsWithoutBasicAuthDisabled
        $nonProductionSlotsWithoutFTPBasicAuthDisabled = $appService.NonProductionSlotsWithoutFTPBasicAuthDisabled
        $nonProductionSlotsWithoutSCMBasicAuthDisabled = $appService.NonProductionSlotsWithoutSCMBasicAuthDisabled



        try
        {
            Write-Host "Fetching App Service configuration: Resource ID: [$($resourceId)], Resource Group Name: [$($resourceGroupName)], Resource Name: [$($resourceName)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)

            if ($isBasicAuthDisabled -eq $false)
            {
                Write-Host "Basic Auth is already enabled on the production slot." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host "Skipping this App Service. If required, manually enable Basic Auth on the production slots." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
                #return
            }

            if ($isBasicAuthDisabled)
            {
                $resource = Get-AzWebApp -ResourceGroupName $resourceGroupName -Name $resourceName
                $updateFTPBasicAuth = $false
                $updateSCMBasicAuth = $false

                if($isFTPBasicAuthDisabledOnProductionSlot -eq "false")
                {   
                    $updateFTPBasicAuth = (Update-FTPAuthSetting -resourceId $resource.Id -allow $true)
                }
                if($isSCMBasicAuthDisabledOnProductionSlot -eq "false"){
                    
                    $updateSCMBasicAuth = (Update-SCMAuthSetting -resourceId $resource.Id -allow $true)
                }

                $isBasicAuthDisabledOnProductionSlot = $updateFTPBasicAuth -or $updateSCMBasicAuth
                
                if (-not $isBasicAuthDisabledOnProductionSlot)
                {
                    $appServicesSkipped += $appService
                    Write-Host "Error enabling Basic Auth on the production slot." -ForegroundColor $([Constants]::MessageType.Error)
                    Write-Host "Skipping this App Service. If required, manually enable Basic Auth on the non-production slots." -ForegroundColor $([Constants]::MessageType.Warning)
                    return
                }
            }

            Write-Host "Successfully enabled Basic Auth on the production slot." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)

            # Reset the states further below, as appropriate.
            $appService | Add-Member -NotePropertyName IsBasicAuthDisabledOnAllNonProductionSlot -NotePropertyValue $false
            $appService | Add-Member -NotePropertyName NonProductionSlotsWithBasicAuthDisabled -NotePropertyValue ([String]::Empty)

            Write-Host "Fetching non-production slot configurations for App Service: Resource ID: [$($resourceId)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)

            $nonProductionSlotConfigurations = @()
            $nonProductionSlotsWithBasicAuthDisabled =@()
            $nonProductionSlotsWithoutBasicAuthDisabled =@()
            $isBasicAuthEnabledOnAllNonProductionSlots = $true
            if ([String]::IsNullOrWhiteSpace($nonProdSlots))
            {
                $isNonProdSlotAvailable = $false
            }
            else
            {
                $isNonProdSlotAvailable = $true
                foreach ($slot in $nonProdSlots.Split(','))
                {
                    $nonProductionSlotConfiguration = Get-AzWebAppSlot -ResourceGroupName $resourceGroupName -Name $resourceName -Slot $slot.Split('/')[1]
                    $nonProductionSlotConfigurations += $nonProductionSlotConfiguration
                    $isFTPBasicAuthDisabled = Get-FTPAuthSetting -resourceId $nonProductionSlotConfiguration.Id
                    $isSCMBasicAuthDisabled = Get-SCMAuthSetting -resourceId $nonProductionSlotConfiguration.Id

                    $isbasicAuthDisabled = $isFTPBasicAuthDisabled -and $isSCMBasicAuthDisabled

                    if($isBasicAuthDisabled){
                        $isBasicAuthEnabledOnAllNonProductionSlots = $false
                        $nonProductionSlotsWithBasicAuthDisabled += $nonProductionSlotConfiguration.Name
                    }else{
                        $nonProductionSlotsWithoutBasicAuthDisabled += $nonProductionSlotConfiguration.Name
                    }
                    $isBasicAuthEnabledOnAllNonProductionSlots = $false
                        $nonProductionSlotsWithBasicAuthDisabled += $nonProductionSlotConfiguration.Name
                }
            }

            # All non-production slots have Basic Auth enabled.
            if ($isBasicAuthEnabledOnAllNonProductionSlots -or -not $isNonProdSlotAvailable)
            {
                $appServicesRolledBack += $appService
                Write-Host "Basic Auth is enabled on all non-production slots in the App Service." -ForegroundColor $([Constants]::MessageType.Update)
                return
            }

            $appService.IsBasicAuthDisabledOnAllNonProductionSlot = $true

            # Holds the list of non-production slots with Basic Auth disabled.
            $nonProductionSlotsWithBasicAuthDisabledStr = $($nonProductionSlotsWithBasicAuthDisabled -join ', ')
            $appService.NonProductionSlotsWithBasicAuthDisabled = $nonProductionSlotsWithBasicAuthDisabledStr

            # Holds the running list of non-production slots with Basic Auth disabled. Remove slots from this list as Basic Auth is being enabled on them.
            $nonProductionSlotsSkipped = $nonProductionSlotsWithBasicAuthDisabled
            $nonProductionSlotsSkippedStr = $($nonProductionSlotsWithBasicAuthDisabled -join ', ')
            $appService.NonProductionSlotsSkipped = $nonProductionSlotsSkippedStr
            $appService.NonProductionSlotsWithBasicAuthDisabled = $nonProductionSlotsSkippedStr

            Write-Host "Basic Auth is disabled on these non-production slots: [$($nonProductionSlotsWithBasicAuthDisabledStr)]" -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
            $nonProductionSlotsSkipped = @()
            foreach($slot in $nonProductionSlotsWithBasicAuthDisabled)
            {
                # Slot names are of the form: app-service-name/slot-name
                $slotName = $slot.Split('/')[1]

                try
                {
                    Write-Host "Enabling Basic Auth on the non-production slot: [$($slot)]..." -ForegroundColor $([Constants]::MessageType.Info)
                    Write-Host $([Constants]::SingleDashLine)
                    $resource = Get-AzWebAppSlot -ResourceGroupName $resourceGroupName -Name $resourceName -Slot $slotName
                    if($nonProductionSlotsWithoutFTPBasicAuthDisabled -contains $slot){
                       $updateFTPBasicAuth = Update-FTPAuthSetting -resourceId $resource.Id -allow $true
                    }
                    if($nonProductionSlotsWithoutSCMBasicAuthDisabled -contains $slot){
                        $updateSCMBasicAuth = Update-SCMAuthSetting -resourceId $resource.Id -allow $true
                    }

                    $isBasicAuthEnabledOnNonProductionSlot = $updateFTPBasicAuth -or  $updateSCMBasicAuth
                   
                    if($isBasicAuthEnabledOnNonProductionSlot){
                        Write-Host "Successfully enabled Basic Auth on the non-production slot." -ForegroundColor $([Constants]::MessageType.Update)
                        Write-Host $([Constants]::SingleDashLine)
                    }
                    else{
                        $nonProductionSlotsSkipped += $slot
                        Write-Host "Error enabling Basic Auth on the non-production slot." -ForegroundColor $([Constants]::MessageType.Error)
                        Write-Host $([Constants]::SingleDashLine)
                    }
                    
                }
                catch
                {
                    $nonProductionSlotsSkipped += $slot
                    Write-Host "Error enabling Basic Auth on the non-production slot." -ForegroundColor $([Constants]::MessageType.Error)
                    Write-Host $([Constants]::SingleDashLine)
                }
            }

            $nonProductionSlotsSkippedStr = $nonProductionSlotsSkipped -join ','

            
            $isFTPBasicAuthDisabledOnProductionSlot = -not (Get-FTPAuthSetting -resourceId $resourceId)
            $isSCMBasicAuthDisabledOnProductionSlot = -not (Get-SCMAuthSetting -resourceId $resourceId)
            $isBasicAuthDisabledOnProductionSlot = $isFTPBasicAuthDisabledOnProductionSlot -and $isSCMBasicAuthDisabledOnProductionSlot
           
            $appService.IsBasicAuthDisabledOnProductionSlot = $isBasicAuthDisabledOnProductionSlot
            $appService.NonProductionSlotsSkipped = $nonProductionSlotsSkippedStr

            # Rollback of the changes previously made to an App Service is successful only if Basic Auth is enabled on the production slot and all non-production slots.
            if ($($nonProductionSlotsSkipped | Measure-Object).Count -eq 0)
            {
                $appService.IsBasicAuthDisabledOnAllNonProductionSlot = $false
                $appServicesRolledBack += $appService | Select-Object @{N='ResourceID';E={$_.ResourceId}},
                                                                        @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                        @{N='ResourceName';E={$_.ResourceName}},
                                                                        @{N='IsBasicAuthDisabledOnProductionSlot';E={$_.IsBasicAuthDisabledOnProductionSlot}},
                                                                        @{N='IsBasicAuthDisabledOnAllNonProductionSlot';E={$_.IsBasicAuthDisabledOnAllNonProductionSlot}},
                                                                        @{N='NonProductionSlotsWithBasicAuthDisabled';E={$_.NonProductionSlotsWithBasicAuthDisabled}},
                                                                        @{N='NonProductionSlotsSkipped';E={$_.NonProductionSlotsSkipped}}
            }
            else
            {
                $appServicesSkipped += $appService | Select-Object @{N='ResourceID';E={$_.ResourceId}},
                                                                        @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                        @{N='ResourceName';E={$_.ResourceName}},
                                                                        @{N='IsBasicAuthDisabledOnProductionSlot';E={$_.IsBasicAuthDisabledOnProductionSlot}},
                                                                        @{N='IsBasicAuthDisabledOnAllNonProductionSlot';E={$_.IsBasicAuthDisabledOnAllNonProductionSlot}},
                                                                        @{N='NonProductionSlotsWithBasicAuthDisabled';E={$_.NonProductionSlotsWithBasicAuthDisabled}},
                                                                        @{N='NonProductionSlotsSkipped';E={$_.NonProductionSlotsSkipped}}
            }
        }
        catch
        {
            $appServicesSkipped += $appService | Select-Object @{N='ResourceID';E={$resourceId}},
                                                                @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                @{N='ResourceName';E={$resourceName}},
                                                                @{N='IsBasicAuthDisabledOnProductionSlot';E={$isBasicAuthDisabledOnProductionSlot}},
                                                                @{N='IsBasicAuthDisabledOnAllNonProductionSlot';E={$isBasicAuthDisabledOnAllNonProductionSlot}},
                                                                @{N='NonProductionSlotsWithBasicAuthDisabled';E={$nonProductionSlotsWithBasicAuthDisabled}},
                                                                @{N='NonProductionSlotsSkipped';E={$nonProductionSlotsSkipped}}
        }
    }

    if (($appServicesSkipped | Measure-Object).Count -eq 0)
    {
        Write-Host "Basic Auth successfully enabled on the production slot and all non-production slots for all [$($totalAppServices)] App Service(s)." -ForegroundColor $([Constants]::MessageType.Update)
    }
    else
    {
        Write-Host "Basic Auth successfully enabled on the production slot and all non-production slots for [$($($appServicesRolledBack | Measure-Object).Count)] out of [$($totalAppServices)] App Service(s)." -ForegroundColor $([Constants]::MessageType.Warning)
    }

    $colsProperty = @{Expression={$_.ResourceId};Label="Resource ID";Width=40;Alignment="left"},
                    @{Expression={$_.ResourceGroupName};Label="Resource Group Name";Width=20;Alignment="left"},
                    @{Expression={$_.ResourceName};Label="Resource Name";Width=20;Alignment="left"},
                    @{Expression={$_.IsBasicAuthDisabledOnProductionSlot};Label="Is Basic Auth disabled on the production slot?";Width=20;Alignment="left"},
                    @{Expression={$_.IsBasicAuthDisabledOnAllNonProductionSlot};Label="Is Basic Auth disabled on all non-production slot?";Width=20;Alignment="left"},
                    @{Expression={$_.NonProductionSlotsWithBasicAuthDisabled};Label="Non-production slots with Basic Auth disabled - Prior to rollback";Width=40;Alignment="left"},
                    @{Expression={$_.NonProductionSlotsSkipped};Label="Non-production slots with Basic Auth disabled - Post rollback";Width=40;Alignment="left"}

    
    Write-Host $([Constants]::DoubleDashLine)
    if($($appServicesRolledBack | Measure-Object).Count -gt 0 -or $($appServicesSkipped | Measure-Object).Count -gt 0){
        Write-Host "Rollback Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)
    }
    if ($($appServicesRolledBack | Measure-Object).Count -gt 0)
    {
        Write-Host "Basic Auth successfully enabled for the following App Service(s):" -ForegroundColor $([Constants]::MessageType.Update)
        $appServicesRolledBack | Format-Table -Property $colsProperty -Wrap
        Write-Host $([Constants]::SingleDashLine)
        # Write this to a file.
        $appServicesRolledBackFile = "$($backupFolderPath)\RolledBackAppServices.csv"
        $appServicesRolledBack | Export-CSV -Path $appServicesRolledBackFile -NoTypeInformation
        Write-Host "This information has been saved to [$($appServicesRolledBackFile)]." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }

    if ($($appServicesSkipped | Measure-Object).Count -gt 0)
    {
        Write-Host "Error enabling Basic Auth for the following App Service(s):" -ForegroundColor $([Constants]::MessageType.Error)
        $appServicesSkipped | Format-Table -Property $colsProperty -Wrap
        Write-Host $([Constants]::SingleDashLine)
        # Write this to a file.
        $appServicesSkippedFile = "$($backupFolderPath)\RollbackSkippedAppServices.csv"
        $appServicesSkipped | Export-CSV -Path $appServicesSkippedFile -NoTypeInformation
        Write-Host "This information has been saved to [$($appServicesSkippedFile)]." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }   
}
function Get-FTPAuthSetting([String] $resourceId) {
    $cloudEnvironmentResourceManagerUrl = (Get-AzContext).Environment.ResourceManagerUrl
    $accessToken = Get-AzAccessToken -ResourceUrl $cloudEnvironmentResourceManagerUrl
    $header = "Bearer " + $accessToken.Token
    $headers = @{"Authorization" = $header; "Content-Type" = "application/json"; }
    [PSObject] $fTPAuthSetting = New-Object PSObject

    $getFTPAuthSettingsUri = "$($cloudEnvironmentResourceManagerUrl)$($resourceId)/basicPublishingCredentialsPolicies/ftp?api-version=2022-03-01"
    $response = Invoke-WebRequest -Method Get -Uri $getFTPAuthSettingsUri -Headers $headers -UseBasicParsing -ContentType "application/json" -ErrorAction Stop
    $fTPAuthSetting = $response.Content | ConvertFrom-Json

    $isFTPBasicAuthEnabled = $fTPAuthSetting.properties.allow

    return $isFTPBasicAuthEnabled
}
function Get-SCMAuthSetting([String] $resourceId) {
    $cloudEnvironmentResourceManagerUrl = (Get-AzContext).Environment.ResourceManagerUrl
    $accessToken = Get-AzAccessToken -ResourceUrl $cloudEnvironmentResourceManagerUrl
    $header = "Bearer " + $accessToken.Token
    $headers = @{"Authorization" = $header; "Content-Type" = "application/json"; }
    [PSObject] $fTPAuthSetting = New-Object PSObject

    $getSCMAuthSettingsUri = "$($cloudEnvironmentResourceManagerUrl)$($resourceId)/basicPublishingCredentialsPolicies/scm?api-version=2022-03-01"
    $response = Invoke-WebRequest -Method Get -Uri $getSCMAuthSettingsUri -Headers $headers -UseBasicParsing -ContentType "application/json" -ErrorAction Stop
    $fTPAuthSetting = $response.Content | ConvertFrom-Json

    $isFTPBasicAuthEnabled = $fTPAuthSetting.properties.allow

    return $isFTPBasicAuthEnabled
}

function Update-FTPAuthSetting([String] $resourceId, [Boolean] $allow) {
    $cloudEnvironmentResourceManagerUrl = (Get-AzContext).Environment.ResourceManagerUrl
    $accessToken = Get-AzAccessToken -ResourceUrl $cloudEnvironmentResourceManagerUrl
    $header = "Bearer " + $accessToken.Token
    $headers = @{"Authorization" = $header; "Content-Type" = "application/json"; }
   
    $getFTPAuthSettingsUri = "$($cloudEnvironmentResourceManagerUrl)$($resourceId)/basicPublishingCredentialsPolicies/ftp?api-version=2022-03-01"
    $response = Invoke-WebRequest -Method Get -Uri $getFTPAuthSettingsUri -Headers $headers -UseBasicParsing -ContentType "application/json" -ErrorAction Stop

    $ftpAuthSetting = $response.Content | ConvertFrom-Json
    $ftpAuthSetting.properties.allow =$allow
    $body = $ftpAuthSetting | ConvertTo-Json

    [PSObject] $ftpAuthSetting = New-Object PSObject

    #$getFTPAuthSettingsUri = "$($cloudEnvironmentResourceManagerUrl)$($resourceId)/basicPublishingCredentialsPolicies/ftp?api-version=2022-03-01"
    $response = Invoke-WebRequest -Method PUT -Uri $getFTPAuthSettingsUri -Headers $headers -Body $body -UseBasicParsing -ContentType "application/json" -ErrorAction Stop 
    $ftpAuthSetting = $response.Content | ConvertFrom-Json

    $isFTPBasicAuthEnabled = $ftpAuthSetting.properties.allow

    return $isFTPBasicAuthEnabled
}
function Update-SCMAuthSetting([String] $resourceId, [Boolean] $allow) {
    $cloudEnvironmentResourceManagerUrl = (Get-AzContext).Environment.ResourceManagerUrl
    $accessToken = Get-AzAccessToken -ResourceUrl $cloudEnvironmentResourceManagerUrl
    $header = "Bearer " + $accessToken.Token
    $headers = @{"Authorization" = $header; "Content-Type" = "application/json"; }
   
    $getSCMAuthSettingsUri = "$($cloudEnvironmentResourceManagerUrl)$($resourceId)/basicPublishingCredentialsPolicies/scm?api-version=2022-03-01"
    $response = Invoke-WebRequest -Method Get -Uri $getSCMAuthSettingsUri -Headers $headers -UseBasicParsing -ContentType "application/json" -ErrorAction Stop

    $scmAuthSetting = $response.Content | ConvertFrom-Json
    $scmAuthSetting.properties.allow =$allow
    $body = $scmAuthSetting | ConvertTo-Json

    [PSObject] $scmAuthSetting = New-Object PSObject

    #$getFTPAuthSettingsUri = "$($cloudEnvironmentResourceManagerUrl)$($resourceId)/basicPublishingCredentialsPolicies/ftp?api-version=2022-03-01"
    $response = Invoke-WebRequest -Method PUT -Uri $getSCMAuthSettingsUri -Headers $headers -Body $body -UseBasicParsing -ContentType "application/json" -ErrorAction Stop 
    $scmAuthSetting = $response.Content | ConvertFrom-Json

    $isSCMBasicAuthEnabled = $scmAuthSetting.properties.allow

    return $isSCMBasicAuthEnabled
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