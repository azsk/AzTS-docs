<###
# Overview:
    This script is used to secure FTP configuration in a Subscription.

# Control ID:
    Azure_AppService_DP_Use_Secure_FTP_Deployment

# Display Name:
    App Services should use secure FTP deployments

# Prerequisites:
    1. Contributor or higher privileges on the App Services in a Subscription.
    2. Must be connected to Azure with an authenticated account.

# Steps performed by the script:
    To remediate:
        1. Validate and install the modules required to run the script.
        2. Get the list of App Services in a Subscription that have FTP state AllAllowed configured for the production slot or for any of the non-production slots.
        3. Back up details of App Services that are to be remediated.
        4. Enable FTPS Only/Disabled under FTP State on the production slot and all non-production slots in all App Services in the Subscription.

    To roll back:
        1. Validate and install the modules required to run the script.
        2. Get the list of App Services in a Subscription, the changes made to which previously, are to be rolled back.
        3. Enable AllAllowed on the production slot and all non-production slots in all App Services in the Subscription.

# Instructions to execute the script:
    To remediate:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to Configure FTP state on the production slot and all non-production slots in all App Services in the Subscription. Refer `Examples`, below.

    To roll back:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to revert changes on FTP state on the production slot and all non-production slots in all App Services in the Subscription. Refer `Examples`, below.

# Examples:
    To remediate:
        1. To review the App Services in a Subscription that will be remediated:
           Enable-SecureFTPDeploymentForAppServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun

        2. To enable secure FTP configuration on the production slot and all non-production slots of all App Services in a Subscription:
           Enable-SecureFTPDeploymentForAppServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck

        3. To enable secure FTP configuration on the production slot and all non-production slots of all App Services in a Subscription, from a previously taken snapshot:
           Enable-SecureFTPDeploymentForAppServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\EnableSecureFTPDeploymentForAppServices\AppServicesWithNonCompliantFTPDeployment.csv

        4. To enable secure FTP configuration on the production slot and non-production slots of all App Services in a Subscription with FTP State as parameter:
           Enable-SecureFTPDeploymentForAppServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -FtpsOnly

        To know more about the options supported by the remediation command, execute:
        Get-Help Enable-SecureFTPDeploymentForAppServices -Detailed

    To roll back:
        1. To configure AllAllowed on the production slot and all non-production slots of all App Services in a Subscription, from a previously taken snapshot:
           Disable-SecureFTPDeploymentForAppServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\DisableSecureFTPDeploymentForAppServices\RemediatedAppServicesForSecuredFTPDeployment.csv
       
        To know more about the options supported by the roll back command, execute:
        Get-Help Disable-HttpsForAppServices -Detailed        
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

function Enable-SecureFTPDeploymentForAppServices
{
    <#
        .SYNOPSIS
        Remediates 'Azure_AppService_DP_Use_Secure_FTP_Deployment' Control.

        .DESCRIPTION
        Remediates 'Azure_AppService_DP_Use_Secure_FTP_Deployment' Control.
        App Services should use secure FTP deployments.
        
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

        .PARAMETER FtpsOnly
        Specifies the FTP State to be used as input for the remediation.

        .PARAMETER Disabled
        Specifies the FTP State to be used as input for the remediation.

        .INPUTS
        None. You cannot pipe objects to Enable-SecureFTPDeploymentForAppServices.

        .OUTPUTS
        None. Enable-SecureFTPDeploymentForAppServices does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Enable-SecureFTPDeploymentForAppServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -DryRun 

        .EXAMPLE
        PS> Enable-SecureFTPDeploymentForAppServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FtpsOnly

        .EXAMPLE
        PS> Enable-SecureFTPDeploymentForAppServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202201011212\EnableFTPSOnlyForAppServices\AppServicesWithFTPSOnlyEnabled.csv

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

        [Switch]
        [Parameter(ParameterSetName = "WetRun", HelpMessage="Specifies the FTP State to be configured")]
        $FtpsOnly,

        [Switch]
        [Parameter(ParameterSetName = "WetRun", HelpMessage="Specifies the FTP State to be configured")]
        $Disabled

    )

    Write-Host $([Constants]::DoubleDashLine)
    Write-Host "[Step 1 of 4] Prepare to use Secure FTP deployment for App Services in Subscription: [$($SubscriptionId)]"
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
    
    
    Write-Host "Subscription Name: [$($context.Subscription.Name)]"
    Write-Host "Subscription ID: [$($context.Subscription.SubscriptionId)]"
    Write-Host "Account Name: [$($context.Account.Id)]"
    Write-Host "Account Type: [$($context.Account.Type)]"
    Write-Host $([Constants]::SingleDashLine)
    

    Write-Host "To Enable FTP deployment for App Services in a Subscription, Contributor or higher privileges on the App Services are required." -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host $([Constants]::SingleDashLine)
    Write-Host "[Step 2 of 4] Fetch all App Services"
    Write-Host $([Constants]::SingleDashLine)

    $appServicesResourceType = "Microsoft.Web/sites"
    $appServiceResources = @()

    # To keep track of remediated and skipped resources
    $logRemediatedResources = @()
    $logSkippedResources=@()

    # Control Id
    $controlIds = "Azure_AppService_DP_Use_Secure_FTP_Deployment"

    #AllAllowed
    $AllAllowed = "AllAllowed"

    
    
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
    

    $totalAppServices = ($appServiceResources | Measure-Object).Count

    if ($totalAppServices -eq 0)
    {
        Write-Host "No App Services found. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        return
    }
  
    Write-Host "Found [$($totalAppServices)] App Service(s)." -ForegroundColor $([Constants]::MessageType.Update)
    Write-Host $([Constants]::SingleDashLine)

    # Includes App Services where AllAllowed is Enabled on all slots - production slot and all non-production slots.
    $appServicesWithAllAllowedEnabled = @()

    # Includes App Services where FTP State is not AllAlowed on all slots - production slot or one or more non-production slots.
    $appServicesWithAllAllowedDisabled = @()

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
            # Using GetAzWebApp to fetch site config for each of the App Service resource.
            $isFTPConfiguredOnProductionSlot = -not $(Get-AzWebApp -ResourceGroupName $resourceGroupName -Name $appServiceResource.Name -ErrorAction SilentlyContinue).SiteConfig.FtpsState.Contains("AllAllowed")
            Write-Host "App Service Configurations successfully fetched." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)

            Write-Host "Fetching non-production slot configurations for App Service: Resource ID: [$($resourceId)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            # Get all non-production slots for this App Service.
            $FTPConfigForNonProductionSlot = $(Get-AzWebAppSlot -ResourceGroupName $resourceGroupName -Name $resourceName)
            Write-Host "App Service non-production slot configuration successfully fetched." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
            $nonProductionSlotsWithAllAllowedEnabled = @()
            $nonProductionSlotsWithAllAllowedEnabledStr = [String]::Empty
            $isFTPConfiguredOnAllNonProductionSlots = $true;
            foreach($slot in $FTPConfigForNonProductionSlot){
                $slotName = $slot.name.Split('/')[1]
                $resource = Get-AzWebAppSlot -ResourceGroupName $resourceGroupName -Name $resourceName -Slot $slotName
                if($resource.SiteConfig.FtpsState -eq $AllAllowed)
                {
                    $nonProductionSlotsWithAllAllowedEnabled += $slot
                    $isFTPConfiguredOnAllNonProductionSlots = $false
                }
            }
            if ($isFTPConfiguredOnProductionSlot -and $isFTPConfiguredOnAllNonProductionSlots)
            {
                $appServicesWithAllAllowedDisabled += $appServiceResource
                Write-Host "FTP State is Configured on the production slot and all non-production slots in the App Service: Resource ID: [$($resourceId)]" -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host "Skipping this App Service..." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                $logResource.Add("ResourceName",($_.ResourceName))
                $logResource.Add("Reason","FTP State is configured on the production slot and all non-production slots in the App Service.")    
                $logSkippedResources += $logResource
            }
            else 
            {
                if (-not $isFTPConfiguredOnProductionSlot)
                {
                    Write-Host "FTP state is not configured on the production slot." -ForegroundColor $([Constants]::MessageType.Warning)
                    Write-Host $([Constants]::SingleDashLine)
                }

                if(-not $isFTPConfiguredOnAllNonProductionSlots){
                    $nonProductionSlotsWithAllAllowedEnabled = $nonProductionSlotsWithAllAllowedEnabled.Name
                    $nonProductionSlotsWithAllAllowedEnabledStr = $($nonProductionSlotsWithAllAllowedEnabled -join ', ')
                    Write-Host "FTP state is not configured  on these non-production slots: [$($nonProductionSlotsWithAllAllowedEnabledStr)]" -ForegroundColor $([Constants]::MessageType.Warning)
                    Write-Host $([Constants]::SingleDashLine)
                }

                $appServicesWithAllAllowedEnabled += $appServiceResource | Select-Object @{N='ResourceID';E={$resourceId}},
                                                                                    @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                                    @{N='ResourceName';E={$resourceName}},
                                                                                    @{N='IsFTPConfiguredOnProductionSlot';E={$isFTPConfiguredOnProductionSlot}},
                                                                                    @{N='IsFTPConfiguredOnAllNonProductionSlots';E={$isFTPConfiguredOnAllNonProductionSlots}},
                                                                                    @{N='NonProductionSlotsWithAllAllowedEnabled';E={$nonProductionSlotsWithAllAllowedEnabledStr}}
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

    $totalAppServicesWithFTPStateConfigured = ($appServicesWithAllAllowedEnabled | Measure-Object).Count

    if ($totalAppServicesWithFTPStateConfigured -eq 0)
    {
        Write-Host "No App Service(s) found with FTP State AllAllowed. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)
        if(($appServicesWithAllAllowedEnabled|Measure-Object).Count -gt 0) 
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

    Write-Host "Found [$($totalAppServicesWithFTPStateConfigured)] out of [$($totalAppServices)] App Service(s) with FTP state not Configured." -ForegroundColor $([Constants]::MessageType.Update)
    
    Write-Host $([Constants]::SingleDashLine)
    # Back up snapshots to `%LocalApplicationData%'.
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\EnableSecureFTPDeploymentForAppServices"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }

    if (-not $DryRun)
    {
        if(-not $SkipBackup)
        {
            Write-Host "Backing up App Services details to [$($backupFolderPath)]..." -ForegroundColor $([Constants]::MessageType.Info)
            $backupFile = "$($backupFolderPath)\AppServicesWithNonCompliantFTPDeployment.csv"
            $appServicesWithAllAllowedEnabled | Export-CSV -Path $backupFile -NoTypeInformation
            Write-Host "App Services details have been backed up to [$($backupFile)]." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
        }
        Write-Host "FTP state will be Configured on the production slot and all non-production slots for all App Services." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)

        $userInputforFTPState = @()

            if (-not $Force)
            {
                if($FtpsOnly.IsPresent -eq $true -or $Disabled.IsPresent -eq $true)
                {
                    Write-Host "FTP State is already given as Parameter. " -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
                }
                else
                {
                Write-Host "Do you want to secure FTP Deployments? " -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
                $userInput = Read-Host -Prompt "(Y|N)"
                Write-Host $([Constants]::SingleDashLine)
                if($userInput -eq "Y")
                {
                    Write-Host "User has provided consent to secure FTP Deployments on the production slot and all non-production slots for all App Services." -ForegroundColor $([Constants]::MessageType.Update)
                    Write-Host $([Constants]::SingleDashLine)
                    Write-Host "Please Select 1 for FTPSOnly or Select 2 for Disabled on the production slot and all non-production slots for all App Services? " -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
                    $userInput = Read-Host -Prompt "(1|2)"
                    Write-Host $([Constants]::SingleDashLine)

                    if($userInput -eq "1")
                    {
                        $userInputforFTPState="1"
                        Write-Host "FTPState will be FTPSOnly on the production slot and all non-production slots for all App Services." -ForegroundColor $([Constants]::MessageType.Update)
                        Write-Host $([Constants]::SingleDashLine)
                    }
                    else
                    {
                         if($userInput -eq "2")
                         {
                            $userInputforFTPState="2"
                            Write-Host "FTPState will be Disabled on the production slot and all non-production slots for all App Services." -ForegroundColor $([Constants]::MessageType.Update)
                            Write-Host $([Constants]::SingleDashLine)
                         }
                         else
                         {
                            Write-Host "User input is not correct. Exiting." -ForegroundColor $([Constants]::MessageType.Update)
                            Write-Host $([Constants]::SingleDashLine)
                            return
                         }
                    }
                }
                else
                {
                    Write-Host "FTP Deployments will not be Enabled for any App Service. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
                    Write-Host $([Constants]::SingleDashLine)
                    return
                }
                }
            }
            else
            {
              if($FtpsOnly.IsPresent -eq $true -or $Disabled.IsPresent -eq $true)
              {
                Write-Host "FTP State is already given as Parameter. " -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
                Write-Host $([Constants]::SingleDashLine)
                Write-Host "'Force' flag is provided. Securing FTP Deployments on the production slot and all non-production slots for all App Services without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
              }
              else
              {
                Write-Host "Please provide FTP State with -force. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
                return
              }
            }

        Write-Host "[Step 4 of 4] Enable Secure FTP Deployments for App Services"
        Write-Host $([Constants]::SingleDashLine)
        # To hold results from the remediation.
        $appServicesRemediated = @()
        $appServicesSkipped = @()
        
        if($FtpsOnly.IsPresent -eq $true)
        {
            $userInputforFTPState="1"
        }
        else
        {
            if($Disabled.IsPresent -eq $true)
            {
                $userInputforFTPState="2"
            }
        }
        
        $appServicesWithAllAllowedEnabled | ForEach-Object {
            $appService = $_
            $resourceId = $_.ResourceID
            $resourceGroupName = $_.ResourceGroupName
            $resourceName = $_.ResourceName
            $isFTPConfiguredOnProductionSlot = $_.isFTPConfiguredOnProductionSlot
            $isFTPConfiguredOnAllNonProductionSlots = $_.isFTPConfiguredOnAllNonProductionSlots
            $NonProductionSlotsWithAllAllowedEnabled = $_.NonProductionSlotsWithAllAllowedEnabled

            Write-Host "Securing FTP Deployment for App Service: Resource ID: [$($resourceId)], Resource Group Name: [$($resourceGroupName)], Resource Name: [$($resourceName)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            $nonProductionSlotsWithAllAllowedEnabledStr = $nonProductionSlotsWithAllAllowedEnabled -join ','
            $isFTPConfiguredOnProductionSlotPostRemediation = $isFTPConfiguredOnProductionSlot
            
            # Reset the status further down, as appropriate.
            $appService | Add-Member -NotePropertyName NonProductionSlotsSkipped -NotePropertyValue $nonProductionSlotsWithAllAllowedEnabledStr
            $appService | Add-Member -NotePropertyName isFTPConfiguredOnProductionSlotPostRemediation -NotePropertyValue $isFTPConfiguredOnProductionSlotPostRemediation

            # If FTP State is not configured on the production slot
            if (-not [System.Convert]::ToBoolean($isFTPConfiguredOnProductionSlot))
            {
                try
                {
                    Write-Host "Configuring Secure FTP Deployment on the production slot..." -ForegroundColor $([Constants]::MessageType.Info)
                    Write-Host $([Constants]::SingleDashLine)
                    $resource = Get-AzWebApp -ResourceGroupName $resourceGroupName -Name $resourceName
                    if($userInputforFTPState -eq "1"){
                        $resource.SiteConfig.FtpsState = "FtpsOnly"
                    }
                    else{
                        if($userInputforFTPState -eq "2"){
                        $resource.SiteConfig.FtpsState = "Disabled"
                        }
                    }
                    
                    # Holding output of set command to avoid unnecessary logs.
                    $temp = $resource | Set-AzWebApp -ErrorAction SilentlyContinue
                    $isFTPConfiguredOnProductionSlot = -not $(Get-AzWebApp -ResourceGroupName $resourceGroupName -Name $resourceName).SiteConfig.FtpsState.Contains("AllAllowed")

                    if ($isFTPConfiguredOnProductionSlot)
                    {
                        $appService.isFTPConfiguredOnProductionSlotPostRemediation = $true
                        Write-Host "Successfully configured the FTP State on the production slot." -ForegroundColor $([Constants]::MessageType.Update)
                        Write-Host $([Constants]::SingleDashLine)
                    }
                    else
                    {
                        $appServicesSkipped += $appService
                        $logResource = @{}
                        $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                        $logResource.Add("ResourceName",($_.ResourceName))
                        $logResource.Add("Reason", "Error in Configuring FTP State on the production slot. Skipping this App Service. FTP State will not be configured for any of the non-production slots.")
                        $logSkippedResources += $logResource
                        Write-Host "Error in Configuring FTP State on the production slot." -ForegroundColor $([Constants]::MessageType.Error)
                        Write-Host "Skipping this App Service. FTP State will not be configured for any of the non-production slots." -ForegroundColor $([Constants]::MessageType.Warning)
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
                    $logResource.Add("Reason", "Error Configuring FTP State on the production slot. Skipping this App Service. FTP State will not be configured for any of the non-production slots.")
                    $logSkippedResources += $logResource
                    Write-Host "Error Configuring FTP State on the production slot." -ForegroundColor $([Constants]::MessageType.Error)
                    Write-Host "Skipping this App Service. FTP State will not be configured for any of the non-production slots." -ForegroundColor $([Constants]::MessageType.Warning)
                    Write-Host $([Constants]::SingleDashLine)
                    return
                }
            }

            # Holds the list of non-production slots not having FTP state as AllAllowed.
            $nonProductionSlotsSkipped = @()
            $nonProductionSlotsSkippedStr = [String]::Empty

            if (-not [System.Convert]::ToBoolean($isFTPConfiguredOnAllNonProductionSlots))
            {
                foreach ($slot in $nonProductionSlotsWithAllAllowedEnabled.Split(','))
                {
                    # Slot names are of the form: app-service-name/slot-name
                    $slotName = $slot.Split('/')[1]
                    try
                    {
                        Write-Host "Configuring FTP State on the non-production slot: [$($slot)]..." -ForegroundColor $([Constants]::MessageType.Info)
                        Write-Host $([Constants]::SingleDashLine)
                        $resource = Get-AzWebAppSlot -ResourceGroupName $resourceGroupName -Name $resourceName -Slot $slotName
                        if($userInputforFTPState -eq "1")
                        {
                            $resource.SiteConfig.FtpsState = "FtpsOnly"
                        }
                        else
                        {
                        if($userInputforFTPState -eq "2")
                            {
                            $resource.SiteConfig.FtpsState = "Disabled"
                            }
                        }
                        
                        # Holding output of set command to avoid unnecessary logs.
                        $temp = $resource | Set-AzWebAppSlot -ErrorAction SilentlyContinue
                        $isFTPConfiguredOnAllNonProductionSlots = -not $(Get-AzWebAppSlot -ResourceGroupName $resourceGroupName -Name $resourceName -Slot $slotName).SiteConfig.FtpsState.Contains("AllAllowed")
                        if($isFTPConfiguredOnAllNonProductionSlots){
                            Write-Host "Successfully Configured FTP State on the non-production slot." -ForegroundColor $([Constants]::MessageType.Update)
                            Write-Host $([Constants]::SingleDashLine)
                        }else{
                            $nonProductionSlotsSkipped += $slot
                            Write-Host "Error Configuring FTP State on the non-production slot." -ForegroundColor $([Constants]::MessageType.Error)
                            Write-Host $([Constants]::SingleDashLine)
                        }
                        
                    }
                    catch
                    {
                        $nonProductionSlotsSkipped += $slot
                        Write-Host "Error Configuring FTP State on the non-production slot." -ForegroundColor $([Constants]::MessageType.Error)
                        Write-Host $([Constants]::SingleDashLine)
                    }
                }
            }
            
            $nonProductionSlotsSkippedStr = $nonProductionSlotsSkipped -join ','
            $appService.NonProductionSlotsSkipped = $nonProductionSlotsSkippedStr

            if ($($nonProductionSlotsSkipped | Measure-Object).Count -eq 0)
            {
                $appService.isFTPConfiguredOnAllNonProductionSlots = $true
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                $logResource.Add("ResourceName",($_.ResourceName))
                $logRemediatedResources += $logResource
                $appServicesRemediated += $appService
                Write-Host "Successfully Configured FTP State on production and all non-production slots for the App Service." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
            }
            else
            {
                $appServicesSkipped += $appService
                $logResource = @{}
                $logResource.Add("ResourceGroupName",($_.ResourceGroupName))
                $logResource.Add("ResourceName",($_.ResourceName))
                $logResource.Add("Reason", "Error Configuring FTP State for these non-production slots: [$($nonProductionSlotsSkippedStr)]")
                $logSkippedResources += $logResource
                Write-Host "Error Configuring FTP State for these non-production slots: [$($nonProductionSlotsSkippedStr)]" -ForegroundColor $([Constants]::MessageType.Error)
                Write-Host $([Constants]::SingleDashLine)
                
            }
        }

        # Write-Host $([Constants]::SingleDashLine)

        if (($appServicesRemediated | Measure-Object).Count -eq $totalAppServicesWithFTPStateConfigured)
        {
            Write-Host "FTP State successfully Configured on the production slot and all non-production slots for all [$($totalAppServicesWithFTPStateConfigured)] App Service(s)." -ForegroundColor $([Constants]::MessageType.Update)
            
        }
        else
        {
            Write-Host "FTP State successfully Configured on the production slot and all non-production slots for [$($($appServicesRemediated | Measure-Object).Count)] out of [$($totalAppServicesWithFTPStateConfigured)] App Service(s)." -ForegroundColor $([Constants]::MessageType.Warning)
        }

        $colsProperty = @{Expression={$_.ResourceId};Label="Resource ID";Width=40;Alignment="left"},
                        @{Expression={$_.ResourceGroupName};Label="Resource Group Name";Width=20;Alignment="left"},
                        @{Expression={$_.ResourceName};Label="Resource Name";Width=20;Alignment="left"},
                        @{Expression={$_.isFTPConfiguredOnProductionSlot};Label="Is FTP State Configured on the production slot - Prior to remediation?";Width=20;Alignment="left"},
                        @{Expression={$_.isFTPConfiguredOnProductionSlotPostRemediation};Label="Is FTP State Configured on the production slot - Post remediation?";Width=20;Alignment="left"},
                        @{Expression={$_.isFTPConfiguredOnAllNonProductionSlots};Label="Is FTP State Configured on all the non-production slots?";Width=20;Alignment="left"},
                        @{Expression={$_.nonProductionSlotsWithAllAllowedEnabled};Label="Non-production slots with FTP State not Configured - Prior to remediation";Width=40;Alignment="left"},
                        @{Expression={$_.NonProductionSlotsSkipped};Label="Non-production slots with FTP State not Configured - Post remediation";Width=40;Alignment="left"}

        Write-Host $([Constants]::DoubleDashLine)

            Write-Host "Remediation Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)
        
            if ($($appServicesRemediated | Measure-Object).Count -gt 0)
            {
                
                Write-Host "FTP State is successfully configured for the following App Service(s):" -ForegroundColor $([Constants]::MessageType.Update)
                $appServicesRemediated | Format-Table -Property $colsProperty -Wrap
                Write-Host $([Constants]::SingleDashLine)
                # Write this to a file.
                $appServicesRemediatedFile = "$($backupFolderPath)\RemediatedAppServicesForSecuredFTPDeployment.csv"
                $appServicesRemediated | Export-CSV -Path $appServicesRemediatedFile -NoTypeInformation
                Write-Host "This information has been saved to [$($appServicesRemediatedFile)]." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host "Use this file for any roll back that may be required." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }

            if ($($appServicesSkipped | Measure-Object).Count -gt 0)
            {
                Write-Host "Error configuring FTP State for the following App Service(s):" -ForegroundColor $([Constants]::MessageType.Error)
                $appServicesSkipped | Format-Table -Property $colsProperty -Wrap
                Write-Host $([Constants]::SingleDashLine)
                # Write this to a file.
                $appServicesSkippedFile = "$($backupFolderPath)\SkippedAppServicesForSecuredFTPDeployment.csv"
                $appServicesSkipped | Export-CSV -Path $appServicesSkippedFile -NoTypeInformation
                Write-Host "This information has been saved to [$($appServicesSkippedFile)]." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
            }
    }
    else
    {
        Write-Host "[Step 4 of 4] Back up App Services details"
        Write-Host $([Constants]::SingleDashLine)
        # Backing up App Services details.
        $backupFile = "$($backupFolderPath)\AppServicesWithNonCompliantFTPDeployment.csv"
        $appServicesWithAllAllowedEnabled | Export-CSV -Path $backupFile -NoTypeInformation
        Write-Host "App Services details have been backed up to [$($backupFile)]. Please review before remediating them." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Next steps: " -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host "Run the same command with -FilePath $($backupFile) and without -DryRun, to configure FTP State for all App Services (across the production slot and all non-production slots) listed in the file." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }   
}

function Disable-SecureFTPDeploymentForAppServices
{
    <#
        .SYNOPSIS
        Rolls back remediation done for 'Azure_AppService_DP_Use_Secure_FTP_Deployment' Control.

        .DESCRIPTION
        Rolls back remediation done for 'Azure_AppService_DP_Use_Secure_FTP_Deployment' Control.
        Enables FTP State not configured on the production slot and all non-production slots in all App Services in the Subscription. 
        
        .PARAMETER SubscriptionId
        Specifies the ID of the Subscription that was previously remediated.
        
        .PARAMETER Force
        Specifies a forceful roll back without any prompts.
        
        .Parameter PerformPreReqCheck
        Specifies validation of prerequisites for the command.
        
        .PARAMETER FilePath
        Specifies the path to the file to be used as input for the roll back.

        .INPUTS
        None. You cannot pipe objects to Disable-SecureFTPDeploymentForAppServices.

        .OUTPUTS
        None. Disable-SecureFTPDeploymentForAppServices does not return anything that can be piped and used as an input to another command.

        .EXAMPLE
        PS> Disable-SecureFTPDeploymentForAppServices -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -PerformPreReqCheck -FilePath C:\AzTS\Subscriptions\00000000-xxxx-0000-xxxx-000000000000\202109131040\EnableFTPSOnlyForAppServices\AppServicesWithFTPSOnlyEnabled.csv

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
    Write-Host "[Step 1 of 3] Prepare to configure secure FTP Deployments for App Services in Subscription: [$($SubscriptionId)]"
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

    $AllAllowed = "AllAllowed"

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

    Write-Host "To configure secure FTP Deployments for App Services in a Subscription, Contributor or higher privileges on the App Services are required." -ForegroundColor $([Constants]::MessageType.Warning)
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
    $backupFolderPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\Remediation\Subscriptions\$($context.Subscription.SubscriptionId.replace('-','_'))\$($(Get-Date).ToString('yyyyMMddhhmm'))\DisableSecureFTPDeploymentForAppServices"

    if (-not (Test-Path -Path $backupFolderPath))
    {
        New-Item -ItemType Directory -Path $backupFolderPath | Out-Null
    }
    
    if (-not $Force)
    {
        Write-Host "Do you want to configure NonCompliant FTP State on the production slot and all non-production slots for all App Services? " -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
            
        $userInput = Read-Host -Prompt "(Y|N)"
        Write-Host $([Constants]::SingleDashLine)
        if($userInput -ne "Y")
        {
            Write-Host "NonCompliant FTP State will not be configured for any App Service. Exiting..." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
            return
        }
        Write-Host "User has provided consent to configure NonCompliant FTP State on the production slot and all non-production slots for all App Services." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::SingleDashLine)
    }
    else
    {
        Write-Host "'Force' flag is provided. NonCompliant FTP State will be configured on the production slot and all non-production slots for all App Services without any further prompts." -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
        Write-Host $([Constants]::SingleDashLine)
    }

    Write-Host "[Step 3 of 3] configure NonCompliant FTPState for App Services"
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
        $nonProdSlots = $appService.nonProductionSlotsWithAllAllowedEnabled
        $isSecureFtpDisabled = $appService.isFTPConfiguredOnProductionSlotPostRemediation

        try
        {
            Write-Host "Fetching App Service configuration: Resource ID: [$($resourceId)], Resource Group Name: [$($resourceGroupName)], Resource Name: [$($resourceName)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)

            if ($isSecureFtpDisabled -eq $false)
            {
                Write-Host "FTP State is already NonCompliant on the production slot." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host "Skipping this App Service. If required, manually configure FTP State as AllAllowed on the non-production slots." -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
                return
            }

            if ($isSecureFtpDisabled)
            {
                $resource = Get-AzWebApp -ResourceGroupName $resourceGroupName -Name $resourceName
                $resource.SiteConfig.FtpsState = "AllAllowed"
            
                # Holding output of set command to avoid unnecessary logs.
                $temp = $resource | Set-AzWebApp -ErrorAction SilentlyContinue
                $isFTPConfiguredOnProductionSlot = -not $(Get-AzWebApp -ResourceGroupName $resourceGroupName -Name $resourceName).SiteConfig.FtpsState.Contains("AllAllowed")
                
                if ($isFTPConfiguredOnProductionSlot)
                {
                    $appServicesSkipped += $appService
                    Write-Host "Error configuring FTP State on the production slot." -ForegroundColor $([Constants]::MessageType.Error)
                    Write-Host "Skipping this App Service. If required, manually configure FTPState on the non-production slots." -ForegroundColor $([Constants]::MessageType.Warning)
                    return
                }
            }

            Write-Host "Successfully configured FTP State on the production slot." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)

            # Reset the states further below, as appropriate.
            $appService | Add-Member -NotePropertyName IsAllAllowedEnableOnAnyNonProductionSlot -NotePropertyValue $false
            $appService | Add-Member -NotePropertyName NonProductionSlotsWithSecureFTPconfigured -NotePropertyValue ([String]::Empty)

            Write-Host "Fetching non-production slot configurations for App Service: Resource ID: [$($resourceId)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)

            $nonProductionSlotConfigurations = @()
            $NonProductionSlotsWithSecureFTPconfigured =@()
            $nonProductionSlotsWithAllAllowedEnabled =@()
            $isAllAllowedEnabledOnAllNonProductionSlots = $true
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
                    if(-not($nonProductionSlotConfiguration.SiteConfig.FtpsState.Contains("AllAllowed") -eq $true)){
                        $isAllAllowedEnabledOnAllNonProductionSlots = $false
                        $NonProductionSlotsWithSecureFTPconfigured += $nonProductionSlotConfiguration.Name
                    }else{
                        $nonProductionSlotsWithAllAllowedEnabled += nonProductionSlotConfiguration.Name
                    }
                }
            }

            # All non-production slots have FTP State as AllAllowed.
            if ($isAllAllowedEnabledOnAllNonProductionSlots -or -not $isNonProdSlotAvailable)
            {
                $appServicesRolledBack += $appService
                Write-Host "NonCompliant FTP State is configured on all non-production slots in the App Service." -ForegroundColor $([Constants]::MessageType.Update)
                return
            }

            $appService.IsAllAllowedEnableOnAnyNonProductionSlot = $true

            # Holds the list of non-production slots with Secure FTP configuration.
            $NonProductionSlotsWithSecureFTPconfiguredStr = $($NonProductionSlotsWithSecureFTPconfigured -join ', ')
            $appService.NonProductionSlotsWithSecureFTPconfigured = $NonProductionSlotsWithSecureFTPconfiguredStr

            # Holds the running list of non-production slots with Secure FTP configuration. Remove slots from this list as Secure FTP configuration is being configured on them.
            $nonProductionSlotsSkipped = $NonProductionSlotsWithSecureFTPconfigured
            $nonProductionSlotsSkippedStr = $($NonProductionSlotsWithSecureFTPconfigured -join ', ')
            $appService.NonProductionSlotsSkipped = $nonProductionSlotsSkippedStr
            $appService.NonProductionSlotsWithSecureFTPconfigured = $nonProductionSlotsSkippedStr

            Write-Host "Secure FTP is configured on these non-production slots: [$($NonProductionSlotsWithSecureFTPconfiguredStr)]" -ForegroundColor $([Constants]::MessageType.Warning)
            Write-Host $([Constants]::SingleDashLine)
            $nonProductionSlotsSkipped = @()
            foreach($slot in $NonProductionSlotsWithSecureFTPconfigured)
            {
                # Slot names are of the form: app-service-name/slot-name
                $slotName = $slot.Split('/')[1]

                try
                {
                    Write-Host "Configuring NonCompliant FTP State  on the non-production slot: [$($slot)]..." -ForegroundColor $([Constants]::MessageType.Info)
                    Write-Host $([Constants]::SingleDashLine)
                    $resource = Get-AzWebAppSlot -ResourceGroupName $resourceGroupName -Name $resourceName -Slot $slotName
                    $resource.SiteConfig.FtpsState = "AllAllowed"
                    
                    # Holding output of set command to avoid unnecessary logs.
                    $temp = $resource | Set-AzWebAppSlot -ErrorAction SilentlyContinue
                    $isAllAllowedEnabledOnNonProductionSlot = $(Get-AzWebAppSlot -ResourceGroupName $resourceGroupName -Name $resourceName -Slot $slotName).SiteConfig.FtpsState.Contains("AllAllowed")
                    if($isAllAllowedEnabledOnNonProductionSlot){
                        Write-Host "Successfully configured NonCompliant FTP State on the non-production slot." -ForegroundColor $([Constants]::MessageType.Update)
                        Write-Host $([Constants]::SingleDashLine)
                    }else{
                        $nonProductionSlotsSkipped += $slot
                        Write-Host "Error configuring NonCompliant FTP State on the non-production slot." -ForegroundColor $([Constants]::MessageType.Error)
                        Write-Host $([Constants]::SingleDashLine)
                    }
                    
                }
                catch
                {
                    $nonProductionSlotsSkipped += $slot
                    Write-Host "Error configuring NonCompliant FTP State on the non-production slot." -ForegroundColor $([Constants]::MessageType.Error)
                    Write-Host $([Constants]::SingleDashLine)
                }
            }

            $nonProductionSlotsSkippedStr = $nonProductionSlotsSkipped -join ','

            $isFTPConfiguredOnProductionSlot = -not $(Get-AzWebApp -ResourceGroupName $resourceGroupName -Name $resourceName).SiteConfig.FtpsState.Contains("AllAllowed")
            $appService.isFTPConfiguredOnProductionSlot = $isFTPConfiguredOnProductionSlot
            $appService.NonProductionSlotsSkipped = $nonProductionSlotsSkippedStr

            # Rollback of the changes previously made to an App Service is successful only if AllAllowed is enabled on the production slot and all non-production slots.
            if ($($nonProductionSlotsSkipped | Measure-Object).Count -eq 0)
            {
                $appService.IsAllAllowedEnableOnAnyNonProductionSlot = $false
                $appServicesRolledBack += $appService | Select-Object @{N='ResourceID';E={$_.ResourceId}},
                                                                        @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                        @{N='ResourceName';E={$_.ResourceName}},
                                                                        @{N='isFTPConfiguredOnProductionSlot';E={$_.isFTPConfiguredOnProductionSlot}},
                                                                        @{N='IsAllAllowedEnableOnAnyNonProductionSlot';E={$_.IsAllAllowedEnableOnAnyNonProductionSlot}},
                                                                        @{N='NonProductionSlotsWithSecureFTPconfigured';E={$_.NonProductionSlotsWithSecureFTPconfigured}},
                                                                        @{N='NonProductionSlotsSkipped';E={$_.NonProductionSlotsSkipped}}
            }
            else
            {
                $appServicesSkipped += $appService | Select-Object @{N='ResourceID';E={$_.ResourceId}},
                                                                        @{N='ResourceGroupName';E={$_.ResourceGroupName}},
                                                                        @{N='ResourceName';E={$_.ResourceName}},
                                                                        @{N='isFTPConfiguredOnProductionSlot';E={$_.isFTPConfiguredOnProductionSlot}},
                                                                        @{N='IsAllAllowedEnableOnAnyNonProductionSlot';E={$_.IsAllAllowedEnableOnAnyNonProductionSlot}},
                                                                        @{N='NonProductionSlotsWithSecureFTPconfigured';E={$_.NonProductionSlotsWithSecureFTPconfigured}},
                                                                        @{N='NonProductionSlotsSkipped';E={$_.NonProductionSlotsSkipped}}
            }
        }
        catch
        {
            $appServicesSkipped += $appService | Select-Object @{N='ResourceID';E={$resourceId}},
                                                                @{N='ResourceGroupName';E={$resourceGroupName}},
                                                                @{N='ResourceName';E={$resourceName}},
                                                                @{N='isFTPConfiguredOnProductionSlot';E={$isFTPConfiguredOnProductionSlot}},
                                                                @{N='IsAllAllowedEnableOnAnyNonProductionSlot';E={$IsAllAllowedEnableOnAnyNonProductionSlot}},
                                                                @{N='NonProductionSlotsWithSecureFTPconfigured';E={$NonProductionSlotsWithSecureFTPconfigured}},
                                                                @{N='NonProductionSlotsSkipped';E={$nonProductionSlotsSkipped}}
        }
    }

    if (($appServicesSkipped | Measure-Object).Count -eq 0)
    {
        Write-Host "NonCompliant FTP State successfully configured on the production slot and all non-production slots for all [$($totalAppServices)] App Service(s)." -ForegroundColor $([Constants]::MessageType.Update)
    }
    else
    {
        Write-Host "NonCompliant FTP State successfully configured on the production slot and all non-production slots for [$($($appServicesRolledBack | Measure-Object).Count)] out of [$($totalAppServices)] App Service(s)." -ForegroundColor $([Constants]::MessageType.Warning)
    }

    $colsProperty = @{Expression={$_.ResourceId};Label="Resource ID";Width=40;Alignment="left"},
                    @{Expression={$_.ResourceGroupName};Label="Resource Group Name";Width=20;Alignment="left"},
                    @{Expression={$_.ResourceName};Label="Resource Name";Width=20;Alignment="left"},
                    @{Expression={$_.isFTPConfiguredOnProductionSlot};Label="Is FTP State Secured on the production slot?";Width=20;Alignment="left"},
                    @{Expression={$_.IsAllAllowedEnableOnAnyNonProductionSlot};Label="Is FTP State Secured on any non-production slot?";Width=20;Alignment="left"},
                    @{Expression={$_.NonProductionSlotsWithSecureFTPconfigured};Label="Non-production slots with Secured FTP State  - Prior to rollback";Width=40;Alignment="left"},
                    @{Expression={$_.NonProductionSlotsSkipped};Label="Non-production slots with Secured FTP State  - Post rollback";Width=40;Alignment="left"}

    
    Write-Host $([Constants]::DoubleDashLine)
    if($($appServicesRolledBack | Measure-Object).Count -gt 0 -or $($appServicesSkipped | Measure-Object).Count -gt 0){
        Write-Host "Rollback Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)
    }
    if ($($appServicesRolledBack | Measure-Object).Count -gt 0)
    {
        Write-Host "NonCompliant FTP State configured for the following App Service(s):" -ForegroundColor $([Constants]::MessageType.Update)
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
        Write-Host "Error configuring FTP State for the following App Service(s):" -ForegroundColor $([Constants]::MessageType.Error)
        $appServicesSkipped | Format-Table -Property $colsProperty -Wrap
        Write-Host $([Constants]::SingleDashLine)
        # Write this to a file.
        $appServicesSkippedFile = "$($backupFolderPath)\RollbackSkippedAppServices.csv"
        $appServicesSkipped | Export-CSV -Path $appServicesSkippedFile -NoTypeInformation
        Write-Host "This information has been saved to [$($appServicesSkippedFile)]." -ForegroundColor $([Constants]::MessageType.Warning)
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